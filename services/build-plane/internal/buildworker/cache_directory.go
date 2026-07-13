package buildworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/flock"
	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
	"github.com/moby/buildkit/client"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
)

const cacheMetadataVersion = 1
const MaxCacheRecordFiles = 200_000

type DirectoryCacheProvider struct {
	root string
}

type cacheMetadata struct {
	Version         int      `json:"version"`
	CompilerVersion string   `json:"compiler_version"`
	PolicyDigest    string   `json:"policy_digest"`
	Namespaces      []string `json:"namespaces"`
	OutputName      string   `json:"output_name"`
	RecordDigest    string   `json:"record_digest"`
}

type directoryCacheLease struct {
	mu        sync.Mutex
	completed bool
	lock      *flock.Flock
	imports   []client.CacheOptionsEntry
	exports   []client.CacheOptionsEntry
	staging   string
	records   string
	current   string
	metadata  cacheMetadata
}

func NewDirectoryCacheProvider(root string) (*DirectoryCacheProvider, error) {
	if root == "" {
		return nil, errors.New("cache root is empty")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, errors.New("cache root is invalid")
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, fmt.Errorf("create cache root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(absolute) {
		return nil, errors.New("cache root may not traverse a symlink")
	}
	return &DirectoryCacheProvider{root: absolute}, nil
}

func (provider *DirectoryCacheProvider) Acquire(ctx context.Context, lock llbcompiler.DefinitionLock, buildID, outputName string, attempt uint32) (CacheLease, error) {
	if len(lock.Caches) == 0 {
		return emptyCacheLease{}, nil
	}
	// BuildKit's external cache exporter covers the whole solve, not only cache
	// mounts. Do not persist a graph that can receive secret-derived bytes.
	if len(lock.Secrets) != 0 {
		return emptyCacheLease{}, nil
	}
	parsed, err := platformid.Parse(buildID)
	if err != nil || parsed.Prefix() != "bld" || !artifactOutputPattern.MatchString(outputName) || attempt == 0 {
		return nil, errors.New("cache lease identity is invalid")
	}
	namespaces := make([]string, 0, len(lock.Caches))
	for _, capability := range lock.Caches {
		if !strings.HasPrefix(capability.Namespace, "lrail-cache-") {
			return nil, errors.New("cache namespace is invalid")
		}
		namespaces = append(namespaces, capability.Namespace)
	}
	sort.Strings(namespaces)
	if len(slices.Compact(append([]string(nil), namespaces...))) != len(namespaces) {
		return nil, errors.New("cache namespace set contains duplicates")
	}
	identity, err := canonicaljson.Marshal(struct {
		Version         int      `json:"version"`
		CompilerVersion string   `json:"compiler_version"`
		PolicyDigest    string   `json:"policy_digest"`
		Namespaces      []string `json:"namespaces"`
		OutputName      string   `json:"output_name"`
	}{Version: 1, CompilerVersion: lock.CompilerVersion, PolicyDigest: lock.PolicyDigest, Namespaces: namespaces, OutputName: outputName})
	if err != nil {
		return nil, errors.New("cache identity cannot be canonicalized")
	}
	key := sha256.Sum256(identity)
	cacheRoot := filepath.Join(provider.root, hex.EncodeToString(key[:]))
	records := filepath.Join(cacheRoot, "records")
	stagingRoot := filepath.Join(cacheRoot, "staging")
	if err := os.MkdirAll(records, 0o700); err != nil {
		return nil, fmt.Errorf("create cache records: %w", err)
	}
	if err := os.MkdirAll(stagingRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create cache staging: %w", err)
	}
	fileLock := flock.New(filepath.Join(cacheRoot, "lease.lock"))
	locked, err := fileLock.TryLockContext(ctx, 10*time.Millisecond)
	if err != nil || !locked {
		_ = fileLock.Close()
		return nil, errors.New("cache trust-domain lease is unavailable")
	}
	lease := &directoryCacheLease{
		lock: fileLock, imports: []client.CacheOptionsEntry{}, exports: []client.CacheOptionsEntry{},
		records: records, current: filepath.Join(cacheRoot, "current"),
		metadata: cacheMetadata{Version: cacheMetadataVersion, CompilerVersion: lock.CompilerVersion, PolicyDigest: lock.PolicyDigest, Namespaces: namespaces, OutputName: outputName},
	}
	currentRecord, err := lease.readCurrent()
	if err != nil {
		_ = lease.unlock()
		return nil, err
	}
	if currentRecord != "" {
		lease.imports = append(lease.imports, client.CacheOptionsEntry{Type: "local", Attrs: map[string]string{"src": currentRecord}})
	}
	lease.staging, err = os.MkdirTemp(stagingRoot, fmt.Sprintf("%s-a%d-", buildID, attempt))
	if err != nil {
		_ = lease.unlock()
		return nil, errors.New("create cache export staging")
	}
	lease.exports = append(lease.exports, client.CacheOptionsEntry{Type: "local", Attrs: map[string]string{"dest": lease.staging, "mode": "max"}})
	return lease, nil
}

func (lease *directoryCacheLease) Imports() []client.CacheOptionsEntry {
	return cloneCacheEntries(lease.imports)
}
func (lease *directoryCacheLease) Exports() []client.CacheOptionsEntry {
	return cloneCacheEntries(lease.exports)
}

func (lease *directoryCacheLease) Complete(success bool) error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.completed {
		return errors.New("cache lease is already complete")
	}
	lease.completed = true
	defer lease.unlock()
	if !success {
		return os.RemoveAll(lease.staging)
	}
	if err := validateBuildKitCache(lease.staging); err != nil {
		_ = os.RemoveAll(lease.staging)
		return err
	}
	digest, _, err := directoryDigest(lease.staging)
	if err != nil {
		_ = os.RemoveAll(lease.staging)
		return errors.New("digest cache export")
	}
	recordID := strings.TrimPrefix(digest, "sha256:")
	recordPath := filepath.Join(lease.records, recordID)
	lease.metadata.RecordDigest = digest
	if info, statErr := os.Lstat(recordPath); statErr == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("existing cache record is unsafe")
		}
		existingDigest, _, digestErr := directoryDigest(recordPath)
		if digestErr != nil || existingDigest != digest {
			return errors.New("existing immutable cache record conflicts")
		}
		_ = os.RemoveAll(lease.staging)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return errors.New("inspect immutable cache record")
	} else if err := os.Rename(lease.staging, recordPath); err != nil {
		return errors.New("publish immutable cache record")
	}
	if err := writeCacheMetadata(recordPath+".json", lease.metadata); err != nil {
		return err
	}
	if err := protectCommittedTree(recordPath); err != nil {
		return err
	}
	return writeAtomicFile(lease.current, []byte(recordID), 0o600)
}

func (lease *directoryCacheLease) readCurrent() (string, error) {
	contents, err := os.ReadFile(lease.current)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil || len(contents) != sha256.Size*2 {
		return "", errors.New("cache current pointer is invalid")
	}
	recordID := string(contents)
	if _, err := hex.DecodeString(recordID); err != nil {
		return "", errors.New("cache current pointer is malformed")
	}
	recordPath := filepath.Join(lease.records, recordID)
	metadata, err := readCacheMetadata(recordPath + ".json")
	if err != nil {
		return "", err
	}
	expected := lease.metadata
	expected.RecordDigest = "sha256:" + recordID
	if !slices.Equal(metadata.Namespaces, expected.Namespaces) || metadata.Version != expected.Version || metadata.CompilerVersion != expected.CompilerVersion ||
		metadata.PolicyDigest != expected.PolicyDigest || metadata.OutputName != expected.OutputName || metadata.RecordDigest != expected.RecordDigest {
		return "", errors.New("cache producer metadata is incompatible")
	}
	if err := validateBuildKitCache(recordPath); err != nil {
		return "", err
	}
	digest, _, err := directoryDigest(recordPath)
	if err != nil || digest != metadata.RecordDigest {
		return "", errors.New("cache record digest verification failed")
	}
	return recordPath, nil
}

func (lease *directoryCacheLease) unlock() error {
	unlockErr := lease.lock.Unlock()
	closeErr := lease.lock.Close()
	return errors.Join(unlockErr, closeErr)
}

func validateBuildKitCache(root string) error {
	type layout struct {
		Version string `json:"imageLayoutVersion"`
	}
	var parsedLayout layout
	if err := readStrictJSON(filepath.Join(root, "oci-layout"), &parsedLayout); err != nil || parsedLayout.Version != "1.0.0" {
		return errors.New("cache OCI layout is invalid")
	}
	var parsedIndex ocispecs.Index
	if err := readStrictJSON(filepath.Join(root, "index.json"), &parsedIndex); err != nil || parsedIndex.SchemaVersion != 2 || parsedIndex.MediaType != ocispecs.MediaTypeImageIndex || len(parsedIndex.Manifests) == 0 || len(parsedIndex.Manifests) > 128 {
		return errors.New("cache OCI index is invalid")
	}
	files := 0
	actualFiles := make(map[string]struct{})
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		files++
		if files > MaxCacheRecordFiles || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("cache record shape is unsafe")
		}
		if !entry.IsDir() && !entry.Type().IsRegular() {
			return errors.New("cache record contains a non-regular entry")
		}
		if entry.Type().IsRegular() {
			relative, err := filepath.Rel(root, path)
			if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				return errors.New("cache record path escaped its root")
			}
			actualFiles[filepath.ToSlash(relative)] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return err
	}
	allowedFiles := map[string]struct{}{"oci-layout": {}, "index.json": {}}
	for _, descriptor := range parsedIndex.Manifests {
		if descriptor.MediaType != ocispecs.MediaTypeImageManifest || !validCacheDescriptor(descriptor) {
			return errors.New("cache manifest descriptor is invalid")
		}
		manifestPath := cacheBlobPath(root, descriptor)
		manifestRelative := filepath.ToSlash(filepath.Join("blobs", "sha256", strings.TrimPrefix(descriptor.Digest.String(), "sha256:")))
		if _, duplicate := allowedFiles[manifestRelative]; duplicate {
			return errors.New("cache manifest descriptor is duplicated")
		}
		allowedFiles[manifestRelative] = struct{}{}
		if err := verifyCacheBlob(manifestPath, descriptor); err != nil {
			return errors.New("cache manifest blob does not match its descriptor")
		}
		var manifest ocispecs.Manifest
		if err := readStrictJSON(manifestPath, &manifest); err != nil || manifest.SchemaVersion != 2 || manifest.MediaType != ocispecs.MediaTypeImageManifest ||
			manifest.Config.MediaType != "application/vnd.buildkit.cacheconfig.v0" || !validCacheDescriptor(manifest.Config) || len(manifest.Layers) > MaxCacheRecordFiles {
			return errors.New("cache manifest is invalid")
		}
		configRelative := filepath.ToSlash(filepath.Join("blobs", "sha256", strings.TrimPrefix(manifest.Config.Digest.String(), "sha256:")))
		if _, duplicate := allowedFiles[configRelative]; duplicate {
			return errors.New("cache configuration descriptor is duplicated")
		}
		allowedFiles[configRelative] = struct{}{}
		if err := verifyCacheBlob(cacheBlobPath(root, manifest.Config), manifest.Config); err != nil {
			return errors.New("cache configuration blob does not match its descriptor")
		}
		for _, layer := range manifest.Layers {
			if !validCacheLayerMediaType(layer.MediaType) || !validCacheDescriptor(layer) || verifyCacheBlob(cacheBlobPath(root, layer), layer) != nil {
				return errors.New("cache layer blob is invalid")
			}
			layerRelative := filepath.ToSlash(filepath.Join("blobs", "sha256", strings.TrimPrefix(layer.Digest.String(), "sha256:")))
			if _, duplicate := allowedFiles[layerRelative]; duplicate {
				return errors.New("cache layer descriptor is duplicated")
			}
			allowedFiles[layerRelative] = struct{}{}
		}
	}
	if len(actualFiles) != len(allowedFiles) {
		return errors.New("cache record contains unreferenced files")
	}
	for file := range actualFiles {
		if _, allowed := allowedFiles[file]; !allowed {
			return errors.New("cache record contains an unreferenced blob")
		}
	}
	return nil
}

func validCacheDescriptor(descriptor ocispecs.Descriptor) bool {
	return artifactDigestPattern.MatchString(descriptor.Digest.String()) && descriptor.Size > 0
}

func cacheBlobPath(root string, descriptor ocispecs.Descriptor) string {
	return filepath.Join(root, "blobs", "sha256", strings.TrimPrefix(descriptor.Digest.String(), "sha256:"))
}

func verifyCacheBlob(path string, descriptor ocispecs.Descriptor) error {
	digest, size, err := fileDigest(path)
	if err != nil || digest != descriptor.Digest.String() || size != descriptor.Size {
		return errors.New("cache blob identity mismatch")
	}
	return nil
}

func validCacheLayerMediaType(mediaType string) bool {
	return slices.Contains([]string{
		ocispecs.MediaTypeImageLayer,
		ocispecs.MediaTypeImageLayerGzip,
		ocispecs.MediaTypeImageLayerZstd,
		ocispecs.MediaTypeImageLayerNonDistributable,
		ocispecs.MediaTypeImageLayerNonDistributableGzip,
		ocispecs.MediaTypeImageLayerNonDistributableZstd,
	}, mediaType)
}

func readStrictJSON(path string, destination any) error {
	contents, err := os.ReadFile(path)
	if err != nil || len(contents) == 0 || len(contents) > 1<<20 {
		return errors.New("cache JSON is absent or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("cache JSON has trailing data")
	}
	return nil
}

func writeCacheMetadata(path string, metadata cacheMetadata) error {
	contents, err := canonicaljson.Marshal(metadata)
	if err != nil {
		return errors.New("canonicalize cache metadata")
	}
	if existing, readErr := os.ReadFile(path); readErr == nil {
		if !bytes.Equal(existing, contents) {
			return errors.New("immutable cache metadata conflicts")
		}
		return nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	return writeAtomicFile(path, contents, 0o400)
}

func readCacheMetadata(path string) (cacheMetadata, error) {
	var metadata cacheMetadata
	if err := readStrictJSON(path, &metadata); err != nil {
		return cacheMetadata{}, err
	}
	return metadata, nil
}

func writeAtomicFile(path string, contents []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".atomic-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncArtifactDirectory(filepath.Dir(path))
}

func cloneCacheEntries(values []client.CacheOptionsEntry) []client.CacheOptionsEntry {
	result := make([]client.CacheOptionsEntry, 0, len(values))
	for _, value := range values {
		result = append(result, client.CacheOptionsEntry{Type: value.Type, Attrs: cloneStringMap(value.Attrs)})
	}
	return result
}
