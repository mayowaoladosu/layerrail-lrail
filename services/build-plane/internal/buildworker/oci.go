package buildworker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"

	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
)

const MaxOCIEntries = 100_000
const MaxOCIMetadataBytes int64 = 4 << 20
const MaxOCILayers = 4096

var ociBlobPathPattern = regexp.MustCompile(`^blobs/sha256/[0-9a-f]{64}$`)

type OCIArtifactDescriptor struct {
	Digest    string
	Size      int64
	MediaType string
}

type OCIArtifactIdentity struct {
	ManifestDigest    string
	ManifestMediaType string
	Manifest          []byte
	Config            OCIArtifactDescriptor
	Layers            []OCIArtifactDescriptor
	LayerDigests      []string
}

type ociArtifactIdentity = OCIArtifactIdentity

type ociCapture struct {
	expectedDigest string
	expectedSize   int64
	maxBytes       int64
	keep           bool
}

func validateOCIArtifact(filePath string) (ociArtifactIdentity, error) {
	return InspectOCIArtifact(filePath)
}

func InspectOCIArtifact(filePath string) (OCIArtifactIdentity, error) {
	initial, archiveEntries, err := scanOCIArchive(filePath, map[string]ociCapture{
		"oci-layout": {maxBytes: MaxOCIMetadataBytes, keep: true},
		"index.json": {maxBytes: MaxOCIMetadataBytes, keep: true},
	})
	if err != nil {
		return OCIArtifactIdentity{}, err
	}
	var layout struct {
		Version string `json:"imageLayoutVersion"`
	}
	if err := decodeStrictOCIJSON(initial["oci-layout"], &layout); err != nil || layout.Version != ocispecs.ImageLayoutVersion {
		return OCIArtifactIdentity{}, errors.New("OCI artifact layout is invalid")
	}
	var index ocispecs.Index
	if err := decodeStrictOCIJSON(initial["index.json"], &index); err != nil || index.SchemaVersion != 2 ||
		index.MediaType != ocispecs.MediaTypeImageIndex || len(index.Manifests) != 1 {
		return OCIArtifactIdentity{}, errors.New("OCI artifact index is invalid")
	}
	manifestDescriptor := index.Manifests[0]
	if manifestDescriptor.MediaType != ocispecs.MediaTypeImageManifest || !validOCIDescriptor(manifestDescriptor) || manifestDescriptor.Size > MaxOCIMetadataBytes {
		return OCIArtifactIdentity{}, errors.New("OCI artifact manifest descriptor is invalid")
	}
	manifestPath := descriptorBlobPath(manifestDescriptor.Digest.String())
	manifestBytes, _, err := scanOCIArchive(filePath, map[string]ociCapture{
		manifestPath: {
			expectedDigest: manifestDescriptor.Digest.String(), expectedSize: manifestDescriptor.Size,
			maxBytes: MaxOCIMetadataBytes, keep: true,
		},
	})
	if err != nil {
		return OCIArtifactIdentity{}, err
	}
	var manifest ocispecs.Manifest
	if err := decodeStrictOCIJSON(manifestBytes[manifestPath], &manifest); err != nil || manifest.SchemaVersion != 2 ||
		manifest.MediaType != ocispecs.MediaTypeImageManifest || manifest.Config.MediaType != ocispecs.MediaTypeImageConfig ||
		!validOCIDescriptor(manifest.Config) || manifest.Config.Size > MaxOCIMetadataBytes ||
		len(manifest.Layers) == 0 || len(manifest.Layers) > MaxOCILayers {
		return OCIArtifactIdentity{}, errors.New("OCI artifact manifest is invalid")
	}
	captures := map[string]ociCapture{
		descriptorBlobPath(manifest.Config.Digest.String()): {
			expectedDigest: manifest.Config.Digest.String(), expectedSize: manifest.Config.Size, maxBytes: manifest.Config.Size,
		},
	}
	layers := make([]string, 0, len(manifest.Layers))
	layerDescriptors := make([]OCIArtifactDescriptor, 0, len(manifest.Layers))
	for _, layer := range manifest.Layers {
		if !validOCIDescriptor(layer) || !validOCILayerMediaType(layer.MediaType) {
			return OCIArtifactIdentity{}, errors.New("OCI artifact layer descriptor is invalid")
		}
		blobPath := descriptorBlobPath(layer.Digest.String())
		if _, duplicate := captures[blobPath]; duplicate {
			return OCIArtifactIdentity{}, errors.New("OCI artifact contains duplicate descriptor identities")
		}
		captures[blobPath] = ociCapture{expectedDigest: layer.Digest.String(), expectedSize: layer.Size, maxBytes: layer.Size}
		layers = append(layers, layer.Digest.String())
		layerDescriptors = append(layerDescriptors, OCIArtifactDescriptor{Digest: layer.Digest.String(), Size: layer.Size, MediaType: layer.MediaType})
	}
	if _, _, err := scanOCIArchive(filePath, captures); err != nil {
		return OCIArtifactIdentity{}, err
	}
	allowedEntries := map[string]struct{}{"oci-layout": {}, "index.json": {}, manifestPath: {}, descriptorBlobPath(manifest.Config.Digest.String()): {}}
	for _, layer := range manifest.Layers {
		allowedEntries[descriptorBlobPath(layer.Digest.String())] = struct{}{}
	}
	if len(archiveEntries) != len(allowedEntries) {
		return OCIArtifactIdentity{}, errors.New("OCI artifact contains unreferenced entries")
	}
	for name := range archiveEntries {
		if _, allowed := allowedEntries[name]; !allowed {
			return OCIArtifactIdentity{}, errors.New("OCI artifact contains an unreferenced blob")
		}
	}
	return OCIArtifactIdentity{
		ManifestDigest: manifestDescriptor.Digest.String(), ManifestMediaType: manifestDescriptor.MediaType,
		Manifest: append([]byte(nil), manifestBytes[manifestPath]...),
		Config:   OCIArtifactDescriptor{Digest: manifest.Config.Digest.String(), Size: manifest.Config.Size, MediaType: manifest.Config.MediaType},
		Layers:   layerDescriptors, LayerDigests: layers,
	}, nil
}

func VisitOCIArtifactBlobs(ctx context.Context, filePath string, identity OCIArtifactIdentity, visit func(OCIArtifactDescriptor, io.Reader) error) error {
	if ctx == nil || visit == nil || !artifactDigestPattern.MatchString(identity.ManifestDigest) || len(identity.Layers) == 0 {
		return errors.New("OCI artifact blob visit is invalid")
	}
	verified, err := InspectOCIArtifact(filePath)
	if err != nil || verified.ManifestDigest != identity.ManifestDigest || verified.Config != identity.Config || !slices.Equal(verified.Layers, identity.Layers) || !bytes.Equal(verified.Manifest, identity.Manifest) {
		return errors.New("OCI artifact changed before blob publication")
	}
	expected := make(map[string]OCIArtifactDescriptor, len(identity.Layers)+1)
	expected[descriptorBlobPath(identity.Config.Digest)] = identity.Config
	for _, descriptor := range identity.Layers {
		path := descriptorBlobPath(descriptor.Digest)
		if _, duplicate := expected[path]; duplicate {
			return errors.New("OCI artifact publication descriptor is duplicated")
		}
		expected[path] = descriptor
	}
	file, err := os.Open(filePath)
	if err != nil {
		return errors.New("open OCI artifact for publication")
	}
	defer file.Close()
	archive := tar.NewReader(file)
	found := make(map[string]struct{}, len(expected))
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.New("read OCI artifact during publication")
		}
		name := path.Clean(strings.TrimPrefix(header.Name, "./"))
		descriptor, wanted := expected[name]
		if !wanted {
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size != descriptor.Size {
			return errors.New("OCI publication blob size differs from descriptor")
		}
		hash := sha256.New()
		reader := &countingReader{reader: io.TeeReader(archive, hash)}
		if err := visit(descriptor, reader); err != nil {
			return err
		}
		if reader.count != descriptor.Size || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != descriptor.Digest {
			return errors.New("OCI publication blob was not consumed with its exact identity")
		}
		found[name] = struct{}{}
	}
	if len(found) != len(expected) {
		return errors.New("OCI artifact publication lacks a required blob")
	}
	return nil
}

type countingReader struct {
	reader io.Reader
	count  int64
}

func (reader *countingReader) Read(destination []byte) (int, error) {
	count, err := reader.reader.Read(destination)
	reader.count += int64(count)
	return count, err
}

func scanOCIArchive(filePath string, captures map[string]ociCapture) (map[string][]byte, map[string]struct{}, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("open OCI artifact: %w", err)
	}
	defer file.Close()
	archive := tar.NewReader(file)
	captured := make(map[string][]byte, len(captures))
	files := make(map[string]struct{})
	found := make(map[string]bool, len(captures))
	seen := make(map[string]struct{})
	entries := 0
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, errors.New("read OCI artifact tar")
		}
		entries++
		if entries > MaxOCIEntries {
			return nil, nil, errors.New("OCI artifact entry limit exceeded")
		}
		rawName := strings.TrimPrefix(header.Name, "./")
		if path.IsAbs(rawName) || strings.HasPrefix(rawName, "../") || strings.Contains(rawName, "\\") {
			return nil, nil, errors.New("OCI artifact contains an unsafe path")
		}
		if header.Typeflag == tar.TypeDir {
			rawName = strings.TrimSuffix(rawName, "/")
			if rawName == "" || rawName == "." {
				continue
			}
		}
		name := path.Clean(rawName)
		if name == "." || name != rawName || strings.HasPrefix(name, "../") {
			return nil, nil, errors.New("OCI artifact contains an unsafe path")
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, nil, errors.New("OCI artifact contains a duplicate path")
		}
		seen[name] = struct{}{}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size < 0 || (name != "oci-layout" && name != "index.json" && !ociBlobPathPattern.MatchString(name)) {
			return nil, nil, errors.New("OCI artifact contains an unsupported entry")
		}
		files[name] = struct{}{}
		capture, requested := captures[name]
		if !requested {
			if _, err := io.Copy(io.Discard, archive); err != nil {
				return nil, nil, errors.New("read OCI artifact entry")
			}
			continue
		}
		if capture.maxBytes < 0 || header.Size > capture.maxBytes || (capture.expectedSize > 0 && header.Size != capture.expectedSize) {
			return nil, nil, errors.New("OCI artifact entry size differs from its descriptor")
		}
		hash := sha256.New()
		var destination io.Writer = hash
		var contents bytes.Buffer
		if capture.keep {
			destination = io.MultiWriter(hash, &contents)
		}
		written, err := io.Copy(destination, archive)
		if err != nil || written != header.Size {
			return nil, nil, errors.New("read OCI artifact entry contents")
		}
		actualDigest := "sha256:" + hex.EncodeToString(hash.Sum(nil))
		if capture.expectedDigest != "" && actualDigest != capture.expectedDigest {
			return nil, nil, errors.New("OCI artifact blob digest differs from its descriptor")
		}
		if strings.HasPrefix(name, "blobs/sha256/") && actualDigest != "sha256:"+path.Base(name) {
			return nil, nil, errors.New("OCI artifact blob path differs from its contents")
		}
		if capture.keep {
			captured[name] = contents.Bytes()
		}
		found[name] = true
	}
	for name := range captures {
		if !found[name] {
			return nil, nil, fmt.Errorf("OCI artifact lacks required entry %s", name)
		}
	}
	return captured, files, nil
}

func decodeStrictOCIJSON(contents []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("OCI JSON contains trailing data")
	}
	return nil
}

func validOCIDescriptor(descriptor ocispecs.Descriptor) bool {
	return artifactDigestPattern.MatchString(descriptor.Digest.String()) && descriptor.Size > 0
}

func descriptorBlobPath(digest string) string {
	return "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:")
}

func validOCILayerMediaType(mediaType string) bool {
	switch mediaType {
	case ocispecs.MediaTypeImageLayer, ocispecs.MediaTypeImageLayerGzip, ocispecs.MediaTypeImageLayerZstd,
		ocispecs.MediaTypeImageLayerNonDistributable, ocispecs.MediaTypeImageLayerNonDistributableGzip,
		ocispecs.MediaTypeImageLayerNonDistributableZstd:
		return true
	default:
		return false
	}
}
