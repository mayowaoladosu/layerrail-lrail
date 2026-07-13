package buildregistry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
)

const StaticArtifactType = "application/vnd.lrail.static.bundle.v1"
const StaticManifestVersion = 1

type StaticPublicationManifest struct {
	Version        int          `json:"version"`
	OrganizationID string       `json:"organization_id"`
	ProjectID      string       `json:"project_id"`
	BuildID        string       `json:"build_id"`
	OutputName     string       `json:"output_name"`
	SourceDigest   string       `json:"source_digest"`
	SourceSize     int64        `json:"source_size"`
	OCIReference   string       `json:"oci_reference"`
	ManifestDigest string       `json:"manifest_digest"`
	Files          []StaticFile `json:"files"`
}

type StaticFile struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
}

type StaticManifestStore interface {
	PutImmutable(ctx context.Context, manifest StaticPublicationManifest) (string, error)
}

type staticPrepared struct {
	path     string
	identity buildworker.OCIArtifactIdentity
	files    []StaticFile
}

type staticSourceEntry struct {
	path  string
	full  string
	info  os.FileInfo
	isDir bool
}

func prepareStaticOCI(ctx context.Context, artifact buildworker.ExportedArtifact, stagingRoot string) (staticPrepared, error) {
	entries, err := inspectStaticSource(ctx, artifact.Path)
	if err != nil {
		return staticPrepared{}, err
	}
	layer, err := os.CreateTemp(stagingRoot, ".lrail-static-layer-*.tar.gz")
	if err != nil {
		return staticPrepared{}, errors.New("create static OCI layer staging")
	}
	layerPath := layer.Name()
	defer func() {
		_ = layer.Close()
		_ = os.Remove(layerPath)
	}()
	compressedHash := sha256.New()
	gzipWriter, err := gzip.NewWriterLevel(io.MultiWriter(layer, compressedHash), gzip.BestCompression)
	if err != nil {
		return staticPrepared{}, errors.New("create deterministic static layer compressor")
	}
	gzipWriter.Header.ModTime = time.Unix(0, 0).UTC()
	gzipWriter.Header.OS = 255
	uncompressedHash := sha256.New()
	tarWriter := tar.NewWriter(io.MultiWriter(gzipWriter, uncompressedHash))
	files := make([]StaticFile, 0)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return staticPrepared{}, err
		}
		mode := normalizedStaticMode(entry.info.Mode(), entry.isDir)
		header := &tar.Header{
			Name: entry.path, Mode: int64(mode), ModTime: time.Unix(0, 0).UTC(), AccessTime: time.Time{}, ChangeTime: time.Time{},
			Uid: 0, Gid: 0, Uname: "", Gname: "", Format: tar.FormatPAX,
		}
		if entry.isDir {
			header.Name += "/"
			header.Typeflag = tar.TypeDir
			if err := tarWriter.WriteHeader(header); err != nil {
				return staticPrepared{}, errors.New("write static OCI directory")
			}
			continue
		}
		header.Typeflag = tar.TypeReg
		header.Size = entry.info.Size()
		if err := tarWriter.WriteHeader(header); err != nil {
			return staticPrepared{}, errors.New("write static OCI file header")
		}
		file, err := os.Open(entry.full)
		if err != nil {
			return staticPrepared{}, errors.New("open static bundle file")
		}
		opened, statErr := file.Stat()
		if statErr != nil || !os.SameFile(entry.info, opened) {
			_ = file.Close()
			return staticPrepared{}, errors.New("static bundle file changed while opening")
		}
		fileHash := sha256.New()
		written, copyErr := io.Copy(io.MultiWriter(tarWriter, fileHash), file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || written != entry.info.Size() {
			return staticPrepared{}, errors.New("stream static bundle file")
		}
		files = append(files, StaticFile{
			Path: entry.path, Digest: "sha256:" + hex.EncodeToString(fileHash.Sum(nil)), Size: written, Mode: uint32(mode),
		})
	}
	if err := tarWriter.Close(); err != nil {
		return staticPrepared{}, errors.New("close static layer tar")
	}
	if err := gzipWriter.Close(); err != nil {
		return staticPrepared{}, errors.New("close static layer compressor")
	}
	if err := layer.Sync(); err != nil {
		return staticPrepared{}, errors.New("sync static OCI layer")
	}
	layerInfo, err := layer.Stat()
	if err != nil || layerInfo.Size() <= 0 {
		return staticPrepared{}, errors.New("stat static OCI layer")
	}
	if err := layer.Close(); err != nil {
		return staticPrepared{}, errors.New("close static OCI layer")
	}
	layerDigest := digest.NewDigestFromEncoded(digest.SHA256, hex.EncodeToString(compressedHash.Sum(nil)))
	diffDigest := digest.NewDigestFromEncoded(digest.SHA256, hex.EncodeToString(uncompressedHash.Sum(nil)))
	imageConfig := ocispecs.Image{
		Platform: ocispecs.Platform{Architecture: "unknown", OS: "unknown"},
		RootFS:   ocispecs.RootFS{Type: "layers", DiffIDs: []digest.Digest{diffDigest}},
	}
	configBytes, err := canonicaljson.Marshal(imageConfig)
	if err != nil {
		return staticPrepared{}, errors.New("canonicalize static OCI config")
	}
	configDescriptor := ocispecs.Descriptor{MediaType: ocispecs.MediaTypeImageConfig, Digest: digest.FromBytes(configBytes), Size: int64(len(configBytes))}
	layerDescriptor := ocispecs.Descriptor{MediaType: ocispecs.MediaTypeImageLayerGzip, Digest: layerDigest, Size: layerInfo.Size()}
	manifest := ocispecs.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispecs.MediaTypeImageManifest, ArtifactType: StaticArtifactType,
		Config: configDescriptor, Layers: []ocispecs.Descriptor{layerDescriptor},
		Annotations: map[string]string{"org.opencontainers.image.title": artifact.OutputName, "dev.lrail.source.digest": artifact.Digest},
	}
	manifestBytes, err := canonicaljson.Marshal(manifest)
	if err != nil {
		return staticPrepared{}, errors.New("canonicalize static OCI manifest")
	}
	manifestDescriptor := ocispecs.Descriptor{
		MediaType: ocispecs.MediaTypeImageManifest, Digest: digest.FromBytes(manifestBytes), Size: int64(len(manifestBytes)), ArtifactType: StaticArtifactType,
	}
	indexBytes, err := canonicaljson.Marshal(ocispecs.Index{
		Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispecs.MediaTypeImageIndex, Manifests: []ocispecs.Descriptor{manifestDescriptor},
	})
	if err != nil {
		return staticPrepared{}, errors.New("canonicalize static OCI index")
	}
	layoutBytes := []byte(`{"imageLayoutVersion":"1.0.0"}`)
	archive, err := os.CreateTemp(stagingRoot, ".lrail-static-*.oci.tar")
	if err != nil {
		return staticPrepared{}, errors.New("create static OCI archive")
	}
	archivePath := archive.Name()
	archiveWriter := tar.NewWriter(archive)
	byteEntries := []struct {
		name     string
		contents []byte
	}{
		{"oci-layout", layoutBytes}, {"index.json", indexBytes},
		{"blobs/sha256/" + manifestDescriptor.Digest.Encoded(), manifestBytes},
		{"blobs/sha256/" + configDescriptor.Digest.Encoded(), configBytes},
	}
	for _, entry := range byteEntries {
		if err := writeStaticOCIEntry(archiveWriter, entry.name, int64(len(entry.contents)), bytes.NewReader(entry.contents)); err != nil {
			_ = archive.Close()
			_ = os.Remove(archivePath)
			return staticPrepared{}, err
		}
	}
	layerReader, err := os.Open(layerPath)
	if err != nil {
		_ = archive.Close()
		_ = os.Remove(archivePath)
		return staticPrepared{}, errors.New("reopen static OCI layer")
	}
	writeErr := writeStaticOCIEntry(archiveWriter, "blobs/sha256/"+layerDescriptor.Digest.Encoded(), layerDescriptor.Size, layerReader)
	layerCloseErr := layerReader.Close()
	archiveCloseErr := archiveWriter.Close()
	syncErr := archive.Sync()
	closeErr := archive.Close()
	if writeErr != nil || layerCloseErr != nil || archiveCloseErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(archivePath)
		return staticPrepared{}, errors.New("finalize static OCI archive")
	}
	identity, err := buildworker.InspectOCIArtifact(archivePath)
	if err != nil || identity.ManifestDigest != manifestDescriptor.Digest.String() {
		_ = os.Remove(archivePath)
		return staticPrepared{}, errors.New("verify generated static OCI artifact")
	}
	return staticPrepared{path: archivePath, identity: identity, files: files}, nil
}

func inspectStaticSource(ctx context.Context, root string) ([]staticSourceEntry, error) {
	entries := make([]staticSourceEntry, 0)
	files := 0
	err := filepath.WalkDir(root, func(fullPath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if fullPath == root {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("static publication contains a symlink")
		}
		relative, err := filepath.Rel(root, fullPath)
		relative = filepath.ToSlash(relative)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, "../") || strings.Contains(relative, "\\") {
			return errors.New("static publication path escaped its root")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !entry.IsDir() && !entry.Type().IsRegular() {
			return errors.New("static publication contains a special file")
		}
		if entry.Type().IsRegular() {
			files++
			if files > buildworker.MaxCommittedArtifactFiles {
				return errors.New("static publication file limit exceeded")
			}
		}
		entries = append(entries, staticSourceEntry{path: relative, full: fullPath, info: info, isDir: entry.IsDir()})
		return nil
	})
	if err != nil || files == 0 {
		return nil, errors.New("static publication is empty or invalid")
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].path < entries[right].path })
	return entries, nil
}

func normalizedStaticMode(mode os.FileMode, directory bool) uint32 {
	if directory || mode.Perm()&0o111 != 0 {
		return 0o555
	}
	return 0o444
}

func writeStaticOCIEntry(writer *tar.Writer, name string, size int64, reader io.Reader) error {
	header := &tar.Header{Name: name, Mode: 0o444, Size: size, Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatPAX}
	if err := writer.WriteHeader(header); err != nil {
		return errors.New("write static OCI entry header")
	}
	written, err := io.Copy(writer, reader)
	if err != nil || written != size {
		return errors.New("write static OCI entry")
	}
	return nil
}
