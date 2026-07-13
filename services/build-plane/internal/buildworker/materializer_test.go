package buildworker

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
	"testing"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
)

const (
	testSnapshotDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testIRDigest       = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testObjectPrefix   = "s3://lrail-fixtures/builds/test/"
)

type archiveStore struct {
	contents []byte
	err      error
}

func (store archiveStore) Open(_ context.Context, _ buildcell.SourceArtifact) (io.ReadCloser, error) {
	if store.err != nil {
		return nil, store.err
	}
	return io.NopCloser(bytes.NewReader(store.contents)), nil
}

func sourceArchive(t *testing.T, entries map[string]string) ([]byte, buildcell.SourceArtifact) {
	t.Helper()
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	archive := tar.NewWriter(compressed)
	paths := make([]string, 0, len(entries))
	for path := range entries {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		contents := []byte(entries[path])
		if err := archive.WriteHeader(&tar.Header{Name: path, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(contents))}); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
		if _, err := archive.Write(contents); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatalf("Close tar: %v", err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatalf("Close gzip: %v", err)
	}
	digest := sha256.Sum256(output.Bytes())
	return output.Bytes(), buildcell.SourceArtifact{
		SnapshotDigest: testSnapshotDigest,
		ArchiveDigest:  "sha256:" + hex.EncodeToString(digest[:]),
		ArchiveRef:     testObjectPrefix + "source.tar.gz",
		SizeBytes:      int64(output.Len()),
	}
}

func TestTarGzipMaterializerExtractsBoundedRegularFiles(t *testing.T) {
	t.Parallel()
	archive, source := sourceArchive(t, map[string]string{"app/main.txt": "hello", "bin/run": "#!/bin/sh\n"})
	destination := t.TempDir()
	if err := (TarGzipMaterializer{}).Materialize(context.Background(), archiveStore{contents: archive}, source, destination); err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	contents, err := os.ReadFile(filepath.Join(destination, "app", "main.txt"))
	if err != nil || string(contents) != "hello" {
		t.Fatalf("materialized contents = %q, %v", contents, err)
	}
}

func TestTarGzipMaterializerRejectsTraversalLinksDigestAndTrailingData(t *testing.T) {
	t.Parallel()
	validArchive, source := sourceArchive(t, map[string]string{"app.txt": "ok"})
	tests := map[string]struct {
		contents []byte
		source   buildcell.SourceArtifact
	}{
		"digest": {contents: validArchive, source: func() buildcell.SourceArtifact {
			changed := source
			changed.ArchiveDigest = testIRDigest
			return changed
		}()},
		"trailing": {contents: append(append([]byte(nil), validArchive...), []byte("trailing")...), source: func() buildcell.SourceArtifact {
			changed := source
			changed.SizeBytes += int64(len("trailing"))
			changed.ArchiveDigest = digestBytes(append(append([]byte(nil), validArchive...), []byte("trailing")...))
			return changed
		}()},
		"traversal": maliciousArchive(t, "../host", tar.TypeReg, "owned"),
		"symlink":   maliciousArchive(t, "link", tar.TypeSymlink, "target"),
	}
	for name, testCase := range tests {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := (TarGzipMaterializer{}).Materialize(context.Background(), archiveStore{contents: testCase.contents}, testCase.source, t.TempDir()); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func maliciousArchive(t *testing.T, path string, entryType byte, contents string) struct {
	contents []byte
	source   buildcell.SourceArtifact
} {
	t.Helper()
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	archive := tar.NewWriter(compressed)
	data := []byte(contents)
	header := &tar.Header{Name: path, Typeflag: entryType, Mode: 0o644, Size: int64(len(data))}
	if entryType == tar.TypeSymlink {
		header.Linkname = contents
		header.Size = 0
	}
	_ = archive.WriteHeader(header)
	if header.Size > 0 {
		_, _ = archive.Write(data)
	}
	_ = archive.Close()
	_ = compressed.Close()
	return struct {
		contents []byte
		source   buildcell.SourceArtifact
	}{
		contents: output.Bytes(),
		source: buildcell.SourceArtifact{
			SnapshotDigest: testSnapshotDigest, ArchiveDigest: digestBytes(output.Bytes()),
			ArchiveRef: testObjectPrefix + "malicious.tar.gz", SizeBytes: int64(output.Len()),
		},
	}
}

func digestBytes(contents []byte) string {
	digest := sha256.Sum256(contents)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func TestMaterializerHonorsCancellationAndStoreFailure(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, source := sourceArchive(t, map[string]string{"app.txt": "ok"})
	if err := (TarGzipMaterializer{}).Materialize(ctx, archiveStore{err: errors.New("unavailable")}, source, t.TempDir()); err == nil {
		t.Fatal("expected store failure")
	}
}
