package sourcearchive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

type archiveEntry struct {
	name     string
	body     []byte
	typeflag byte
	mode     int64
	linkname string
}

func TestFinalizeDeterministicManifest(t *testing.T) {
	t.Parallel()
	first := makeArchive(t, []archiveEntry{
		{name: "bin/start", body: []byte("#!/bin/sh\n"), typeflag: tar.TypeReg, mode: 0o755},
		{name: "README.md", body: []byte("hello\n"), typeflag: tar.TypeReg, mode: 0o644},
	})
	second := makeArchive(t, []archiveEntry{
		{name: "README.md", body: []byte("hello\n"), typeflag: tar.TypeReg, mode: 0o644},
		{name: "bin/start", body: []byte("#!/bin/sh\n"), typeflag: tar.TypeReg, mode: 0o755},
	})

	firstResult := finalizeBytes(t, first, DefaultPolicy())
	secondResult := finalizeBytes(t, second, DefaultPolicy())
	if firstResult.ManifestSHA256 != secondResult.ManifestSHA256 || firstResult.SnapshotSHA256 != secondResult.SnapshotSHA256 {
		t.Fatalf("same tree produced different source identity: %#v %#v", firstResult, secondResult)
	}
	if firstResult.ArchiveSHA256 == secondResult.ArchiveSHA256 {
		t.Fatal("test archives unexpectedly had identical compressed bytes")
	}
	if got := firstResult.Manifest.Entries[0].Path; got != "README.md" {
		t.Fatalf("manifest is not path sorted: %q", got)
	}
	if len(firstResult.Manifest.Warnings) != 1 {
		t.Fatalf("expected executable warning, got %#v", firstResult.Manifest.Warnings)
	}
}

func TestFinalizeRejectsUnsafeArchiveCorpus(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		entries []archiveEntry
		want    error
	}{
		{name: "parent traversal", entries: []archiveEntry{{name: "../escape", body: []byte("x"), typeflag: tar.TypeReg}}, want: ErrPathUnsafe},
		{name: "absolute path", entries: []archiveEntry{{name: "/escape", body: []byte("x"), typeflag: tar.TypeReg}}, want: ErrPathUnsafe},
		{name: "windows separator", entries: []archiveEntry{{name: "..\\escape", body: []byte("x"), typeflag: tar.TypeReg}}, want: ErrPathUnsafe},
		{name: "windows drive", entries: []archiveEntry{{name: "C:/escape", body: []byte("x"), typeflag: tar.TypeReg}}, want: ErrPathUnsafe},
		{name: "windows device", entries: []archiveEntry{{name: "CON.txt", body: []byte("x"), typeflag: tar.TypeReg}}, want: ErrPathUnsafe},
		{name: "control character", entries: []archiveEntry{{name: "bad\nname", body: []byte("x"), typeflag: tar.TypeReg}}, want: ErrPathUnsafe},
		{name: "symlink", entries: []archiveEntry{{name: "link", typeflag: tar.TypeSymlink, linkname: "../../escape"}}, want: ErrEntryType},
		{name: "hard link", entries: []archiveEntry{{name: "link", typeflag: tar.TypeLink, linkname: "target"}}, want: ErrEntryType},
		{name: "device", entries: []archiveEntry{{name: "device", typeflag: tar.TypeChar}}, want: ErrEntryType},
		{name: "case collision", entries: []archiveEntry{{name: "App.rb", body: []byte("a"), typeflag: tar.TypeReg}, {name: "app.rb", body: []byte("b"), typeflag: tar.TypeReg}}, want: ErrDuplicatePath},
		{name: "secret path", entries: []archiveEntry{{name: ".env.production", body: []byte("SAFE=x"), typeflag: tar.TypeReg}}, want: ErrSecretMaterial},
		{name: "private key marker", entries: []archiveEntry{{name: "fixture.txt", body: []byte("-----BEGIN PRIVATE KEY-----"), typeflag: tar.TypeReg}}, want: ErrSecretMaterial},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			archive := makeArchive(t, test.entries)
			_, err := Finalize(bytes.NewReader(archive), optionsFor(archive, DefaultPolicy()))
			if !errors.Is(err, test.want) {
				t.Fatalf("Finalize() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestFinalizeEnforcesSizeDigestRatioAndTrailingData(t *testing.T) {
	t.Parallel()
	archive := makeArchive(t, []archiveEntry{{name: "large.txt", body: bytes.Repeat([]byte("a"), 16_384), typeflag: tar.TypeReg}})

	badDigest := optionsFor(archive, DefaultPolicy())
	badDigest.ExpectedArchiveSHA256 = "sha256:" + stringsOf("0", 64)
	if _, err := Finalize(bytes.NewReader(archive), badDigest); !errors.Is(err, ErrArchiveDigest) {
		t.Fatalf("digest error = %v", err)
	}

	badSize := optionsFor(archive, DefaultPolicy())
	badSize.ExpectedArchiveBytes++
	if _, err := Finalize(bytes.NewReader(archive), badSize); !errors.Is(err, ErrArchiveSize) {
		t.Fatalf("size error = %v", err)
	}

	strictRatio := DefaultPolicy()
	strictRatio.MaxCompressionRatio = 2
	if _, err := Finalize(bytes.NewReader(archive), optionsFor(archive, strictRatio)); !errors.Is(err, ErrCompressionRatio) {
		t.Fatalf("ratio error = %v", err)
	}

	trailing := append(append([]byte(nil), archive...), []byte("trailing")...)
	if _, err := Finalize(bytes.NewReader(trailing), optionsFor(trailing, DefaultPolicy())); !errors.Is(err, ErrArchiveFormat) {
		t.Fatalf("trailing data error = %v", err)
	}
}

func TestFinalizeRejectsFileAndEntryLimits(t *testing.T) {
	t.Parallel()
	archive := makeArchive(t, []archiveEntry{
		{name: "one", body: []byte("12"), typeflag: tar.TypeReg},
		{name: "two", body: []byte("34"), typeflag: tar.TypeReg},
	})
	entryPolicy := DefaultPolicy()
	entryPolicy.MaxEntries = 1
	if _, err := Finalize(bytes.NewReader(archive), optionsFor(archive, entryPolicy)); !errors.Is(err, ErrEntryLimit) {
		t.Fatalf("entry limit error = %v", err)
	}

	filePolicy := DefaultPolicy()
	filePolicy.MaxFileBytes = 1
	if _, err := Finalize(bytes.NewReader(archive), optionsFor(archive, filePolicy)); !errors.Is(err, ErrExpandedSize) {
		t.Fatalf("file limit error = %v", err)
	}
}

func makeArchive(t *testing.T, entries []archiveEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	compressed.Header.ModTime = time.Unix(0, 0)
	compressed.Header.OS = 255
	writer := tar.NewWriter(compressed)
	for _, entry := range entries {
		mode := entry.mode
		if mode == 0 {
			mode = 0o644
		}
		header := &tar.Header{
			Name:     entry.name,
			Mode:     mode,
			Size:     int64(len(entry.body)),
			Typeflag: entry.typeflag,
			Linkname: entry.linkname,
			ModTime:  time.Unix(0, 0),
		}
		if header.Typeflag == 0 {
			header.Typeflag = tar.TypeReg
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if len(entry.body) > 0 {
			if _, err := writer.Write(entry.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func finalizeBytes(t *testing.T, archive []byte, policy Policy) Result {
	t.Helper()
	result, err := Finalize(bytes.NewReader(archive), optionsFor(archive, policy))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func optionsFor(archive []byte, policy Policy) Options {
	digest := sha256.Sum256(archive)
	return Options{
		ExpectedArchiveBytes:  int64(len(archive)),
		ExpectedArchiveSHA256: "sha256:" + hex.EncodeToString(digest[:]),
		Metadata: Metadata{
			SourceKind:    "local",
			RootDirectory: "",
			CreatorID:     "acct_019b01da-7e31-7000-8000-000000000001",
		},
		Policy: policy,
	}
}

func stringsOf(value string, count int) string {
	var output bytes.Buffer
	for range count {
		output.WriteString(value)
	}
	return output.String()
}
