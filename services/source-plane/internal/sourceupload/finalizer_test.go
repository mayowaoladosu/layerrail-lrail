package sourceupload

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourcearchive"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourceauth"
)

func TestFinalizerPersistsImmutableSnapshotAndIdempotentReceipt(t *testing.T) {
	t.Parallel()
	archive := sourceArchive(t, "README.md", []byte("hello source\n"))
	midpoint := len(archive) / 2
	bodies := [][]byte{archive[:midpoint], archive[midpoint:]}
	grant := uploadGrant(int64(len(archive)), len(bodies))
	grant.ExpectedArchiveSHA256 = digest(archive)
	store := newMemoryStore()
	parts := make([]Part, len(bodies))
	for index, body := range bodies {
		parts[index] = part(index+1, body)
		store.objects[PartKey(grant, index+1)] = append([]byte(nil), body...)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	finalizedAt := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	finalizer := Finalizer{
		Store:        store,
		ScratchDir:   t.TempDir(),
		Policy:       sourcearchive.DefaultPolicy(),
		PrivateKey:   privateKey,
		SigningKeyID: "source-finalizer-test",
		Now:          func() time.Time { return finalizedAt },
	}

	first, err := finalizer.Finalize(context.Background(), grant, parts)
	if err != nil {
		t.Fatal(err)
	}
	if err := sourceauth.VerifyResult(publicKey, first); err != nil {
		t.Fatal(err)
	}
	if first.Result.ArchiveSHA256 != grant.ExpectedArchiveSHA256 || first.Result.FinalizedAt != finalizedAt {
		t.Fatalf("unexpected signed result: %#v", first)
	}
	if _, exists := store.objects[PartKey(grant, 1)]; exists {
		t.Fatal("source part was not deleted after receipt persistence")
	}
	if _, exists := store.objects[finalizationKey(grant)]; !exists {
		t.Fatal("finalization receipt was not persisted")
	}

	second, err := finalizer.Finalize(context.Background(), grant, []Part{{Number: 99}})
	if err != nil {
		t.Fatal(err)
	}
	if first.Signature != second.Signature {
		t.Fatal("idempotent finalization returned a different receipt")
	}
}

func TestFinalizerRejectsConflictingImmutableSnapshot(t *testing.T) {
	t.Parallel()
	archive := sourceArchive(t, "main.go", []byte("package main\n"))
	grant := uploadGrant(int64(len(archive)), 1)
	grant.ExpectedArchiveSHA256 = digest(archive)
	store := newMemoryStore()
	store.objects[PartKey(grant, 1)] = archive
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	finalizer := Finalizer{
		Store:        store,
		ScratchDir:   t.TempDir(),
		Policy:       sourcearchive.DefaultPolicy(),
		PrivateKey:   privateKey,
		SigningKeyID: "source-finalizer-test",
	}

	first, err := finalizer.Finalize(context.Background(), grant, []Part{part(1, archive)})
	if err != nil {
		t.Fatal(err)
	}
	delete(store.objects, finalizationKey(grant))
	store.objects[PartKey(grant, 1)] = archive
	archiveKey := strings.TrimPrefix(first.Result.ArchiveRef, "memory://")
	store.objects[archiveKey] = []byte("conflicting immutable bytes")
	if _, err := finalizer.Finalize(context.Background(), grant, []Part{part(1, archive)}); err == nil {
		t.Fatal("expected immutable conflict")
	}
}

func sourceArchive(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	compressed.Header.ModTime = time.Unix(0, 0)
	compressed.Header.OS = 255
	writer := tar.NewWriter(compressed)
	if err := writer.WriteHeader(&tar.Header{
		Name:     name,
		Mode:     0o644,
		Size:     int64(len(body)),
		Typeflag: tar.TypeReg,
		ModTime:  time.Unix(0, 0),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestStoredReceiptRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	grant := uploadGrant(1, 1)
	store := newMemoryStore()
	store.objects[finalizationKey(grant)] = []byte(`{"unknown":true}`)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	finalizer := Finalizer{Store: store, Policy: sourcearchive.DefaultPolicy(), PrivateKey: privateKey, SigningKeyID: "test"}
	if _, _, err := finalizer.completedResult(context.Background(), grant); err == nil {
		t.Fatal("expected unknown receipt field rejection")
	}
}
