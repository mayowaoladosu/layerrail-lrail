package sourceupload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/objectstore"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourceauth"
)

func TestPartsReaderValidatesAndConcatenatesParts(t *testing.T) {
	t.Parallel()
	first := []byte("first-")
	second := []byte("second")
	grant := uploadGrant(int64(len(first)+len(second)), 2)
	store := newMemoryStore()
	store.objects[PartKey(grant, 1)] = first
	store.objects[PartKey(grant, 2)] = second
	parts := []Part{part(2, second), part(1, first)}
	reader, err := NewPartsReader(context.Background(), store, grant, parts)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, append(first, second...)) {
		t.Fatalf("joined parts = %q", got)
	}
}

func TestPartsReaderRejectsMissingModifiedAndOversizedParts(t *testing.T) {
	t.Parallel()
	body := []byte("expected")
	grant := uploadGrant(int64(len(body)), 1)

	t.Run("missing", func(t *testing.T) {
		store := newMemoryStore()
		reader, err := NewPartsReader(context.Background(), store, grant, []Part{part(1, body)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(reader); !errors.Is(err, objectstore.ErrNotFound) {
			t.Fatalf("missing part error = %v", err)
		}
	})

	t.Run("modified", func(t *testing.T) {
		store := newMemoryStore()
		store.objects[PartKey(grant, 1)] = []byte("tampered")
		reader, err := NewPartsReader(context.Background(), store, grant, []Part{part(1, body)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(reader); !errors.Is(err, ErrInvalidParts) {
			t.Fatalf("modified part error = %v", err)
		}
	})

	t.Run("declared too large", func(t *testing.T) {
		oversized := Part{Number: 1, Size: sourceauth.MaxPartBytes + 1, SHA256: digest(body)}
		if _, err := ValidateParts(grant, []Part{oversized}); !errors.Is(err, ErrInvalidParts) {
			t.Fatalf("oversized part error = %v", err)
		}
	})
}

func part(number int, body []byte) Part {
	return Part{Number: number, Size: int64(len(body)), SHA256: digest(body)}
}

func digest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func uploadGrant(size int64, parts int) sourceauth.UploadGrant {
	return sourceauth.UploadGrant{
		Version:               1,
		Audience:              sourceauth.Audience,
		SessionID:             "upl_019b01da-7e31-7000-8000-000000000001",
		OrganizationID:        "org_019b01da-7e31-7000-8000-000000000002",
		ProjectID:             "prj_019b01da-7e31-7000-8000-000000000003",
		CreatorID:             "acct_019b01da-7e31-7000-8000-000000000004",
		ExpectedArchiveBytes:  size,
		ExpectedArchiveSHA256: "sha256:" + string(bytes.Repeat([]byte("a"), 64)),
		ExpectedParts:         parts,
		ExpiresAt:             time.Now().UTC().Add(15 * time.Minute),
	}
}

type memoryStore struct {
	objects map[string][]byte
}

func newMemoryStore() *memoryStore { return &memoryStore{objects: make(map[string][]byte)} }

func (store *memoryStore) PresignPut(_ context.Context, key string, _ time.Duration) (*url.URL, error) {
	return url.Parse("https://objects.example.test/" + key)
}

func (store *memoryStore) Open(_ context.Context, key string) (io.ReadCloser, objectstore.Info, error) {
	body, ok := store.objects[key]
	if !ok {
		return nil, objectstore.Info{}, objectstore.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(body)), objectstore.Info{Size: int64(len(body))}, nil
}

func (store *memoryStore) PutImmutable(_ context.Context, key string, reader io.Reader, _ int64, _ string, _ string) error {
	body, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	if existing, ok := store.objects[key]; ok && !bytes.Equal(existing, body) {
		return objectstore.ErrImmutableConflict
	}
	store.objects[key] = body
	return nil
}

func (store *memoryStore) Delete(_ context.Context, keys []string) error {
	for _, key := range keys {
		delete(store.objects, key)
	}
	return nil
}

func (store *memoryStore) Ready(context.Context) error { return nil }
func (store *memoryStore) Ref(key string) string       { return "memory://" + key }
