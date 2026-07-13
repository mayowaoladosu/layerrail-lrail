package buildcontent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func testStore(t *testing.T, contents string) (*Store, func()) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/lrail-build/cell-a/object.bin" {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		response.Header().Set("Content-Length", fmt.Sprintf("%d", len(contents)))
		response.Header().Set("ETag", `"fake-etag"`)
		response.Header().Set("Last-Modified", "Mon, 13 Jul 2026 00:00:00 GMT")
		if request.Method == http.MethodGet {
			_, _ = response.Write([]byte(contents))
		}
	}))
	parsed, _ := url.Parse(server.URL)
	client, err := minio.New(parsed.Host, &minio.Options{Creds: credentials.NewStaticV4("fake-access", "fake-secret", ""), Secure: false, Region: "us-east-1"})
	if err != nil {
		server.Close()
		t.Fatalf("minio.New: %v", err)
	}
	store, err := NewStore(client, "lrail-build", "cell-a")
	if err != nil {
		server.Close()
		t.Fatalf("NewStore: %v", err)
	}
	return store, server.Close
}

func TestStoreReadsOnlyBoundedCellObjects(t *testing.T) {
	t.Parallel()
	store, closeServer := testStore(t, "fake immutable object")
	defer closeServer()
	reader, err := store.OpenObject(context.Background(), "s3://lrail-build/cell-a/object.bin", 100)
	if err != nil {
		t.Fatalf("OpenObject: %v", err)
	}
	contents, err := io.ReadAll(reader)
	closeErr := reader.Close()
	if err != nil || closeErr != nil || string(contents) != "fake immutable object" {
		t.Fatalf("contents=%q error=%v close=%v", contents, err, closeErr)
	}
	for _, reference := range []string{
		"s3://other/cell-a/object.bin", "s3://lrail-build/other/object.bin",
		"s3://lrail-build/cell-a/../object.bin", "https://lrail-build/cell-a/object.bin",
	} {
		if _, err := store.OpenObject(context.Background(), reference, 100); err == nil {
			t.Fatalf("expected reference rejection: %s", reference)
		}
	}
	if _, err := store.OpenObject(context.Background(), "s3://lrail-build/cell-a/object.bin", 4); err == nil {
		t.Fatal("expected size rejection")
	}
}

func TestSourceAndArtifactAdaptersFailClosed(t *testing.T) {
	t.Parallel()
	store, closeServer := testStore(t, "source")
	defer closeServer()
	source := buildcell.SourceArtifact{ArchiveRef: "s3://lrail-build/cell-a/object.bin", SizeBytes: 6}
	reader, err := (SourceStore{Store: store}).Open(context.Background(), source)
	if err != nil {
		t.Fatalf("source Open: %v", err)
	}
	_ = reader.Close()
	reader, err = (ArtifactStore{Store: store}).Open(context.Background(), source.ArchiveRef, 6)
	if err != nil {
		t.Fatalf("artifact Open: %v", err)
	}
	_ = reader.Close()
	if _, err := (SourceStore{}).Open(context.Background(), source); err == nil {
		t.Fatal("expected nil source adapter rejection")
	}
	if _, err := NewStore(nil, "bucket", "prefix"); err == nil {
		t.Fatal("expected nil client rejection")
	}
}
