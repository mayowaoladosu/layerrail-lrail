package buildorchestrator

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type memorySource struct{ archive []byte }

func (source memorySource) Open(_ context.Context, _ buildcell.SourceArtifact) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(source.archive)), nil
}

type objectEndpoint struct {
	mu       sync.Mutex
	objects  map[string][]byte
	requests []string
}

func (endpoint *objectEndpoint) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	endpoint.requests = append(endpoint.requests, request.Method+" "+request.URL.RequestURI())
	switch request.Method {
	case http.MethodPut:
		contents, err := io.ReadAll(io.LimitReader(request.Body, 2<<20))
		if err != nil {
			http.Error(response, "read", http.StatusBadRequest)
			return
		}
		endpoint.objects[request.URL.Path] = contents
		response.Header().Set("ETag", `"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`)
		response.WriteHeader(http.StatusOK)
	case http.MethodHead:
		contents, found := endpoint.objects[request.URL.Path]
		if !found {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Content-Length", strconv.Itoa(len(contents)))
		response.Header().Set("Content-Type", "application/octet-stream")
		response.Header().Set("ETag", `"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`)
		response.Header().Set("Last-Modified", time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC).Format(http.TimeFormat))
		response.WriteHeader(http.StatusOK)
	case http.MethodGet:
		contents, found := endpoint.objects[request.URL.Path]
		if !found {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Content-Length", strconv.Itoa(len(contents)))
		response.Header().Set("ETag", `"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`)
		response.Header().Set("Last-Modified", time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC).Format(http.TimeFormat))
		_, _ = response.Write(contents)
	default:
		http.Error(response, "unsupported", http.StatusMethodNotAllowed)
	}
}

func TestS3ContentMaterializesMirrorsAndVerifiesImmutableObjects(t *testing.T) {
	t.Parallel()
	archive := sourceArchive(t, map[string]string{"main.go": "package main\n"})
	endpoint := &objectEndpoint{objects: make(map[string][]byte)}
	server := httptest.NewServer(endpoint)
	defer server.Close()
	parsed, _ := url.Parse(server.URL)
	client, err := minio.New(parsed.Host, &minio.Options{
		Creds: credentials.NewStaticV4("test-access", "test-secret", ""), Secure: false, Region: "us-east-1",
	})
	if err != nil {
		t.Fatalf("minio.New: %v", err)
	}
	content, err := NewS3Content(memorySource{archive: archive}, client, "cell-content", "cell-a")
	if err != nil {
		t.Fatalf("NewS3Content: %v", err)
	}
	source := Source{
		SnapshotID: testSnapshotID, SnapshotDigest: testDigest, ManifestDigest: testDigest,
		ArchiveDigest: digestBytes(archive), ArchiveRef: "s3://source/snapshot.tar.gz", SizeBytes: int64(len(archive)), SelectedRoot: ".",
	}
	destination := filepath.Join(t.TempDir(), "source")
	if err := content.Materialize(context.Background(), source, destination); err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	if contents, err := os.ReadFile(filepath.Join(destination, "main.go")); err != nil || string(contents) != "package main\n" {
		t.Fatalf("materialized source: %q err=%v", contents, err)
	}
	mirrorName := fmt.Sprintf("builds/%s/g1/%s/source/archive.tar.gz", testBuildID, strings.TrimPrefix(source.ArchiveDigest, "sha256:"))
	mirrored, err := content.MirrorSource(context.Background(), source, mirrorName)
	if err != nil {
		t.Fatalf("MirrorSource: %v requests=%#v", err, endpoint.requests)
	}
	if mirrored.ArchiveDigest != source.ArchiveDigest || mirrored.SizeBytes != source.SizeBytes || mirrored.ArchiveRef != "s3://cell-content/cell-a/"+mirrorName {
		t.Fatalf("mirrored = %#v", mirrored)
	}
	payload := []byte(`{"version":1}`)
	payloadDigest := digestBytes(payload)
	objectName := fmt.Sprintf("builds/%s/g1/%s/build/value.json", testBuildID, strings.TrimPrefix(payloadDigest, "sha256:"))
	object, err := content.PutImmutable(context.Background(), objectName, "application/json", payload)
	if err != nil {
		t.Fatalf("PutImmutable: %v", err)
	}
	if object.Digest != payloadDigest || object.Size != int64(len(payload)) || object.Reference != "s3://cell-content/cell-a/"+objectName {
		t.Fatalf("object = %#v", object)
	}
	if _, err := content.PutImmutable(context.Background(), "builds/no-content-digest/value.json", "application/json", payload); err == nil {
		t.Fatal("expected content-address mismatch rejection")
	}
}

func sourceArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	tarWriter := tar.NewWriter(gzipWriter)
	for name, contents := range files {
		header := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(contents)), Typeflag: tar.TypeReg}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
		if _, err := io.WriteString(tarWriter, contents); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return compressed.Bytes()
}
