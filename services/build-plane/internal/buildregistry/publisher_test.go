package buildregistry

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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
)

type publisherBroker struct {
	registry    string
	repository  string
	token       string
	issues      int
	revokes     int
	revokeErr   error
	foreignRepo bool
}

func (broker *publisherBroker) Issue(_ context.Context, scope PublicationScope) (PushCapability, error) {
	broker.issues++
	repository := broker.repository
	if broker.foreignRepo {
		repository = "builds/foreign/api"
	}
	return PushCapability{
		LeaseID: "tok_019b01da-7e31-7000-8000-000000000013", Registry: broker.registry,
		Repository: repository, Token: broker.token, ExpiresAt: registryNow.Add(5 * time.Minute),
	}, nil
}

func (broker *publisherBroker) Revoke(context.Context, string) error {
	broker.revokes++
	return broker.revokeErr
}

type fakeDistribution struct {
	mu             sync.Mutex
	server         *httptest.Server
	fullRepository string
	token          string
	blobs          map[string][]byte
	manifests      map[string][]byte
	blobPuts       int
	manifestPuts   int
	wrongDigest    bool
}

func newFakeDistribution(t *testing.T, fullRepository, token string) *fakeDistribution {
	t.Helper()
	registry := &fakeDistribution{fullRepository: fullRepository, token: token, blobs: map[string][]byte{}, manifests: map[string][]byte{}}
	registry.server = httptest.NewTLSServer(http.HandlerFunc(registry.handle))
	t.Cleanup(registry.server.Close)
	return registry
}

func (registry *fakeDistribution) handle(response http.ResponseWriter, request *http.Request) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if request.Header.Get("Authorization") != "Bearer "+registry.token {
		response.WriteHeader(http.StatusForbidden)
		return
	}
	prefix := "/v2/" + registry.fullRepository
	if !strings.HasPrefix(request.URL.Path, prefix) {
		response.WriteHeader(http.StatusForbidden)
		return
	}
	suffix := strings.TrimPrefix(request.URL.Path, prefix)
	switch {
	case request.Method == http.MethodHead && strings.HasPrefix(suffix, "/blobs/"):
		digest := strings.TrimPrefix(suffix, "/blobs/")
		contents, found := registry.blobs[digest]
		if !found {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		response.Header().Set("Docker-Content-Digest", digest)
		response.Header().Set("Content-Length", fmt.Sprintf("%d", len(contents)))
		response.WriteHeader(http.StatusOK)
	case request.Method == http.MethodPost && suffix == "/blobs/uploads/":
		response.Header().Set("Location", registry.server.URL+prefix+"/blobs/uploads/session-1?state=fixed")
		response.WriteHeader(http.StatusAccepted)
	case request.Method == http.MethodPut && suffix == "/blobs/uploads/session-1":
		digestText := request.URL.Query().Get("digest")
		contents, err := io.ReadAll(request.Body)
		actual := digest.FromBytes(contents).String()
		if err != nil || actual != digestText || request.ContentLength != int64(len(contents)) {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		registry.blobs[digestText] = contents
		registry.blobPuts++
		if registry.wrongDigest {
			digestText = "sha256:" + strings.Repeat("f", 64)
		}
		response.Header().Set("Docker-Content-Digest", digestText)
		response.WriteHeader(http.StatusCreated)
	case strings.HasPrefix(suffix, "/manifests/"):
		digestText := strings.TrimPrefix(suffix, "/manifests/")
		switch request.Method {
		case http.MethodGet:
			contents, found := registry.manifests[digestText]
			if !found {
				response.WriteHeader(http.StatusNotFound)
				return
			}
			response.Header().Set("Content-Type", ocispecs.MediaTypeImageManifest)
			response.Header().Set("Docker-Content-Digest", digestText)
			response.WriteHeader(http.StatusOK)
			_, _ = response.Write(contents)
		case http.MethodPut:
			contents, err := io.ReadAll(request.Body)
			if err != nil || digest.FromBytes(contents).String() != digestText || request.Header.Get("Content-Type") != ocispecs.MediaTypeImageManifest {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			registry.manifests[digestText] = contents
			registry.manifestPuts++
			response.Header().Set("Docker-Content-Digest", digestText)
			response.WriteHeader(http.StatusCreated)
		default:
			response.WriteHeader(http.StatusMethodNotAllowed)
		}
	default:
		response.WriteHeader(http.StatusNotFound)
	}
}

func TestPublisherPushesAndVerifiesOCIByDigestIdempotently(t *testing.T) {
	t.Parallel()
	artifact, expectedManifest := registryOCIFixture(t)
	projectName, _ := ProjectName(artifact.OrganizationID)
	repository, _ := RepositoryName(artifact.ProjectID, artifact.OutputName)
	fullName, _ := fullRepository(projectName, repository)
	registry := newFakeDistribution(t, fullName, "scoped-token")
	broker := &publisherBroker{registry: registry.server.URL, repository: repository, token: registry.token}
	distribution, err := NewDistributionClient(registry.server.Client())
	if err != nil {
		t.Fatalf("NewDistributionClient: %v", err)
	}
	publisher, err := NewPublisher(PublisherConfig{Broker: broker, Registry: distribution, Clock: func() time.Time { return registryNow }})
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	first, err := publisher.Commit(t.Context(), artifact)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	second, err := publisher.Commit(t.Context(), artifact)
	if err != nil {
		t.Fatalf("idempotent Commit: %v", err)
	}
	if first != second || first.Digest != artifact.Digest || first.Size != artifact.Size || first.ManifestDigest != expectedManifest ||
		first.Reference != strings.TrimPrefix(registry.server.URL, "https://")+"/"+fullName+"@"+expectedManifest {
		t.Fatalf("first=%#v second=%#v", first, second)
	}
	if registry.blobPuts != 2 || registry.manifestPuts != 1 || broker.issues != 2 || broker.revokes != 2 {
		t.Fatalf("registry blobs=%d manifests=%d broker=%#v", registry.blobPuts, registry.manifestPuts, broker)
	}
}

func TestPublisherRecoversWhenBlobsExistBeforeManifest(t *testing.T) {
	t.Parallel()
	artifact, expectedManifest := registryOCIFixture(t)
	projectName, _ := ProjectName(artifact.OrganizationID)
	repository, _ := RepositoryName(artifact.ProjectID, artifact.OutputName)
	fullName, _ := fullRepository(projectName, repository)
	registry := newFakeDistribution(t, fullName, "scoped-token")
	broker := &publisherBroker{registry: registry.server.URL, repository: repository, token: registry.token}
	distribution, _ := NewDistributionClient(registry.server.Client())
	publisher, _ := NewPublisher(PublisherConfig{Broker: broker, Registry: distribution, Clock: func() time.Time { return registryNow }})
	if _, err := publisher.Commit(t.Context(), artifact); err != nil {
		t.Fatalf("initial Commit: %v", err)
	}
	registry.mu.Lock()
	delete(registry.manifests, expectedManifest)
	registry.mu.Unlock()
	if _, err := publisher.Commit(t.Context(), artifact); err != nil {
		t.Fatalf("recovery Commit: %v", err)
	}
	if registry.blobPuts != 2 || registry.manifestPuts != 2 || broker.revokes != 2 {
		t.Fatalf("registry blobs=%d manifests=%d broker=%#v", registry.blobPuts, registry.manifestPuts, broker)
	}
}

func TestPublisherFailsClosedOnRegistryOrCapabilityMismatch(t *testing.T) {
	t.Parallel()
	artifact, _ := registryOCIFixture(t)
	projectName, _ := ProjectName(artifact.OrganizationID)
	repository, _ := RepositoryName(artifact.ProjectID, artifact.OutputName)
	fullName, _ := fullRepository(projectName, repository)
	for name, configure := range map[string]func(*fakeDistribution, *publisherBroker){
		"blob digest":        func(registry *fakeDistribution, _ *publisherBroker) { registry.wrongDigest = true },
		"foreign repository": func(_ *fakeDistribution, broker *publisherBroker) { broker.foreignRepo = true },
		"revocation": func(_ *fakeDistribution, broker *publisherBroker) {
			broker.revokeErr = errors.New("revocation unavailable")
		},
	} {
		t.Run(name, func(t *testing.T) {
			registry := newFakeDistribution(t, fullName, "scoped-token")
			broker := &publisherBroker{registry: registry.server.URL, repository: repository, token: registry.token}
			configure(registry, broker)
			distribution, _ := NewDistributionClient(registry.server.Client())
			publisher, _ := NewPublisher(PublisherConfig{Broker: broker, Registry: distribution, Clock: func() time.Time { return registryNow }})
			if committed, err := publisher.Commit(t.Context(), artifact); err == nil || committed.Reference != "" {
				t.Fatalf("committed=%#v error=%v", committed, err)
			}
		})
	}
}

func TestDistributionRejectsCrossRepositoryCapability(t *testing.T) {
	t.Parallel()
	artifact, _ := registryOCIFixture(t)
	identity, _ := buildworker.InspectOCIArtifact(artifact.Path)
	projectName, _ := ProjectName(artifact.OrganizationID)
	repository, _ := RepositoryName(artifact.ProjectID, artifact.OutputName)
	fullName, _ := fullRepository(projectName, repository)
	registry := newFakeDistribution(t, fullName, "scoped-token")
	client, _ := NewDistributionClient(registry.server.Client())
	capability := PushCapability{
		Registry: registry.server.URL, Repository: "builds/foreign/api", Token: registry.token,
	}
	if _, err := client.ManifestExists(t.Context(), capability, projectName, identity); err == nil {
		t.Fatal("expected cross-repository request denial")
	}
}

func registryOCIFixture(t *testing.T) (buildworker.ExportedArtifact, string) {
	t.Helper()
	config := []byte(`{"architecture":"amd64","config":{"Cmd":["/app"]},"os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
	layer := []byte("registry-layer")
	configDescriptor := ocispecs.Descriptor{MediaType: ocispecs.MediaTypeImageConfig, Digest: digest.FromBytes(config), Size: int64(len(config))}
	layerDescriptor := ocispecs.Descriptor{MediaType: ocispecs.MediaTypeImageLayer, Digest: digest.FromBytes(layer), Size: int64(len(layer))}
	manifest := ocispecs.Manifest{Versioned: specsVersion(), MediaType: ocispecs.MediaTypeImageManifest, Config: configDescriptor, Layers: []ocispecs.Descriptor{layerDescriptor}}
	manifestBytes, _ := json.Marshal(manifest)
	manifestDescriptor := ocispecs.Descriptor{MediaType: ocispecs.MediaTypeImageManifest, Digest: digest.FromBytes(manifestBytes), Size: int64(len(manifestBytes))}
	index := ocispecs.Index{Versioned: specsVersion(), MediaType: ocispecs.MediaTypeImageIndex, Manifests: []ocispecs.Descriptor{manifestDescriptor}}
	indexBytes, _ := json.Marshal(index)
	layout := []byte(`{"imageLayoutVersion":"1.0.0"}`)
	entries := map[string][]byte{
		"oci-layout": layout, "index.json": indexBytes,
		"blobs/sha256/" + manifestDescriptor.Digest.Encoded(): manifestBytes,
		"blobs/sha256/" + configDescriptor.Digest.Encoded():   config,
		"blobs/sha256/" + layerDescriptor.Digest.Encoded():    layer,
	}
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	names := []string{"oci-layout", "index.json", "blobs/sha256/" + manifestDescriptor.Digest.Encoded(), "blobs/sha256/" + configDescriptor.Digest.Encoded(), "blobs/sha256/" + layerDescriptor.Digest.Encoded()}
	for _, name := range names {
		contents := entries[name]
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(contents)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
		if _, err := writer.Write(contents); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	path := filepath.Join(t.TempDir(), "artifact.oci.tar")
	if err := os.WriteFile(path, archive.Bytes(), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	digestBytes := sha256.Sum256(archive.Bytes())
	return buildworker.ExportedArtifact{
		OrganizationID: registryOrgID, ProjectID: registryProjectID, BuildID: registryBuildID, Attempt: 1,
		OutputName: "api", Kind: "oci_image", Path: path,
		Digest: "sha256:" + hex.EncodeToString(digestBytes[:]), Size: int64(archive.Len()),
	}, manifestDescriptor.Digest.String()
}

func specsVersion() specs.Versioned { return specs.Versioned{SchemaVersion: 2} }
