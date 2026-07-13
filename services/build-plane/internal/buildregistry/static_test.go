package buildregistry

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	"github.com/minio/minio-go/v7"
)

type memoryStaticManifestStore struct {
	mu       sync.Mutex
	manifest StaticPublicationManifest
	puts     int
	err      error
}

func (store *memoryStaticManifestStore) PutImmutable(_ context.Context, manifest StaticPublicationManifest) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.err != nil {
		return "", store.err
	}
	if err := validateStaticPublicationManifest(manifest); err != nil {
		return "", err
	}
	if store.puts > 0 && store.manifest.ManifestDigest != manifest.ManifestDigest {
		return "", ErrConflict
	}
	store.manifest = manifest
	store.puts++
	return "s3://static-publications/manifest.json", nil
}

func TestPublisherPackagesStaticBundleAndCommitsPublicationManifest(t *testing.T) {
	t.Parallel()
	artifact := staticArtifactFixture(t)
	artifact, evidence := withRegistryEvidence(t, artifact)
	projectName, _ := ProjectName(artifact.OrganizationID)
	repository, _ := RepositoryName(artifact.ProjectID, artifact.OutputName)
	fullName, _ := fullRepository(projectName, repository)
	registry := newFakeDistribution(t, fullName, "scoped-token")
	broker := &publisherBroker{registry: registry.server.URL, repository: repository, token: registry.token}
	distribution, _ := NewDistributionClient(registry.server.Client())
	manifests := new(memoryStaticManifestStore)
	staging := t.TempDir()
	publisher, err := NewPublisher(PublisherConfig{
		Broker: broker, Registry: distribution, RegistryOrigin: registry.server.URL, Evidence: evidence,
		Clock: func() time.Time { return registryNow }, StagingRoot: staging, StaticStore: manifests,
	})
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
	if first != second || first.ManifestDigest == "" || first.PublicationManifestRef != "s3://static-publications/manifest.json" || registry.blobPuts != 8 || registry.manifestPuts != 7 || first.SupplyChain.PolicyState != "accepted" {
		t.Fatalf("first=%#v second=%#v registry=%#v", first, second, registry)
	}
	if manifests.puts != 2 || manifests.manifest.SourceDigest != artifact.Digest || manifests.manifest.SourceSize != artifact.Size || len(manifests.manifest.Files) != 2 || manifests.manifest.OCIReference != first.Reference {
		t.Fatalf("publication manifest=%#v", manifests.manifest)
	}
	entries, err := os.ReadDir(staging)
	if err != nil || len(entries) != 0 {
		t.Fatalf("static staging residue=%#v error=%v", entries, err)
	}
}

func TestPublisherStaticManifestFailureFailsBuildAfterRevocation(t *testing.T) {
	t.Parallel()
	artifact := staticArtifactFixture(t)
	artifact, evidence := withRegistryEvidence(t, artifact)
	projectName, _ := ProjectName(artifact.OrganizationID)
	repository, _ := RepositoryName(artifact.ProjectID, artifact.OutputName)
	fullName, _ := fullRepository(projectName, repository)
	registry := newFakeDistribution(t, fullName, "scoped-token")
	broker := &publisherBroker{registry: registry.server.URL, repository: repository, token: registry.token}
	distribution, _ := NewDistributionClient(registry.server.Client())
	publisher, _ := NewPublisher(PublisherConfig{
		Broker: broker, Registry: distribution, RegistryOrigin: registry.server.URL, Evidence: evidence,
		Clock: func() time.Time { return registryNow }, StagingRoot: t.TempDir(),
		StaticStore: &memoryStaticManifestStore{err: errors.New("object store unavailable")},
	})
	if committed, err := publisher.Commit(t.Context(), artifact); err == nil || committed.Reference != "" || broker.revokes != 1 {
		t.Fatalf("committed=%#v error=%v revokes=%d", committed, err, broker.revokes)
	}
}

func staticArtifactFixture(t *testing.T) buildworker.ExportedArtifact {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "assets"), 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("Write index: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "assets", "app.js"), []byte("app"), 0o600); err != nil {
		t.Fatalf("Write app: %v", err)
	}
	digest, size, err := buildworker.ExportedArtifactIdentity(root, "static_bundle")
	if err != nil {
		t.Fatalf("ExportedArtifactIdentity: %v", err)
	}
	return buildworker.ExportedArtifact{
		OrganizationID: registryOrgID, ProjectID: registryProjectID, BuildID: registryBuildID, Attempt: 1,
		OutputName: "site", Kind: "static_bundle", Path: root, Digest: digest, Size: size,
	}
}

type fakeStaticObjectClient struct {
	mu       sync.Mutex
	contents []byte
	info     minio.ObjectInfo
	conflict bool
}

func (client *fakeStaticObjectClient) PutObject(_ context.Context, _, key string, reader io.Reader, size int64, options minio.PutObjectOptions) (minio.UploadInfo, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.contents != nil {
		return minio.UploadInfo{}, minio.ErrorResponse{Code: "PreconditionFailed"}
	}
	contents, err := io.ReadAll(reader)
	if err != nil || int64(len(contents)) != size || !strings.HasSuffix(key, ".json") {
		return minio.UploadInfo{}, errors.New("invalid immutable put")
	}
	client.contents = contents
	client.info = minio.ObjectInfo{Size: size, UserMetadata: options.UserMetadata}
	return minio.UploadInfo{Size: size}, nil
}

func (client *fakeStaticObjectClient) StatObject(context.Context, string, string, minio.StatObjectOptions) (minio.ObjectInfo, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	info := client.info
	if client.conflict {
		info.Size++
	}
	return info, nil
}

func TestS3StaticManifestStoreIsImmutableAndDetectsConflict(t *testing.T) {
	t.Parallel()
	artifact := staticArtifactFixture(t)
	manifest := StaticPublicationManifest{
		Version: StaticManifestVersion, OrganizationID: artifact.OrganizationID, ProjectID: artifact.ProjectID, BuildID: artifact.BuildID,
		OutputName: artifact.OutputName, SourceDigest: artifact.Digest, SourceSize: artifact.Size,
		OCIReference: "registry.example.invalid/lrail/site@sha256:" + strings.Repeat("a", 64), ManifestDigest: "sha256:" + strings.Repeat("a", 64),
		Files: []StaticFile{{Path: "assets/app.js", Digest: "sha256:" + strings.Repeat("b", 64), Size: 3, Mode: 0o444}, {Path: "index.html", Digest: "sha256:" + strings.Repeat("c", 64), Size: 5, Mode: 0o444}},
	}
	client := new(fakeStaticObjectClient)
	store, err := NewS3StaticManifestStore(client, "static-bucket", "publications/v1")
	if err != nil {
		t.Fatalf("NewS3StaticManifestStore: %v", err)
	}
	first, err := store.PutImmutable(t.Context(), manifest)
	if err != nil {
		t.Fatalf("PutImmutable: %v", err)
	}
	second, err := store.PutImmutable(t.Context(), manifest)
	if err != nil || first != second || !strings.HasPrefix(first, "s3://static-bucket/publications/v1/") {
		t.Fatalf("first=%q second=%q error=%v", first, second, err)
	}
	client.conflict = true
	if _, err := store.PutImmutable(t.Context(), manifest); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected immutable conflict, got %v", err)
	}
}
