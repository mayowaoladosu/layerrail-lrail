package integration

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildsupply"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
	ocidigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
)

type integrationEvidenceSigner struct {
	private ed25519.PrivateKey
	public  []byte
}

type integrationEvidenceCommitter struct{ inner buildworker.ArtifactCommitter }

func (committer integrationEvidenceCommitter) Commit(ctx context.Context, artifact buildworker.ExportedArtifact) (buildworker.CommittedArtifact, error) {
	committed, err := committer.inner.Commit(ctx, artifact)
	if err != nil {
		return buildworker.CommittedArtifact{}, err
	}
	manifestDigest := artifact.Digest
	if artifact.Kind == "oci_image" {
		identity, inspectErr := buildworker.InspectOCIArtifact(artifact.Path)
		if inspectErr != nil {
			return buildworker.CommittedArtifact{}, inspectErr
		}
		manifestDigest = identity.ManifestDigest
		committed.ManifestDigest = manifestDigest
	}
	repository := "registry.example.invalid/lrail/" + artifact.OutputName
	committed.Reference = repository + "@" + manifestDigest
	kinds := []string{"sbom", "vulnerability_scan", "provenance", "signature", "policy_decision"}
	var references [5]buildworker.EvidenceReference
	for index, kind := range kinds {
		manifest := "sha256:" + strings.Repeat(string("12345"[index]), 64)
		payload := "sha256:" + strings.Repeat(string("6789a"[index]), 64)
		references[index] = buildworker.EvidenceReference{Kind: kind, Reference: repository + "@" + manifest, ManifestDigest: manifest, PayloadDigest: payload}
	}
	committed.SupplyChain = buildworker.SupplyChainResult{
		PolicyState: "accepted", ScanState: "passed", PolicyDigest: artifact.Provenance.PolicyDigest,
		SignerKeyID: artifact.Provenance.SupplyChain.SignerKeyID, SignerKeyVersion: 1,
		SignerPublicKeyDigest: artifact.Provenance.SupplyChain.AllowedSignerPublicKeyDigests[0], Evidence: references,
	}
	return committed, nil
}

func (signer integrationEvidenceSigner) Sign(_ context.Context, request buildsupply.SigningRequest) (buildsupply.Signature, error) {
	return buildsupply.Signature{
		KeyID: llbcompiler.DefaultBuildSignerKeyID, KeyVersion: 1, Algorithm: buildsupply.SignatureAlgorithm,
		PublicKeyPEM: signer.public, Value: ed25519.Sign(signer.private, request.Payload),
	}, nil
}

func TestRealSyftTrivyPipelineAcceptsCleanAndDeniesSeededLayerSecret(t *testing.T) {
	if os.Getenv("LRAIL_EVIDENCE_INTEGRATION") != "1" {
		t.Skip("set LRAIL_EVIDENCE_INTEGRATION=1")
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x75}, ed25519.SeedSize))
	der, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	publicHash := sha256.Sum256(der)
	policy := llbcompiler.PlatformSupplyChainPolicy([]string{"sha256:" + hex.EncodeToString(publicHash[:])})
	scanner, err := buildsupply.NewCommandScanner(buildsupply.CommandScannerConfig{
		SyftPath: requiredEvidenceEnv(t, "LRAIL_SYFT_PATH"), TrivyPath: requiredEvidenceEnv(t, "LRAIL_TRIVY_PATH"),
		TrivyCacheDir: requiredEvidenceEnv(t, "LRAIL_TRIVY_CACHE_DIR"), TrivyDBMetadata: requiredEvidenceEnv(t, "LRAIL_TRIVY_DB_METADATA"),
		SecretConfigPath: requiredEvidenceEnv(t, "LRAIL_TRIVY_SECRET_CONFIG"), WorkRoot: t.TempDir(),
		ScanTimeout: 5 * time.Minute, MaxDBAge: 48 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewCommandScanner: %v", err)
	}
	pipeline, err := buildsupply.NewPipeline(scanner, integrationEvidenceSigner{private: private, public: public})
	if err != nil {
		t.Fatal(err)
	}
	clean := evidenceIntegrationRequest(t, []byte("ordinary application configuration\n"), policy)
	bundle, err := pipeline.Generate(t.Context(), clean)
	if err != nil || bundle.PolicyState != "accepted" || bundle.ScanState != "passed" || len(bundle.Attestations) != 4 {
		var denial *buildsupply.Denial
		_ = errors.As(err, &denial)
		t.Fatalf("clean bundle=%#v denial=%#v error=%v", bundle, denial, err)
	}
	seeded := evidenceIntegrationRequest(t, []byte("LRAIL_SECRET_CANARY_ABCDEFGHIJKLMNOPQRSTUVWX\n"), policy)
	if _, err := pipeline.Generate(t.Context(), seeded); !errors.Is(err, buildsupply.ErrDenied) {
		t.Fatalf("seeded secret error=%v", err)
	} else {
		var denial *buildsupply.Denial
		if !errors.As(err, &denial) || denial.Code != "security_secret_found" || denial.Summary.Secrets == 0 {
			t.Fatalf("seeded secret denial=%#v", denial)
		}
	}
}

func evidenceIntegrationRequest(t *testing.T, layerFile []byte, policy llbcompiler.SupplyChainPolicy) buildsupply.GenerateRequest {
	t.Helper()
	archive, identity := evidenceOCIArchive(t, layerFile)
	path := filepath.Join(t.TempDir(), "artifact.oci.tar")
	if err := os.WriteFile(path, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	archiveHash := sha256.Sum256(archive)
	archiveDigest := "sha256:" + hex.EncodeToString(archiveHash[:])
	artifact := buildworker.ExportedArtifact{
		OrganizationID: "org_019b01da-7e31-7000-8000-000000000071", ProjectID: "prj_019b01da-7e31-7000-8000-000000000072",
		BuildID: "bld_019b01da-7e31-7000-8000-000000000073", Attempt: 1, OutputName: "api", Kind: "oci_image",
		Path: path, Digest: archiveDigest, Size: int64(len(archive)),
		Provenance: buildworker.ProvenanceContext{
			AssignmentDigest: "sha256:" + strings.Repeat("1", 64), DefinitionDigest: "sha256:" + strings.Repeat("2", 64),
			IRDigest: "sha256:" + strings.Repeat("3", 64), PolicyDigest: "sha256:" + strings.Repeat("4", 64),
			SourceSnapshot: "sha256:" + strings.Repeat("5", 64), SourceArchive: "sha256:" + strings.Repeat("6", 64),
			TargetPlatform: "linux/amd64", BuilderIdentity: "spiffe://lrail.internal/build-cell/integration", CompilerVersion: "0.2.0",
			AssignmentIssuedAt: "2026-07-13T10:00:00Z", AssignmentExpiresAt: "2026-07-13T11:00:00Z",
			BuildArguments: []llbcompiler.NameValue{}, BaseMaterials: []llbcompiler.BaseMaterial{}, Network: []llbcompiler.NetworkCapability{}, SecretNames: []string{}, SupplyChain: policy,
		},
	}
	return buildsupply.GenerateRequest{
		Artifact: artifact, OCIPath: path, OCIArchiveDigest: archiveDigest, OCIArchiveSize: int64(len(archive)), Identity: identity,
		RepositoryReference: "registry.example.invalid/lrail/integration/api",
	}
}

func evidenceOCIArchive(t *testing.T, fileContents []byte) ([]byte, buildworker.OCIArtifactIdentity) {
	t.Helper()
	var uncompressed bytes.Buffer
	layerWriter := tar.NewWriter(&uncompressed)
	if err := layerWriter.WriteHeader(&tar.Header{Name: "app/config.txt", Mode: 0o444, Size: int64(len(fileContents)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := layerWriter.Write(fileContents); err != nil {
		t.Fatal(err)
	}
	if err := layerWriter.Close(); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	gzipWriter, _ := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	gzipWriter.Header.ModTime = time.Unix(0, 0).UTC()
	gzipWriter.Header.OS = 255
	_, _ = gzipWriter.Write(uncompressed.Bytes())
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	diffID := ocidigest.FromBytes(uncompressed.Bytes())
	configBytes, _ := canonicaljson.Marshal(ocispecs.Image{
		Platform: ocispecs.Platform{Architecture: "amd64", OS: "linux"},
		Config: ocispecs.ImageConfig{
			User: "65532:65532", WorkingDir: "/app", Entrypoint: []string{"/app/server"},
			Labels: map[string]string{"org.opencontainers.image.source": "https://example.invalid/source"},
		},
		RootFS: ocispecs.RootFS{Type: "layers", DiffIDs: []ocidigest.Digest{diffID}},
	})
	config := ocispecs.Descriptor{MediaType: ocispecs.MediaTypeImageConfig, Digest: ocidigest.FromBytes(configBytes), Size: int64(len(configBytes))}
	layer := ocispecs.Descriptor{MediaType: ocispecs.MediaTypeImageLayerGzip, Digest: ocidigest.FromBytes(compressed.Bytes()), Size: int64(compressed.Len())}
	manifestBytes, _ := canonicaljson.Marshal(ocispecs.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispecs.MediaTypeImageManifest, Config: config, Layers: []ocispecs.Descriptor{layer}})
	manifest := ocispecs.Descriptor{MediaType: ocispecs.MediaTypeImageManifest, Digest: ocidigest.FromBytes(manifestBytes), Size: int64(len(manifestBytes))}
	indexBytes, _ := canonicaljson.Marshal(ocispecs.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispecs.MediaTypeImageIndex, Manifests: []ocispecs.Descriptor{manifest}})
	entries := []struct {
		name     string
		contents []byte
	}{
		{"oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`)}, {"index.json", indexBytes},
		{"blobs/sha256/" + manifest.Digest.Encoded(), manifestBytes}, {"blobs/sha256/" + config.Digest.Encoded(), configBytes}, {"blobs/sha256/" + layer.Digest.Encoded(), compressed.Bytes()},
	}
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	for _, entry := range entries {
		if err := writer.WriteHeader(&tar.Header{Name: entry.name, Mode: 0o600, Size: int64(len(entry.contents)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(entry.contents); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "inspect.oci.tar")
	if err := os.WriteFile(path, archive.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := buildworker.InspectOCIArtifact(path)
	if err != nil {
		t.Fatalf("InspectOCIArtifact: %v", err)
	}
	return archive.Bytes(), identity
}

func requiredEvidenceEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}
