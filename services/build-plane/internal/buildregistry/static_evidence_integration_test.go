package buildregistry

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildsupply"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
)

func TestRealStaticBundleEvidenceAcceptsCleanAndDeniesSeededLayerSecret(t *testing.T) {
	if os.Getenv("LRAIL_EVIDENCE_INTEGRATION") != "1" {
		t.Skip("set LRAIL_EVIDENCE_INTEGRATION=1")
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x63}, ed25519.SeedSize))
	der, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	scanner, err := buildsupply.NewCommandScanner(buildsupply.CommandScannerConfig{
		SyftPath: requiredStaticEvidenceEnv(t, "LRAIL_SYFT_PATH"), TrivyPath: requiredStaticEvidenceEnv(t, "LRAIL_TRIVY_PATH"),
		TrivyCacheDir: requiredStaticEvidenceEnv(t, "LRAIL_TRIVY_CACHE_DIR"), TrivyDBMetadata: requiredStaticEvidenceEnv(t, "LRAIL_TRIVY_DB_METADATA"),
		SecretConfigPath: requiredStaticEvidenceEnv(t, "LRAIL_TRIVY_SECRET_CONFIG"), WorkRoot: filepath.Join(t.TempDir(), "scanner"),
		ScanTimeout: 5 * time.Minute, MaxDBAge: 48 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewCommandScanner: %v", err)
	}
	pipeline, err := buildsupply.NewPipeline(scanner, registryEvidenceSigner{private: private, public: public})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		seed bool
	}{
		{name: "clean"},
		{name: "seeded secret", seed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			artifact := staticArtifactFixture(t)
			if test.seed {
				if err := os.WriteFile(filepath.Join(artifact.Path, "assets", "canary.txt"), []byte("LRAIL_SECRET_CANARY_ABCDEFGHIJKLMNOPQRSTUVWX\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				digest, size, err := buildworker.ExportedArtifactIdentity(artifact.Path, artifact.Kind)
				if err != nil {
					t.Fatal(err)
				}
				artifact.Digest, artifact.Size = digest, size
			}
			artifact, _, _ = registryEvidenceMaterials(t, artifact)
			projectName, _ := ProjectName(artifact.OrganizationID)
			repository, _ := RepositoryName(artifact.ProjectID, artifact.OutputName)
			fullName, _ := fullRepository(projectName, repository)
			registry := newFakeDistribution(t, fullName, "scoped-token")
			broker := &publisherBroker{registry: registry.server.URL, repository: repository, token: registry.token}
			distribution, _ := NewDistributionClient(registry.server.Client())
			publisher, err := NewPublisher(PublisherConfig{
				Broker: broker, Registry: distribution, RegistryOrigin: registry.server.URL, Evidence: pipeline,
				Clock: func() time.Time { return registryNow }, StagingRoot: t.TempDir(), StaticStore: new(memoryStaticManifestStore),
			})
			if err != nil {
				t.Fatal(err)
			}
			committed, err := publisher.Commit(t.Context(), artifact)
			if !test.seed {
				if err != nil || committed.Reference == "" || committed.SupplyChain.PolicyState != "accepted" || broker.issues != 1 {
					t.Fatalf("committed=%#v broker=%#v error=%v", committed, broker, err)
				}
				return
			}
			var denial *buildsupply.Denial
			if !errors.Is(err, buildsupply.ErrDenied) || !errors.As(err, &denial) || denial.Code != "security_secret_found" ||
				committed.Reference != "" || broker.issues != 0 || registry.blobPuts != 0 || registry.manifestPuts != 0 {
				t.Fatalf("committed=%#v denial=%#v broker=%#v registry=%#v error=%v", committed, denial, broker, registry, err)
			}
		})
	}
}

func requiredStaticEvidenceEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}
