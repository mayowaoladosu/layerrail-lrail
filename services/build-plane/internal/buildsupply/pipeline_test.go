package buildsupply

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
)

const supplyOrgID = "org_019b01da-7e31-7000-8000-000000000001"
const supplyProjectID = "prj_019b01da-7e31-7000-8000-000000000002"
const supplyBuildID = "bld_019b01da-7e31-7000-8000-000000000003"

type fakeScanner struct {
	analysis Analysis
	err      error
	calls    int
}

func (scanner *fakeScanner) Analyze(context.Context, ScanRequest) (Analysis, error) {
	scanner.calls++
	return scanner.analysis, scanner.err
}

type testSigner struct {
	private ed25519.PrivateKey
	public  []byte
	calls   int
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	der, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return &testSigner{private: private, public: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})}
}

func (signer *testSigner) Sign(_ context.Context, request SigningRequest) (Signature, error) {
	signer.calls++
	return Signature{
		KeyID: "lrail-build-evidence", KeyVersion: 3, Algorithm: SignatureAlgorithm,
		PublicKeyPEM: append([]byte(nil), signer.public...), Value: ed25519.Sign(signer.private, request.Payload),
	}, nil
}

func TestPipelineGeneratesDeterministicTrustedEvidenceBundle(t *testing.T) {
	t.Parallel()
	signer := newTestSigner(t)
	request := supplyRequest(t, signer)
	scanner := &fakeScanner{analysis: safeAnalysis(t)}
	pipeline, _ := NewPipeline(scanner, signer)
	first, err := pipeline.Generate(t.Context(), request)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	second, err := pipeline.Generate(t.Context(), request)
	if err != nil {
		t.Fatalf("Generate replay: %v", err)
	}
	if !reflect.DeepEqual(first, second) || first.PolicyState != "accepted" || first.ScanState != "passed" || len(first.Attestations) != 4 || signer.calls != 10 || scanner.calls != 2 {
		t.Fatalf("first=%#v second=%#v signer=%d scanner=%d", first, second, signer.calls, scanner.calls)
	}
	if err := ValidateBundle(request, first); err != nil {
		t.Fatalf("ValidateBundle: %v", err)
	}
}

func TestValidateBundleRejectsMutatedDigestEvidenceAndSignature(t *testing.T) {
	t.Parallel()
	signer := newTestSigner(t)
	request := supplyRequest(t, signer)
	pipeline, _ := NewPipeline(&fakeScanner{analysis: safeAnalysis(t)}, signer)
	bundle, err := pipeline.Generate(t.Context(), request)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for name, mutate := range map[string]func(*Bundle){
		"subject":        func(candidate *Bundle) { candidate.SubjectDigest = "sha256:" + strings.Repeat("f", 64) },
		"attestation":    func(candidate *Bundle) { candidate.Attestations[0].Payload[0] ^= 0xff },
		"payload digest": func(candidate *Bundle) { candidate.Attestations[1].PayloadDigest = "sha256:" + strings.Repeat("a", 64) },
		"signature":      func(candidate *Bundle) { candidate.ImageSignature.Signature[0] ^= 0xff },
		"signer":         func(candidate *Bundle) { candidate.SignerPublicKeyDigest = "sha256:" + strings.Repeat("b", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneBundle(bundle)
			mutate(&candidate)
			if err := ValidateBundle(request, candidate); err == nil {
				t.Fatal("mutated evidence bundle was accepted")
			}
		})
	}
}

func TestPipelineDeniesSecurityFindingsBeforeSigning(t *testing.T) {
	t.Parallel()
	for name, summary := range map[string]ScanSummary{
		"secret":        {Vulnerabilities: map[string]int{}, Secrets: 1, Misconfigurations: map[string]int{}, Licenses: map[string]int{}},
		"critical":      {Vulnerabilities: map[string]int{"CRITICAL": 1}, Misconfigurations: map[string]int{}, Licenses: map[string]int{}},
		"license":       {Vulnerabilities: map[string]int{}, Misconfigurations: map[string]int{}, Licenses: map[string]int{"Forbidden": 1}},
		"configuration": {Vulnerabilities: map[string]int{}, Misconfigurations: map[string]int{"HIGH": 1}, Licenses: map[string]int{}},
	} {
		t.Run(name, func(t *testing.T) {
			signer := newTestSigner(t)
			request := supplyRequest(t, signer)
			analysis := safeAnalysis(t)
			analysis.Summary = summary
			pipeline, _ := NewPipeline(&fakeScanner{analysis: analysis}, signer)
			if _, err := pipeline.Generate(t.Context(), request); !errors.Is(err, ErrDenied) || signer.calls != 0 {
				t.Fatalf("error=%v signer calls=%d", err, signer.calls)
			}
		})
	}
}

func TestScannerNormalizationRedactsSecretValuesAndStabilizesSPDX(t *testing.T) {
	t.Parallel()
	request := ScanRequest{ManifestDigest: "sha256:" + strings.Repeat("a", 64), OutputName: "api", SyftVersion: "1.46.0", TrivyVersion: "0.72.0"}
	sbomRaw := []byte(`{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"random","documentNamespace":"https://random.invalid/uuid","creationInfo":{"created":"2026-07-13T11:00:00Z","creators":["Tool: syft-1.46.0"]},"packages":[]}`)
	first, err := normalizeSPDXDocument(sbomRaw, request)
	if err != nil {
		t.Fatalf("normalizeSPDXDocument: %v", err)
	}
	sbomRaw = bytes.Replace(sbomRaw, []byte("2026-07-13T11:00:00Z"), []byte("2026-07-14T12:00:00Z"), 1)
	second, err := normalizeSPDXDocument(sbomRaw, request)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("normalized SPDX differs: %v", err)
	}
	trivyRaw := []byte(`{"SchemaVersion":2,"Results":[{"Target":"app/credentials","Secrets":[{"RuleID":"aws-secret-access-key","Category":"AWS","Severity":"CRITICAL","StartLine":4,"EndLine":4,"Match":"TOP-SECRET-VALUE"}],"Vulnerabilities":[],"Misconfigurations":[],"Licenses":[]}]}`)
	report, summary, err := normalizeTrivyReport(trivyRaw, request, databaseIdentity{
		Digest: "sha256:" + strings.Repeat("b", 64), MetadataDigest: "sha256:" + strings.Repeat("c", 64), UpdatedAt: "2026-07-13T00:00:00Z",
	})
	if err != nil || summary.Secrets != 1 || bytes.Contains(report, []byte("TOP-SECRET-VALUE")) {
		t.Fatalf("report=%s summary=%#v error=%v", report, summary, err)
	}
}

func safeAnalysis(t *testing.T) Analysis {
	t.Helper()
	sbom, _ := canonicaljson.Normalize([]byte(`{"SPDXID":"SPDXRef-DOCUMENT","creationInfo":{"created":"1970-01-01T00:00:00Z","creators":["Tool: syft-1.46.0"]},"dataLicense":"CC0-1.0","documentNamespace":"https://lrail.internal/sbom/a","name":"api","packages":[],"spdxVersion":"SPDX-2.3"}`))
	scan, _ := canonicaljson.Normalize([]byte(`{"database":{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","metadata_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","updated_at":"2026-07-13T00:00:00Z"},"licenses":[],"misconfigurations":[],"secrets":[],"subject":{"digest":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"name":"api"},"summary":{"licenses":{},"misconfigurations":{},"secrets":0,"vulnerabilities":{}},"tool":{"name":"trivy","version":"0.72.0"},"version":1,"vulnerabilities":[]}`))
	return Analysis{SBOM: sbom, Scan: scan, Summary: ScanSummary{Vulnerabilities: map[string]int{}, Misconfigurations: map[string]int{}, Licenses: map[string]int{}}}
}

func supplyRequest(t *testing.T, signer *testSigner) GenerateRequest {
	t.Helper()
	artifactBytes, identity := supplyOCIArchive(t)
	path := filepath.Join(t.TempDir(), "artifact.oci.tar")
	if err := os.WriteFile(path, artifactBytes, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, publicDigest, err := parsePublicKey(signer.public)
	if err != nil {
		t.Fatalf("parsePublicKey: %v", err)
	}
	artifactDigest := sha256.Sum256(artifactBytes)
	return GenerateRequest{
		Artifact: buildworker.ExportedArtifact{
			OrganizationID: supplyOrgID, ProjectID: supplyProjectID, BuildID: supplyBuildID, Attempt: 1,
			OutputName: "api", Kind: "oci_image", Path: path, Digest: "sha256:" + hex.EncodeToString(artifactDigest[:]), Size: int64(len(artifactBytes)),
			Provenance: supplyProvenance(publicDigest),
		},
		OCIPath: path, OCIArchiveDigest: "sha256:" + hex.EncodeToString(artifactDigest[:]), OCIArchiveSize: int64(len(artifactBytes)),
		Identity: identity, RepositoryReference: "registry.example.invalid/lrail/builds/api",
	}
}

func supplyProvenance(publicDigest string) buildworker.ProvenanceContext {
	return buildworker.ProvenanceContext{
		AssignmentDigest: "sha256:" + strings.Repeat("1", 64), DefinitionDigest: "sha256:" + strings.Repeat("2", 64),
		IRDigest: "sha256:" + strings.Repeat("3", 64), PolicyDigest: "sha256:" + strings.Repeat("4", 64),
		SourceSnapshot: "sha256:" + strings.Repeat("5", 64), SourceArchive: "sha256:" + strings.Repeat("6", 64),
		TargetPlatform: "linux/amd64", BuilderIdentity: "spiffe://lrail.internal/build-cell/cell-test", CompilerVersion: "0.2.0",
		AssignmentIssuedAt: "2026-07-13T10:00:00Z", AssignmentExpiresAt: "2026-07-13T11:00:00Z",
		BuildArguments: []llbcompiler.NameValue{}, BaseMaterials: []llbcompiler.BaseMaterial{}, Network: []llbcompiler.NetworkCapability{}, SecretNames: []string{},
		SupplyChain: llbcompiler.SupplyChainPolicy{
			Version: llbcompiler.CurrentSupplyChainPolicyVersion, SyftVersion: "1.46.0", TrivyVersion: "0.72.0",
			SignerKeyID: "lrail-build-evidence", AllowedSignerPublicKeyDigests: []string{publicDigest},
			DeniedVulnerabilitySeverities: []string{"CRITICAL"}, DeniedConfigurationSeverities: []string{"CRITICAL", "HIGH"},
			DeniedLicenseClassifications: []string{"Forbidden"}, RequireSecretFree: true, RequireImageConfigurationScan: true,
		},
	}
}

func supplyOCIArchive(t *testing.T) ([]byte, buildworker.OCIArtifactIdentity) {
	t.Helper()
	config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
	layer := []byte("safe-layer")
	configDescriptor := ocispecs.Descriptor{MediaType: ocispecs.MediaTypeImageConfig, Digest: digest.FromBytes(config), Size: int64(len(config))}
	layerDescriptor := ocispecs.Descriptor{MediaType: ocispecs.MediaTypeImageLayer, Digest: digest.FromBytes(layer), Size: int64(len(layer))}
	manifestBytes, _ := canonicaljson.Marshal(ocispecs.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispecs.MediaTypeImageManifest, Config: configDescriptor, Layers: []ocispecs.Descriptor{layerDescriptor}})
	manifestDescriptor := ocispecs.Descriptor{MediaType: ocispecs.MediaTypeImageManifest, Digest: digest.FromBytes(manifestBytes), Size: int64(len(manifestBytes))}
	indexBytes, _ := canonicaljson.Marshal(ocispecs.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispecs.MediaTypeImageIndex, Manifests: []ocispecs.Descriptor{manifestDescriptor}})
	entries := []struct {
		name     string
		contents []byte
	}{
		{"oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`)}, {"index.json", indexBytes},
		{"blobs/sha256/" + manifestDescriptor.Digest.Encoded(), manifestBytes}, {"blobs/sha256/" + configDescriptor.Digest.Encoded(), config}, {"blobs/sha256/" + layerDescriptor.Digest.Encoded(), layer},
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

func cloneBundle(bundle Bundle) Bundle {
	clone := bundle
	clone.SignerPublicKeyPEM = append([]byte(nil), bundle.SignerPublicKeyPEM...)
	clone.ImageSignature.Payload = append([]byte(nil), bundle.ImageSignature.Payload...)
	clone.ImageSignature.Signature = append([]byte(nil), bundle.ImageSignature.Signature...)
	clone.Attestations = append([]SignedPayload(nil), bundle.Attestations...)
	for index := range clone.Attestations {
		clone.Attestations[index].Payload = append([]byte(nil), bundle.Attestations[index].Payload...)
		clone.Attestations[index].Signature = append([]byte(nil), bundle.Attestations[index].Signature...)
	}
	return clone
}
