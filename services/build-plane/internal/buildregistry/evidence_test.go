package buildregistry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildsupply"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
)

type registryEvidenceScanner struct{}

type generatorFunc func(context.Context, buildsupply.GenerateRequest) (buildsupply.Bundle, error)

func (generate generatorFunc) Generate(ctx context.Context, request buildsupply.GenerateRequest) (buildsupply.Bundle, error) {
	return generate(ctx, request)
}

func (registryEvidenceScanner) Analyze(context.Context, buildsupply.ScanRequest) (buildsupply.Analysis, error) {
	sbom, _ := canonicaljson.Normalize([]byte(`{"SPDXID":"SPDXRef-DOCUMENT","creationInfo":{"created":"1970-01-01T00:00:00Z","creators":["Tool: syft-1.46.0"]},"dataLicense":"CC0-1.0","documentNamespace":"https://lrail.internal/sbom/fixture","name":"api","packages":[],"spdxVersion":"SPDX-2.3"}`))
	scan, _ := canonicaljson.Normalize([]byte(`{"database":{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","metadata_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","updated_at":"2026-07-13T00:00:00Z"},"licenses":[],"misconfigurations":[],"secrets":[],"subject":{"digest":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"name":"api"},"summary":{"licenses":{},"misconfigurations":{},"secrets":0,"vulnerabilities":{}},"tool":{"name":"trivy","version":"0.72.0"},"version":1,"vulnerabilities":[]}`))
	return buildsupply.Analysis{
		SBOM: sbom, Scan: scan,
		Summary: buildsupply.ScanSummary{Vulnerabilities: map[string]int{}, Misconfigurations: map[string]int{}, Licenses: map[string]int{}},
	}, nil
}

type registryEvidenceSigner struct {
	private ed25519.PrivateKey
	public  []byte
}

func (signer registryEvidenceSigner) Sign(_ context.Context, request buildsupply.SigningRequest) (buildsupply.Signature, error) {
	return buildsupply.Signature{
		KeyID: llbcompiler.DefaultBuildSignerKeyID, KeyVersion: 1, Algorithm: buildsupply.SignatureAlgorithm,
		PublicKeyPEM: append([]byte(nil), signer.public...), Value: ed25519.Sign(signer.private, request.Payload),
	}, nil
}

func withRegistryEvidence(t *testing.T, artifact buildworker.ExportedArtifact) (buildworker.ExportedArtifact, buildsupply.Generator) {
	artifact, pipeline, _ := registryEvidenceMaterials(t, artifact)
	return artifact, pipeline
}

func registryEvidenceMaterials(t *testing.T, artifact buildworker.ExportedArtifact) (buildworker.ExportedArtifact, buildsupply.Generator, []byte) {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x63}, ed25519.SeedSize))
	der, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	publicDigest := sha256.Sum256(der)
	artifact.Provenance = buildworker.ProvenanceContext{
		AssignmentDigest: "sha256:" + strings.Repeat("1", 64), DefinitionDigest: "sha256:" + strings.Repeat("2", 64),
		IRDigest: "sha256:" + strings.Repeat("3", 64), PolicyDigest: "sha256:" + strings.Repeat("4", 64),
		SourceSnapshot: "sha256:" + strings.Repeat("5", 64), SourceArchive: "sha256:" + strings.Repeat("6", 64),
		TargetPlatform: "linux/amd64", BuilderIdentity: "spiffe://lrail.internal/build-cell/fixture", CompilerVersion: "0.2.0",
		AssignmentIssuedAt: "2026-07-13T10:00:00Z", AssignmentExpiresAt: "2026-07-13T11:00:00Z",
		BuildArguments: []llbcompiler.NameValue{}, BaseMaterials: []llbcompiler.BaseMaterial{}, Network: []llbcompiler.NetworkCapability{}, SecretNames: []string{},
		SupplyChain: llbcompiler.PlatformSupplyChainPolicy([]string{"sha256:" + hex.EncodeToString(publicDigest[:])}),
	}
	pipeline, err := buildsupply.NewPipeline(registryEvidenceScanner{}, registryEvidenceSigner{private: private, public: public})
	if err != nil {
		t.Fatal(err)
	}
	return artifact, pipeline, append([]byte(nil), public...)
}
