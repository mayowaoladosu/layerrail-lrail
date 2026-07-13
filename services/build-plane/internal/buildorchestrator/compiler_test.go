package buildorchestrator

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
)

const (
	testBaseDigest    = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testSignerDigest  = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	testBaseReference = "docker.io/library/golang:1.26-alpine@" + testBaseDigest
	testBaseSignature = "upstream-unverified:docker.io"
	testPolicyID      = "pol_019b01da-7e31-7000-8000-000000000007"
)

func validPolicy() llbcompiler.Policy {
	return llbcompiler.Policy{
		APIVersion: llbcompiler.CurrentPolicyAPIVersion,
		ID:         testPolicyID,
		Revision:   "1.0.0",
		Base: llbcompiler.BasePolicy{
			AllowedRegistries: []string{"docker.io"}, AllowCustomerBases: true,
			AllowedSignatureIdentities: []string{testBaseSignature},
		},
		Network: llbcompiler.NetworkPolicy{
			AllowedProfiles: []string{"none", "packages"}, PackageHosts: []string{"proxy.golang.org", "sum.golang.org"},
			PackageGatewayID: "gateway.packages.v1",
		},
		Cache:          llbcompiler.CachePolicy{Scope: "project", TrustDomain: "trusted-builds-v1"},
		Secrets:        llbcompiler.SecretPolicy{AllowedNames: []string{}},
		BuildArguments: llbcompiler.BuildArgumentPolicy{AllowedNames: []string{}},
		SupplyChain: llbcompiler.SupplyChainPolicy{
			Version: llbcompiler.CurrentSupplyChainPolicyVersion, SyftVersion: llbcompiler.CurrentSyftVersion,
			TrivyVersion: llbcompiler.CurrentTrivyVersion, SignerKeyID: llbcompiler.DefaultBuildSignerKeyID,
			AllowedSignerPublicKeyDigests: []string{testSignerDigest}, DeniedVulnerabilitySeverities: []string{"CRITICAL"},
			DeniedConfigurationSeverities: []string{"CRITICAL", "HIGH"}, DeniedLicenseClassifications: []string{"Forbidden"},
			RequireSecretFree: true, RequireImageConfigurationScan: true,
		},
	}
}

func validCatalog(t *testing.T) BaseCatalog {
	t.Helper()
	material := llbcompiler.BaseMaterial{
		RequestedRef: testBaseReference, ResolvedRef: testBaseReference, Digest: testBaseDigest,
		Registry: "docker.io", Classification: "customer", Platforms: []string{"linux/amd64"},
		SignatureIdentity: testBaseSignature,
	}
	var err error
	material.ResolutionDigest, err = llbcompiler.ResolutionDigest(material)
	if err != nil {
		t.Fatalf("ResolutionDigest: %v", err)
	}
	return BaseCatalog{Version: "1.0.0", Entries: []BaseEntry{{Language: "go", Material: material}}}
}

func validDetection() DetectionResult {
	version := "1.26"
	port := 8080
	return DetectionResult{
		SchemaVersion: DetectorSchemaVersion, ProposalVersion: 1, DetectorVersion: DetectorVersion,
		RulesetVersion: "2026-07-13.1", SourceSnapshotID: testSnapshotID, SnapshotRoot: ".",
		Plugins: []DetectorPlugin{{Plugin: "go", Version: "1.0.0"}},
		Services: []DetectedService{{
			Name: "api", Root: ".", Kind: "web", Language: "go", Framework: "Go net/http",
			Runtime: DetectedRuntime{Name: "go", Version: &version},
			Build: DetectedBuild{
				Strategy: "auto", InstallCommand: []string{"go", "mod", "download"},
				BuildCommand: []string{"go", "build", "-trimpath", "-o", "out/web", "."},
				CachePaths:   []string{".cache/go-build"}, RequiredFiles: []string{"go.mod", "go.sum", "main.go"},
			},
			Processes:  []DetectedProcess{{Name: "web", Kind: "web", Command: []string{"/app/out/web"}, Port: &port, Protocol: "http"}},
			Confidence: 0.93, EvidenceIDs: []string{"ev_aaaaaaaaaaaaaaaaaaaa"}, FilesConsidered: []string{"go.mod", "go.sum", "main.go"},
		}},
		EvidenceGraph: []byte(`{"nodes":[],"edges":[]}`), Warnings: []json.RawMessage{}, Unresolved: []json.RawMessage{},
		UnsupportedFeatures: []string{}, SuggestedAddons: []json.RawMessage{}, FilesConsidered: []string{"go.mod", "go.sum", "main.go"},
		GeneratedManifest: []byte(`{"api_version":"lrail.dev/v1"}`), Blocked: false,
	}
}

func TestGenerateRecipeOwnsDetectorToStarlarkTranslation(t *testing.T) {
	t.Parallel()
	detection := validDetection()
	if err := detection.Validate(testSnapshotID, "."); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	program, materials, err := GenerateRecipe(detection, validCatalog(t), "linux/amd64")
	if err != nil {
		t.Fatalf("GenerateRecipe: %v", err)
	}
	text := string(program)
	for _, required := range []string{
		"source(path = \".\"", "image(ref = \"" + testBaseReference + "\")", "argv = [\"go\", \"mod\", \"download\"]",
		"network = \"packages\"", "user = \"10001:10001\"", "cmd = [\"/workspace/out/web\"]", "ports = [8080]",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("generated recipe lacks %q:\n%s", required, text)
		}
	}
	if len(materials) != 1 || materials[0].RequestedRef != testBaseReference {
		t.Fatalf("materials = %#v", materials)
	}
}

func TestDefinitionCompilerProducesPolicyLockedRealLLB(t *testing.T) {
	t.Parallel()
	compiler, err := NewDefinitionCompiler(validPolicy(), validCatalog(t), "0.3.0", "0.2.0")
	if err != nil {
		t.Fatalf("NewDefinitionCompiler: %v", err)
	}
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	request := validRequest(now)
	result, err := compiler.Compile(context.Background(), request, t.TempDir(), validDetection())
	if err != nil {
		program, _, recipeErr := GenerateRecipe(validDetection(), validCatalog(t), request.TargetPlatform)
		t.Fatalf("Compile: %v (recipe error: %v)\n%s", err, recipeErr, program)
	}
	if !result.Generated || result.IRDigest == "" || result.DefinitionDigest == "" || result.PolicyDigest == "" ||
		len(result.IRBytes) == 0 || len(result.LockBytes) == 0 || len(result.Outputs) != 1 || len(result.Outputs[0].Definition) == 0 {
		t.Fatalf("incomplete compilation: %#v", result)
	}
	if result.Lock.SourceSnapshot != request.Source.SnapshotDigest || len(result.Lock.BaseMaterials) != 1 || len(result.Lock.Network) != 2 {
		t.Fatalf("definition lock = %#v", result.Lock)
	}
}

func TestRecipeRejectsUnacceptedBlockedAndUncataloguedProposals(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*DetectionResult, *BaseCatalog){
		"blocked": func(result *DetectionResult, _ *BaseCatalog) { result.Blocked = true },
		"unsupported language": func(result *DetectionResult, _ *BaseCatalog) {
			result.Services[0].Language = "ruby"
			result.Services[0].Runtime.Name = "ruby"
		},
		"static": func(result *DetectionResult, _ *BaseCatalog) {
			result.Services[0].Language = "static"
			result.Services[0].Runtime.Name = "static"
			result.Services[0].Kind = "static"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			result := validDetection()
			catalog := validCatalog(t)
			mutate(&result, &catalog)
			if _, _, err := GenerateRecipe(result, catalog, "linux/amd64"); err == nil {
				t.Fatal("expected recipe rejection")
			}
		})
	}
}

func TestBlockedDetectorOutputRemainsAValidAdvisoryResult(t *testing.T) {
	t.Parallel()
	result := validDetection()
	result.Services[0].Ambiguous = true
	result.Unresolved = []json.RawMessage{[]byte(`{"code":"go.listen-port-unresolved"}`)}
	result.GeneratedManifest = []byte("null")
	result.Blocked = true
	if err := result.Validate(testSnapshotID, "."); err != nil {
		t.Fatalf("blocked detector contract should remain valid: %v", err)
	}
	if _, _, err := GenerateRecipe(result, validCatalog(t), "linux/amd64"); err == nil {
		t.Fatal("blocked advisory output must not become executable Starlark")
	}
}
