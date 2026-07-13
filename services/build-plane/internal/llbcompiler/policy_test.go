package llbcompiler

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildir"
	"github.com/moby/buildkit/client/llb"
)

func TestCompileRejectsInvalidScopeDigestPolicyAndMaterialLocks(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		mutate func(*Request)
		code   string
	}{
		"organization scope": {
			mutate: func(request *Request) { request.OrganizationID = testProjectID },
			code:   "llb.scope",
		},
		"project scope": {
			mutate: func(request *Request) { request.ProjectID = testOrganizationID },
			code:   "llb.scope",
		},
		"IR digest": {
			mutate: func(request *Request) {
				request.ExpectedIRDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
			},
			code: "llb.ir_digest",
		},
		"policy version": {
			mutate: func(request *Request) { request.Policy.APIVersion = "lrail.build-policy/v2" },
			code:   "llb.policy_version",
		},
		"registry": {
			mutate: func(request *Request) { request.Policy.Base.AllowedRegistries = []string{"other.invalid"} },
			code:   "llb.material_registry",
		},
		"curated digest": {
			mutate: func(request *Request) {
				request.Policy.Base.CuratedDigests = []string{"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}
			},
			code: "llb.material_curated",
		},
		"platform": {
			mutate: func(request *Request) {
				request.BaseMaterials[0].Platforms = []string{"linux/arm64"}
				refreshMaterial(request)
			},
			code: "llb.material_platform",
		},
		"signature": {
			mutate: func(request *Request) {
				request.BaseMaterials[0].SignatureIdentity = "https://attacker.invalid"
				refreshMaterial(request)
			},
			code: "llb.material_signature",
		},
		"SBOM": {
			mutate: func(request *Request) { request.BaseMaterials[0].SBOMDigest = ""; refreshMaterial(request) },
			code:   "llb.material_sbom",
		},
		"provenance": {
			mutate: func(request *Request) { request.BaseMaterials[0].ProvenanceDigest = ""; refreshMaterial(request) },
			code:   "llb.material_provenance",
		},
		"resolution tamper": {
			mutate: func(request *Request) {
				request.BaseMaterials[0].ResolutionDigest = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
			},
			code: "llb.material_resolution",
		},
		"missing material": {
			mutate: func(request *Request) { request.BaseMaterials = nil },
			code:   "llb.material_set",
		},
		"extra material": {
			mutate: func(request *Request) {
				request.BaseMaterials = append(request.BaseMaterials, request.BaseMaterials[0])
			},
			code: "llb.material_set",
		},
		"customer base disabled": {
			mutate: func(request *Request) { request.BaseMaterials[0].Classification = "customer"; refreshMaterial(request) },
			code:   "llb.material_customer",
		},
	}
	for name, testCase := range tests {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			request := validCompileRequest(t)
			testCase.mutate(&request)
			if code := compileCode(t, request); code != testCase.code {
				t.Fatalf("code = %q, want %q", code, testCase.code)
			}
		})
	}
}

func TestCompileRejectsNetworkCacheSecretAndArgumentPolicyViolations(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		mutate func(*Request)
		code   string
	}{
		"network profile": {
			mutate: func(request *Request) { request.Policy.Network.AllowedProfiles = []string{"none"} },
			code:   "llb.network_denied",
		},
		"allowlist host": {
			mutate: func(request *Request) {
				request.IR.NetworkProfile = "allowlist"
				request.IR.AllowedHosts = []string{"downloads.example.invalid"}
				request.IR.Nodes[4].Attributes["network"] = "allowlist"
				request.Policy.Network.AllowedProfiles = []string{"allowlist"}
				request.Policy.Network.AllowlistGatewayID = "gateway.allowlist.v1"
				request.Policy.Network.ExternalHosts = []string{"approved.example.invalid"}
				request.ExpectedIRDigest, _ = buildir.DefinitionDigest(request.IR)
			},
			code: "llb.network_host",
		},
		"shared cache": {
			mutate: func(request *Request) {
				request.IR.Nodes[2].Attributes["sharing"] = "shared"
				request.ExpectedIRDigest, _ = buildir.DefinitionDigest(request.IR)
			},
			code: "llb.cache_shared",
		},
		"secret shared cache": {
			mutate: func(request *Request) {
				request.IR.Nodes[2].Attributes["sharing"] = "shared"
				request.Policy.Cache.AllowShared = true
				request.ExpectedIRDigest, _ = buildir.DefinitionDigest(request.IR)
			},
			code: "llb.cache_secret",
		},
		"secret denied": {
			mutate: func(request *Request) { request.Policy.Secrets.AllowedNames = nil },
			code:   "llb.secret_denied",
		},
		"secret in argv": {
			mutate: func(request *Request) {
				request.IR.Nodes[4].Attributes["argv"] = []string{"rails-build-key"}
				request.ExpectedIRDigest, _ = buildir.DefinitionDigest(request.IR)
			},
			code: "llb.secret_reference",
		},
		"secret in env": {
			mutate: func(request *Request) {
				request.IR.Nodes[4].Attributes["env"] = map[string]string{"KEY_NAME": "rails-build-key"}
				request.ExpectedIRDigest, _ = buildir.DefinitionDigest(request.IR)
			},
			code: "llb.secret_reference",
		},
		"argument denied": {
			mutate: func(request *Request) { request.BuildArguments["UNKNOWN"] = "value" },
			code:   "llb.argument_denied",
		},
		"secret-like argument": {
			mutate: func(request *Request) {
				request.Policy.BuildArguments.AllowedNames = append(request.Policy.BuildArguments.AllowedNames, "API_TOKEN")
				request.BuildArguments["API_TOKEN"] = "must-not-enter"
			},
			code: "llb.policy_argument",
		},
		"embedded auth argument": {
			mutate: func(request *Request) {
				request.Policy.BuildArguments.AllowedNames = append(request.Policy.BuildArguments.AllowedNames, "SERVICE_AUTH_MODE")
				request.BuildArguments["SERVICE_AUTH_MODE"] = "enabled"
			},
			code: "llb.policy_argument",
		},
		"argument environment conflict": {
			mutate: func(request *Request) {
				request.BuildArguments = map[string]string{"RAILS_ENV": "release"}
				request.Policy.BuildArguments.AllowedNames = []string{"RAILS_ENV"}
			},
			code: "llb.argument_conflict",
		},
		"mount overlap": {
			mutate: func(request *Request) {
				request.IR.Nodes[2].Attributes["target"] = "/run"
				request.ExpectedIRDigest, _ = buildir.DefinitionDigest(request.IR)
			},
			code: "llb.mount_overlap",
		},
	}
	for name, testCase := range tests {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			request := validCompileRequest(t)
			testCase.mutate(&request)
			if code := compileCode(t, request); code != testCase.code {
				t.Fatalf("code = %q, want %q", code, testCase.code)
			}
		})
	}
}

func TestCacheNamespaceBindsTenantProjectTrustAndPolicy(t *testing.T) {
	t.Parallel()
	compiler, _ := New("0.1.0")
	firstRequest := validCompileRequest(t)
	first, err := compiler.Compile(context.Background(), firstRequest)
	if err != nil {
		t.Fatalf("Compile first: %v", err)
	}
	secondRequest := validCompileRequest(t)
	secondRequest.ProjectID = "prj_019b01da-7e31-7000-8000-000000000013"
	second, err := compiler.Compile(context.Background(), secondRequest)
	if err != nil {
		t.Fatalf("Compile second: %v", err)
	}
	if first.Lock.Caches[0].Namespace == second.Lock.Caches[0].Namespace {
		t.Fatal("cache namespace did not bind project scope")
	}
	thirdRequest := validCompileRequest(t)
	thirdRequest.Policy.Cache.TrustDomain = "untrusted-builds-v1"
	third, err := compiler.Compile(context.Background(), thirdRequest)
	if err != nil {
		t.Fatalf("Compile third: %v", err)
	}
	if first.Lock.Caches[0].Namespace == third.Lock.Caches[0].Namespace {
		t.Fatal("cache namespace did not bind trust domain")
	}
}

func TestCacheNamespaceBindsNodeIdentityAndOutputLockBindsState(t *testing.T) {
	t.Parallel()
	compiler, _ := New("0.1.0")
	request := validCompileRequest(t)
	result, err := compiler.Compile(context.Background(), request)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if result.Lock.Outputs[0].StateID != request.IR.Outputs[0].State {
		t.Fatalf("output state lock = %#v", result.Lock.Outputs[0])
	}

	input, err := normalizeRequest(request)
	if err != nil {
		t.Fatalf("normalizeRequest: %v", err)
	}
	firstCache, err := cacheCapability(input, request.IR.Nodes[2])
	if err != nil {
		t.Fatalf("cacheCapability first: %v", err)
	}
	otherNode := request.IR.Nodes[2]
	otherNode.ID = "n99"
	secondCache, err := cacheCapability(input, otherNode)
	if err != nil {
		t.Fatalf("cacheCapability second: %v", err)
	}
	if firstCache.Namespace == secondCache.Namespace {
		t.Fatal("cache namespace did not bind node identity")
	}
}

func TestCompileRunFailsClosedWithoutNetworkCapability(t *testing.T) {
	t.Parallel()
	input, err := normalizeRequest(validCompileRequest(t))
	if err != nil {
		t.Fatalf("normalizeRequest: %v", err)
	}
	capabilities, err := compileCapabilities(input)
	if err != nil {
		t.Fatalf("compileCapabilities: %v", err)
	}
	delete(capabilities.networkByNode, "n5")
	platform, _ := parsePlatform(input.ir.TargetPlatform)
	graph := &graphCompiler{
		input:        input,
		capabilities: capabilities,
		platform:     platform,
		states:       map[string]llb.State{"n2": llb.Scratch()},
		sourcePaths:  map[string]string{},
		materials:    map[string]BaseMaterial{},
	}
	_, err = graph.compileRun(input.ir.Nodes[4])
	var compileError *CompileError
	if !errors.As(err, &compileError) || compileError.Code != "llb.network_missing" {
		t.Fatalf("missing network error = %v", err)
	}
}

func TestEquivalentNormalizedPolicyAndArgumentsYieldSameDefinition(t *testing.T) {
	t.Parallel()
	compiler, _ := New("0.1.0")
	firstRequest := validCompileRequest(t)
	firstRequest.Policy.Network.PackageHosts = []string{"packages.example.invalid", "gems.example.invalid"}
	firstRequest.Policy.Network.AllowedProfiles = []string{"packages", "none"}
	firstRequest.Policy.Secrets.AllowedNames = []string{"rails-build-key", "rails-build-key"}
	first, err := compiler.Compile(context.Background(), firstRequest)
	if err != nil {
		t.Fatalf("Compile first: %v", err)
	}
	secondRequest := validCompileRequest(t)
	secondRequest.Policy.Network.PackageHosts = []string{"gems.example.invalid", "packages.example.invalid"}
	second, err := compiler.Compile(context.Background(), secondRequest)
	if err != nil {
		t.Fatalf("Compile second: %v", err)
	}
	if first.DefinitionDigest != second.DefinitionDigest || first.Outputs[0].LLBDigest != second.Outputs[0].LLBDigest {
		t.Fatalf("normalized inputs diverged: %#v %#v", first, second)
	}
}

func TestDefinitionDigestBindsPolicyMaterialArgumentAndCompiler(t *testing.T) {
	t.Parallel()
	baseCompiler, _ := New("0.1.0")
	baseRequest := validCompileRequest(t)
	base, err := baseCompiler.Compile(context.Background(), baseRequest)
	if err != nil {
		t.Fatalf("Compile base: %v", err)
	}

	policyRequest := validCompileRequest(t)
	policyRequest.Policy.Revision = "1.0.1"
	policy, err := baseCompiler.Compile(context.Background(), policyRequest)
	if err != nil {
		t.Fatalf("Compile policy: %v", err)
	}
	argumentRequest := validCompileRequest(t)
	argumentRequest.BuildArguments["BUILD_MODE"] = "debug"
	argument, err := baseCompiler.Compile(context.Background(), argumentRequest)
	if err != nil {
		t.Fatalf("Compile argument: %v", err)
	}
	otherCompiler, _ := New("0.1.1")
	compilerResult, err := otherCompiler.Compile(context.Background(), validCompileRequest(t))
	if err != nil {
		t.Fatalf("Compile version: %v", err)
	}
	if base.DefinitionDigest == policy.DefinitionDigest || base.DefinitionDigest == argument.DefinitionDigest || base.DefinitionDigest == compilerResult.DefinitionDigest {
		t.Fatal("definition digest omitted a locked input")
	}
}

func TestCompileNeverAcceptsSecretValuesAsInput(t *testing.T) {
	t.Parallel()
	request := validCompileRequest(t)
	serialized, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("Marshal request: %v", err)
	}
	if strings.Contains(string(serialized), "must-not-enter") {
		t.Fatal("test fixture unexpectedly contains secret value")
	}
	compiler, _ := New("0.1.0")
	result, err := compiler.Compile(context.Background(), request)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	serialized, err = json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal result: %v", err)
	}
	if strings.Contains(string(serialized), "must-not-enter") {
		t.Fatal("secret value entered compiler result")
	}
}

func TestCompilerRejectsInvalidVersionNilAndCanceledContext(t *testing.T) {
	t.Parallel()
	if _, err := New("latest"); !errors.Is(err, ErrCompile) {
		t.Fatalf("invalid version error = %v", err)
	}
	compiler, _ := New("0.1.0")
	if _, err := compiler.Compile(nil, validCompileRequest(t)); !errors.Is(err, ErrCompile) {
		t.Fatalf("nil context error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := compiler.Compile(ctx, validCompileRequest(t)); !errors.Is(err, ErrCompile) {
		t.Fatalf("canceled context error = %v", err)
	}
}

func TestPolicyValidationRejectsMalformedCapabilities(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		mutate func(*Request)
		code   string
	}{
		"policy id": {
			mutate: func(request *Request) { request.Policy.ID = testProjectID },
			code:   "llb.scope",
		},
		"registry syntax": {
			mutate: func(request *Request) { request.Policy.Base.AllowedRegistries = []string{"https://registry.invalid"} },
			code:   "llb.policy_base",
		},
		"signature identities": {
			mutate: func(request *Request) { request.Policy.Base.AllowedSignatureIdentities = nil },
			code:   "llb.policy_base",
		},
		"unknown network": {
			mutate: func(request *Request) { request.Policy.Network.AllowedProfiles = []string{"internet"} },
			code:   "llb.policy_network",
		},
		"package gateway": {
			mutate: func(request *Request) { request.Policy.Network.PackageGatewayID = "" },
			code:   "llb.policy_network",
		},
		"private gateway": {
			mutate: func(request *Request) {
				request.Policy.Network.AllowedProfiles = append(request.Policy.Network.AllowedProfiles, "private")
			},
			code: "llb.policy_network",
		},
		"cache scope": {
			mutate: func(request *Request) { request.Policy.Cache.Scope = "global" },
			code:   "llb.policy_cache",
		},
		"shared secret policy": {
			mutate: func(request *Request) { request.Policy.Cache.AllowSharedWithSecrets = true },
			code:   "llb.policy_cache",
		},
		"secret name": {
			mutate: func(request *Request) { request.Policy.Secrets.AllowedNames = []string{"../secret"} },
			code:   "llb.policy_secret",
		},
	}
	for name, testCase := range tests {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			request := validCompileRequest(t)
			testCase.mutate(&request)
			if code := compileCode(t, request); code != testCase.code {
				t.Fatalf("code = %q, want %q", code, testCase.code)
			}
		})
	}
}

func TestCompileAcceptsCustomerBaseAllowlistPrivateSharedAndOptionalCapabilities(t *testing.T) {
	t.Parallel()
	compiler, _ := New("0.1.0")

	customer := validCompileRequest(t)
	customer.Policy.Base.AllowCustomerBases = true
	customer.BaseMaterials[0].Classification = "customer"
	refreshMaterial(&customer)
	if _, err := compiler.Compile(context.Background(), customer); err != nil {
		t.Fatalf("customer base: %v", err)
	}

	allowlist := validCompileRequest(t)
	allowlist.IR.NetworkProfile = "allowlist"
	allowlist.IR.AllowedHosts = []string{"downloads.example.invalid"}
	allowlist.IR.Nodes[4].Attributes["network"] = "allowlist"
	allowlist.Policy.Network.AllowedProfiles = []string{"allowlist"}
	allowlist.Policy.Network.AllowlistGatewayID = "gateway.allowlist.v1"
	allowlist.ExpectedIRDigest, _ = buildir.DefinitionDigest(allowlist.IR)
	result, err := compiler.Compile(context.Background(), allowlist)
	if err != nil {
		t.Fatalf("allowlist: %v", err)
	}
	if result.Lock.Network[0].GatewayID != "gateway.allowlist.v1" || len(result.Lock.Network[0].Hosts) != 1 {
		t.Fatalf("allowlist capability = %#v", result.Lock.Network)
	}

	private := validCompileRequest(t)
	private.IR.NetworkProfile = "private"
	private.IR.Nodes[4].Attributes["network"] = "private"
	private.Policy.Network.AllowedProfiles = []string{"private"}
	private.Policy.Network.PrivateGatewayID = "gateway.private.v1"
	private.ExpectedIRDigest, _ = buildir.DefinitionDigest(private.IR)
	if _, err := compiler.Compile(context.Background(), private); err != nil {
		t.Fatalf("private: %v", err)
	}

	shared := validCompileRequest(t)
	shared.IR.Nodes[2].Attributes["sharing"] = "shared"
	shared.IR.Nodes[3].Attributes["required"] = false
	shared.Policy.Cache.AllowShared = true
	shared.Policy.Cache.AllowSharedWithSecrets = true
	shared.ExpectedIRDigest, _ = buildir.DefinitionDigest(shared.IR)
	if _, err := compiler.Compile(context.Background(), shared); err != nil {
		t.Fatalf("shared and optional: %v", err)
	}
}

func refreshMaterial(request *Request) {
	request.BaseMaterials[0].ResolutionDigest, _ = materialResolutionDigest(request.BaseMaterials[0])
}
