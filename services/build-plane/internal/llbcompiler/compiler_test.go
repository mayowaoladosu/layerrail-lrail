package llbcompiler

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildir"
	"github.com/moby/buildkit/solver/pb"
	"google.golang.org/protobuf/proto"
)

const testOrganizationID = "org_019b01da-7e31-7000-8000-000000000002"
const testProjectID = "prj_019b01da-7e31-7000-8000-000000000003"
const testPolicyID = "pol_019b01da-7e31-7000-8000-000000000004"
const testBaseDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const testBaseRef = "registry.example.invalid/lrail/ruby:3.4@" + testBaseDigest
const testSBOMDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
const testProvenanceDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
const testSignerPublicKeyDigest = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

func validCompileRequest(t *testing.T) Request {
	t.Helper()
	ir := validBuildIR()
	irDigest, err := buildir.DefinitionDigest(ir)
	if err != nil {
		t.Fatalf("DefinitionDigest: %v", err)
	}
	material := BaseMaterial{
		RequestedRef:      testBaseRef,
		ResolvedRef:       testBaseRef,
		Digest:            testBaseDigest,
		Registry:          "registry.example.invalid",
		Classification:    "curated",
		Platforms:         []string{"linux/amd64"},
		SBOMDigest:        testSBOMDigest,
		ProvenanceDigest:  testProvenanceDigest,
		SignatureIdentity: "https://signing.layerrail.invalid/base",
	}
	material.ResolutionDigest, err = materialResolutionDigest(material)
	if err != nil {
		t.Fatalf("materialResolutionDigest: %v", err)
	}
	return Request{
		OrganizationID:   testOrganizationID,
		ProjectID:        testProjectID,
		IR:               ir,
		ExpectedIRDigest: irDigest,
		Policy:           validPolicy(),
		BaseMaterials:    []BaseMaterial{material},
		BuildArguments:   map[string]string{"BUILD_MODE": "release"},
	}
}

func validPolicy() Policy {
	return Policy{
		APIVersion: CurrentPolicyAPIVersion,
		ID:         testPolicyID,
		Revision:   "1.0.0",
		Base: BasePolicy{
			AllowedRegistries:          []string{"registry.example.invalid"},
			CuratedDigests:             []string{testBaseDigest},
			AllowedSignatureIdentities: []string{"https://signing.layerrail.invalid/base"},
			RequireSBOM:                true,
			RequireProvenance:          true,
		},
		Network: NetworkPolicy{
			AllowedProfiles:  []string{"none", "packages"},
			PackageHosts:     []string{"gems.example.invalid", "packages.example.invalid"},
			ExternalHosts:    []string{"downloads.example.invalid"},
			PackageGatewayID: "gateway.packages.v1",
		},
		Cache: CachePolicy{
			Scope:       "project",
			TrustDomain: "trusted-builds-v1",
			AllowShared: false,
		},
		Secrets:        SecretPolicy{AllowedNames: []string{"rails-build-key"}},
		BuildArguments: BuildArgumentPolicy{AllowedNames: []string{"BUILD_MODE"}},
		SupplyChain: SupplyChainPolicy{
			Version: CurrentSupplyChainPolicyVersion, SyftVersion: "1.46.0", TrivyVersion: "0.72.0",
			SignerKeyID: "lrail-build-evidence", AllowedSignerPublicKeyDigests: []string{testSignerPublicKeyDigest},
			DeniedVulnerabilitySeverities: []string{"CRITICAL"}, DeniedConfigurationSeverities: []string{"CRITICAL", "HIGH"},
			DeniedLicenseClassifications: []string{"Forbidden"}, RequireSecretFree: true, RequireImageConfigurationScan: true,
		},
	}
}

func validBuildIR() buildir.IR {
	return buildir.IR{
		Version:         buildir.CurrentVersion,
		DSLAPIVersion:   buildir.CurrentDSLAPIVersion,
		CompilerVersion: "0.2.0",
		SourceSnapshot:  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TargetPlatform:  "linux/amd64",
		NetworkProfile:  "packages",
		Modules:         []buildir.Module{},
		Nodes: []buildir.Node{
			{ID: "n1", Operation: "source", Inputs: []string{}, Attributes: map[string]any{"path": ".", "include": []string{"app/**"}, "exclude": []string{".git/**"}}},
			{ID: "n2", Operation: "image", Inputs: []string{}, Attributes: map[string]any{"ref": testBaseRef}},
			{ID: "n3", Operation: "cache", Inputs: []string{}, Attributes: map[string]any{"name": "bundle", "target": "/usr/local/bundle", "sharing": "locked"}},
			{ID: "n4", Operation: "secret", Inputs: []string{}, Attributes: map[string]any{"name": "rails-build-key", "target": "/run/secrets/rails-build-key", "required": true}},
			{ID: "n5", Operation: "run", Inputs: []string{"n2", "n3", "n4"}, Attributes: map[string]any{
				"argv": []string{"bundle", "install"}, "env": map[string]string{"RAILS_ENV": "production"},
				"mounts": []string{"n3", "n4"}, "network": "packages", "shell": false,
				"user": "10001:10001", "workdir": "/workspace",
			}},
			{ID: "n6", Operation: "copy", Inputs: []string{"n5", "n1"}, Attributes: map[string]any{"dest": "/workspace", "owner": "10001:10001", "mode": "0755"}},
		},
		Outputs: []buildir.Output{{
			Name: "api", Kind: "oci_image", State: "n6", Entrypoint: []string{"bin/rails"},
			Command: []string{"server"}, Ports: []int{3000}, Labels: map[string]string{"org.example.kind": "web"}, Headers: map[string]string{},
		}},
	}
}

func TestCompileProducesDeterministicRealLLBGraph(t *testing.T) {
	t.Parallel()
	compiler, err := New("0.1.0")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	request := validCompileRequest(t)
	first, err := compiler.Compile(context.Background(), request)
	if err != nil {
		t.Fatalf("Compile first: %v", err)
	}
	second, err := compiler.Compile(context.Background(), request)
	if err != nil {
		t.Fatalf("Compile second: %v", err)
	}
	if first.DefinitionDigest != second.DefinitionDigest || first.Outputs[0].LLBDigest != second.Outputs[0].LLBDigest {
		t.Fatalf("digests changed: %#v %#v", first, second)
	}
	if len(first.Outputs) != 1 || len(first.Outputs[0].Definition) == 0 || len(first.Outputs[0].Graph.Vertices) < 5 {
		t.Fatalf("incomplete compiled output: %#v", first.Outputs)
	}
	if !slices.Contains(vertexKinds(first.Outputs[0].Graph), "source") || !slices.Contains(vertexKinds(first.Outputs[0].Graph), "exec") || !slices.Contains(vertexKinds(first.Outputs[0].Graph), "file") {
		t.Fatalf("unexpected graph: %#v", first.Outputs[0].Graph)
	}
	var definition pb.Definition
	if err := proto.Unmarshal(first.Outputs[0].Definition, &definition); err != nil {
		t.Fatalf("Unmarshal definition: %v", err)
	}
	if len(definition.Def) != len(first.Outputs[0].Graph.Vertices) {
		t.Fatalf("definition/graph mismatch: %d != %d", len(definition.Def), len(first.Outputs[0].Graph.Vertices))
	}
	if len(first.Outputs[0].ImageConfig) == 0 || first.Lock.Outputs[0].ConfigDigest == "" {
		t.Fatalf("image output config absent: %#v", first.Outputs[0])
	}
	serialized, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(serialized), "must-not-enter") {
		t.Fatal("secret value entered compiler result")
	}
}

func TestCompileEmitsExplicitCacheSecretAndNetworkCapabilities(t *testing.T) {
	t.Parallel()
	compiler, _ := New("0.1.0")
	result, err := compiler.Compile(context.Background(), validCompileRequest(t))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(result.Lock.Caches) != 1 || !strings.HasPrefix(result.Lock.Caches[0].Namespace, "lrail-cache-") {
		t.Fatalf("cache capability = %#v", result.Lock.Caches)
	}
	if len(result.Lock.Secrets) != 1 || result.Lock.Secrets[0].MountID != "rails-build-key" {
		t.Fatalf("secret capability = %#v", result.Lock.Secrets)
	}
	if len(result.Lock.Network) != 1 || result.Lock.Network[0].Profile != "packages" || result.Lock.Network[0].GatewayID == "" {
		t.Fatalf("network capability = %#v", result.Lock.Network)
	}

	operations := decodeOperations(t, result.Outputs[0].Definition)
	var execution *pb.ExecOp
	for _, operation := range operations {
		if exec, ok := operation.Op.(*pb.Op_Exec); ok {
			execution = exec.Exec
		}
	}
	if execution == nil {
		t.Fatal("exec op absent")
	}
	mountTypes := make(map[pb.MountType]int)
	for _, mount := range execution.Mounts {
		mountTypes[mount.MountType]++
	}
	if mountTypes[pb.MountType_CACHE] != 1 || mountTypes[pb.MountType_SECRET] != 1 {
		t.Fatalf("mount types = %#v", mountTypes)
	}
	cacheOwned := false
	for _, operation := range operations {
		file := operation.GetFile()
		if file == nil {
			continue
		}
		for _, action := range file.Actions {
			directory := action.GetMkdir()
			if directory != nil && directory.Path == "/cache" && directory.Mode == 0o755 &&
				directory.Owner.GetUser().GetByID() == 10001 && directory.Owner.GetGroup().GetByID() == 10001 {
				cacheOwned = true
			}
		}
	}
	if !cacheOwned {
		t.Fatal("cache mount lacks signed non-root ownership initialization")
	}
	if execution.Network != pb.NetMode_UNSET {
		t.Fatalf("packages network mode = %v", execution.Network)
	}
	if execution.Meta == nil || execution.Meta.ProxyEnv == nil || execution.Meta.ProxyEnv.HttpProxy != BuildEgressProxyURL || execution.Meta.ProxyEnv.HttpsProxy != BuildEgressProxyURL ||
		execution.Meta.ProxyEnv.AllProxy != "" || execution.Meta.ProxyEnv.NoProxy != "" || execution.Meta.ProxyEnv.FtpProxy != "" {
		t.Fatalf("packages proxy authority = %#v", execution.Meta)
	}
}

func TestCompileNoneNetworkUsesBuildKitNoNetwork(t *testing.T) {
	t.Parallel()
	request := validCompileRequest(t)
	request.IR.NetworkProfile = "none"
	request.IR.Nodes[4].Attributes["network"] = "none"
	request.Policy.Network.AllowedProfiles = []string{"none"}
	request.ExpectedIRDigest, _ = buildir.DefinitionDigest(request.IR)
	compiler, _ := New("0.1.0")
	result, err := compiler.Compile(context.Background(), request)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	for _, operation := range decodeOperations(t, result.Outputs[0].Definition) {
		if exec, ok := operation.Op.(*pb.Op_Exec); ok {
			if exec.Exec.Network != pb.NetMode_NONE || exec.Exec.Meta == nil || exec.Exec.Meta.ProxyEnv != nil {
				t.Fatalf("none network execution = %#v", exec.Exec)
			}
		}
	}
}

func TestAuditDefinitionsBindsEveryAmbientCapabilityToLock(t *testing.T) {
	t.Parallel()
	compiler, _ := New("0.1.0")
	result, err := compiler.Compile(context.Background(), validCompileRequest(t))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	definitions := make([][]byte, 0, len(result.Outputs))
	for _, output := range result.Outputs {
		definitions = append(definitions, output.Definition)
	}
	if err := AuditDefinitions(definitions, result.Lock); err != nil {
		t.Fatalf("AuditDefinitions valid compiler output: %v", err)
	}

	hostNetwork := mutateDefinitionOperation(t, definitions[0], func(operation *pb.Op) bool {
		execution := operation.GetExec()
		if execution == nil {
			return false
		}
		execution.Network = pb.NetMode_HOST
		return true
	})
	if err := AuditDefinitions([][]byte{hostNetwork}, result.Lock); err == nil {
		t.Fatal("expected host-network LLB rejection")
	}

	foreignProxy := mutateDefinitionOperation(t, definitions[0], func(operation *pb.Op) bool {
		execution := operation.GetExec()
		if execution == nil || execution.Meta == nil || execution.Meta.ProxyEnv == nil {
			return false
		}
		execution.Meta.ProxyEnv.HttpsProxy = "http://decoy.example.invalid:3128"
		return true
	})
	if err := AuditDefinitions([][]byte{foreignProxy}, result.Lock); err == nil {
		t.Fatal("expected decoy proxy LLB rejection")
	}

	foreignSource := mutateDefinitionOperation(t, definitions[0], func(operation *pb.Op) bool {
		source := operation.GetSource()
		if source == nil || !strings.HasPrefix(source.Identifier, "local://") {
			return false
		}
		source.Identifier = "git://example.invalid/foreign.git"
		return true
	})
	if err := AuditDefinitions([][]byte{foreignSource}, result.Lock); err == nil {
		t.Fatal("expected undeclared source rejection")
	}

	unreachable := appendDefinitionOperation(t, definitions[0], &pb.Op{Op: &pb.Op_Source{Source: &pb.SourceOp{
		Identifier: "local://lrail-source",
		Attrs: map[string]string{
			pb.AttrLocalUniqueID: result.Lock.SourceSnapshot, pb.AttrSharedKeyHint: result.Lock.SourceSnapshot,
			pb.AttrIncludePatterns: `["unreachable/**"]`,
		},
	}}})
	if err := AuditDefinitions([][]byte{unreachable}, result.Lock); err == nil {
		t.Fatal("expected unreachable decoy operation rejection")
	}

	broaderLock := result.Lock
	broaderLock.Network = append(append([]NetworkCapability(nil), result.Lock.Network...), NetworkCapability{
		NodeID: "n99", Profile: "allowlist", GatewayID: "extra-gateway", Hosts: []string{"extra.example.invalid"},
	})
	if err := AuditDefinitions(definitions, broaderLock); err == nil {
		t.Fatal("expected unused broader network capability rejection")
	}
}

func mutateDefinitionOperation(t *testing.T, contents []byte, mutate func(*pb.Op) bool) []byte {
	t.Helper()
	var definition pb.Definition
	if err := proto.Unmarshal(contents, &definition); err != nil {
		t.Fatalf("Unmarshal definition: %v", err)
	}
	mutated := false
	for index, raw := range definition.Def {
		var operation pb.Op
		if err := proto.Unmarshal(raw, &operation); err != nil {
			t.Fatalf("Unmarshal operation: %v", err)
		}
		if !mutated && mutate(&operation) {
			updated, err := proto.MarshalOptions{Deterministic: true}.Marshal(&operation)
			if err != nil {
				t.Fatalf("Marshal operation: %v", err)
			}
			definition.Def[index] = updated
			mutated = true
		}
	}
	if !mutated {
		t.Fatal("definition mutation target was absent")
	}
	updated, err := proto.MarshalOptions{Deterministic: true}.Marshal(&definition)
	if err != nil {
		t.Fatalf("Marshal definition: %v", err)
	}
	return updated
}

func appendDefinitionOperation(t *testing.T, contents []byte, operation *pb.Op) []byte {
	t.Helper()
	var definition pb.Definition
	if err := proto.Unmarshal(contents, &definition); err != nil {
		t.Fatalf("Unmarshal definition: %v", err)
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(operation)
	if err != nil {
		t.Fatalf("Marshal operation: %v", err)
	}
	definition.Def = append(definition.Def, raw)
	updated, err := proto.MarshalOptions{Deterministic: true}.Marshal(&definition)
	if err != nil {
		t.Fatalf("Marshal definition: %v", err)
	}
	return updated
}

func TestCompileStaticSourceOutputWithoutBaseMaterial(t *testing.T) {
	t.Parallel()
	request := validCompileRequest(t)
	request.IR.Nodes = []buildir.Node{
		{ID: "n1", Operation: "source", Inputs: []string{}, Attributes: map[string]any{"path": "public", "include": []string{"**"}, "exclude": []string{}}},
	}
	request.IR.Outputs = []buildir.Output{{
		Name: "site", Kind: "static_bundle", State: "n1", Entrypoint: []string{}, Command: []string{}, Ports: []int{}, Labels: map[string]string{}, Headers: map[string]string{"Cache-Control": "public, max-age=60"},
	}}
	request.IR.NetworkProfile = "none"
	request.Policy.Network.AllowedProfiles = []string{"none"}
	request.BaseMaterials = nil
	request.ExpectedIRDigest, _ = buildir.DefinitionDigest(request.IR)
	compiler, _ := New("0.1.0")
	result, err := compiler.Compile(context.Background(), request)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(result.Outputs) != 1 || result.Outputs[0].Kind != "static_bundle" || result.Outputs[0].StaticHeaders["Cache-Control"] == "" || len(result.Outputs[0].ImageConfig) != 0 {
		t.Fatalf("static output = %#v", result.Outputs)
	}
	if len(result.Lock.BaseMaterials) != 0 {
		t.Fatalf("static lock has base materials: %#v", result.Lock.BaseMaterials)
	}
}

func decodeOperations(t *testing.T, definition []byte) []*pb.Op {
	t.Helper()
	var parsed pb.Definition
	if err := proto.Unmarshal(definition, &parsed); err != nil {
		t.Fatalf("Unmarshal definition: %v", err)
	}
	operations := make([]*pb.Op, 0, len(parsed.Def))
	for _, raw := range parsed.Def {
		operation := new(pb.Op)
		if err := proto.Unmarshal(raw, operation); err != nil {
			t.Fatalf("Unmarshal op: %v", err)
		}
		operations = append(operations, operation)
	}
	return operations
}

func vertexKinds(graph Graph) []string {
	result := make([]string, 0, len(graph.Vertices))
	for _, vertex := range graph.Vertices {
		result = append(result, vertex.Kind)
	}
	return result
}

func compileCode(t *testing.T, request Request) string {
	t.Helper()
	compiler, err := New("0.1.0")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = compiler.Compile(context.Background(), request)
	if err == nil {
		t.Fatal("expected compile failure")
	}
	if !errors.Is(err, ErrCompile) {
		t.Fatalf("error does not wrap ErrCompile: %v", err)
	}
	var compileError *CompileError
	if !errors.As(err, &compileError) {
		t.Fatalf("error type = %T", err)
	}
	return compileError.Code
}
