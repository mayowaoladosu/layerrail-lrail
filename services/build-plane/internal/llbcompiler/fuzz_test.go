package llbcompiler

import (
	"context"
	"errors"
	"testing"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildir"
	"github.com/moby/buildkit/solver/pb"
	"google.golang.org/protobuf/proto"
)

func FuzzCompilePolicyBoundary(f *testing.F) {
	f.Add("packages", "bundle", "/usr/local/bundle", "locked", "rails-build-key")
	f.Add("none", "cache", "/cache", "private", "build-key")
	f.Add("private", "../escape", "/run/secrets/key", "shared", "../../secret")
	f.Fuzz(func(t *testing.T, network, cacheName, cacheTarget, sharing, secretName string) {
		request := validCompileRequest(t)
		request.IR.NetworkProfile = network
		request.IR.Nodes[2].Attributes["name"] = cacheName
		request.IR.Nodes[2].Attributes["target"] = cacheTarget
		request.IR.Nodes[2].Attributes["sharing"] = sharing
		request.IR.Nodes[3].Attributes["name"] = secretName
		request.IR.Nodes[4].Attributes["network"] = network
		if err := request.IR.Validate(); err != nil {
			return
		}
		request.ExpectedIRDigest, _ = buildir.DefinitionDigest(request.IR)
		request.Policy.Network.AllowedProfiles = []string{network}
		request.Policy.Secrets.AllowedNames = []string{secretName}
		if network == "packages" {
			request.Policy.Network.PackageGatewayID = "gateway.packages.v1"
		}
		if network == "allowlist" {
			request.Policy.Network.AllowlistGatewayID = "gateway.allowlist.v1"
		}
		if network == "private" {
			request.Policy.Network.PrivateGatewayID = "gateway.private.v1"
		}
		compiler, err := New("0.1.0")
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		result, compileErr := compiler.Compile(context.Background(), request)
		if compileErr != nil {
			if !errors.Is(compileErr, ErrCompile) {
				t.Fatalf("untyped error: %v", compileErr)
			}
			return
		}
		if result.DefinitionDigest == "" || len(result.Outputs) == 0 || len(result.Outputs[0].Definition) == 0 {
			t.Fatalf("successful compile returned incomplete result: %#v", result)
		}
		var definition pb.Definition
		if err := proto.Unmarshal(result.Outputs[0].Definition, &definition); err != nil || len(definition.Def) == 0 {
			t.Fatalf("successful compile returned invalid LLB: %v", err)
		}
		if len(result.Lock.Caches) != 1 || len(result.Lock.Secrets) != 1 || len(result.Lock.Network) != 1 {
			t.Fatalf("successful compile omitted capabilities: %#v", result.Lock)
		}
	})
}
