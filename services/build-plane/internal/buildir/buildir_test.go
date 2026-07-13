package buildir

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const testSnapshotDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testModuleDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const testImageRef = "registry.example.invalid/lrail/ruby:3.4@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

func validIR() IR {
	return IR{
		Version:         CurrentVersion,
		DSLAPIVersion:   CurrentDSLAPIVersion,
		CompilerVersion: "0.2.0",
		SourceSnapshot:  testSnapshotDigest,
		TargetPlatform:  "linux/amd64",
		NetworkProfile:  "packages",
		Modules: []Module{
			{Name: "//build/helpers.star", Kind: "repository", Digest: testModuleDigest},
		},
		Nodes: []Node{
			{ID: "n1", Operation: "source", Inputs: []string{}, Attributes: map[string]any{"path": ".", "include": []string{"app/**"}, "exclude": []string{".git/**"}}},
			{ID: "n2", Operation: "image", Inputs: []string{}, Attributes: map[string]any{"ref": testImageRef}},
			{ID: "n3", Operation: "cache", Inputs: []string{}, Attributes: map[string]any{"name": "bundle", "target": "/usr/local/bundle", "sharing": "locked"}},
			{ID: "n4", Operation: "secret", Inputs: []string{}, Attributes: map[string]any{"name": "rails-build-key", "target": "/run/secrets/rails-build-key", "required": true}},
			{ID: "n5", Operation: "run", Inputs: []string{"n2", "n3", "n4"}, Attributes: map[string]any{
				"argv": []string{"bundle", "install"}, "env": map[string]string{"RAILS_ENV": "production"},
				"mounts": []string{"n3", "n4"}, "network": "packages", "shell": false,
				"user": "10001:10001", "workdir": "/workspace",
			}},
			{ID: "n6", Operation: "copy", Inputs: []string{"n5", "n1"}, Attributes: map[string]any{"dest": "/workspace", "owner": "10001:10001", "mode": "0755"}},
		},
		Outputs: []Output{{
			Name: "api", Kind: "oci_image", State: "n6", Entrypoint: []string{"bin/rails"},
			Command: []string{"server"}, Ports: []int{3000}, Labels: map[string]string{"org.example.kind": "web"}, Headers: map[string]string{},
		}},
	}
}

func TestDefinitionDigestIsStableAndBindsCompatibilityIdentity(t *testing.T) {
	t.Parallel()
	first := validIR()
	second := validIR()
	second.Nodes[4].Attributes["env"] = map[string]string{"RAILS_ENV": "production"}
	got, err := DefinitionDigest(first)
	if err != nil {
		t.Fatalf("DefinitionDigest first: %v", err)
	}
	again, err := DefinitionDigest(second)
	if err != nil {
		t.Fatalf("DefinitionDigest second: %v", err)
	}
	if got != again || !strings.HasPrefix(got, "sha256:") {
		t.Fatalf("digests differ: %q != %q", got, again)
	}

	changedCompiler := validIR()
	changedCompiler.CompilerVersion = "0.2.1"
	changedDigest, err := DefinitionDigest(changedCompiler)
	if err != nil {
		t.Fatalf("DefinitionDigest compiler change: %v", err)
	}
	if changedDigest == got {
		t.Fatal("compiler identity did not affect definition digest")
	}
	changedModule := validIR()
	changedModule.Modules[0].Digest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	changedDigest, err = DefinitionDigest(changedModule)
	if err != nil {
		t.Fatalf("DefinitionDigest module change: %v", err)
	}
	if changedDigest == got {
		t.Fatal("module identity did not affect definition digest")
	}
}

func TestJSONRoundTripPreservesValidationAndDefinitionDigest(t *testing.T) {
	t.Parallel()
	original := validIR()
	originalDigest, err := DefinitionDigest(original)
	if err != nil {
		t.Fatalf("DefinitionDigest original: %v", err)
	}
	serialized, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	restored, err := Decode(serialized)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	restoredDigest, err := DefinitionDigest(restored)
	if err != nil {
		t.Fatalf("DefinitionDigest restored: %v", err)
	}
	if restoredDigest != originalDigest {
		t.Fatalf("round-trip digest = %q, want %q", restoredDigest, originalDigest)
	}
}

func TestDecodeRejectsUnknownAndTrailingJSON(t *testing.T) {
	t.Parallel()
	serialized, err := json.Marshal(validIR())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	unknown := append([]byte(`{"unknown":true,`), serialized[1:]...)
	if _, err := Decode(unknown); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown field error = %v", err)
	}
	if _, err := Decode(append(serialized, []byte(` {}`)...)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("trailing JSON error = %v", err)
	}
}

func TestValidateRejectsUnsafeGraphs(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*IR){
		"version":              func(ir *IR) { ir.Version = 1 },
		"dsl version":          func(ir *IR) { ir.DSLAPIVersion = "lrail.build/v2" },
		"compiler version":     func(ir *IR) { ir.CompilerVersion = "latest" },
		"source digest":        func(ir *IR) { ir.SourceSnapshot = "latest" },
		"platform":             func(ir *IR) { ir.TargetPlatform = "windows/amd64" },
		"network":              func(ir *IR) { ir.NetworkProfile = "internet" },
		"network ceiling":      func(ir *IR) { ir.NetworkProfile = "none" },
		"allowed hosts":        func(ir *IR) { ir.AllowedHosts = []string{"packages.invalid"} },
		"module order":         func(ir *IR) { ir.Modules = append(ir.Modules, ir.Modules[0]) },
		"module kind":          func(ir *IR) { ir.Modules[0].Kind = "remote" },
		"module path":          func(ir *IR) { ir.Modules[0].Name = "//../host.star" },
		"module digest":        func(ir *IR) { ir.Modules[0].Digest = "mutable" },
		"nonsequential id":     func(ir *IR) { ir.Nodes[1].ID = "n7" },
		"forward input":        func(ir *IR) { ir.Nodes[0].Inputs = []string{"n6"} },
		"duplicate input":      func(ir *IR) { ir.Nodes[4].Inputs = []string{"n2", "n3", "n3"} },
		"unknown op":           func(ir *IR) { ir.Nodes[0].Operation = "shell" },
		"source fields":        func(ir *IR) { ir.Nodes[0].Attributes["unknown"] = true },
		"source escape":        func(ir *IR) { ir.Nodes[0].Attributes["path"] = "../host" },
		"source drive":         func(ir *IR) { ir.Nodes[0].Attributes["path"] = "C:workspace" },
		"source pattern order": func(ir *IR) { ir.Nodes[0].Attributes["include"] = []string{"z/**", "a/**"} },
		"mutable image":        func(ir *IR) { ir.Nodes[1].Attributes["ref"] = "ruby:latest" },
		"ambiguous image": func(ir *IR) {
			ir.Nodes[1].Attributes["ref"] = "registry.invalid/a/../b@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		},
		"empty argv":     func(ir *IR) { ir.Nodes[4].Attributes["argv"] = []string{} },
		"implicit shell": func(ir *IR) { ir.Nodes[4].Attributes["argv"] = []string{"/bin/sh", "-c", "echo unsafe"} },
		"bad run net":    func(ir *IR) { ir.Nodes[4].Attributes["network"] = "internet" },
		"mount mismatch": func(ir *IR) { ir.Nodes[4].Attributes["mounts"] = []string{"n4"} },
		"mount source":   func(ir *IR) { ir.Nodes[4].Inputs[1] = "n1"; ir.Nodes[4].Attributes["mounts"] = []string{"n1", "n4"} },
		"bad env":        func(ir *IR) { ir.Nodes[4].Attributes["env"] = map[string]string{"lower": "x"} },
		"root user":      func(ir *IR) { ir.Nodes[4].Attributes["user"] = "0:0" },
		"copy escape":    func(ir *IR) { ir.Nodes[5].Attributes["dest"] = "/app/../host" },
		"copy source":    func(ir *IR) { ir.Nodes[5].Inputs[1] = "n3" },
		"unknown state":  func(ir *IR) { ir.Outputs[0].State = "n99" },
		"bad port":       func(ir *IR) { ir.Outputs[0].Ports = []int{70000} },
		"duplicate port": func(ir *IR) { ir.Outputs[0].Ports = []int{3000, 3000} },
		"bad kind":       func(ir *IR) { ir.Outputs[0].Kind = "tar" },
		"null labels":    func(ir *IR) { ir.Outputs[0].Labels = nil },
		"OCI headers":    func(ir *IR) { ir.Outputs[0].Headers["Cache-Control"] = "public" },
		"header case alias": func(ir *IR) {
			ir.Outputs = []Output{{Name: "site", Kind: "static_bundle", State: "n1", Entrypoint: []string{}, Command: []string{}, Ports: []int{}, Labels: map[string]string{}, Headers: map[string]string{"Cache-Control": "public", "cache-control": "private"}}}
		},
	}
	for name, mutate := range tests {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ir := validIR()
			mutate(&ir)
			if err := ir.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate error = %v", err)
			}
		})
	}
}

func TestValidateAcceptsExplicitShellAndStaticOutput(t *testing.T) {
	t.Parallel()
	ir := validIR()
	ir.Nodes[4].Attributes["argv"] = []string{"/bin/sh", "-euc", "bundle install && bundle exec rake assets:precompile"}
	ir.Nodes[4].Attributes["shell"] = true
	ir.Outputs = []Output{
		{Name: "api", Kind: "oci_image", State: "n6", Entrypoint: []string{}, Command: []string{}, Ports: []int{}, Labels: map[string]string{}, Headers: map[string]string{}},
		{Name: "site", Kind: "static_bundle", State: "n1", Entrypoint: []string{}, Command: []string{}, Ports: []int{}, Labels: map[string]string{}, Headers: map[string]string{"Cache-Control": "public, max-age=60"}},
	}
	if err := ir.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateAcceptsCanonicalAllowlistedHosts(t *testing.T) {
	t.Parallel()
	ir := validIR()
	ir.NetworkProfile = "allowlist"
	ir.AllowedHosts = []string{"packages.example.invalid", "registry.example.invalid"}
	ir.Nodes[4].Attributes["network"] = "allowlist"
	if err := ir.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ir.AllowedHosts = []string{"registry.example.invalid", "packages.example.invalid"}
	if err := ir.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsorted host error = %v", err)
	}
}

func TestValidateNeverAcceptsSecretValues(t *testing.T) {
	t.Parallel()
	ir := validIR()
	ir.Nodes[3].Attributes["value"] = "must-not-enter-ir"
	if err := ir.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Validate error = %v", err)
	}
}
