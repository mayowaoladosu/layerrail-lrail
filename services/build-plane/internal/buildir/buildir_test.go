package buildir

import (
	"errors"
	"strings"
	"testing"
)

const digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func validIR() IR {
	return IR{
		Version:         CurrentVersion,
		CompilerVersion: "0.1.0",
		SourceSnapshot:  digestA,
		TargetPlatform:  "linux/amd64",
		NetworkProfile:  "packages",
		Nodes: []Node{
			{ID: "n1", Operation: "source", Attributes: map[string]any{"path": "."}},
			{ID: "n2", Operation: "image", Attributes: map[string]any{"digest": digestB}},
			{ID: "n3", Operation: "run", Inputs: []string{"n2"}, Attributes: map[string]any{"argv": []string{"bundle", "install"}, "network": "packages"}},
			{ID: "n4", Operation: "copy", Inputs: []string{"n1", "n3"}, Attributes: map[string]any{"destination": "/workspace"}},
		},
		Outputs: []Output{{Name: "api", Kind: "oci_image", State: "n4", Ports: []int{3000}}},
	}
}

func TestDefinitionDigestIsStable(t *testing.T) {
	t.Parallel()
	first := validIR()
	second := validIR()
	second.Nodes[0].Attributes = map[string]any{"path": "."}
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
}

func TestValidateRejectsUnsafeGraphs(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*IR){
		"version":         func(ir *IR) { ir.Version = 2 },
		"source digest":   func(ir *IR) { ir.SourceSnapshot = "latest" },
		"platform":        func(ir *IR) { ir.TargetPlatform = "windows/amd64" },
		"network":         func(ir *IR) { ir.NetworkProfile = "internet" },
		"network ceiling": func(ir *IR) { ir.NetworkProfile = "none" },
		"allowed hosts":   func(ir *IR) { ir.AllowedHosts = []string{"packages.invalid"} },
		"duplicate":       func(ir *IR) { ir.Nodes[1].ID = "n1" },
		"forward input":   func(ir *IR) { ir.Nodes[0].Inputs = []string{"n4"} },
		"unknown op":      func(ir *IR) { ir.Nodes[0].Operation = "shell" },
		"source escape":   func(ir *IR) { ir.Nodes[0].Attributes["path"] = "../host" },
		"mutable image":   func(ir *IR) { ir.Nodes[1].Attributes["digest"] = "ruby:latest" },
		"empty argv":      func(ir *IR) { ir.Nodes[2].Attributes["argv"] = []string{} },
		"bad run net":     func(ir *IR) { ir.Nodes[2].Attributes["network"] = "internet" },
		"copy escape":     func(ir *IR) { ir.Nodes[3].Attributes["destination"] = "/app/../host" },
		"unknown state":   func(ir *IR) { ir.Outputs[0].State = "n99" },
		"bad port":        func(ir *IR) { ir.Outputs[0].Ports = []int{70000} },
		"bad kind":        func(ir *IR) { ir.Outputs[0].Kind = "tar" },
		"bad attribute":   func(ir *IR) { ir.Nodes[0].Attributes["nested"] = map[string]any{"x": true} },
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

func TestValidateRejectsSecretValues(t *testing.T) {
	t.Parallel()
	ir := validIR()
	ir.Nodes = append(ir.Nodes, Node{
		ID:        "n5",
		Operation: "secret",
		Attributes: map[string]any{
			"id":    "registry-token",
			"value": "must-not-enter-ir",
		},
	})
	if err := ir.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Validate error = %v", err)
	}
}

func TestValidateAcceptsAllowlistedHosts(t *testing.T) {
	t.Parallel()
	ir := validIR()
	ir.NetworkProfile = "allowlist"
	ir.AllowedHosts = []string{"packages.example.invalid"}
	if err := ir.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateCacheAndSecretMounts(t *testing.T) {
	t.Parallel()
	ir := validIR()
	ir.Nodes = append(ir.Nodes,
		Node{ID: "n5", Operation: "cache", Attributes: map[string]any{"target": "/cache", "scope": "project"}},
		Node{ID: "n6", Operation: "secret", Attributes: map[string]any{"id": "registry", "target": "/run/secrets/registry"}},
	)
	if err := ir.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ir.Nodes[4].Attributes["scope"] = "global"
	if err := ir.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid cache scope error = %v", err)
	}
}
