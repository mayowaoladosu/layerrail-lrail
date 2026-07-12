package dsl

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const (
	sourceDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	baseDigest   = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func compilerForTest(t *testing.T, mutate func(*Options)) *Compiler {
	t.Helper()
	options := Options{
		CompilerVersion: "0.1.0",
		SourceSnapshot:  sourceDigest,
		TargetPlatform:  "linux/amd64",
		NetworkProfile:  "packages",
		MaxSteps:        10_000,
	}
	if mutate != nil {
		mutate(&options)
	}
	compiler, err := New(options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return compiler
}

func validProgram() []byte {
	return []byte(`
src = source(path = ".", exclude = [".git/**"])
base = image(digest = "` + baseDigest + `")
deps = run(base = base, argv = ["bundle", "install"], network = "packages")
app = copy(base = deps, source = src, destination = "/workspace")
secret(id = "bundle-token", target = "/run/secrets/bundle-token")
artifact(name = "api", state = app, entrypoint = ["bin/rails"], command = ["server"], ports = [3000])
`)
}

func TestCompileProducesDeterministicValidatedIR(t *testing.T) {
	t.Parallel()
	compiler := compilerForTest(t, nil)
	first, err := compiler.Compile(context.Background(), "Lrailfile.star", validProgram())
	if err != nil {
		t.Fatalf("Compile first: %v", err)
	}
	second, err := compiler.Compile(context.Background(), "Lrailfile.star", validProgram())
	if err != nil {
		t.Fatalf("Compile second: %v", err)
	}
	if first.Digest != second.Digest {
		t.Fatalf("digest changed: %q != %q", first.Digest, second.Digest)
	}
	if len(first.IR.Nodes) != 5 || len(first.IR.Outputs) != 1 {
		t.Fatalf("unexpected graph size: %d nodes, %d outputs", len(first.IR.Nodes), len(first.IR.Outputs))
	}
	secret := first.IR.Nodes[4]
	if _, exists := secret.Attributes["value"]; exists {
		t.Fatal("secret value entered Build IR")
	}
}

func TestCompileRejectsAmbientIOAndUnsafeInput(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"load":          `load("https://invalid/module.star", "x")`,
		"source escape": `s = source(path = "../host")\nstatic_site(name = "x", state = s)`,
		"mutable image": `i = image(digest = "ruby:latest")\nartifact(name = "x", state = i)`,
		"secret value":  `secret(id = "x", target = "/run/x", value = "plaintext")`,
		"no output":     `source(path = ".")`,
		"forged handle": `artifact(name = "x", state = "n1")`,
	}
	for name, source := range tests {
		source := source
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := compilerForTest(t, nil).Compile(context.Background(), "Lrailfile.star", []byte(source))
			if !errors.Is(err, ErrCompile) {
				t.Fatalf("Compile error = %v", err)
			}
		})
	}
}

func TestCompileEnforcesSourceAndStepLimits(t *testing.T) {
	t.Parallel()
	compiler := compilerForTest(t, func(options *Options) {
		options.MaxSourceBytes = 32
		options.MaxSteps = 100
	})
	if _, err := compiler.Compile(context.Background(), "Lrailfile.star", []byte(strings.Repeat("x", 33))); !errors.Is(err, ErrCompile) {
		t.Fatalf("source limit error = %v", err)
	}
	program := []byte(`x = [i for i in range(10000)]`)
	if _, err := compiler.Compile(context.Background(), "Lrailfile.star", program); !errors.Is(err, ErrCompile) {
		t.Fatalf("step limit error = %v", err)
	}
}

func TestCompileHonorsCanceledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := compilerForTest(t, nil).Compile(ctx, "Lrailfile.star", validProgram()); !errors.Is(err, ErrCompile) {
		t.Fatalf("Compile error = %v", err)
	}
}

func TestNewRejectsUnsafeOptions(t *testing.T) {
	t.Parallel()
	if _, err := New(Options{}); !errors.Is(err, ErrCompile) {
		t.Fatalf("empty options error = %v", err)
	}
	if _, err := New(Options{CompilerVersion: "x", SourceSnapshot: sourceDigest, MaxSourceBytes: DefaultMaxSourceBytes + 1}); !errors.Is(err, ErrCompile) {
		t.Fatalf("source bound error = %v", err)
	}
}
