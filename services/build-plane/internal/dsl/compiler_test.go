package dsl

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildir"
)

const testSourceSnapshot = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testBaseImage = "registry.example.invalid/lrail/ruby:3.4@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func compilerForTest(t *testing.T, mutate func(*Options)) *Compiler {
	t.Helper()
	options := Options{
		DSLAPIVersion:       buildir.CurrentDSLAPIVersion,
		CompilerVersion:     "0.2.0",
		SourceSnapshot:      testSourceSnapshot,
		TargetPlatform:      "linux/amd64",
		NetworkProfile:      "packages",
		ApprovedModuleRoots: []string{"build"},
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

func inputFor(source string, modules ...Module) Input {
	return Input{Filename: "Lrailfile.star", Source: []byte(source), Modules: modules}
}

func validProgram() string {
	return `src = source(path = ".", include = ["app/**"], exclude = [".git/**"])
base = image(ref = "` + testBaseImage + `")
bundle = cache(name = "bundle", target = "/usr/local/bundle", sharing = "locked")
key = secret(name = "rails-build-key", target = "/run/secrets/rails-build-key", required = True)
deps = run(base = base, argv = ["bundle", "install"], env = {"RAILS_ENV": "production"}, mounts = [key, bundle], network = "packages", user = "10001:10001", workdir = "/workspace")
app = copy(base = deps, src = src, dest = "/workspace", owner = "10001:10001", mode = "0755")
artifact(name = "api", state = app, entrypoint = ["bin/rails"], cmd = ["server"], ports = [3000], labels = {"org.example.kind": "web"})
`
}

func TestCompileProducesDeterministicValidatedIR(t *testing.T) {
	t.Parallel()
	compiler := compilerForTest(t, nil)
	first, err := compiler.Compile(context.Background(), inputFor(validProgram()))
	if err != nil {
		t.Fatalf("Compile first: %v", err)
	}
	second, err := compiler.Compile(context.Background(), inputFor(validProgram()))
	if err != nil {
		t.Fatalf("Compile second: %v", err)
	}
	if first.Digest != second.Digest {
		t.Fatalf("digest changed: %q != %q", first.Digest, second.Digest)
	}
	if err := first.IR.Validate(); err != nil {
		t.Fatalf("IR Validate: %v", err)
	}
	if len(first.IR.Nodes) != 6 || len(first.IR.Outputs) != 1 {
		t.Fatalf("unexpected graph size: %d nodes, %d outputs", len(first.IR.Nodes), len(first.IR.Outputs))
	}
	if first.IR.DSLAPIVersion != buildir.CurrentDSLAPIVersion || first.IR.CompilerVersion != "0.2.0" {
		t.Fatalf("compatibility identity missing: %#v", first.IR)
	}
	serialized, err := json.Marshal(first.IR)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if stringContainsAny(string(serialized), "must-not-enter-ir", "secret_value", "plaintext") {
		t.Fatalf("secret material entered Build IR: %s", serialized)
	}
}

func TestCompilerIsSafeForConcurrentIndependentRequests(t *testing.T) {
	t.Parallel()
	compiler := compilerForTest(t, nil)
	const workers = 12
	digests := make(chan string, workers)
	errorsChannel := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := compiler.Compile(context.Background(), inputFor(validProgram()))
			if err != nil {
				errorsChannel <- err
				return
			}
			digests <- result.Digest
		}()
	}
	wait.Wait()
	close(digests)
	close(errorsChannel)
	for err := range errorsChannel {
		t.Fatalf("Compile: %v", err)
	}
	var expected string
	for digest := range digests {
		if expected == "" {
			expected = digest
		}
		if digest != expected {
			t.Fatalf("concurrent digest = %q, want %q", digest, expected)
		}
	}
}

func TestCompileSupportsExplicitShellAndStaticOutputs(t *testing.T) {
	t.Parallel()
	program := `src = source(path = "public", include = ["**"], exclude = [])
base = image(ref = "` + testBaseImage + `")
built = run(base = base, argv = shell(command = "printf '%s\\n' ready"), env = {}, mounts = [], network = "none", user = "10001:10001", workdir = "/workspace")
artifact(name = "worker", state = built, entrypoint = [], cmd = ["job"], ports = [], labels = {})
static_site(name = "site", source_dir = src, headers = {"Cache-Control": "public, max-age=60"})
`
	result, err := compilerForTest(t, nil).Compile(context.Background(), inputFor(program))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(result.IR.Outputs) != 2 || result.IR.Outputs[0].Name != "site" || result.IR.Outputs[1].Name != "worker" {
		t.Fatalf("outputs not normalized: %#v", result.IR.Outputs)
	}
	arguments := result.IR.Nodes[2].Attributes["argv"].([]string)
	if result.IR.Nodes[2].Attributes["shell"] != true || arguments[0] != "/bin/sh" {
		t.Fatalf("explicit shell marker missing: %#v", result.IR.Nodes[2])
	}
}

func TestCompileCarriesCanonicalNetworkAllowlist(t *testing.T) {
	t.Parallel()
	compiler := compilerForTest(t, func(options *Options) {
		options.NetworkProfile = "allowlist"
		options.AllowedHosts = []string{"registry.example.invalid", "packages.example.invalid"}
	})
	program := `base = image(ref = "` + testBaseImage + `")
state = run(base = base, argv = ["true"], env = {}, mounts = [], network = "allowlist", user = "10001:10001", workdir = "/workspace")
artifact(name = "api", state = state, entrypoint = [], cmd = [], ports = [], labels = {})`
	result, err := compiler.Compile(context.Background(), inputFor(program))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	want := []string{"packages.example.invalid", "registry.example.invalid"}
	if !slices.Equal(result.IR.AllowedHosts, want) {
		t.Fatalf("allowed hosts = %#v, want %#v", result.IR.AllowedHosts, want)
	}
}

func TestCompileRejectsAmbientCapabilitiesAndPositionalBuiltins(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"file":          `x = open("/etc/passwd")`,
		"environment":   `x = getenv("HOME")`,
		"network":       `x = http_get("https://example.invalid")`,
		"clock":         `x = now()`,
		"random":        `x = random()`,
		"process":       `x = exec(["id"])`,
		"print":         `print("not allowed")`,
		"positional":    `src = source(".")`,
		"drive source":  `src = source(path = "C:workspace")`,
		"mutable image": `base = image(ref = "ruby:latest")`,
		"implicit shell": `base = image(ref = "` + testBaseImage + `")
run(base = base, argv = ["/bin/sh", "-c", "echo unsafe"], env = {}, mounts = [], network = "none", user = "10001:10001", workdir = "/workspace")`,
		"network escalation": `base = image(ref = "` + testBaseImage + `")
run(base = base, argv = ["true"], env = {}, mounts = [], network = "private", user = "10001:10001", workdir = "/workspace")`,
		"secret traversal": `secret(name = "key", target = "/run/secrets/../key", required = True)`,
		"header alias": `src = source(path = ".")
static_site(name = "site", source_dir = src, headers = {"Cache-Control": "public", "cache-control": "private"})`,
	}
	for name, source := range tests {
		source := source
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := compilerForTest(t, nil).Compile(context.Background(), inputFor(source))
			if !errors.Is(err, ErrCompile) {
				t.Fatalf("Compile error = %v", err)
			}
		})
	}
}

func TestCompileRejectsMissingDuplicateAndForgedOutputs(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"no output": `source(path = ".")`,
		"forged":    `artifact(name = "api", state = "n1", entrypoint = [], cmd = [], ports = [], labels = {})`,
		"duplicate": `src = source(path = ".")
static_site(name = "site", source_dir = src, headers = {})
static_site(name = "site", source_dir = src, headers = {})`,
		"secret state": `key = secret(name = "key", target = "/run/secrets/key", required = True)
artifact(name = "api", state = key, entrypoint = [], cmd = [], ports = [], labels = {})`,
	}
	for name, source := range tests {
		source := source
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := compilerForTest(t, nil).Compile(context.Background(), inputFor(source))
			if !errors.Is(err, ErrCompile) {
				t.Fatalf("Compile error = %v", err)
			}
		})
	}
}

func TestNewRejectsUnsafeCompatibilityAndPolicyOptions(t *testing.T) {
	t.Parallel()
	valid := Options{
		DSLAPIVersion:   buildir.CurrentDSLAPIVersion,
		CompilerVersion: "0.2.0",
		SourceSnapshot:  testSourceSnapshot,
	}
	tests := map[string]func(*Options){
		"DSL version":       func(options *Options) { options.DSLAPIVersion = "lrail.build/v2" },
		"compiler version":  func(options *Options) { options.CompilerVersion = "latest" },
		"snapshot":          func(options *Options) { options.SourceSnapshot = "mutable" },
		"platform":          func(options *Options) { options.TargetPlatform = "windows/amd64" },
		"network profile":   func(options *Options) { options.NetworkProfile = "internet" },
		"missing allowlist": func(options *Options) { options.NetworkProfile = "allowlist" },
		"hosts without profile": func(options *Options) {
			options.AllowedHosts = []string{"packages.example.invalid"}
		},
		"invalid host": func(options *Options) {
			options.NetworkProfile = "allowlist"
			options.AllowedHosts = []string{"https://packages.example.invalid"}
		},
		"module root":    func(options *Options) { options.ApprovedModuleRoots = []string{"../build"} },
		"duplicate root": func(options *Options) { options.ApprovedModuleRoots = []string{"build", "build"} },
		"unsafe limit":   func(options *Options) { options.Limits.MaxSourceBytes = DefaultMaxSourceBytes + 1 },
	}
	for name, mutate := range tests {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			options := valid
			mutate(&options)
			if _, err := New(options); !errors.Is(err, ErrCompile) {
				t.Fatalf("New error = %v", err)
			}
		})
	}
}

func stringContainsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if len(candidate) > 0 && strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}
