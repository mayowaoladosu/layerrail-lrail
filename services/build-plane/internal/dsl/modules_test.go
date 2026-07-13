package dsl

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestCompileLoadsVersionedStandardAndApprovedRepositoryModules(t *testing.T) {
	t.Parallel()
	moduleSource := `load("@lrail/v1/helpers.star", "install")
def build(base, cache_mount):
    return install(base = base, argv = ["bundle", "install"], mounts = [cache_mount], network = "packages", env = {"RAILS_ENV": "production"})
`
	module := Module{Path: "build/helpers.star", Digest: hashSource([]byte(moduleSource)), Source: []byte(moduleSource)}
	program := `load("//build/helpers.star", "build")
src = source(path = ".", include = ["app/**"], exclude = [".git/**"])
base = image(ref = "` + testBaseImage + `")
bundle = cache(name = "bundle", target = "/usr/local/bundle", sharing = "locked")
deps = build(base = base, cache_mount = bundle)
app = copy(base = deps, src = src, dest = "/workspace", owner = "10001:10001", mode = "0755")
artifact(name = "api", state = app, entrypoint = [], cmd = ["server"], ports = [3000], labels = {})
`
	result, err := compilerForTest(t, nil).Compile(context.Background(), inputFor(program, module))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(result.IR.Modules) != 2 {
		t.Fatalf("module evidence = %#v", result.IR.Modules)
	}
	if result.IR.Modules[0].Name != "//build/helpers.star" || result.IR.Modules[0].Kind != "repository" {
		t.Fatalf("repository evidence = %#v", result.IR.Modules[0])
	}
	if result.IR.Modules[1].Name != "@lrail/v1/helpers.star" || result.IR.Modules[1].Kind != "standard" {
		t.Fatalf("standard evidence = %#v", result.IR.Modules[1])
	}
}

func TestModuleCacheHandlesDiamondGraphDeterministically(t *testing.T) {
	t.Parallel()
	modules := moduleSet(map[string]string{
		"build/common.star": `def identity(value):
    return value
`,
		"build/left.star": `load("//build/common.star", "identity")
def left(value):
    return identity(value = value)
`,
		"build/right.star": `load("//build/common.star", "identity")
def right(value):
    return identity(value = value)
`,
	})
	program := `load("//build/left.star", "left")
load("//build/right.star", "right")
src = source(path = ".")
base = image(ref = "` + testBaseImage + `")
state = left(value = right(value = base))
artifact(name = "api", state = state, entrypoint = [], cmd = [], ports = [], labels = {})
`
	compiler := compilerForTest(t, nil)
	first, err := compiler.Compile(context.Background(), inputFor(program, modules...))
	if err != nil {
		t.Fatalf("Compile first: %v", err)
	}
	second, err := compiler.Compile(context.Background(), inputFor(program, modules...))
	if err != nil {
		t.Fatalf("Compile second: %v", err)
	}
	if first.Digest != second.Digest || len(first.IR.Modules) != 3 {
		t.Fatalf("cache result changed: %q %q %#v", first.Digest, second.Digest, first.IR.Modules)
	}
}

func TestCompileRejectsModuleTraversalCyclesAndUntrustedSources(t *testing.T) {
	t.Parallel()
	cycleModules := moduleSet(map[string]string{
		"build/a.star": `load("//build/b.star", "b")
a = b
`,
		"build/b.star": `load("//build/a.star", "a")
b = a
`,
	})
	validModuleSource := "x = 1\n"
	validModule := Module{Path: "build/valid.star", Source: []byte(validModuleSource), Digest: hashSource([]byte(validModuleSource))}
	tests := map[string]struct {
		program string
		modules []Module
		code    string
	}{
		"traversal": {
			program: `load("//build/../host.star", "x")`,
			code:    "dsl.module_path",
		},
		"absolute": {
			program: `load("/etc/passwd", "x")`,
			code:    "dsl.module_path",
		},
		"URL": {
			program: `load("https://example.invalid/module.star", "x")`,
			code:    "dsl.module_path",
		},
		"missing": {
			program: `load("//build/missing.star", "x")`,
			code:    "dsl.module_missing",
		},
		"cycle": {
			program: `load("//build/a.star", "a")`,
			modules: cycleModules,
			code:    "dsl.module_cycle",
		},
		"initialization side effect": {
			program: `load("//build/effect.star", "x")`,
			modules: moduleSet(map[string]string{"build/effect.star": "x = source(path = \".\")\n"}),
			code:    "dsl.module_side_effect",
		},
		"unsupported standard version": {
			program: `load("@lrail/v2/helpers.star", "install")`,
			code:    "dsl.module_missing",
		},
		"valid module but missing output": {
			program: `load("//build/valid.star", "x")`,
			modules: []Module{validModule},
			code:    "dsl.output_missing",
		},
	}
	for name, testCase := range tests {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := compilerForTest(t, nil).Compile(context.Background(), inputFor(testCase.program, testCase.modules...))
			if !errors.Is(err, ErrCompile) {
				t.Fatalf("Compile error = %v", err)
			}
			if diagnostic := diagnosticFor(t, err); diagnostic.Code != testCase.code {
				t.Fatalf("diagnostic code = %q, want %q (%v)", diagnostic.Code, testCase.code, err)
			}
		})
	}
}

func TestCompileRejectsModuleSetSubstitutionAndScopeEscape(t *testing.T) {
	t.Parallel()
	source := []byte("x = 1\n")
	tests := map[string]struct {
		modules []Module
		code    string
	}{
		"digest mismatch": {
			modules: []Module{{Path: "build/helpers.star", Digest: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", Source: source}},
			code:    "dsl.module_digest",
		},
		"outside approved root": {
			modules: []Module{{Path: "scripts/helpers.star", Digest: hashSource(source), Source: source}},
			code:    "dsl.module_path",
		},
		"path traversal": {
			modules: []Module{{Path: "build/../helpers.star", Digest: hashSource(source), Source: source}},
			code:    "dsl.module_path",
		},
		"duplicate": {
			modules: []Module{
				{Path: "build/helpers.star", Digest: hashSource(source), Source: source},
				{Path: "build/helpers.star", Digest: hashSource(source), Source: source},
			},
			code: "dsl.module_duplicate",
		},
	}
	for name, testCase := range tests {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := compilerForTest(t, nil).Compile(context.Background(), inputFor(validProgram(), testCase.modules...))
			if diagnostic := diagnosticFor(t, err); diagnostic.Code != testCase.code {
				t.Fatalf("diagnostic code = %q, want %q", diagnostic.Code, testCase.code)
			}
		})
	}
}

func TestCompileEnforcesModuleDepth(t *testing.T) {
	t.Parallel()
	modules := moduleSet(map[string]string{
		"build/a.star": `load("//build/b.star", "b")
a = b
`,
		"build/b.star": `load("//build/c.star", "c")
b = c
`,
		"build/c.star": "c = 1\n",
	})
	compiler := compilerForTest(t, func(options *Options) {
		options.Limits.MaxModuleDepth = 2
	})
	_, err := compiler.Compile(context.Background(), inputFor(`load("//build/a.star", "a")`, modules...))
	if diagnostic := diagnosticFor(t, err); diagnostic.Code != "dsl.module_depth" {
		t.Fatalf("diagnostic = %#v", diagnostic)
	}
}

func TestCompileCountsStandardModulesAgainstTotalModuleLimit(t *testing.T) {
	t.Parallel()
	moduleSource := `load("@lrail/v1/helpers.star", "install")
def build(base):
    return install(base = base, argv = ["true"], network = "none")
`
	module := Module{Path: "build/helper.star", Source: []byte(moduleSource), Digest: hashSource([]byte(moduleSource))}
	compiler := compilerForTest(t, func(options *Options) {
		options.Limits.MaxModules = 1
	})
	_, err := compiler.Compile(context.Background(), inputFor(`load("//build/helper.star", "build")`, module))
	if diagnostic := diagnosticFor(t, err); diagnostic.Code != "dsl.module_limit" {
		t.Fatalf("diagnostic = %#v", diagnostic)
	}
}

func moduleSet(sources map[string]string) []Module {
	paths := make([]string, 0, len(sources))
	for modulePath := range sources {
		paths = append(paths, modulePath)
	}
	slices.Sort(paths)
	modules := make([]Module, 0, len(paths))
	for _, modulePath := range paths {
		source := []byte(sources[modulePath])
		modules = append(modules, Module{Path: modulePath, Digest: hashSource(source), Source: source})
	}
	return modules
}
