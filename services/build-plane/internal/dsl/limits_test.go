package dsl

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestCompileEnforcesSourceASTStepAndCallDepthLimits(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		mutate func(*Options)
		input  Input
		code   string
	}{
		"source bytes": {
			mutate: func(options *Options) { options.Limits.MaxSourceBytes = 32 },
			input:  inputFor(strings.Repeat("x", 33)),
			code:   "dsl.source_size",
		},
		"AST nodes": {
			mutate: func(options *Options) { options.Limits.MaxASTNodes = 12 },
			input: inputFor(`src = source(path = ".")
static_site(name = "site", source_dir = src, headers = {})`),
			code: "dsl.ast_limit",
		},
		"execution steps": {
			mutate: func(options *Options) { options.Limits.MaxSteps = 20 },
			input: inputFor(manyAssignments(40) + `
src = source(path = ".")
static_site(name = "site", source_dir = src, headers = {})`),
			code: "dsl.step_limit",
		},
		"call depth": {
			mutate: func(options *Options) { options.Limits.MaxCallDepth = 6 },
			input:  inputFor(functionChain(12)),
			code:   "dsl.call_depth",
		},
		"built-in call depth": {
			mutate: func(options *Options) { options.Limits.MaxCallDepth = 1 },
			input:  inputFor(`src = source(path = ".")`),
			code:   "dsl.call_depth",
		},
	}
	for name, testCase := range tests {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := compilerForTest(t, testCase.mutate).Compile(context.Background(), testCase.input)
			if diagnostic := diagnosticFor(t, err); diagnostic.Code != testCase.code {
				t.Fatalf("diagnostic code = %q, want %q (%v)", diagnostic.Code, testCase.code, err)
			}
		})
	}
}

func TestCompileEnforcesStringCollectionResultAndOutputLimits(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		mutate func(*Options)
		source string
		code   string
	}{
		"string": {
			mutate: func(options *Options) { options.Limits.MaxStringBytes = 8 },
			source: `value = "123456789"`,
			code:   "dsl.string_limit",
		},
		"collection": {
			mutate: func(options *Options) { options.Limits.MaxCollectionItems = 2 },
			source: `value = ["one", "two", "three"]`,
			code:   "dsl.collection_limit",
		},
		"result nodes": {
			mutate: func(options *Options) { options.Limits.MaxResultNodes = 2 },
			source: `src = source(path = ".")
base = image(ref = "` + testBaseImage + `")
cache_mount = cache(name = "cache", target = "/cache", sharing = "locked")
artifact(name = "api", state = base, entrypoint = [], cmd = [], ports = [], labels = {})`,
			code: "dsl.result_limit",
		},
		"outputs": {
			mutate: func(options *Options) { options.Limits.MaxOutputs = 1 },
			source: `src = source(path = ".")
static_site(name = "first", source_dir = src, headers = {})
static_site(name = "second", source_dir = src, headers = {})`,
			code: "dsl.output_limit",
		},
	}
	for name, testCase := range tests {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := compilerForTest(t, testCase.mutate).Compile(context.Background(), inputFor(testCase.source))
			if diagnostic := diagnosticFor(t, err); diagnostic.Code != testCase.code {
				t.Fatalf("diagnostic code = %q, want %q", diagnostic.Code, testCase.code)
			}
		})
	}
}

func TestCompileRejectsAmplifyingAndMutableSyntax(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"for loop": `for x in [1]:
    y = x`,
		"while loop": `while True:
    pass`,
		"comprehension": `values = [x for x in [1, 2, 3]]`,
		"list multiply": `values = [1] * 1000000000`,
		"string add":    `value = "a" + "b"`,
		"method mutation": `values = []
values.append("x")`,
		"augmented": `value = 1
value += 1`,
		"lambda":       `value = lambda x: x`,
		"slice":        `value = [1, 2][0:1]`,
		"byte literal": `value = b"bytes"`,
		"allocator":    `value = list((1, 2))`,
		"allocator alias": `allocate = list
value = allocate((1, 2))`,
		"method recovery": `values = []
getattr(values, "extend")(values)`,
	}
	for name, source := range tests {
		source := source
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := compilerForTest(t, nil).Compile(context.Background(), inputFor(source))
			if diagnostic := diagnosticFor(t, err); diagnostic.Code != "dsl.unsupported_syntax" {
				t.Fatalf("diagnostic = %#v", diagnostic)
			}
		})
	}
}

func TestCompileHonorsCancellationDeadlineAndEncoding(t *testing.T) {
	t.Parallel()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := compilerForTest(t, nil).Compile(canceled, inputFor(validProgram()))
	if diagnostic := diagnosticFor(t, err); diagnostic.Code != "dsl.canceled" {
		t.Fatalf("cancel diagnostic = %#v", diagnostic)
	}

	deadlineCompiler := compilerForTest(t, func(options *Options) {
		options.Limits.MaxEvaluationDuration = time.Nanosecond
	})
	_, err = deadlineCompiler.Compile(context.Background(), inputFor(manyAssignments(2000)))
	if diagnostic := diagnosticFor(t, err); diagnostic.Code != "dsl.deadline" {
		t.Fatalf("deadline diagnostic = %#v", diagnostic)
	}

	_, err = compilerForTest(t, nil).Compile(context.Background(), Input{Filename: "Lrailfile.star", Source: []byte{0xff, 0xfe}})
	if diagnostic := diagnosticFor(t, err); diagnostic.Code != "dsl.source_encoding" {
		t.Fatalf("encoding diagnostic = %#v", diagnostic)
	}
	_, err = compilerForTest(t, nil).Compile(context.Background(), Input{Filename: "../Lrailfile.star", Source: []byte("x = 1")})
	if diagnostic := diagnosticFor(t, err); diagnostic.Code != "dsl.filename" {
		t.Fatalf("filename diagnostic = %#v", diagnostic)
	}
}

func TestCompileEnforcesAggregateSourceBudgetAcrossModules(t *testing.T) {
	t.Parallel()
	moduleSource := "def identity(value):\n    return value\n"
	module := Module{Path: "build/helper.star", Source: []byte(moduleSource), Digest: hashSource([]byte(moduleSource))}
	program := `load("//build/helper.star", "identity")
src = source(path = ".")
static_site(name = "site", source_dir = identity(value = src), headers = {})`
	compiler := compilerForTest(t, func(options *Options) {
		options.Limits.MaxSourceBytes = len(program) + len(moduleSource) - 1
	})
	_, err := compiler.Compile(context.Background(), inputFor(program, module))
	if diagnostic := diagnosticFor(t, err); diagnostic.Code != "dsl.source_size" {
		t.Fatalf("aggregate source diagnostic = %#v", diagnostic)
	}
}

func manyAssignments(count int) string {
	var source strings.Builder
	for index := range count {
		fmt.Fprintf(&source, "value_%d = %d\n", index, index)
	}
	return source.String()
}

func functionChain(depth int) string {
	var source strings.Builder
	for index := 1; index <= depth; index++ {
		fmt.Fprintf(&source, "def f%d():\n", index)
		if index == depth {
			source.WriteString("    return source(path = \".\")\n")
		} else {
			fmt.Fprintf(&source, "    return f%d()\n", index+1)
		}
	}
	source.WriteString("src = f1()\nstatic_site(name = \"site\", source_dir = src, headers = {})\n")
	return source.String()
}
