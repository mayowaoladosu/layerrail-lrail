package dsl

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDiagnosticsContainStableSafeLocationRuleHintAndStack(t *testing.T) {
	t.Parallel()
	program := `def emit():
    return source(path = "../host")
emit()
`
	_, err := compilerForTest(t, nil).Compile(context.Background(), inputFor(program))
	diagnostic := diagnosticFor(t, err)
	if diagnostic.Code != "dsl.path" || diagnostic.Rule != "builtins.source.path" || diagnostic.Hint == "" {
		t.Fatalf("diagnostic metadata = %#v", diagnostic)
	}
	if diagnostic.File != "Lrailfile.star" || diagnostic.Line != 2 || diagnostic.Column < 1 {
		t.Fatalf("diagnostic position = %#v", diagnostic)
	}
	if len(diagnostic.CallStack) < 2 {
		t.Fatalf("call stack = %#v", diagnostic.CallStack)
	}
	for _, frame := range diagnostic.CallStack {
		if strings.Contains(frame.File, `C:\`) || strings.Contains(frame.File, "/Users/") {
			t.Fatalf("host path leaked in frame: %#v", frame)
		}
	}
}

func TestDiagnosticsNeverEchoSourceLiteralsOrSecretValues(t *testing.T) {
	t.Parallel()
	const secretValue = "customer-super-secret-value"
	program := `secret(name = "build-key", target = "/run/secrets/build-key", required = True, value = "` + secretValue + `")`
	_, err := compilerForTest(t, nil).Compile(context.Background(), inputFor(program))
	diagnostic := diagnosticFor(t, err)
	serialized, marshalErr := json.Marshal(diagnostic)
	if marshalErr != nil {
		t.Fatalf("Marshal: %v", marshalErr)
	}
	if strings.Contains(err.Error(), secretValue) || strings.Contains(string(serialized), secretValue) {
		t.Fatalf("secret leaked through diagnostic: %v %s", err, serialized)
	}
	if diagnostic.Code != "dsl.arguments" {
		t.Fatalf("diagnostic code = %q", diagnostic.Code)
	}
}

func TestSyntaxDiagnosticsUseRepositoryRelativePositions(t *testing.T) {
	t.Parallel()
	_, err := compilerForTest(t, nil).Compile(context.Background(), inputFor("value = (\n"))
	diagnostic := diagnosticFor(t, err)
	if diagnostic.Code != "dsl.syntax" || diagnostic.File != "Lrailfile.star" || diagnostic.Line < 1 || diagnostic.Column < 1 {
		t.Fatalf("syntax diagnostic = %#v", diagnostic)
	}
	if diagnostic.Message == "" || diagnostic.Rule == "" || diagnostic.CallStack == nil {
		t.Fatalf("incomplete syntax diagnostic = %#v", diagnostic)
	}
}

func TestBuiltinsReportNamedArgumentAndReferenceErrorsAtCallSite(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		source string
		code   string
	}{
		"positional": {
			source: `src = source(".")`,
			code:   "dsl.named_arguments",
		},
		"missing": {
			source: `src = source(path = ".")
artifact(name = "api", state = src, entrypoint = [], cmd = [], ports = [], labels = {})`,
			code: "dsl.reference_type",
		},
		"unknown": {
			source: `src = source(path = ".", surprise = True)`,
			code:   "dsl.arguments",
		},
	}
	for name, testCase := range tests {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := compilerForTest(t, nil).Compile(context.Background(), inputFor(testCase.source))
			diagnostic := diagnosticFor(t, err)
			if diagnostic.Code != testCase.code || diagnostic.File != "Lrailfile.star" || diagnostic.Line < 1 {
				t.Fatalf("diagnostic = %#v", diagnostic)
			}
		})
	}
}

func diagnosticFor(t *testing.T, err error) Diagnostic {
	t.Helper()
	if err == nil {
		t.Fatal("expected compile error")
	}
	if !errors.Is(err, ErrCompile) {
		t.Fatalf("error does not wrap ErrCompile: %v", err)
	}
	var compileError *CompileError
	if !errors.As(err, &compileError) {
		t.Fatalf("error is not a CompileError: %T %v", err, err)
	}
	return compileError.Diagnostic
}
