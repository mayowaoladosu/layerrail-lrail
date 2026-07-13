package dsl

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildir"
)

func FuzzCompileHostileStarlark(f *testing.F) {
	compiler, err := New(Options{
		DSLAPIVersion:       buildir.CurrentDSLAPIVersion,
		CompilerVersion:     "0.2.0",
		SourceSnapshot:      testSourceSnapshot,
		NetworkProfile:      "packages",
		ApprovedModuleRoots: []string{"build"},
		Limits: Limits{
			MaxEvaluationDuration: 250 * time.Millisecond,
		},
	})
	if err != nil {
		f.Fatalf("New: %v", err)
	}
	f.Add([]byte(validProgram()))
	f.Add([]byte(`load("//../escape.star", "x")`))
	f.Add([]byte(`values = [x for x in range(1000000000)]`))
	f.Add([]byte{0xff, 0xfe, 0x00})
	f.Fuzz(func(t *testing.T, source []byte) {
		if len(source) > DefaultMaxSourceBytes+1 {
			t.Skip()
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		result, compileErr := compiler.Compile(ctx, Input{Filename: "Lrailfile.star", Source: source})
		if compileErr == nil {
			if err := result.IR.Validate(); err != nil {
				t.Fatalf("successful compile emitted invalid IR: %v", err)
			}
			return
		}
		if strings.Contains(compileErr.Error(), `C:\Users\`) || strings.Contains(compileErr.Error(), "/Users/") {
			t.Fatalf("host path leaked through error: %v", compileErr)
		}
	})
}
