package llbcompiler

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type goldenSummary struct {
	DefinitionDigest string   `json:"definition_digest"`
	IRDigest         string   `json:"ir_digest"`
	PolicyDigest     string   `json:"policy_digest"`
	OutputName       string   `json:"output_name"`
	OutputKind       string   `json:"output_kind"`
	LLBDigest        string   `json:"llb_digest"`
	ConfigDigest     string   `json:"config_digest"`
	Head             string   `json:"head"`
	VertexKinds      []string `json:"vertex_kinds"`
}

func TestLLBDefinitionGoldenSummary(t *testing.T) {
	t.Parallel()
	compiler, err := New("0.1.0")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	result, err := compiler.Compile(context.Background(), validCompileRequest(t))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	actual := goldenSummary{
		DefinitionDigest: result.DefinitionDigest,
		IRDigest:         result.IRDigest,
		PolicyDigest:     result.PolicyDigest,
		OutputName:       result.Outputs[0].Name,
		OutputKind:       result.Outputs[0].Kind,
		LLBDigest:        result.Outputs[0].LLBDigest,
		ConfigDigest:     result.Lock.Outputs[0].ConfigDigest,
		Head:             result.Outputs[0].Head,
		VertexKinds:      vertexKinds(result.Outputs[0].Graph),
	}
	contents, err := os.ReadFile(filepath.Join("testdata", "golden", "summary.json"))
	if err != nil {
		t.Fatalf("Read golden: %v", err)
	}
	var expected goldenSummary
	if err := json.Unmarshal(contents, &expected); err != nil {
		t.Fatalf("Unmarshal golden: %v", err)
	}
	if !reflect.DeepEqual(actual, expected) {
		actualJSON, _ := json.MarshalIndent(actual, "", "  ")
		expectedJSON, _ := json.MarshalIndent(expected, "", "  ")
		t.Fatalf("LLB summary differs\nactual: %s\nexpected: %s", actualJSON, expectedJSON)
	}
}
