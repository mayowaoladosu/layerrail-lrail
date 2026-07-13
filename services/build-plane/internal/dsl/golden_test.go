package dsl

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
)

const expectedGoldenDefinitionDigest = "sha256:9187fe043c44b328855131e8fa673c51a2baa2112e83e36bc11e7426b9605973"

func TestDeterministicIRGoldenFixture(t *testing.T) {
	t.Parallel()
	entry := readGoldenFile(t, "Lrailfile.star")
	moduleSource := readGoldenFile(t, "helpers.star")
	module := Module{
		Path:   "build/helpers.star",
		Digest: hashSource(moduleSource),
		Source: moduleSource,
	}
	result, err := compilerForTest(t, nil).Compile(context.Background(), Input{
		Filename: "Lrailfile.star",
		Source:   entry,
		Modules:  []Module{module},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	actualJSON, err := json.Marshal(result.IR)
	if err != nil {
		t.Fatalf("Marshal IR: %v", err)
	}
	expectedJSON, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "contracts", "fixtures", "build-ir-v2.valid.json"))
	if err != nil {
		t.Fatalf("Read golden fixture: %v", err)
	}
	actualCanonical, err := canonicaljson.Normalize(actualJSON)
	if err != nil {
		t.Fatalf("Normalize actual: %v", err)
	}
	expectedCanonical, err := canonicaljson.Normalize(expectedJSON)
	if err != nil {
		t.Fatalf("Normalize expected: %v", err)
	}
	if !bytes.Equal(actualCanonical, expectedCanonical) {
		t.Fatalf("Build IR differs from golden fixture\nactual: %s\nexpected: %s", actualCanonical, expectedCanonical)
	}
	if result.Digest != expectedGoldenDefinitionDigest {
		t.Fatalf("definition digest = %q, want %q", result.Digest, expectedGoldenDefinitionDigest)
	}
}

func readGoldenFile(t *testing.T, name string) []byte {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("testdata", "golden", name))
	if err != nil {
		t.Fatalf("Read %s: %v", name, err)
	}
	return contents
}
