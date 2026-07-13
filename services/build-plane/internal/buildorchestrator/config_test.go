package buildorchestrator

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
)

func TestCommittedMBBuildPolicyAndBaseCatalogConform(t *testing.T) {
	t.Parallel()
	var policy llbcompiler.Policy
	decodeConfig(t, "../../config/build-policy.v1.example.json", &policy)
	var catalog BaseCatalog
	decodeConfig(t, "../../config/base-catalog.v1.json", &catalog)
	compiler, err := NewDefinitionCompiler(policy, catalog, "0.3.0", "0.2.0")
	if err != nil {
		t.Fatalf("NewDefinitionCompiler: %v", err)
	}
	if compiler.Catalog.Entries[0].Material.ResolutionDigest != "sha256:10e6846b69e6978fd51a0825ac080fc7ac8e2408af53ac2e5e0968c04f7bc7ef" {
		t.Fatalf("resolution digest = %s", compiler.Catalog.Entries[0].Material.ResolutionDigest)
	}
}

func decodeConfig(t *testing.T, path string, destination any) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		t.Fatalf("Decode %s: %v", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatalf("trailing data in %s: %v", path, err)
	}
}
