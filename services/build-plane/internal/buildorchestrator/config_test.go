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
	material := compiler.Catalog.Entries[0].Material
	if material.ResolutionDigest != "sha256:461aadf2be0c3f76155bcdf155b4a63a5b9151ede0703cb755f69998d0ffd303" {
		t.Fatalf("resolution digest = %s", compiler.Catalog.Entries[0].Material.ResolutionDigest)
	}
	if material.Registry != "ghcr.io" || material.Classification != "curated" || len(material.Platforms) != 1 || material.Platforms[0] != "linux/amd64" {
		t.Fatalf("curated material = %#v", material)
	}
	if compiler.Policy.Base.AllowCustomerBases || len(compiler.Policy.Base.CuratedDigests) != 1 || compiler.Policy.Base.CuratedDigests[0] != material.Digest {
		t.Fatalf("curated policy = %#v", compiler.Policy.Base)
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
