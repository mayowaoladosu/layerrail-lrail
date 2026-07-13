package buildorchestrator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildir"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/dsl"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
)

type DefinitionCompiler struct {
	Policy             llbcompiler.Policy
	Catalog            BaseCatalog
	DSLCompilerVersion string
	LLBCompilerVersion string
}

type Compilation struct {
	Program          []byte
	Generated        bool
	IR               buildir.IR
	IRBytes          []byte
	IRDigest         string
	DefinitionDigest string
	PolicyDigest     string
	Lock             llbcompiler.DefinitionLock
	LockBytes        []byte
	Outputs          []llbcompiler.OutputDefinition
	Materials        []llbcompiler.BaseMaterial
}

func NewDefinitionCompiler(policy llbcompiler.Policy, catalog BaseCatalog, dslVersion, llbVersion string) (*DefinitionCompiler, error) {
	if !semanticVersionPattern.MatchString(dslVersion) || !semanticVersionPattern.MatchString(llbVersion) {
		return nil, errors.New("build compiler versions are invalid")
	}
	if err := llbcompiler.ValidatePolicy(policy); err != nil {
		return nil, fmt.Errorf("build policy is invalid: %w", err)
	}
	if err := catalog.Validate(policy); err != nil {
		return nil, err
	}
	return &DefinitionCompiler{Policy: policy, Catalog: catalog, DSLCompilerVersion: dslVersion, LLBCompilerVersion: llbVersion}, nil
}

func (compiler *DefinitionCompiler) Compile(ctx context.Context, request Request, snapshotRoot string, detection DetectionResult) (Compilation, error) {
	if ctx == nil || snapshotRoot == "" {
		return Compilation{}, errors.New("build compilation request is invalid")
	}
	program, materials, generated, filename, err := compiler.program(request, snapshotRoot, detection)
	if err != nil {
		return Compilation{}, err
	}
	network := "none"
	if slices.Contains(compiler.Policy.Network.AllowedProfiles, "packages") {
		network = "packages"
	}
	starlarkCompiler, err := dsl.New(dsl.Options{
		DSLAPIVersion: buildir.CurrentDSLAPIVersion, CompilerVersion: compiler.DSLCompilerVersion,
		SourceSnapshot: request.Source.SnapshotDigest, TargetPlatform: request.TargetPlatform, NetworkProfile: network,
	})
	if err != nil {
		return Compilation{}, err
	}
	starlarkResult, err := starlarkCompiler.Compile(ctx, dsl.Input{Filename: filename, Source: program})
	if err != nil {
		return Compilation{}, err
	}
	if !generated {
		materials, err = compiler.materialsForIR(starlarkResult.IR)
		if err != nil {
			return Compilation{}, err
		}
	}
	llb, err := llbcompiler.New(compiler.LLBCompilerVersion)
	if err != nil {
		return Compilation{}, err
	}
	compiled, err := llb.Compile(ctx, llbcompiler.Request{
		OrganizationID: request.OrganizationID, ProjectID: request.ProjectID, IR: starlarkResult.IR,
		ExpectedIRDigest: starlarkResult.Digest, Policy: compiler.Policy, BaseMaterials: materials,
		BuildArguments: map[string]string{},
	})
	if err != nil {
		return Compilation{}, err
	}
	irBytes, err := canonicaljson.Marshal(starlarkResult.IR)
	if err != nil {
		return Compilation{}, errors.New("canonicalize Build IR")
	}
	lockBytes, err := canonicaljson.Marshal(compiled.Lock)
	if err != nil {
		return Compilation{}, errors.New("canonicalize definition lock")
	}
	return Compilation{
		Program: append([]byte(nil), program...), Generated: generated, IR: starlarkResult.IR, IRBytes: irBytes,
		IRDigest: compiled.IRDigest, DefinitionDigest: compiled.DefinitionDigest, PolicyDigest: compiled.PolicyDigest,
		Lock: compiled.Lock, LockBytes: lockBytes, Outputs: append([]llbcompiler.OutputDefinition(nil), compiled.Outputs...),
		Materials: append([]llbcompiler.BaseMaterial(nil), materials...),
	}, nil
}

func (compiler *DefinitionCompiler) program(request Request, snapshotRoot string, detection DetectionResult) ([]byte, []llbcompiler.BaseMaterial, bool, string, error) {
	if request.Configuration.Mode == "auto" {
		if !request.Configuration.AcceptDetected {
			return nil, nil, false, "", errors.New("detected configuration has not been accepted")
		}
		program, materials, err := GenerateRecipe(detection, compiler.Catalog, request.TargetPlatform)
		return program, materials, true, "Lrailfile.generated.star", err
	}
	relative := selectedBuildFile(request.Source.SelectedRoot, request.Configuration.BuildFile)
	if !validRelativePath(relative, false) {
		return nil, nil, false, "", errors.New("repository build file path is invalid")
	}
	absolute := filepath.Join(snapshotRoot, filepath.FromSlash(relative))
	info, err := os.Lstat(absolute)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > dsl.DefaultMaxSourceBytes {
		return nil, nil, false, "", errors.New("repository build file is unavailable or oversized")
	}
	program, err := os.ReadFile(absolute)
	if err != nil || len(program) == 0 || len(program) > dsl.DefaultMaxSourceBytes {
		return nil, nil, false, "", errors.New("read repository build file")
	}
	return program, nil, false, relative, nil
}

func (compiler *DefinitionCompiler) materialsForIR(ir buildir.IR) ([]llbcompiler.BaseMaterial, error) {
	materials := make([]llbcompiler.BaseMaterial, 0)
	seen := make(map[string]struct{})
	for _, node := range ir.Nodes {
		if node.Operation != "image" {
			continue
		}
		reference, _ := node.Attributes["ref"].(string)
		matched := false
		for _, entry := range compiler.Catalog.Entries {
			if entry.Material.RequestedRef == reference {
				if _, exists := seen[reference]; !exists {
					materials = append(materials, entry.Material)
					seen[reference] = struct{}{}
				}
				matched = true
				break
			}
		}
		if !matched {
			return nil, errors.New("repository build definition requests a base outside the approved catalog")
		}
	}
	slices.SortFunc(materials, func(left, right llbcompiler.BaseMaterial) int {
		return strings.Compare(left.RequestedRef, right.RequestedRef)
	})
	return materials, nil
}

func (compilation Compilation) AssignmentOutputs(refs func(name, suffix string) string) ([]buildcell.OutputArtifact, error) {
	outputs := make([]buildcell.OutputArtifact, 0, len(compilation.Outputs))
	for _, output := range compilation.Outputs {
		if len(output.Definition) == 0 || len(output.Definition) > buildcell.MaxDefinitionBytes || len(output.ImageConfig) > buildcell.MaxConfigBytes {
			return nil, errors.New("compiled output exceeds assignment bounds")
		}
		configDigest := ""
		for _, locked := range compilation.Lock.Outputs {
			if locked.Name == output.Name {
				configDigest = locked.ConfigDigest
				break
			}
		}
		if configDigest == "" {
			return nil, errors.New("compiled output lacks its config lock")
		}
		outputs = append(outputs, buildcell.OutputArtifact{
			Name: output.Name, Kind: output.Kind, LLBDigest: output.LLBDigest, Head: output.Head,
			LLBRef: refs(output.Name, "llb.pb"), ConfigDigest: configDigest, ConfigRef: refs(output.Name, "config.json"),
		})
	}
	return outputs, nil
}
