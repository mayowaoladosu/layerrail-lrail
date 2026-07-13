package dsl

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildir"
	"go.starlark.net/starlark"
)

const standardHelpersSource = `def install(base, argv, mounts = [], network = "packages", env = {}, user = "10001:10001", workdir = "/workspace"):
    return run(base = base, argv = argv, env = env, mounts = mounts, network = network, user = user, workdir = workdir)
`

type moduleSource struct {
	name   string
	kind   string
	digest string
	source []byte
}

type moduleEntry struct {
	globals starlark.StringDict
	err     error
}

func newCompileSession(compiler *Compiler, entryFile string, modules []Module) (*compileSession, error) {
	limits := compiler.options.Limits
	if len(modules) > limits.MaxModules {
		return nil, failure(
			"dsl.module_limit",
			"Repository module count exceeds the configured limit.",
			"limits.modules",
			fmt.Sprintf("Provide at most %d approved repository modules.", limits.MaxModules),
			entryFile,
			1,
			1,
		)
	}
	session := &compileSession{
		compiler:          compiler,
		limits:            limits,
		entryFile:         entryFile,
		repositoryModules: make(map[string]moduleSource, len(modules)),
		moduleCache:       make(map[string]*moduleEntry),
		usedModules:       make(map[string]buildir.Module),
		nodes:             []buildir.Node{},
		outputs:           []buildir.Output{},
	}
	for _, module := range modules {
		name := "//" + module.Path
		if !validEntryFilename(module.Path) || !compiler.approvesModule(module.Path) {
			return nil, failure(
				"dsl.module_path",
				"A repository module is outside approved canonical module roots.",
				"modules.repository_path",
				"Use a .star path beneath an explicitly approved repository module root.",
				entryFile,
				1,
				1,
			)
		}
		if _, exists := session.repositoryModules[name]; exists {
			return nil, failure(
				"dsl.module_duplicate",
				"A repository module path was supplied more than once.",
				"modules.unique_path",
				"Provide exactly one immutable source for each module path.",
				name,
				1,
				1,
			)
		}
		if sourceFailure := validateSourceBytes(name, module.Source, limits); sourceFailure != nil {
			return nil, sourceFailure
		}
		actualDigest := hashSource(module.Source)
		if module.Digest != actualDigest {
			return nil, failure(
				"dsl.module_digest",
				"A repository module does not match its declared immutable digest.",
				"modules.source_digest",
				"Materialize modules from the accepted source snapshot and recompute their sha256 digest.",
				name,
				1,
				1,
			)
		}
		session.repositoryModules[name] = moduleSource{
			name:   name,
			kind:   "repository",
			digest: actualDigest,
			source: append([]byte(nil), module.Source...),
		}
	}
	return session, nil
}

func (compiler *Compiler) approvesModule(modulePath string) bool {
	for _, root := range compiler.options.ApprovedModuleRoots {
		if strings.HasPrefix(modulePath, root+"/") {
			return true
		}
	}
	return false
}

func (session *compileSession) compileProgram(filename string, source []byte) (*starlark.Program, *CompileError) {
	if sourceFailure := validateSourceBytes(filename, source, session.limits); sourceFailure != nil {
		return nil, sourceFailure
	}
	if session.sourceBytes+len(source) > session.limits.MaxSourceBytes {
		return nil, failure(
			"dsl.source_size",
			"The entry file and loaded modules exceed the aggregate source-byte limit.",
			"limits.source_bytes",
			fmt.Sprintf("Keep all evaluated Starlark source within %d bytes.", session.limits.MaxSourceBytes),
			filename,
			1,
			1,
		)
	}
	session.sourceBytes += len(source)
	file, err := fileOptions.Parse(filename, source, 0)
	if err != nil {
		return nil, compileFailure(err, filename, nil)
	}
	astNodes, policyFailure := validateSyntaxPolicy(file, session.limits, session.astNodes)
	if policyFailure != nil {
		return nil, policyFailure
	}
	session.astNodes = astNodes
	program, err := starlark.FileProgram(file, session.predeclared.Has)
	if err != nil {
		return nil, compileFailure(err, filename, nil)
	}
	return program, nil
}

func (session *compileSession) load(thread *starlark.Thread, name string) (starlark.StringDict, error) {
	if !validModuleName(name) {
		return nil, builtinFailure(
			thread,
			"dsl.module_path",
			"A load target is not a canonical approved module name.",
			"modules.load_path",
			"Use //approved/root/module.star or a versioned @lrail/v1 module.",
		)
	}
	if entry, exists := session.moduleCache[name]; exists {
		if entry == nil {
			return nil, builtinFailure(
				thread,
				"dsl.module_cycle",
				"The Starlark module load graph contains a cycle.",
				"modules.acyclic",
				"Remove the cyclic load edge; module initialization must form a DAG.",
			)
		}
		return entry.globals, entry.err
	}
	if session.moduleDepth >= session.limits.MaxModuleDepth {
		return nil, builtinFailure(
			thread,
			"dsl.module_depth",
			"The Starlark module load graph exceeds the configured depth limit.",
			"limits.module_depth",
			fmt.Sprintf("Keep module load chains within %d levels.", session.limits.MaxModuleDepth),
		)
	}
	module, exists := session.module(name)
	if !exists {
		return nil, builtinFailure(
			thread,
			"dsl.module_missing",
			"The requested Starlark module is not present in the immutable module set.",
			"modules.present",
			"Declare the exact repository module digest or use a published versioned standard module.",
		)
	}
	if len(session.moduleCache) >= session.limits.MaxModules {
		return nil, builtinFailure(
			thread,
			"dsl.module_limit",
			"Loaded module count exceeds the configured limit.",
			"limits.modules",
			fmt.Sprintf("Load at most %d repository and standard modules.", session.limits.MaxModules),
		)
	}

	session.moduleCache[name] = nil
	session.moduleDepth++
	program, compileErr := session.compileProgram(name, module.source)
	var globals starlark.StringDict
	var loadErr error
	if compileErr != nil {
		loadErr = compileErr
	} else {
		session.initializingModule++
		globals, loadErr = program.Init(thread, session.predeclared)
		session.initializingModule--
		if globals != nil {
			globals.Freeze()
		}
		if loadErr != nil {
			loadErr = compileFailure(loadErr, name, session.cancellation())
		}
	}
	session.moduleDepth--
	entry := &moduleEntry{globals: globals, err: loadErr}
	session.moduleCache[name] = entry
	if loadErr == nil {
		session.usedModules[name] = buildir.Module{Name: name, Kind: module.kind, Digest: module.digest}
	}
	return entry.globals, entry.err
}

func (session *compileSession) module(name string) (moduleSource, bool) {
	if strings.HasPrefix(name, "//") {
		module, exists := session.repositoryModules[name]
		return module, exists
	}
	module, exists := standardModules()[name]
	return module, exists
}

func (session *compileSession) moduleEvidence() []buildir.Module {
	result := make([]buildir.Module, 0, len(session.usedModules))
	for _, module := range session.usedModules {
		result = append(result, module)
	}
	slices.SortFunc(result, func(left, right buildir.Module) int {
		return strings.Compare(left.Name, right.Name)
	})
	return result
}

func standardModules() map[string]moduleSource {
	source := []byte(standardHelpersSource)
	name := "@lrail/v1/helpers.star"
	return map[string]moduleSource{
		name: {
			name:   name,
			kind:   "standard",
			digest: hashSource(source),
			source: source,
		},
	}
}

func hashSource(source []byte) string {
	digest := sha256.Sum256(source)
	return "sha256:" + hex.EncodeToString(digest[:])
}
