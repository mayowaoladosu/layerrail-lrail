package llbcompiler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildir"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/solver/pb"
	digest "github.com/opencontainers/go-digest"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"google.golang.org/protobuf/proto"
)

type graphCompiler struct {
	input        normalizedRequest
	capabilities capabilitySet
	platform     ocispecs.Platform
	states       map[string]llb.State
	sourcePaths  map[string]string
	materials    map[string]BaseMaterial
}

func (compiler *Compiler) compile(ctx context.Context, request Request) (Result, error) {
	if ctx == nil {
		return Result{}, fail("llb.context", "LLB compilation requires a cancellation context.", "")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, fail("llb.canceled", "LLB compilation was canceled before policy validation.", "")
	}
	input, err := normalizeRequest(request)
	if err != nil {
		return Result{}, err
	}
	capabilities, err := compileCapabilities(input)
	if err != nil {
		return Result{}, err
	}
	platform, err := parsePlatform(input.ir.TargetPlatform)
	if err != nil {
		return Result{}, fail("llb.platform", "Build target platform is unsupported.", "")
	}
	graph := &graphCompiler{
		input:        input,
		capabilities: capabilities,
		platform:     platform,
		states:       make(map[string]llb.State),
		sourcePaths:  make(map[string]string),
		materials:    make(map[string]BaseMaterial, len(input.materials)),
	}
	for _, material := range input.materials {
		graph.materials[material.RequestedRef] = material
	}
	if err := graph.compileNodes(ctx); err != nil {
		return Result{}, err
	}
	outputs, outputLocks, err := graph.compileOutputs(ctx)
	if err != nil {
		return Result{}, err
	}
	lock := DefinitionLock{
		Version:         CurrentLockVersion,
		CompilerVersion: compiler.version,
		IRDigest:        input.irDigest,
		PolicyDigest:    input.policyDigest,
		SourceSnapshot:  input.ir.SourceSnapshot,
		TargetPlatform:  input.ir.TargetPlatform,
		BuildArguments:  append([]NameValue(nil), input.buildArguments...),
		BaseMaterials:   append([]BaseMaterial(nil), input.materials...),
		Network:         append([]NetworkCapability(nil), capabilities.network...),
		Caches:          append([]CacheCapability(nil), capabilities.caches...),
		Secrets:         append([]SecretCapability(nil), capabilities.secrets...),
		Outputs:         outputLocks,
	}
	definitionDigest, err := digestValue(lock)
	if err != nil {
		return Result{}, fail("llb.definition_digest", "Build definition lock could not be canonicalized.", "")
	}
	return Result{
		DefinitionDigest: definitionDigest,
		IRDigest:         input.irDigest,
		PolicyDigest:     input.policyDigest,
		Lock:             lock,
		Outputs:          outputs,
	}, nil
}

func (compiler *graphCompiler) compileNodes(ctx context.Context) error {
	for _, node := range compiler.input.ir.Nodes {
		if err := ctx.Err(); err != nil {
			return fail("llb.canceled", "LLB compilation was canceled.", node.ID)
		}
		switch node.Operation {
		case "source":
			state, sourcePath, err := compiler.compileSource(node)
			if err != nil {
				return err
			}
			compiler.states[node.ID] = state
			compiler.sourcePaths[node.ID] = sourcePath
		case "image":
			state, err := compiler.compileImage(node)
			if err != nil {
				return err
			}
			compiler.states[node.ID] = state
		case "cache", "secret":
		case "run":
			state, err := compiler.compileRun(node)
			if err != nil {
				return err
			}
			compiler.states[node.ID] = state
		case "copy":
			state, err := compiler.compileCopy(node)
			if err != nil {
				return err
			}
			compiler.states[node.ID] = state
		default:
			return fail("llb.operation", "Build IR operation is unsupported by this LLB compiler.", node.ID)
		}
	}
	return nil
}

func (compiler *graphCompiler) compileSource(node buildir.Node) (llb.State, string, error) {
	sourcePath, _ := node.Attributes["path"].(string)
	include, includeOK := stringSlice(node.Attributes["include"])
	exclude, excludeOK := stringSlice(node.Attributes["exclude"])
	if !includeOK || !excludeOK {
		return llb.State{}, "", fail("llb.source_shape", "Source filters are not typed string arrays.", node.ID)
	}
	options := []llb.LocalOption{
		llb.SharedKeyHint(compiler.input.ir.SourceSnapshot),
		llb.WithCustomName("lrail source " + node.ID),
	}
	if len(include) > 0 {
		options = append(options, llb.IncludePatterns(prefixPatterns(sourcePath, include)))
	}
	if len(exclude) > 0 {
		options = append(options, llb.ExcludePatterns(prefixPatterns(sourcePath, exclude)))
	}
	if sourcePath != "." {
		options = append(options, llb.FollowPaths([]string{sourcePath}))
	}
	copyPath := "/"
	if sourcePath != "." {
		copyPath = "/" + sourcePath
	}
	return llb.Local("lrail-source", options...), copyPath, nil
}

func (compiler *graphCompiler) compileImage(node buildir.Node) (llb.State, error) {
	reference, _ := node.Attributes["ref"].(string)
	material, exists := compiler.materials[reference]
	if !exists {
		return llb.State{}, fail("llb.material_missing", "Image node lacks resolved base material.", node.ID)
	}
	return llb.Image(
		material.ResolvedRef,
		llb.ResolveModeForcePull,
		llb.Platform(compiler.platform),
		llb.WithCustomName("lrail image "+node.ID),
	), nil
}

func (compiler *graphCompiler) compileRun(node buildir.Node) (llb.State, error) {
	if err := validateRunMounts(node, compiler.capabilities, compiler.input.policy.Cache); err != nil {
		return llb.State{}, err
	}
	base, exists := compiler.states[node.Inputs[0]]
	if !exists {
		return llb.State{}, fail("llb.run_base", "Run base state is unavailable.", node.ID)
	}
	arguments, argumentsOK := stringSlice(node.Attributes["argv"])
	environment, environmentOK := stringMap(node.Attributes["env"])
	mountIDs, mountsOK := stringSlice(node.Attributes["mounts"])
	workdir, workdirOK := node.Attributes["workdir"].(string)
	user, userOK := node.Attributes["user"].(string)
	if !argumentsOK || !environmentOK || !mountsOK || !workdirOK || !userOK {
		return llb.State{}, fail("llb.run_shape", "Run node attributes are not typed correctly.", node.ID)
	}
	options := []llb.RunOption{
		llb.Args(arguments),
		llb.Dir(workdir),
		llb.User(user),
	}
	networkCapability, exists := compiler.capabilities.networkByNode[node.ID]
	if !exists {
		return llb.State{}, fail("llb.network_missing", "Run network capability is unavailable.", node.ID)
	}
	options = append(options, llb.WithCustomName(
		"lrail run "+node.ID+" network="+networkCapability.Profile+" gateway="+networkCapability.GatewayID+" hosts="+strings.Join(networkCapability.Hosts, ","),
	))
	profile := networkCapability.Profile
	if profile == "none" {
		options = append(options, llb.Network(pb.NetMode_NONE))
	} else {
		options = append(options, llb.Network(pb.NetMode_UNSET), llb.WithProxy(llb.ProxyEnv{
			HTTPProxy: BuildEgressProxyURL, HTTPSProxy: BuildEgressProxyURL,
		}))
	}
	for _, argument := range compiler.input.buildArguments {
		if _, exists := environment[argument.Name]; exists {
			return llb.State{}, fail("llb.argument_conflict", "Build argument conflicts with run environment.", node.ID)
		}
		options = append(options, llb.AddEnv(argument.Name, argument.Value))
	}
	environmentNames := make([]string, 0, len(environment))
	for name := range environment {
		environmentNames = append(environmentNames, name)
	}
	slices.Sort(environmentNames)
	for _, name := range environmentNames {
		options = append(options, llb.AddEnv(name, environment[name]))
	}
	uid, gid, err := parseOwner(user)
	if err != nil {
		return llb.State{}, fail("llb.run_user", "Run user cannot own capability mounts.", node.ID)
	}
	for _, mountID := range mountIDs {
		if cache, exists := compiler.capabilities.cacheByNode[mountID]; exists {
			options = append(options, llb.AddMount(
				cache.Target,
				llb.Scratch(),
				llb.AsPersistentCacheDir(cache.Namespace, cacheSharing(cache.Sharing)),
			))
			continue
		}
		secret, exists := compiler.capabilities.secretByNode[mountID]
		if !exists {
			return llb.State{}, fail("llb.mount_unknown", "Run mount capability is unavailable.", node.ID)
		}
		secretOptions := []llb.SecretOption{
			llb.SecretID(secret.MountID),
			llb.SecretFileOpt(uid, gid, 0o400),
		}
		if !secret.Required {
			secretOptions = append(secretOptions, llb.SecretOptional)
		}
		target := secret.Target
		options = append(options, llb.AddSecretWithDest(secret.MountID, &target, secretOptions...))
	}
	return base.Run(options...).Root(), nil
}

func (compiler *graphCompiler) compileCopy(node buildir.Node) (llb.State, error) {
	base, baseExists := compiler.states[node.Inputs[0]]
	source, sourceExists := compiler.states[node.Inputs[1]]
	sourcePath, pathExists := compiler.sourcePaths[node.Inputs[1]]
	if !baseExists || !sourceExists || !pathExists {
		return llb.State{}, fail("llb.copy_input", "Copy state or source input is unavailable.", node.ID)
	}
	destination, destinationOK := node.Attributes["dest"].(string)
	owner, ownerOK := node.Attributes["owner"].(string)
	modeText, modeOK := node.Attributes["mode"].(string)
	if !destinationOK || !ownerOK || !modeOK {
		return llb.State{}, fail("llb.copy_shape", "Copy node attributes are not typed correctly.", node.ID)
	}
	mode, err := strconv.ParseUint(strings.TrimPrefix(modeText, "0"), 8, 32)
	if err != nil {
		return llb.State{}, fail("llb.copy_mode", "Copy mode is invalid.", node.ID)
	}
	action := llb.Copy(
		source,
		sourcePath,
		destination,
		&llb.CopyInfo{CopyDirContentsOnly: true, CreateDestPath: true},
		llb.WithUser(owner),
		llb.ChmodOpt{Mode: os.FileMode(mode)},
	)
	return base.File(action, llb.WithCustomName("lrail copy "+node.ID)), nil
}

func (compiler *graphCompiler) compileOutputs(ctx context.Context) ([]OutputDefinition, []OutputLock, error) {
	outputs := make([]OutputDefinition, 0, len(compiler.input.ir.Outputs))
	locks := make([]OutputLock, 0, len(compiler.input.ir.Outputs))
	for _, output := range compiler.input.ir.Outputs {
		state, exists := compiler.states[output.State]
		if !exists {
			return nil, nil, fail("llb.output_state", "Build output state is unavailable.", output.State)
		}
		definition, err := state.Marshal(
			ctx,
			llb.Platform(compiler.platform),
			llb.LocalUniqueID(compiler.input.ir.SourceSnapshot),
		)
		if err != nil {
			return nil, nil, fail("llb.marshal", "BuildKit LLB graph could not be marshaled.", output.State)
		}
		definitionBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(definition.ToPB())
		if err != nil {
			return nil, nil, fail("llb.serialize", "BuildKit LLB definition could not be serialized.", output.State)
		}
		llbDigest := bytesDigest(definitionBytes)
		head, err := definition.Head()
		if err != nil {
			return nil, nil, fail("llb.head", "BuildKit LLB graph head is invalid.", output.State)
		}
		graph, err := normalizeGraph(definition)
		if err != nil {
			return nil, nil, fail("llb.graph", "BuildKit LLB graph is invalid.", output.State)
		}
		compiled := OutputDefinition{
			Name:          output.Name,
			Kind:          output.Kind,
			LLBDigest:     llbDigest,
			Head:          string(head),
			Definition:    definitionBytes,
			StaticHeaders: map[string]string{},
			Graph:         graph,
		}
		configDigest := ""
		switch output.Kind {
		case "oci_image":
			compiled.ImageConfig, err = imageConfig(output)
			if err != nil {
				return nil, nil, fail("llb.image_config", "OCI image config could not be canonicalized.", output.State)
			}
			configDigest = bytesDigest(compiled.ImageConfig)
		case "static_bundle":
			compiled.StaticHeaders = cloneMap(output.Headers)
			headerBytes, headerErr := canonicaljson.Marshal(compiled.StaticHeaders)
			if headerErr != nil {
				return nil, nil, fail("llb.static_config", "Static headers could not be canonicalized.", output.State)
			}
			configDigest = bytesDigest(headerBytes)
		default:
			return nil, nil, fail("llb.output_kind", "Build output kind is unsupported.", output.State)
		}
		outputs = append(outputs, compiled)
		locks = append(locks, OutputLock{Name: output.Name, Kind: output.Kind, StateID: output.State, LLBDigest: llbDigest, ConfigDigest: configDigest})
	}
	return outputs, locks, nil
}

func imageConfig(output buildir.Output) ([]byte, error) {
	exposedPorts := make(map[string]struct{}, len(output.Ports))
	for _, port := range output.Ports {
		exposedPorts[fmt.Sprintf("%d/tcp", port)] = struct{}{}
	}
	return canonicaljson.Marshal(struct {
		Config struct {
			Entrypoint   []string            `json:"Entrypoint"`
			Cmd          []string            `json:"Cmd"`
			ExposedPorts map[string]struct{} `json:"ExposedPorts"`
			Labels       map[string]string   `json:"Labels"`
		} `json:"config"`
	}{
		Config: struct {
			Entrypoint   []string            `json:"Entrypoint"`
			Cmd          []string            `json:"Cmd"`
			ExposedPorts map[string]struct{} `json:"ExposedPorts"`
			Labels       map[string]string   `json:"Labels"`
		}{
			Entrypoint:   append([]string(nil), output.Entrypoint...),
			Cmd:          append([]string(nil), output.Command...),
			ExposedPorts: exposedPorts,
			Labels:       cloneMap(output.Labels),
		},
	})
}

func normalizeGraph(definition *llb.Definition) (Graph, error) {
	head, err := definition.Head()
	if err != nil {
		return Graph{}, err
	}
	graph := Graph{Head: string(head), Vertices: make([]GraphVertex, 0, len(definition.Def))}
	for _, raw := range definition.Def {
		var operation pb.Op
		if err := proto.Unmarshal(raw, &operation); err != nil {
			return Graph{}, err
		}
		inputs := make([]string, 0, len(operation.Inputs))
		for _, input := range operation.Inputs {
			inputs = append(inputs, input.Digest)
		}
		graph.Vertices = append(graph.Vertices, GraphVertex{
			Digest: string(digest.FromBytes(raw)),
			Kind:   operationKind(&operation),
			Inputs: inputs,
		})
	}
	return graph, nil
}

func operationKind(operation *pb.Op) string {
	switch operation.Op.(type) {
	case *pb.Op_Source:
		return "source"
	case *pb.Op_Exec:
		return "exec"
	case *pb.Op_File:
		return "file"
	case *pb.Op_Build:
		return "build"
	case *pb.Op_Merge:
		return "merge"
	case *pb.Op_Diff:
		return "diff"
	default:
		if operation.Op == nil && len(operation.Inputs) == 1 {
			return "output"
		}
		return "unknown"
	}
}

func cacheSharing(value string) llb.CacheMountSharingMode {
	switch value {
	case "private":
		return llb.CacheMountPrivate
	case "locked":
		return llb.CacheMountLocked
	default:
		return llb.CacheMountShared
	}
}

func parsePlatform(value string) (ocispecs.Platform, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 2 {
		return ocispecs.Platform{}, fmt.Errorf("invalid platform")
	}
	return ocispecs.Platform{OS: parts[0], Architecture: parts[1]}, nil
}

func prefixPatterns(sourcePath string, patterns []string) []string {
	if sourcePath == "." {
		return append([]string(nil), patterns...)
	}
	result := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		result = append(result, sourcePath+"/"+pattern)
	}
	return result
}

func bytesDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func cloneMap(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
