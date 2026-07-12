// Package dsl evaluates the constrained Lrail Starlark build language into
// typed Build IR without ambient I/O, network, time, randomness, or environment.
package dsl

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildir"
	"go.starlark.net/starlark"
)

const (
	DefaultMaxSourceBytes = 256 * 1024
	DefaultMaxSteps       = 1_000_000
)

var ErrCompile = errors.New("compile Lrailfile")

type Options struct {
	CompilerVersion string
	SourceSnapshot  string
	TargetPlatform  string
	NetworkProfile  string
	AllowedHosts    []string
	MaxSourceBytes  int
	MaxSteps        uint64
}

type Result struct {
	IR     buildir.IR
	Digest string
}

type Compiler struct {
	options Options
	mu      sync.Mutex
	nodes   []buildir.Node
	outputs []buildir.Output
}

func New(options Options) (*Compiler, error) {
	if options.CompilerVersion == "" || options.SourceSnapshot == "" {
		return nil, fmt.Errorf("%w: compiler version and source snapshot are required", ErrCompile)
	}
	if options.TargetPlatform == "" {
		options.TargetPlatform = "linux/amd64"
	}
	if options.NetworkProfile == "" {
		options.NetworkProfile = "none"
	}
	if options.MaxSourceBytes == 0 {
		options.MaxSourceBytes = DefaultMaxSourceBytes
	}
	if options.MaxSteps == 0 {
		options.MaxSteps = DefaultMaxSteps
	}
	if options.MaxSourceBytes < 1 || options.MaxSourceBytes > DefaultMaxSourceBytes {
		return nil, fmt.Errorf("%w: max source bytes is outside the safe range", ErrCompile)
	}
	return &Compiler{options: options}, nil
}

func (compiler *Compiler) Compile(ctx context.Context, filename string, source []byte) (Result, error) {
	compiler.mu.Lock()
	defer compiler.mu.Unlock()
	if ctx == nil {
		return Result{}, fmt.Errorf("%w: context is nil", ErrCompile)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrCompile, err)
	}
	if len(source) == 0 || len(source) > compiler.options.MaxSourceBytes {
		return Result{}, fmt.Errorf("%w: source size must be between 1 and %d bytes", ErrCompile, compiler.options.MaxSourceBytes)
	}
	if filename == "" {
		filename = "Lrailfile.star"
	}
	compiler.nodes = nil
	compiler.outputs = nil
	thread := &starlark.Thread{
		Name: "lrail-build-compiler",
		Load: func(_ *starlark.Thread, module string) (starlark.StringDict, error) {
			return nil, fmt.Errorf("module loading is disabled: %s", module)
		},
		Print: func(_ *starlark.Thread, _ string) {},
	}
	thread.SetMaxExecutionSteps(compiler.options.MaxSteps)
	finished := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			thread.Cancel(ctx.Err().Error())
		case <-finished:
		}
	}()
	defer close(finished)

	predeclared := starlark.StringDict{
		"source":      starlark.NewBuiltin("source", compiler.source),
		"image":       starlark.NewBuiltin("image", compiler.image),
		"run":         starlark.NewBuiltin("run", compiler.run),
		"copy":        starlark.NewBuiltin("copy", compiler.copy),
		"cache":       starlark.NewBuiltin("cache", compiler.cache),
		"secret":      starlark.NewBuiltin("secret", compiler.secret),
		"artifact":    starlark.NewBuiltin("artifact", compiler.artifact),
		"static_site": starlark.NewBuiltin("static_site", compiler.staticSite),
	}
	if _, err := starlark.ExecFile(thread, filename, source, predeclared); err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrCompile, err)
	}
	ir := buildir.IR{
		Version:         buildir.CurrentVersion,
		CompilerVersion: compiler.options.CompilerVersion,
		SourceSnapshot:  compiler.options.SourceSnapshot,
		TargetPlatform:  compiler.options.TargetPlatform,
		NetworkProfile:  compiler.options.NetworkProfile,
		AllowedHosts:    append([]string(nil), compiler.options.AllowedHosts...),
		Nodes:           append([]buildir.Node(nil), compiler.nodes...),
		Outputs:         append([]buildir.Output(nil), compiler.outputs...),
	}
	digest, err := buildir.DefinitionDigest(ir)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrCompile, err)
	}
	return Result{IR: ir, Digest: digest}, nil
}

type nodeRef string

func (reference nodeRef) String() string        { return string(reference) }
func (reference nodeRef) Type() string          { return "lrail_node" }
func (reference nodeRef) Freeze()               {}
func (reference nodeRef) Truth() starlark.Bool  { return starlark.True }
func (reference nodeRef) Hash() (uint32, error) { return starlark.String(reference).Hash() }

func (compiler *Compiler) appendNode(operation string, inputs []string, attributes map[string]any) nodeRef {
	identifier := fmt.Sprintf("n%d", len(compiler.nodes)+1)
	compiler.nodes = append(compiler.nodes, buildir.Node{
		ID:         identifier,
		Operation:  operation,
		Inputs:     inputs,
		Attributes: attributes,
	})
	return nodeRef(identifier)
}

func (compiler *Compiler) source(_ *starlark.Thread, function *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var sourcePath string
	var exclude *starlark.List
	if err := starlark.UnpackArgs(function.Name(), args, kwargs, "path", &sourcePath, "exclude?", &exclude); err != nil {
		return nil, err
	}
	exclusions, err := unpackStrings(exclude)
	if err != nil {
		return nil, fmt.Errorf("source exclude: %w", err)
	}
	return compiler.appendNode("source", nil, map[string]any{"path": sourcePath, "exclude": exclusions}), nil
}

func (compiler *Compiler) image(_ *starlark.Thread, function *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var digest string
	if err := starlark.UnpackArgs(function.Name(), args, kwargs, "digest", &digest); err != nil {
		return nil, err
	}
	return compiler.appendNode("image", nil, map[string]any{"digest": digest}), nil
}

func (compiler *Compiler) run(_ *starlark.Thread, function *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var baseValue starlark.Value
	var argv *starlark.List
	network := "none"
	if err := starlark.UnpackArgs(function.Name(), args, kwargs, "base", &baseValue, "argv", &argv, "network?", &network); err != nil {
		return nil, err
	}
	base, err := requireNodeRef(baseValue)
	if err != nil {
		return nil, fmt.Errorf("run base: %w", err)
	}
	arguments, err := unpackStrings(argv)
	if err != nil {
		return nil, fmt.Errorf("run argv: %w", err)
	}
	return compiler.appendNode("run", []string{string(base)}, map[string]any{"argv": arguments, "network": network}), nil
}

func (compiler *Compiler) copy(_ *starlark.Thread, function *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var baseValue, sourceValue starlark.Value
	var destination string
	owner := "10001:10001"
	if err := starlark.UnpackArgs(function.Name(), args, kwargs, "base", &baseValue, "source", &sourceValue, "destination", &destination, "owner?", &owner); err != nil {
		return nil, err
	}
	base, err := requireNodeRef(baseValue)
	if err != nil {
		return nil, fmt.Errorf("copy base: %w", err)
	}
	source, err := requireNodeRef(sourceValue)
	if err != nil {
		return nil, fmt.Errorf("copy source: %w", err)
	}
	return compiler.appendNode("copy", []string{string(base), string(source)}, map[string]any{"destination": destination, "owner": owner}), nil
}

func (compiler *Compiler) cache(_ *starlark.Thread, function *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var target, scope string
	if err := starlark.UnpackArgs(function.Name(), args, kwargs, "target", &target, "scope", &scope); err != nil {
		return nil, err
	}
	return compiler.appendNode("cache", nil, map[string]any{"target": target, "scope": scope}), nil
}

func (compiler *Compiler) secret(_ *starlark.Thread, function *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var identifier, target string
	if err := starlark.UnpackArgs(function.Name(), args, kwargs, "id", &identifier, "target", &target); err != nil {
		return nil, err
	}
	return compiler.appendNode("secret", nil, map[string]any{"id": identifier, "target": target}), nil
}

func (compiler *Compiler) artifact(_ *starlark.Thread, function *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return compiler.outputBuiltin("oci_image", function, args, kwargs)
}

func (compiler *Compiler) staticSite(_ *starlark.Thread, function *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return compiler.outputBuiltin("static_bundle", function, args, kwargs)
}

func (compiler *Compiler) outputBuiltin(kind string, function *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var stateValue starlark.Value
	var entrypoint, command, ports *starlark.List
	if err := starlark.UnpackArgs(function.Name(), args, kwargs, "name", &name, "state", &stateValue, "entrypoint?", &entrypoint, "command?", &command, "ports?", &ports); err != nil {
		return nil, err
	}
	state, err := requireNodeRef(stateValue)
	if err != nil {
		return nil, fmt.Errorf("%s state: %w", function.Name(), err)
	}
	entrypointValues, err := unpackStrings(entrypoint)
	if err != nil {
		return nil, fmt.Errorf("%s entrypoint: %w", function.Name(), err)
	}
	commandValues, err := unpackStrings(command)
	if err != nil {
		return nil, fmt.Errorf("%s command: %w", function.Name(), err)
	}
	portValues, err := unpackInts(ports)
	if err != nil {
		return nil, fmt.Errorf("%s ports: %w", function.Name(), err)
	}
	compiler.outputs = append(compiler.outputs, buildir.Output{
		Name:       name,
		Kind:       kind,
		State:      string(state),
		Entrypoint: entrypointValues,
		Command:    commandValues,
		Ports:      portValues,
	})
	return starlark.None, nil
}

func requireNodeRef(value starlark.Value) (nodeRef, error) {
	reference, ok := value.(nodeRef)
	if !ok {
		return "", fmt.Errorf("expected lrail_node, got %s", value.Type())
	}
	return reference, nil
}

func unpackStrings(list *starlark.List) ([]string, error) {
	if list == nil {
		return []string{}, nil
	}
	result := make([]string, 0, list.Len())
	iterator := list.Iterate()
	defer iterator.Done()
	var value starlark.Value
	for iterator.Next(&value) {
		text, ok := starlark.AsString(value)
		if !ok {
			return nil, fmt.Errorf("expected string, got %s", value.Type())
		}
		if strings.IndexByte(text, 0) >= 0 {
			return nil, errors.New("strings cannot contain NUL")
		}
		result = append(result, text)
	}
	return result, nil
}

func unpackInts(list *starlark.List) ([]int, error) {
	if list == nil {
		return []int{}, nil
	}
	result := make([]int, 0, list.Len())
	iterator := list.Iterate()
	defer iterator.Done()
	var value starlark.Value
	for iterator.Next(&value) {
		integer, err := starlark.AsInt32(value)
		if err != nil {
			return nil, err
		}
		result = append(result, integer)
	}
	return result, nil
}
