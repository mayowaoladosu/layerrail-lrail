// Package dsl evaluates the constrained Lrail Starlark build language into
// typed Build IR without ambient I/O, network, time, randomness, or environment.
package dsl

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildir"
	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
)

const (
	DefaultMaxSourceBytes     = 256 * 1024
	DefaultMaxASTNodes        = 20_000
	DefaultMaxSteps           = 1_000_000
	DefaultMaxCallDepth       = 128
	DefaultMaxResultNodes     = buildir.MaxNodes
	DefaultMaxOutputs         = buildir.MaxOutputs
	DefaultMaxStringBytes     = buildir.MaxStringBytes
	DefaultMaxCollectionItems = buildir.MaxArguments
	DefaultMaxModules         = buildir.MaxModules
	DefaultMaxModuleDepth     = 32
	DefaultEvaluationDuration = 5 * time.Second
	MaximumEvaluationDuration = 30 * time.Second
	defaultEntryFilename      = "Lrailfile.star"
	defaultTargetPlatform     = "linux/amd64"
	defaultNetworkProfile     = "none"
)

var (
	compilerVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	digestPattern          = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	moduleVersionPattern   = regexp.MustCompile(`^v[1-9][0-9]*$`)
	hostPattern            = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)
)

type Limits struct {
	MaxSourceBytes        int
	MaxASTNodes           int
	MaxSteps              uint64
	MaxCallDepth          int
	MaxResultNodes        int
	MaxOutputs            int
	MaxStringBytes        int
	MaxCollectionItems    int
	MaxModules            int
	MaxModuleDepth        int
	MaxEvaluationDuration time.Duration
}

type Options struct {
	DSLAPIVersion       string
	CompilerVersion     string
	SourceSnapshot      string
	TargetPlatform      string
	NetworkProfile      string
	AllowedHosts        []string
	ApprovedModuleRoots []string
	Limits              Limits
}

type Module struct {
	Path   string
	Digest string
	Source []byte
}

type Input struct {
	Filename string
	Source   []byte
	Modules  []Module
}

type Result struct {
	IR     buildir.IR
	Digest string
}

type Compiler struct {
	options Options
}

type compileSession struct {
	compiler           *Compiler
	limits             Limits
	entryFile          string
	predeclared        starlark.StringDict
	repositoryModules  map[string]moduleSource
	moduleCache        map[string]*moduleEntry
	usedModules        map[string]buildir.Module
	nodes              []buildir.Node
	outputs            []buildir.Output
	sourceBytes        int
	astNodes           int
	moduleDepth        int
	initializingModule int
	cancelOnce         sync.Once
	cancelMu           sync.Mutex
	cancelCause        *ruleError
}

func New(options Options) (*Compiler, error) {
	if options.DSLAPIVersion != buildir.CurrentDSLAPIVersion {
		return nil, failure(
			"dsl.api_version",
			"The requested Starlark language version is not supported.",
			"compatibility.dsl_api_version",
			fmt.Sprintf("Use %s for this compiler.", buildir.CurrentDSLAPIVersion),
			defaultEntryFilename,
			1,
			1,
		)
	}
	if !compilerVersionPattern.MatchString(options.CompilerVersion) {
		return nil, failure(
			"dsl.compiler_version",
			"Compiler version must be semantic version text.",
			"compatibility.compiler_version",
			"Use a pinned major.minor.patch compiler version.",
			defaultEntryFilename,
			1,
			1,
		)
	}
	if !digestPattern.MatchString(options.SourceSnapshot) {
		return nil, failure(
			"dsl.source_snapshot",
			"Source snapshot must be an immutable sha256 digest.",
			"source.snapshot_digest",
			"Compile only an accepted immutable source snapshot.",
			defaultEntryFilename,
			1,
			1,
		)
	}
	if options.TargetPlatform == "" {
		options.TargetPlatform = defaultTargetPlatform
	}
	if options.NetworkProfile == "" {
		options.NetworkProfile = defaultNetworkProfile
	}
	if !slices.Contains([]string{"linux/amd64", "linux/arm64"}, options.TargetPlatform) {
		return nil, failure(
			"dsl.target_platform",
			"The requested build target platform is not supported.",
			"assignment.target_platform",
			"Use linux/amd64 or linux/arm64.",
			defaultEntryFilename,
			1,
			1,
		)
	}
	if !slices.Contains([]string{"none", "packages", "allowlist", "private"}, options.NetworkProfile) {
		return nil, failure(
			"dsl.network_profile",
			"The build assignment network profile is not supported.",
			"assignment.network_profile",
			"Use none, packages, allowlist, or private.",
			defaultEntryFilename,
			1,
			1,
		)
	}
	limits, err := normalizedLimits(options.Limits)
	if err != nil {
		return nil, err
	}
	options.Limits = limits
	options.AllowedHosts = append([]string(nil), options.AllowedHosts...)
	slices.Sort(options.AllowedHosts)
	if !uniqueSorted(options.AllowedHosts) {
		return nil, failure(
			"dsl.allowed_hosts",
			"Allowed network hosts must be unique.",
			"network.allowed_hosts",
			"Remove duplicate hostnames from the build assignment.",
			defaultEntryFilename,
			1,
			1,
		)
	}
	if (options.NetworkProfile == "allowlist") != (len(options.AllowedHosts) > 0) {
		return nil, failure(
			"dsl.allowed_hosts",
			"Allowed hosts must be present exactly when the allowlist network profile is selected.",
			"network.allowed_hosts",
			"Pair a non-empty canonical host allowlist with the allowlist profile only.",
			defaultEntryFilename,
			1,
			1,
		)
	}
	for _, host := range options.AllowedHosts {
		if len(host) > 253 || !hostPattern.MatchString(host) {
			return nil, failure(
				"dsl.allowed_hosts",
				"An allowed network host is not a canonical lowercase hostname.",
				"network.allowed_hosts",
				"Use lowercase DNS hostnames without schemes, ports, paths, or wildcards.",
				defaultEntryFilename,
				1,
				1,
			)
		}
	}
	options.ApprovedModuleRoots = append([]string(nil), options.ApprovedModuleRoots...)
	slices.Sort(options.ApprovedModuleRoots)
	if !uniqueSorted(options.ApprovedModuleRoots) {
		return nil, failure(
			"dsl.module_root",
			"Approved module roots must be unique.",
			"modules.approved_roots",
			"Provide each canonical repository root once.",
			defaultEntryFilename,
			1,
			1,
		)
	}
	for _, root := range options.ApprovedModuleRoots {
		if !validModuleRoot(root) {
			return nil, failure(
				"dsl.module_root",
				"An approved module root is not a canonical repository-relative path.",
				"modules.approved_roots",
				"Use a bounded path such as build or platform/build without traversal.",
				defaultEntryFilename,
				1,
				1,
			)
		}
	}
	return &Compiler{options: options}, nil
}

func (compiler *Compiler) Compile(ctx context.Context, input Input) (Result, error) {
	if ctx == nil {
		return Result{}, failure(
			"dsl.context",
			"Build compilation requires a cancellation context.",
			"execution.context",
			"Pass the build-request context so cancellation and deadlines propagate.",
			defaultEntryFilename,
			1,
			1,
		)
	}
	filename := input.Filename
	if filename == "" {
		filename = defaultEntryFilename
	}
	if !validEntryFilename(filename) {
		return Result{}, failure(
			"dsl.filename",
			"The entry filename is not a canonical repository-relative Starlark path.",
			"source.entry_filename",
			"Use a .star path without traversal, a drive prefix, or backslashes.",
			defaultEntryFilename,
			1,
			1,
		)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, contextFailure(err, filename)
	}

	evaluationContext, cancel := context.WithTimeout(ctx, compiler.options.Limits.MaxEvaluationDuration)
	defer cancel()
	session, err := newCompileSession(compiler, filename, input.Modules)
	if err != nil {
		return Result{}, err
	}
	session.predeclared = session.builtins()
	thread := &starlark.Thread{
		Name:  "lrail-build-compiler",
		Load:  session.load,
		Print: func(_ *starlark.Thread, _ string) {},
	}
	thread.SetMaxExecutionSteps(1)
	thread.OnMaxSteps = session.monitorExecution

	finished := make(chan struct{})
	go func() {
		select {
		case <-evaluationContext.Done():
			code := "dsl.canceled"
			message := "Build compilation was canceled."
			rule := "execution.cancellation"
			hint := "Retry only while the build request remains active."
			if evaluationContext.Err() == context.DeadlineExceeded {
				code = "dsl.deadline"
				message = "Build compilation exceeded its wall-clock deadline."
				rule = "limits.wall_time"
				hint = "Reduce Starlark evaluation work; extending the hard platform ceiling is not permitted."
			}
			session.cancelThread(thread, &ruleError{code: code, message: message, rule: rule, hint: hint})
		case <-finished:
		}
	}()
	defer close(finished)

	program, compileErr := session.compileProgram(filename, input.Source)
	if compileErr != nil {
		return Result{}, compileErr
	}
	if contextErr := evaluationContext.Err(); contextErr != nil {
		return Result{}, contextFailure(contextErr, filename)
	}
	globals, evaluationErr := program.Init(thread, session.predeclared)
	globals.Freeze()
	if evaluationErr != nil {
		return Result{}, compileFailure(evaluationErr, filename, session.cancellation())
	}
	if evaluationErr = evaluationContext.Err(); evaluationErr != nil {
		if cancellation := session.cancellation(); cancellation != nil {
			return Result{}, compileFailure(evaluationErr, filename, cancellation)
		}
		return Result{}, contextFailure(evaluationErr, filename)
	}
	if len(session.outputs) == 0 {
		return Result{}, failure(
			"dsl.output_missing",
			"The build definition did not declare an artifact or static site output.",
			"result.output_required",
			"Declare at least one named artifact or static_site output.",
			filename,
			1,
			1,
		)
	}

	slices.SortFunc(session.outputs, func(left, right buildir.Output) int {
		return strings.Compare(left.Name, right.Name)
	})
	ir := buildir.IR{
		Version:         buildir.CurrentVersion,
		DSLAPIVersion:   compiler.options.DSLAPIVersion,
		CompilerVersion: compiler.options.CompilerVersion,
		SourceSnapshot:  compiler.options.SourceSnapshot,
		TargetPlatform:  compiler.options.TargetPlatform,
		NetworkProfile:  compiler.options.NetworkProfile,
		AllowedHosts:    append([]string(nil), compiler.options.AllowedHosts...),
		Modules:         session.moduleEvidence(),
		Nodes:           append([]buildir.Node{}, session.nodes...),
		Outputs:         append([]buildir.Output{}, session.outputs...),
	}
	digest, digestErr := buildir.DefinitionDigest(ir)
	if digestErr != nil {
		return Result{}, failure(
			"dsl.ir_invalid",
			"The evaluated program produced Build IR that violates the typed contract.",
			"result.build_ir",
			"Correct the owned built-in arguments at the reported build definition location.",
			filename,
			1,
			1,
		)
	}
	return Result{IR: ir, Digest: digest}, nil
}

func contextFailure(err error, filename string) *CompileError {
	if err == context.DeadlineExceeded {
		return failure(
			"dsl.deadline",
			"Build compilation exceeded its wall-clock deadline.",
			"limits.wall_time",
			"Reduce Starlark evaluation work; extending the hard platform ceiling is not permitted.",
			filename,
			1,
			1,
		)
	}
	return failure(
		"dsl.canceled",
		"Build compilation was canceled.",
		"execution.cancellation",
		"Retry only while the build request remains active.",
		filename,
		1,
		1,
	)
}

func normalizedLimits(limits Limits) (Limits, error) {
	applyDefault(&limits.MaxSourceBytes, DefaultMaxSourceBytes)
	applyDefault(&limits.MaxASTNodes, DefaultMaxASTNodes)
	if limits.MaxSteps == 0 {
		limits.MaxSteps = DefaultMaxSteps
	}
	applyDefault(&limits.MaxCallDepth, DefaultMaxCallDepth)
	applyDefault(&limits.MaxResultNodes, DefaultMaxResultNodes)
	applyDefault(&limits.MaxOutputs, DefaultMaxOutputs)
	applyDefault(&limits.MaxStringBytes, DefaultMaxStringBytes)
	applyDefault(&limits.MaxCollectionItems, DefaultMaxCollectionItems)
	applyDefault(&limits.MaxModules, DefaultMaxModules)
	applyDefault(&limits.MaxModuleDepth, DefaultMaxModuleDepth)
	if limits.MaxEvaluationDuration == 0 {
		limits.MaxEvaluationDuration = DefaultEvaluationDuration
	}
	valid := limits.MaxSourceBytes > 0 && limits.MaxSourceBytes <= DefaultMaxSourceBytes &&
		limits.MaxASTNodes > 0 && limits.MaxASTNodes <= DefaultMaxASTNodes &&
		limits.MaxSteps > 0 && limits.MaxSteps <= DefaultMaxSteps &&
		limits.MaxCallDepth > 0 && limits.MaxCallDepth <= DefaultMaxCallDepth &&
		limits.MaxResultNodes > 0 && limits.MaxResultNodes <= DefaultMaxResultNodes &&
		limits.MaxOutputs > 0 && limits.MaxOutputs <= DefaultMaxOutputs &&
		limits.MaxStringBytes > 0 && limits.MaxStringBytes <= DefaultMaxStringBytes &&
		limits.MaxCollectionItems > 0 && limits.MaxCollectionItems <= DefaultMaxCollectionItems &&
		limits.MaxModules > 0 && limits.MaxModules <= DefaultMaxModules &&
		limits.MaxModuleDepth > 0 && limits.MaxModuleDepth <= DefaultMaxModuleDepth &&
		limits.MaxEvaluationDuration > 0 && limits.MaxEvaluationDuration <= MaximumEvaluationDuration
	if !valid {
		return Limits{}, failure(
			"dsl.limit_configuration",
			"A Starlark resource limit is outside the platform safety ceiling.",
			"limits.configuration",
			"Use a positive limit no greater than the documented platform maximum.",
			defaultEntryFilename,
			1,
			1,
		)
	}
	return limits, nil
}

func applyDefault(value *int, fallback int) {
	if *value == 0 {
		*value = fallback
	}
}

func validEntryFilename(value string) bool {
	return validRepositoryPath(value) && strings.HasSuffix(value, ".star")
}

func validRepositoryPath(value string) bool {
	return value != "" && value != "." && !strings.HasPrefix(value, "/") &&
		!strings.Contains(value, "\\") && !strings.Contains(value, ":") &&
		path.Clean(value) == value && value != ".." && !strings.HasPrefix(value, "../")
}

func validModuleRoot(value string) bool {
	return validRepositoryPath(value) && !strings.HasSuffix(value, ".star")
}

func validModuleName(value string) bool {
	if strings.HasPrefix(value, "//") {
		return validEntryFilename(strings.TrimPrefix(value, "//"))
	}
	if !strings.HasPrefix(value, "@lrail/v") {
		return false
	}
	parts := strings.Split(value, "/")
	return len(parts) >= 3 && parts[0] == "@lrail" && moduleVersionPattern.MatchString(parts[1]) && validEntryFilename(strings.Join(parts[2:], "/"))
}

func uniqueSorted(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return false
		}
	}
	return true
}

func (session *compileSession) monitorExecution(thread *starlark.Thread) {
	if thread.CallStackDepth() > session.limits.MaxCallDepth {
		cause := &ruleError{
			code:    "dsl.call_depth",
			message: "Starlark evaluation exceeded the configured call-depth limit.",
			rule:    "limits.call_depth",
			hint:    fmt.Sprintf("Keep helper call chains within %d frames.", session.limits.MaxCallDepth),
			pos:     currentPosition(thread),
		}
		session.cancelThread(thread, cause)
		return
	}
	if thread.ExecutionSteps() >= session.limits.MaxSteps {
		cause := &ruleError{
			code:    "dsl.step_limit",
			message: "Starlark evaluation exceeded the configured execution-step limit.",
			rule:    "limits.execution_steps",
			hint:    fmt.Sprintf("Reduce evaluation work below %d abstract steps.", session.limits.MaxSteps),
			pos:     currentPosition(thread),
		}
		session.cancelThread(thread, cause)
		return
	}
	thread.SetMaxExecutionSteps(thread.ExecutionSteps() + 1)
}

func (session *compileSession) cancelThread(thread *starlark.Thread, cause *ruleError) {
	session.cancelOnce.Do(func() {
		session.cancelMu.Lock()
		session.cancelCause = cause
		session.cancelMu.Unlock()
		thread.Cancel(cause.code)
	})
}

func currentPosition(thread *starlark.Thread) syntax.Position {
	for depth := 0; depth < thread.CallStackDepth(); depth++ {
		position := thread.CallFrame(depth).Pos
		if position.IsValid() && position.Filename() != "<builtin>" {
			return position
		}
	}
	return syntax.Position{}
}

func (session *compileSession) cancellation() *ruleError {
	session.cancelMu.Lock()
	defer session.cancelMu.Unlock()
	return session.cancelCause
}
