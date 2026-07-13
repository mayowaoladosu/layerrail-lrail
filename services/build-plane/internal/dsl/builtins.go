package dsl

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildir"
	"go.starlark.net/starlark"
)

var (
	localOutputName     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	localCapabilityName = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
	localEnvironmentKey = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
	localLabelKey       = regexp.MustCompile(`^[a-z0-9][a-z0-9./_-]{0,127}$`)
	localHeaderName     = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,126}$`)
	localOwner          = regexp.MustCompile(`^[1-9][0-9]{0,9}:[1-9][0-9]{0,9}$`)
	localMode           = regexp.MustCompile(`^0[0-7]{3}$`)
	localPinnedImage    = regexp.MustCompile(`^[a-z0-9][a-z0-9./:_-]{0,511}@sha256:[0-9a-f]{64}$`)
)

func (session *compileSession) builtins() starlark.StringDict {
	return starlark.StringDict{
		"artifact":    starlark.NewBuiltin("artifact", session.artifact),
		"cache":       starlark.NewBuiltin("cache", session.cache),
		"copy":        starlark.NewBuiltin("copy", session.copy),
		"image":       starlark.NewBuiltin("image", session.image),
		"run":         starlark.NewBuiltin("run", session.run),
		"secret":      starlark.NewBuiltin("secret", session.secret),
		"shell":       starlark.NewBuiltin("shell", session.shell),
		"source":      starlark.NewBuiltin("source", session.source),
		"static_site": starlark.NewBuiltin("static_site", session.staticSite),
	}
}

func (session *compileSession) source(thread *starlark.Thread, function *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := session.beforeBuiltin(thread, args); err != nil {
		return nil, err
	}
	var sourcePath string
	var include, exclude *starlark.List
	if err := starlark.UnpackArgs(function.Name(), args, kwargs, "path", &sourcePath, "include?", &include, "exclude?", &exclude); err != nil {
		return nil, argumentFailure(thread)
	}
	includes, ok := session.stringList(include, true)
	if !ok {
		return nil, valueFailure(thread, "Source include patterns must be bounded canonical UTF-8 strings.")
	}
	excludes, ok := session.stringList(exclude, true)
	if !ok {
		return nil, valueFailure(thread, "Source exclude patterns must be bounded canonical UTF-8 strings.")
	}
	if !safeRelative(sourcePath) {
		return nil, builtinFailure(
			thread,
			"dsl.path",
			"Source paths must be canonical repository-relative paths.",
			"builtins.source.path",
			"Use . or a path without traversal, backslashes, or a drive prefix.",
		)
	}
	return session.appendNode(thread, "source", nil, map[string]any{
		"path":    sourcePath,
		"include": includes,
		"exclude": excludes,
	})
}

func (session *compileSession) image(thread *starlark.Thread, function *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := session.beforeBuiltin(thread, args); err != nil {
		return nil, err
	}
	var reference string
	if err := starlark.UnpackArgs(function.Name(), args, kwargs, "ref", &reference); err != nil {
		return nil, argumentFailure(thread)
	}
	if !localPinnedImage.MatchString(reference) || strings.Contains(reference, "..") || strings.Contains(reference, "//") {
		return nil, builtinFailure(
			thread,
			"dsl.image_ref",
			"Base images must use a lowercase digest-pinned OCI reference.",
			"builtins.image.ref",
			"Use repository/name@sha256 followed by exactly 64 lowercase hexadecimal characters.",
		)
	}
	return session.appendNode(thread, "image", nil, map[string]any{"ref": reference})
}

func (session *compileSession) run(thread *starlark.Thread, function *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := session.beforeBuiltin(thread, args); err != nil {
		return nil, err
	}
	var baseValue, commandValue starlark.Value
	var environment *starlark.Dict
	var mounts *starlark.List
	network := "none"
	user := "10001:10001"
	workdir := "/workspace"
	if err := starlark.UnpackArgs(
		function.Name(), args, kwargs,
		"base", &baseValue,
		"argv", &commandValue,
		"env?", &environment,
		"mounts?", &mounts,
		"network?", &network,
		"user?", &user,
		"workdir?", &workdir,
	); err != nil {
		return nil, argumentFailure(thread)
	}
	base, ok := requireNode(baseValue, "image", "run", "copy")
	if !ok {
		return nil, typeFailure(thread, "Run base must be an image, run, or copy state reference.")
	}
	arguments, explicitShell, ok := session.command(commandValue)
	if !ok || len(arguments) == 0 {
		return nil, valueFailure(thread, "Run argv must be a bounded non-empty string list or an explicit shell() value.")
	}
	if !explicitShell && shellInvocation(arguments) {
		return nil, builtinFailure(
			thread,
			"dsl.shell_required",
			"Shell interpreters require the explicit shell() wrapper.",
			"builtins.run.explicit_shell",
			"Pass shell(command = ...) as argv so shell interpretation is visible in typed Build IR.",
		)
	}
	environmentValues, ok := session.stringDict(environment, localEnvironmentKey, false)
	if !ok {
		return nil, valueFailure(thread, "Run environment keys and values must be bounded strings.")
	}
	mountValues, ok := session.nodeList(mounts, "cache", "secret")
	if !ok {
		return nil, typeFailure(thread, "Run mounts must contain unique cache or secret references.")
	}
	slices.SortFunc(mountValues, func(left, right nodeRef) int {
		return strings.Compare(left.id, right.id)
	})
	mountIDs := make([]string, 0, len(mountValues))
	inputs := []string{base.id}
	for _, mount := range mountValues {
		mountIDs = append(mountIDs, mount.id)
		inputs = append(inputs, mount.id)
	}
	if !slices.Contains([]string{"none", "packages", "allowlist", "private"}, network) || networkRank(network) > networkRank(session.compiler.options.NetworkProfile) {
		return nil, builtinFailure(
			thread,
			"dsl.network",
			"Run network access exceeds the build assignment ceiling.",
			"builtins.run.network",
			"Request none or a network profile no broader than the signed build assignment.",
		)
	}
	if !localOwner.MatchString(user) || !safeAbsolute(workdir) {
		return nil, valueFailure(thread, "Run user and workdir must be a non-root numeric uid:gid and canonical absolute path.")
	}
	return session.appendNode(thread, "run", inputs, map[string]any{
		"argv":    arguments,
		"env":     environmentValues,
		"mounts":  mountIDs,
		"network": network,
		"shell":   explicitShell,
		"user":    user,
		"workdir": workdir,
	})
}

func (session *compileSession) copy(thread *starlark.Thread, function *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := session.beforeBuiltin(thread, args); err != nil {
		return nil, err
	}
	var baseValue, sourceValue starlark.Value
	var destination string
	owner := "10001:10001"
	mode := "0755"
	if err := starlark.UnpackArgs(function.Name(), args, kwargs, "base", &baseValue, "src", &sourceValue, "dest", &destination, "owner?", &owner, "mode?", &mode); err != nil {
		return nil, argumentFailure(thread)
	}
	base, baseOK := requireNode(baseValue, "image", "run", "copy")
	source, sourceOK := requireNode(sourceValue, "source")
	if !baseOK || !sourceOK {
		return nil, typeFailure(thread, "Copy requires a state base and a source() reference.")
	}
	if !safeAbsolute(destination) || !localOwner.MatchString(owner) || !localMode.MatchString(mode) {
		return nil, valueFailure(thread, "Copy dest, owner, and mode must be canonical, non-root, and bounded.")
	}
	return session.appendNode(thread, "copy", []string{base.id, source.id}, map[string]any{
		"dest":  destination,
		"owner": owner,
		"mode":  mode,
	})
}

func (session *compileSession) cache(thread *starlark.Thread, function *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := session.beforeBuiltin(thread, args); err != nil {
		return nil, err
	}
	var name, target string
	sharing := "locked"
	if err := starlark.UnpackArgs(function.Name(), args, kwargs, "name", &name, "target", &target, "sharing?", &sharing); err != nil {
		return nil, argumentFailure(thread)
	}
	if !localCapabilityName.MatchString(name) || !safeAbsolute(target) || !slices.Contains([]string{"locked", "private", "shared"}, sharing) {
		return nil, valueFailure(thread, "Cache name, target, and sharing mode are invalid.")
	}
	return session.appendNode(thread, "cache", nil, map[string]any{
		"name":    name,
		"target":  target,
		"sharing": sharing,
	})
}

func (session *compileSession) secret(thread *starlark.Thread, function *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := session.beforeBuiltin(thread, args); err != nil {
		return nil, err
	}
	var name, target string
	required := true
	if err := starlark.UnpackArgs(function.Name(), args, kwargs, "name", &name, "target", &target, "required?", &required); err != nil {
		return nil, argumentFailure(thread)
	}
	if !localCapabilityName.MatchString(name) || !strings.HasPrefix(target, "/run/secrets/") || !safeAbsolute(target) {
		return nil, valueFailure(thread, "Secret name and /run/secrets target are invalid.")
	}
	return session.appendNode(thread, "secret", nil, map[string]any{
		"name":     name,
		"target":   target,
		"required": required,
	})
}

func (session *compileSession) shell(thread *starlark.Thread, function *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := session.beforeBuiltin(thread, args); err != nil {
		return nil, err
	}
	var command string
	if err := starlark.UnpackArgs(function.Name(), args, kwargs, "command", &command); err != nil {
		return nil, argumentFailure(thread)
	}
	if !session.validString(command, false) {
		return nil, valueFailure(thread, "Explicit shell command must be a bounded UTF-8 string without NUL bytes.")
	}
	return shellCommand{arguments: []string{"/bin/sh", "-euc", command}}, nil
}

func (session *compileSession) artifact(thread *starlark.Thread, function *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := session.beforeBuiltin(thread, args); err != nil {
		return nil, err
	}
	var name string
	var stateValue starlark.Value
	var entrypoint, command, ports *starlark.List
	var labels *starlark.Dict
	if err := starlark.UnpackArgs(function.Name(), args, kwargs, "name", &name, "state", &stateValue, "entrypoint?", &entrypoint, "cmd?", &command, "ports?", &ports, "labels?", &labels); err != nil {
		return nil, argumentFailure(thread)
	}
	state, ok := requireNode(stateValue, "image", "run", "copy")
	if !ok {
		return nil, typeFailure(thread, "Artifact state must be an image, run, or copy reference.")
	}
	entrypointValues, ok := session.stringList(entrypoint, false)
	if !ok || len(entrypointValues) > 32 {
		return nil, valueFailure(thread, "Artifact entrypoint must contain at most 32 bounded strings.")
	}
	commandValues, ok := session.stringList(command, false)
	if !ok || len(commandValues) > 64 {
		return nil, valueFailure(thread, "Artifact cmd must contain at most 64 bounded strings.")
	}
	portValues, ok := session.intList(ports)
	if !ok || len(portValues) > 16 {
		return nil, valueFailure(thread, "Artifact ports must contain at most 16 unique valid TCP ports.")
	}
	slices.Sort(portValues)
	labelValues, ok := session.stringDict(labels, localLabelKey, true)
	if !ok {
		return nil, valueFailure(thread, "Artifact labels must be bounded lowercase string pairs.")
	}
	return session.appendOutput(thread, buildir.Output{
		Name:       name,
		Kind:       "oci_image",
		State:      state.id,
		Entrypoint: entrypointValues,
		Command:    commandValues,
		Ports:      portValues,
		Labels:     labelValues,
		Headers:    map[string]string{},
	})
}

func (session *compileSession) staticSite(thread *starlark.Thread, function *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := session.beforeBuiltin(thread, args); err != nil {
		return nil, err
	}
	var name string
	var sourceValue starlark.Value
	var headers *starlark.Dict
	if err := starlark.UnpackArgs(function.Name(), args, kwargs, "name", &name, "source_dir", &sourceValue, "headers?", &headers); err != nil {
		return nil, argumentFailure(thread)
	}
	state, ok := requireNode(sourceValue, "source", "run", "copy")
	if !ok {
		return nil, typeFailure(thread, "Static site source_dir must be a source, run, or copy reference.")
	}
	headerValues, ok := session.stringDict(headers, localHeaderName, true)
	if !ok {
		return nil, valueFailure(thread, "Static site headers must be bounded strings without line breaks.")
	}
	return session.appendOutput(thread, buildir.Output{
		Name:       name,
		Kind:       "static_bundle",
		State:      state.id,
		Entrypoint: []string{},
		Command:    []string{},
		Ports:      []int{},
		Labels:     map[string]string{},
		Headers:    headerValues,
	})
}

func (session *compileSession) beforeBuiltin(thread *starlark.Thread, args starlark.Tuple) error {
	if thread.CallStackDepth() > session.limits.MaxCallDepth {
		return builtinFailure(
			thread,
			"dsl.call_depth",
			"Starlark evaluation exceeded the configured call-depth limit.",
			"limits.call_depth",
			fmt.Sprintf("Keep helper and built-in call chains within %d frames.", session.limits.MaxCallDepth),
		)
	}
	if session.initializingModule > 0 {
		return builtinFailure(
			thread,
			"dsl.module_side_effect",
			"Loaded modules may define immutable helpers but may not emit Build IR during initialization.",
			"modules.no_initialization_effects",
			"Move owned built-in calls into a helper function invoked by the entry file.",
		)
	}
	if len(args) != 0 {
		return builtinFailure(
			thread,
			"dsl.named_arguments",
			"Owned Lrail built-ins accept named arguments only.",
			"arguments.named_only",
			"Name every argument so build definitions remain schema-readable across compiler versions.",
		)
	}
	return nil
}

func (session *compileSession) appendNode(thread *starlark.Thread, operation string, inputs []string, attributes map[string]any) (starlark.Value, error) {
	if len(session.nodes) >= session.limits.MaxResultNodes {
		return nil, builtinFailure(
			thread,
			"dsl.result_limit",
			"Build IR node count exceeds the configured result limit.",
			"limits.result_nodes",
			fmt.Sprintf("Emit at most %d typed Build IR nodes.", session.limits.MaxResultNodes),
		)
	}
	identifier := fmt.Sprintf("n%d", len(session.nodes)+1)
	node := buildir.Node{
		ID:         identifier,
		Operation:  operation,
		Inputs:     append([]string{}, inputs...),
		Attributes: attributes,
	}
	session.nodes = append(session.nodes, node)
	return nodeRef{id: identifier, operation: operation}, nil
}

func (session *compileSession) appendOutput(thread *starlark.Thread, output buildir.Output) (starlark.Value, error) {
	if !localOutputName.MatchString(output.Name) {
		return nil, valueFailure(thread, "Output name must be a lowercase DNS-label-like identifier.")
	}
	if len(session.outputs) >= session.limits.MaxOutputs {
		return nil, builtinFailure(
			thread,
			"dsl.output_limit",
			"Build output count exceeds the configured result limit.",
			"limits.outputs",
			fmt.Sprintf("Declare at most %d named outputs.", session.limits.MaxOutputs),
		)
	}
	for _, existing := range session.outputs {
		if existing.Name == output.Name {
			return nil, builtinFailure(
				thread,
				"dsl.output_duplicate",
				"Build output names must be unique.",
				"result.output_names",
				"Rename one of the duplicate artifact or static site outputs.",
			)
		}
	}
	session.outputs = append(session.outputs, output)
	return outputRef{name: output.Name, kind: output.Kind}, nil
}

func requireNode(value starlark.Value, operations ...string) (nodeRef, bool) {
	reference, ok := value.(nodeRef)
	return reference, ok && slices.Contains(operations, reference.operation)
}

func (session *compileSession) command(value starlark.Value) ([]string, bool, bool) {
	if shellValue, ok := value.(shellCommand); ok {
		return append([]string(nil), shellValue.arguments...), true, true
	}
	list, ok := value.(*starlark.List)
	if !ok {
		return nil, false, false
	}
	arguments, ok := session.stringList(list, false)
	return arguments, false, ok
}

func (session *compileSession) stringList(list *starlark.List, patterns bool) ([]string, bool) {
	if list == nil {
		return []string{}, true
	}
	if list.Len() > session.limits.MaxCollectionItems {
		return nil, false
	}
	result := make([]string, 0, list.Len())
	iterator := list.Iterate()
	defer iterator.Done()
	var value starlark.Value
	for iterator.Next(&value) {
		text, ok := starlark.AsString(value)
		if !ok || !session.validString(text, false) || (patterns && !safeGlob(text)) {
			return nil, false
		}
		result = append(result, text)
	}
	if patterns {
		slices.Sort(result)
		result = slices.Compact(result)
	}
	return result, true
}

func (session *compileSession) nodeList(list *starlark.List, operations ...string) ([]nodeRef, bool) {
	if list == nil {
		return []nodeRef{}, true
	}
	if list.Len() > session.limits.MaxCollectionItems {
		return nil, false
	}
	result := make([]nodeRef, 0, list.Len())
	seen := make(map[string]struct{}, list.Len())
	iterator := list.Iterate()
	defer iterator.Done()
	var value starlark.Value
	for iterator.Next(&value) {
		reference, ok := requireNode(value, operations...)
		if !ok {
			return nil, false
		}
		if _, exists := seen[reference.id]; exists {
			return nil, false
		}
		seen[reference.id] = struct{}{}
		result = append(result, reference)
	}
	return result, true
}

func (session *compileSession) intList(list *starlark.List) ([]int, bool) {
	if list == nil {
		return []int{}, true
	}
	if list.Len() > session.limits.MaxCollectionItems {
		return nil, false
	}
	result := make([]int, 0, list.Len())
	seen := make(map[int]struct{}, list.Len())
	iterator := list.Iterate()
	defer iterator.Done()
	var value starlark.Value
	for iterator.Next(&value) {
		integer, err := starlark.AsInt32(value)
		if err != nil || integer < 1 || integer > 65535 {
			return nil, false
		}
		if _, exists := seen[integer]; exists {
			return nil, false
		}
		seen[integer] = struct{}{}
		result = append(result, integer)
	}
	return result, true
}

func (session *compileSession) stringDict(dictionary *starlark.Dict, keyPattern *regexp.Regexp, rejectNewline bool) (map[string]string, bool) {
	if dictionary == nil {
		return map[string]string{}, true
	}
	if dictionary.Len() > session.limits.MaxCollectionItems {
		return nil, false
	}
	result := make(map[string]string, dictionary.Len())
	foldedKeys := make(map[string]struct{}, dictionary.Len())
	for _, item := range dictionary.Items() {
		key, keyOK := starlark.AsString(item[0])
		value, valueOK := starlark.AsString(item[1])
		if !keyOK || !valueOK || !keyPattern.MatchString(key) || !session.validString(value, true) || (rejectNewline && strings.ContainsAny(value, "\r\n")) {
			return nil, false
		}
		if keyPattern == localHeaderName {
			folded := strings.ToLower(key)
			if _, exists := foldedKeys[folded]; exists {
				return nil, false
			}
			foldedKeys[folded] = struct{}{}
		}
		result[key] = value
	}
	return result, true
}

func (session *compileSession) validString(value string, allowEmpty bool) bool {
	return (allowEmpty || value != "") && len(value) <= session.limits.MaxStringBytes && utf8.ValidString(value) && !strings.ContainsRune(value, '\x00')
}

func safeRelative(value string) bool {
	if value == "." {
		return true
	}
	return value != "" && !strings.HasPrefix(value, "/") && !strings.ContainsAny(value, "\\:") && path.Clean(value) == value && value != ".." && !strings.HasPrefix(value, "../")
}

func safeAbsolute(value string) bool {
	return value != "/" && strings.HasPrefix(value, "/") && !strings.Contains(value, "\\") && !strings.ContainsRune(value, '\x00') && path.Clean(value) == value
}

func safeGlob(value string) bool {
	if value == "" || strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\\:") {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == ".." {
			return false
		}
	}
	return true
}

func networkRank(network string) int {
	return slices.Index([]string{"none", "packages", "allowlist", "private"}, network)
}

func shellInvocation(arguments []string) bool {
	if len(arguments) == 0 {
		return false
	}
	isShell := func(value string) bool {
		name := path.Base(value)
		return slices.Contains([]string{"ash", "bash", "cmd.exe", "dash", "ksh", "powershell", "pwsh", "sh", "zsh"}, name)
	}
	if isShell(arguments[0]) {
		return true
	}
	name := path.Base(arguments[0])
	return len(arguments) > 1 && (name == "env" || name == "busybox") && isShell(arguments[1])
}

func argumentFailure(thread *starlark.Thread) error {
	return builtinFailure(
		thread,
		"dsl.arguments",
		"An owned Lrail built-in received missing, unknown, or incorrectly typed arguments.",
		"arguments.schema",
		"Use only the documented named arguments and value types for this built-in.",
	)
}

func valueFailure(thread *starlark.Thread, message string) error {
	return builtinFailure(
		thread,
		"dsl.value",
		message,
		"arguments.value",
		"Use bounded canonical values accepted by the typed Build IR contract.",
	)
}

func typeFailure(thread *starlark.Thread, message string) error {
	return builtinFailure(
		thread,
		"dsl.reference_type",
		message,
		"arguments.reference_type",
		"Pass only immutable references returned by compatible owned Lrail built-ins.",
	)
}
