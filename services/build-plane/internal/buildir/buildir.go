// Package buildir validates and digests the deterministic graph between the
// constrained Starlark language and BuildKit LLB compilation.
package buildir

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
)

const (
	CurrentVersion       = 2
	CurrentDSLAPIVersion = "lrail.build/v1"
	MaxNodes             = 1024
	MaxOutputs           = 64
	MaxModules           = 64
	MaxInputs            = 32
	MaxArguments         = 128
	MaxStringBytes       = 4096
)

var (
	ErrInvalid            = errors.New("invalid Build IR")
	digestPattern         = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	semverPattern         = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	nodeIDPattern         = regexp.MustCompile(`^n[1-9][0-9]{0,3}$`)
	outputNamePattern     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	capabilityNamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
	environmentKeyPattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
	labelKeyPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9./_-]{0,127}$`)
	headerNamePattern     = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,126}$`)
	ownerPattern          = regexp.MustCompile(`^[1-9][0-9]{0,9}:[1-9][0-9]{0,9}$`)
	modePattern           = regexp.MustCompile(`^0[0-7]{3}$`)
	pinnedImagePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9./:_-]{0,511}@sha256:[0-9a-f]{64}$`)
	hostnamePattern       = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)
	repositoryModule      = regexp.MustCompile(`^//[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\.star$`)
	standardModule        = regexp.MustCompile(`^@lrail/v[1-9][0-9]*/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\.star$`)
	allowedOperations     = []string{"cache", "copy", "image", "run", "secret", "source"}
	allowedNetworks       = []string{"none", "packages", "allowlist", "private"}
	stateOperations       = []string{"copy", "image", "run"}
)

type IR struct {
	Version         int      `json:"ir_version"`
	DSLAPIVersion   string   `json:"dsl_api_version"`
	CompilerVersion string   `json:"compiler_version"`
	SourceSnapshot  string   `json:"source_snapshot"`
	TargetPlatform  string   `json:"target_platform"`
	NetworkProfile  string   `json:"network_profile"`
	AllowedHosts    []string `json:"allowed_hosts,omitempty"`
	Modules         []Module `json:"modules"`
	Nodes           []Node   `json:"nodes"`
	Outputs         []Output `json:"outputs"`
}

type Module struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Digest string `json:"digest"`
}

type Node struct {
	ID         string         `json:"id"`
	Operation  string         `json:"op"`
	Inputs     []string       `json:"inputs"`
	Attributes map[string]any `json:"attributes"`
}

type Output struct {
	Name       string            `json:"name"`
	Kind       string            `json:"kind"`
	State      string            `json:"state"`
	Entrypoint []string          `json:"entrypoint"`
	Command    []string          `json:"command"`
	Ports      []int             `json:"ports"`
	Labels     map[string]string `json:"labels"`
	Headers    map[string]string `json:"headers"`
}

func (ir IR) Validate() error {
	if ir.Version != CurrentVersion {
		return invalidf("unsupported ir_version %d", ir.Version)
	}
	if ir.DSLAPIVersion != CurrentDSLAPIVersion {
		return invalidf("unsupported dsl_api_version %q", ir.DSLAPIVersion)
	}
	if !semverPattern.MatchString(ir.CompilerVersion) {
		return invalidf("compiler_version must be semantic version text")
	}
	if !digestPattern.MatchString(ir.SourceSnapshot) {
		return invalidf("source_snapshot must be a sha256 digest")
	}
	if ir.TargetPlatform != "linux/amd64" && ir.TargetPlatform != "linux/arm64" {
		return invalidf("unsupported target_platform %q", ir.TargetPlatform)
	}
	if !slices.Contains(allowedNetworks, ir.NetworkProfile) {
		return invalidf("unsupported network_profile %q", ir.NetworkProfile)
	}
	if err := validateAllowedHosts(ir.NetworkProfile, ir.AllowedHosts); err != nil {
		return err
	}
	if err := validateModules(ir.Modules); err != nil {
		return err
	}
	if len(ir.Nodes) == 0 || len(ir.Nodes) > MaxNodes {
		return invalidf("node count must be between 1 and %d", MaxNodes)
	}
	if len(ir.Outputs) == 0 || len(ir.Outputs) > MaxOutputs {
		return invalidf("output count must be between 1 and %d", MaxOutputs)
	}

	seen := make(map[string]Node, len(ir.Nodes))
	for index, node := range ir.Nodes {
		expectedID := "n" + strconv.Itoa(index+1)
		if node.ID != expectedID || !nodeIDPattern.MatchString(node.ID) {
			return invalidf("nodes[%d].id must be %q", index, expectedID)
		}
		if !slices.Contains(allowedOperations, node.Operation) {
			return invalidf("node %s has unsupported operation %q", node.ID, node.Operation)
		}
		if len(node.Inputs) > MaxInputs || !uniqueStrings(node.Inputs) {
			return invalidf("node %s inputs must be bounded and unique", node.ID)
		}
		for _, input := range node.Inputs {
			if _, exists := seen[input]; !exists {
				return invalidf("node %s input %q must reference an earlier node", node.ID, input)
			}
		}
		if err := validateNode(node, seen, ir.NetworkProfile); err != nil {
			return err
		}
		seen[node.ID] = node
	}

	previousName := ""
	for index, output := range ir.Outputs {
		if !outputNamePattern.MatchString(output.Name) {
			return invalidf("outputs[%d].name is invalid", index)
		}
		if output.Name <= previousName {
			return invalidf("outputs must have unique names in lexical order")
		}
		state, exists := seen[output.State]
		if !exists {
			return invalidf("output %s references unknown state %q", output.Name, output.State)
		}
		if err := validateOutput(output, state); err != nil {
			return err
		}
		previousName = output.Name
	}
	return nil
}

func DefinitionDigest(ir IR) (string, error) {
	if err := ir.Validate(); err != nil {
		return "", err
	}
	canonical, err := canonicaljson.Marshal(ir)
	if err != nil {
		return "", fmt.Errorf("canonicalize Build IR: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func Decode(raw []byte) (IR, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var ir IR
	if err := decoder.Decode(&ir); err != nil {
		return IR{}, invalidf("decode typed JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return IR{}, invalidf("JSON must contain exactly one Build IR value")
	}
	if err := ir.Validate(); err != nil {
		return IR{}, err
	}
	return ir, nil
}

func validateAllowedHosts(profile string, hosts []string) error {
	if profile != "allowlist" && len(hosts) > 0 {
		return invalidf("allowed_hosts require the allowlist network profile")
	}
	if profile == "allowlist" && len(hosts) == 0 {
		return invalidf("the allowlist network profile requires allowed_hosts")
	}
	if len(hosts) > 64 || !strictlySorted(hosts) {
		return invalidf("allowed_hosts must be unique, sorted, and bounded")
	}
	for _, host := range hosts {
		if len(host) > 253 || host != strings.ToLower(host) || !hostnamePattern.MatchString(host) {
			return invalidf("allowed host %q is invalid", host)
		}
	}
	return nil
}

func validateModules(modules []Module) error {
	if len(modules) > MaxModules {
		return invalidf("module count exceeds %d", MaxModules)
	}
	previousName := ""
	for _, module := range modules {
		if module.Name <= previousName {
			return invalidf("modules must have unique names in lexical order")
		}
		switch module.Kind {
		case "repository":
			if !repositoryModule.MatchString(module.Name) || !safeRelativePath(strings.TrimPrefix(module.Name, "//")) {
				return invalidf("repository module name %q is invalid", module.Name)
			}
		case "standard":
			parts := strings.SplitN(module.Name, "/", 3)
			if !standardModule.MatchString(module.Name) || len(parts) != 3 || !safeRelativePath(parts[2]) {
				return invalidf("standard module name %q is invalid", module.Name)
			}
		default:
			return invalidf("module %q has invalid kind %q", module.Name, module.Kind)
		}
		if !digestPattern.MatchString(module.Digest) {
			return invalidf("module %q has invalid digest", module.Name)
		}
		previousName = module.Name
	}
	return nil
}

func validateNode(node Node, earlier map[string]Node, networkCeiling string) error {
	if node.Attributes == nil {
		return invalidf("node %s attributes must be an object", node.ID)
	}
	switch node.Operation {
	case "source":
		if len(node.Inputs) != 0 || !exactKeys(node.Attributes, "exclude", "include", "path") {
			return invalidf("source node %s has invalid fields", node.ID)
		}
		sourcePath, ok := node.Attributes["path"].(string)
		if !ok || !safeRelativePath(sourcePath) {
			return invalidf("source node %s requires a safe relative path", node.ID)
		}
		include, includeOK := stringSlice(node.Attributes["include"])
		exclude, excludeOK := stringSlice(node.Attributes["exclude"])
		if !includeOK || !excludeOK || !validPatterns(include) || !validPatterns(exclude) {
			return invalidf("source node %s has invalid include or exclude patterns", node.ID)
		}
	case "image":
		if len(node.Inputs) != 0 || !exactKeys(node.Attributes, "ref") {
			return invalidf("image node %s has invalid fields", node.ID)
		}
		ref, ok := node.Attributes["ref"].(string)
		if !ok || !pinnedImagePattern.MatchString(ref) || strings.Contains(ref, "..") || strings.Contains(ref, "//") {
			return invalidf("image node %s requires a digest-pinned image reference", node.ID)
		}
	case "run":
		if err := validateRun(node, earlier, networkCeiling); err != nil {
			return err
		}
	case "copy":
		if len(node.Inputs) != 2 || !exactKeys(node.Attributes, "dest", "mode", "owner") {
			return invalidf("copy node %s has invalid fields", node.ID)
		}
		if !slices.Contains(stateOperations, earlier[node.Inputs[0]].Operation) || earlier[node.Inputs[1]].Operation != "source" {
			return invalidf("copy node %s requires state and source inputs", node.ID)
		}
		destination, destinationOK := node.Attributes["dest"].(string)
		owner, ownerOK := node.Attributes["owner"].(string)
		mode, modeOK := node.Attributes["mode"].(string)
		if !destinationOK || !safeAbsolutePath(destination) || !ownerOK || !ownerPattern.MatchString(owner) || !modeOK || !modePattern.MatchString(mode) {
			return invalidf("copy node %s has unsafe destination, owner, or mode", node.ID)
		}
	case "cache":
		if len(node.Inputs) != 0 || !exactKeys(node.Attributes, "name", "sharing", "target") {
			return invalidf("cache node %s has invalid fields", node.ID)
		}
		name, nameOK := node.Attributes["name"].(string)
		target, targetOK := node.Attributes["target"].(string)
		sharing, sharingOK := node.Attributes["sharing"].(string)
		if !nameOK || !capabilityNamePattern.MatchString(name) || !targetOK || !safeAbsolutePath(target) || !sharingOK || !slices.Contains([]string{"locked", "private", "shared"}, sharing) {
			return invalidf("cache node %s has invalid name, target, or sharing", node.ID)
		}
	case "secret":
		if len(node.Inputs) != 0 || !exactKeys(node.Attributes, "name", "required", "target") {
			return invalidf("secret node %s has invalid fields", node.ID)
		}
		name, nameOK := node.Attributes["name"].(string)
		target, targetOK := node.Attributes["target"].(string)
		_, requiredOK := node.Attributes["required"].(bool)
		if !nameOK || !capabilityNamePattern.MatchString(name) || !targetOK || !safeSecretTarget(target) || !requiredOK {
			return invalidf("secret node %s has invalid name, target, or required flag", node.ID)
		}
	}
	return nil
}

func validateRun(node Node, earlier map[string]Node, networkCeiling string) error {
	if len(node.Inputs) == 0 || !exactKeys(node.Attributes, "argv", "env", "mounts", "network", "shell", "user", "workdir") {
		return invalidf("run node %s has invalid fields", node.ID)
	}
	if !slices.Contains(stateOperations, earlier[node.Inputs[0]].Operation) {
		return invalidf("run node %s requires a state base", node.ID)
	}
	arguments, argumentsOK := stringSlice(node.Attributes["argv"])
	mounts, mountsOK := stringSlice(node.Attributes["mounts"])
	environment, environmentOK := stringMap(node.Attributes["env"])
	network, networkOK := node.Attributes["network"].(string)
	shell, shellOK := node.Attributes["shell"].(bool)
	user, userOK := node.Attributes["user"].(string)
	workdir, workdirOK := node.Attributes["workdir"].(string)
	if !argumentsOK || len(arguments) == 0 || len(arguments) > MaxArguments || !validStrings(arguments) {
		return invalidf("run node %s requires bounded argv", node.ID)
	}
	if shell && (len(arguments) != 3 || arguments[0] != "/bin/sh" || arguments[1] != "-euc") {
		return invalidf("run node %s has an invalid explicit shell command", node.ID)
	}
	if !shell && shellInvocation(arguments) {
		return invalidf("run node %s must mark shell interpretation explicitly", node.ID)
	}
	if !mountsOK || !strictlySorted(mounts) || !slices.Equal(node.Inputs[1:], mounts) {
		return invalidf("run node %s mounts must match sorted mount inputs", node.ID)
	}
	for _, mount := range mounts {
		operation := earlier[mount].Operation
		if operation != "cache" && operation != "secret" {
			return invalidf("run node %s mount %s is not a cache or secret", node.ID, mount)
		}
	}
	if !environmentOK || !validStringMap(environment, environmentKeyPattern, false) {
		return invalidf("run node %s has invalid environment", node.ID)
	}
	if !networkOK || !slices.Contains(allowedNetworks, network) || networkRank(network) > networkRank(networkCeiling) {
		return invalidf("run node %s requests network broader than its assignment", node.ID)
	}
	if !shellOK || !userOK || !ownerPattern.MatchString(user) || !workdirOK || !safeAbsolutePath(workdir) {
		return invalidf("run node %s has invalid shell, user, or workdir", node.ID)
	}
	return nil
}

func validateOutput(output Output, state Node) error {
	if output.Entrypoint == nil || output.Command == nil || output.Ports == nil || output.Labels == nil || output.Headers == nil {
		return invalidf("output %s collections must not be null", output.Name)
	}
	if len(output.Entrypoint) > 32 || len(output.Command) > 64 || len(output.Ports) > 16 || !validStrings(output.Entrypoint) || !validStrings(output.Command) || !uniqueInts(output.Ports) {
		return invalidf("output %s process values are invalid", output.Name)
	}
	for _, port := range output.Ports {
		if port < 1 || port > 65535 {
			return invalidf("output %s has invalid port %d", output.Name, port)
		}
	}
	switch output.Kind {
	case "oci_image":
		if !slices.Contains(stateOperations, state.Operation) || len(output.Headers) != 0 || !validStringMap(output.Labels, labelKeyPattern, false) {
			return invalidf("OCI output %s has invalid state, labels, or headers", output.Name)
		}
	case "static_bundle":
		if !slices.Contains([]string{"copy", "run", "source"}, state.Operation) || len(output.Entrypoint) != 0 || len(output.Command) != 0 || len(output.Ports) != 0 || len(output.Labels) != 0 || !validStringMap(output.Headers, headerNamePattern, true) || !uniqueFoldedKeys(output.Headers) {
			return invalidf("static output %s has invalid state or metadata", output.Name)
		}
	default:
		return invalidf("output %s has unsupported kind %q", output.Name, output.Kind)
	}
	return nil
}

func exactKeys(attributes map[string]any, expected ...string) bool {
	if len(attributes) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, exists := attributes[key]; !exists {
			return false
		}
	}
	return true
}

func stringSlice(value any) ([]string, bool) {
	switch typed := value.(type) {
	case []string:
		return typed, true
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			text, ok := item.(string)
			if !ok {
				return nil, false
			}
			result = append(result, text)
		}
		return result, true
	default:
		return nil, false
	}
}

func stringMap(value any) (map[string]string, bool) {
	switch typed := value.(type) {
	case map[string]string:
		return typed, true
	case map[string]any:
		result := make(map[string]string, len(typed))
		for key, item := range typed {
			text, ok := item.(string)
			if !ok {
				return nil, false
			}
			result[key] = text
		}
		return result, true
	default:
		return nil, false
	}
}

func validStrings(values []string) bool {
	for _, value := range values {
		if !validString(value) {
			return false
		}
	}
	return true
}

func validPatterns(values []string) bool {
	if len(values) > MaxArguments || !strictlySorted(values) {
		return false
	}
	for _, value := range values {
		if !validString(value) || !safePattern(value) {
			return false
		}
	}
	return true
}

func validStringMap(values map[string]string, keyPattern *regexp.Regexp, rejectNewline bool) bool {
	if len(values) > MaxArguments {
		return false
	}
	for key, value := range values {
		if !keyPattern.MatchString(key) || !boundedString(value, true) || (rejectNewline && strings.ContainsAny(value, "\r\n")) {
			return false
		}
	}
	return true
}

func validString(value string) bool {
	return boundedString(value, false)
}

func boundedString(value string, allowEmpty bool) bool {
	return (allowEmpty || value != "") && len(value) <= MaxStringBytes && utf8.ValidString(value) && !strings.ContainsRune(value, '\x00')
}

func safePattern(value string) bool {
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

func safeRelativePath(value string) bool {
	if value == "." {
		return true
	}
	return value != "" && !strings.HasPrefix(value, "/") && !strings.ContainsAny(value, "\\:") && path.Clean(value) == value && value != ".." && !strings.HasPrefix(value, "../")
}

func safeAbsolutePath(value string) bool {
	return value != "/" && strings.HasPrefix(value, "/") && !strings.Contains(value, "\\") && !strings.ContainsRune(value, '\x00') && path.Clean(value) == value
}

func safeSecretTarget(value string) bool {
	return strings.HasPrefix(value, "/run/secrets/") && safeAbsolutePath(value) && len(strings.TrimPrefix(value, "/run/secrets/")) > 0
}

func strictlySorted(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] >= values[index] {
			return false
		}
	}
	return true
}

func uniqueStrings(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func uniqueInts(values []int) bool {
	seen := make(map[int]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func uniqueFoldedKeys(values map[string]string) bool {
	seen := make(map[string]struct{}, len(values))
	for key := range values {
		folded := strings.ToLower(key)
		if _, exists := seen[folded]; exists {
			return false
		}
		seen[folded] = struct{}{}
	}
	return true
}

func networkRank(network string) int {
	return slices.Index(allowedNetworks, network)
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

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
