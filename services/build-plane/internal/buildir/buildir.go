// Package buildir validates and digests the deterministic graph between the
// constrained Starlark language and BuildKit LLB compilation.
package buildir

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
)

const (
	CurrentVersion = 1
	MaxNodes       = 1024
	MaxOutputs     = 64
)

var (
	ErrInvalid         = errors.New("invalid Build IR")
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	nodeIDPattern      = regexp.MustCompile(`^n[1-9][0-9]{0,4}$`)
	allowedOperations  = []string{"artifact", "cache", "copy", "image", "run", "secret", "source", "static_site"}
	allowedNetworks    = []string{"none", "packages", "allowlist", "private"}
	allowedOutputKinds = []string{"oci_image", "static_bundle", "artifact"}
)

type IR struct {
	Version         int      `json:"ir_version"`
	CompilerVersion string   `json:"compiler_version"`
	SourceSnapshot  string   `json:"source_snapshot"`
	TargetPlatform  string   `json:"target_platform"`
	NetworkProfile  string   `json:"network_profile"`
	AllowedHosts    []string `json:"allowed_hosts,omitempty"`
	Nodes           []Node   `json:"nodes"`
	Outputs         []Output `json:"outputs"`
}

type Node struct {
	ID         string         `json:"id"`
	Operation  string         `json:"op"`
	Inputs     []string       `json:"inputs"`
	Attributes map[string]any `json:"attributes"`
}

type Output struct {
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	State      string   `json:"state"`
	Entrypoint []string `json:"entrypoint"`
	Command    []string `json:"command"`
	Ports      []int    `json:"ports"`
}

func (ir IR) Validate() error {
	if ir.Version != CurrentVersion {
		return invalidf("unsupported ir_version %d", ir.Version)
	}
	if ir.CompilerVersion == "" {
		return invalidf("compiler_version is required")
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
	if ir.NetworkProfile != "allowlist" && len(ir.AllowedHosts) > 0 {
		return invalidf("allowed_hosts require the allowlist network profile")
	}
	if len(ir.Nodes) == 0 || len(ir.Nodes) > MaxNodes {
		return invalidf("node count must be between 1 and %d", MaxNodes)
	}
	if len(ir.Outputs) == 0 || len(ir.Outputs) > MaxOutputs {
		return invalidf("output count must be between 1 and %d", MaxOutputs)
	}

	seen := make(map[string]struct{}, len(ir.Nodes))
	for index, node := range ir.Nodes {
		if !nodeIDPattern.MatchString(node.ID) {
			return invalidf("nodes[%d].id %q is invalid", index, node.ID)
		}
		if _, exists := seen[node.ID]; exists {
			return invalidf("duplicate node id %q", node.ID)
		}
		if !slices.Contains(allowedOperations, node.Operation) {
			return invalidf("node %s has unsupported operation %q", node.ID, node.Operation)
		}
		for _, input := range node.Inputs {
			if _, exists := seen[input]; !exists {
				return invalidf("node %s input %q must reference an earlier node", node.ID, input)
			}
		}
		if err := validateAttributes(node); err != nil {
			return err
		}
		if node.Operation == "run" {
			network, _ := node.Attributes["network"].(string)
			if networkRank(network) > networkRank(ir.NetworkProfile) {
				return invalidf("node %s requests network broader than build assignment", node.ID)
			}
		}
		seen[node.ID] = struct{}{}
	}

	outputNames := make(map[string]struct{}, len(ir.Outputs))
	for index, output := range ir.Outputs {
		if output.Name == "" || len(output.Name) > 63 {
			return invalidf("outputs[%d].name is invalid", index)
		}
		if _, exists := outputNames[output.Name]; exists {
			return invalidf("duplicate output name %q", output.Name)
		}
		if !slices.Contains(allowedOutputKinds, output.Kind) {
			return invalidf("output %s has unsupported kind %q", output.Name, output.Kind)
		}
		if _, exists := seen[output.State]; !exists {
			return invalidf("output %s references unknown state %q", output.Name, output.State)
		}
		for _, port := range output.Ports {
			if port < 1 || port > 65535 {
				return invalidf("output %s has invalid port %d", output.Name, port)
			}
		}
		outputNames[output.Name] = struct{}{}
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

func validateAttributes(node Node) error {
	for key, value := range node.Attributes {
		if key == "" || len(key) > 64 {
			return invalidf("node %s has invalid attribute name", node.ID)
		}
		if err := validateAttributeValue(value); err != nil {
			return invalidf("node %s attribute %s: %v", node.ID, key, err)
		}
	}
	switch node.Operation {
	case "source":
		value, ok := node.Attributes["path"].(string)
		if !ok || !safeRelativePath(value) {
			return invalidf("source node %s requires a safe relative path", node.ID)
		}
	case "image":
		value, ok := node.Attributes["digest"].(string)
		if !ok || !digestPattern.MatchString(value) {
			return invalidf("image node %s requires an immutable digest", node.ID)
		}
	case "run":
		argv, ok := stringSlice(node.Attributes["argv"])
		if !ok || len(argv) == 0 {
			return invalidf("run node %s requires a non-empty argv array", node.ID)
		}
		network, ok := node.Attributes["network"].(string)
		if !ok || !slices.Contains(allowedNetworks, network) {
			return invalidf("run node %s has invalid network profile", node.ID)
		}
	case "copy":
		destination, ok := node.Attributes["destination"].(string)
		if !ok || !strings.HasPrefix(destination, "/") || strings.Contains(destination, "..") {
			return invalidf("copy node %s has unsafe destination", node.ID)
		}
	case "secret":
		if _, exists := node.Attributes["value"]; exists {
			return invalidf("secret node %s cannot contain a secret value", node.ID)
		}
		identifier, ok := node.Attributes["id"].(string)
		if !ok || identifier == "" {
			return invalidf("secret node %s requires a logical id", node.ID)
		}
		target, ok := node.Attributes["target"].(string)
		if !ok || !strings.HasPrefix(target, "/run/secrets/") || strings.Contains(target, "..") {
			return invalidf("secret node %s requires a safe /run/secrets target", node.ID)
		}
	case "cache":
		target, ok := node.Attributes["target"].(string)
		if !ok || !strings.HasPrefix(target, "/") || strings.Contains(target, "..") {
			return invalidf("cache node %s requires a safe absolute target", node.ID)
		}
		scope, ok := node.Attributes["scope"].(string)
		if !ok || !slices.Contains([]string{"build", "project", "org"}, scope) {
			return invalidf("cache node %s has an invalid scope", node.ID)
		}
	}
	return nil
}

func networkRank(network string) int {
	return slices.Index(allowedNetworks, network)
}

func validateAttributeValue(value any) error {
	switch typed := value.(type) {
	case string, bool, int, int32, int64, uint, uint32, uint64, json.Number:
		return nil
	case []string:
		return nil
	case []any:
		for _, item := range typed {
			if _, ok := item.(string); !ok {
				return errors.New("arrays may contain strings only")
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported value type %T", value)
	}
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

func safeRelativePath(value string) bool {
	if value == "." {
		return true
	}
	return value != "" && !strings.HasPrefix(value, "/") && !strings.Contains(value, "\\") && path.Clean(value) == value && value != ".." && !strings.HasPrefix(value, "../")
}

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
