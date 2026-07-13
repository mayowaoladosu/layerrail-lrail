package llbcompiler

import (
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildir"
)

type capabilitySet struct {
	networkByNode map[string]NetworkCapability
	cacheByNode   map[string]CacheCapability
	secretByNode  map[string]SecretCapability
	network       []NetworkCapability
	caches        []CacheCapability
	secrets       []SecretCapability
}

func compileCapabilities(input normalizedRequest) (capabilitySet, error) {
	result := capabilitySet{
		networkByNode: make(map[string]NetworkCapability),
		cacheByNode:   make(map[string]CacheCapability),
		secretByNode:  make(map[string]SecretCapability),
		network:       []NetworkCapability{},
		caches:        []CacheCapability{},
		secrets:       []SecretCapability{},
	}
	if !slices.Contains(input.policy.Network.AllowedProfiles, input.ir.NetworkProfile) {
		return capabilitySet{}, fail("llb.network_denied", "Build-wide network profile is denied by policy.", "")
	}
	for _, node := range input.ir.Nodes {
		switch node.Operation {
		case "cache":
			capability, err := cacheCapability(input, node)
			if err != nil {
				return capabilitySet{}, err
			}
			result.cacheByNode[node.ID] = capability
			result.caches = append(result.caches, capability)
		case "secret":
			capability, err := secretCapability(input, node)
			if err != nil {
				return capabilitySet{}, err
			}
			result.secretByNode[node.ID] = capability
			result.secrets = append(result.secrets, capability)
		case "run":
			profile, _ := node.Attributes["network"].(string)
			capability, err := networkCapability(input, node.ID, profile)
			if err != nil {
				return capabilitySet{}, err
			}
			result.networkByNode[node.ID] = capability
			result.network = append(result.network, capability)
		}
	}
	if err := rejectSecretReferences(input, result); err != nil {
		return capabilitySet{}, err
	}
	return result, nil
}

func rejectSecretReferences(input normalizedRequest, capabilities capabilitySet) error {
	secretIdentifiers := make(map[string]struct{}, len(capabilities.secrets)*2)
	for _, secret := range capabilities.secrets {
		secretIdentifiers[secret.Name] = struct{}{}
		secretIdentifiers[secret.MountID] = struct{}{}
	}
	for _, argument := range input.buildArguments {
		if _, exists := secretIdentifiers[argument.Value]; exists {
			return fail("llb.secret_reference", "Build argument may not contain a secret capability identifier.", "")
		}
	}
	for _, node := range input.ir.Nodes {
		if node.Operation != "run" {
			continue
		}
		arguments, _ := stringSlice(node.Attributes["argv"])
		for _, argument := range arguments {
			if _, exists := secretIdentifiers[argument]; exists {
				return fail("llb.secret_reference", "Run argv may not contain a secret capability identifier.", node.ID)
			}
		}
		environment, _ := stringMap(node.Attributes["env"])
		for _, value := range environment {
			if _, exists := secretIdentifiers[value]; exists {
				return fail("llb.secret_reference", "Run environment may not contain a secret capability identifier.", node.ID)
			}
		}
	}
	return nil
}

func networkCapability(input normalizedRequest, nodeID, profile string) (NetworkCapability, error) {
	if !slices.Contains(input.policy.Network.AllowedProfiles, profile) {
		return NetworkCapability{}, fail("llb.network_denied", "Run network profile is denied by policy.", nodeID)
	}
	capability := NetworkCapability{NodeID: nodeID, Profile: profile, Hosts: []string{}}
	switch profile {
	case "none":
	case "packages":
		capability.Hosts = append([]string(nil), input.policy.Network.PackageHosts...)
		capability.GatewayID = input.policy.Network.PackageGatewayID
	case "allowlist":
		for _, host := range input.ir.AllowedHosts {
			if !slices.Contains(input.policy.Network.ExternalHosts, host) {
				return NetworkCapability{}, fail("llb.network_host", "Build host allowlist exceeds organization policy.", nodeID)
			}
		}
		capability.Hosts = append([]string(nil), input.ir.AllowedHosts...)
		capability.GatewayID = input.policy.Network.AllowlistGatewayID
	case "private":
		capability.GatewayID = input.policy.Network.PrivateGatewayID
	default:
		return NetworkCapability{}, fail("llb.network_profile", "Run network profile is unsupported.", nodeID)
	}
	return capability, nil
}

func cacheCapability(input normalizedRequest, node buildir.Node) (CacheCapability, error) {
	name, _ := node.Attributes["name"].(string)
	target, _ := node.Attributes["target"].(string)
	sharing, _ := node.Attributes["sharing"].(string)
	if sharing == "shared" && !input.policy.Cache.AllowShared {
		return CacheCapability{}, fail("llb.cache_shared", "Shared caches are denied by policy.", node.ID)
	}
	scopeID := input.projectID
	if input.policy.Cache.Scope == "organization" {
		scopeID = input.organizationID
	}
	namespace, err := digestValue(struct {
		Version      int    `json:"version"`
		NodeID       string `json:"node_id"`
		Scope        string `json:"scope"`
		ScopeID      string `json:"scope_id"`
		TrustDomain  string `json:"trust_domain"`
		PolicyDigest string `json:"policy_digest"`
		Name         string `json:"name"`
		Target       string `json:"target"`
	}{
		Version:      1,
		NodeID:       node.ID,
		Scope:        input.policy.Cache.Scope,
		ScopeID:      scopeID,
		TrustDomain:  input.policy.Cache.TrustDomain,
		PolicyDigest: input.policyDigest,
		Name:         name,
		Target:       target,
	})
	if err != nil {
		return CacheCapability{}, fail("llb.cache_namespace", "Cache namespace could not be canonicalized.", node.ID)
	}
	return CacheCapability{
		NodeID:    node.ID,
		Name:      name,
		Target:    target,
		Sharing:   sharing,
		Scope:     input.policy.Cache.Scope,
		Namespace: "lrail-cache-" + strings.TrimPrefix(namespace, "sha256:"),
	}, nil
}

func secretCapability(input normalizedRequest, node buildir.Node) (SecretCapability, error) {
	name, _ := node.Attributes["name"].(string)
	target, _ := node.Attributes["target"].(string)
	required, _ := node.Attributes["required"].(bool)
	if !slices.Contains(input.policy.Secrets.AllowedNames, name) {
		return SecretCapability{}, fail("llb.secret_denied", "Secret capability is denied by policy.", node.ID)
	}
	return SecretCapability{
		NodeID:   node.ID,
		Name:     name,
		Target:   target,
		Required: required,
		MountID:  name,
	}, nil
}

func validateRunMounts(node buildir.Node, capabilities capabilitySet, policy CachePolicy) error {
	mountIDs, ok := stringSlice(node.Attributes["mounts"])
	if !ok {
		return fail("llb.mount_shape", "Run mount references are invalid.", node.ID)
	}
	targets := make([]string, 0, len(mountIDs))
	hasSecret := false
	hasShared := false
	for _, mountID := range mountIDs {
		if cache, exists := capabilities.cacheByNode[mountID]; exists {
			targets = append(targets, cache.Target)
			hasShared = hasShared || cache.Sharing == "shared"
			continue
		}
		if secret, exists := capabilities.secretByNode[mountID]; exists {
			targets = append(targets, secret.Target)
			hasSecret = true
			continue
		}
		return fail("llb.mount_unknown", "Run references an unknown cache or secret capability.", node.ID)
	}
	for left := range targets {
		for right := left + 1; right < len(targets); right++ {
			if pathsOverlap(targets[left], targets[right]) {
				return fail("llb.mount_overlap", "Run mount targets overlap.", node.ID)
			}
		}
	}
	if hasSecret && hasShared && !policy.AllowSharedWithSecrets {
		return fail("llb.cache_secret", "Secret-mounted runs cannot write shared cache under current policy.", node.ID)
	}
	return nil
}

func pathsOverlap(left, right string) bool {
	left = path.Clean(left)
	right = path.Clean(right)
	return left == right || strings.HasPrefix(left, right+"/") || strings.HasPrefix(right, left+"/")
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

func parseOwner(value string) (int, int, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid owner")
	}
	uid, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid uid")
	}
	gid, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid gid")
	}
	return uid, gid, nil
}
