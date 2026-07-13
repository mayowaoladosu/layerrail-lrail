package llbcompiler

import (
	"errors"
	"fmt"
	"strings"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildir"
	"github.com/moby/buildkit/solver/pb"
	"github.com/opencontainers/go-digest"
	"google.golang.org/protobuf/proto"
)

// AuditDefinitions proves that untrusted serialized LLB does not exceed the
// source, base-image, network, cache, or secret authority in its signed lock.
func AuditDefinitions(definitions [][]byte, lock DefinitionLock) error {
	if len(definitions) == 0 || len(definitions) != len(lock.Outputs) {
		return errors.New("LLB definition set does not match the output lock")
	}
	auditor, err := newDefinitionAuditor(lock)
	if err != nil {
		return err
	}
	for _, definition := range definitions {
		if err := auditor.audit(definition); err != nil {
			return err
		}
	}
	return auditor.complete()
}

type definitionAuditor struct {
	lock              DefinitionLock
	materials         map[string]string
	networkNames      map[string]string
	secrets           map[string]SecretCapability
	caches            map[string]CacheCapability
	expectedMaterials map[string]struct{}
	expectedNetwork   map[string]struct{}
	expectedSecrets   map[string]struct{}
	expectedCaches    map[string]struct{}
	observedMaterials map[string]struct{}
	observedNetwork   map[string]struct{}
	observedSecrets   map[string]struct{}
	observedCaches    map[string]struct{}
}

func newDefinitionAuditor(lock DefinitionLock) (*definitionAuditor, error) {
	auditor := &definitionAuditor{
		lock: lock, materials: make(map[string]string), networkNames: make(map[string]string),
		secrets: make(map[string]SecretCapability), caches: make(map[string]CacheCapability),
		expectedMaterials: make(map[string]struct{}), expectedNetwork: make(map[string]struct{}),
		expectedSecrets: make(map[string]struct{}), expectedCaches: make(map[string]struct{}),
		observedMaterials: make(map[string]struct{}), observedNetwork: make(map[string]struct{}),
		observedSecrets: make(map[string]struct{}), observedCaches: make(map[string]struct{}),
	}
	for _, material := range lock.BaseMaterials {
		identifier := "docker-image://" + material.ResolvedRef
		key := materialAuthority(material)
		if existing, duplicate := auditor.materials[identifier]; duplicate && existing != key {
			return nil, errors.New("LLB base material authority is ambiguous")
		}
		auditor.materials[identifier] = key
		auditor.expectedMaterials[key] = struct{}{}
	}
	for _, network := range lock.Network {
		key, err := networkAuthority(network)
		if err != nil {
			return nil, errors.New("LLB network authority cannot be canonicalized")
		}
		name := "lrail run " + network.NodeID + " network=" + network.Profile + " gateway=" + network.GatewayID + " hosts=" + strings.Join(network.Hosts, ",")
		if _, duplicate := auditor.networkNames[name]; duplicate {
			return nil, errors.New("LLB network vertex identity is duplicated")
		}
		auditor.networkNames[name] = key
		auditor.expectedNetwork[key] = struct{}{}
	}
	for _, secret := range lock.Secrets {
		key, err := secretAuthority(secret)
		if err != nil {
			return nil, errors.New("LLB secret authority cannot be canonicalized")
		}
		if _, duplicate := auditor.secrets[secret.MountID]; duplicate {
			return nil, errors.New("LLB secret identity is duplicated")
		}
		auditor.secrets[secret.MountID] = secret
		auditor.expectedSecrets[key] = struct{}{}
	}
	for _, cache := range lock.Caches {
		key, err := cacheAuthority(cache)
		if err != nil {
			return nil, errors.New("LLB cache authority cannot be canonicalized")
		}
		if _, duplicate := auditor.caches[cache.Namespace]; duplicate {
			return nil, errors.New("LLB cache identity is duplicated")
		}
		auditor.caches[cache.Namespace] = cache
		auditor.expectedCaches[key] = struct{}{}
	}
	return auditor, nil
}

func (auditor *definitionAuditor) audit(contents []byte) error {
	var definition pb.Definition
	if err := proto.Unmarshal(contents, &definition); err != nil || len(definition.Def) == 0 || len(definition.Def) > buildir.MaxNodes+1 {
		return errors.New("LLB definition is malformed or exceeds graph limits")
	}
	operations := make(map[string]*pb.Op, len(definition.Def))
	outputDigest := ""
	for _, raw := range definition.Def {
		var operation pb.Op
		if err := proto.Unmarshal(raw, &operation); err != nil {
			return errors.New("LLB operation is malformed")
		}
		operationDigest := digest.FromBytes(raw).String()
		if _, duplicate := operations[operationDigest]; duplicate {
			return errors.New("LLB definition contains a duplicate operation")
		}
		operations[operationDigest] = &operation
		if operation.Op == nil {
			if outputDigest != "" || len(operation.Inputs) != 1 {
				return errors.New("LLB definition must contain exactly one output vertex")
			}
			outputDigest = operationDigest
		}
	}
	if outputDigest == "" || !completeLLBGraph(operations, outputDigest) {
		return errors.New("LLB definition is disconnected, cyclic, or has a missing input")
	}
	for _, raw := range definition.Def {
		operationDigest := digest.FromBytes(raw).String()
		operation := operations[operationDigest]
		if err := auditor.auditPlatform(operation.Platform); err != nil {
			return err
		}
		if operation.Constraints != nil && len(operation.Constraints.Filter) != 0 {
			return errors.New("LLB operation carries unsupported worker constraints")
		}
		for _, input := range operation.Inputs {
			if input == nil || !strings.HasPrefix(input.Digest, "sha256:") {
				return errors.New("LLB operation input identity is invalid")
			}
		}
		metadata := definition.Metadata[operationDigest]
		switch typed := operation.Op.(type) {
		case *pb.Op_Source:
			if err := auditor.auditSource(typed.Source); err != nil {
				return err
			}
		case *pb.Op_Exec:
			if err := auditor.auditExec(typed.Exec, metadata); err != nil {
				return err
			}
		case *pb.Op_File, *pb.Op_Merge, *pb.Op_Diff:
		case nil:
		default:
			return errors.New("LLB contains an unsupported privileged operation")
		}
	}
	return nil
}

func completeLLBGraph(operations map[string]*pb.Op, outputDigest string) bool {
	visiting := make(map[string]bool, len(operations))
	visited := make(map[string]bool, len(operations))
	var visit func(string) bool
	visit = func(operationDigest string) bool {
		if visiting[operationDigest] {
			return false
		}
		if visited[operationDigest] {
			return true
		}
		operation, exists := operations[operationDigest]
		if !exists {
			return false
		}
		visiting[operationDigest] = true
		for _, input := range operation.Inputs {
			if input == nil || !visit(input.Digest) {
				return false
			}
		}
		delete(visiting, operationDigest)
		visited[operationDigest] = true
		return true
	}
	return visit(outputDigest) && len(visited) == len(operations)
}

func (auditor *definitionAuditor) auditPlatform(platform *pb.Platform) error {
	if platform == nil {
		return nil
	}
	if platform.OS+"/"+platform.Architecture != auditor.lock.TargetPlatform || platform.Variant != "" || platform.OSVersion != "" || len(platform.OSFeatures) != 0 {
		return errors.New("LLB operation platform exceeds the signed target")
	}
	return nil
}

func (auditor *definitionAuditor) auditSource(source *pb.SourceOp) error {
	if source == nil {
		return errors.New("LLB source operation is absent")
	}
	if source.Identifier == "local://lrail-source" {
		if source.Attrs[pb.AttrLocalUniqueID] != auditor.lock.SourceSnapshot || source.Attrs[pb.AttrSharedKeyHint] != auditor.lock.SourceSnapshot {
			return errors.New("LLB local source is not bound to the signed snapshot")
		}
		return nil
	}
	key, allowed := auditor.materials[source.Identifier]
	if !allowed || source.Attrs[pb.AttrImageResolveMode] != pb.AttrImageResolveModeForcePull {
		return errors.New("LLB source is not an exact signed base material")
	}
	auditor.observedMaterials[key] = struct{}{}
	return nil
}

func (auditor *definitionAuditor) auditExec(execution *pb.ExecOp, metadata *pb.OpMetadata) error {
	if execution == nil || execution.Security != pb.SecurityMode_SANDBOX || execution.Network == pb.NetMode_HOST || len(execution.Secretenv) != 0 || len(execution.CdiDevices) != 0 {
		return errors.New("LLB execution requests unsupported ambient authority")
	}
	if execution.Meta == nil {
		return errors.New("LLB execution metadata is absent")
	}
	if len(execution.Meta.ExtraHosts) != 0 {
		return errors.New("LLB execution metadata requests unsupported network authority")
	}
	if execution.Meta.CgroupParent != "" || execution.Meta.Hostname != "" || len(execution.Meta.Ulimit) != 0 || len(execution.Meta.ValidExitCodes) != 0 {
		return errors.New("LLB execution metadata requests unsupported process authority")
	}
	if metadata == nil || metadata.LinuxResources != nil {
		return errors.New("LLB execution metadata is absent or carries resource authority")
	}
	name := metadata.Description["llb.customname"]
	networkKey, allowed := auditor.networkNames[name]
	if !allowed {
		return errors.New("LLB execution is not bound to a signed network capability")
	}
	profile := networkProfileFromName(name)
	if (profile == "none" && execution.Network != pb.NetMode_NONE) || (profile != "none" && execution.Network != pb.NetMode_UNSET) {
		return errors.New("LLB execution network mode differs from its signed capability")
	}
	if profile == "none" {
		if execution.Meta.ProxyEnv != nil {
			return errors.New("Hermetic LLB execution carries proxy authority")
		}
	} else if execution.Meta.ProxyEnv == nil || execution.Meta.ProxyEnv.HttpProxy != BuildEgressProxyURL || execution.Meta.ProxyEnv.HttpsProxy != BuildEgressProxyURL ||
		execution.Meta.ProxyEnv.FtpProxy != "" || execution.Meta.ProxyEnv.NoProxy != "" || execution.Meta.ProxyEnv.AllProxy != "" {
		return errors.New("Networked LLB execution does not use the exact policy proxy")
	}
	auditor.observedNetwork[networkKey] = struct{}{}
	for _, mount := range execution.Mounts {
		if mount == nil {
			return errors.New("LLB execution contains an empty mount")
		}
		switch mount.MountType {
		case pb.MountType_BIND, pb.MountType_TMPFS:
		case pb.MountType_SECRET:
			if err := auditor.auditSecretMount(mount); err != nil {
				return err
			}
		case pb.MountType_CACHE:
			if err := auditor.auditCacheMount(mount); err != nil {
				return err
			}
		default:
			return errors.New("LLB execution contains an unsupported SSH or unknown mount")
		}
	}
	return nil
}

func (auditor *definitionAuditor) auditSecretMount(mount *pb.Mount) error {
	if mount.SecretOpt == nil {
		return errors.New("LLB secret mount lacks options")
	}
	secret, allowed := auditor.secrets[mount.SecretOpt.ID]
	if !allowed || mount.Dest != secret.Target || mount.SecretOpt.Mode != 0o400 || mount.SecretOpt.Optional == secret.Required {
		return errors.New("LLB secret mount differs from its signed capability")
	}
	key, _ := secretAuthority(secret)
	auditor.observedSecrets[key] = struct{}{}
	return nil
}

func (auditor *definitionAuditor) auditCacheMount(mount *pb.Mount) error {
	if mount.CacheOpt == nil {
		return errors.New("LLB cache mount lacks options")
	}
	cache, allowed := auditor.caches[mount.CacheOpt.ID]
	if !allowed || mount.Dest != cache.Target || mount.CacheOpt.Sharing != cacheSharingOption(cache.Sharing) {
		return errors.New("LLB cache mount differs from its signed capability")
	}
	key, _ := cacheAuthority(cache)
	auditor.observedCaches[key] = struct{}{}
	return nil
}

func (auditor *definitionAuditor) complete() error {
	for name, pair := range map[string][2]map[string]struct{}{
		"base material": {auditor.expectedMaterials, auditor.observedMaterials},
		"network":       {auditor.expectedNetwork, auditor.observedNetwork},
		"secret":        {auditor.expectedSecrets, auditor.observedSecrets},
		"cache":         {auditor.expectedCaches, auditor.observedCaches},
	} {
		if !equalStringSets(pair[0], pair[1]) {
			return fmt.Errorf("LLB %s capabilities do not exactly match the signed lock", name)
		}
	}
	return nil
}

func equalStringSets(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for key := range left {
		if _, exists := right[key]; !exists {
			return false
		}
	}
	return true
}

func materialAuthority(material BaseMaterial) string {
	return material.ResolvedRef + "\x00" + material.Digest
}

func networkAuthority(network NetworkCapability) (string, error) {
	return digestValue(struct {
		Profile   string   `json:"profile"`
		GatewayID string   `json:"gateway_id"`
		Hosts     []string `json:"hosts"`
	}{Profile: network.Profile, GatewayID: network.GatewayID, Hosts: network.Hosts})
}

func secretAuthority(secret SecretCapability) (string, error) {
	return digestValue(struct {
		MountID  string `json:"mount_id"`
		Target   string `json:"target"`
		Required bool   `json:"required"`
	}{MountID: secret.MountID, Target: secret.Target, Required: secret.Required})
}

func cacheAuthority(cache CacheCapability) (string, error) {
	return digestValue(struct {
		Namespace string `json:"namespace"`
		Target    string `json:"target"`
		Sharing   string `json:"sharing"`
	}{Namespace: cache.Namespace, Target: cache.Target, Sharing: cache.Sharing})
}

func cacheSharingOption(value string) pb.CacheSharingOpt {
	switch value {
	case "private":
		return pb.CacheSharingOpt_PRIVATE
	case "locked":
		return pb.CacheSharingOpt_LOCKED
	default:
		return pb.CacheSharingOpt_SHARED
	}
}

func networkProfileFromName(name string) string {
	const marker = " network="
	index := strings.Index(name, marker)
	if index < 0 {
		return ""
	}
	remaining, found := strings.CutPrefix(name[index:], marker)
	if !found {
		return ""
	}
	profile, _, _ := strings.Cut(remaining, " ")
	return profile
}
