package llbcompiler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildir"
)

const maxPolicyValues = 128

var (
	semanticVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	digestPattern          = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	registryPattern        = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?(?::[1-9][0-9]{0,4})?$`)
	capabilityPattern      = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
	buildArgumentPattern   = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
	suspiciousArgument     = regexp.MustCompile(`(?:AUTH|CREDENTIAL|PASSWORD|PRIVATE_KEY|SECRET|TOKEN)`)
)

type normalizedRequest struct {
	organizationID string
	projectID      string
	ir             buildir.IR
	irDigest       string
	policy         Policy
	policyDigest   string
	materials      []BaseMaterial
	buildArguments []NameValue
}

func newCompiler(version string) (*Compiler, error) {
	if !semanticVersionPattern.MatchString(version) {
		return nil, fail("llb.compiler_version", "LLB compiler version must be pinned semantic version text.", "")
	}
	return &Compiler{version: version}, nil
}

func normalizeRequest(request Request) (normalizedRequest, error) {
	if err := validateResourceID(request.OrganizationID, "org"); err != nil {
		return normalizedRequest{}, err
	}
	if err := validateResourceID(request.ProjectID, "prj"); err != nil {
		return normalizedRequest{}, err
	}
	irDigest, err := buildir.DefinitionDigest(request.IR)
	if err != nil {
		return normalizedRequest{}, fail("llb.ir_invalid", "Build IR does not satisfy the v2 typed contract.", "")
	}
	if request.ExpectedIRDigest != irDigest {
		return normalizedRequest{}, fail("llb.ir_digest", "Build IR does not match its expected immutable digest.", "")
	}
	policy, err := normalizePolicy(request.Policy)
	if err != nil {
		return normalizedRequest{}, err
	}
	policyDigest, err := digestValue(policy)
	if err != nil {
		return normalizedRequest{}, fail("llb.policy_digest", "Build policy could not be canonicalized.", "")
	}
	materials, err := normalizeMaterials(request.IR, request.BaseMaterials, policy)
	if err != nil {
		return normalizedRequest{}, err
	}
	arguments, err := normalizeBuildArguments(request.BuildArguments, policy.BuildArguments)
	if err != nil {
		return normalizedRequest{}, err
	}
	return normalizedRequest{
		organizationID: request.OrganizationID,
		projectID:      request.ProjectID,
		ir:             request.IR,
		irDigest:       irDigest,
		policy:         policy,
		policyDigest:   policyDigest,
		materials:      materials,
		buildArguments: arguments,
	}, nil
}

func normalizePolicy(policy Policy) (Policy, error) {
	if policy.APIVersion != CurrentPolicyAPIVersion || !semanticVersionPattern.MatchString(policy.Revision) {
		return Policy{}, fail("llb.policy_version", "Build policy API version or revision is unsupported.", "")
	}
	if err := validateResourceID(policy.ID, "pol"); err != nil {
		return Policy{}, err
	}
	policy.Base.AllowedRegistries = sortedUnique(policy.Base.AllowedRegistries)
	policy.Base.CuratedDigests = sortedUnique(policy.Base.CuratedDigests)
	policy.Base.AllowedSignatureIdentities = sortedUnique(policy.Base.AllowedSignatureIdentities)
	policy.Network.AllowedProfiles = sortedUnique(policy.Network.AllowedProfiles)
	policy.Network.PackageHosts = sortedUnique(policy.Network.PackageHosts)
	policy.Network.ExternalHosts = sortedUnique(policy.Network.ExternalHosts)
	policy.Secrets.AllowedNames = sortedUnique(policy.Secrets.AllowedNames)
	policy.BuildArguments.AllowedNames = sortedUnique(policy.BuildArguments.AllowedNames)
	policy.SupplyChain.AllowedSignerPublicKeyDigests = sortedUnique(policy.SupplyChain.AllowedSignerPublicKeyDigests)
	policy.SupplyChain.DeniedVulnerabilitySeverities = sortedUnique(policy.SupplyChain.DeniedVulnerabilitySeverities)
	policy.SupplyChain.DeniedConfigurationSeverities = sortedUnique(policy.SupplyChain.DeniedConfigurationSeverities)
	policy.SupplyChain.DeniedLicenseClassifications = sortedUnique(policy.SupplyChain.DeniedLicenseClassifications)

	if len(policy.Base.AllowedRegistries) == 0 || len(policy.Base.AllowedRegistries) > maxPolicyValues {
		return Policy{}, fail("llb.policy_base", "Base policy requires a bounded registry allowlist.", "")
	}
	for _, registry := range policy.Base.AllowedRegistries {
		if !registryPattern.MatchString(registry) {
			return Policy{}, fail("llb.policy_base", "Base policy contains an invalid registry.", "")
		}
	}
	if len(policy.Base.CuratedDigests) > maxPolicyValues || !allDigests(policy.Base.CuratedDigests) {
		return Policy{}, fail("llb.policy_base", "Curated base digests are invalid or outside limits.", "")
	}
	if len(policy.Base.AllowedSignatureIdentities) == 0 || len(policy.Base.AllowedSignatureIdentities) > maxPolicyValues || !allBounded(policy.Base.AllowedSignatureIdentities) {
		return Policy{}, fail("llb.policy_base", "Base signature identities are invalid or outside limits.", "")
	}
	if len(policy.Network.AllowedProfiles) == 0 || len(policy.Network.AllowedProfiles) > 4 {
		return Policy{}, fail("llb.policy_network", "Network policy requires bounded allowed profiles.", "")
	}
	for _, profile := range policy.Network.AllowedProfiles {
		if !slices.Contains([]string{"allowlist", "none", "packages", "private"}, profile) {
			return Policy{}, fail("llb.policy_network", "Network policy contains an unsupported profile.", "")
		}
	}
	if err := validateHosts(policy.Network.PackageHosts); err != nil {
		return Policy{}, err
	}
	if err := validateHosts(policy.Network.ExternalHosts); err != nil {
		return Policy{}, err
	}
	if slices.Contains(policy.Network.AllowedProfiles, "packages") && (len(policy.Network.PackageHosts) == 0 || !validCapabilityID(policy.Network.PackageGatewayID)) {
		return Policy{}, fail("llb.policy_network", "Packages network policy requires owned hosts and a gateway capability.", "")
	}
	if slices.Contains(policy.Network.AllowedProfiles, "allowlist") && !validCapabilityID(policy.Network.AllowlistGatewayID) {
		return Policy{}, fail("llb.policy_network", "Allowlist network policy requires a gateway capability.", "")
	}
	if slices.Contains(policy.Network.AllowedProfiles, "private") && !validCapabilityID(policy.Network.PrivateGatewayID) {
		return Policy{}, fail("llb.policy_network", "Private network policy requires an isolated gateway capability.", "")
	}
	if !slices.Contains([]string{"organization", "project"}, policy.Cache.Scope) || !validCapabilityID(policy.Cache.TrustDomain) {
		return Policy{}, fail("llb.policy_cache", "Cache scope or trust domain is invalid.", "")
	}
	if policy.Cache.AllowSharedWithSecrets && !policy.Cache.AllowShared {
		return Policy{}, fail("llb.policy_cache", "Secret-aware shared cache requires shared cache to be enabled.", "")
	}
	if len(policy.Secrets.AllowedNames) > maxPolicyValues || !allCapabilities(policy.Secrets.AllowedNames) {
		return Policy{}, fail("llb.policy_secret", "Secret policy names are invalid or outside limits.", "")
	}
	if len(policy.BuildArguments.AllowedNames) > maxPolicyValues {
		return Policy{}, fail("llb.policy_argument", "Build argument policy is outside limits.", "")
	}
	for _, name := range policy.BuildArguments.AllowedNames {
		if !buildArgumentPattern.MatchString(name) || suspiciousArgument.MatchString(name) {
			return Policy{}, fail("llb.policy_argument", "Build argument policy contains a secret-like or invalid name.", "")
		}
	}
	if err := ValidateSupplyChainPolicy(policy.SupplyChain); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

func ValidateSupplyChainPolicy(policy SupplyChainPolicy) error {
	if policy.Version != CurrentSupplyChainPolicyVersion || !semanticVersionPattern.MatchString(policy.SyftVersion) ||
		!semanticVersionPattern.MatchString(policy.TrivyVersion) || !validCapabilityID(policy.SignerKeyID) ||
		len(policy.AllowedSignerPublicKeyDigests) == 0 || len(policy.AllowedSignerPublicKeyDigests) > 8 || !allDigests(policy.AllowedSignerPublicKeyDigests) ||
		!sortedDistinct(policy.AllowedSignerPublicKeyDigests) || !policy.RequireSecretFree || !policy.RequireImageConfigurationScan {
		return fail("llb.policy_supply_chain", "Supply-chain evidence policy is incomplete or outside platform minimums.", "")
	}
	if len(policy.DeniedVulnerabilitySeverities) == 0 || len(policy.DeniedVulnerabilitySeverities) > 5 ||
		!sortedDistinct(policy.DeniedVulnerabilitySeverities) || !slices.Contains(policy.DeniedVulnerabilitySeverities, "CRITICAL") {
		return fail("llb.policy_supply_chain", "Supply-chain vulnerability policy must deny critical findings.", "")
	}
	for _, severity := range policy.DeniedVulnerabilitySeverities {
		if !slices.Contains([]string{"CRITICAL", "HIGH", "LOW", "MEDIUM", "UNKNOWN"}, severity) {
			return fail("llb.policy_supply_chain", "Supply-chain vulnerability policy contains an unsupported severity.", "")
		}
	}
	if len(policy.DeniedConfigurationSeverities) == 0 || len(policy.DeniedConfigurationSeverities) > 5 ||
		!sortedDistinct(policy.DeniedConfigurationSeverities) || !slices.Contains(policy.DeniedConfigurationSeverities, "CRITICAL") {
		return fail("llb.policy_supply_chain", "Supply-chain configuration policy must deny critical findings.", "")
	}
	for _, severity := range policy.DeniedConfigurationSeverities {
		if !slices.Contains([]string{"CRITICAL", "HIGH", "LOW", "MEDIUM", "UNKNOWN"}, severity) {
			return fail("llb.policy_supply_chain", "Supply-chain configuration policy contains an unsupported severity.", "")
		}
	}
	if len(policy.DeniedLicenseClassifications) == 0 || len(policy.DeniedLicenseClassifications) > 7 ||
		!sortedDistinct(policy.DeniedLicenseClassifications) || !slices.Contains(policy.DeniedLicenseClassifications, "Forbidden") {
		return fail("llb.policy_supply_chain", "Supply-chain license policy must deny forbidden licenses.", "")
	}
	for _, classification := range policy.DeniedLicenseClassifications {
		if !slices.Contains([]string{"Forbidden", "Notice", "Permissive", "Reciprocal", "Restricted", "Unencumbered", "Unknown"}, classification) {
			return fail("llb.policy_supply_chain", "Supply-chain license policy contains an unsupported classification.", "")
		}
	}
	return nil
}

func sortedDistinct(values []string) bool {
	return slices.IsSorted(values) && len(slices.Compact(append([]string(nil), values...))) == len(values)
}

func normalizeMaterials(ir buildir.IR, materials []BaseMaterial, policy Policy) ([]BaseMaterial, error) {
	expected := make(map[string]string)
	for _, node := range ir.Nodes {
		if node.Operation != "image" {
			continue
		}
		reference, _ := node.Attributes["ref"].(string)
		expected[reference] = node.ID
	}
	if len(materials) != len(expected) {
		return nil, fail("llb.material_set", "Base material lock must contain exactly one entry per image node.", "")
	}
	result := append([]BaseMaterial(nil), materials...)
	for index := range result {
		material := &result[index]
		nodeID, exists := expected[material.RequestedRef]
		if !exists {
			return nil, fail("llb.material_extra", "Base material does not correspond to an image node.", "")
		}
		delete(expected, material.RequestedRef)
		if !digestPattern.MatchString(material.Digest) || !strings.HasSuffix(material.RequestedRef, "@"+material.Digest) || !strings.HasSuffix(material.ResolvedRef, "@"+material.Digest) {
			return nil, fail("llb.material_digest", "Base material references do not agree on one immutable digest.", nodeID)
		}
		registry := registryFromReference(material.ResolvedRef)
		if material.Registry != registry || !slices.Contains(policy.Base.AllowedRegistries, registry) {
			return nil, fail("llb.material_registry", "Base material registry is not allowed by policy.", nodeID)
		}
		material.Platforms = sortedUnique(material.Platforms)
		if !slices.Contains(material.Platforms, ir.TargetPlatform) {
			return nil, fail("llb.material_platform", "Base material does not contain the requested target platform.", nodeID)
		}
		switch material.Classification {
		case "curated":
			if !slices.Contains(policy.Base.CuratedDigests, material.Digest) {
				return nil, fail("llb.material_curated", "Curated base digest is absent from the policy catalog.", nodeID)
			}
		case "customer":
			if !policy.Base.AllowCustomerBases {
				return nil, fail("llb.material_customer", "Customer base images are disabled by policy.", nodeID)
			}
		default:
			return nil, fail("llb.material_classification", "Base material classification is invalid.", nodeID)
		}
		if !slices.Contains(policy.Base.AllowedSignatureIdentities, material.SignatureIdentity) {
			return nil, fail("llb.material_signature", "Base material signature identity is not allowed by policy.", nodeID)
		}
		if policy.Base.RequireSBOM && !digestPattern.MatchString(material.SBOMDigest) {
			return nil, fail("llb.material_sbom", "Base material lacks required SBOM evidence.", nodeID)
		}
		if policy.Base.RequireProvenance && !digestPattern.MatchString(material.ProvenanceDigest) {
			return nil, fail("llb.material_provenance", "Base material lacks required provenance evidence.", nodeID)
		}
		expectedResolution, resolutionErr := materialResolutionDigest(*material)
		if resolutionErr != nil || material.ResolutionDigest != expectedResolution {
			return nil, fail("llb.material_resolution", "Base material lacks immutable resolution evidence.", nodeID)
		}
	}
	if len(expected) != 0 {
		return nil, fail("llb.material_missing", "Base material lock is incomplete.", "")
	}
	slices.SortFunc(result, func(left, right BaseMaterial) int {
		return strings.Compare(left.RequestedRef, right.RequestedRef)
	})
	for index := 1; index < len(result); index++ {
		if result[index-1].RequestedRef == result[index].RequestedRef {
			return nil, fail("llb.material_duplicate", "Base material lock contains duplicate references.", "")
		}
	}
	return result, nil
}

func materialResolutionDigest(material BaseMaterial) (string, error) {
	return digestValue(struct {
		Version           int      `json:"version"`
		RequestedRef      string   `json:"requested_ref"`
		ResolvedRef       string   `json:"resolved_ref"`
		Digest            string   `json:"digest"`
		Registry          string   `json:"registry"`
		Classification    string   `json:"classification"`
		Platforms         []string `json:"platforms"`
		SBOMDigest        string   `json:"sbom_digest,omitempty"`
		ProvenanceDigest  string   `json:"provenance_digest,omitempty"`
		SignatureIdentity string   `json:"signature_identity"`
	}{
		Version:           1,
		RequestedRef:      material.RequestedRef,
		ResolvedRef:       material.ResolvedRef,
		Digest:            material.Digest,
		Registry:          material.Registry,
		Classification:    material.Classification,
		Platforms:         append([]string(nil), material.Platforms...),
		SBOMDigest:        material.SBOMDigest,
		ProvenanceDigest:  material.ProvenanceDigest,
		SignatureIdentity: material.SignatureIdentity,
	})
}

func normalizeBuildArguments(arguments map[string]string, policy BuildArgumentPolicy) ([]NameValue, error) {
	if len(arguments) > 64 {
		return nil, fail("llb.argument_limit", "Build argument count exceeds the platform limit.", "")
	}
	result := make([]NameValue, 0, len(arguments))
	for name, value := range arguments {
		if !buildArgumentPattern.MatchString(name) || suspiciousArgument.MatchString(name) || !slices.Contains(policy.AllowedNames, name) {
			return nil, fail("llb.argument_denied", "Build argument name is secret-like, invalid, or denied by policy.", "")
		}
		if !boundedText(value, true) {
			return nil, fail("llb.argument_value", "Build argument value is outside safe text limits.", "")
		}
		result = append(result, NameValue{Name: name, Value: value})
	}
	slices.SortFunc(result, func(left, right NameValue) int {
		return strings.Compare(left.Name, right.Name)
	})
	return result, nil
}

func validateResourceID(value, prefix string) error {
	parsed, err := platformid.Parse(value)
	if err != nil || parsed.Prefix() != prefix {
		return fail("llb.scope", "Build request contains an invalid immutable scope identifier.", "")
	}
	return nil
}

func validateHosts(hosts []string) error {
	if len(hosts) > maxPolicyValues {
		return fail("llb.policy_network", "Network host policy exceeds the platform limit.", "")
	}
	for _, host := range hosts {
		if !registryPattern.MatchString(host) || strings.Contains(host, ":") {
			return fail("llb.policy_network", "Network policy contains an invalid hostname.", "")
		}
	}
	return nil
}

func registryFromReference(reference string) string {
	name, _, _ := strings.Cut(reference, "@")
	component, _, hasSlash := strings.Cut(name, "/")
	if hasSlash && (strings.Contains(component, ".") || strings.Contains(component, ":") || component == "localhost") {
		return component
	}
	return "docker.io"
}

func digestValue(value any) (string, error) {
	canonical, err := canonicaljson.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("canonicalize digest input: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func sortedUnique(values []string) []string {
	result := append([]string(nil), values...)
	slices.Sort(result)
	return slices.Compact(result)
}

func allDigests(values []string) bool {
	for _, value := range values {
		if !digestPattern.MatchString(value) {
			return false
		}
	}
	return true
}

func allBounded(values []string) bool {
	for _, value := range values {
		if !boundedText(value, false) {
			return false
		}
	}
	return true
}

func allCapabilities(values []string) bool {
	for _, value := range values {
		if !capabilityPattern.MatchString(value) {
			return false
		}
	}
	return true
}

func validCapabilityID(value string) bool {
	return capabilityPattern.MatchString(value)
}

func boundedText(value string, allowEmpty bool) bool {
	return (allowEmpty || value != "") && len(value) <= buildir.MaxStringBytes && utf8.ValidString(value) && !strings.ContainsRune(value, '\x00')
}
