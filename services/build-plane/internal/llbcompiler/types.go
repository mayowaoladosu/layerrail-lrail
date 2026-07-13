// Package llbcompiler validates Build IR policy and emits deterministic BuildKit LLB.
package llbcompiler

import (
	"context"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildir"
)

const (
	CurrentPolicyAPIVersion         = "lrail.build-policy/v1"
	CurrentLockVersion              = 2
	CurrentSupplyChainPolicyVersion = 1
	CurrentSyftVersion              = "1.46.0"
	CurrentTrivyVersion             = "0.72.0"
	DefaultBuildSignerKeyID         = "lrail-build-evidence"
	BuildEgressProxyURL             = "http://127.0.0.1:3128"
)

type Compiler struct {
	version string
}

type Request struct {
	OrganizationID   string
	ProjectID        string
	IR               buildir.IR
	ExpectedIRDigest string
	Policy           Policy
	BaseMaterials    []BaseMaterial
	BuildArguments   map[string]string
}

type Policy struct {
	APIVersion     string              `json:"api_version"`
	ID             string              `json:"id"`
	Revision       string              `json:"revision"`
	Base           BasePolicy          `json:"base"`
	Network        NetworkPolicy       `json:"network"`
	Cache          CachePolicy         `json:"cache"`
	Secrets        SecretPolicy        `json:"secrets"`
	BuildArguments BuildArgumentPolicy `json:"build_arguments"`
	SupplyChain    SupplyChainPolicy   `json:"supply_chain"`
}

type SupplyChainPolicy struct {
	Version                       int      `json:"version"`
	SyftVersion                   string   `json:"syft_version"`
	TrivyVersion                  string   `json:"trivy_version"`
	SignerKeyID                   string   `json:"signer_key_id"`
	AllowedSignerPublicKeyDigests []string `json:"allowed_signer_public_key_digests"`
	DeniedVulnerabilitySeverities []string `json:"denied_vulnerability_severities"`
	DeniedConfigurationSeverities []string `json:"denied_configuration_severities"`
	DeniedLicenseClassifications  []string `json:"denied_license_classifications"`
	RequireSecretFree             bool     `json:"require_secret_free"`
	RequireImageConfigurationScan bool     `json:"require_image_configuration_scan"`
}

type BasePolicy struct {
	AllowedRegistries          []string `json:"allowed_registries"`
	CuratedDigests             []string `json:"curated_digests"`
	AllowCustomerBases         bool     `json:"allow_customer_bases"`
	AllowedSignatureIdentities []string `json:"allowed_signature_identities"`
	RequireSBOM                bool     `json:"require_sbom"`
	RequireProvenance          bool     `json:"require_provenance"`
}

type NetworkPolicy struct {
	AllowedProfiles    []string `json:"allowed_profiles"`
	PackageHosts       []string `json:"package_hosts"`
	ExternalHosts      []string `json:"external_hosts"`
	PackageGatewayID   string   `json:"package_gateway_id,omitempty"`
	AllowlistGatewayID string   `json:"allowlist_gateway_id,omitempty"`
	PrivateGatewayID   string   `json:"private_gateway_id,omitempty"`
}

type CachePolicy struct {
	Scope                  string `json:"scope"`
	TrustDomain            string `json:"trust_domain"`
	AllowShared            bool   `json:"allow_shared"`
	AllowSharedWithSecrets bool   `json:"allow_shared_with_secrets"`
}

type SecretPolicy struct {
	AllowedNames []string `json:"allowed_names"`
}

type BuildArgumentPolicy struct {
	AllowedNames []string `json:"allowed_names"`
}

type BaseMaterial struct {
	RequestedRef      string   `json:"requested_ref"`
	ResolvedRef       string   `json:"resolved_ref"`
	Digest            string   `json:"digest"`
	Registry          string   `json:"registry"`
	Classification    string   `json:"classification"`
	Platforms         []string `json:"platforms"`
	SBOMDigest        string   `json:"sbom_digest,omitempty"`
	ProvenanceDigest  string   `json:"provenance_digest,omitempty"`
	SignatureIdentity string   `json:"signature_identity"`
	ResolutionDigest  string   `json:"resolution_digest"`
}

type Result struct {
	DefinitionDigest string
	IRDigest         string
	PolicyDigest     string
	Lock             DefinitionLock
	Outputs          []OutputDefinition
}

type OutputDefinition struct {
	Name          string
	Kind          string
	LLBDigest     string
	Head          string
	Definition    []byte
	ImageConfig   []byte
	StaticHeaders map[string]string
	Graph         Graph
}

type DefinitionLock struct {
	Version         int                 `json:"version"`
	CompilerVersion string              `json:"compiler_version"`
	IRDigest        string              `json:"ir_digest"`
	PolicyDigest    string              `json:"policy_digest"`
	SourceSnapshot  string              `json:"source_snapshot"`
	TargetPlatform  string              `json:"target_platform"`
	BuildArguments  []NameValue         `json:"build_arguments"`
	BaseMaterials   []BaseMaterial      `json:"base_materials"`
	Network         []NetworkCapability `json:"network"`
	Caches          []CacheCapability   `json:"caches"`
	Secrets         []SecretCapability  `json:"secrets"`
	SupplyChain     SupplyChainPolicy   `json:"supply_chain"`
	Outputs         []OutputLock        `json:"outputs"`
}

type NameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type NetworkCapability struct {
	NodeID    string   `json:"node_id"`
	Profile   string   `json:"profile"`
	Hosts     []string `json:"hosts"`
	GatewayID string   `json:"gateway_id,omitempty"`
}

type CacheCapability struct {
	NodeID    string `json:"node_id"`
	Name      string `json:"name"`
	Target    string `json:"target"`
	Sharing   string `json:"sharing"`
	Scope     string `json:"scope"`
	Namespace string `json:"namespace"`
}

type SecretCapability struct {
	NodeID   string `json:"node_id"`
	Name     string `json:"name"`
	Target   string `json:"target"`
	Required bool   `json:"required"`
	MountID  string `json:"mount_id"`
}

type OutputLock struct {
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	StateID      string `json:"state_id"`
	LLBDigest    string `json:"llb_digest"`
	ConfigDigest string `json:"config_digest,omitempty"`
}

type Graph struct {
	Head     string        `json:"head"`
	Vertices []GraphVertex `json:"vertices"`
}

type GraphVertex struct {
	Digest string   `json:"digest"`
	Kind   string   `json:"kind"`
	Inputs []string `json:"inputs"`
}

func New(version string) (*Compiler, error) {
	return newCompiler(version)
}

func LockDigest(lock DefinitionLock) (string, error) {
	return digestValue(lock)
}

func ResolutionDigest(material BaseMaterial) (string, error) {
	material.Platforms = sortedUnique(material.Platforms)
	return materialResolutionDigest(material)
}

func ValidatePolicy(policy Policy) error {
	_, err := normalizePolicy(policy)
	return err
}

func PlatformSupplyChainPolicy(allowedSignerPublicKeyDigests []string) SupplyChainPolicy {
	return SupplyChainPolicy{
		Version: CurrentSupplyChainPolicyVersion, SyftVersion: CurrentSyftVersion, TrivyVersion: CurrentTrivyVersion,
		SignerKeyID: DefaultBuildSignerKeyID, AllowedSignerPublicKeyDigests: sortedUnique(allowedSignerPublicKeyDigests),
		DeniedVulnerabilitySeverities: []string{"CRITICAL"}, DeniedConfigurationSeverities: []string{"CRITICAL", "HIGH"},
		DeniedLicenseClassifications: []string{"Forbidden"}, RequireSecretFree: true, RequireImageConfigurationScan: true,
	}
}

func (compiler *Compiler) Compile(ctx context.Context, request Request) (Result, error) {
	return compiler.compile(ctx, request)
}
