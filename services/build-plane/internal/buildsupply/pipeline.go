package buildsupply

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
)

type Pipeline struct {
	scanner Scanner
	signer  Signer
}

func NewPipeline(scanner Scanner, signer Signer) (*Pipeline, error) {
	if scanner == nil || signer == nil {
		return nil, errors.New("supply-chain pipeline dependencies are incomplete")
	}
	return &Pipeline{scanner: scanner, signer: signer}, nil
}

func (pipeline *Pipeline) Generate(ctx context.Context, request GenerateRequest) (Bundle, error) {
	if err := validateGenerateRequest(request); err != nil {
		return Bundle{}, err
	}
	analysis, err := pipeline.scanner.Analyze(ctx, ScanRequest{
		OCIPath: request.OCIPath, OCIArchiveDigest: request.OCIArchiveDigest, OCIArchiveSize: request.OCIArchiveSize,
		ManifestDigest: request.Identity.ManifestDigest, OutputName: request.Artifact.OutputName,
		TargetPlatform: request.Artifact.Provenance.TargetPlatform,
		SyftVersion:    request.Artifact.Provenance.SupplyChain.SyftVersion,
		TrivyVersion:   request.Artifact.Provenance.SupplyChain.TrivyVersion,
	})
	if err != nil {
		return Bundle{}, errors.Join(ErrEvidence, err)
	}
	if denial := evaluatePolicy(request.Artifact.Provenance.SupplyChain, analysis.Summary); denial != nil {
		return Bundle{}, denial
	}
	provenance, err := provenanceStatement(request)
	if err != nil {
		return Bundle{}, errors.Join(ErrEvidence, err)
	}
	policy, err := policyStatement(request, analysis)
	if err != nil {
		return Bundle{}, errors.Join(ErrEvidence, err)
	}
	statements := []struct {
		kind      string
		statement []byte
	}{
		{KindSBOM, mustEvidenceStatement(request, SPDXPredicateType, analysis.SBOM)},
		{KindScan, mustEvidenceStatement(request, ScanPredicateType, analysis.Scan)},
		{KindProvenance, provenance},
		{KindPolicy, policy},
	}
	for _, item := range statements {
		if item.statement == nil {
			return Bundle{}, errors.New("build evidence statement could not be created")
		}
	}
	image, trustedSignature, err := signImage(ctx, pipeline.signer, request)
	if err != nil {
		return Bundle{}, errors.Join(ErrEvidence, err)
	}
	attestations := make([]SignedPayload, 0, len(statements))
	for _, item := range statements {
		signed, signature, err := signDSSE(ctx, pipeline.signer, request, item.kind, item.statement)
		if err != nil {
			return Bundle{}, errors.Join(ErrEvidence, err)
		}
		if !sameSigner(trustedSignature, signature) {
			return Bundle{}, errors.New("signing identity rotated within one evidence bundle")
		}
		attestations = append(attestations, signed)
	}
	_, publicKeyDigest, _ := parsePublicKey(trustedSignature.PublicKeyPEM)
	bundle := Bundle{
		Version: CurrentEvidenceVersion, SubjectDigest: request.Identity.ManifestDigest,
		PolicyDigest: request.Artifact.Provenance.PolicyDigest, PolicyState: "accepted", ScanState: "passed",
		SignerKeyID: trustedSignature.KeyID, SignerKeyVersion: trustedSignature.KeyVersion,
		SignerPublicKeyDigest: publicKeyDigest, SignerPublicKeyPEM: append([]byte(nil), trustedSignature.PublicKeyPEM...),
		ImageSignature: image, Attestations: attestations,
	}
	if err := ValidateBundle(request, bundle); err != nil {
		return Bundle{}, errors.Join(ErrEvidence, err)
	}
	return bundle, nil
}

func ValidateBundle(request GenerateRequest, bundle Bundle) error {
	if err := validateGenerateRequest(request); err != nil {
		return err
	}
	policy := request.Artifact.Provenance.SupplyChain
	if bundle.Version != CurrentEvidenceVersion || bundle.SubjectDigest != request.Identity.ManifestDigest ||
		bundle.PolicyDigest != request.Artifact.Provenance.PolicyDigest || bundle.PolicyState != "accepted" || bundle.ScanState != "passed" ||
		bundle.SignerKeyID != policy.SignerKeyID || bundle.SignerKeyVersion < 1 || !slices.Contains(policy.AllowedSignerPublicKeyDigests, bundle.SignerPublicKeyDigest) ||
		len(bundle.Attestations) != 4 {
		return errors.New("supply-chain bundle identity is incomplete")
	}
	signature := Signature{KeyID: bundle.SignerKeyID, KeyVersion: bundle.SignerKeyVersion, Algorithm: SignatureAlgorithm, PublicKeyPEM: bundle.SignerPublicKeyPEM, Value: bundle.ImageSignature.Signature}
	if _, digest, err := parsePublicKey(bundle.SignerPublicKeyPEM); err != nil || digest != bundle.SignerPublicKeyDigest ||
		validateSignedPayload(bundle.ImageSignature, bundle.SubjectDigest, signature) != nil {
		return errors.New("supply-chain image signature is invalid")
	}
	expected := map[string]string{KindSBOM: SPDXPredicateType, KindScan: ScanPredicateType, KindProvenance: SLSAPredicateType, KindPolicy: PolicyPredicateType}
	for _, attestation := range bundle.Attestations {
		predicate, found := expected[attestation.Kind]
		if !found || predicate != attestation.PredicateType {
			return errors.New("supply-chain attestation set is duplicated or unexpected")
		}
		delete(expected, attestation.Kind)
		signature.Value = attestation.Signature
		if err := validateSignedPayload(attestation, bundle.SubjectDigest, signature); err != nil {
			return err
		}
	}
	if len(expected) != 0 {
		return errors.New("supply-chain attestation set is incomplete")
	}
	return nil
}

func evaluatePolicy(policy llbcompiler.SupplyChainPolicy, summary ScanSummary) error {
	if policy.RequireSecretFree && summary.Secrets > 0 {
		return &Denial{Code: "security_secret_found", Summary: summary}
	}
	for _, severity := range policy.DeniedVulnerabilitySeverities {
		if summary.Vulnerabilities[severity] > 0 {
			return &Denial{Code: "security_vulnerability_policy", Summary: summary}
		}
	}
	for _, classification := range policy.DeniedLicenseClassifications {
		if summary.Licenses[classification] > 0 {
			return &Denial{Code: "security_license_policy", Summary: summary}
		}
	}
	if policy.RequireImageConfigurationScan {
		for _, severity := range policy.DeniedConfigurationSeverities {
			if summary.Misconfigurations[severity] > 0 {
				return &Denial{Code: "security_configuration_policy", Summary: summary}
			}
		}
	}
	return nil
}

func validateGenerateRequest(request GenerateRequest) error {
	if request.OCIPath == "" || !digestPattern.MatchString(request.OCIArchiveDigest) || request.OCIArchiveSize <= 0 ||
		request.RepositoryReference == "" || strings.ContainsAny(request.RepositoryReference, "@?#") ||
		!digestPattern.MatchString(request.Identity.ManifestDigest) || len(request.Identity.Manifest) == 0 {
		return errors.New("supply-chain generation request is invalid")
	}
	parsed, err := url.Parse("https://" + request.RepositoryReference)
	if err != nil || parsed.Host == "" || parsed.Path == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("supply-chain repository reference is invalid")
	}
	if err := buildworker.ValidateExportedArtifact(request.Artifact, buildworker.DefaultMaxCommittedArtifactBytes); err != nil {
		return err
	}
	verified, err := buildworker.InspectOCIArtifact(request.OCIPath)
	if err != nil || verified.ManifestDigest != request.Identity.ManifestDigest || verified.ManifestMediaType != request.Identity.ManifestMediaType ||
		verified.Config != request.Identity.Config || !slices.Equal(verified.Layers, request.Identity.Layers) || !bytes.Equal(verified.Manifest, request.Identity.Manifest) {
		return errors.New("supply-chain OCI identity differs")
	}
	if err := llbcompiler.ValidateSupplyChainPolicy(request.Artifact.Provenance.SupplyChain); err != nil {
		return err
	}
	return validateProvenanceContext(request.Artifact.Provenance)
}

func mustEvidenceStatement(request GenerateRequest, predicateType string, predicate []byte) []byte {
	statement, err := evidenceStatement(request.Artifact.OutputName, request.Identity.ManifestDigest, predicateType, predicate)
	if err != nil {
		return nil
	}
	return statement
}

func sameSigner(left, right Signature) bool {
	return left.KeyID == right.KeyID && left.KeyVersion == right.KeyVersion && left.Algorithm == right.Algorithm && bytes.Equal(left.PublicKeyPEM, right.PublicKeyPEM)
}

var _ Generator = (*Pipeline)(nil)
