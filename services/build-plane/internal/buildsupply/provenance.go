package buildsupply

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
)

type statement struct {
	Type          string            `json:"_type"`
	Subject       []evidenceSubject `json:"subject"`
	PredicateType string            `json:"predicateType"`
	Predicate     json.RawMessage   `json:"predicate"`
}

type slsaPredicate struct {
	BuildDefinition slsaBuildDefinition `json:"buildDefinition"`
	RunDetails      slsaRunDetails      `json:"runDetails"`
}

type slsaBuildDefinition struct {
	BuildType            string                 `json:"buildType"`
	ExternalParameters   provenanceExternal     `json:"externalParameters"`
	InternalParameters   provenanceInternal     `json:"internalParameters"`
	ResolvedDependencies []provenanceDependency `json:"resolvedDependencies"`
}

type provenanceExternal struct {
	OrganizationID string `json:"organizationId"`
	ProjectID      string `json:"projectId"`
	OutputName     string `json:"outputName"`
	OutputKind     string `json:"outputKind"`
	TargetPlatform string `json:"targetPlatform"`
	SourceSnapshot string `json:"sourceSnapshot"`
	IRDigest       string `json:"buildIrDigest"`
}

type provenanceInternal struct {
	AssignmentDigest   string   `json:"assignmentDigest"`
	DefinitionDigest   string   `json:"definitionDigest"`
	PolicyDigest       string   `json:"policyDigest"`
	CompilerVersion    string   `json:"compilerVersion"`
	AssignmentIssuedAt string   `json:"assignmentIssuedAt"`
	AssignmentDeadline string   `json:"assignmentDeadline"`
	BuildArguments     any      `json:"buildArguments"`
	Network            any      `json:"network"`
	SecretReferences   []string `json:"secretReferences"`
}

type provenanceDependency struct {
	URI         string            `json:"uri"`
	Digest      map[string]string `json:"digest"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type slsaRunDetails struct {
	Builder  slsaBuilder  `json:"builder"`
	Metadata slsaMetadata `json:"metadata"`
}

type slsaBuilder struct {
	ID string `json:"id"`
}

type slsaMetadata struct {
	InvocationID string `json:"invocationId"`
}

type policyDecision struct {
	Version        int             `json:"version"`
	Decision       string          `json:"decision"`
	PolicyDigest   string          `json:"policy_digest"`
	Subject        evidenceSubject `json:"subject"`
	RequiredKinds  []string        `json:"required_evidence"`
	ScannerSummary ScanSummary     `json:"scanner_summary"`
	SyftVersion    string          `json:"syft_version"`
	TrivyVersion   string          `json:"trivy_version"`
	SignerKeyID    string          `json:"signer_key_id"`
}

func provenanceStatement(request GenerateRequest) ([]byte, error) {
	context := request.Artifact.Provenance
	if err := validateProvenanceContext(context); err != nil {
		return nil, err
	}
	dependencies := []provenanceDependency{{
		URI:         "lrail:source-snapshot:" + strings.TrimPrefix(context.SourceSnapshot, "sha256:"),
		Digest:      map[string]string{"sha256": strings.TrimPrefix(context.SourceSnapshot, "sha256:")},
		Annotations: map[string]string{"archiveDigest": context.SourceArchive},
	}}
	for _, material := range context.BaseMaterials {
		dependencies = append(dependencies, provenanceDependency{
			URI: material.ResolvedRef, Digest: map[string]string{"sha256": strings.TrimPrefix(material.Digest, "sha256:")},
			Annotations: map[string]string{
				"classification": material.Classification, "resolutionDigest": material.ResolutionDigest,
				"sbomDigest": material.SBOMDigest, "provenanceDigest": material.ProvenanceDigest,
				"signatureIdentity": material.SignatureIdentity,
			},
		})
	}
	predicate := slsaPredicate{
		BuildDefinition: slsaBuildDefinition{
			BuildType: "https://lrail.internal/build-types/buildkit-llb/v1",
			ExternalParameters: provenanceExternal{
				OrganizationID: request.Artifact.OrganizationID, ProjectID: request.Artifact.ProjectID,
				OutputName: request.Artifact.OutputName, OutputKind: request.Artifact.Kind,
				TargetPlatform: context.TargetPlatform, SourceSnapshot: context.SourceSnapshot, IRDigest: context.IRDigest,
			},
			InternalParameters: provenanceInternal{
				AssignmentDigest: context.AssignmentDigest, DefinitionDigest: context.DefinitionDigest, PolicyDigest: context.PolicyDigest,
				CompilerVersion: context.CompilerVersion, AssignmentIssuedAt: context.AssignmentIssuedAt,
				AssignmentDeadline: context.AssignmentExpiresAt, BuildArguments: context.BuildArguments,
				Network: context.Network, SecretReferences: append([]string(nil), context.SecretNames...),
			},
			ResolvedDependencies: dependencies,
		},
		RunDetails: slsaRunDetails{
			Builder:  slsaBuilder{ID: context.BuilderIdentity},
			Metadata: slsaMetadata{InvocationID: fmt.Sprintf("%s:%d:%s", request.Artifact.BuildID, request.Artifact.Attempt, request.Artifact.OutputName)},
		},
	}
	predicateBytes, err := canonicaljson.Marshal(predicate)
	if err != nil {
		return nil, errors.New("canonicalize SLSA provenance predicate")
	}
	return marshalStatement(request.Artifact.OutputName, request.Identity.ManifestDigest, SLSAPredicateType, predicateBytes)
}

func policyStatement(request GenerateRequest, analysis Analysis) ([]byte, error) {
	policy := request.Artifact.Provenance.SupplyChain
	decision := policyDecision{
		Version: CurrentEvidenceVersion, Decision: "accepted", PolicyDigest: request.Artifact.Provenance.PolicyDigest,
		Subject:        subject(request.Artifact.OutputName, request.Identity.ManifestDigest),
		RequiredKinds:  []string{KindPolicy, KindProvenance, KindSBOM, KindScan, KindSignature},
		ScannerSummary: analysis.Summary, SyftVersion: policy.SyftVersion, TrivyVersion: policy.TrivyVersion, SignerKeyID: policy.SignerKeyID,
	}
	predicate, err := canonicaljson.Marshal(decision)
	if err != nil {
		return nil, errors.New("canonicalize supply-chain policy decision")
	}
	return marshalStatement(request.Artifact.OutputName, request.Identity.ManifestDigest, PolicyPredicateType, predicate)
}

func evidenceStatement(outputName, manifestDigest, predicateType string, predicate []byte) ([]byte, error) {
	if len(predicate) == 0 || len(predicate) > MaxEvidenceBytes {
		return nil, errors.New("evidence predicate is absent or oversized")
	}
	return marshalStatement(outputName, manifestDigest, predicateType, predicate)
}

func marshalStatement(outputName, manifestDigest, predicateType string, predicate []byte) ([]byte, error) {
	if outputName == "" || !digestPattern.MatchString(manifestDigest) || predicateType == "" || !json.Valid(predicate) {
		return nil, errors.New("in-toto statement identity is invalid")
	}
	return canonicaljson.Marshal(statement{
		Type: InTotoStatementType, Subject: []evidenceSubject{subject(outputName, manifestDigest)},
		PredicateType: predicateType, Predicate: json.RawMessage(predicate),
	})
}

func subject(name, manifestDigest string) evidenceSubject {
	return evidenceSubject{Name: name, Digest: map[string]string{"sha256": strings.TrimPrefix(manifestDigest, "sha256:")}}
}

func validateProvenanceContext(context buildworker.ProvenanceContext) error {
	for _, digest := range []string{context.AssignmentDigest, context.DefinitionDigest, context.IRDigest, context.PolicyDigest, context.SourceSnapshot, context.SourceArchive} {
		if !digestPattern.MatchString(digest) {
			return errors.New("provenance digest identity is invalid")
		}
	}
	if context.TargetPlatform == "" || context.BuilderIdentity == "" || context.CompilerVersion == "" ||
		context.AssignmentIssuedAt == "" || context.AssignmentExpiresAt == "" {
		return errors.New("provenance invocation identity is incomplete")
	}
	return nil
}
