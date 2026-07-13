// Package buildsupply generates, evaluates, signs, and verifies the complete
// supply-chain evidence set for one immutable build output.
package buildsupply

import (
	"context"
	"errors"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
)

const (
	CurrentEvidenceVersion = 1
	MaxEvidenceBytes       = 16 << 20
	MaxToolOutputBytes     = 64 << 20

	KindSBOM       = "sbom"
	KindScan       = "vulnerability_scan"
	KindProvenance = "provenance"
	KindSignature  = "signature"
	KindPolicy     = "policy_decision"

	InTotoStatementType = "https://in-toto.io/Statement/v1"
	SLSAPredicateType   = "https://slsa.dev/provenance/v1"
	SPDXPredicateType   = "https://spdx.dev/Document"
	ScanPredicateType   = "https://lrail.internal/attestation/trivy-scan/v1"
	PolicyPredicateType = "https://lrail.internal/attestation/supply-chain-policy/v1"
	DSSEPayloadType     = "application/vnd.in-toto+json"
	DSSEMediaType       = "application/vnd.dsse.envelope.v1+json"
	SimpleSigningType   = "application/vnd.dev.cosign.simplesigning.v1+json"
	SignatureAlgorithm  = "ed25519"
)

var (
	ErrEvidence = errors.New("build supply-chain evidence failed")
	ErrDenied   = errors.New("build supply-chain policy denied publication")
)

type GenerateRequest struct {
	Artifact            buildworker.ExportedArtifact
	OCIPath             string
	OCIArchiveDigest    string
	OCIArchiveSize      int64
	Identity            buildworker.OCIArtifactIdentity
	RepositoryReference string
}

type Scanner interface {
	Analyze(ctx context.Context, request ScanRequest) (Analysis, error)
}

type ScanRequest struct {
	OCIPath          string
	OCIArchiveDigest string
	OCIArchiveSize   int64
	ManifestDigest   string
	OutputName       string
	TargetPlatform   string
	SyftVersion      string
	TrivyVersion     string
}

type Analysis struct {
	SBOM    []byte
	Scan    []byte
	Summary ScanSummary
}

type ScanSummary struct {
	Vulnerabilities   map[string]int `json:"vulnerabilities"`
	Secrets           int            `json:"secrets"`
	Misconfigurations map[string]int `json:"misconfigurations"`
	Licenses          map[string]int `json:"licenses"`
}

type Signer interface {
	Sign(ctx context.Context, request SigningRequest) (Signature, error)
}

type SigningRequest struct {
	OrganizationID string
	ProjectID      string
	BuildID        string
	Attempt        uint32
	OutputName     string
	Kind           string
	SubjectDigest  string
	Payload        []byte
}

type Signature struct {
	KeyID        string
	KeyVersion   int
	Algorithm    string
	PublicKeyPEM []byte
	Value        []byte
}

type Generator interface {
	Generate(ctx context.Context, request GenerateRequest) (Bundle, error)
}

type Bundle struct {
	Version               int
	SubjectDigest         string
	PolicyDigest          string
	PolicyState           string
	ScanState             string
	SignerKeyID           string
	SignerKeyVersion      int
	SignerPublicKeyDigest string
	SignerPublicKeyPEM    []byte
	ImageSignature        SignedPayload
	Attestations          []SignedPayload
}

type SignedPayload struct {
	Kind          string
	PredicateType string
	MediaType     string
	Payload       []byte
	PayloadDigest string
	Signature     []byte
}

type Denial struct {
	Code    string
	Summary ScanSummary
}

func (denial *Denial) Error() string          { return ErrDenied.Error() }
func (denial *Denial) Unwrap() error          { return ErrDenied }
func (denial *Denial) BuildErrorCode() string { return denial.Code }
