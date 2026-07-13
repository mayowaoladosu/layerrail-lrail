// Package buildworker executes one verified LLB assignment against BuildKit.
package buildworker

import (
	"context"
	"io"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
	"github.com/moby/buildkit/client"
)

type Phase string

const (
	PhaseAccepted      Phase = "accepted"
	PhaseResolving     Phase = "resolving"
	PhaseAllocating    Phase = "allocating"
	PhaseMaterializing Phase = "materializing"
	PhaseSolving       Phase = "solving"
	PhaseExporting     Phase = "exporting"
	PhaseRetrying      Phase = "retrying"
	PhaseCanceling     Phase = "canceling"
	PhaseCleaning      Phase = "cleaning"
	PhaseComplete      Phase = "complete"
	PhaseFailed        Phase = "failed"
	PhaseCanceled      Phase = "canceled"
	PhaseQuarantined   Phase = "quarantined"
)

type Event struct {
	Sequence   uint64    `json:"sequence"`
	Attempt    uint32    `json:"attempt"`
	Phase      Phase     `json:"phase"`
	Kind       string    `json:"kind"`
	Output     string    `json:"output,omitempty"`
	Vertex     string    `json:"vertex,omitempty"`
	Name       string    `json:"name,omitempty"`
	Current    int64     `json:"current,omitempty"`
	Total      int64     `json:"total,omitempty"`
	Cached     bool      `json:"cached,omitempty"`
	Stream     int       `json:"stream,omitempty"`
	Line       string    `json:"line,omitempty"`
	Code       string    `json:"code,omitempty"`
	Message    string    `json:"message,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
}

type OutputResult struct {
	Name                   string            `json:"name"`
	Kind                   string            `json:"kind"`
	ArtifactRef            string            `json:"artifact_ref"`
	ArtifactPath           string            `json:"artifact_path,omitempty"`
	ArtifactDigest         string            `json:"artifact_digest"`
	ArtifactSize           int64             `json:"artifact_size"`
	ConfigDigest           string            `json:"config_digest"`
	ManifestDigest         string            `json:"manifest_digest,omitempty"`
	PublicationManifestRef string            `json:"publication_manifest_ref,omitempty"`
	LayerDigests           []string          `json:"layer_digests"`
	ExporterResponse       map[string]string `json:"exporter_response"`
	SupplyChain            SupplyChainResult `json:"supply_chain"`
}

type Result struct {
	BuildID    string         `json:"build_id"`
	Attempt    uint32         `json:"attempt"`
	Phase      Phase          `json:"phase"`
	Outputs    []OutputResult `json:"outputs"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt time.Time      `json:"finished_at"`
	ErrorCode  string         `json:"error_code,omitempty"`
	LogsDigest string         `json:"logs_digest,omitempty"`
	Cache      CacheStats     `json:"cache"`
	Cleanup    CleanupReport  `json:"cleanup"`
}

type CacheStats struct {
	Hits   int64 `json:"hits"`
	Misses int64 `json:"misses"`
}

type Request struct {
	Assignment buildcell.ResolvedAssignment
	Attempt    uint32
	Secrets    map[string][]byte
	Events     func(Event)
}

type ContentStore interface {
	Open(ctx context.Context, source buildcell.SourceArtifact) (io.ReadCloser, error)
}

type SourceStore = ContentStore

type SourceMaterializer interface {
	Materialize(ctx context.Context, store SourceStore, source buildcell.SourceArtifact, destination string) error
}

type Cleaner interface {
	Cleanup(ctx context.Context, buildID string) CleanupReport
}

type ExportedArtifact struct {
	OrganizationID string
	ProjectID      string
	BuildID        string
	Attempt        uint32
	OutputName     string
	Kind           string
	Path           string
	Digest         string
	Size           int64
	Provenance     ProvenanceContext
}

type ProvenanceContext struct {
	AssignmentDigest    string
	DefinitionDigest    string
	IRDigest            string
	PolicyDigest        string
	SourceSnapshot      string
	SourceArchive       string
	TargetPlatform      string
	BuilderIdentity     string
	CompilerVersion     string
	AssignmentIssuedAt  string
	AssignmentExpiresAt string
	BuildArguments      []llbcompiler.NameValue
	BaseMaterials       []llbcompiler.BaseMaterial
	Network             []llbcompiler.NetworkCapability
	SecretNames         []string
	SupplyChain         llbcompiler.SupplyChainPolicy
}

type EvidenceReference struct {
	Kind           string `json:"kind"`
	Reference      string `json:"reference"`
	ManifestDigest string `json:"manifest_digest"`
	PayloadDigest  string `json:"payload_digest"`
}

type SupplyChainResult struct {
	PolicyState           string               `json:"policy_state"`
	ScanState             string               `json:"scan_state"`
	PolicyDigest          string               `json:"policy_digest"`
	SignerKeyID           string               `json:"signer_key_id"`
	SignerKeyVersion      int                  `json:"signer_key_version"`
	SignerPublicKeyDigest string               `json:"signer_public_key_digest"`
	Evidence              [5]EvidenceReference `json:"evidence"`
}

type CommittedArtifact struct {
	Reference              string
	Path                   string
	Digest                 string
	Size                   int64
	ManifestDigest         string
	PublicationManifestRef string
	SupplyChain            SupplyChainResult
}

type ArtifactCommitter interface {
	Commit(ctx context.Context, artifact ExportedArtifact) (CommittedArtifact, error)
}

type CacheLease interface {
	Imports() []client.CacheOptionsEntry
	Exports() []client.CacheOptionsEntry
	Complete(success bool) error
}

type CacheProvider interface {
	Acquire(ctx context.Context, lock llbcompiler.DefinitionLock, buildID, outputName string, attempt uint32) (CacheLease, error)
}

type Executor interface {
	Execute(ctx context.Context, request Request) (Result, error)
}
