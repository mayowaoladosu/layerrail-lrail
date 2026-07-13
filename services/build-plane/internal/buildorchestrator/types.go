// Package buildorchestrator owns one immutable source-to-artifact build journey.
package buildorchestrator

import (
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
)

const (
	CurrentRequestVersion = 1
	CurrentEventVersion   = 1
	CurrentResultVersion  = 1
	MaxEventLineBytes     = 16 << 10
	MaxEventMessageBytes  = 4 << 10
)

var (
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	stagePattern       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	eventKindPattern   = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
	failureCodePattern = regexp.MustCompile(`^(source|detect|dsl|solve|artifact|security|build)_[a-z0-9_.-]{1,95}$`)
	outputNamePattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
)

type Request struct {
	Version        int                 `json:"version"`
	BuildID        string              `json:"build_id"`
	OrganizationID string              `json:"organization_id"`
	ProjectID      string              `json:"project_id"`
	DeploymentID   string              `json:"deployment_id"`
	OperationID    string              `json:"operation_id"`
	Generation     uint64              `json:"generation"`
	Source         Source              `json:"source"`
	Configuration  ConfigurationIntent `json:"configuration"`
	TargetPlatform string              `json:"target_platform"`
	Deadline       string              `json:"deadline"`
}

type Source struct {
	SnapshotID     string `json:"snapshot_id"`
	SnapshotDigest string `json:"snapshot_digest"`
	ManifestDigest string `json:"manifest_digest"`
	ArchiveDigest  string `json:"archive_digest"`
	ArchiveRef     string `json:"archive_ref"`
	SizeBytes      int64  `json:"size_bytes"`
	SelectedRoot   string `json:"selected_root"`
}

type ConfigurationIntent struct {
	Mode           string `json:"mode"`
	BuildFile      string `json:"build_file,omitempty"`
	AcceptDetected bool   `json:"accept_detected"`
}

type Event struct {
	Version    int     `json:"version"`
	BuildID    string  `json:"build_id"`
	Generation uint64  `json:"generation"`
	Sequence   uint64  `json:"sequence"`
	Attempt    uint32  `json:"attempt"`
	Stage      string  `json:"stage"`
	Kind       string  `json:"kind"`
	Output     string  `json:"output,omitempty"`
	Vertex     string  `json:"vertex,omitempty"`
	Name       string  `json:"name,omitempty"`
	Current    int64   `json:"current,omitempty"`
	Total      int64   `json:"total,omitempty"`
	Cached     bool    `json:"cached,omitempty"`
	Stream     uint32  `json:"stream,omitempty"`
	Line       string  `json:"line,omitempty"`
	Code       string  `json:"code,omitempty"`
	Message    string  `json:"message,omitempty"`
	OccurredAt string  `json:"occurred_at"`
	Terminal   *Result `json:"terminal,omitempty"`
}

type Result struct {
	Version           int             `json:"version"`
	BuildID           string          `json:"build_id"`
	Generation        uint64          `json:"generation"`
	State             string          `json:"state"`
	SourceSnapshotID  string          `json:"source_snapshot_id"`
	SourceDigest      string          `json:"source_digest"`
	DetectionDigest   string          `json:"detection_digest,omitempty"`
	ManifestDigest    string          `json:"manifest_digest,omitempty"`
	BuildIRDigest     string          `json:"build_ir_digest,omitempty"`
	DefinitionDigest  string          `json:"definition_digest,omitempty"`
	AssignmentDigest  string          `json:"assignment_digest,omitempty"`
	LogsDigest        string          `json:"logs_digest,omitempty"`
	Outputs           []OutputResult  `json:"outputs"`
	Services          []ServiceResult `json:"services"`
	FailureCode       string          `json:"failure_code,omitempty"`
	FailureMessage    string          `json:"failure_message,omitempty"`
	StartedAt         string          `json:"started_at"`
	FinishedAt        string          `json:"finished_at"`
	WorkerIdentity    string          `json:"worker_identity,omitempty"`
	Cleanup           CleanupResult   `json:"cleanup"`
	CacheHits         int64           `json:"cache_hits"`
	CacheMisses       int64           `json:"cache_misses"`
	DetectorResultRef string          `json:"detector_result_ref,omitempty"`
	ManifestRef       string          `json:"manifest_ref,omitempty"`
	GeneratedBuildRef string          `json:"generated_build_ref,omitempty"`
	BuildIRRef        string          `json:"build_ir_ref,omitempty"`
	DefinitionLockRef string          `json:"definition_lock_ref,omitempty"`
}

type OutputResult struct {
	Name                   string                        `json:"name"`
	Kind                   string                        `json:"kind"`
	ArtifactRef            string                        `json:"artifact_ref"`
	ArtifactDigest         string                        `json:"artifact_digest"`
	ArtifactSize           int64                         `json:"artifact_size"`
	ConfigDigest           string                        `json:"config_digest"`
	ManifestDigest         string                        `json:"manifest_digest"`
	LayerDigests           []string                      `json:"layer_digests"`
	PublicationManifestRef string                        `json:"publication_manifest_ref,omitempty"`
	SupplyChain            buildworker.SupplyChainResult `json:"supply_chain"`
}

type ServiceResult struct {
	Name           string          `json:"name"`
	Root           string          `json:"root"`
	Kind           string          `json:"kind"`
	Language       string          `json:"language"`
	Framework      string          `json:"framework"`
	RuntimeVersion string          `json:"runtime_version,omitempty"`
	Build          BuildResult     `json:"build"`
	Processes      []ProcessResult `json:"processes"`
}

type BuildResult struct {
	Strategy       string   `json:"strategy"`
	InstallCommand []string `json:"install_command"`
	BuildCommand   []string `json:"build_command"`
	OutputPath     string   `json:"output_path,omitempty"`
	CachePaths     []string `json:"cache_paths"`
}

type ProcessResult struct {
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	Command    []string `json:"command"`
	Port       *int     `json:"port,omitempty"`
	Protocol   string   `json:"protocol"`
	HealthPath string   `json:"health_path,omitempty"`
}

type CleanupResult struct {
	Status           string `json:"status"`
	ResidueCount     uint32 `json:"residue_count"`
	QuarantineReason string `json:"quarantine_reason,omitempty"`
}

func (request Request) Validate(now time.Time) error {
	if request.Version != CurrentRequestVersion || request.Generation == 0 {
		return errors.New("build request version or generation is invalid")
	}
	identities := [][2]string{
		{request.BuildID, "bld"}, {request.OrganizationID, "org"}, {request.ProjectID, "prj"},
		{request.DeploymentID, "dep"}, {request.OperationID, "op"}, {request.Source.SnapshotID, "snp"},
	}
	for _, expected := range identities {
		identity, err := platformid.Parse(expected[0])
		if err != nil || identity.Prefix() != expected[1] {
			return errors.New("build request resource identity is invalid")
		}
	}
	archiveReference, archiveErr := url.Parse(request.Source.ArchiveRef)
	if !digestPattern.MatchString(request.Source.SnapshotDigest) ||
		!digestPattern.MatchString(request.Source.ManifestDigest) ||
		!digestPattern.MatchString(request.Source.ArchiveDigest) ||
		request.Source.SizeBytes <= 0 || request.Source.SizeBytes > 1<<30 ||
		archiveErr != nil || archiveReference.Scheme != "s3" || archiveReference.Host == "" || archiveReference.Path == "" ||
		archiveReference.User != nil || archiveReference.RawQuery != "" || archiveReference.Fragment != "" ||
		strings.Contains(archiveReference.Path, "//") || slices.Contains(strings.Split(archiveReference.Path, "/"), "..") ||
		len(request.Source.ArchiveRef) > 2048 ||
		!validRelativePath(request.Source.SelectedRoot, true) {
		return errors.New("build request source is invalid")
	}
	if request.Configuration.Mode != "auto" && request.Configuration.Mode != "repository" {
		return errors.New("build request configuration mode is invalid")
	}
	if request.Configuration.Mode == "repository" {
		if !validRelativePath(request.Configuration.BuildFile, false) || !strings.HasSuffix(request.Configuration.BuildFile, ".star") {
			return errors.New("repository build file is invalid")
		}
	} else if request.Configuration.BuildFile != "" {
		return errors.New("automatic configuration cannot select a repository build file")
	}
	if request.TargetPlatform != "linux/amd64" && request.TargetPlatform != "linux/arm64" {
		return errors.New("build target platform is unsupported")
	}
	deadline, err := time.Parse(time.RFC3339Nano, request.Deadline)
	if err != nil || !deadline.After(now.UTC()) || deadline.Sub(now.UTC()) > 2*time.Hour {
		return errors.New("build request deadline is invalid")
	}
	return nil
}

func (event Event) Validate() error {
	if event.Version != CurrentEventVersion || event.Generation == 0 || event.Sequence == 0 || event.Attempt == 0 ||
		!stagePattern.MatchString(event.Stage) || !eventKindPattern.MatchString(event.Kind) ||
		len(event.Line) > MaxEventLineBytes || len(event.Message) > MaxEventMessageBytes ||
		!utf8.ValidString(event.Line) || !utf8.ValidString(event.Message) || strings.ContainsRune(event.Line, '\x00') || strings.ContainsRune(event.Message, '\x00') {
		return errors.New("build event is invalid")
	}
	identity, err := platformid.Parse(event.BuildID)
	if err != nil || identity.Prefix() != "bld" {
		return errors.New("build event identity is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, event.OccurredAt); err != nil {
		return errors.New("build event time is invalid")
	}
	if event.Terminal != nil {
		if event.Kind != "terminal" || event.Terminal.BuildID != event.BuildID || event.Terminal.Generation != event.Generation {
			return errors.New("terminal build event is inconsistent")
		}
		if err := event.Terminal.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (result Result) Validate() error {
	if result.Version != CurrentResultVersion || result.Generation == 0 ||
		!slices.Contains([]string{"complete", "failed", "canceled", "waiting"}, result.State) {
		return errors.New("build result version, generation, or state is invalid")
	}
	for _, expected := range [][2]string{{result.BuildID, "bld"}, {result.SourceSnapshotID, "snp"}} {
		identity, err := platformid.Parse(expected[0])
		if err != nil || identity.Prefix() != expected[1] {
			return errors.New("build result resource identity is invalid")
		}
	}
	if !digestPattern.MatchString(result.SourceDigest) {
		return errors.New("build result source digest is invalid")
	}
	started, startErr := time.Parse(time.RFC3339Nano, result.StartedAt)
	finished, finishErr := time.Parse(time.RFC3339Nano, result.FinishedAt)
	if startErr != nil || finishErr != nil || finished.Before(started) {
		return errors.New("build result timing is invalid")
	}
	if result.State == "complete" {
		if len(result.Outputs) == 0 || len(result.Services) != len(result.Outputs) || result.FailureCode != "" || result.FailureMessage != "" ||
			!digestPattern.MatchString(result.DetectionDigest) || !digestPattern.MatchString(result.ManifestDigest) ||
			!digestPattern.MatchString(result.BuildIRDigest) || !digestPattern.MatchString(result.DefinitionDigest) ||
			!digestPattern.MatchString(result.AssignmentDigest) || !digestPattern.MatchString(result.LogsDigest) ||
			result.DetectorResultRef == "" || result.ManifestRef == "" || result.GeneratedBuildRef == "" ||
			result.BuildIRRef == "" || result.DefinitionLockRef == "" || result.Cleanup.Status != "clean" {
			return errors.New("complete build result is missing immutable evidence")
		}
	} else if !failureCodePattern.MatchString(result.FailureCode) || result.FailureMessage == "" || len(result.FailureMessage) > MaxEventMessageBytes {
		return errors.New("non-complete build result lacks a safe failure")
	}
	names := make([]string, 0, len(result.Outputs))
	for _, output := range result.Outputs {
		if !outputNamePattern.MatchString(output.Name) || !slices.Contains([]string{"oci_image", "static_bundle"}, output.Kind) ||
			!digestPattern.MatchString(output.ArtifactDigest) || !digestPattern.MatchString(output.ConfigDigest) ||
			!digestPattern.MatchString(output.ManifestDigest) ||
			output.ArtifactRef == "" || output.ArtifactSize <= 0 {
			return errors.New("build output result is invalid")
		}
		if !validSupplyChain(output) {
			return errors.New("build output supply-chain result is invalid")
		}
		names = append(names, output.Name)
	}
	if !slices.IsSorted(names) || len(slices.Compact(append([]string(nil), names...))) != len(names) {
		return errors.New("build output results must be sorted and unique")
	}
	serviceNames := make([]string, 0, len(result.Services))
	for _, service := range result.Services {
		if !outputNamePattern.MatchString(service.Name) || !validRelativePath(service.Root, true) ||
			!slices.Contains([]string{"web", "worker", "private_service", "static"}, service.Kind) ||
			!slices.Contains([]string{"ruby", "node", "python", "go", "static", "docker"}, service.Language) ||
			service.Framework == "" || len(service.Framework) > 64 || len(service.Processes) == 0 || len(service.Processes) > 32 {
			return errors.New("build service result is invalid")
		}
		serviceNames = append(serviceNames, service.Name)
	}
	if result.State == "complete" && !slices.Equal(serviceNames, names) {
		return errors.New("build services do not match immutable outputs")
	}
	return nil
}

func validRelativePath(value string, allowDot bool) bool {
	if value == "." {
		return allowDot
	}
	if value == "" || len(value) > 1024 || !utf8.ValidString(value) || strings.ContainsAny(value, "\\\x00:") ||
		strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.Contains(value, "//") ||
		strings.HasPrefix(value, "./") {
		return false
	}
	return !slices.Contains(strings.Split(value, "/"), "..") && !slices.Contains(strings.Split(value, "/"), ".")
}

func validSupplyChain(output OutputResult) bool {
	evidence := output.SupplyChain
	if evidence.PolicyState != "accepted" || evidence.ScanState != "passed" ||
		!digestPattern.MatchString(evidence.PolicyDigest) || evidence.SignerKeyID == "" ||
		evidence.SignerKeyVersion < 1 || !digestPattern.MatchString(evidence.SignerPublicKeyDigest) {
		return false
	}
	repository, _, found := strings.Cut(output.ArtifactRef, "@")
	if !found || repository == "" {
		return false
	}
	expected := map[string]struct{}{
		"sbom": {}, "vulnerability_scan": {}, "provenance": {}, "signature": {}, "policy_decision": {},
	}
	manifests := make(map[string]struct{}, len(evidence.Evidence))
	for _, reference := range evidence.Evidence {
		if _, exists := expected[reference.Kind]; !exists || reference.Reference != repository+"@"+reference.ManifestDigest ||
			!digestPattern.MatchString(reference.ManifestDigest) || !digestPattern.MatchString(reference.PayloadDigest) {
			return false
		}
		if _, duplicate := manifests[reference.ManifestDigest]; duplicate {
			return false
		}
		manifests[reference.ManifestDigest] = struct{}{}
		delete(expected, reference.Kind)
	}
	return len(expected) == 0
}
