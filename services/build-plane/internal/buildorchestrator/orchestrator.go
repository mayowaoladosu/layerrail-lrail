package buildorchestrator

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	lrailv1 "github.com/mayowaoladosu/layerrail-lrail/gen/go/lrail/v1"
	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildsigning"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildsupply"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/dsl"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
)

const (
	DefaultAssignmentTTL = buildcell.DefaultMaxAssignmentTTL
	MaxStoredObjectBytes = 32 << 20
)

var objectPartPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
var noncePattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Content interface {
	Materialize(ctx context.Context, source Source, destination string) error
	MirrorSource(ctx context.Context, source Source, objectName string) (buildcell.SourceArtifact, error)
	PutImmutable(ctx context.Context, objectName, mediaType string, contents []byte) (StoredObject, error)
}

type StoredObject struct {
	Reference string `json:"reference"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type CellDispatcher interface {
	Execute(ctx context.Context, envelope buildcell.Envelope, events func(*lrailv1.BuildCellEvent) error) (*lrailv1.BuildCellResult, error)
	Cancel(ctx context.Context, buildID string, generation uint64, reason string) (bool, error)
}

type CheckpointStore interface {
	Load(ctx context.Context, buildID string, generation uint64) (Checkpoint, bool, error)
	Save(ctx context.Context, checkpoint Checkpoint) error
}

type Checkpoint struct {
	Version       int                `json:"version"`
	BuildID       string             `json:"build_id"`
	Generation    uint64             `json:"generation"`
	RequestDigest string             `json:"request_digest"`
	StartedAt     string             `json:"started_at"`
	Partial       Result             `json:"partial"`
	Envelope      buildcell.Envelope `json:"envelope"`
	UpdatedAt     string             `json:"updated_at"`
}

type OrchestratorOptions struct {
	Content                   Content
	Detector                  Detector
	Compiler                  *DefinitionCompiler
	Signer                    buildsigning.Authority
	Dispatcher                CellDispatcher
	Checkpoints               CheckpointStore
	CellID                    string
	AssignmentKeyID           string
	AssignmentPublicKeyDigest string
	ScratchRoot               string
	Clock                     func() time.Time
	Nonce                     func() (string, error)
	AssignmentTTL             time.Duration
}

type Orchestrator struct {
	content         Content
	detector        Detector
	compiler        *DefinitionCompiler
	signer          buildsigning.Authority
	dispatcher      CellDispatcher
	checkpoints     CheckpointStore
	cellID          string
	assignmentKeyID string
	assignmentKey   string
	scratch         string
	clock           func() time.Time
	nonce           func() (string, error)
	assignmentTTL   time.Duration
}

type Emit func(Event) error

func New(options OrchestratorOptions) (*Orchestrator, error) {
	if options.Content == nil || options.Detector == nil || options.Compiler == nil || options.Signer == nil || options.Dispatcher == nil || options.Checkpoints == nil {
		return nil, errors.New("build orchestrator dependencies are incomplete")
	}
	cell, cellErr := platformid.Parse(options.CellID)
	if cellErr != nil || cell.Prefix() != "cell" || !eventKindPattern.MatchString(options.AssignmentKeyID) ||
		!digestPattern.MatchString(options.AssignmentPublicKeyDigest) {
		return nil, errors.New("build orchestrator assignment identity is invalid")
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.Nonce == nil {
		options.Nonce = randomNonce
	}
	if options.AssignmentTTL == 0 {
		options.AssignmentTTL = DefaultAssignmentTTL
	}
	if options.AssignmentTTL < time.Minute || options.AssignmentTTL > buildcell.DefaultMaxAssignmentTTL {
		return nil, errors.New("build orchestrator assignment TTL is outside policy")
	}
	if options.ScratchRoot == "" {
		return nil, errors.New("build orchestrator scratch root is absent")
	}
	absolute, err := filepath.Abs(options.ScratchRoot)
	if err != nil || os.MkdirAll(absolute, 0o700) != nil {
		return nil, errors.New("build orchestrator scratch root is invalid")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(absolute) {
		return nil, errors.New("build orchestrator scratch root traverses a symlink")
	}
	return &Orchestrator{
		content: options.Content, detector: options.Detector, compiler: options.Compiler, signer: options.Signer,
		dispatcher: options.Dispatcher, checkpoints: options.Checkpoints, cellID: options.CellID, assignmentKeyID: options.AssignmentKeyID,
		assignmentKey: options.AssignmentPublicKeyDigest, scratch: absolute, clock: options.Clock, nonce: options.Nonce,
		assignmentTTL: options.AssignmentTTL,
	}, nil
}

func (orchestrator *Orchestrator) Run(ctx context.Context, request Request, emit Emit) (Result, error) {
	if ctx == nil || emit == nil {
		return Result{}, errors.New("build orchestration context or event sink is absent")
	}
	requestBytes, err := canonicaljson.Marshal(request)
	if err != nil {
		return Result{}, errors.New("canonicalize build orchestration request")
	}
	requestDigest := digestBytes(requestBytes)
	checkpoint, found, err := orchestrator.checkpoints.Load(ctx, request.BuildID, request.Generation)
	if err != nil {
		return Result{}, err
	}
	started := orchestrator.clock().UTC()
	if found {
		if checkpoint.RequestDigest != requestDigest {
			return Result{}, errors.New("build generation was already bound to another request")
		}
		parsed, parseErr := time.Parse(time.RFC3339Nano, checkpoint.StartedAt)
		if parseErr != nil {
			return Result{}, errors.New("build checkpoint start time is invalid")
		}
		started = parsed.UTC()
	}
	if err := request.Validate(started); err != nil {
		return Result{}, err
	}
	stream := &eventStream{request: request, clock: orchestrator.clock, emit: emit}
	if err := stream.send("accepted", "accepted", "Build request accepted"); err != nil {
		return Result{}, err
	}
	if !found {
		checkpoint = Checkpoint{
			Version: 1, BuildID: request.BuildID, Generation: request.Generation, RequestDigest: requestDigest,
			StartedAt: started.Format(time.RFC3339Nano), Partial: Result{}, UpdatedAt: started.Format(time.RFC3339Nano),
		}
		if err := orchestrator.checkpoints.Save(ctx, checkpoint); err != nil {
			return Result{}, err
		}
	}
	if checkpoint.Envelope.Payload.BuildID != "" {
		if err := validateCheckpoint(checkpoint, request); err != nil {
			return Result{}, err
		}
		if err := stream.send("resuming", "progress", "Recovering the exact signed BuildCell assignment"); err != nil {
			return Result{}, err
		}
		cellResult, err := orchestrator.dispatcher.Execute(ctx, checkpoint.Envelope, stream.relay)
		if err != nil {
			return Result{}, err
		}
		result, err := mapCellResult(request, started, checkpoint.Partial, cellResult)
		if err != nil {
			return Result{}, err
		}
		if err := stream.terminal(result); err != nil {
			return Result{}, err
		}
		return result, nil
	}
	workspace, err := os.MkdirTemp(orchestrator.scratch, "lrail-orchestrator-*")
	if err != nil {
		return Result{}, errors.New("create build orchestration scratch")
	}
	defer os.RemoveAll(workspace)
	snapshotRoot := filepath.Join(workspace, "source")
	if err := stream.send("materializing", "progress", "Materializing immutable source snapshot"); err != nil {
		return Result{}, err
	}
	if err := orchestrator.content.Materialize(ctx, request.Source, snapshotRoot); err != nil {
		if ctx.Err() != nil {
			return orchestrator.finishFailure(stream, request, started, "canceled", "build_canceled", "Build was canceled during source materialization", Result{})
		}
		return orchestrator.finishFailure(stream, request, started, "failed", "source_archive_invalid", "Source snapshot could not be materialized", Result{})
	}

	if err := stream.send("detecting", "progress", "Detecting service configuration"); err != nil {
		return Result{}, err
	}
	detection, detectionBytes, err := orchestrator.detector.Detect(ctx, snapshotRoot, request.Source.SnapshotID, request.Source.SelectedRoot)
	if err != nil {
		if ctx.Err() != nil {
			return orchestrator.finishFailure(stream, request, started, "canceled", "build_canceled", "Build was canceled during detection", Result{})
		}
		return Result{}, err
	}
	detectionObject, err := orchestrator.put(ctx, request, "detector/result.json", "application/vnd.lrail.detector.v2+json", detectionBytes)
	if err != nil {
		return Result{}, err
	}
	partial := Result{DetectionDigest: detectionObject.Digest, DetectorResultRef: detectionObject.Reference}
	partial.Services = serviceResults(detection, nil)
	if request.Configuration.Mode == "auto" && (!request.Configuration.AcceptDetected || detection.Blocked) {
		return orchestrator.finishFailure(stream, request, started, "waiting", "detect_confirmation_required", "Detected configuration requires explicit confirmation", partial)
	}

	if err := stream.send("compiling", "progress", "Compiling accepted configuration into policy-locked BuildKit LLB"); err != nil {
		return Result{}, err
	}
	compilation, err := orchestrator.compiler.Compile(ctx, request, snapshotRoot, detection)
	if err != nil {
		if ctx.Err() != nil {
			return orchestrator.finishFailure(stream, request, started, "canceled", "build_canceled", "Build was canceled during compilation", partial)
		}
		code, message, deterministic := compilationFailure(err)
		if !deterministic {
			return Result{}, err
		}
		return orchestrator.finishFailure(stream, request, started, "failed", code, message, partial)
	}
	manifestBytes, err := acceptedManifestBytes(request, detection, compilation.Program)
	if err != nil {
		return Result{}, err
	}
	manifestObject, err := orchestrator.put(ctx, request, "configuration/manifest.json", "application/vnd.lrail.manifest.v1+json", manifestBytes)
	if err != nil {
		return Result{}, err
	}
	programObject, err := orchestrator.put(ctx, request, "configuration/Lrailfile.star", "text/x-starlark", compilation.Program)
	if err != nil {
		return Result{}, err
	}
	irObject, err := orchestrator.put(ctx, request, "build/build-ir.json", "application/vnd.lrail.build-ir.v2+json", compilation.IRBytes)
	if err != nil {
		return Result{}, err
	}
	lockObject, err := orchestrator.put(ctx, request, "build/definition-lock.json", "application/vnd.lrail.definition-lock.v2+json", compilation.LockBytes)
	if err != nil {
		return Result{}, err
	}
	partial.ManifestDigest = manifestObject.Digest
	partial.ManifestRef = manifestObject.Reference
	partial.GeneratedBuildRef = programObject.Reference
	partial.BuildIRDigest = irObject.Digest
	partial.BuildIRRef = irObject.Reference
	partial.DefinitionDigest = compilation.DefinitionDigest
	partial.DefinitionLockRef = lockObject.Reference
	partial.Services = serviceResults(detection, compilation.Outputs)

	if err := stream.send("assigning", "progress", "Preparing signed isolated BuildCell assignment"); err != nil {
		return Result{}, err
	}
	cellSource, err := orchestrator.content.MirrorSource(ctx, request.Source, orchestrator.objectName(request, "source/archive.tar.gz", request.Source.ArchiveDigest))
	if err != nil {
		return Result{}, err
	}
	if cellSource.SnapshotDigest != request.Source.SnapshotDigest || cellSource.ArchiveDigest != request.Source.ArchiveDigest || cellSource.SizeBytes != request.Source.SizeBytes {
		return Result{}, errors.New("mirrored source identity changed")
	}
	assignmentOutputs := make([]buildcell.OutputArtifact, 0, len(compilation.Outputs))
	for _, output := range compilation.Outputs {
		definitionObject, putErr := orchestrator.put(ctx, request, "outputs/"+output.Name+"/llb.pb", "application/vnd.buildkit.llb+protobuf", output.Definition)
		if putErr != nil {
			return Result{}, putErr
		}
		configBytes, configErr := outputConfig(output)
		if configErr != nil {
			return Result{}, configErr
		}
		configObject, putErr := orchestrator.put(ctx, request, "outputs/"+output.Name+"/config.json", "application/vnd.oci.image.config.v1+json", configBytes)
		if putErr != nil {
			return Result{}, putErr
		}
		locked, found := lockedOutput(compilation.Lock, output.Name)
		if !found || definitionObject.Digest != output.LLBDigest || configObject.Digest != locked.ConfigDigest {
			return Result{}, errors.New("compiled output changed while entering immutable content storage")
		}
		assignmentOutputs = append(assignmentOutputs, buildcell.OutputArtifact{
			Name: output.Name, Kind: output.Kind, LLBDigest: output.LLBDigest, Head: output.Head,
			LLBRef: definitionObject.Reference, ConfigDigest: configObject.Digest, ConfigRef: configObject.Reference,
		})
	}
	nonce, err := orchestrator.nonce()
	if err != nil || !noncePattern.MatchString(nonce) {
		return Result{}, errors.New("generate build assignment nonce")
	}
	deadline, _ := time.Parse(time.RFC3339Nano, request.Deadline)
	issuedAt := started.Truncate(time.Second)
	expiresAt := issuedAt.Add(orchestrator.assignmentTTL)
	if deadline.Before(expiresAt) {
		expiresAt = deadline.Truncate(time.Second)
	}
	if !expiresAt.After(issuedAt) {
		return Result{}, errors.New("build assignment deadline is outside the accepted window")
	}
	payload := buildcell.Payload{
		Version: buildcell.CurrentAssignmentVersion, BuildID: request.BuildID, CellID: orchestrator.cellID,
		OrganizationID: request.OrganizationID, ProjectID: request.ProjectID, OperationID: request.OperationID,
		Generation: request.Generation, Nonce: nonce, IssuedAt: issuedAt.Format(time.RFC3339), ExpiresAt: expiresAt.Format(time.RFC3339),
		DefinitionDigest: compilation.DefinitionDigest, Lock: compilation.Lock, Source: cellSource, Outputs: assignmentOutputs,
	}
	envelope, assignmentDigest, err := orchestrator.sign(ctx, payload)
	if err != nil {
		return Result{}, err
	}
	partial.AssignmentDigest = assignmentDigest
	checkpoint.Partial = partial
	checkpoint.Envelope = envelope
	checkpoint.UpdatedAt = orchestrator.clock().UTC().Format(time.RFC3339Nano)
	if err := orchestrator.checkpoints.Save(ctx, checkpoint); err != nil {
		return Result{}, err
	}
	if err := stream.send("assigned", "progress", "Signed BuildCell assignment accepted for dispatch"); err != nil {
		return Result{}, err
	}

	cellResult, err := orchestrator.dispatcher.Execute(ctx, envelope, stream.relay)
	if err != nil {
		return Result{}, err
	}
	result, err := mapCellResult(request, started, partial, cellResult)
	if err != nil {
		return Result{}, err
	}
	if err := stream.terminal(result); err != nil {
		return Result{}, err
	}
	return result, nil
}

func validateCheckpoint(checkpoint Checkpoint, request Request) error {
	payload := checkpoint.Envelope.Payload
	if checkpoint.Version != 1 || checkpoint.BuildID != request.BuildID || checkpoint.Generation != request.Generation ||
		payload.BuildID != request.BuildID || payload.Generation != request.Generation || payload.OrganizationID != request.OrganizationID ||
		payload.ProjectID != request.ProjectID || payload.OperationID != request.OperationID || payload.Source.SnapshotDigest != request.Source.SnapshotDigest ||
		checkpoint.Partial.AssignmentDigest == "" || checkpoint.Partial.AssignmentDigest != digestCanonicalPayload(payload) {
		return errors.New("build checkpoint is inconsistent with its immutable request")
	}
	return nil
}

func digestCanonicalPayload(payload buildcell.Payload) string {
	contents, err := canonicaljson.Marshal(payload)
	if err != nil {
		return ""
	}
	return digestBytes(contents)
}

func (orchestrator *Orchestrator) Cancel(ctx context.Context, buildID string, generation uint64, reason string) (bool, error) {
	identity, err := platformid.Parse(buildID)
	if ctx == nil || err != nil || identity.Prefix() != "bld" || generation == 0 || reason == "" || len(reason) > 512 {
		return false, errors.New("build cancellation request is invalid")
	}
	return orchestrator.dispatcher.Cancel(ctx, buildID, generation, reason)
}

func (orchestrator *Orchestrator) put(ctx context.Context, request Request, suffix, mediaType string, contents []byte) (StoredObject, error) {
	if len(contents) == 0 || len(contents) > MaxStoredObjectBytes {
		return StoredObject{}, errors.New("immutable build object is absent or oversized")
	}
	digest := digestBytes(contents)
	object, err := orchestrator.content.PutImmutable(ctx, orchestrator.objectName(request, suffix, digest), mediaType, contents)
	if err != nil {
		return StoredObject{}, err
	}
	if object.Digest != digest || object.Size != int64(len(contents)) || !strings.HasPrefix(object.Reference, "s3://") {
		return StoredObject{}, errors.New("immutable content store returned a changed object identity")
	}
	return object, nil
}

func (orchestrator *Orchestrator) objectName(request Request, suffix, digest string) string {
	cleanDigest := strings.TrimPrefix(digest, "sha256:")
	name := fmt.Sprintf("builds/%s/g%d/%s/%s", request.BuildID, request.Generation, cleanDigest, suffix)
	if len(name) > 1024 || !objectPartPattern.MatchString(name) || strings.Contains(name, "..") {
		panic("owned build object name is invalid")
	}
	return name
}

func (orchestrator *Orchestrator) sign(ctx context.Context, payload buildcell.Payload) (buildcell.Envelope, string, error) {
	canonical, err := canonicaljson.Marshal(payload)
	if err != nil {
		return buildcell.Envelope{}, "", errors.New("canonicalize build assignment")
	}
	material, err := orchestrator.signer.Sign(ctx, canonical)
	if err != nil {
		return buildcell.Envelope{}, "", err
	}
	publicDigest, err := buildsupply.VerifySignature(material.PublicKeyPEM, canonical, material.Signature)
	if err != nil || material.KeyID != orchestrator.assignmentKeyID || material.KeyVersion < 1 ||
		material.Algorithm != buildsupply.SignatureAlgorithm || publicDigest != orchestrator.assignmentKey {
		return buildcell.Envelope{}, "", errors.New("assignment signing authority returned an untrusted identity")
	}
	return buildcell.Envelope{
		KeyID: material.KeyID, Payload: payload, Signature: base64.RawURLEncoding.EncodeToString(material.Signature),
	}, digestBytes(canonical), nil
}

func (orchestrator *Orchestrator) finishFailure(stream *eventStream, request Request, started time.Time, state, code, message string, partial Result) (Result, error) {
	partial.Version = CurrentResultVersion
	partial.BuildID = request.BuildID
	partial.Generation = request.Generation
	partial.State = state
	partial.SourceSnapshotID = request.Source.SnapshotID
	partial.SourceDigest = request.Source.SnapshotDigest
	partial.Outputs = []OutputResult{}
	if partial.Services == nil {
		partial.Services = []ServiceResult{}
	}
	partial.FailureCode = code
	partial.FailureMessage = message
	partial.StartedAt = started.Format(time.RFC3339Nano)
	partial.FinishedAt = orchestrator.clock().UTC().Format(time.RFC3339Nano)
	partial.Cleanup = CleanupResult{Status: "clean"}
	if err := partial.Validate(); err != nil {
		return Result{}, err
	}
	if err := stream.terminal(partial); err != nil {
		return Result{}, err
	}
	return partial, nil
}

func serviceResults(detection DetectionResult, outputs []llbcompiler.OutputDefinition) []ServiceResult {
	detected := make(map[string]DetectedService, len(detection.Services))
	for _, service := range detection.Services {
		detected[service.Name] = service
	}
	names := make([]string, 0)
	if len(outputs) == 0 {
		for _, service := range detection.Services {
			names = append(names, service.Name)
		}
	} else {
		for _, output := range outputs {
			names = append(names, output.Name)
		}
	}
	slices.Sort(names)
	result := make([]ServiceResult, 0, len(names))
	for _, name := range names {
		service, found := detected[name]
		if !found {
			kind := "web"
			for _, output := range outputs {
				if output.Name == name && output.Kind == "static_bundle" {
					kind = "static"
				}
			}
			result = append(result, ServiceResult{
				Name: name, Root: ".", Kind: kind, Language: "docker", Framework: "Custom Starlark",
				Build:     BuildResult{Strategy: "starlark", InstallCommand: []string{}, BuildCommand: []string{}, CachePaths: []string{}},
				Processes: []ProcessResult{{Name: "web", Kind: kind, Command: []string{"platform-defined"}, Protocol: "none"}},
			})
			continue
		}
		processes := make([]ProcessResult, 0, len(service.Processes))
		for _, process := range service.Processes {
			health := ""
			if process.HealthPath != nil {
				health = *process.HealthPath
			}
			processes = append(processes, ProcessResult{
				Name: process.Name, Kind: process.Kind, Command: append([]string(nil), process.Command...),
				Port: process.Port, Protocol: process.Protocol, HealthPath: health,
			})
		}
		runtimeVersion := ""
		if service.Runtime.Version != nil {
			runtimeVersion = *service.Runtime.Version
		}
		outputPath := ""
		if service.Build.OutputPath != nil {
			outputPath = *service.Build.OutputPath
		}
		result = append(result, ServiceResult{
			Name: service.Name, Root: service.Root, Kind: service.Kind, Language: service.Language,
			Framework: service.Framework, RuntimeVersion: runtimeVersion,
			Build: BuildResult{
				Strategy: service.Build.Strategy, InstallCommand: append([]string(nil), service.Build.InstallCommand...),
				BuildCommand: append([]string(nil), service.Build.BuildCommand...), OutputPath: outputPath,
				CachePaths: append([]string(nil), service.Build.CachePaths...),
			}, Processes: processes,
		})
	}
	return result
}

func compilationFailure(err error) (string, string, bool) {
	var dslError *dsl.CompileError
	if errors.As(err, &dslError) {
		return "dsl_" + strings.TrimPrefix(dslError.Diagnostic.Code, "dsl."), dslError.Diagnostic.Message, true
	}
	var llbError *llbcompiler.CompileError
	if errors.As(err, &llbError) {
		return "dsl_" + strings.TrimPrefix(llbError.Code, "llb."), llbError.Message, true
	}
	if strings.Contains(err.Error(), "detector proposal") || strings.Contains(err.Error(), "detected configuration") {
		return "detect_confirmation_required", "Detected configuration cannot be compiled without confirmation", true
	}
	return "", "", false
}

func acceptedManifestBytes(request Request, detection DetectionResult, program []byte) ([]byte, error) {
	if request.Configuration.Mode == "repository" {
		return canonicaljson.Marshal(struct {
			Version       int    `json:"version"`
			Mode          string `json:"mode"`
			BuildFile     string `json:"build_file"`
			ProgramDigest string `json:"program_digest"`
		}{
			Version: 1, Mode: "repository", BuildFile: request.Configuration.BuildFile, ProgramDigest: digestBytes(program),
		})
	}
	decoder := json.NewDecoder(bytes.NewReader(detection.GeneratedManifest))
	decoder.UseNumber()
	var manifest any
	if err := decoder.Decode(&manifest); err != nil {
		return nil, errors.New("decode generated manifest")
	}
	return canonicaljson.Marshal(manifest)
}

func outputConfig(output llbcompiler.OutputDefinition) ([]byte, error) {
	if output.Kind == "oci_image" {
		return append([]byte(nil), output.ImageConfig...), nil
	}
	if output.Kind == "static_bundle" {
		return canonicaljson.Marshal(output.StaticHeaders)
	}
	return nil, errors.New("compiled output kind is unsupported")
}

func lockedOutput(lock llbcompiler.DefinitionLock, name string) (llbcompiler.OutputLock, bool) {
	for _, output := range lock.Outputs {
		if output.Name == name {
			return output, true
		}
	}
	return llbcompiler.OutputLock{}, false
}

func mapCellResult(request Request, started time.Time, partial Result, cell *lrailv1.BuildCellResult) (Result, error) {
	if cell == nil || cell.GetBuildId() != request.BuildID || cell.GetPayloadDigest() != partial.AssignmentDigest || cell.GetAttempts() == 0 {
		return Result{}, errors.New("BuildCell returned an inconsistent terminal identity")
	}
	state := "failed"
	switch cell.GetPhase() {
	case "complete":
		state = "complete"
	case "canceled":
		state = "canceled"
	case "failed", "quarantined":
	default:
		return Result{}, errors.New("BuildCell returned a non-terminal result")
	}
	result := partial
	result.Version = CurrentResultVersion
	result.BuildID = request.BuildID
	result.Generation = request.Generation
	result.State = state
	result.SourceSnapshotID = request.Source.SnapshotID
	result.SourceDigest = request.Source.SnapshotDigest
	result.StartedAt = started.Format(time.RFC3339Nano)
	result.FinishedAt = cell.GetFinishedAt()
	result.WorkerIdentity = cell.GetWorkerIdentity()
	result.LogsDigest = cell.GetLogsDigest()
	result.CacheHits = cell.GetCacheHits()
	result.CacheMisses = cell.GetCacheMisses()
	result.Cleanup = CleanupResult{
		Status: cell.GetCleanup().GetStatus(), ResidueCount: cell.GetCleanup().GetResidueCount(), QuarantineReason: cell.GetCleanup().GetQuarantineReason(),
	}
	result.Outputs = make([]OutputResult, 0, len(cell.GetOutputs()))
	for _, output := range cell.GetOutputs() {
		evidence := output.GetSupplyChain().GetEvidence()
		if len(evidence) != 5 {
			return Result{}, errors.New("BuildCell output lacks complete evidence")
		}
		slices.SortFunc(evidence, func(left, right *lrailv1.BuildEvidenceReference) int {
			return strings.Compare(left.GetKind(), right.GetKind())
		})
		var references [5]buildworker.EvidenceReference
		for index, reference := range evidence {
			references[index] = buildworker.EvidenceReference{
				Kind: reference.GetKind(), Reference: reference.GetReference(), ManifestDigest: reference.GetManifestDigest(), PayloadDigest: reference.GetPayloadDigest(),
			}
		}
		result.Outputs = append(result.Outputs, OutputResult{
			Name: output.GetName(), Kind: output.GetKind(), ArtifactRef: output.GetArtifactRef(), ArtifactDigest: output.GetArtifactDigest(),
			ArtifactSize: output.GetArtifactSize(), ConfigDigest: output.GetConfigDigest(), ManifestDigest: output.GetManifestDigest(),
			LayerDigests: append([]string(nil), output.GetLayerDigests()...), PublicationManifestRef: output.GetPublicationManifestRef(),
			SupplyChain: buildworker.SupplyChainResult{
				PolicyState: output.GetSupplyChain().GetPolicyState(), ScanState: output.GetSupplyChain().GetScanState(),
				PolicyDigest: output.GetSupplyChain().GetPolicyDigest(), SignerKeyID: output.GetSupplyChain().GetSignerKeyId(),
				SignerKeyVersion: int(output.GetSupplyChain().GetSignerKeyVersion()), SignerPublicKeyDigest: output.GetSupplyChain().GetSignerPublicKeyDigest(),
				Evidence: references,
			},
		})
	}
	slices.SortFunc(result.Outputs, func(left, right OutputResult) int { return strings.Compare(left.Name, right.Name) })
	if state != "complete" {
		result.FailureCode = normalizedCellFailure(cell.GetErrorCode(), state, cell.GetPhase())
		result.FailureMessage = "BuildCell reported a terminal " + cell.GetPhase() + " result"
	} else {
		result.FailureCode = ""
		result.FailureMessage = ""
	}
	if err := result.Validate(); err != nil {
		return Result{}, fmt.Errorf("BuildCell terminal result failed product validation: %w", err)
	}
	return result, nil
}

func normalizedCellFailure(value, state, phase string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = regexp.MustCompile(`[^a-z0-9_.-]`).ReplaceAllString(value, "_")
	if value == "" {
		value = phase
	}
	if state == "canceled" {
		return "build_canceled"
	}
	if phase == "quarantined" {
		return "build_cleanup_quarantined"
	}
	return "build_" + strings.Trim(value, "_")
}

type eventStream struct {
	request Request
	clock   func() time.Time
	emit    Emit
	next    uint64
}

func (stream *eventStream) send(stage, kind, message string) error {
	stream.next++
	event := Event{
		Version: CurrentEventVersion, BuildID: stream.request.BuildID, Generation: stream.request.Generation,
		Sequence: stream.next, Attempt: 1, Stage: stage, Kind: kind, Message: message,
		OccurredAt: stream.clock().UTC().Format(time.RFC3339Nano),
	}
	if err := event.Validate(); err != nil {
		return err
	}
	return stream.emit(event)
}

func (stream *eventStream) relay(cell *lrailv1.BuildCellEvent) error {
	if cell == nil {
		return errors.New("BuildCell emitted an absent event")
	}
	stream.next++
	stage := cell.GetPhase()
	if !stagePattern.MatchString(stage) {
		stage = "building"
	}
	kind := cell.GetKind()
	if cell.GetResult() != nil {
		kind = "cell_terminal"
	}
	if !eventKindPattern.MatchString(kind) {
		kind = "progress"
	}
	occurredAt := cell.GetOccurredAt()
	if _, err := time.Parse(time.RFC3339Nano, occurredAt); err != nil {
		occurredAt = stream.clock().UTC().Format(time.RFC3339Nano)
	}
	event := Event{
		Version: CurrentEventVersion, BuildID: stream.request.BuildID, Generation: stream.request.Generation,
		Sequence: stream.next, Attempt: max(cell.GetAttempt(), 1), Stage: stage, Kind: kind,
		Output: boundedText(cell.GetOutput(), 512), Vertex: boundedText(cell.GetVertex(), 512), Name: boundedText(cell.GetName(), 512),
		Current: cell.GetCurrent(), Total: cell.GetTotal(), Cached: cell.GetCached(), Stream: cell.GetStream(),
		Line: boundedText(cell.GetLine(), MaxEventLineBytes), Code: boundedText(cell.GetCode(), 128),
		Message: boundedText(cell.GetMessage(), MaxEventMessageBytes), OccurredAt: occurredAt,
	}
	if err := event.Validate(); err != nil {
		return err
	}
	return stream.emit(event)
}

func (stream *eventStream) terminal(result Result) error {
	stream.next++
	event := Event{
		Version: CurrentEventVersion, BuildID: stream.request.BuildID, Generation: stream.request.Generation,
		Sequence: stream.next, Attempt: 1, Stage: result.State, Kind: "terminal", Message: "Build reached a terminal result",
		OccurredAt: stream.clock().UTC().Format(time.RFC3339Nano), Terminal: &result,
	}
	if err := event.Validate(); err != nil {
		return err
	}
	return stream.emit(event)
}

func boundedText(value string, limit int) string {
	value = strings.ReplaceAll(strings.ToValidUTF8(value, "?"), "\x00", "")
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func digestBytes(contents []byte) string {
	digest := sha256.Sum256(contents)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func randomNonce() (string, error) {
	contents := make([]byte, 32)
	if _, err := rand.Read(contents); err != nil {
		return "", err
	}
	return hex.EncodeToString(contents), nil
}
