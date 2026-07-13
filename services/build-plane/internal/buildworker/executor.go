package buildworker

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/secrets/secretsprovider"
	"github.com/moby/buildkit/solver/pb"
	"github.com/tonistiigi/fsutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const DefaultSolveTimeout = time.Hour
const DefaultArtifactCommitTimeout = 15 * time.Minute

var ErrExecute = errors.New("build worker execution failed")

type BuildKitClient interface {
	Solve(ctx context.Context, definition *llb.Definition, options client.SolveOpt, status chan *client.SolveStatus) (*client.SolveResponse, error)
}

type BuildKitExecutor struct {
	client       BuildKitClient
	sources      SourceStore
	materializer SourceMaterializer
	cleaner      Cleaner
	committer    ArtifactCommitter
	caches       CacheProvider
	scratchRoot  string
	clock        func() time.Time
	solveTimeout time.Duration
	quota        ScratchQuota
}

func NewBuildKitExecutor(client BuildKitClient, sources SourceStore, cleaner Cleaner, committer ArtifactCommitter, caches CacheProvider, scratchRoot string, solveTimeout time.Duration) (*BuildKitExecutor, error) {
	if client == nil || sources == nil || cleaner == nil || committer == nil || caches == nil || scratchRoot == "" {
		return nil, fmt.Errorf("%w: worker dependencies are incomplete", ErrExecute)
	}
	if solveTimeout == 0 {
		solveTimeout = DefaultSolveTimeout
	}
	if solveTimeout <= 0 || solveTimeout > DefaultSolveTimeout {
		return nil, fmt.Errorf("%w: solve timeout is outside safety bounds", ErrExecute)
	}
	quota, err := normalizeScratchQuota(ScratchQuota{})
	if err != nil {
		return nil, fmt.Errorf("%w: scratch quota", ErrExecute)
	}
	return &BuildKitExecutor{
		client: client, sources: sources, materializer: TarGzipMaterializer{}, cleaner: cleaner, committer: committer, caches: caches,
		scratchRoot: scratchRoot, clock: time.Now, solveTimeout: solveTimeout, quota: quota,
	}, nil
}

func (executor *BuildKitExecutor) Execute(ctx context.Context, request Request) (result Result, resultErr error) {
	startedAt := executor.clock().UTC()
	if err := request.Assignment.Validate(); err != nil {
		return Result{Phase: PhaseFailed, ErrorCode: "assignment_invalid", StartedAt: startedAt, FinishedAt: startedAt},
			fmt.Errorf("%w: assignment proof", ErrExecute)
	}
	result = Result{
		BuildID: request.Assignment.Verified.Payload.BuildID,
		Attempt: request.Attempt,
		Phase:   PhaseMaterializing, Outputs: []OutputResult{}, StartedAt: startedAt,
	}
	if request.Attempt == 0 || request.Events == nil {
		return result, fmt.Errorf("%w: attempt and event sink are required", ErrExecute)
	}
	if err := validateSecrets(request.Assignment.Verified.Payload.Lock.Secrets, request.Secrets); err != nil {
		result.Phase = PhaseFailed
		result.ErrorCode = "secret_capability"
		return result, fmt.Errorf("%w: secret capability mismatch", ErrExecute)
	}
	redactor := NewRedactor(request.Secrets)
	defer redactor.Close()
	transcript := sha256.New()
	var transcriptErr error
	var sequence uint64
	var emitMutex sync.Mutex
	emit := func(event Event) {
		emitMutex.Lock()
		defer emitMutex.Unlock()
		sequence++
		event.Sequence = sequence
		event.Attempt = request.Attempt
		if event.OccurredAt.IsZero() {
			event.OccurredAt = executor.clock().UTC()
		}
		event.Line = redactor.RedactString(event.Line)
		event.Message = redactor.RedactString(event.Message)
		event.Name = redactor.RedactString(event.Name)
		encoded, err := canonicaljson.Marshal(event)
		if err != nil {
			transcriptErr = errors.New("encode structured build event")
		} else {
			writeDigestField(transcript, encoded)
		}
		request.Events(event)
	}
	emit(Event{Phase: PhaseMaterializing, Kind: "phase"})

	attemptDirectory := filepath.Join(executor.scratchRoot, request.Assignment.Verified.Payload.BuildID, fmt.Sprintf("attempt-%d", request.Attempt))
	defer func() {
		emit(Event{Phase: PhaseCleaning, Kind: "phase"})
		cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		result.Cleanup = executor.cleaner.Cleanup(cleanupContext, request.Assignment.Verified.Payload.BuildID)
		result.FinishedAt = executor.clock().UTC()
		if result.Cleanup.Status != CleanupClean {
			result.Phase = PhaseFailed
			if result.ErrorCode == "" {
				result.ErrorCode = "cleanup_failed"
			}
			if resultErr == nil {
				resultErr = fmt.Errorf("%w: cleanup did not prove a clean worker", ErrExecute)
			}
			emit(Event{Phase: PhaseFailed, Kind: "error", Code: "cleanup_failed", Message: "Worker residue cleanup failed; the worker is quarantined."})
			return
		}
		emit(Event{Phase: PhaseCleaning, Kind: "cleanup", Code: string(CleanupClean), Message: "Worker residue cleanup verified."})
		if resultErr == nil {
			result.Phase = PhaseComplete
			emit(Event{Phase: PhaseComplete, Kind: "phase"})
		}
		result.LogsDigest = "sha256:" + hex.EncodeToString(transcript.Sum(nil))
		if transcriptErr != nil && resultErr == nil {
			result.Phase = PhaseFailed
			result.ErrorCode = "event_digest"
			resultErr = fmt.Errorf("%w: structured event digest", ErrExecute)
		}
	}()
	if err := ensureFreshDirectory(attemptDirectory); err != nil {
		result.Phase = PhaseFailed
		result.ErrorCode = "scratch_prepare"
		resultErr = fmt.Errorf("%w: prepare scratch: %v", ErrExecute, err)
		return result, resultErr
	}
	executionContext, stopQuota, quotaViolations := monitorScratch(ctx, filepath.Join(executor.scratchRoot, request.Assignment.Verified.Payload.BuildID), executor.quota)
	quotaDone := make(chan struct{})
	go func() {
		defer close(quotaDone)
		for usage := range quotaViolations {
			emit(Event{Phase: PhaseFailed, Kind: "error", Code: "scratch_quota", Message: fmt.Sprintf("Scratch quota exceeded (%d bytes, %d inodes).", usage.Bytes, usage.Inodes)})
		}
	}()
	defer func() {
		stopQuota(nil)
		<-quotaDone
	}()

	sourceDirectory := filepath.Join(attemptDirectory, "source")
	if err := executor.materializer.Materialize(executionContext, executor.sources, request.Assignment.Verified.Payload.Source, sourceDirectory); err != nil {
		result.Phase = phaseForContext(executionContext)
		result.ErrorCode = "source_materialization"
		if errors.Is(context.Cause(executionContext), ErrScratchQuota) {
			result.Phase = PhaseFailed
			result.ErrorCode = "scratch_quota"
		} else if result.Phase == PhaseCanceled {
			result.ErrorCode = "canceled"
		}
		emit(Event{Phase: result.Phase, Kind: "error", Code: result.ErrorCode, Message: "Source materialization failed."})
		resultErr = fmt.Errorf("%w: source materialization", ErrExecute)
		if executionContext.Err() != nil {
			resultErr = fmt.Errorf("%w: source materialization: %w", ErrExecute, context.Cause(executionContext))
		}
		return result, resultErr
	}
	localFS, err := fsutil.NewFS(sourceDirectory)
	if err != nil {
		result.Phase = PhaseFailed
		result.ErrorCode = "source_filesystem"
		resultErr = fmt.Errorf("%w: source filesystem", ErrExecute)
		return result, resultErr
	}
	secretValues := copySecrets(request.Secrets)
	defer wipeSecrets(secretValues)
	secretAttachable := secretsprovider.FromMap(secretValues)

	result.Phase = PhaseSolving
	emit(Event{Phase: PhaseSolving, Kind: "phase"})
	for _, output := range request.Assignment.Outputs {
		if err := executionContext.Err(); err != nil {
			result.Phase = PhaseCanceled
			result.ErrorCode = "canceled"
			if errors.Is(context.Cause(executionContext), ErrScratchQuota) {
				result.Phase = PhaseFailed
				result.ErrorCode = "scratch_quota"
			}
			resultErr = fmt.Errorf("%w: canceled: %w", ErrExecute, context.Cause(executionContext))
			return result, resultErr
		}
		var definition llb.Definition
		wireDefinition := new(pb.Definition)
		if err := proto.Unmarshal(output.Definition, wireDefinition); err != nil {
			result.Phase = PhaseFailed
			result.ErrorCode = "definition_decode"
			resultErr = fmt.Errorf("%w: definition decode", ErrExecute)
			return result, resultErr
		}
		definition.FromPB(wireDefinition)
		exportDirectory := filepath.Join(attemptDirectory, "exports", output.Name)
		if err := os.MkdirAll(exportDirectory, 0o700); err != nil {
			result.Phase = PhaseFailed
			result.ErrorCode = "export_directory"
			resultErr = fmt.Errorf("%w: export directory", ErrExecute)
			return result, resultErr
		}
		exportEntry, artifactPath, exportErr := buildExportEntry(output, exportDirectory)
		if exportErr != nil {
			result.Phase = PhaseFailed
			result.ErrorCode = "export_configuration"
			resultErr = fmt.Errorf("%w: export configuration", ErrExecute)
			return result, resultErr
		}
		cacheLease, cacheErr := executor.caches.Acquire(executionContext, request.Assignment.Verified.Payload.Lock, result.BuildID, output.Name, result.Attempt)
		if cacheErr != nil {
			result.Phase = PhaseFailed
			result.ErrorCode = "cache_acquire"
			resultErr = fmt.Errorf("%w: cache capability", ErrExecute)
			return result, resultErr
		}
		cacheSucceeded := false
		defer func() {
			if err := cacheLease.Complete(cacheSucceeded); err != nil {
				result.Phase = PhaseFailed
				result.ErrorCode = "cache_commit"
				resultErr = fmt.Errorf("%w: cache commit", ErrExecute)
			}
		}()
		solveContext, cancel := context.WithTimeout(executionContext, executor.solveTimeout)
		statuses := make(chan *client.SolveStatus)
		statusDone := make(chan CacheStats, 1)
		go func() {
			statusDone <- executor.streamStatuses(statuses, output.Name, redactor, emit)
		}()
		emit(Event{Phase: PhaseSolving, Kind: "output_started", Output: output.Name})
		response, solveErr := executor.client.Solve(solveContext, &definition, client.SolveOpt{
			LocalMounts:  map[string]fsutil.FS{"lrail-source": localFS},
			Session:      []session.Attachable{secretAttachable},
			Exports:      []client.ExportEntry{exportEntry},
			CacheImports: cacheLease.Imports(),
			CacheExports: cacheLease.Exports(),
			Ref:          fmt.Sprintf("%s-%d-%s", result.BuildID, result.Attempt, output.Name),
		}, statuses)
		cancel()
		cacheStats := <-statusDone
		result.Cache.Hits += cacheStats.Hits
		result.Cache.Misses += cacheStats.Misses
		if solveErr != nil {
			result.Phase = phaseForContext(executionContext)
			result.ErrorCode = classifySolveError(solveErr, executionContext)
			if result.ErrorCode == "scratch_quota" {
				result.Phase = PhaseFailed
			}
			emit(Event{Phase: result.Phase, Kind: "error", Output: output.Name, Code: result.ErrorCode, Message: "Build solve failed."})
			resultErr = fmt.Errorf("%w: %s: %w", ErrExecute, result.ErrorCode, solveErr)
			return result, resultErr
		}
		if response == nil {
			result.Phase = PhaseFailed
			result.ErrorCode = "solve_response"
			resultErr = fmt.Errorf("%w: BuildKit returned no solve response", ErrExecute)
			return result, resultErr
		}
		artifactDigest, artifactSize, digestErr := exportedArtifactDigest(artifactPath, output.Kind)
		if digestErr != nil {
			result.Phase = PhaseFailed
			result.ErrorCode = "export_missing"
			emit(Event{Phase: result.Phase, Kind: "error", Output: output.Name, Code: result.ErrorCode, Message: "Exported artifact is absent or invalid."})
			resultErr = fmt.Errorf("%w: exported artifact", ErrExecute)
			return result, resultErr
		}
		ociIdentity := ociArtifactIdentity{LayerDigests: []string{}}
		if output.Kind == "oci_image" {
			ociIdentity, digestErr = validateOCIArtifact(artifactPath)
			if digestErr != nil {
				result.Phase = PhaseFailed
				result.ErrorCode = "export_invalid"
				emit(Event{Phase: result.Phase, Kind: "error", Output: output.Name, Code: result.ErrorCode, Message: "OCI export failed structural and descriptor validation."})
				resultErr = fmt.Errorf("%w: invalid OCI export: %w", ErrExecute, digestErr)
				return result, resultErr
			}
		}
		result.Phase = PhaseExporting
		emit(Event{Phase: PhaseExporting, Kind: "artifact_commit_started", Output: output.Name})
		commitContext, commitCancel := context.WithTimeout(executionContext, DefaultArtifactCommitTimeout)
		committed, commitErr := executor.committer.Commit(commitContext, ExportedArtifact{
			OrganizationID: request.Assignment.Verified.Payload.OrganizationID,
			ProjectID:      request.Assignment.Verified.Payload.ProjectID,
			BuildID:        result.BuildID, Attempt: result.Attempt, OutputName: output.Name, Kind: output.Kind,
			Path: artifactPath, Digest: artifactDigest, Size: artifactSize,
		})
		commitCancel()
		if commitErr != nil || committed.Reference == "" || committed.Digest != artifactDigest || committed.Size != artifactSize ||
			(output.Kind == "oci_image" && committed.ManifestDigest != "" && committed.ManifestDigest != ociIdentity.ManifestDigest) {
			result.Phase = phaseForContext(executionContext)
			result.ErrorCode = "artifact_commit"
			emit(Event{Phase: result.Phase, Kind: "error", Output: output.Name, Code: result.ErrorCode, Message: "Exported artifact could not be committed."})
			resultErr = fmt.Errorf("%w: artifact commit", ErrExecute)
			if commitErr != nil {
				resultErr = fmt.Errorf("%w: artifact commit: %w", ErrExecute, commitErr)
			}
			if executionContext.Err() != nil {
				resultErr = fmt.Errorf("%w: artifact commit: %w", ErrExecute, context.Cause(executionContext))
			}
			return result, resultErr
		}
		emit(Event{Phase: PhaseExporting, Kind: "output_complete", Output: output.Name})
		manifestDigest := ociIdentity.ManifestDigest
		if committed.ManifestDigest != "" {
			manifestDigest = committed.ManifestDigest
		}
		result.Outputs = append(result.Outputs, OutputResult{
			Name: output.Name, Kind: output.Kind, ArtifactRef: committed.Reference, ArtifactPath: committed.Path,
			ArtifactDigest: committed.Digest, ArtifactSize: committed.Size, ConfigDigest: digestContents(output.Config),
			ManifestDigest: manifestDigest, PublicationManifestRef: committed.PublicationManifestRef,
			LayerDigests:     append([]string{}, ociIdentity.LayerDigests...),
			ExporterResponse: cloneStringMap(response.ExporterResponse),
		})
		cacheSucceeded = true
	}
	if errors.Is(context.Cause(executionContext), ErrScratchQuota) {
		result.Phase = PhaseFailed
		result.ErrorCode = "scratch_quota"
		return result, fmt.Errorf("%w: %w", ErrExecute, context.Cause(executionContext))
	}
	return result, nil
}

func (executor *BuildKitExecutor) streamStatuses(statuses <-chan *client.SolveStatus, output string, redactor *Redactor, emit func(Event)) CacheStats {
	completed := make(map[string]bool)
	for status := range statuses {
		if status == nil {
			continue
		}
		for _, vertex := range status.Vertexes {
			occurredAt := executor.clock().UTC()
			kind := "vertex"
			if vertex.Started != nil {
				occurredAt = vertex.Started.UTC()
				kind = "vertex_started"
			}
			if vertex.Completed != nil {
				occurredAt = vertex.Completed.UTC()
				kind = "vertex_completed"
				completed[string(vertex.Digest)] = vertex.Cached
			}
			emit(Event{Phase: PhaseSolving, Kind: kind, Output: output, Vertex: string(vertex.Digest), Name: vertex.Name, Cached: vertex.Cached, Message: vertex.Error, OccurredAt: occurredAt})
		}
		for _, progress := range status.Statuses {
			emit(Event{Phase: PhaseSolving, Kind: "status", Output: output, Vertex: string(progress.Vertex), Name: progress.Name, Current: progress.Current, Total: progress.Total, OccurredAt: progress.Timestamp.UTC()})
		}
		for _, log := range status.Logs {
			for _, line := range redactor.Push(streamKey(string(log.Vertex), log.Stream), log.Data) {
				emit(Event{Phase: PhaseSolving, Kind: "log", Output: output, Vertex: string(log.Vertex), Stream: log.Stream, Line: line, OccurredAt: log.Timestamp.UTC()})
			}
		}
		for _, warning := range status.Warnings {
			emit(Event{Phase: PhaseSolving, Kind: "warning", Output: output, Vertex: string(warning.Vertex), Message: string(warning.Short)})
		}
	}
	flushed := redactor.Flush()
	keys := make([]string, 0, len(flushed))
	for key := range flushed {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, line := range flushed[key] {
			emit(Event{Phase: PhaseSolving, Kind: "log", Output: output, Line: line})
		}
	}
	result := CacheStats{}
	for _, cached := range completed {
		if cached {
			result.Hits++
		} else {
			result.Misses++
		}
	}
	return result
}

func ensureFreshDirectory(directory string) error {
	if err := os.RemoveAll(directory); err != nil {
		return err
	}
	return os.MkdirAll(directory, 0o700)
}

func copySecrets(values map[string][]byte) map[string][]byte {
	result := make(map[string][]byte, len(values))
	for key, value := range values {
		result[key] = append([]byte(nil), value...)
	}
	return result
}

func wipeSecrets(values map[string][]byte) {
	for key, value := range values {
		for index := range value {
			value[index] = 0
		}
		delete(values, key)
	}
}

func cloneStringMap(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func phaseForContext(ctx context.Context) Phase {
	if ctx.Err() != nil {
		return PhaseCanceled
	}
	return PhaseFailed
}

func classifySolveError(err error, ctx context.Context) string {
	if errors.Is(context.Cause(ctx), ErrScratchQuota) {
		return "scratch_quota"
	}
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "solve_timeout"
	}
	if code := status.Code(err); code == codes.Unavailable || code == codes.Aborted {
		return "worker_lost"
	}
	return "solve_failed"
}

func buildExportEntry(output buildcell.ResolvedOutput, exportDirectory string) (client.ExportEntry, string, error) {
	if output.Kind == "static_bundle" {
		return client.ExportEntry{Type: client.ExporterLocal, OutputDir: exportDirectory}, exportDirectory, nil
	}
	if output.Kind != "oci_image" || len(output.Config) == 0 {
		return client.ExportEntry{}, "", errors.New("unsupported output kind or empty OCI config")
	}
	artifactPath := filepath.Join(exportDirectory, "artifact.oci.tar")
	return client.ExportEntry{
		Type:  client.ExporterOCI,
		Attrs: map[string]string{exptypes.ExporterImageConfigKey: string(output.Config)},
		Output: func(_ map[string]string) (io.WriteCloser, error) {
			return os.OpenFile(artifactPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		},
	}, artifactPath, nil
}

func exportedArtifactDigest(artifactPath, kind string) (string, int64, error) {
	if kind == "oci_image" {
		return fileDigest(artifactPath)
	}
	return directoryDigest(artifactPath)
}

func ExportedArtifactIdentity(artifactPath, kind string) (string, int64, error) {
	if kind != "oci_image" && kind != "static_bundle" {
		return "", 0, errors.New("exported artifact kind is invalid")
	}
	return exportedArtifactDigest(artifactPath, kind)
}

func fileDigest(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil || size <= 0 {
		return "", 0, errors.New("artifact is empty or unreadable")
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), size, nil
}

func digestContents(contents []byte) string {
	digest := sha256.Sum256(contents)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func directoryDigest(root string) (string, int64, error) {
	type entry struct {
		path string
		mode os.FileMode
		size int64
	}
	entries := make([]entry, 0)
	var total int64
	err := filepath.WalkDir(root, func(path string, directory os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if directory.Type()&os.ModeSymlink != 0 {
			return errors.New("static export contains a symlink")
		}
		if directory.IsDir() {
			return nil
		}
		if !directory.Type().IsRegular() {
			return errors.New("static export contains a non-regular file")
		}
		info, err := directory.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == "." || strings.HasPrefix(relative, "..") {
			return errors.New("static export escaped its root")
		}
		entries = append(entries, entry{path: filepath.ToSlash(relative), mode: normalizedArtifactMode(info.Mode()), size: info.Size()})
		total += info.Size()
		return nil
	})
	if err != nil || len(entries) == 0 {
		return "", 0, errors.New("static export is empty or invalid")
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].path < entries[right].path })
	hash := sha256.New()
	for _, item := range entries {
		writeDigestField(hash, []byte(item.path))
		var numbers [16]byte
		binary.BigEndian.PutUint64(numbers[:8], uint64(item.mode))
		binary.BigEndian.PutUint64(numbers[8:], uint64(item.size))
		_, _ = hash.Write(numbers[:])
		file, err := os.Open(filepath.Join(root, filepath.FromSlash(item.path)))
		if err != nil {
			return "", 0, err
		}
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return "", 0, errors.New("hash static export")
		}
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), total, nil
}

func normalizedArtifactMode(mode os.FileMode) os.FileMode {
	if mode.Perm()&0o111 != 0 {
		return 0o555
	}
	return 0o444
}

func writeDigestField(writer io.Writer, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}

func validateSecrets(capabilities []llbcompiler.SecretCapability, values map[string][]byte) error {
	allowed := make(map[string]llbcompiler.SecretCapability, len(capabilities))
	for _, capability := range capabilities {
		allowed[capability.MountID] = capability
	}
	for key, value := range values {
		if _, exists := allowed[key]; !exists || len(value) == 0 || len(value) > secretsprovider.MaxSecretSize {
			return errors.New("secret set contains an unknown, empty, or oversized value")
		}
	}
	for key, capability := range allowed {
		if _, exists := values[key]; capability.Required && !exists {
			return errors.New("required secret is absent")
		}
	}
	return nil
}
