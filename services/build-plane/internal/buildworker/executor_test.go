package buildworker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	"github.com/moby/buildkit/solver/pb"
	"github.com/opencontainers/go-digest"
	imagespecs "github.com/opencontainers/image-spec/specs-go"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"google.golang.org/protobuf/proto"
)

const testCellID = "cell_019b01da-7e31-7000-8000-000000000002"
const testProjectID = "prj_019b01da-7e31-7000-8000-000000000004"
const testOperationID = "op_019b01da-7e31-7000-8000-000000000005"
const testPolicyDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

var workerNow = time.Date(2026, 7, 13, 2, 0, 0, 0, time.UTC)
var workerPrivateKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x24}, ed25519.SeedSize))

type workerArtifactStore map[string][]byte

func (store workerArtifactStore) Open(_ context.Context, reference string, _ int64) (io.ReadCloser, error) {
	contents, exists := store[reference]
	if !exists {
		return nil, errors.New("missing fake artifact")
	}
	return io.NopCloser(bytes.NewReader(contents)), nil
}

func resolvedWorkerAssignment(t *testing.T, kind string, secrets []llbcompiler.SecretCapability) (buildcell.ResolvedAssignment, []byte) {
	t.Helper()
	archive, source := sourceArchive(t, map[string]string{"input.txt": "source"})
	state := llb.Scratch().File(llb.Mkfile("/result.txt", 0o644, []byte("result")))
	network := []llbcompiler.NetworkCapability{}
	if len(secrets) > 0 {
		runOptions := []llb.RunOption{
			llb.Args([]string{"/bin/true"}), llb.Network(pb.NetMode_NONE),
			llb.WithCustomName("lrail run n1 network=none gateway= hosts="),
		}
		for _, secret := range secrets {
			target := secret.Target
			secretOptions := []llb.SecretOption{llb.SecretID(secret.MountID), llb.SecretFileOpt(0, 0, 0o400)}
			if !secret.Required {
				secretOptions = append(secretOptions, llb.SecretOptional)
			}
			runOptions = append(runOptions, llb.AddSecretWithDest(secret.MountID, &target, secretOptions...))
		}
		state = state.Run(runOptions...).Root()
		network = append(network, llbcompiler.NetworkCapability{NodeID: "n1", Profile: "none", Hosts: []string{}})
	}
	definition, err := state.Marshal(context.Background(), llb.Platform(ocispecs.Platform{OS: "linux", Architecture: "amd64"}))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	head, err := definition.Head()
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	definitionBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(definition.ToPB())
	if err != nil {
		t.Fatalf("Marshal definition: %v", err)
	}
	config := []byte(`{"architecture":"amd64","config":{"Cmd":["/bin/true"]},"os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
	outputName := "site"
	if kind == "oci_image" {
		outputName = "api"
	}
	lock := llbcompiler.DefinitionLock{
		Version: llbcompiler.CurrentLockVersion, CompilerVersion: "0.1.0",
		IRDigest: testIRDigest, PolicyDigest: testPolicyDigest, SourceSnapshot: testSnapshotDigest,
		TargetPlatform: "linux/amd64", BuildArguments: []llbcompiler.NameValue{},
		BaseMaterials: []llbcompiler.BaseMaterial{}, Network: network,
		Caches: []llbcompiler.CacheCapability{}, Secrets: secrets,
		Outputs: []llbcompiler.OutputLock{{
			Name: outputName, Kind: kind, StateID: "n1",
			LLBDigest: digestBytes(definitionBytes), ConfigDigest: digestBytes(config),
		}},
	}
	definitionDigest, err := llbcompiler.LockDigest(lock)
	if err != nil {
		t.Fatalf("LockDigest: %v", err)
	}
	output := buildcell.OutputArtifact{
		Name: outputName, Kind: kind, LLBDigest: digestBytes(definitionBytes), Head: string(head),
		LLBRef:       testObjectPrefix + "definitions/" + outputName + ".llb",
		ConfigDigest: digestBytes(config), ConfigRef: testObjectPrefix + "definitions/" + outputName + ".config.json",
	}
	payload := buildcell.Payload{
		Version: buildcell.CurrentAssignmentVersion, BuildID: testBuildID, CellID: testCellID,
		OrganizationID: testOrgID, ProjectID: testProjectID, OperationID: testOperationID,
		Generation: 1, Nonce: strings.Repeat("d", 64), IssuedAt: workerNow.Format(time.RFC3339),
		ExpiresAt: workerNow.Add(30 * time.Minute).Format(time.RFC3339), DefinitionDigest: definitionDigest,
		Lock: lock, Source: source, Outputs: []buildcell.OutputArtifact{output},
	}
	envelope, err := buildcell.Sign(payload, "worker-test-v1", workerPrivateKey)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	verifier, err := buildcell.NewVerifier(buildcell.VerifierOptions{
		CellID:       testCellID,
		Keys:         map[string]ed25519.PublicKey{"worker-test-v1": workerPrivateKey.Public().(ed25519.PublicKey)},
		ObjectPrefix: testObjectPrefix, Clock: func() time.Time { return workerNow },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	verified, err := verifier.Verify(envelope)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	store := workerArtifactStore{
		output.LLBRef: definitionBytes, output.ConfigRef: config,
	}
	resolved, err := buildcell.Resolve(context.Background(), verified, store)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return resolved, archive
}

type fakeBuildKitClient struct {
	mu    sync.Mutex
	calls int
	solve func(context.Context, *llb.Definition, client.SolveOpt, chan *client.SolveStatus) (*client.SolveResponse, error)
}

func (fake *fakeBuildKitClient) Solve(ctx context.Context, definition *llb.Definition, options client.SolveOpt, statuses chan *client.SolveStatus) (*client.SolveResponse, error) {
	fake.mu.Lock()
	fake.calls++
	fake.mu.Unlock()
	return fake.solve(ctx, definition, options, statuses)
}

type cleanerFunc func(context.Context, string) CleanupReport

func (function cleanerFunc) Cleanup(ctx context.Context, buildID string) CleanupReport {
	return function(ctx, buildID)
}

type committerFunc func(context.Context, ExportedArtifact) (CommittedArtifact, error)

func (function committerFunc) Commit(ctx context.Context, artifact ExportedArtifact) (CommittedArtifact, error) {
	return function(ctx, artifact)
}

type eventRecorder struct {
	mu     sync.Mutex
	events []Event
}

func (recorder *eventRecorder) Push(event Event) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.events = append(recorder.events, event)
}

func (recorder *eventRecorder) Snapshot() []Event {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return append([]Event(nil), recorder.events...)
}

func successfulFakeSolve(kind string, artifact []byte, secret []byte) func(context.Context, *llb.Definition, client.SolveOpt, chan *client.SolveStatus) (*client.SolveResponse, error) {
	return func(_ context.Context, _ *llb.Definition, options client.SolveOpt, statuses chan *client.SolveStatus) (*client.SolveResponse, error) {
		defer close(statuses)
		if len(options.LocalMounts) != 1 || options.LocalMounts["lrail-source"] == nil || len(options.Session) != 1 || len(options.Exports) != 1 {
			return nil, errors.New("incomplete solve options")
		}
		now := workerNow
		vertexDigest := digest.FromString("fake vertex")
		statuses <- &client.SolveStatus{Vertexes: []*client.Vertex{{Digest: vertexDigest, Name: "build " + string(secret), Started: &now}}}
		completed := now.Add(time.Millisecond)
		statuses <- &client.SolveStatus{Vertexes: []*client.Vertex{{Digest: vertexDigest, Name: "build " + string(secret), Started: &now, Completed: &completed, Cached: false}}}
		statuses <- &client.SolveStatus{Logs: []*client.VertexLog{{Vertex: vertexDigest, Stream: 1, Data: append([]byte("log "), secret[:len(secret)/2]...), Timestamp: now}}}
		statuses <- &client.SolveStatus{Logs: []*client.VertexLog{{Vertex: vertexDigest, Stream: 1, Data: append(append([]byte(nil), secret[len(secret)/2:]...), '\n'), Timestamp: now}}}
		export := options.Exports[0]
		if kind == "static_bundle" {
			if export.Type != client.ExporterLocal || export.OutputDir == "" {
				return nil, errors.New("invalid local exporter")
			}
			if err := os.WriteFile(filepath.Join(export.OutputDir, "index.html"), artifact, 0o644); err != nil {
				return nil, err
			}
		} else {
			if export.Type != client.ExporterOCI || export.Output == nil || export.Attrs[exptypes.ExporterImageConfigKey] == "" {
				return nil, errors.New("invalid OCI exporter")
			}
			writer, err := export.Output(map[string]string{"mediaType": "application/vnd.oci.image.manifest.v1+json"})
			if err != nil {
				return nil, err
			}
			if _, err := writer.Write(artifact); err != nil {
				_ = writer.Close()
				return nil, err
			}
			if err := writer.Close(); err != nil {
				return nil, err
			}
		}
		return &client.SolveResponse{ExporterResponse: map[string]string{"fake.result": "ok"}}, nil
	}
}

func executorHarness(t *testing.T, client BuildKitClient, archive []byte, cleanupStatus CleanupStatus, solveTimeout time.Duration) (*BuildKitExecutor, string) {
	t.Helper()
	scratchRoot := filepath.Join(t.TempDir(), "scratch")
	artifactRoot := filepath.Join(t.TempDir(), "artifacts")
	committer, err := NewDirectoryArtifactCommitter(artifactRoot, 0)
	if err != nil {
		t.Fatalf("NewDirectoryArtifactCommitter: %v", err)
	}
	t.Cleanup(func() { removeArtifactTree(artifactRoot) })
	cleaner := cleanerFunc(func(_ context.Context, buildID string) CleanupReport {
		_ = os.RemoveAll(filepath.Join(scratchRoot, buildID))
		report := CleanupReport{BuildID: buildID, Status: cleanupStatus, Residue: []Residue{}, RemovedPaths: []string{filepath.Join(scratchRoot, buildID)}}
		if cleanupStatus != CleanupClean {
			report.QuarantineReason = "fake residue"
			report.Residue = []Residue{{Kind: "mount", Target: "fake", Detail: "test residue"}}
		}
		return report
	})
	executor, err := NewBuildKitExecutor(client, archiveStore{contents: archive}, cleaner, committer, RejectingCacheProvider{}, scratchRoot, solveTimeout)
	if err != nil {
		t.Fatalf("NewBuildKitExecutor: %v", err)
	}
	executor.clock = func() time.Time { return workerNow }
	return executor, scratchRoot
}

func TestBuildKitExecutorCompletesStaticOutputAfterCleanResidue(t *testing.T) {
	t.Parallel()
	secret := []byte("fake-split-secret")
	capabilities := []llbcompiler.SecretCapability{{NodeID: "n2", Name: "token", Target: "/run/secrets/token", Required: true, MountID: "token"}}
	assignment, archive := resolvedWorkerAssignment(t, "static_bundle", capabilities)
	fake := &fakeBuildKitClient{solve: successfulFakeSolve("static_bundle", []byte("site artifact"), secret)}
	executor, scratchRoot := executorHarness(t, fake, archive, CleanupClean, time.Minute)
	recorder := new(eventRecorder)
	result, err := executor.Execute(context.Background(), Request{
		Assignment: assignment, Attempt: 1, Secrets: map[string][]byte{"token": secret}, Events: recorder.Push,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Phase != PhaseComplete || result.Cleanup.Status != CleanupClean || !artifactDigestPattern.MatchString(result.LogsDigest) || result.Cache.Misses != 1 || result.Cache.Hits != 0 || len(result.Outputs) != 1 || result.Outputs[0].ArtifactRef == "" {
		t.Fatalf("result = %#v", result)
	}
	if _, err := os.Stat(result.Outputs[0].ArtifactPath); err != nil {
		t.Fatalf("committed artifact is not retrievable: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(scratchRoot, testBuildID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scratch remains: %v", err)
	}
	events := recorder.Snapshot()
	if len(events) < 7 || events[len(events)-1].Phase != PhaseComplete || events[len(events)-2].Kind != "cleanup" {
		t.Fatalf("terminal events = %#v", events)
	}
	for index, event := range events {
		if event.Sequence != uint64(index+1) {
			t.Fatalf("sequence[%d] = %d", index, event.Sequence)
		}
		serialized := fmt.Sprintf("%s %s %s", event.Name, event.Line, event.Message)
		if strings.Contains(serialized, string(secret)) {
			t.Fatalf("secret leaked in event %#v", event)
		}
	}
}

func TestBuildKitExecutorCommitsOCIOutput(t *testing.T) {
	t.Parallel()
	assignment, archive := resolvedWorkerAssignment(t, "oci_image", nil)
	artifact, manifestDigest, layerDigests := fakeOCIArchive(t)
	fake := &fakeBuildKitClient{solve: successfulFakeSolve("oci_image", artifact, []byte("fake-progress-value"))}
	executor, _ := executorHarness(t, fake, archive, CleanupClean, time.Minute)
	result, err := executor.Execute(context.Background(), Request{Assignment: assignment, Attempt: 1, Secrets: map[string][]byte{}, Events: func(Event) {}})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Phase != PhaseComplete || len(result.Outputs) != 1 || result.Outputs[0].ArtifactDigest != digestBytes(artifact) || result.Outputs[0].ArtifactSize != int64(len(artifact)) || result.Outputs[0].ManifestDigest != manifestDigest || !slices.Equal(result.Outputs[0].LayerDigests, layerDigests) {
		t.Fatalf("result = %#v", result)
	}
}

func TestBuildKitExecutorRejectsMalformedOCIOutput(t *testing.T) {
	t.Parallel()
	assignment, archive := resolvedWorkerAssignment(t, "oci_image", nil)
	fake := &fakeBuildKitClient{solve: successfulFakeSolve("oci_image", []byte("not-an-oci-layout"), []byte("fake-progress-value"))}
	executor, _ := executorHarness(t, fake, archive, CleanupClean, time.Minute)
	result, err := executor.Execute(context.Background(), Request{Assignment: assignment, Attempt: 1, Secrets: map[string][]byte{}, Events: func(Event) {}})
	if !errors.Is(err, ErrExecute) || result.Phase != PhaseFailed || result.ErrorCode != "export_invalid" || len(result.Outputs) != 0 {
		t.Fatalf("result=%#v error=%v", result, err)
	}
}

func TestOCIValidationRejectsUnreferencedBlob(t *testing.T) {
	t.Parallel()
	extra := []byte("unreferenced-oci-content")
	artifact, _, _ := fakeOCIArchiveWithExtra(t, map[string][]byte{
		"blobs/sha256/" + digest.FromBytes(extra).Hex(): extra,
	})
	filePath := filepath.Join(t.TempDir(), "polluted.oci.tar")
	if err := os.WriteFile(filePath, artifact, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := validateOCIArtifact(filePath); err == nil {
		t.Fatal("expected unreferenced OCI blob rejection")
	}
}

func TestVisitOCIArtifactBlobsStreamsEveryVerifiedDescriptor(t *testing.T) {
	t.Parallel()
	artifact, _, _ := fakeOCIArchive(t)
	filePath := filepath.Join(t.TempDir(), "artifact.oci.tar")
	if err := os.WriteFile(filePath, artifact, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	identity, err := InspectOCIArtifact(filePath)
	if err != nil {
		t.Fatalf("InspectOCIArtifact: %v", err)
	}
	visited := map[string]int64{}
	if err := VisitOCIArtifactBlobs(context.Background(), filePath, identity, func(descriptor OCIArtifactDescriptor, reader io.Reader) error {
		count, err := io.Copy(io.Discard, reader)
		visited[descriptor.Digest] = count
		return err
	}); err != nil {
		t.Fatalf("VisitOCIArtifactBlobs: %v", err)
	}
	if len(visited) != len(identity.Layers)+1 || visited[identity.Config.Digest] != identity.Config.Size {
		t.Fatalf("visited=%#v identity=%#v", visited, identity)
	}
	if err := VisitOCIArtifactBlobs(context.Background(), filePath, identity, func(_ OCIArtifactDescriptor, reader io.Reader) error {
		_, _ = io.CopyN(io.Discard, reader, 1)
		return nil
	}); err == nil {
		t.Fatal("expected partially consumed blob rejection")
	}
}

func fakeOCIArchive(t *testing.T) ([]byte, string, []string) {
	return fakeOCIArchiveWithExtra(t, nil)
}

func fakeOCIArchiveWithExtra(t *testing.T, extra map[string][]byte) ([]byte, string, []string) {
	t.Helper()
	config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
	layer := []byte("fake-layer-contents")
	configDescriptor := ocispecs.Descriptor{MediaType: ocispecs.MediaTypeImageConfig, Digest: digest.FromBytes(config), Size: int64(len(config))}
	layerDescriptor := ocispecs.Descriptor{MediaType: ocispecs.MediaTypeImageLayer, Digest: digest.FromBytes(layer), Size: int64(len(layer))}
	manifest := ocispecs.Manifest{
		Versioned: imagespecs.Versioned{SchemaVersion: 2}, MediaType: ocispecs.MediaTypeImageManifest,
		Config: configDescriptor, Layers: []ocispecs.Descriptor{layerDescriptor},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal manifest: %v", err)
	}
	manifestDescriptor := ocispecs.Descriptor{MediaType: ocispecs.MediaTypeImageManifest, Digest: digest.FromBytes(manifestBytes), Size: int64(len(manifestBytes))}
	index := ocispecs.Index{
		Versioned: imagespecs.Versioned{SchemaVersion: 2}, MediaType: ocispecs.MediaTypeImageIndex,
		Manifests: []ocispecs.Descriptor{manifestDescriptor},
	}
	indexBytes, err := json.Marshal(index)
	if err != nil {
		t.Fatalf("Marshal index: %v", err)
	}
	layoutBytes := []byte(`{"imageLayoutVersion":"1.0.0"}`)
	entries := map[string][]byte{
		"blobs/sha256/" + configDescriptor.Digest.Hex():   config,
		"blobs/sha256/" + layerDescriptor.Digest.Hex():    layer,
		"blobs/sha256/" + manifestDescriptor.Digest.Hex(): manifestBytes,
		"index.json": indexBytes, "oci-layout": layoutBytes,
	}
	for name, contents := range extra {
		entries[name] = contents
	}
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	slices.Sort(names)
	var output bytes.Buffer
	archive := tar.NewWriter(&output)
	for _, name := range names {
		contents := entries[name]
		if err := archive.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o444, Size: int64(len(contents))}); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
		if _, err := archive.Write(contents); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatalf("Close OCI tar: %v", err)
	}
	return output.Bytes(), manifestDescriptor.Digest.String(), []string{layerDescriptor.Digest.String()}
}

func TestBuildKitExecutorFailsClosedAndStillCleans(t *testing.T) {
	t.Parallel()
	assignment, archive := resolvedWorkerAssignment(t, "static_bundle", nil)
	tests := map[string]struct {
		solve         func(context.Context, *llb.Definition, client.SolveOpt, chan *client.SolveStatus) (*client.SolveResponse, error)
		cleanupStatus CleanupStatus
		timeout       time.Duration
		wantCode      string
	}{
		"solve failure": {
			solve: func(_ context.Context, _ *llb.Definition, _ client.SolveOpt, statuses chan *client.SolveStatus) (*client.SolveResponse, error) {
				close(statuses)
				return nil, errors.New("fake worker loss")
			}, cleanupStatus: CleanupClean, timeout: time.Minute, wantCode: "solve_failed",
		},
		"timeout": {
			solve: func(ctx context.Context, _ *llb.Definition, _ client.SolveOpt, statuses chan *client.SolveStatus) (*client.SolveResponse, error) {
				<-ctx.Done()
				close(statuses)
				return nil, ctx.Err()
			}, cleanupStatus: CleanupClean, timeout: 10 * time.Millisecond, wantCode: "solve_timeout",
		},
		"missing export": {
			solve: func(_ context.Context, _ *llb.Definition, _ client.SolveOpt, statuses chan *client.SolveStatus) (*client.SolveResponse, error) {
				close(statuses)
				return &client.SolveResponse{}, nil
			}, cleanupStatus: CleanupClean, timeout: time.Minute, wantCode: "export_missing",
		},
		"cleanup quarantine": {
			solve:         successfulFakeSolve("static_bundle", []byte("artifact"), []byte("fake-progress-value")),
			cleanupStatus: CleanupQuarantined, timeout: time.Minute, wantCode: "cleanup_failed",
		},
	}
	for name, testCase := range tests {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			recorder := new(eventRecorder)
			executor, scratchRoot := executorHarness(t, &fakeBuildKitClient{solve: testCase.solve}, archive, testCase.cleanupStatus, testCase.timeout)
			result, err := executor.Execute(context.Background(), Request{Assignment: assignment, Attempt: 1, Secrets: map[string][]byte{}, Events: recorder.Push})
			if !errors.Is(err, ErrExecute) || result.Phase != PhaseFailed || result.ErrorCode != testCase.wantCode || result.Cleanup.Status != testCase.cleanupStatus {
				t.Fatalf("result = %#v, error = %v", result, err)
			}
			if _, err := os.Lstat(filepath.Join(scratchRoot, testBuildID)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("scratch remains: %v", err)
			}
			for _, event := range recorder.Snapshot() {
				if event.Phase == PhaseComplete {
					t.Fatalf("false complete event: %#v", event)
				}
			}
		})
	}
}

func TestBuildKitExecutorRejectsSecretMismatchBeforeSolve(t *testing.T) {
	t.Parallel()
	capabilities := []llbcompiler.SecretCapability{{NodeID: "n2", Name: "token", Target: "/run/secrets/token", Required: true, MountID: "token"}}
	assignment, archive := resolvedWorkerAssignment(t, "static_bundle", capabilities)
	fake := &fakeBuildKitClient{solve: successfulFakeSolve("static_bundle", []byte("unused"), []byte("fake"))}
	executor, _ := executorHarness(t, fake, archive, CleanupClean, time.Minute)
	result, err := executor.Execute(context.Background(), Request{Assignment: assignment, Attempt: 1, Secrets: map[string][]byte{"other": []byte("fake")}, Events: func(Event) {}})
	if !errors.Is(err, ErrExecute) || result.ErrorCode != "secret_capability" || fake.calls != 0 {
		t.Fatalf("result = %#v, error = %v, calls = %d", result, err, fake.calls)
	}
}

func TestBuildKitExecutorCooperativelyCancelsSolveAndCleans(t *testing.T) {
	t.Parallel()
	assignment, archive := resolvedWorkerAssignment(t, "static_bundle", nil)
	started := make(chan struct{})
	fake := &fakeBuildKitClient{solve: func(ctx context.Context, _ *llb.Definition, _ client.SolveOpt, statuses chan *client.SolveStatus) (*client.SolveResponse, error) {
		close(started)
		<-ctx.Done()
		close(statuses)
		return nil, ctx.Err()
	}}
	executor, scratchRoot := executorHarness(t, fake, archive, CleanupClean, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	type execution struct {
		result Result
		err    error
	}
	done := make(chan execution, 1)
	go func() {
		result, err := executor.Execute(ctx, Request{Assignment: assignment, Attempt: 1, Secrets: map[string][]byte{}, Events: func(Event) {}})
		done <- execution{result: result, err: err}
	}()
	<-started
	cancel()
	completed := <-done
	if !errors.Is(completed.err, context.Canceled) || !errors.Is(completed.err, ErrExecute) || completed.result.Phase != PhaseCanceled || completed.result.ErrorCode != "canceled" || completed.result.Cleanup.Status != CleanupClean {
		t.Fatalf("result = %#v, error = %v", completed.result, completed.err)
	}
	if _, err := os.Lstat(filepath.Join(scratchRoot, testBuildID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scratch remains: %v", err)
	}
}

func TestBuildKitExecutorRejectsMismatchedArtifactCommit(t *testing.T) {
	t.Parallel()
	assignment, archive := resolvedWorkerAssignment(t, "static_bundle", nil)
	fake := &fakeBuildKitClient{solve: successfulFakeSolve("static_bundle", []byte("artifact"), []byte("fake-progress-value"))}
	executor, _ := executorHarness(t, fake, archive, CleanupClean, time.Minute)
	executor.committer = committerFunc(func(_ context.Context, artifact ExportedArtifact) (CommittedArtifact, error) {
		return CommittedArtifact{Reference: "fake://artifact", Digest: testIRDigest, Size: artifact.Size}, nil
	})
	result, err := executor.Execute(context.Background(), Request{Assignment: assignment, Attempt: 1, Secrets: map[string][]byte{}, Events: func(Event) {}})
	if !errors.Is(err, ErrExecute) || result.Phase != PhaseFailed || result.ErrorCode != "artifact_commit" || result.Cleanup.Status != CleanupClean {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
}

func TestBuildKitExecutorEnforcesScratchQuota(t *testing.T) {
	t.Parallel()
	assignment, archive := resolvedWorkerAssignment(t, "static_bundle", nil)
	fake := &fakeBuildKitClient{solve: func(ctx context.Context, _ *llb.Definition, _ client.SolveOpt, statuses chan *client.SolveStatus) (*client.SolveResponse, error) {
		<-ctx.Done()
		close(statuses)
		return nil, context.Cause(ctx)
	}}
	executor, scratchRoot := executorHarness(t, fake, archive, CleanupClean, time.Minute)
	executor.quota = ScratchQuota{MaxBytes: 1, MaxInodes: 100, PollInterval: time.Millisecond}
	result, err := executor.Execute(context.Background(), Request{Assignment: assignment, Attempt: 1, Secrets: map[string][]byte{}, Events: func(Event) {}})
	if !errors.Is(err, ErrExecute) || !errors.Is(err, ErrScratchQuota) || result.Phase != PhaseFailed || result.ErrorCode != "scratch_quota" || result.Cleanup.Status != CleanupClean {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	if _, err := os.Lstat(filepath.Join(scratchRoot, testBuildID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scratch remains: %v", err)
	}
}
