package buildtransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	lrailv1 "github.com/mayowaoladosu/layerrail-lrail/gen/go/lrail/v1"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcontrol"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildsupply"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const transportBuildID = "bld_019b01da-7e31-7000-8000-000000000001"
const transportCellID = "cell_019b01da-7e31-7000-8000-000000000002"
const transportOrgID = "org_019b01da-7e31-7000-8000-000000000003"
const transportProjectID = "prj_019b01da-7e31-7000-8000-000000000004"
const transportOperationID = "op_019b01da-7e31-7000-8000-000000000005"
const transportSnapshot = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const transportIR = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const transportPolicy = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
const transportLLB = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
const transportHead = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
const transportConfig = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
const transportPrefix = "s3://lrail-build/cell-transport/"

var transportNow = time.Date(2026, 7, 13, 4, 0, 0, 0, time.UTC)
var transportPrivateKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))

func transportEnvelope(t *testing.T) ([]byte, buildcell.Envelope, *buildcell.Verifier) {
	t.Helper()
	lock := llbcompiler.DefinitionLock{
		Version: llbcompiler.CurrentLockVersion, CompilerVersion: "0.1.0", IRDigest: transportIR,
		PolicyDigest: transportPolicy, SourceSnapshot: transportSnapshot, TargetPlatform: "linux/amd64",
		BuildArguments: []llbcompiler.NameValue{}, BaseMaterials: []llbcompiler.BaseMaterial{},
		Network: []llbcompiler.NetworkCapability{}, Caches: []llbcompiler.CacheCapability{}, Secrets: []llbcompiler.SecretCapability{},
		SupplyChain: llbcompiler.PlatformSupplyChainPolicy([]string{"sha256:1111111111111111111111111111111111111111111111111111111111111111"}),
		Outputs:     []llbcompiler.OutputLock{{Name: "site", Kind: "static_bundle", StateID: "n1", LLBDigest: transportLLB, ConfigDigest: transportConfig}},
	}
	lockDigest, err := llbcompiler.LockDigest(lock)
	if err != nil {
		t.Fatalf("LockDigest: %v", err)
	}
	payload := buildcell.Payload{
		Version: buildcell.CurrentAssignmentVersion, BuildID: transportBuildID, CellID: transportCellID,
		OrganizationID: transportOrgID, ProjectID: transportProjectID, OperationID: transportOperationID,
		Generation: 1, Nonce: string(bytes.Repeat([]byte("a"), 64)), IssuedAt: transportNow.Format(time.RFC3339),
		ExpiresAt: transportNow.Add(time.Hour).Format(time.RFC3339), DefinitionDigest: lockDigest, Lock: lock,
		Source: buildcell.SourceArtifact{SnapshotDigest: transportSnapshot, ArchiveDigest: transportIR, ArchiveRef: transportPrefix + "source.tar.gz", SizeBytes: 100},
		Outputs: []buildcell.OutputArtifact{{
			Name: "site", Kind: "static_bundle", LLBDigest: transportLLB, Head: transportHead,
			LLBRef: transportPrefix + "site.llb", ConfigDigest: transportConfig, ConfigRef: transportPrefix + "site.json",
		}},
	}
	envelope, err := buildcell.Sign(payload, "transport-test-v1", transportPrivateKey)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	contents, err := buildcell.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	verifier, err := buildcell.NewVerifier(buildcell.VerifierOptions{
		CellID: transportCellID, Keys: map[string]ed25519.PublicKey{"transport-test-v1": transportPrivateKey.Public().(ed25519.PublicKey)},
		ObjectPrefix: transportPrefix, Clock: func() time.Time { return transportNow },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return contents, envelope, verifier
}

type runnerFunc func(context.Context, buildcontrol.RunRequest) (buildcontrol.Result, error)

func (function runnerFunc) Run(ctx context.Context, request buildcontrol.RunRequest) (buildcontrol.Result, error) {
	return function(ctx, request)
}

type captureStream struct {
	ctx    context.Context
	mu     sync.Mutex
	events []*lrailv1.BuildCellEvent
	err    error
}

func (stream *captureStream) Send(event *lrailv1.BuildCellEvent) error {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.err != nil {
		return stream.err
	}
	stream.events = append(stream.events, event)
	return nil
}
func (stream *captureStream) SetHeader(metadata.MD) error  { return nil }
func (stream *captureStream) SendHeader(metadata.MD) error { return nil }
func (stream *captureStream) SetTrailer(metadata.MD)       {}
func (stream *captureStream) Context() context.Context     { return stream.ctx }
func (stream *captureStream) SendMsg(any) error            { return nil }
func (stream *captureStream) RecvMsg(any) error            { return errors.New("receive unsupported") }

func terminalTransportResult() buildcontrol.Result {
	cleanup := buildworker.CleanupReport{BuildID: transportBuildID, Status: buildworker.CleanupClean, Residue: []buildworker.Residue{}, RemovedPaths: []string{"fake"}}
	return buildcontrol.Result{
		BuildID: transportBuildID, PayloadDigest: transportIR, Phase: buildworker.PhaseComplete, Attempts: 1,
		WorkerIdentity: "worker-test", StartedAt: transportNow, FinishedAt: transportNow.Add(time.Second), Cleanup: cleanup, LogsDigest: transportIR,
		Worker: buildworker.Result{BuildID: transportBuildID, Attempt: 1, Phase: buildworker.PhaseComplete, Cleanup: cleanup, LogsDigest: transportIR, Cache: buildworker.CacheStats{Hits: 2, Misses: 3},
			Outputs: []buildworker.OutputResult{{
				Name: "site", Kind: "static_bundle", ArtifactRef: "registry.example.invalid/lrail/site@" + transportIR,
				ArtifactDigest: transportIR, ArtifactSize: 10, ConfigDigest: transportConfig, ManifestDigest: transportIR,
				PublicationManifestRef: "s3://build-artifacts/static/site.json",
				SupplyChain:            transportSupplyChain("registry.example.invalid/lrail/site"),
			}}},
	}
}

func transportSupplyChain(repository string) buildworker.SupplyChainResult {
	kinds := []string{buildsupply.KindSBOM, buildsupply.KindScan, buildsupply.KindProvenance, buildsupply.KindSignature, buildsupply.KindPolicy}
	var references [5]buildworker.EvidenceReference
	for index, kind := range kinds {
		manifestDigest := fmt.Sprintf("sha256:%064x", index+10)
		payloadDigest := fmt.Sprintf("sha256:%064x", index+20)
		references[index] = buildworker.EvidenceReference{Kind: kind, Reference: repository + "@" + manifestDigest, ManifestDigest: manifestDigest, PayloadDigest: payloadDigest}
	}
	return buildworker.SupplyChainResult{
		PolicyState: "accepted", ScanState: "passed", PolicyDigest: transportPolicy,
		SignerKeyID: llbcompiler.DefaultBuildSignerKeyID, SignerKeyVersion: 1,
		SignerPublicKeyDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111", Evidence: references,
	}
}

func TestServerStreamsProgressAndTerminalResult(t *testing.T) {
	t.Parallel()
	contents, _, verifier := transportEnvelope(t)
	runner := runnerFunc(func(_ context.Context, request buildcontrol.RunRequest) (buildcontrol.Result, error) {
		request.Events(buildworker.Event{Sequence: 1, Attempt: 1, Phase: buildworker.PhaseSolving, Kind: "vertex", Name: "fake"})
		return terminalTransportResult(), nil
	})
	server, err := NewServer(runner, verifier, buildcontrol.NewMemoryRunStore())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	stream := &captureStream{ctx: context.Background()}
	if err := server.ExecuteAssignment(&lrailv1.ExecuteBuildAssignmentRequest{CanonicalEnvelope: contents}, stream); err != nil {
		t.Fatalf("ExecuteAssignment: %v", err)
	}
	if len(stream.events) != 2 || stream.events[0].Kind != "vertex" || stream.events[1].Kind != "result" || stream.events[1].Result.GetCleanup().GetStatus() != string(buildworker.CleanupClean) {
		t.Fatalf("events = %#v", stream.events)
	}
	if stream.events[1].Sequence != stream.events[0].Sequence+1 || stream.events[1].Result.GetOutputs()[0].GetArtifactRef() == "" || stream.events[1].Result.GetOutputs()[0].GetConfigDigest() != transportConfig ||
		len(stream.events[1].Result.GetOutputs()[0].GetSupplyChain().GetEvidence()) != 5 || stream.events[1].Result.GetOutputs()[0].GetSupplyChain().GetPolicyState() != "accepted" ||
		stream.events[1].Result.GetLogsDigest() != transportIR || stream.events[1].Result.GetCacheHits() != 2 || stream.events[1].Result.GetCacheMisses() != 3 {
		t.Fatalf("terminal event = %#v", stream.events[1])
	}
}

func TestServerCancellationReachesActiveGeneration(t *testing.T) {
	t.Parallel()
	contents, _, verifier := transportEnvelope(t)
	started := make(chan struct{})
	runner := runnerFunc(func(_ context.Context, request buildcontrol.RunRequest) (buildcontrol.Result, error) {
		close(started)
		<-request.Cancellation
		result := terminalTransportResult()
		result.Phase = buildworker.PhaseCanceled
		result.ErrorCode = "canceled"
		return result, nil
	})
	server, _ := NewServer(runner, verifier, buildcontrol.NewMemoryRunStore())
	stream := &captureStream{ctx: context.Background()}
	done := make(chan error, 1)
	go func() {
		done <- server.ExecuteAssignment(&lrailv1.ExecuteBuildAssignmentRequest{CanonicalEnvelope: contents}, stream)
	}()
	<-started
	wrong, err := server.CancelAssignment(context.Background(), &lrailv1.CancelBuildAssignmentRequest{BuildId: transportBuildID, Generation: 2, Reason: "fake wrong generation"})
	if err != nil || wrong.GetAccepted() {
		t.Fatalf("wrong generation = %#v, %v", wrong, err)
	}
	accepted, err := server.CancelAssignment(context.Background(), &lrailv1.CancelBuildAssignmentRequest{BuildId: transportBuildID, Generation: 1, Reason: "fake test cancellation"})
	if err != nil || !accepted.GetAccepted() {
		t.Fatalf("cancellation = %#v, %v", accepted, err)
	}
	if err := <-done; err != nil {
		t.Fatalf("ExecuteAssignment: %v", err)
	}
	if stream.events[len(stream.events)-1].Result.GetPhase() != string(buildworker.PhaseCanceled) {
		t.Fatalf("events = %#v", stream.events)
	}
}

func TestServerPersistsCancellationWithoutActiveStream(t *testing.T) {
	t.Parallel()
	_, _, verifier := transportEnvelope(t)
	runs := buildcontrol.NewMemoryRunStore()
	claim := buildcontrol.ClaimRequest{
		BuildID: transportBuildID, Generation: 1, PayloadDigest: transportIR,
		Owner: "transport-owner", Now: transportNow, LeaseTTL: time.Minute,
	}
	if outcome, _, err := runs.Claim(context.Background(), claim); err != nil || outcome != buildcontrol.ClaimAccepted {
		t.Fatalf("Claim=%s error=%v", outcome, err)
	}
	server, err := NewServer(runnerFunc(func(context.Context, buildcontrol.RunRequest) (buildcontrol.Result, error) {
		return terminalTransportResult(), nil
	}), verifier, runs)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	response, err := server.CancelAssignment(context.Background(), &lrailv1.CancelBuildAssignmentRequest{
		BuildId: transportBuildID, Generation: 1, Reason: "persist while controller restarts",
	})
	if err != nil || !response.GetAccepted() {
		t.Fatalf("CancelAssignment response=%#v error=%v", response, err)
	}
	record, found, err := runs.Lookup(context.Background(), transportBuildID)
	if err != nil || !found || !record.CancelRequested {
		t.Fatalf("record=%#v found=%t error=%v", record, found, err)
	}
}

func TestServerRejectsMalformedAndUnauthorizedAssignments(t *testing.T) {
	t.Parallel()
	contents, envelope, verifier := transportEnvelope(t)
	server, _ := NewServer(runnerFunc(func(context.Context, buildcontrol.RunRequest) (buildcontrol.Result, error) {
		return terminalTransportResult(), nil
	}), verifier, buildcontrol.NewMemoryRunStore())
	stream := &captureStream{ctx: context.Background()}
	if err := server.ExecuteAssignment(&lrailv1.ExecuteBuildAssignmentRequest{CanonicalEnvelope: append([]byte(" "), contents...)}, stream); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("malformed code = %s, error = %v", status.Code(err), err)
	}
	envelope.Signature = "AAAA"
	tampered, err := buildcell.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	if err := server.ExecuteAssignment(&lrailv1.ExecuteBuildAssignmentRequest{CanonicalEnvelope: tampered}, stream); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unauthorized code = %s, error = %v", status.Code(err), err)
	}
}
