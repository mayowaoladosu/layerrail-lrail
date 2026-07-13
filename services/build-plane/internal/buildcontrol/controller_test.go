package buildcontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildsupply"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/solver/pb"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"google.golang.org/protobuf/proto"
)

const controlBuildID = "bld_019b01da-7e31-7000-8000-000000000001"
const controlCellID = "cell_019b01da-7e31-7000-8000-000000000002"
const controlOrgID = "org_019b01da-7e31-7000-8000-000000000003"
const controlProjectID = "prj_019b01da-7e31-7000-8000-000000000004"
const controlOperationID = "op_019b01da-7e31-7000-8000-000000000005"
const controlSnapshotDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const controlIRDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const controlPolicyDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
const controlObjectPrefix = "s3://lrail-build/cell-test/"

var controlNow = time.Date(2026, 7, 13, 3, 0, 0, 0, time.UTC)
var controlPrivateKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x35}, ed25519.SeedSize))

type controlArtifactStore map[string][]byte

func (store controlArtifactStore) Open(_ context.Context, reference string, _ int64) (io.ReadCloser, error) {
	contents, exists := store[reference]
	if !exists {
		return nil, errors.New("missing fake artifact")
	}
	return io.NopCloser(bytes.NewReader(contents)), nil
}

func controlFixture(t *testing.T, withSecret bool) (buildcell.Envelope, *buildcell.Verifier, controlArtifactStore) {
	t.Helper()
	secrets := []llbcompiler.SecretCapability{}
	network := []llbcompiler.NetworkCapability{}
	state := llb.Scratch().File(llb.Mkfile("/index.html", 0o644, []byte("ok")))
	if withSecret {
		secret := llbcompiler.SecretCapability{NodeID: "n2", Name: "token", Target: "/run/secrets/token", Required: true, MountID: "token"}
		secrets = append(secrets, secret)
		target := secret.Target
		state = state.Run(
			llb.Args([]string{"/bin/true"}), llb.Network(pb.NetMode_NONE),
			llb.WithCustomName("lrail run n1 network=none gateway= hosts="),
			llb.AddSecretWithDest(secret.MountID, &target, llb.SecretID(secret.MountID), llb.SecretFileOpt(0, 0, 0o400)),
		).Root()
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
	config := []byte(`{"config":{"Cmd":["true"]}}`)
	lock := llbcompiler.DefinitionLock{
		Version: llbcompiler.CurrentLockVersion, CompilerVersion: "0.1.0", IRDigest: controlIRDigest,
		PolicyDigest: controlPolicyDigest, SourceSnapshot: controlSnapshotDigest, TargetPlatform: "linux/amd64",
		BuildArguments: []llbcompiler.NameValue{}, BaseMaterials: []llbcompiler.BaseMaterial{},
		Network: network, Caches: []llbcompiler.CacheCapability{}, Secrets: secrets,
		SupplyChain: llbcompiler.PlatformSupplyChainPolicy([]string{"sha256:1111111111111111111111111111111111111111111111111111111111111111"}),
		Outputs:     []llbcompiler.OutputLock{{Name: "site", Kind: "static_bundle", StateID: "n1", LLBDigest: digest(definitionBytes), ConfigDigest: digest(config)}},
	}
	definitionDigest, err := llbcompiler.LockDigest(lock)
	if err != nil {
		t.Fatalf("LockDigest: %v", err)
	}
	output := buildcell.OutputArtifact{
		Name: "site", Kind: "static_bundle", LLBDigest: digest(definitionBytes), Head: string(head),
		LLBRef: controlObjectPrefix + "site.llb", ConfigDigest: digest(config), ConfigRef: controlObjectPrefix + "site.config.json",
	}
	payload := buildcell.Payload{
		Version: buildcell.CurrentAssignmentVersion, BuildID: controlBuildID, CellID: controlCellID,
		OrganizationID: controlOrgID, ProjectID: controlProjectID, OperationID: controlOperationID,
		Generation: 1, Nonce: strings.Repeat("d", 64), IssuedAt: controlNow.Format(time.RFC3339),
		ExpiresAt: controlNow.Add(30 * time.Minute).Format(time.RFC3339), DefinitionDigest: definitionDigest, Lock: lock,
		Source:  buildcell.SourceArtifact{SnapshotDigest: controlSnapshotDigest, ArchiveDigest: digest([]byte("source")), ArchiveRef: controlObjectPrefix + "source.tar.gz", SizeBytes: 6},
		Outputs: []buildcell.OutputArtifact{output},
	}
	envelope, err := buildcell.Sign(payload, "control-test-v1", controlPrivateKey)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	verifier, err := buildcell.NewVerifier(buildcell.VerifierOptions{
		CellID: controlCellID, Keys: map[string]ed25519.PublicKey{"control-test-v1": controlPrivateKey.Public().(ed25519.PublicKey)},
		ObjectPrefix: controlObjectPrefix, Clock: func() time.Time { return controlNow },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return envelope, verifier, controlArtifactStore{output.LLBRef: definitionBytes, output.ConfigRef: config}
}

func digest(value []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(value))
}

type fakeBroker struct {
	mu         sync.Mutex
	secret     []byte
	invalid    bool
	pending    bool
	acquireErr error
	revokeErr  error
	acquired   int
	revoked    int
}

func (broker *fakeBroker) Acquire(_ context.Context, assignment buildcell.VerifiedAssignment, attempt uint32) (CapabilityLease, error) {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	broker.acquired++
	secrets := map[string][]byte{}
	if len(assignment.Payload.Lock.Secrets) > 0 {
		secrets["token"] = append([]byte(nil), broker.secret...)
	}
	if broker.invalid {
		secrets["unknown"] = []byte("fake-unknown")
	}
	lease := CapabilityLease{
		ID: fmt.Sprintf("lease-%d", attempt), ExpiresAt: controlNow.Add(10 * time.Minute), Secrets: secrets,
		Network: append([]llbcompiler.NetworkCapability(nil), assignment.Payload.Lock.Network...),
		Caches:  append([]llbcompiler.CacheCapability(nil), assignment.Payload.Lock.Caches...),
	}
	if broker.pending {
		lease.ExpiresAt = time.Time{}
		lease.Network = nil
		lease.Caches = nil
	}
	return lease, broker.acquireErr
}

func (broker *fakeBroker) Revoke(_ context.Context, _ CapabilityLease) error {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	broker.revoked++
	return broker.revokeErr
}

type fakeWorker struct {
	id      string
	execute func(context.Context, buildworker.Request) (buildworker.Result, error)
	force   func(context.Context) (buildworker.CleanupReport, error)
	release func(context.Context) (buildworker.CleanupReport, error)
}

func (worker *fakeWorker) Identity() string { return worker.id }
func (worker *fakeWorker) Execute(ctx context.Context, request buildworker.Request) (buildworker.Result, error) {
	return worker.execute(ctx, request)
}
func (worker *fakeWorker) ForceTerminate(ctx context.Context) (buildworker.CleanupReport, error) {
	return worker.force(ctx)
}
func (worker *fakeWorker) Release(ctx context.Context) (buildworker.CleanupReport, error) {
	return worker.release(ctx)
}

type fakeAllocator struct {
	mu           sync.Mutex
	workers      []*fakeWorker
	calls        int
	cleanupCalls int
	cleanup      buildworker.CleanupReport
	cleanupErr   error
}

func (allocator *fakeAllocator) CleanupBuild(_ context.Context, buildID string) (buildworker.CleanupReport, error) {
	allocator.mu.Lock()
	defer allocator.mu.Unlock()
	allocator.cleanupCalls++
	report := allocator.cleanup
	if report.BuildID == "" {
		report = cleanReport()
		report.BuildID = buildID
	}
	return report, allocator.cleanupErr
}

func (allocator *fakeAllocator) Allocate(_ context.Context, request AllocationRequest) (Worker, error) {
	allocator.mu.Lock()
	defer allocator.mu.Unlock()
	if request.Attempt == 0 || request.LeaseID == "" || request.Assignment.Validate() != nil {
		return nil, errors.New("invalid fake allocation")
	}
	allocator.calls++
	if len(allocator.workers) == 0 {
		return nil, errors.New("no fake worker")
	}
	worker := allocator.workers[0]
	allocator.workers = allocator.workers[1:]
	return worker, nil
}

func cleanReport() buildworker.CleanupReport {
	return buildworker.CleanupReport{BuildID: controlBuildID, Status: buildworker.CleanupClean, Residue: []buildworker.Residue{}, RemovedPaths: []string{"fake-scratch"}}
}

func successWorker(id string) *fakeWorker {
	return &fakeWorker{
		id: id,
		execute: func(_ context.Context, request buildworker.Request) (buildworker.Result, error) {
			request.Events(buildworker.Event{Attempt: request.Attempt, Phase: buildworker.PhaseSolving, Kind: "vertex", Name: "fake vertex"})
			return buildworker.Result{
				BuildID: controlBuildID, Attempt: request.Attempt, Phase: buildworker.PhaseComplete, LogsDigest: controlIRDigest,
				Outputs: []buildworker.OutputResult{{
					Name: "site", Kind: "static_bundle", ArtifactRef: "registry.example.invalid/lrail/site@" + controlIRDigest,
					ArtifactDigest: controlIRDigest, ArtifactSize: 10, ConfigDigest: digest([]byte(`{"config":{"Cmd":["true"]}}`)), ManifestDigest: controlIRDigest,
					PublicationManifestRef: "s3://build-artifacts/static/site.json", ExporterResponse: map[string]string{},
					SupplyChain: successfulSupplyChain("registry.example.invalid/lrail/site", controlPolicyDigest),
				}},
				StartedAt: controlNow, FinishedAt: controlNow.Add(time.Second), Cleanup: cleanReport(),
			}, nil
		},
		force:   func(context.Context) (buildworker.CleanupReport, error) { return cleanReport(), nil },
		release: func(context.Context) (buildworker.CleanupReport, error) { return cleanReport(), nil },
	}
}

func successfulSupplyChain(repository, policyDigest string) buildworker.SupplyChainResult {
	kinds := []string{buildsupply.KindSBOM, buildsupply.KindScan, buildsupply.KindProvenance, buildsupply.KindSignature, buildsupply.KindPolicy}
	var references [5]buildworker.EvidenceReference
	for index, kind := range kinds {
		manifestDigest := fmt.Sprintf("sha256:%064x", index+10)
		payloadDigest := fmt.Sprintf("sha256:%064x", index+20)
		references[index] = buildworker.EvidenceReference{Kind: kind, Reference: repository + "@" + manifestDigest, ManifestDigest: manifestDigest, PayloadDigest: payloadDigest}
	}
	return buildworker.SupplyChainResult{
		PolicyState: "accepted", ScanState: "passed", PolicyDigest: policyDigest,
		SignerKeyID: llbcompiler.DefaultBuildSignerKeyID, SignerKeyVersion: 1,
		SignerPublicKeyDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111", Evidence: references,
	}
}

func TestValidOutputContentIdentityRequiresStaticPublicationManifest(t *testing.T) {
	t.Parallel()
	valid := buildworker.OutputResult{
		Kind: "static_bundle", ManifestDigest: controlIRDigest,
		PublicationManifestRef: "s3://build-artifacts/static/site.json",
	}
	if !validOutputContentIdentity(valid) {
		t.Fatal("complete static publication identity was rejected")
	}
	withoutOCI := valid
	withoutOCI.ManifestDigest = ""
	if validOutputContentIdentity(withoutOCI) {
		t.Fatal("static output without OCI manifest digest was accepted")
	}
	withoutPublicationManifest := valid
	withoutPublicationManifest.PublicationManifestRef = ""
	if validOutputContentIdentity(withoutPublicationManifest) {
		t.Fatal("static output without immutable publication manifest was accepted")
	}
	imageWithStaticManifest := buildworker.OutputResult{
		Kind: "oci_image", ManifestDigest: controlIRDigest, LayerDigests: []string{controlPolicyDigest},
		PublicationManifestRef: "s3://build-artifacts/static/site.json",
	}
	if validOutputContentIdentity(imageWithStaticManifest) {
		t.Fatal("image output with a static publication manifest was accepted")
	}
}

func TestValidSupplyChainIdentityRejectsIncompleteOrForeignEvidence(t *testing.T) {
	t.Parallel()
	output := buildworker.OutputResult{
		ArtifactRef: "registry.example.invalid/lrail/site@" + controlIRDigest,
		SupplyChain: successfulSupplyChain("registry.example.invalid/lrail/site", controlPolicyDigest),
	}
	policy := llbcompiler.PlatformSupplyChainPolicy([]string{"sha256:1111111111111111111111111111111111111111111111111111111111111111"})
	if !validSupplyChainIdentity(output, controlPolicyDigest, policy) {
		t.Fatal("complete supply-chain identity was rejected")
	}
	for name, mutate := range map[string]func(*buildworker.OutputResult){
		"missing": func(candidate *buildworker.OutputResult) {
			candidate.SupplyChain.Evidence[0] = buildworker.EvidenceReference{}
		},
		"foreign repository": func(candidate *buildworker.OutputResult) {
			candidate.SupplyChain.Evidence[0].Reference = "registry.example.invalid/foreign@" + candidate.SupplyChain.Evidence[0].ManifestDigest
		},
		"duplicate kind": func(candidate *buildworker.OutputResult) {
			candidate.SupplyChain.Evidence[1].Kind = candidate.SupplyChain.Evidence[0].Kind
		},
		"policy": func(candidate *buildworker.OutputResult) { candidate.SupplyChain.PolicyDigest = controlIRDigest },
		"signer": func(candidate *buildworker.OutputResult) {
			candidate.SupplyChain.SignerPublicKeyDigest = controlIRDigest
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := output
			mutate(&candidate)
			if validSupplyChainIdentity(candidate, controlPolicyDigest, policy) {
				t.Fatal("invalid supply-chain identity was accepted")
			}
		})
	}
}

func testController(t *testing.T, verifier *buildcell.Verifier, artifacts controlArtifactStore, broker *fakeBroker, allocator *fakeAllocator, runs RunStore) *Controller {
	t.Helper()
	if runs == nil {
		runs = NewMemoryRunStore()
	}
	var ownerCounter atomic.Uint64
	controller, err := New(Options{
		Verifier: verifier, Replay: mustReplayStore(t), Runs: runs, Artifacts: artifacts,
		Capabilities: broker, Workers: allocator, Clock: func() time.Time { return controlNow },
		Owner:    func() (string, error) { return fmt.Sprintf("owner-%d", ownerCounter.Add(1)), nil },
		LeaseTTL: time.Second, CancelGrace: 5 * time.Millisecond, ForceTimeout: 100 * time.Millisecond,
		ReleaseTimeout: 100 * time.Millisecond, RevokeTimeout: 100 * time.Millisecond,
		RetryDelay: func(uint32) time.Duration { return 0 },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return controller
}

func mustReplayStore(t *testing.T) buildcell.ReplayStore {
	t.Helper()
	store, err := buildcell.NewMemoryReplayStore(func() time.Time { return controlNow }, 100)
	if err != nil {
		t.Fatalf("NewMemoryReplayStore: %v", err)
	}
	return store
}

func TestControllerCompletesAndReturnsExactReplay(t *testing.T) {
	t.Parallel()
	envelope, verifier, artifacts := controlFixture(t, true)
	broker := &fakeBroker{secret: []byte("fake-jit-secret")}
	allocator := &fakeAllocator{workers: []*fakeWorker{successWorker("worker-1")}}
	runs := NewMemoryRunStore()
	controller := testController(t, verifier, artifacts, broker, allocator, runs)
	var events []buildworker.Event
	result, err := controller.Run(context.Background(), RunRequest{Envelope: envelope, Events: func(event buildworker.Event) { events = append(events, event) }})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Phase != buildworker.PhaseComplete || result.Replay || result.Attempts != 1 || result.WorkerIdentity != "worker-1" || broker.acquired != 1 || broker.revoked != 1 || allocator.calls != 1 {
		t.Fatalf("result = %#v, broker=%#v allocator=%#v", result, broker, allocator)
	}
	for index, event := range events {
		if event.Sequence != uint64(index+1) {
			t.Fatalf("event sequence = %#v", events)
		}
	}
	replayed, err := controller.Run(context.Background(), RunRequest{Envelope: envelope, Events: func(buildworker.Event) {}})
	if err != nil || !replayed.Replay || replayed.Phase != buildworker.PhaseComplete || allocator.calls != 1 {
		t.Fatalf("replay = %#v, error = %v, allocations = %d", replayed, err, allocator.calls)
	}
}

func TestControllerRetriesWorkerLossOnFreshWorker(t *testing.T) {
	t.Parallel()
	envelope, verifier, artifacts := controlFixture(t, false)
	lost := successWorker("worker-lost")
	lost.execute = func(_ context.Context, request buildworker.Request) (buildworker.Result, error) {
		return buildworker.Result{BuildID: controlBuildID, Attempt: request.Attempt, Phase: buildworker.PhaseFailed, ErrorCode: "worker_lost", Cleanup: cleanReport()}, errors.New("fake worker lost")
	}
	broker := &fakeBroker{}
	allocator := &fakeAllocator{workers: []*fakeWorker{lost, successWorker("worker-2")}}
	controller := testController(t, verifier, artifacts, broker, allocator, nil)
	result, err := controller.Run(context.Background(), RunRequest{Envelope: envelope, Events: func(buildworker.Event) {}})
	if err != nil || result.Phase != buildworker.PhaseComplete || result.Attempts != 2 || result.WorkerIdentity != "worker-2" || allocator.calls != 2 || broker.acquired != 2 || broker.revoked != 2 {
		t.Fatalf("result = %#v, error = %v, broker=%#v allocator=%#v", result, err, broker, allocator)
	}
}

func TestControllerCooperativeAndForcedCancellation(t *testing.T) {
	t.Parallel()
	for _, forced := range []bool{false, true} {
		forced := forced
		t.Run(fmt.Sprintf("forced=%t", forced), func(t *testing.T) {
			envelope, verifier, artifacts := controlFixture(t, false)
			started := make(chan struct{})
			killed := make(chan struct{})
			worker := successWorker("worker-cancel")
			worker.execute = func(ctx context.Context, request buildworker.Request) (buildworker.Result, error) {
				close(started)
				if forced {
					<-killed
				} else {
					<-ctx.Done()
				}
				return buildworker.Result{BuildID: controlBuildID, Attempt: request.Attempt, Phase: buildworker.PhaseCanceled, ErrorCode: "canceled", Cleanup: cleanReport()}, ctx.Err()
			}
			worker.force = func(context.Context) (buildworker.CleanupReport, error) {
				close(killed)
				return cleanReport(), nil
			}
			controller := testController(t, verifier, artifacts, &fakeBroker{}, &fakeAllocator{workers: []*fakeWorker{worker}}, nil)
			cancellation := make(chan struct{})
			type response struct {
				result Result
				err    error
			}
			done := make(chan response, 1)
			go func() {
				result, err := controller.Run(context.Background(), RunRequest{Envelope: envelope, Cancellation: cancellation, Events: func(buildworker.Event) {}})
				done <- response{result: result, err: err}
			}()
			<-started
			close(cancellation)
			received := <-done
			if received.err != nil || received.result.Phase != buildworker.PhaseCanceled || received.result.Worker.Cleanup.Status != buildworker.CleanupClean {
				t.Fatalf("result = %#v, error = %v", received.result, received.err)
			}
		})
	}
}

func TestControllerQuarantinesCleanupAndRevocationFailures(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		configureBroker func(*fakeBroker)
		configureWorker func(*fakeWorker)
	}{
		"release residue": {configureWorker: func(worker *fakeWorker) {
			worker.release = func(context.Context) (buildworker.CleanupReport, error) {
				return buildworker.CleanupReport{BuildID: controlBuildID, Status: buildworker.CleanupQuarantined, Residue: []buildworker.Residue{{Kind: "mount", Target: "fake"}}, QuarantineReason: "fake residue"}, nil
			}
		}},
		"cleanup identity": {configureWorker: func(worker *fakeWorker) {
			execute := worker.execute
			worker.execute = func(ctx context.Context, request buildworker.Request) (buildworker.Result, error) {
				result, err := execute(ctx, request)
				result.Cleanup.BuildID = "bld_019b01da-7e31-7000-8000-000000000099"
				return result, err
			}
		}},
		"revoke": {configureBroker: func(broker *fakeBroker) { broker.revokeErr = errors.New("fake revoke failure") }},
	}
	for name, testCase := range tests {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			envelope, verifier, artifacts := controlFixture(t, false)
			broker := &fakeBroker{}
			worker := successWorker("worker-quarantine")
			if testCase.configureBroker != nil {
				testCase.configureBroker(broker)
			}
			if testCase.configureWorker != nil {
				testCase.configureWorker(worker)
			}
			controller := testController(t, verifier, artifacts, broker, &fakeAllocator{workers: []*fakeWorker{worker}}, nil)
			result, err := controller.Run(context.Background(), RunRequest{Envelope: envelope, Events: func(buildworker.Event) {}})
			if err != nil || result.Phase != buildworker.PhaseQuarantined || result.ErrorCode != "cleanup_quarantined" {
				t.Fatalf("result = %#v, error = %v", result, err)
			}
		})
	}
}

func TestControllerRejectsConcurrentReplayWhileRunning(t *testing.T) {
	t.Parallel()
	envelope, verifier, artifacts := controlFixture(t, false)
	started := make(chan struct{})
	release := make(chan struct{})
	worker := successWorker("worker-blocked")
	worker.execute = func(_ context.Context, request buildworker.Request) (buildworker.Result, error) {
		close(started)
		<-release
		return successWorker("nested").execute(context.Background(), request)
	}
	controller := testController(t, verifier, artifacts, &fakeBroker{}, &fakeAllocator{workers: []*fakeWorker{worker}}, NewMemoryRunStore())
	done := make(chan error, 1)
	go func() {
		_, err := controller.Run(context.Background(), RunRequest{Envelope: envelope, Events: func(buildworker.Event) {}})
		done <- err
	}()
	<-started
	if _, err := controller.Run(context.Background(), RunRequest{Envelope: envelope, Events: func(buildworker.Event) {}}); !errors.Is(err, ErrInProgress) {
		t.Fatalf("concurrent replay error = %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first run error = %v", err)
	}
}

func TestControllerHonorsPersistedCancellationBeforeWorkerAllocation(t *testing.T) {
	t.Parallel()
	envelope, verifier, artifacts := controlFixture(t, false)
	runs := NewMemoryRunStore()
	claim := ClaimRequest{
		BuildID: controlBuildID, Generation: 1, PayloadDigest: func() string {
			verified, err := verifier.Verify(envelope)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			return verified.PayloadDigest
		}(),
		Owner: "old-owner", Now: controlNow.Add(-2 * time.Minute), LeaseTTL: time.Minute,
	}
	if outcome, _, err := runs.Claim(context.Background(), claim); err != nil || outcome != ClaimAccepted {
		t.Fatalf("Claim=%s error=%v", outcome, err)
	}
	if accepted, err := runs.RequestCancel(context.Background(), controlBuildID, 1, controlNow); err != nil || !accepted {
		t.Fatalf("RequestCancel accepted=%t error=%v", accepted, err)
	}
	broker := &fakeBroker{}
	allocator := &fakeAllocator{workers: []*fakeWorker{successWorker("unused")}}
	controller := testController(t, verifier, artifacts, broker, allocator, runs)
	result, err := controller.Run(context.Background(), RunRequest{Envelope: envelope, Events: func(buildworker.Event) {}})
	if err != nil || result.Phase != buildworker.PhaseCanceled || result.ErrorCode != "canceled" || broker.acquired != 0 || allocator.calls != 0 || allocator.cleanupCalls != 1 || !runDigestPattern.MatchString(result.LogsDigest) {
		t.Fatalf("result=%#v error=%v broker=%#v allocator=%#v", result, err, broker, allocator)
	}
}

func TestControllerRejectsInvalidCapabilityBeforeAllocation(t *testing.T) {
	t.Parallel()
	envelope, verifier, artifacts := controlFixture(t, true)
	broker := &fakeBroker{secret: []byte("fake-jit-secret"), invalid: true}
	allocator := &fakeAllocator{workers: []*fakeWorker{successWorker("unused")}}
	controller := testController(t, verifier, artifacts, broker, allocator, nil)
	result, err := controller.Run(context.Background(), RunRequest{Envelope: envelope, Events: func(buildworker.Event) {}})
	if err != nil || result.Phase != buildworker.PhaseFailed || result.ErrorCode != "capability_invalid" || allocator.calls != 0 || broker.revoked != 1 {
		t.Fatalf("result = %#v, error = %v, broker=%#v allocator=%#v", result, err, broker, allocator)
	}
}

func TestControllerRetriesRevocationAfterCapabilityAcquisitionFailure(t *testing.T) {
	t.Parallel()
	envelope, verifier, artifacts := controlFixture(t, false)
	broker := &fakeBroker{acquireErr: errors.New("fake acquisition failure"), pending: true}
	allocator := &fakeAllocator{workers: []*fakeWorker{successWorker("unused")}}
	controller := testController(t, verifier, artifacts, broker, allocator, nil)
	result, err := controller.Run(context.Background(), RunRequest{Envelope: envelope, Events: func(buildworker.Event) {}})
	if err != nil || result.Phase != buildworker.PhaseFailed || result.ErrorCode != "capability_acquire" || allocator.calls != 0 || broker.revoked != 1 {
		t.Fatalf("result=%#v error=%v broker=%#v allocator=%#v", result, err, broker, allocator)
	}
}

func TestControllerQuarantinesFailedAcquisitionWhenRevocationStillFails(t *testing.T) {
	t.Parallel()
	envelope, verifier, artifacts := controlFixture(t, false)
	broker := &fakeBroker{acquireErr: errors.New("fake acquisition failure"), revokeErr: errors.New("fake revoke failure"), pending: true}
	controller := testController(t, verifier, artifacts, broker, &fakeAllocator{workers: []*fakeWorker{successWorker("unused")}}, nil)
	result, err := controller.Run(context.Background(), RunRequest{Envelope: envelope, Events: func(buildworker.Event) {}})
	if err != nil || result.Phase != buildworker.PhaseQuarantined || result.ErrorCode != "capability_revoke" || result.Cleanup.Status != buildworker.CleanupQuarantined || broker.revoked != 1 {
		t.Fatalf("result=%#v error=%v broker=%#v", result, err, broker)
	}
}
