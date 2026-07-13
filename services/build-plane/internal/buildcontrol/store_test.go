package buildcontrol

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
)

func claimRequest(owner string, now time.Time) ClaimRequest {
	return ClaimRequest{
		BuildID: controlBuildID, Generation: 1,
		PayloadDigest: controlIRDigest, Owner: owner, Now: now, LeaseTTL: time.Minute,
	}
}

func TestMemoryRunStoreClaimsLeasesResumesAndReplays(t *testing.T) {
	t.Parallel()
	store := NewMemoryRunStore()
	first := claimRequest("owner-1", controlNow)
	outcome, record, err := store.Claim(context.Background(), first)
	if err != nil || outcome != ClaimAccepted || record.Owner != first.Owner {
		t.Fatalf("first claim = %s, %#v, %v", outcome, record, err)
	}
	second := claimRequest("owner-2", controlNow.Add(30*time.Second))
	if outcome, _, err := store.Claim(context.Background(), second); err != nil || outcome != ClaimInProgress {
		t.Fatalf("active claim = %s, %v", outcome, err)
	}
	second.Now = controlNow.Add(2 * time.Minute)
	if outcome, record, err := store.Claim(context.Background(), second); err != nil || outcome != ClaimResumed || record.Owner != second.Owner {
		t.Fatalf("resumed claim = %s, %#v, %v", outcome, record, err)
	}
	if err := store.Heartbeat(context.Background(), controlBuildID, second.Owner, buildworker.PhaseSolving, 2, second.Now, time.Minute); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	result := Result{
		BuildID: controlBuildID, PayloadDigest: controlIRDigest, Phase: buildworker.PhaseFailed,
		Attempts: 2, ErrorCode: "fake_failure", StartedAt: controlNow, FinishedAt: second.Now,
		Cleanup: noResourceCleanup(controlBuildID), LogsDigest: controlIRDigest,
	}
	if err := store.Finish(context.Background(), controlBuildID, second.Owner, result, second.Now); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	second.Now = second.Now.Add(time.Minute)
	if outcome, record, err := store.Claim(context.Background(), second); err != nil || outcome != ClaimReplay || record.Result.ErrorCode != result.ErrorCode {
		t.Fatalf("replay claim = %s, %#v, %v", outcome, record, err)
	}
	conflict := second
	conflict.PayloadDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	if outcome, _, err := store.Claim(context.Background(), conflict); err != nil || outcome != ClaimConflict {
		t.Fatalf("conflict claim = %s, %v", outcome, err)
	}
}

func TestRunStoreRejectsFalseTerminalSuccess(t *testing.T) {
	t.Parallel()
	store := NewMemoryRunStore()
	claim := claimRequest("owner-1", controlNow)
	if outcome, _, err := store.Claim(context.Background(), claim); err != nil || outcome != ClaimAccepted {
		t.Fatalf("Claim=%s error=%v", outcome, err)
	}
	falseSuccess := Result{
		BuildID: controlBuildID, PayloadDigest: controlIRDigest, Phase: buildworker.PhaseComplete,
		Attempts: 1, StartedAt: controlNow, FinishedAt: controlNow.Add(time.Second), Cleanup: noResourceCleanup(controlBuildID), LogsDigest: controlIRDigest,
	}
	if err := store.Finish(context.Background(), controlBuildID, claim.Owner, falseSuccess, falseSuccess.FinishedAt); !errors.Is(err, ErrController) {
		t.Fatalf("Finish false success error = %v", err)
	}
}

func TestRunStorePersistsGenerationBoundCancellation(t *testing.T) {
	t.Parallel()
	store := NewMemoryRunStore()
	claim := claimRequest("owner-1", controlNow)
	if outcome, _, err := store.Claim(context.Background(), claim); err != nil || outcome != ClaimAccepted {
		t.Fatalf("Claim=%s error=%v", outcome, err)
	}
	if accepted, err := store.RequestCancel(context.Background(), controlBuildID, 2, controlNow.Add(time.Second)); err != nil || accepted {
		t.Fatalf("wrong-generation cancellation accepted=%t error=%v", accepted, err)
	}
	if accepted, err := store.RequestCancel(context.Background(), controlBuildID, 1, controlNow.Add(time.Second)); err != nil || !accepted {
		t.Fatalf("cancellation accepted=%t error=%v", accepted, err)
	}
	resume := claimRequest("owner-2", controlNow.Add(2*time.Minute))
	outcome, record, err := store.Claim(context.Background(), resume)
	if err != nil || outcome != ClaimResumed || !record.CancelRequested || record.Owner != resume.Owner {
		t.Fatalf("canceled claim=%s record=%#v error=%v", outcome, record, err)
	}
	falseSuccess := Result{
		BuildID: controlBuildID, PayloadDigest: controlIRDigest, Phase: buildworker.PhaseComplete, Attempts: 1,
		WorkerIdentity: "worker", Worker: buildworker.Result{
			BuildID: controlBuildID, Attempt: 1, Phase: buildworker.PhaseComplete, LogsDigest: controlIRDigest,
			Cleanup: noResourceCleanup(controlBuildID), Outputs: []buildworker.OutputResult{{
				Name: "site", Kind: "static_bundle", ArtifactRef: "registry.example.invalid/lrail/site@" + controlIRDigest,
				ArtifactDigest: controlIRDigest, ArtifactSize: 1, ConfigDigest: controlPolicyDigest, ManifestDigest: controlIRDigest,
				PublicationManifestRef: "s3://build-artifacts/static/site.json",
			}},
		},
		Cleanup: noResourceCleanup(controlBuildID), LogsDigest: controlIRDigest, StartedAt: controlNow, FinishedAt: resume.Now,
	}
	if err := store.Finish(context.Background(), controlBuildID, resume.Owner, falseSuccess, resume.Now); !errors.Is(err, ErrController) {
		t.Fatalf("canceled false success error = %v", err)
	}
}

func TestFileRunStorePersistsAndSerializesClaims(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state", "runs.json")
	firstStore, err := NewFileRunStore(path, 8)
	if err != nil {
		t.Fatalf("NewFileRunStore: %v", err)
	}
	secondStore, err := NewFileRunStore(path, 8)
	if err != nil {
		t.Fatalf("NewFileRunStore second: %v", err)
	}
	claims := []ClaimRequest{claimRequest("owner-1", controlNow), claimRequest("owner-2", controlNow)}
	outcomes := make(chan ClaimOutcome, 2)
	errorsSeen := make(chan error, 2)
	var wait sync.WaitGroup
	for index, claim := range claims {
		index, claim := index, claim
		wait.Add(1)
		go func() {
			defer wait.Done()
			store := firstStore
			if index == 1 {
				store = secondStore
			}
			outcome, _, err := store.Claim(context.Background(), claim)
			outcomes <- outcome
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(outcomes)
	close(errorsSeen)
	accepted := 0
	inProgress := 0
	for outcome := range outcomes {
		if outcome == ClaimAccepted {
			accepted++
		}
		if outcome == ClaimInProgress {
			inProgress++
		}
	}
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("Claim: %v", err)
		}
	}
	if accepted != 1 || inProgress != 1 {
		t.Fatalf("accepted=%d in_progress=%d", accepted, inProgress)
	}
	if err := firstStore.Close(); err != nil {
		t.Fatalf("Close first: %v", err)
	}
	if err := secondStore.Close(); err != nil {
		t.Fatalf("Close second: %v", err)
	}

	restarted, err := NewFileRunStore(path, 8)
	if err != nil {
		t.Fatalf("restart store: %v", err)
	}
	defer restarted.Close()
	resume := claimRequest("owner-restarted", controlNow.Add(2*time.Minute))
	if outcome, _, err := restarted.Claim(context.Background(), resume); err != nil || outcome != ClaimResumed {
		t.Fatalf("restart resume = %s, %v", outcome, err)
	}
	result := Result{BuildID: controlBuildID, PayloadDigest: controlIRDigest, Phase: buildworker.PhaseCanceled, Attempts: 1, ErrorCode: "canceled", StartedAt: controlNow, FinishedAt: resume.Now, Cleanup: noResourceCleanup(controlBuildID), LogsDigest: controlIRDigest}
	if err := restarted.Finish(context.Background(), controlBuildID, resume.Owner, result, resume.Now); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if outcome, record, err := restarted.Claim(context.Background(), claimRequest("owner-after", resume.Now.Add(time.Minute))); err != nil || outcome != ClaimReplay || record.Result.Phase != buildworker.PhaseCanceled {
		t.Fatalf("terminal replay = %s, %#v, %v", outcome, record, err)
	}
}

func TestFileRunStoreFailsClosedOnCorruption(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "runs.json")
	store, err := NewFileRunStore(path, 4)
	if err != nil {
		t.Fatalf("NewFileRunStore: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"records":{},"unknown":true}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := NewFileRunStore(path, 4); !errors.Is(err, ErrController) {
		t.Fatalf("corruption error = %v", err)
	}
}

func TestBoltRunStoreSurvivesRestartAndReturnsTerminalReplay(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "runs.db")
	store, err := NewBoltRunStore(path, 100)
	if err != nil {
		t.Fatalf("NewBoltRunStore: %v", err)
	}
	claim := claimRequest("owner-1", controlNow)
	if outcome, _, err := store.Claim(context.Background(), claim); err != nil || outcome != ClaimAccepted {
		t.Fatalf("claim=%s error=%v", outcome, err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	restarted, err := NewBoltRunStore(path, 100)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	defer restarted.Close()
	resume := claimRequest("owner-2", controlNow.Add(2*time.Minute))
	if outcome, _, err := restarted.Claim(context.Background(), resume); err != nil || outcome != ClaimResumed {
		t.Fatalf("resume=%s error=%v", outcome, err)
	}
	result := Result{BuildID: controlBuildID, PayloadDigest: controlIRDigest, Phase: buildworker.PhaseFailed, Attempts: 2, ErrorCode: "fake_failure", StartedAt: controlNow, FinishedAt: resume.Now, Cleanup: noResourceCleanup(controlBuildID), LogsDigest: controlIRDigest}
	if err := restarted.Finish(context.Background(), controlBuildID, resume.Owner, result, resume.Now); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	lookup, found, err := restarted.Lookup(context.Background(), controlBuildID)
	if err != nil || !found || lookup.Result.ErrorCode != result.ErrorCode {
		t.Fatalf("lookup=%#v found=%t error=%v", lookup, found, err)
	}
	if outcome, record, err := restarted.Claim(context.Background(), claimRequest("owner-3", resume.Now.Add(time.Minute))); err != nil || outcome != ClaimReplay || record.Result.ErrorCode != result.ErrorCode {
		t.Fatalf("replay=%s record=%#v error=%v", outcome, record, err)
	}
}

func TestBoltRunStorePersistsCancellationAcrossRestart(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "canceled-runs.db")
	store, err := NewBoltRunStore(path, 100)
	if err != nil {
		t.Fatalf("NewBoltRunStore: %v", err)
	}
	claim := claimRequest("owner-1", controlNow)
	if outcome, _, err := store.Claim(context.Background(), claim); err != nil || outcome != ClaimAccepted {
		t.Fatalf("Claim=%s error=%v", outcome, err)
	}
	if accepted, err := store.RequestCancel(context.Background(), controlBuildID, 1, controlNow.Add(time.Second)); err != nil || !accepted {
		t.Fatalf("RequestCancel accepted=%t error=%v", accepted, err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	restarted, err := NewBoltRunStore(path, 100)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	defer restarted.Close()
	resume := claimRequest("owner-2", controlNow.Add(2*time.Minute))
	outcome, record, err := restarted.Claim(context.Background(), resume)
	if err != nil || outcome != ClaimResumed || !record.CancelRequested || record.Owner != resume.Owner {
		t.Fatalf("resume=%s record=%#v error=%v", outcome, record, err)
	}
}
