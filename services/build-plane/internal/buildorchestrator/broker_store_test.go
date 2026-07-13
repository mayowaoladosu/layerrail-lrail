package buildorchestrator

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
)

func TestBoltBrokerStorePersistsFencedRunEventsResultAndCheckpoint(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	path := t.TempDir() + "/broker.db"
	store, err := NewBoltBrokerStore(path, 100, 1000)
	if err != nil {
		t.Fatalf("NewBoltBrokerStore: %v", err)
	}
	request := validRequest(now)
	record, created, err := store.Claim(context.Background(), request, now)
	if err != nil || !created || record.State != "accepted" {
		t.Fatalf("Claim: record=%#v created=%v err=%v", record, created, err)
	}
	duplicate, created, err := store.Claim(context.Background(), request, now)
	if err != nil || created || duplicate.RequestDigest != record.RequestDigest {
		t.Fatalf("duplicate Claim: record=%#v created=%v err=%v", duplicate, created, err)
	}
	conflict := request
	conflict.Source.SnapshotDigest = repeatedDigest("4")
	if _, _, err := store.Claim(context.Background(), conflict, now); err == nil {
		t.Fatal("expected immutable request conflict")
	}

	persisted, running, err := store.Append(context.Background(), Event{
		Version: CurrentEventVersion, BuildID: request.BuildID, Generation: request.Generation, Sequence: 99, Attempt: 1,
		Stage: "detecting", Kind: "progress", Message: "Detecting source", OccurredAt: now.Add(time.Second).Format(time.RFC3339Nano),
	}, now.Add(time.Second))
	if err != nil || persisted.Sequence != 1 || running.State != "running" || running.LastSequence != 1 {
		t.Fatalf("Append: event=%#v record=%#v err=%v", persisted, running, err)
	}
	if _, err := store.SetState(context.Background(), request.BuildID, request.Generation, "retrying", now.Add(2*time.Second)); err != nil {
		t.Fatalf("SetState retrying: %v", err)
	}
	if _, err := store.SetState(context.Background(), request.BuildID, request.Generation, "running", now.Add(3*time.Second)); err != nil {
		t.Fatalf("SetState running: %v", err)
	}

	checkpoint := Checkpoint{
		Version: 1, BuildID: request.BuildID, Generation: request.Generation, RequestDigest: record.RequestDigest,
		StartedAt: now.Format(time.RFC3339Nano), UpdatedAt: now.Add(3 * time.Second).Format(time.RFC3339Nano),
	}
	if err := store.Save(context.Background(), checkpoint); err != nil {
		t.Fatalf("Save initial checkpoint: %v", err)
	}
	payload := buildcell.Payload{
		BuildID: request.BuildID, OrganizationID: request.OrganizationID, ProjectID: request.ProjectID,
		OperationID: request.OperationID, Generation: request.Generation, Nonce: strings.Repeat("a", 64),
		Source: buildcell.SourceArtifact{SnapshotDigest: request.Source.SnapshotDigest},
	}
	checkpoint.Envelope = buildcell.Envelope{KeyID: "assignment-test", Payload: payload, Signature: "signature"}
	checkpoint.Partial = Result{AssignmentDigest: digestCanonicalPayload(payload)}
	checkpoint.UpdatedAt = now.Add(4 * time.Second).Format(time.RFC3339Nano)
	if err := store.Save(context.Background(), checkpoint); err != nil {
		t.Fatalf("Save signed checkpoint: %v", err)
	}
	mutated := checkpoint
	mutated.Envelope.Payload.Nonce = strings.Repeat("b", 64)
	mutated.Partial.AssignmentDigest = digestCanonicalPayload(mutated.Envelope.Payload)
	if err := store.Save(context.Background(), mutated); err == nil {
		t.Fatal("expected signed checkpoint mutation rejection")
	}

	failed := Result{
		Version: CurrentResultVersion, BuildID: request.BuildID, Generation: request.Generation, State: "failed",
		SourceSnapshotID: request.Source.SnapshotID, SourceDigest: request.Source.SnapshotDigest,
		Outputs: []OutputResult{}, Services: []ServiceResult{},
		FailureCode: "source_archive_invalid", FailureMessage: "Source snapshot could not be materialized",
		StartedAt: now.Format(time.RFC3339Nano), FinishedAt: now.Add(5 * time.Second).Format(time.RFC3339Nano), Cleanup: CleanupResult{Status: "clean"},
	}
	terminalEvent, terminalRecord, err := store.Append(context.Background(), Event{
		Version: CurrentEventVersion, BuildID: request.BuildID, Generation: request.Generation, Sequence: 500, Attempt: 1,
		Stage: "failed", Kind: "terminal", Message: "Build reached a terminal result",
		OccurredAt: now.Add(5 * time.Second).Format(time.RFC3339Nano), Terminal: &failed,
	}, now.Add(5*time.Second))
	if err != nil || terminalEvent.Sequence != 2 || !terminalRecord.Terminal() || terminalRecord.Result == nil || terminalRecord.Result.FailureCode != "source_archive_invalid" {
		t.Fatalf("terminal Append: event=%#v record=%#v err=%v", terminalEvent, terminalRecord, err)
	}
	events, err := store.EventsAfter(context.Background(), request.BuildID, request.Generation, 0, 100)
	if err != nil || len(events) != 2 || events[0].Sequence != 1 || events[1].Sequence != 2 {
		t.Fatalf("EventsAfter: events=%#v err=%v", events, err)
	}
	if active, err := store.Nonterminal(context.Background(), 100); err != nil || len(active) != 0 {
		t.Fatalf("Nonterminal: %#v err=%v", active, err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := NewBoltBrokerStore(path, 100, 1000)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	recovered, found, err := reopened.Lookup(context.Background(), request.BuildID, request.Generation)
	if err != nil || !found || recovered.Result == nil || recovered.LastSequence != 2 {
		t.Fatalf("Lookup recovered: record=%#v found=%v err=%v", recovered, found, err)
	}
	recoveredCheckpoint, found, err := reopened.Load(context.Background(), request.BuildID, request.Generation)
	if err != nil || !found || recoveredCheckpoint.Partial.AssignmentDigest != checkpoint.Partial.AssignmentDigest {
		t.Fatalf("Load checkpoint: checkpoint=%#v found=%v err=%v", recoveredCheckpoint, found, err)
	}
	next := request
	next.Generation = 2
	nextRecord, created, err := reopened.Claim(context.Background(), next, now.Add(6*time.Second))
	if err != nil || !created || nextRecord.Request.Generation != 2 {
		t.Fatalf("next generation Claim: record=%#v created=%v err=%v", nextRecord, created, err)
	}
	stale := request
	stale.Generation = 1
	if existing, created, err := reopened.Claim(context.Background(), stale, now.Add(6*time.Second)); err != nil || created || existing.Request.Generation != 1 {
		t.Fatalf("existing stale lookup should remain idempotent: record=%#v created=%v err=%v", existing, created, err)
	}
}

func TestBoltBrokerStoreRejectsNextGenerationWhilePriorRunActive(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	store, err := NewBoltBrokerStore(t.TempDir()+"/broker.db", 10, 10)
	if err != nil {
		t.Fatalf("NewBoltBrokerStore: %v", err)
	}
	defer store.Close()
	request := validRequest(now)
	if _, _, err := store.Claim(context.Background(), request, now); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	next := request
	next.Generation = 2
	if _, _, err := store.Claim(context.Background(), next, now); err == nil {
		t.Fatal("expected active-generation fence")
	}
}
