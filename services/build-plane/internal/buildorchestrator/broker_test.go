package buildorchestrator

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeBrokerRunner struct {
	mu          sync.Mutex
	calls       int
	cancelCalls int
	run         func(context.Context, Request, Emit, int) (Result, error)
}

func (runner *fakeBrokerRunner) Run(ctx context.Context, request Request, emit Emit) (Result, error) {
	runner.mu.Lock()
	runner.calls++
	call := runner.calls
	runner.mu.Unlock()
	return runner.run(ctx, request, emit, call)
}

func (runner *fakeBrokerRunner) Cancel(_ context.Context, _ string, _ uint64, _ string) (bool, error) {
	runner.mu.Lock()
	runner.cancelCalls++
	runner.mu.Unlock()
	return true, nil
}

func (runner *fakeBrokerRunner) counts() (int, int) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.calls, runner.cancelCalls
}

func TestBrokerDetachesDeduplicatesAndRetainsCursorEvents(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	runner := &fakeBrokerRunner{}
	runner.run = func(_ context.Context, request Request, emit Emit, _ int) (Result, error) {
		if err := emit(progressEvent(request, now, "detecting")); err != nil {
			return Result{}, err
		}
		result := failedBrokerResult(request, now, "detect_fixture_failure")
		if err := emit(terminalBrokerEvent(request, now.Add(time.Second), result)); err != nil {
			return Result{}, err
		}
		return result, nil
	}
	broker, store := testBroker(t, runner, now, 3)
	defer closeTestBroker(t, broker, store)
	request := validRequest(now)
	submitContext, cancelSubmit := context.WithCancel(context.Background())
	record, err := broker.Submit(submitContext, request)
	cancelSubmit()
	if err != nil || record.State != "accepted" {
		t.Fatalf("Submit: record=%#v err=%v", record, err)
	}
	events, terminal := waitBrokerTerminal(t, broker, request, 0)
	if terminal.State != "failed" || len(events) != 2 || events[0].Sequence != 1 || events[1].Sequence != 2 || events[1].Terminal == nil {
		t.Fatalf("events=%#v terminal=%#v", events, terminal)
	}
	resumed, current, err := broker.Watch(context.Background(), request.BuildID, request.Generation, 1, 100, 0)
	if err != nil || len(resumed) != 1 || resumed[0].Sequence != 2 || current.State != "failed" {
		t.Fatalf("cursor Watch: events=%#v record=%#v err=%v", resumed, current, err)
	}
	duplicate, err := broker.Submit(context.Background(), request)
	if calls, _ := runner.counts(); err != nil || duplicate.State != "failed" || calls != 1 {
		t.Fatalf("duplicate Submit: record=%#v calls=%d err=%v", duplicate, calls, err)
	}
}

func TestBrokerRetriesInfrastructureWithoutChangingGeneration(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	runner := &fakeBrokerRunner{}
	runner.run = func(_ context.Context, request Request, emit Emit, call int) (Result, error) {
		if call == 1 {
			return Result{}, errors.New("injected transient transport failure")
		}
		result := failedBrokerResult(request, now, "build_fixture_terminal")
		if err := emit(terminalBrokerEvent(request, now.Add(time.Second), result)); err != nil {
			return Result{}, err
		}
		return result, nil
	}
	broker, store := testBroker(t, runner, now, 3)
	defer closeTestBroker(t, broker, store)
	request := validRequest(now)
	if _, err := broker.Submit(context.Background(), request); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	events, record := waitBrokerTerminal(t, broker, request, 0)
	if calls, _ := runner.counts(); calls != 2 || record.State != "failed" {
		t.Fatalf("calls=%d record=%#v", calls, record)
	}
	foundRetry := false
	for _, event := range events {
		foundRetry = foundRetry || event.Stage == "retrying" && event.Attempt == 2
	}
	if !foundRetry {
		t.Fatalf("retry event absent: %#v", events)
	}
}

func TestBrokerCancelsLocalWorkAndPersistsTerminalResult(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	started := make(chan struct{})
	runner := &fakeBrokerRunner{}
	runner.run = func(ctx context.Context, _ Request, _ Emit, _ int) (Result, error) {
		close(started)
		<-ctx.Done()
		return Result{}, ctx.Err()
	}
	broker, store := testBroker(t, runner, now, 2)
	defer closeTestBroker(t, broker, store)
	request := validRequest(now)
	if _, err := broker.Submit(context.Background(), request); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("runner did not start")
	}
	canceling, err := broker.Cancel(context.Background(), request.BuildID, request.Generation, "user requested cancellation")
	if err != nil || canceling.State != "canceling" {
		t.Fatalf("Cancel: record=%#v err=%v", canceling, err)
	}
	_, terminal := waitBrokerTerminal(t, broker, request, 0)
	if _, cancelCalls := runner.counts(); terminal.State != "canceled" || terminal.Result == nil || terminal.Result.FailureCode != "build_canceled" || cancelCalls != 0 {
		t.Fatalf("terminal=%#v cancelCalls=%d", terminal, cancelCalls)
	}
}

func TestBrokerResumesAcceptedRunAfterProcessRestart(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	store, err := NewBoltBrokerStore(t.TempDir()+"/broker.db", 100, 1000)
	if err != nil {
		t.Fatalf("NewBoltBrokerStore: %v", err)
	}
	request := validRequest(now)
	if _, _, err := store.Claim(context.Background(), request, now); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	runner := &fakeBrokerRunner{}
	runner.run = func(_ context.Context, request Request, emit Emit, _ int) (Result, error) {
		result := failedBrokerResult(request, now, "build_recovered_fixture")
		if err := emit(terminalBrokerEvent(request, now.Add(time.Second), result)); err != nil {
			return Result{}, err
		}
		return result, nil
	}
	broker, err := NewBroker(BrokerOptions{Store: store, Runner: runner, Clock: time.Now, MaxAttempts: 2, RetryBase: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	defer closeTestBroker(t, broker, store)
	if err := broker.Resume(context.Background(), 100); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	_, record := waitBrokerTerminal(t, broker, request, 0)
	if calls, _ := runner.counts(); record.State != "failed" || calls != 1 {
		t.Fatalf("record=%#v calls=%d", record, calls)
	}
}

func testBroker(t *testing.T, runner Runner, _ time.Time, attempts int) (*Broker, *BoltBrokerStore) {
	t.Helper()
	store, err := NewBoltBrokerStore(t.TempDir()+"/broker.db", 100, 1000)
	if err != nil {
		t.Fatalf("NewBoltBrokerStore: %v", err)
	}
	broker, err := NewBroker(BrokerOptions{Store: store, Runner: runner, Clock: time.Now, MaxAttempts: attempts, RetryBase: 10 * time.Millisecond})
	if err != nil {
		_ = store.Close()
		t.Fatalf("NewBroker: %v", err)
	}
	return broker, store
}

func closeTestBroker(t *testing.T, broker *Broker, store *BoltBrokerStore) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := broker.Close(ctx); err != nil {
		t.Errorf("Broker Close: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Errorf("Store Close: %v", err)
	}
}

func waitBrokerTerminal(t *testing.T, broker *Broker, request Request, after uint64) ([]Event, RunRecord) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	events := make([]Event, 0)
	for {
		batch, record, err := broker.Watch(ctx, request.BuildID, request.Generation, after, 100, time.Second)
		if err != nil {
			t.Fatalf("Watch: %v", err)
		}
		events = append(events, batch...)
		if len(batch) != 0 {
			after = batch[len(batch)-1].Sequence
		}
		if record.Terminal() {
			return events, record
		}
	}
}

func progressEvent(request Request, now time.Time, stage string) Event {
	return Event{
		Version: CurrentEventVersion, BuildID: request.BuildID, Generation: request.Generation, Sequence: 1, Attempt: 1,
		Stage: stage, Kind: "progress", Message: "fixture progress", OccurredAt: now.Format(time.RFC3339Nano),
	}
}

func terminalBrokerEvent(request Request, now time.Time, result Result) Event {
	return Event{
		Version: CurrentEventVersion, BuildID: request.BuildID, Generation: request.Generation, Sequence: 1, Attempt: 1,
		Stage: result.State, Kind: "terminal", Message: "Build reached a terminal result", OccurredAt: now.Format(time.RFC3339Nano), Terminal: &result,
	}
}

func failedBrokerResult(request Request, now time.Time, code string) Result {
	return Result{
		Version: CurrentResultVersion, BuildID: request.BuildID, Generation: request.Generation, State: "failed",
		SourceSnapshotID: request.Source.SnapshotID, SourceDigest: request.Source.SnapshotDigest, Outputs: []OutputResult{},
		FailureCode: code, FailureMessage: "Fixture terminal failure", StartedAt: now.Format(time.RFC3339Nano),
		FinishedAt: now.Add(time.Second).Format(time.RFC3339Nano), Cleanup: CleanupResult{Status: "clean"},
	}
}

var _ Runner = (*fakeBrokerRunner)(nil)
