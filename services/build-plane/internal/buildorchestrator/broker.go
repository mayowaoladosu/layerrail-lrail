package buildorchestrator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	DefaultBrokerAttempts = 5
	DefaultRetryBase      = 250 * time.Millisecond
	DefaultWatchLimit     = 250
	MaxWatchDuration      = 30 * time.Second
)

type Runner interface {
	Run(ctx context.Context, request Request, emit Emit) (Result, error)
	Cancel(ctx context.Context, buildID string, generation uint64, reason string) (bool, error)
}

type BrokerOptions struct {
	Store       *BoltBrokerStore
	Runner      Runner
	Clock       func() time.Time
	MaxAttempts int
	RetryBase   time.Duration
}

type Broker struct {
	store       *BoltBrokerStore
	runner      Runner
	clock       func() time.Time
	maxAttempts int
	retryBase   time.Duration
	root        context.Context
	stop        context.CancelFunc
	mu          sync.Mutex
	active      map[string]*activeRun
	notify      chan struct{}
	wait        sync.WaitGroup
}

type activeRun struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func NewBroker(options BrokerOptions) (*Broker, error) {
	if options.Store == nil || options.Runner == nil {
		return nil, errors.New("build broker dependencies are incomplete")
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.MaxAttempts == 0 {
		options.MaxAttempts = DefaultBrokerAttempts
	}
	if options.RetryBase == 0 {
		options.RetryBase = DefaultRetryBase
	}
	if options.MaxAttempts < 1 || options.MaxAttempts > 10 || options.RetryBase < 10*time.Millisecond || options.RetryBase > 10*time.Second {
		return nil, errors.New("build broker retry policy is invalid")
	}
	root, stop := context.WithCancel(context.Background())
	return &Broker{
		store: options.Store, runner: options.Runner, clock: options.Clock, maxAttempts: options.MaxAttempts,
		retryBase: options.RetryBase, root: root, stop: stop, active: make(map[string]*activeRun), notify: make(chan struct{}),
	}, nil
}

func (broker *Broker) Submit(ctx context.Context, request Request) (RunRecord, error) {
	record, _, err := broker.store.Claim(ctx, request, broker.clock().UTC())
	if err != nil {
		return RunRecord{}, err
	}
	if !record.Terminal() {
		broker.start(record)
	}
	return record, nil
}

func (broker *Broker) Get(ctx context.Context, buildID string, generation uint64) (RunRecord, bool, error) {
	return broker.store.Lookup(ctx, buildID, generation)
}

func (broker *Broker) Watch(ctx context.Context, buildID string, generation, after uint64, limit int, wait time.Duration) ([]Event, RunRecord, error) {
	if limit == 0 {
		limit = DefaultWatchLimit
	}
	if wait < 0 || wait > MaxWatchDuration {
		return nil, RunRecord{}, errors.New("build event watch duration is invalid")
	}
	var deadline <-chan time.Time
	var timer *time.Timer
	if wait > 0 {
		timer = time.NewTimer(wait)
		defer timer.Stop()
		deadline = timer.C
	}
	for {
		events, err := broker.store.EventsAfter(ctx, buildID, generation, after, limit)
		if err != nil {
			return nil, RunRecord{}, err
		}
		record, found, err := broker.store.Lookup(ctx, buildID, generation)
		if err != nil {
			return nil, RunRecord{}, err
		}
		if !found {
			return nil, RunRecord{}, errors.New("build broker run is absent")
		}
		if len(events) != 0 || record.Terminal() || wait == 0 {
			return events, record, nil
		}
		broker.mu.Lock()
		notification := broker.notify
		broker.mu.Unlock()
		// Close the append-between-query-and-subscribe race before waiting.
		events, err = broker.store.EventsAfter(ctx, buildID, generation, after, limit)
		if err != nil || len(events) != 0 {
			return events, record, err
		}
		select {
		case <-ctx.Done():
			return nil, RunRecord{}, ctx.Err()
		case <-deadline:
			record, _, lookupErr := broker.store.Lookup(ctx, buildID, generation)
			return []Event{}, record, lookupErr
		case <-notification:
		}
	}
}

func (broker *Broker) Cancel(ctx context.Context, buildID string, generation uint64, reason string) (RunRecord, error) {
	if reason == "" || len(reason) > 512 || !utf8.ValidString(reason) || strings.ContainsRune(reason, '\x00') {
		return RunRecord{}, errors.New("build cancellation reason is invalid")
	}
	record, found, err := broker.store.Lookup(ctx, buildID, generation)
	if err != nil || !found {
		return RunRecord{}, errors.New("build broker run is absent")
	}
	if record.Terminal() {
		return record, nil
	}
	record, err = broker.store.SetState(ctx, buildID, generation, "canceling", broker.clock().UTC())
	if err != nil {
		return RunRecord{}, err
	}
	broker.signal()
	if !record.Dispatched {
		done := broker.cancelActive(buildID, generation)
		if done == nil {
			if err := broker.appendSyntheticTerminal(record, "canceled", "build_canceled", "Build was canceled before BuildCell dispatch", "clean"); err != nil {
				return RunRecord{}, err
			}
		} else {
			broker.wait.Add(1)
			go broker.reconcileLocalCancellation(record, reason, done)
		}
		updated, _, lookupErr := broker.store.Lookup(ctx, buildID, generation)
		return updated, lookupErr
	}
	accepted, cancelErr := broker.runner.Cancel(ctx, buildID, generation, reason)
	if cancelErr == nil && accepted {
		broker.start(record)
		return record, nil
	}
	done := broker.cancelActive(buildID, generation)
	broker.wait.Add(1)
	go broker.retryDispatchedCancellation(record, reason, done)
	return record, nil
}

func (broker *Broker) Resume(ctx context.Context, limit int) error {
	records, err := broker.store.Nonterminal(ctx, limit)
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.State == "canceling" && !record.Dispatched {
			if err := broker.appendSyntheticTerminal(record, "canceled", "build_canceled", "Build cancellation recovered before dispatch", "clean"); err != nil {
				return err
			}
			continue
		}
		broker.start(record)
		if record.State == "canceling" && record.Dispatched {
			broker.wait.Add(1)
			go broker.retryDispatchedCancellation(record, "recovered cancellation", nil)
		}
	}
	return nil
}

func (broker *Broker) Close(ctx context.Context) error {
	broker.stop()
	broker.mu.Lock()
	for _, active := range broker.active {
		active.cancel()
	}
	broker.mu.Unlock()
	finished := make(chan struct{})
	go func() { broker.wait.Wait(); close(finished) }()
	select {
	case <-finished:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (broker *Broker) start(record RunRecord) {
	key := string(brokerRunKey(record.Request.BuildID, record.Request.Generation))
	broker.mu.Lock()
	if _, exists := broker.active[key]; exists || record.Terminal() {
		broker.mu.Unlock()
		return
	}
	deadline, err := time.Parse(time.RFC3339Nano, record.Request.Deadline)
	if err != nil {
		broker.mu.Unlock()
		return
	}
	if record.State == "canceling" && record.Dispatched && !deadline.After(broker.clock().UTC().Add(2*time.Minute)) {
		deadline = broker.clock().UTC().Add(2 * time.Minute)
	}
	runContext, cancel := context.WithDeadline(broker.root, deadline)
	active := &activeRun{cancel: cancel, done: make(chan struct{})}
	broker.active[key] = active
	broker.wait.Add(1)
	broker.mu.Unlock()
	go broker.execute(runContext, record, key, active)
}

func (broker *Broker) execute(ctx context.Context, initial RunRecord, key string, active *activeRun) {
	defer broker.wait.Done()
	defer active.cancel()
	defer func() {
		broker.mu.Lock()
		delete(broker.active, key)
		close(active.done)
		broker.mu.Unlock()
	}()
	request := initial.Request
	for attempt := 1; attempt <= broker.maxAttempts; attempt++ {
		record, found, err := broker.store.Lookup(context.Background(), request.BuildID, request.Generation)
		if err != nil || !found || record.Terminal() {
			return
		}
		if record.State != "canceling" {
			if _, err := broker.store.SetState(context.Background(), request.BuildID, request.Generation, "running", broker.clock().UTC()); err != nil {
				return
			}
		}
		result, runErr := broker.runner.Run(ctx, request, func(event Event) error {
			persisted, _, err := broker.store.Append(context.Background(), event, broker.clock().UTC())
			if err == nil {
				_ = persisted
				broker.signal()
			}
			return err
		})
		if runErr == nil {
			record, found, _ = broker.store.Lookup(context.Background(), request.BuildID, request.Generation)
			if found && !record.Terminal() {
				_ = broker.appendTerminal(record, result)
			}
			return
		}
		record, found, _ = broker.store.Lookup(context.Background(), request.BuildID, request.Generation)
		if !found || record.Terminal() {
			return
		}
		if record.State == "canceling" && !record.Dispatched {
			_ = broker.appendSyntheticTerminal(record, "canceled", "build_canceled", "Build was canceled before BuildCell dispatch", "clean")
			return
		}
		if ctx.Err() != nil || attempt == broker.maxAttempts {
			// Process shutdown is not a build failure. Preserve the nonterminal
			// record so the replacement broker can recover the durable run.
			if broker.root.Err() != nil {
				return
			}
			if record.State == "canceling" && record.Dispatched {
				return
			}
			_ = broker.appendSyntheticTerminal(record, "failed", "build_orchestration_unavailable", "Build orchestration could not recover before its retry limit", "unknown")
			return
		}
		retryEvent := Event{
			Version: CurrentEventVersion, BuildID: request.BuildID, Generation: request.Generation, Sequence: 1, Attempt: uint32(attempt + 1),
			Stage: "retrying", Kind: "retry", Message: "Retrying build orchestration without changing immutable inputs",
			OccurredAt: broker.clock().UTC().Format(time.RFC3339Nano),
		}
		if _, _, err := broker.store.Append(context.Background(), retryEvent, broker.clock().UTC()); err != nil {
			return
		}
		if _, err := broker.store.SetState(context.Background(), request.BuildID, request.Generation, "retrying", broker.clock().UTC()); err != nil {
			return
		}
		broker.signal()
		timer := time.NewTimer(broker.retryDelay(attempt))
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			continue
		case <-timer.C:
		}
	}
}

func (broker *Broker) retryDispatchedCancellation(record RunRecord, reason string, priorDone <-chan struct{}) {
	defer broker.wait.Done()
	if priorDone != nil {
		select {
		case <-priorDone:
		case <-broker.root.Done():
			return
		}
	}
	deadline := time.NewTimer(2 * time.Minute)
	defer deadline.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		current, found, _ := broker.store.Lookup(context.Background(), record.Request.BuildID, record.Request.Generation)
		if !found || current.Terminal() {
			return
		}
		requestContext, cancel := context.WithTimeout(broker.root, 5*time.Second)
		accepted, err := broker.runner.Cancel(requestContext, record.Request.BuildID, record.Request.Generation, reason)
		cancel()
		if err == nil && accepted {
			broker.start(current)
			return
		}
		select {
		case <-broker.root.Done():
			return
		case <-deadline.C:
			_ = broker.appendSyntheticTerminal(current, "failed", "build_cancel_unconfirmed", "BuildCell cancellation could not be confirmed", "unknown")
			return
		case <-ticker.C:
		}
	}
}

func (broker *Broker) reconcileLocalCancellation(record RunRecord, reason string, done <-chan struct{}) {
	select {
	case <-done:
	case <-broker.root.Done():
		broker.wait.Done()
		return
	}
	current, found, _ := broker.store.Lookup(context.Background(), record.Request.BuildID, record.Request.Generation)
	if !found || current.Terminal() {
		broker.wait.Done()
		return
	}
	if current.Dispatched {
		broker.retryDispatchedCancellation(current, reason, nil)
		return
	}
	_ = broker.appendSyntheticTerminal(current, "canceled", "build_canceled", "Build was canceled before BuildCell dispatch", "clean")
	broker.wait.Done()
}

func (broker *Broker) appendTerminal(record RunRecord, result Result) error {
	if err := result.Validate(); err != nil {
		return err
	}
	event := Event{
		Version: CurrentEventVersion, BuildID: record.Request.BuildID, Generation: record.Request.Generation,
		Sequence: 1, Attempt: max(record.Attempt, 1), Stage: result.State, Kind: "terminal", Message: "Build reached a terminal result",
		OccurredAt: broker.clock().UTC().Format(time.RFC3339Nano), Terminal: &result,
	}
	_, _, err := broker.store.Append(context.Background(), event, broker.clock().UTC())
	if err == nil {
		broker.signal()
	}
	return err
}

func (broker *Broker) appendSyntheticTerminal(record RunRecord, state, code, message, cleanup string) error {
	started, _ := time.Parse(time.RFC3339Nano, record.CreatedAt)
	result := Result{
		Version: CurrentResultVersion, BuildID: record.Request.BuildID, Generation: record.Request.Generation, State: state,
		SourceSnapshotID: record.Request.Source.SnapshotID, SourceDigest: record.Request.Source.SnapshotDigest,
		Outputs: []OutputResult{}, Services: []ServiceResult{},
		FailureCode: code, FailureMessage: message, StartedAt: started.UTC().Format(time.RFC3339Nano),
		FinishedAt: broker.clock().UTC().Format(time.RFC3339Nano), Cleanup: CleanupResult{Status: cleanup},
	}
	return broker.appendTerminal(record, result)
}

func (broker *Broker) retryDelay(attempt int) time.Duration {
	delay := broker.retryBase * time.Duration(1<<min(attempt-1, 5))
	return min(delay, 30*time.Second)
}

func (broker *Broker) cancelActive(buildID string, generation uint64) <-chan struct{} {
	key := string(brokerRunKey(buildID, generation))
	broker.mu.Lock()
	defer broker.mu.Unlock()
	active := broker.active[key]
	if active == nil {
		return nil
	}
	active.cancel()
	return active.done
}

func (broker *Broker) signal() {
	broker.mu.Lock()
	close(broker.notify)
	broker.notify = make(chan struct{})
	broker.mu.Unlock()
}

func (broker *Broker) String() string {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	return fmt.Sprintf("BuildBroker(active=%d)", len(broker.active))
}

var _ Runner = (*Orchestrator)(nil)
