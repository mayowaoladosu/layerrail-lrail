package buildcell

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func reservation(generation uint64, nonceByte byte, payloadByte byte, expiresAt time.Time) Reservation {
	return Reservation{
		CellID: testCellID, BuildID: testBuildID, Generation: generation,
		Nonce:         string(repeatByte(nonceByte, 64)),
		PayloadDigest: "sha256:" + string(repeatByte(payloadByte, 64)),
		ExpiresAt:     expiresAt,
	}
}

func TestFileReplayStorePersistsAndSerializesInstances(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state", "replay.json")
	firstStore, err := NewFileReplayStore(path, func() time.Time { return testNow }, 16)
	if err != nil {
		t.Fatalf("NewFileReplayStore: %v", err)
	}
	secondStore, err := NewFileReplayStore(path, func() time.Time { return testNow }, 16)
	if err != nil {
		t.Fatalf("NewFileReplayStore second: %v", err)
	}
	first := reservation(1, 'a', 'b', testNow.Add(time.Hour))
	second := reservation(1, 'c', 'd', testNow.Add(time.Hour))
	second.BuildID = "bld_019b01da-7e31-7000-8000-000000000011"

	var wait sync.WaitGroup
	errorsSeen := make(chan error, 2)
	for index, candidate := range []Reservation{first, second} {
		index, candidate := index, candidate
		wait.Add(1)
		go func() {
			defer wait.Done()
			store := firstStore
			if index == 1 {
				store = secondStore
			}
			outcome, err := store.Reserve(context.Background(), candidate)
			if err != nil || outcome != ReservationAccepted {
				errorsSeen <- errors.New("durable concurrent reservation failed")
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Fatal(err)
	}
	if err := firstStore.Close(); err != nil {
		t.Fatalf("Close first: %v", err)
	}
	if err := secondStore.Close(); err != nil {
		t.Fatalf("Close second: %v", err)
	}

	restarted, err := NewFileReplayStore(path, func() time.Time { return testNow }, 16)
	if err != nil {
		t.Fatalf("restart store: %v", err)
	}
	defer restarted.Close()
	for _, candidate := range []Reservation{first, second} {
		outcome, err := restarted.Reserve(context.Background(), candidate)
		if err != nil || outcome != ReservationReplay {
			t.Fatalf("persisted replay = %s, %v", outcome, err)
		}
	}
}

func TestFileReplayStoreFailsClosedOnCorruption(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "replay.json")
	store, err := NewFileReplayStore(path, func() time.Time { return testNow }, 4)
	if err != nil {
		t.Fatalf("NewFileReplayStore: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"builds":{},"nonces":{},"unknown":true}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := NewFileReplayStore(path, func() time.Time { return testNow }, 4); !errors.Is(err, ErrReplay) {
		t.Fatalf("corrupt state error = %v", err)
	}
}

func TestBoltReplayStorePersistsAndSerializes(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "replay.db")
	store, err := NewBoltReplayStore(path, func() time.Time { return testNow }, 100)
	if err != nil {
		t.Fatalf("NewBoltReplayStore: %v", err)
	}
	candidate := reservation(1, 'a', 'b', testNow.Add(time.Hour))
	const callers = 32
	outcomes := make(chan ReservationOutcome, callers)
	errorsSeen := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			outcome, reserveErr := store.Reserve(context.Background(), candidate)
			outcomes <- outcome
			errorsSeen <- reserveErr
		}()
	}
	wait.Wait()
	close(outcomes)
	close(errorsSeen)
	accepted, replayed := 0, 0
	for outcome := range outcomes {
		if outcome == ReservationAccepted {
			accepted++
		}
		if outcome == ReservationReplay {
			replayed++
		}
	}
	for reserveErr := range errorsSeen {
		if reserveErr != nil {
			t.Fatalf("Reserve: %v", reserveErr)
		}
	}
	if accepted != 1 || replayed != callers-1 {
		t.Fatalf("accepted=%d replayed=%d", accepted, replayed)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	restarted, err := NewBoltReplayStore(path, func() time.Time { return testNow }, 100)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	defer restarted.Close()
	if outcome, err := restarted.Reserve(context.Background(), candidate); err != nil || outcome != ReservationReplay {
		t.Fatalf("restart replay=%s error=%v", outcome, err)
	}
}

func repeatByte(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func TestReplayStoreIsAtomicAndIdempotent(t *testing.T) {
	t.Parallel()
	store, err := NewMemoryReplayStore(func() time.Time { return testNow }, 100)
	if err != nil {
		t.Fatalf("NewMemoryReplayStore: %v", err)
	}
	input := reservation(1, 'a', 'b', testNow.Add(time.Hour))
	const workers = 64
	outcomes := make(chan ReservationOutcome, workers)
	errorsChannel := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			outcome, reserveErr := store.Reserve(context.Background(), input)
			if reserveErr != nil {
				errorsChannel <- reserveErr
				return
			}
			outcomes <- outcome
		}()
	}
	wait.Wait()
	close(outcomes)
	close(errorsChannel)
	for reserveErr := range errorsChannel {
		t.Fatalf("Reserve: %v", reserveErr)
	}
	accepted := 0
	replays := 0
	for outcome := range outcomes {
		switch outcome {
		case ReservationAccepted:
			accepted++
		case ReservationReplay:
			replays++
		default:
			t.Fatalf("unexpected outcome: %s", outcome)
		}
	}
	if accepted != 1 || replays != workers-1 {
		t.Fatalf("accepted=%d replay=%d", accepted, replays)
	}
}

func TestReplayStoreRejectsStaleConflictAndNonceReuse(t *testing.T) {
	t.Parallel()
	store, _ := NewMemoryReplayStore(func() time.Time { return testNow }, 100)
	accepted := reservation(2, 'a', 'b', testNow.Add(time.Hour))
	if outcome, err := store.Reserve(context.Background(), accepted); err != nil || outcome != ReservationAccepted {
		t.Fatalf("accepted = %s, %v", outcome, err)
	}
	stale := reservation(1, 'c', 'd', testNow.Add(time.Hour))
	if outcome, _ := store.Reserve(context.Background(), stale); outcome != ReservationStale {
		t.Fatalf("stale = %s", outcome)
	}
	conflict := reservation(2, 'a', 'e', testNow.Add(time.Hour))
	if outcome, _ := store.Reserve(context.Background(), conflict); outcome != ReservationConflict {
		t.Fatalf("conflict = %s", outcome)
	}
	nonceReuse := reservation(3, 'a', 'f', testNow.Add(time.Hour))
	nonceReuse.BuildID = "bld_019b01da-7e31-7000-8000-000000000011"
	if outcome, _ := store.Reserve(context.Background(), nonceReuse); outcome != ReservationConflict {
		t.Fatalf("nonce reuse = %s", outcome)
	}
}

func TestReplayStorePersistsWatermarksAndFailsClosed(t *testing.T) {
	t.Parallel()
	now := testNow
	store, _ := NewMemoryReplayStore(func() time.Time { return now }, 1)
	first := reservation(2, 'a', 'b', now.Add(time.Minute))
	if outcome, _ := store.Reserve(context.Background(), first); outcome != ReservationAccepted {
		t.Fatalf("first = %s", outcome)
	}
	second := reservation(1, 'c', 'd', now.Add(time.Hour))
	second.BuildID = "bld_019b01da-7e31-7000-8000-000000000011"
	if _, err := store.Reserve(context.Background(), second); err == nil {
		t.Fatal("expected capacity error")
	}
	now = now.Add(2 * time.Minute)
	second.ExpiresAt = now.Add(time.Hour)
	if _, err := store.Reserve(context.Background(), second); !errors.Is(err, ErrReplay) {
		t.Fatalf("capacity after expiry error = %v", err)
	}
	stale := reservation(1, 'e', 'f', now.Add(time.Hour))
	if outcome, err := store.Reserve(context.Background(), stale); err != nil || outcome != ReservationStale {
		t.Fatalf("persistent generation watermark = %s, %v", outcome, err)
	}
	expired := first
	expired.ExpiresAt = now
	if _, err := store.Reserve(context.Background(), expired); !errors.Is(err, ErrReplay) {
		t.Fatalf("expired reservation error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Reserve(ctx, first); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled reservation error = %v", err)
	}
}
