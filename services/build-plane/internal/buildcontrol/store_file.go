package buildcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/gofrs/flock"
	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
)

const runStateVersion = 1

type runState struct {
	Version int                  `json:"version"`
	Records map[string]RunRecord `json:"records"`
}

type FileRunStore struct {
	mu         sync.Mutex
	path       string
	lock       *flock.Flock
	maxEntries int
}

func NewFileRunStore(path string, maxEntries int) (*FileRunStore, error) {
	if path == "" || maxEntries < 1 || maxEntries > 100_000 {
		return nil, fmt.Errorf("%w: durable run-store configuration is invalid", ErrController)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("%w: durable run-store path is invalid", ErrController)
	}
	parent := filepath.Dir(absolute)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("%w: create durable run-store directory", ErrController)
	}
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil || filepath.Clean(resolvedParent) != filepath.Clean(parent) {
		return nil, fmt.Errorf("%w: durable run-store directory may not traverse a symlink", ErrController)
	}
	store := &FileRunStore{path: absolute, lock: flock.New(absolute + ".lock"), maxEntries: maxEntries}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := store.withLock(ctx, func() error {
		_, statErr := os.Lstat(store.path)
		if errors.Is(statErr, os.ErrNotExist) {
			return store.writeState(runState{Version: runStateVersion, Records: map[string]RunRecord{}})
		}
		if statErr != nil {
			return statErr
		}
		_, readErr := store.readState()
		return readErr
	}); err != nil {
		_ = store.lock.Close()
		return nil, err
	}
	return store, nil
}

func (store *FileRunStore) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.lock.Close()
}

func (store *FileRunStore) Claim(ctx context.Context, request ClaimRequest) (ClaimOutcome, RunRecord, error) {
	if err := ctx.Err(); err != nil {
		return "", RunRecord{}, err
	}
	if err := validateClaim(request); err != nil {
		return "", RunRecord{}, err
	}
	var outcome ClaimOutcome
	var record RunRecord
	err := store.withLock(ctx, func() error {
		state, err := store.readState()
		if err != nil {
			return err
		}
		existing, exists := state.Records[request.BuildID]
		if !exists {
			if len(state.Records) >= store.maxEntries {
				return fmt.Errorf("%w: durable run-store capacity exhausted", ErrController)
			}
			record = newRunRecord(request)
			state.Records[request.BuildID] = record
			outcome = ClaimAccepted
			return store.writeState(state)
		}
		outcome, record = applyClaim(existing, request)
		if outcome == ClaimResumed {
			state.Records[request.BuildID] = record
			return store.writeState(state)
		}
		return nil
	})
	return outcome, record, err
}

func (store *FileRunStore) Heartbeat(ctx context.Context, buildID, owner string, phase buildworker.Phase, attempt uint32, now time.Time, leaseTTL time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.withLock(ctx, func() error {
		state, err := store.readState()
		if err != nil {
			return err
		}
		record, exists := state.Records[buildID]
		if !exists || record.Owner != owner || record.Result.Terminal() || !validLeaseUpdate(phase, attempt, now, leaseTTL) {
			return fmt.Errorf("%w: durable run lease ownership or heartbeat is invalid", ErrController)
		}
		record.Phase = phase
		record.Attempt = attempt
		record.UpdatedAt = now.UTC()
		record.LeaseUntil = now.UTC().Add(leaseTTL)
		state.Records[buildID] = record
		return store.writeState(state)
	})
}

func (store *FileRunStore) Finish(ctx context.Context, buildID, owner string, result Result, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.withLock(ctx, func() error {
		state, err := store.readState()
		if err != nil {
			return err
		}
		record, exists := state.Records[buildID]
		if !exists || record.Owner != owner || validateTerminalResult(result, buildID, record.PayloadDigest) != nil || !terminalAllowedForRecord(record, result) || now.IsZero() {
			return fmt.Errorf("%w: durable terminal run result is invalid", ErrController)
		}
		record.Phase = result.Phase
		record.Attempt = result.Attempts
		record.Result = result
		record.UpdatedAt = now.UTC()
		record.LeaseUntil = time.Time{}
		state.Records[buildID] = record
		return store.writeState(state)
	})
}

func (store *FileRunStore) Lookup(ctx context.Context, buildID string) (record RunRecord, exists bool, resultErr error) {
	if err := ctx.Err(); err != nil {
		return RunRecord{}, false, err
	}
	resultErr = store.withLock(ctx, func() error {
		state, err := store.readState()
		if err != nil {
			return err
		}
		record, exists = state.Records[buildID]
		return nil
	})
	return record, exists, resultErr
}

func (store *FileRunStore) RequestCancel(ctx context.Context, buildID string, generation uint64, now time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !validCancelRequest(buildID, generation, now) {
		return false, fmt.Errorf("%w: cancellation request is invalid", ErrController)
	}
	accepted := false
	err := store.withLock(ctx, func() error {
		state, err := store.readState()
		if err != nil {
			return err
		}
		record, exists := state.Records[buildID]
		if !exists || record.Generation != generation || record.Result.Terminal() {
			return nil
		}
		record.CancelRequested = true
		record.UpdatedAt = now.UTC()
		state.Records[buildID] = record
		accepted = true
		return store.writeState(state)
	})
	return accepted, err
}

func (store *FileRunStore) withLock(ctx context.Context, operation func() error) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	locked, err := store.lock.TryLockContext(ctx, 10*time.Millisecond)
	if err != nil || !locked {
		return fmt.Errorf("%w: acquire durable run-store lock", ErrController)
	}
	defer store.lock.Unlock()
	return operation()
}

func (store *FileRunStore) readState() (runState, error) {
	info, err := os.Lstat(store.path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return runState{}, fmt.Errorf("%w: durable run state is absent or unsafe", ErrController)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return runState{}, fmt.Errorf("%w: durable run state permissions are too broad", ErrController)
	}
	file, err := os.Open(store.path)
	if err != nil {
		return runState{}, fmt.Errorf("%w: open durable run state", ErrController)
	}
	defer file.Close()
	limit := int64(store.maxEntries)*16*1024 + 1024
	contents, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(contents)) > limit {
		return runState{}, fmt.Errorf("%w: durable run state is unreadable or oversized", ErrController)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var state runState
	if err := decoder.Decode(&state); err != nil {
		return runState{}, fmt.Errorf("%w: durable run state is malformed", ErrController)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return runState{}, fmt.Errorf("%w: durable run state has trailing data", ErrController)
	}
	if err := validateRunState(state, store.maxEntries); err != nil {
		return runState{}, err
	}
	return state, nil
}

func (store *FileRunStore) writeState(state runState) error {
	if err := validateRunState(state, store.maxEntries); err != nil {
		return err
	}
	contents, err := canonicaljson.Marshal(state)
	if err != nil {
		return fmt.Errorf("%w: canonicalize durable run state", ErrController)
	}
	parent := filepath.Dir(store.path)
	temporary, err := os.CreateTemp(parent, ".runs-*.tmp")
	if err != nil {
		return fmt.Errorf("%w: create durable run state", ErrController)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("%w: protect durable run state", ErrController)
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("%w: write durable run state", ErrController)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("%w: sync durable run state", ErrController)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("%w: close durable run state", ErrController)
	}
	if err := os.Rename(temporaryPath, store.path); err != nil {
		return fmt.Errorf("%w: publish durable run state", ErrController)
	}
	if runtime.GOOS != "windows" {
		directory, err := os.Open(parent)
		if err != nil {
			return fmt.Errorf("%w: open durable run directory", ErrController)
		}
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil || closeErr != nil {
			return fmt.Errorf("%w: sync durable run directory", ErrController)
		}
	}
	return nil
}

func validateRunState(state runState, maxEntries int) error {
	if state.Version != runStateVersion || state.Records == nil || len(state.Records) > maxEntries {
		return fmt.Errorf("%w: durable run state shape is invalid", ErrController)
	}
	for key, record := range state.Records {
		if record.BuildID != key || validateRunRecord(record) != nil {
			return fmt.Errorf("%w: durable run record is invalid", ErrController)
		}
	}
	return nil
}
