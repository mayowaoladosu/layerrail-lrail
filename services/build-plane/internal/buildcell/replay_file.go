package buildcell

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
	"strings"
	"sync"
	"time"

	"github.com/gofrs/flock"
	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
)

const replayStateVersion = 1

type replayState struct {
	Version int                    `json:"version"`
	Builds  map[string]replayEntry `json:"builds"`
	Nonces  map[string]bool        `json:"nonces"`
}

type FileReplayStore struct {
	mu         sync.Mutex
	path       string
	lock       *flock.Flock
	clock      func() time.Time
	maxEntries int
}

func NewFileReplayStore(path string, clock func() time.Time, maxEntries int) (*FileReplayStore, error) {
	if path == "" || maxEntries < 1 || maxEntries > 1_000_000 {
		return nil, fmt.Errorf("%w: durable replay configuration is invalid", ErrReplay)
	}
	absolute, err := filepath.Abs(path)
	if err != nil || filepath.Base(absolute) == "." {
		return nil, fmt.Errorf("%w: durable replay path is invalid", ErrReplay)
	}
	parent := filepath.Dir(absolute)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("%w: create durable replay directory", ErrReplay)
	}
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve durable replay directory", ErrReplay)
	}
	if filepath.Clean(resolvedParent) != filepath.Clean(parent) {
		return nil, fmt.Errorf("%w: durable replay directory may not traverse a symlink", ErrReplay)
	}
	if clock == nil {
		clock = time.Now
	}
	store := &FileReplayStore{
		path: absolute, lock: flock.New(absolute + ".lock"), clock: clock, maxEntries: maxEntries,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := store.withLock(ctx, func() error {
		_, err := os.Lstat(store.path)
		if errors.Is(err, os.ErrNotExist) {
			return store.writeState(newReplayState())
		}
		if err != nil {
			return err
		}
		_, err = store.readState()
		return err
	}); err != nil {
		_ = store.lock.Close()
		return nil, err
	}
	return store, nil
}

func (store *FileReplayStore) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.lock.Close()
}

func (store *FileReplayStore) Reserve(ctx context.Context, reservation Reservation) (ReservationOutcome, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := validateReservation(reservation); err != nil {
		return "", err
	}
	if !reservation.ExpiresAt.After(store.clock().UTC()) {
		return "", fmt.Errorf("%w: reservation is expired", ErrReplay)
	}
	var outcome ReservationOutcome
	err := store.withLock(ctx, func() error {
		state, err := store.readState()
		if err != nil {
			return err
		}
		outcome, err = reserveReplayState(state.Builds, state.Nonces, store.maxEntries, reservation)
		if err != nil || outcome != ReservationAccepted {
			return err
		}
		return store.writeState(state)
	})
	if err != nil {
		return "", err
	}
	return outcome, nil
}

func (store *FileReplayStore) withLock(ctx context.Context, operation func() error) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	locked, err := store.lock.TryLockContext(ctx, 10*time.Millisecond)
	if err != nil {
		return fmt.Errorf("%w: acquire durable replay lock", ErrReplay)
	}
	if !locked {
		return fmt.Errorf("%w: durable replay lock unavailable", ErrReplay)
	}
	defer store.lock.Unlock()
	return operation()
}

func (store *FileReplayStore) readState() (replayState, error) {
	info, err := os.Lstat(store.path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return replayState{}, fmt.Errorf("%w: durable replay state is absent or not regular", ErrReplay)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return replayState{}, fmt.Errorf("%w: durable replay state permissions are too broad", ErrReplay)
	}
	file, err := os.Open(store.path)
	if err != nil {
		return replayState{}, fmt.Errorf("%w: open durable replay state", ErrReplay)
	}
	defer file.Close()
	limit := int64(store.maxEntries)*512 + 1024
	contents, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(contents)) > limit {
		return replayState{}, fmt.Errorf("%w: durable replay state is unreadable or oversized", ErrReplay)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var state replayState
	if err := decoder.Decode(&state); err != nil {
		return replayState{}, fmt.Errorf("%w: durable replay state is malformed", ErrReplay)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return replayState{}, err
	}
	if err := validateReplayState(state, store.maxEntries); err != nil {
		return replayState{}, err
	}
	return state, nil
}

func (store *FileReplayStore) writeState(state replayState) error {
	if err := validateReplayState(state, store.maxEntries); err != nil {
		return err
	}
	contents, err := canonicaljson.Marshal(state)
	if err != nil {
		return fmt.Errorf("%w: canonicalize durable replay state", ErrReplay)
	}
	parent := filepath.Dir(store.path)
	temporary, err := os.CreateTemp(parent, ".replay-*.tmp")
	if err != nil {
		return fmt.Errorf("%w: create durable replay state", ErrReplay)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("%w: protect durable replay state", ErrReplay)
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("%w: write durable replay state", ErrReplay)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("%w: sync durable replay state", ErrReplay)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("%w: close durable replay state", ErrReplay)
	}
	if err := os.Rename(temporaryPath, store.path); err != nil {
		return fmt.Errorf("%w: publish durable replay state", ErrReplay)
	}
	if runtime.GOOS != "windows" {
		directory, err := os.Open(parent)
		if err != nil {
			return fmt.Errorf("%w: open durable replay directory", ErrReplay)
		}
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil || closeErr != nil {
			return fmt.Errorf("%w: sync durable replay directory", ErrReplay)
		}
	}
	return nil
}

func newReplayState() replayState {
	return replayState{Version: replayStateVersion, Builds: map[string]replayEntry{}, Nonces: map[string]bool{}}
}

func validateReplayState(state replayState, maxEntries int) error {
	if state.Version != replayStateVersion || state.Builds == nil || state.Nonces == nil ||
		len(state.Builds) > maxEntries || len(state.Nonces) > maxEntries {
		return fmt.Errorf("%w: durable replay state shape is invalid", ErrReplay)
	}
	for key, entry := range state.Builds {
		cellID, buildID, found := strings.Cut(key, ":")
		if !found || validateID(cellID, "cell") != nil || validateID(buildID, "bld") != nil || entry.Generation == 0 ||
			!noncePattern.MatchString(entry.Nonce) || !digestPattern.MatchString(entry.PayloadDigest) || !state.Nonces[cellID+":"+entry.Nonce] {
			return fmt.Errorf("%w: durable replay build watermark is invalid", ErrReplay)
		}
	}
	for key, present := range state.Nonces {
		cellID, nonce, found := strings.Cut(key, ":")
		if !present || !found || validateID(cellID, "cell") != nil || !noncePattern.MatchString(nonce) {
			return fmt.Errorf("%w: durable replay nonce watermark is invalid", ErrReplay)
		}
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: durable replay state has trailing data", ErrReplay)
	}
	return nil
}
