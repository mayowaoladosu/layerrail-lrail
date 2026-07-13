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
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	bolt "go.etcd.io/bbolt"
)

var runRecordBucket = []byte("run-records-v1")

type BoltRunStore struct {
	db         *bolt.DB
	maxEntries int
}

func NewBoltRunStore(path string, maxEntries int) (*BoltRunStore, error) {
	if path == "" || maxEntries < 1 || maxEntries > 10_000_000 {
		return nil, fmt.Errorf("%w: Bolt run-store configuration is invalid", ErrController)
	}
	absolute, err := secureRunDatabasePath(path)
	if err != nil {
		return nil, err
	}
	database, err := bolt.Open(absolute, 0o600, &bolt.Options{Timeout: 5 * time.Second, NoGrowSync: false, FreelistType: bolt.FreelistMapType})
	if err != nil {
		return nil, fmt.Errorf("%w: open Bolt run database", ErrController)
	}
	if err := database.Update(func(transaction *bolt.Tx) error {
		_, err := transaction.CreateBucketIfNotExists(runRecordBucket)
		return err
	}); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("%w: initialize Bolt run database", ErrController)
	}
	return &BoltRunStore{db: database, maxEntries: maxEntries}, nil
}

func (store *BoltRunStore) Close() error { return store.db.Close() }

func (store *BoltRunStore) Claim(ctx context.Context, request ClaimRequest) (ClaimOutcome, RunRecord, error) {
	if err := ctx.Err(); err != nil {
		return "", RunRecord{}, err
	}
	if err := validateClaim(request); err != nil {
		return "", RunRecord{}, err
	}
	var outcome ClaimOutcome
	var record RunRecord
	err := store.db.Update(func(transaction *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		bucket := transaction.Bucket(runRecordBucket)
		contents := bucket.Get([]byte(request.BuildID))
		if contents == nil {
			if bucket.Stats().KeyN >= store.maxEntries {
				return fmt.Errorf("%w: Bolt run-store capacity exhausted", ErrController)
			}
			record = newRunRecord(request)
			outcome = ClaimAccepted
			return putRunRecord(bucket, record)
		}
		existing, err := decodeRunRecord(contents)
		if err != nil {
			return err
		}
		outcome, record = applyClaim(existing, request)
		if outcome == ClaimResumed {
			return putRunRecord(bucket, record)
		}
		return nil
	})
	return outcome, record, err
}

func (store *BoltRunStore) Heartbeat(ctx context.Context, buildID, owner string, phase buildworker.Phase, attempt uint32, now time.Time, leaseTTL time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.db.Update(func(transaction *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		bucket := transaction.Bucket(runRecordBucket)
		contents := bucket.Get([]byte(buildID))
		if contents == nil {
			return fmt.Errorf("%w: Bolt run record is absent", ErrController)
		}
		record, err := decodeRunRecord(contents)
		if err != nil {
			return err
		}
		if record.Owner != owner || record.Result.Terminal() || !validLeaseUpdate(phase, attempt, now, leaseTTL) {
			return fmt.Errorf("%w: Bolt run lease ownership or heartbeat is invalid", ErrController)
		}
		record.Phase = phase
		record.Attempt = attempt
		record.UpdatedAt = now.UTC()
		record.LeaseUntil = now.UTC().Add(leaseTTL)
		return putRunRecord(bucket, record)
	})
}

func (store *BoltRunStore) Finish(ctx context.Context, buildID, owner string, result Result, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.db.Update(func(transaction *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		bucket := transaction.Bucket(runRecordBucket)
		contents := bucket.Get([]byte(buildID))
		if contents == nil {
			return fmt.Errorf("%w: Bolt run record is absent", ErrController)
		}
		record, err := decodeRunRecord(contents)
		if err != nil {
			return err
		}
		if record.Owner != owner || validateTerminalResult(result, buildID, record.PayloadDigest) != nil || !terminalAllowedForRecord(record, result) || now.IsZero() {
			return fmt.Errorf("%w: Bolt terminal run result is invalid", ErrController)
		}
		record.Phase = result.Phase
		record.Attempt = result.Attempts
		record.Result = result
		record.UpdatedAt = now.UTC()
		record.LeaseUntil = time.Time{}
		return putRunRecord(bucket, record)
	})
}

func (store *BoltRunStore) Lookup(ctx context.Context, buildID string) (record RunRecord, exists bool, resultErr error) {
	if err := ctx.Err(); err != nil {
		return RunRecord{}, false, err
	}
	resultErr = store.db.View(func(transaction *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		contents := transaction.Bucket(runRecordBucket).Get([]byte(buildID))
		if contents == nil {
			return nil
		}
		var err error
		record, err = decodeRunRecord(contents)
		exists = err == nil
		return err
	})
	return record, exists, resultErr
}

func (store *BoltRunStore) RequestCancel(ctx context.Context, buildID string, generation uint64, now time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !validCancelRequest(buildID, generation, now) {
		return false, fmt.Errorf("%w: cancellation request is invalid", ErrController)
	}
	accepted := false
	err := store.db.Update(func(transaction *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		bucket := transaction.Bucket(runRecordBucket)
		contents := bucket.Get([]byte(buildID))
		if contents == nil {
			return nil
		}
		record, err := decodeRunRecord(contents)
		if err != nil {
			return err
		}
		if record.Generation != generation || record.Result.Terminal() {
			return nil
		}
		record.CancelRequested = true
		record.UpdatedAt = now.UTC()
		accepted = true
		return putRunRecord(bucket, record)
	})
	return accepted, err
}

func putRunRecord(bucket *bolt.Bucket, record RunRecord) error {
	if err := validateRunRecord(record); err != nil {
		return err
	}
	contents, err := canonicaljson.Marshal(record)
	if err != nil {
		return fmt.Errorf("%w: canonicalize Bolt run record", ErrController)
	}
	return bucket.Put([]byte(record.BuildID), contents)
}

func decodeRunRecord(contents []byte) (RunRecord, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var record RunRecord
	if err := decoder.Decode(&record); err != nil {
		return RunRecord{}, fmt.Errorf("%w: Bolt run record is malformed", ErrController)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return RunRecord{}, fmt.Errorf("%w: Bolt run record has trailing data", ErrController)
	}
	if err := validateRunState(runState{Version: runStateVersion, Records: map[string]RunRecord{record.BuildID: record}}, 1); err != nil {
		return RunRecord{}, err
	}
	return record, nil
}

func secureRunDatabasePath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("%w: run database path is invalid", ErrController)
	}
	parent := filepath.Dir(absolute)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", fmt.Errorf("%w: create run database directory", ErrController)
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(parent) {
		return "", fmt.Errorf("%w: run database directory traverses a symlink", ErrController)
	}
	if info, statErr := os.Lstat(absolute); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: run database is a symlink", ErrController)
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return "", fmt.Errorf("%w: inspect run database", ErrController)
	}
	return absolute, nil
}
