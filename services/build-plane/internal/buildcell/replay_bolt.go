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
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	bolt "go.etcd.io/bbolt"
)

var replayBuildBucket = []byte("build-watermarks-v1")
var replayNonceBucket = []byte("nonce-watermarks-v1")

type BoltReplayStore struct {
	db         *bolt.DB
	clock      func() time.Time
	maxEntries int
}

func NewBoltReplayStore(path string, clock func() time.Time, maxEntries int) (*BoltReplayStore, error) {
	if path == "" || maxEntries < 1 || maxEntries > 10_000_000 {
		return nil, fmt.Errorf("%w: Bolt replay configuration is invalid", ErrReplay)
	}
	absolute, err := secureDatabasePath(path)
	if err != nil {
		return nil, err
	}
	if clock == nil {
		clock = time.Now
	}
	database, err := bolt.Open(absolute, 0o600, &bolt.Options{Timeout: 5 * time.Second, NoGrowSync: false, FreelistType: bolt.FreelistMapType})
	if err != nil {
		return nil, fmt.Errorf("%w: open Bolt replay database", ErrReplay)
	}
	store := &BoltReplayStore{db: database, clock: clock, maxEntries: maxEntries}
	if err := database.Update(func(transaction *bolt.Tx) error {
		if _, err := transaction.CreateBucketIfNotExists(replayBuildBucket); err != nil {
			return err
		}
		_, err := transaction.CreateBucketIfNotExists(replayNonceBucket)
		return err
	}); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("%w: initialize Bolt replay database", ErrReplay)
	}
	return store, nil
}

func (store *BoltReplayStore) Close() error { return store.db.Close() }

func (store *BoltReplayStore) Reserve(ctx context.Context, reservation Reservation) (ReservationOutcome, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := validateReservation(reservation); err != nil {
		return "", err
	}
	if !reservation.ExpiresAt.After(store.clock().UTC()) {
		return "", fmt.Errorf("%w: reservation is expired", ErrReplay)
	}
	outcome := ReservationConflict
	err := store.db.Update(func(transaction *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		builds := transaction.Bucket(replayBuildBucket)
		nonces := transaction.Bucket(replayNonceBucket)
		buildKey := []byte(reservation.CellID + ":" + reservation.BuildID)
		nonceKey := []byte(reservation.CellID + ":" + reservation.Nonce)
		if contents := builds.Get(buildKey); contents != nil {
			existing, err := decodeReplayEntry(contents)
			if err != nil {
				return err
			}
			if reservation.Generation < existing.Generation {
				outcome = ReservationStale
				return nil
			}
			if reservation.Generation == existing.Generation {
				if reservation.Nonce == existing.Nonce && reservation.PayloadDigest == existing.PayloadDigest {
					outcome = ReservationReplay
				} else {
					outcome = ReservationConflict
				}
				return nil
			}
		}
		if nonces.Get(nonceKey) != nil {
			outcome = ReservationConflict
			return nil
		}
		if builds.Stats().KeyN >= store.maxEntries || nonces.Stats().KeyN >= store.maxEntries {
			return fmt.Errorf("%w: Bolt replay capacity exhausted", ErrReplay)
		}
		entry, err := canonicaljson.Marshal(replayEntry{Generation: reservation.Generation, Nonce: reservation.Nonce, PayloadDigest: reservation.PayloadDigest})
		if err != nil {
			return err
		}
		if err := builds.Put(buildKey, entry); err != nil {
			return err
		}
		if err := nonces.Put(nonceKey, []byte{1}); err != nil {
			return err
		}
		outcome = ReservationAccepted
		return nil
	})
	if err != nil {
		return "", err
	}
	return outcome, nil
}

func decodeReplayEntry(contents []byte) (replayEntry, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var entry replayEntry
	if err := decoder.Decode(&entry); err != nil {
		return replayEntry{}, fmt.Errorf("%w: Bolt replay entry is malformed", ErrReplay)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) || entry.Generation == 0 || !noncePattern.MatchString(entry.Nonce) || !digestPattern.MatchString(entry.PayloadDigest) {
		return replayEntry{}, fmt.Errorf("%w: Bolt replay entry is invalid", ErrReplay)
	}
	return entry, nil
}

func secureDatabasePath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("%w: database path is invalid", ErrReplay)
	}
	parent := filepath.Dir(absolute)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", fmt.Errorf("%w: create database directory", ErrReplay)
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(parent) {
		return "", fmt.Errorf("%w: database directory traverses a symlink", ErrReplay)
	}
	if info, statErr := os.Lstat(absolute); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: database file is a symlink", ErrReplay)
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return "", fmt.Errorf("%w: inspect database file", ErrReplay)
	}
	return absolute, nil
}
