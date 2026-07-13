package buildorchestrator

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
	bolt "go.etcd.io/bbolt"
)

const BrokerRecordVersion = 1

var (
	brokerRunsBucket       = []byte("build-service-runs-v1")
	brokerEventsBucket     = []byte("build-service-events-v1")
	brokerCheckpointBucket = []byte("build-service-checkpoints-v1")
)

type RunRecord struct {
	Version       int     `json:"version"`
	Request       Request `json:"request"`
	RequestDigest string  `json:"request_digest"`
	State         string  `json:"state"`
	Stage         string  `json:"stage"`
	Attempt       uint32  `json:"attempt"`
	LastSequence  uint64  `json:"last_sequence"`
	Dispatched    bool    `json:"dispatched"`
	Result        *Result `json:"result,omitempty"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

type BoltBrokerStore struct {
	db           *bolt.DB
	maxRuns      int
	maxEventsRun int
}

func NewBoltBrokerStore(path string, maxRuns, maxEventsPerRun int) (*BoltBrokerStore, error) {
	if path == "" || maxRuns < 1 || maxRuns > 10_000_000 || maxEventsPerRun < 1 || maxEventsPerRun > 10_000_000 {
		return nil, errors.New("build broker store configuration is invalid")
	}
	absolute, err := secureBrokerDatabasePath(path)
	if err != nil {
		return nil, err
	}
	database, err := bolt.Open(absolute, 0o600, &bolt.Options{Timeout: 5 * time.Second, NoGrowSync: false, FreelistType: bolt.FreelistMapType})
	if err != nil {
		return nil, errors.New("open build broker database")
	}
	if err := database.Update(func(transaction *bolt.Tx) error {
		for _, name := range [][]byte{brokerRunsBucket, brokerEventsBucket, brokerCheckpointBucket} {
			if _, err := transaction.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		_ = database.Close()
		return nil, errors.New("initialize build broker database")
	}
	return &BoltBrokerStore{db: database, maxRuns: maxRuns, maxEventsRun: maxEventsPerRun}, nil
}

func (store *BoltBrokerStore) Close() error { return store.db.Close() }

func (store *BoltBrokerStore) Claim(ctx context.Context, request Request, now time.Time) (RunRecord, bool, error) {
	if err := request.Validate(now); err != nil {
		return RunRecord{}, false, err
	}
	requestBytes, err := canonicaljson.Marshal(request)
	if err != nil {
		return RunRecord{}, false, errors.New("canonicalize broker request")
	}
	requestDigest := digestBytes(requestBytes)
	key := brokerRunKey(request.BuildID, request.Generation)
	var record RunRecord
	created := false
	err = store.db.Update(func(transaction *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		runs := transaction.Bucket(brokerRunsBucket)
		if contents := runs.Get(key); contents != nil {
			existing, decodeErr := decodeCanonical[RunRecord](contents)
			if decodeErr != nil {
				return decodeErr
			}
			if existing.RequestDigest != requestDigest {
				return errors.New("build generation already has a different immutable request")
			}
			record = existing
			return nil
		}
		if runs.Stats().KeyN >= store.maxRuns {
			return errors.New("build broker run capacity is exhausted")
		}
		latest, found, latestErr := latestRun(runs, request.BuildID)
		if latestErr != nil {
			return latestErr
		}
		if found && request.Generation <= latest.Request.Generation {
			return errors.New("build generation is stale")
		}
		if found && !latest.Terminal() {
			return errors.New("a prior build generation is still active")
		}
		timestamp := now.UTC().Format(time.RFC3339Nano)
		record = RunRecord{
			Version: BrokerRecordVersion, Request: request, RequestDigest: requestDigest, State: "accepted", Stage: "accepted",
			Attempt: 0, LastSequence: 0, Dispatched: false, CreatedAt: timestamp, UpdatedAt: timestamp,
		}
		created = true
		return putCanonical(runs, key, record)
	})
	return record, created, err
}

func (store *BoltBrokerStore) Lookup(ctx context.Context, buildID string, generation uint64) (RunRecord, bool, error) {
	if err := validateBrokerIdentity(buildID, generation); err != nil {
		return RunRecord{}, false, err
	}
	var record RunRecord
	found := false
	err := store.db.View(func(transaction *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		contents := transaction.Bucket(brokerRunsBucket).Get(brokerRunKey(buildID, generation))
		if contents == nil {
			return nil
		}
		var decodeErr error
		record, decodeErr = decodeCanonical[RunRecord](contents)
		found = decodeErr == nil
		return decodeErr
	})
	return record, found, err
}

func (store *BoltBrokerStore) SetState(ctx context.Context, buildID string, generation uint64, state string, now time.Time) (RunRecord, error) {
	if err := validateBrokerIdentity(buildID, generation); err != nil || !slices.Contains([]string{"running", "retrying", "canceling"}, state) || now.IsZero() {
		return RunRecord{}, errors.New("build broker state update is invalid")
	}
	var record RunRecord
	err := store.db.Update(func(transaction *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		runs := transaction.Bucket(brokerRunsBucket)
		key := brokerRunKey(buildID, generation)
		contents := runs.Get(key)
		if contents == nil {
			return errors.New("build broker run is absent")
		}
		var err error
		record, err = decodeCanonical[RunRecord](contents)
		if err != nil {
			return err
		}
		if record.Terminal() || !validBrokerTransition(record.State, state) {
			return errors.New("build broker state transition is invalid")
		}
		record.State = state
		record.UpdatedAt = now.UTC().Format(time.RFC3339Nano)
		return putCanonical(runs, key, record)
	})
	return record, err
}

func (store *BoltBrokerStore) Append(ctx context.Context, event Event, now time.Time) (Event, RunRecord, error) {
	if err := event.Validate(); err != nil || now.IsZero() {
		return Event{}, RunRecord{}, errors.New("build broker event is invalid")
	}
	key := brokerRunKey(event.BuildID, event.Generation)
	var record RunRecord
	var persisted Event
	err := store.db.Update(func(transaction *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		runs := transaction.Bucket(brokerRunsBucket)
		contents := runs.Get(key)
		if contents == nil {
			return errors.New("build broker run is absent")
		}
		var decodeErr error
		record, decodeErr = decodeCanonical[RunRecord](contents)
		if decodeErr != nil {
			return decodeErr
		}
		if record.Terminal() {
			return errors.New("build broker run is already terminal")
		}
		occurredAt, occurredErr := time.Parse(time.RFC3339Nano, event.OccurredAt)
		createdAt, createdErr := time.Parse(time.RFC3339Nano, record.CreatedAt)
		if occurredErr != nil || createdErr != nil || occurredAt.Before(createdAt.Add(-time.Minute)) || occurredAt.After(now.UTC().Add(time.Minute)) {
			return errors.New("build broker event time is outside the run window")
		}
		eventsRoot := transaction.Bucket(brokerEventsBucket)
		events, bucketErr := eventsRoot.CreateBucketIfNotExists(key)
		if bucketErr != nil {
			return bucketErr
		}
		if events.Stats().KeyN >= store.maxEventsRun {
			return errors.New("build broker event capacity is exhausted")
		}
		persisted = event
		persisted.Sequence = record.LastSequence + 1
		if err := persisted.Validate(); err != nil {
			return err
		}
		if err := putCanonical(events, sequenceKey(persisted.Sequence), persisted); err != nil {
			return err
		}
		record.LastSequence = persisted.Sequence
		record.Stage = persisted.Stage
		record.Attempt = max(record.Attempt, persisted.Attempt)
		record.Dispatched = record.Dispatched || persisted.Stage == "assigned"
		record.UpdatedAt = now.UTC().Format(time.RFC3339Nano)
		if persisted.Terminal != nil {
			copyResult := *persisted.Terminal
			record.Result = &copyResult
			record.State = copyResult.State
		} else if record.State != "canceling" {
			record.State = "running"
		}
		return putCanonical(runs, key, record)
	})
	return persisted, record, err
}

func (store *BoltBrokerStore) EventsAfter(ctx context.Context, buildID string, generation, after uint64, limit int) ([]Event, error) {
	if err := validateBrokerIdentity(buildID, generation); err != nil || limit < 1 || limit > 1000 {
		return nil, errors.New("build broker event query is invalid")
	}
	result := make([]Event, 0, limit)
	err := store.db.View(func(transaction *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		events := transaction.Bucket(brokerEventsBucket).Bucket(brokerRunKey(buildID, generation))
		if events == nil {
			return nil
		}
		cursor := events.Cursor()
		for key, contents := cursor.Seek(sequenceKey(after + 1)); key != nil && len(result) < limit; key, contents = cursor.Next() {
			event, err := decodeCanonical[Event](contents)
			if err != nil {
				return err
			}
			result = append(result, event)
		}
		return nil
	})
	return result, err
}

func (store *BoltBrokerStore) Nonterminal(ctx context.Context, limit int) ([]RunRecord, error) {
	if limit < 1 || limit > 10_000 {
		return nil, errors.New("build broker recovery limit is invalid")
	}
	result := make([]RunRecord, 0)
	err := store.db.View(func(transaction *bolt.Tx) error {
		return transaction.Bucket(brokerRunsBucket).ForEach(func(_, contents []byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			record, err := decodeCanonical[RunRecord](contents)
			if err != nil {
				return err
			}
			if !record.Terminal() {
				if len(result) >= limit {
					return errors.New("build broker recovery limit exceeded")
				}
				result = append(result, record)
			}
			return nil
		})
	})
	return result, err
}

func (store *BoltBrokerStore) Load(ctx context.Context, buildID string, generation uint64) (Checkpoint, bool, error) {
	if err := validateBrokerIdentity(buildID, generation); err != nil {
		return Checkpoint{}, false, err
	}
	var checkpoint Checkpoint
	found := false
	err := store.db.View(func(transaction *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		contents := transaction.Bucket(brokerCheckpointBucket).Get(brokerRunKey(buildID, generation))
		if contents == nil {
			return nil
		}
		var decodeErr error
		checkpoint, decodeErr = decodeCanonical[Checkpoint](contents)
		found = decodeErr == nil
		return decodeErr
	})
	return checkpoint, found, err
}

func (store *BoltBrokerStore) Save(ctx context.Context, checkpoint Checkpoint) error {
	if err := validateCheckpointRecord(checkpoint); err != nil {
		return err
	}
	key := brokerRunKey(checkpoint.BuildID, checkpoint.Generation)
	return store.db.Update(func(transaction *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		runContents := transaction.Bucket(brokerRunsBucket).Get(key)
		if runContents == nil {
			return errors.New("build checkpoint has no broker run")
		}
		run, err := decodeCanonical[RunRecord](runContents)
		if err != nil || run.RequestDigest != checkpoint.RequestDigest {
			return errors.New("build checkpoint request digest differs from broker run")
		}
		checkpoints := transaction.Bucket(brokerCheckpointBucket)
		if existingContents := checkpoints.Get(key); existingContents != nil {
			existing, decodeErr := decodeCanonical[Checkpoint](existingContents)
			if decodeErr != nil {
				return decodeErr
			}
			if existing.Envelope.Payload.BuildID != "" && (!bytes.Equal(canonicalOrNil(existing.Envelope), canonicalOrNil(checkpoint.Envelope)) ||
				!bytes.Equal(canonicalOrNil(existing.Partial), canonicalOrNil(checkpoint.Partial))) {
				return errors.New("signed build checkpoint identity is immutable")
			}
		}
		return putCanonical(checkpoints, key, checkpoint)
	})
}

func (record RunRecord) Terminal() bool {
	return slices.Contains([]string{"complete", "failed", "canceled", "waiting"}, record.State)
}

func (record RunRecord) Validate() error {
	if record.Version != BrokerRecordVersion || validateBrokerIdentity(record.Request.BuildID, record.Request.Generation) != nil ||
		!digestPattern.MatchString(record.RequestDigest) || !slices.Contains([]string{"accepted", "running", "retrying", "canceling", "complete", "failed", "canceled", "waiting"}, record.State) ||
		!stagePattern.MatchString(record.Stage) {
		return errors.New("build broker run record identity or state is invalid")
	}
	created, createdErr := time.Parse(time.RFC3339Nano, record.CreatedAt)
	updated, updatedErr := time.Parse(time.RFC3339Nano, record.UpdatedAt)
	if createdErr != nil || updatedErr != nil || updated.Before(created) || record.Request.Validate(created) != nil {
		return errors.New("build broker run record timing or request is invalid")
	}
	requestBytes, err := canonicaljson.Marshal(record.Request)
	if err != nil || digestBytes(requestBytes) != record.RequestDigest {
		return errors.New("build broker run request digest is invalid")
	}
	if record.Terminal() {
		if record.Result == nil || record.Result.State != record.State || record.Result.BuildID != record.Request.BuildID ||
			record.Result.Generation != record.Request.Generation || record.Result.Validate() != nil {
			return errors.New("terminal build broker run lacks a valid result")
		}
	} else if record.Result != nil {
		return errors.New("nonterminal build broker run contains a terminal result")
	}
	return nil
}

func validateCheckpointRecord(checkpoint Checkpoint) error {
	if checkpoint.Version != 1 || validateBrokerIdentity(checkpoint.BuildID, checkpoint.Generation) != nil ||
		!digestPattern.MatchString(checkpoint.RequestDigest) {
		return errors.New("build checkpoint identity is invalid")
	}
	started, startErr := time.Parse(time.RFC3339Nano, checkpoint.StartedAt)
	updated, updateErr := time.Parse(time.RFC3339Nano, checkpoint.UpdatedAt)
	if startErr != nil || updateErr != nil || updated.Before(started) {
		return errors.New("build checkpoint time is invalid")
	}
	if checkpoint.Envelope.Payload.BuildID != "" {
		if checkpoint.Envelope.Payload.BuildID != checkpoint.BuildID || checkpoint.Envelope.Payload.Generation != checkpoint.Generation ||
			checkpoint.Partial.AssignmentDigest != digestCanonicalPayload(checkpoint.Envelope.Payload) {
			return errors.New("signed build checkpoint payload is invalid")
		}
	}
	return nil
}

func validBrokerTransition(from, to string) bool {
	allowed := map[string][]string{
		"accepted": {"running", "canceling"}, "running": {"retrying", "canceling"},
		"retrying": {"running", "canceling"}, "canceling": {},
	}
	return slices.Contains(allowed[from], to) || from == to
}

func latestRun(bucket *bolt.Bucket, buildID string) (RunRecord, bool, error) {
	prefix := []byte(buildID + "/")
	cursor := bucket.Cursor()
	var latest RunRecord
	found := false
	for key, contents := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, contents = cursor.Next() {
		record, err := decodeCanonical[RunRecord](contents)
		if err != nil {
			return RunRecord{}, false, err
		}
		if !found || record.Request.Generation > latest.Request.Generation {
			latest = record
			found = true
		}
	}
	return latest, found, nil
}

func validateBrokerIdentity(buildID string, generation uint64) error {
	identity, err := platformid.Parse(buildID)
	if err != nil || identity.Prefix() != "bld" || generation == 0 {
		return errors.New("build broker identity is invalid")
	}
	return nil
}

func brokerRunKey(buildID string, generation uint64) []byte {
	return []byte(fmt.Sprintf("%s/%020d", buildID, generation))
}

func sequenceKey(sequence uint64) []byte {
	result := make([]byte, 8)
	binary.BigEndian.PutUint64(result, sequence)
	return result
}

func putCanonical(bucket *bolt.Bucket, key []byte, value any) error {
	if err := validateDurableValue(value); err != nil {
		return err
	}
	contents, err := canonicaljson.Marshal(value)
	if err != nil {
		return errors.New("canonicalize build broker record")
	}
	return bucket.Put(key, contents)
}

func decodeCanonical[T any](contents []byte) (T, error) {
	var result T
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return result, errors.New("build broker record is malformed")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return result, errors.New("build broker record has trailing data")
	}
	canonical, err := canonicaljson.Marshal(result)
	if err != nil || !bytes.Equal(contents, canonical) {
		return result, errors.New("build broker record is not canonical")
	}
	if err := validateDurableValue(result); err != nil {
		return result, err
	}
	return result, nil
}

func validateDurableValue(value any) error {
	switch typed := value.(type) {
	case RunRecord:
		return typed.Validate()
	case Event:
		return typed.Validate()
	case Checkpoint:
		return validateCheckpointRecord(typed)
	default:
		return errors.New("unsupported build broker durable value")
	}
}

func canonicalOrNil(value any) []byte {
	contents, _ := canonicaljson.Marshal(value)
	return contents
}

func secureBrokerDatabasePath(value string) (string, error) {
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", errors.New("build broker database path is invalid")
	}
	parent := filepath.Dir(absolute)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", errors.New("create build broker database directory")
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(parent) {
		return "", errors.New("build broker database directory traverses a symlink")
	}
	if info, statErr := os.Lstat(absolute); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("build broker database is a symlink")
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return "", errors.New("inspect build broker database")
	}
	return absolute, nil
}

var _ CheckpointStore = (*BoltBrokerStore)(nil)
