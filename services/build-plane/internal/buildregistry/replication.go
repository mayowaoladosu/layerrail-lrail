package buildregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
	bolt "go.etcd.io/bbolt"
)

const ReplicationRequestVersion = 1
const ReplicationStatusRequested = "requested"

var registryReferencePattern = regexp.MustCompile(`^[a-z0-9.-]+(?::[0-9]{1,5})?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$`)
var replicationRequestsBucket = []byte("registry-replication-requests-v1")
var replicationBusinessBucket = []byte("registry-replication-business-v1")

type ReplicationRequest struct {
	Version        int      `json:"version"`
	OperationID    string   `json:"operation_id"`
	OrganizationID string   `json:"organization_id"`
	ProjectID      string   `json:"project_id"`
	ArtifactRef    string   `json:"artifact_ref"`
	Digest         string   `json:"digest"`
	TargetCells    []string `json:"target_cells"`
	Status         string   `json:"status"`
	RequestedAt    string   `json:"requested_at"`
}

type ReplicationStore interface {
	Reserve(ctx context.Context, key string, request ReplicationRequest) (ReplicationRequest, bool, error)
	Get(ctx context.Context, operationID string) (ReplicationRequest, bool, error)
}

type ReplicationPlanner struct {
	store ReplicationStore
	clock func() time.Time
	newID func() (platformid.ID, error)
}

func NewReplicationPlanner(store ReplicationStore, clock func() time.Time, newID func() (platformid.ID, error)) (*ReplicationPlanner, error) {
	if store == nil {
		return nil, errors.New("replication planner store is absent")
	}
	if clock == nil {
		clock = time.Now
	}
	if newID == nil {
		newID = func() (platformid.ID, error) { return platformid.New("op") }
	}
	return &ReplicationPlanner{store: store, clock: clock, newID: newID}, nil
}

func (planner *ReplicationPlanner) Request(ctx context.Context, organizationID, projectID, artifactRef, digest string, targetCells []string) (ReplicationRequest, bool, error) {
	targetCells = append([]string(nil), targetCells...)
	sort.Strings(targetCells)
	targetCells = slices.Compact(targetCells)
	operationID, err := planner.newID()
	if err != nil || operationID.Prefix() != "op" {
		return ReplicationRequest{}, false, errors.New("replication operation identity could not be created")
	}
	request := ReplicationRequest{
		Version: ReplicationRequestVersion, OperationID: string(operationID), OrganizationID: organizationID, ProjectID: projectID,
		ArtifactRef: artifactRef, Digest: digest, TargetCells: targetCells, Status: ReplicationStatusRequested,
		RequestedAt: planner.clock().UTC().Format(time.RFC3339Nano),
	}
	if err := validateReplicationRequest(request); err != nil {
		return ReplicationRequest{}, false, err
	}
	key, err := replicationBusinessKey(request)
	if err != nil {
		return ReplicationRequest{}, false, err
	}
	return planner.store.Reserve(ctx, key, request)
}

func (planner *ReplicationPlanner) Get(ctx context.Context, operationID string) (ReplicationRequest, bool, error) {
	return planner.store.Get(ctx, operationID)
}

func replicationBusinessKey(request ReplicationRequest) (string, error) {
	contents, err := canonicaljson.Marshal(struct {
		OrganizationID string   `json:"organization_id"`
		ProjectID      string   `json:"project_id"`
		Digest         string   `json:"digest"`
		TargetCells    []string `json:"target_cells"`
	}{request.OrganizationID, request.ProjectID, request.Digest, request.TargetCells})
	if err != nil {
		return "", errors.New("canonicalize replication identity")
	}
	return sha256Text(string(contents)), nil
}

func validateReplicationRequest(request ReplicationRequest) error {
	operation, operationErr := platformid.Parse(request.OperationID)
	organization, organizationErr := platformid.Parse(request.OrganizationID)
	project, projectErr := platformid.Parse(request.ProjectID)
	requestedAt, timeErr := time.Parse(time.RFC3339Nano, request.RequestedAt)
	if request.Version != ReplicationRequestVersion || operationErr != nil || operation.Prefix() != "op" || organizationErr != nil || organization.Prefix() != "org" ||
		projectErr != nil || project.Prefix() != "prj" || !validDigest(request.Digest) || !registryReferencePattern.MatchString(request.ArtifactRef) ||
		!strings.HasSuffix(request.ArtifactRef, "@"+request.Digest) || len(request.TargetCells) == 0 || len(request.TargetCells) > 32 ||
		request.Status != ReplicationStatusRequested || timeErr != nil || requestedAt.UTC().Format(time.RFC3339Nano) != request.RequestedAt {
		return errors.New("regional replication request is invalid")
	}
	previous := ""
	for _, cellID := range request.TargetCells {
		cell, err := platformid.Parse(cellID)
		if err != nil || cell.Prefix() != "cell" || cellID <= previous {
			return errors.New("regional replication target set is invalid")
		}
		previous = cellID
	}
	return nil
}

type MemoryReplicationStore struct {
	mu       sync.Mutex
	requests map[string]ReplicationRequest
	business map[string]string
}

func NewMemoryReplicationStore() *MemoryReplicationStore {
	return &MemoryReplicationStore{requests: map[string]ReplicationRequest{}, business: map[string]string{}}
}

func (store *MemoryReplicationStore) Reserve(ctx context.Context, key string, request ReplicationRequest) (ReplicationRequest, bool, error) {
	if err := ctx.Err(); err != nil {
		return ReplicationRequest{}, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existingID, found := store.business[key]; found {
		return store.requests[existingID], true, nil
	}
	store.requests[request.OperationID] = request
	store.business[key] = request.OperationID
	return request, false, nil
}

func (store *MemoryReplicationStore) Get(ctx context.Context, operationID string) (ReplicationRequest, bool, error) {
	if err := ctx.Err(); err != nil {
		return ReplicationRequest{}, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	request, found := store.requests[operationID]
	return request, found, nil
}

type BoltReplicationStore struct {
	db         *bolt.DB
	maxEntries int
}

func NewBoltReplicationStore(path string, maxEntries int) (*BoltReplicationStore, error) {
	if maxEntries < 1 || maxEntries > 10_000_000 {
		return nil, errors.New("Bolt replication store capacity is invalid")
	}
	absolute, err := secureLeaseDatabasePath(path)
	if err != nil {
		return nil, err
	}
	database, err := bolt.Open(absolute, 0o600, &bolt.Options{Timeout: 5 * time.Second, NoGrowSync: false, FreelistType: bolt.FreelistMapType})
	if err != nil {
		return nil, fmt.Errorf("%w: open Bolt replication database", ErrRegistry)
	}
	store := &BoltReplicationStore{db: database, maxEntries: maxEntries}
	if err := database.Update(func(transaction *bolt.Tx) error {
		if _, err := transaction.CreateBucketIfNotExists(replicationRequestsBucket); err != nil {
			return err
		}
		_, err := transaction.CreateBucketIfNotExists(replicationBusinessBucket)
		return err
	}); err != nil {
		_ = database.Close()
		return nil, errors.New("initialize Bolt replication database")
	}
	return store, nil
}

func (store *BoltReplicationStore) Close() error { return store.db.Close() }

func (store *BoltReplicationStore) Reserve(ctx context.Context, key string, request ReplicationRequest) (ReplicationRequest, bool, error) {
	if err := ctx.Err(); err != nil {
		return ReplicationRequest{}, false, err
	}
	if key == "" || validateReplicationRequest(request) != nil {
		return ReplicationRequest{}, false, errors.New("replication reservation is invalid")
	}
	contents, err := canonicaljson.Marshal(request)
	if err != nil {
		return ReplicationRequest{}, false, err
	}
	result := request
	replay := false
	err = store.db.Update(func(transaction *bolt.Tx) error {
		requests := transaction.Bucket(replicationRequestsBucket)
		business := transaction.Bucket(replicationBusinessBucket)
		if existingID := business.Get([]byte(key)); existingID != nil {
			existing := requests.Get(existingID)
			if existing == nil {
				return errors.New("replication business index is inconsistent")
			}
			var err error
			result, err = decodeReplicationRequest(existing)
			replay = err == nil
			return err
		}
		if requests.Stats().KeyN >= store.maxEntries {
			return errors.New("replication request capacity exhausted")
		}
		if err := requests.Put([]byte(request.OperationID), contents); err != nil {
			return err
		}
		return business.Put([]byte(key), []byte(request.OperationID))
	})
	return result, replay, err
}

func (store *BoltReplicationStore) Get(ctx context.Context, operationID string) (ReplicationRequest, bool, error) {
	if err := ctx.Err(); err != nil {
		return ReplicationRequest{}, false, err
	}
	var request ReplicationRequest
	found := false
	err := store.db.View(func(transaction *bolt.Tx) error {
		contents := transaction.Bucket(replicationRequestsBucket).Get([]byte(operationID))
		if contents == nil {
			return nil
		}
		var err error
		request, err = decodeReplicationRequest(contents)
		found = err == nil
		return err
	})
	return request, found, err
}

func decodeReplicationRequest(contents []byte) (ReplicationRequest, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var request ReplicationRequest
	if err := decoder.Decode(&request); err != nil {
		return ReplicationRequest{}, errors.New("replication request record is malformed")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) || validateReplicationRequest(request) != nil {
		return ReplicationRequest{}, errors.New("replication request record is invalid")
	}
	return request, nil
}
