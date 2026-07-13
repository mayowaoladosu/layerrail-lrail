package buildregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
	bolt "go.etcd.io/bbolt"
)

var robotLeasesBucket = []byte("registry-robot-leases-v1")
var robotBusinessBucket = []byte("registry-robot-business-v1")

type MemoryLeaseStore struct {
	mu       sync.Mutex
	leases   map[string]RobotLease
	business map[string]string
}

func NewMemoryLeaseStore() *MemoryLeaseStore {
	return &MemoryLeaseStore{leases: make(map[string]RobotLease), business: make(map[string]string)}
}

func (store *MemoryLeaseStore) Put(ctx context.Context, lease RobotLease) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateRobotLease(lease); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, found := store.business[lease.BusinessKey]; found && existing != lease.LeaseID {
		return errors.New("registry lease business key already exists")
	}
	if existing, found := store.leases[lease.LeaseID]; found && existing.BusinessKey != lease.BusinessKey {
		return errors.New("registry lease identity conflicts")
	}
	store.leases[lease.LeaseID] = lease
	store.business[lease.BusinessKey] = lease.LeaseID
	return nil
}

func (store *MemoryLeaseStore) Get(ctx context.Context, leaseID string) (RobotLease, bool, error) {
	if err := ctx.Err(); err != nil {
		return RobotLease{}, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lease, found := store.leases[leaseID]
	return lease, found, nil
}

func (store *MemoryLeaseStore) GetByBusinessKey(ctx context.Context, key string) (RobotLease, bool, error) {
	if err := ctx.Err(); err != nil {
		return RobotLease{}, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	leaseID, found := store.business[key]
	if !found {
		return RobotLease{}, false, nil
	}
	lease, found := store.leases[leaseID]
	return lease, found, nil
}

func (store *MemoryLeaseStore) Remove(ctx context.Context, leaseID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lease, found := store.leases[leaseID]
	if !found {
		return nil
	}
	delete(store.leases, leaseID)
	delete(store.business, lease.BusinessKey)
	return nil
}

func (store *MemoryLeaseStore) Expired(ctx context.Context, now time.Time, limit int) ([]RobotLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 10_000 {
		return nil, errors.New("registry lease scan limit is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	result := make([]RobotLease, 0)
	for _, lease := range store.leases {
		expiresAt, _ := time.Parse(time.RFC3339, lease.ExpiresAt)
		if !expiresAt.After(now.UTC()) {
			result = append(result, lease)
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].LeaseID < result[right].LeaseID })
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

type BoltLeaseStore struct {
	db         *bolt.DB
	maxEntries int
}

func NewBoltLeaseStore(path string, maxEntries int) (*BoltLeaseStore, error) {
	if path == "" || maxEntries < 1 || maxEntries > 10_000_000 {
		return nil, errors.New("Bolt registry lease configuration is invalid")
	}
	absolute, err := secureLeaseDatabasePath(path)
	if err != nil {
		return nil, err
	}
	database, err := bolt.Open(absolute, 0o600, &bolt.Options{Timeout: 5 * time.Second, NoGrowSync: false, FreelistType: bolt.FreelistMapType})
	if err != nil {
		return nil, fmt.Errorf("%w: open Bolt registry lease database", ErrRegistry)
	}
	store := &BoltLeaseStore{db: database, maxEntries: maxEntries}
	if err := database.Update(func(transaction *bolt.Tx) error {
		if _, err := transaction.CreateBucketIfNotExists(robotLeasesBucket); err != nil {
			return err
		}
		_, err := transaction.CreateBucketIfNotExists(robotBusinessBucket)
		return err
	}); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("%w: initialize Bolt registry lease database", ErrRegistry)
	}
	return store, nil
}

func (store *BoltLeaseStore) Close() error { return store.db.Close() }

func (store *BoltLeaseStore) Put(ctx context.Context, lease RobotLease) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateRobotLease(lease); err != nil {
		return err
	}
	contents, err := canonicaljson.Marshal(lease)
	if err != nil {
		return errors.New("canonicalize registry lease")
	}
	return store.db.Update(func(transaction *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		leases := transaction.Bucket(robotLeasesBucket)
		business := transaction.Bucket(robotBusinessBucket)
		if existing := business.Get([]byte(lease.BusinessKey)); existing != nil && string(existing) != lease.LeaseID {
			return errors.New("registry lease business key already exists")
		}
		if existing := leases.Get([]byte(lease.LeaseID)); existing != nil {
			decoded, err := decodeRobotLease(existing)
			if err != nil || decoded.BusinessKey != lease.BusinessKey {
				return errors.New("registry lease identity conflicts")
			}
		}
		if leases.Stats().KeyN >= store.maxEntries && leases.Get([]byte(lease.LeaseID)) == nil {
			return errors.New("registry lease capacity exhausted")
		}
		if err := leases.Put([]byte(lease.LeaseID), contents); err != nil {
			return err
		}
		return business.Put([]byte(lease.BusinessKey), []byte(lease.LeaseID))
	})
}

func (store *BoltLeaseStore) Get(ctx context.Context, leaseID string) (RobotLease, bool, error) {
	if err := ctx.Err(); err != nil {
		return RobotLease{}, false, err
	}
	var lease RobotLease
	found := false
	err := store.db.View(func(transaction *bolt.Tx) error {
		contents := transaction.Bucket(robotLeasesBucket).Get([]byte(leaseID))
		if contents == nil {
			return nil
		}
		var err error
		lease, err = decodeRobotLease(contents)
		found = err == nil
		return err
	})
	return lease, found, err
}

func (store *BoltLeaseStore) GetByBusinessKey(ctx context.Context, key string) (RobotLease, bool, error) {
	if err := ctx.Err(); err != nil {
		return RobotLease{}, false, err
	}
	var lease RobotLease
	found := false
	err := store.db.View(func(transaction *bolt.Tx) error {
		leaseID := transaction.Bucket(robotBusinessBucket).Get([]byte(key))
		if leaseID == nil {
			return nil
		}
		contents := transaction.Bucket(robotLeasesBucket).Get(leaseID)
		if contents == nil {
			return errors.New("registry lease index is inconsistent")
		}
		var err error
		lease, err = decodeRobotLease(contents)
		found = err == nil
		return err
	})
	return lease, found, err
}

func (store *BoltLeaseStore) Remove(ctx context.Context, leaseID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.db.Update(func(transaction *bolt.Tx) error {
		leases := transaction.Bucket(robotLeasesBucket)
		contents := leases.Get([]byte(leaseID))
		if contents == nil {
			return nil
		}
		lease, err := decodeRobotLease(contents)
		if err != nil {
			return err
		}
		if err := transaction.Bucket(robotBusinessBucket).Delete([]byte(lease.BusinessKey)); err != nil {
			return err
		}
		return leases.Delete([]byte(leaseID))
	})
}

func (store *BoltLeaseStore) Expired(ctx context.Context, now time.Time, limit int) ([]RobotLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 10_000 {
		return nil, errors.New("registry lease scan limit is invalid")
	}
	result := make([]RobotLease, 0)
	err := store.db.View(func(transaction *bolt.Tx) error {
		return transaction.Bucket(robotLeasesBucket).ForEach(func(_, contents []byte) error {
			if len(result) >= limit {
				return nil
			}
			lease, err := decodeRobotLease(contents)
			if err != nil {
				return err
			}
			expiresAt, _ := time.Parse(time.RFC3339, lease.ExpiresAt)
			if !expiresAt.After(now.UTC()) {
				result = append(result, lease)
			}
			return nil
		})
	})
	return result, err
}

func validateRobotLease(lease RobotLease) error {
	leaseID, leaseErr := platformid.Parse(lease.LeaseID)
	organization, organizationErr := platformid.Parse(lease.OrganizationID)
	build, buildErr := platformid.Parse(lease.BuildID)
	expiresAt, expiresErr := time.Parse(time.RFC3339, lease.ExpiresAt)
	if lease.Version != CurrentLeaseVersion || leaseErr != nil || leaseID.Prefix() != "tok" || lease.BusinessKey == "" || len(lease.BusinessKey) > 255 ||
		organizationErr != nil || organization.Prefix() != "org" || buildErr != nil || build.Prefix() != "bld" || !harborNamePattern.MatchString(lease.ProjectName) ||
		!repositoryPattern.MatchString(lease.Repository) || lease.RobotID <= 0 || expiresErr != nil || expiresAt.Format(time.RFC3339) != lease.ExpiresAt {
		return errors.New("registry robot lease is invalid")
	}
	return nil
}

func decodeRobotLease(contents []byte) (RobotLease, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var lease RobotLease
	if err := decoder.Decode(&lease); err != nil {
		return RobotLease{}, errors.New("registry lease record is malformed")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return RobotLease{}, errors.New("registry lease record has trailing data")
	}
	if err := validateRobotLease(lease); err != nil {
		return RobotLease{}, err
	}
	return lease, nil
}

func secureLeaseDatabasePath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", errors.New("registry lease database path is invalid")
	}
	parent := filepath.Dir(absolute)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", errors.New("create registry lease database directory")
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(parent) {
		return "", errors.New("registry lease database directory traverses a symlink")
	}
	if info, statErr := os.Lstat(absolute); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("registry lease database is a symlink")
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return "", errors.New("inspect registry lease database")
	}
	return absolute, nil
}
