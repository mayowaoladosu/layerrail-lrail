package buildregistry

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
)

const replicationCellA = "cell_019b01da-7e31-7000-8000-000000000006"
const replicationCellB = "cell_019b01da-7e31-7000-8000-000000000007"
const replicationDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const replicationRef = "registry.example.invalid/lrail/builds/api@" + replicationDigest

func TestReplicationPlannerPersistsRequestedStateIdempotently(t *testing.T) {
	t.Parallel()
	ids := []string{"op_019b01da-7e31-7000-8000-000000000014", "op_019b01da-7e31-7000-8000-000000000015"}
	planner, err := NewReplicationPlanner(NewMemoryReplicationStore(), func() time.Time { return registryNow }, func() (platformid.ID, error) {
		id := ids[0]
		ids = ids[1:]
		return platformid.Parse(id)
	})
	if err != nil {
		t.Fatalf("NewReplicationPlanner: %v", err)
	}
	first, replay, err := planner.Request(t.Context(), registryOrgID, registryProjectID, replicationRef, replicationDigest, []string{replicationCellB, replicationCellA, replicationCellA})
	if err != nil || replay {
		t.Fatalf("first=%#v replay=%v error=%v", first, replay, err)
	}
	second, replay, err := planner.Request(t.Context(), registryOrgID, registryProjectID, replicationRef, replicationDigest, []string{replicationCellA, replicationCellB})
	if err != nil || !replay || second.OperationID != first.OperationID || second.Status != ReplicationStatusRequested || len(second.TargetCells) != 2 || second.TargetCells[0] != replicationCellA {
		t.Fatalf("second=%#v replay=%v error=%v", second, replay, err)
	}
	loaded, found, err := planner.Get(t.Context(), first.OperationID)
	if err != nil || !found || loaded.OperationID != first.OperationID {
		t.Fatalf("loaded=%#v found=%v error=%v", loaded, found, err)
	}
}

func TestBoltReplicationStoreSurvivesRestart(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "replication.db")
	store, err := NewBoltReplicationStore(path, 100)
	if err != nil {
		t.Fatalf("NewBoltReplicationStore: %v", err)
	}
	planner, _ := NewReplicationPlanner(store, func() time.Time { return registryNow }, func() (platformid.ID, error) {
		return platformid.Parse("op_019b01da-7e31-7000-8000-000000000016")
	})
	created, replay, err := planner.Request(t.Context(), registryOrgID, registryProjectID, replicationRef, replicationDigest, []string{replicationCellA})
	if err != nil || replay {
		t.Fatalf("created=%#v replay=%v error=%v", created, replay, err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	store, err = NewBoltReplicationStore(path, 100)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer store.Close()
	planner, _ = NewReplicationPlanner(store, func() time.Time { return registryNow }, func() (platformid.ID, error) {
		return platformid.Parse("op_019b01da-7e31-7000-8000-000000000017")
	})
	replayed, replay, err := planner.Request(t.Context(), registryOrgID, registryProjectID, replicationRef, replicationDigest, []string{replicationCellA})
	if err != nil || !replay || replayed.OperationID != created.OperationID {
		t.Fatalf("replayed=%#v replay=%v error=%v", replayed, replay, err)
	}
}

func TestReplicationPlannerRejectsForeignOrMutableRequests(t *testing.T) {
	t.Parallel()
	planner, _ := NewReplicationPlanner(NewMemoryReplicationStore(), func() time.Time { return registryNow }, func() (platformid.ID, error) {
		return platformid.Parse("op_019b01da-7e31-7000-8000-000000000018")
	})
	for name, values := range map[string]struct {
		org, project, reference, digest string
		cells                           []string
	}{
		"organization": {registryProjectID, registryProjectID, replicationRef, replicationDigest, []string{replicationCellA}},
		"project":      {registryOrgID, registryOrgID, replicationRef, replicationDigest, []string{replicationCellA}},
		"tag":          {registryOrgID, registryProjectID, "registry.example.invalid/lrail/api:latest", replicationDigest, []string{replicationCellA}},
		"digest":       {registryOrgID, registryProjectID, replicationRef, "sha256:bad", []string{replicationCellA}},
		"cell":         {registryOrgID, registryProjectID, replicationRef, replicationDigest, []string{registryProjectID}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := planner.Request(t.Context(), values.org, values.project, values.reference, values.digest, values.cells); err == nil {
				t.Fatal("expected replication request rejection")
			}
		})
	}
}
