package buildregistry

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
)

func validRegistryScope() PublicationScope {
	return PublicationScope{
		OrganizationID: registryOrgID, ProjectID: registryProjectID, BuildID: registryBuildID,
		Attempt: 1, OutputName: "api", ExpiresAt: registryNow.Add(10 * time.Minute),
	}
}

func fixedTokenID(last string) func() (platformid.ID, error) {
	return func() (platformid.ID, error) {
		return platformid.Parse("tok_019b01da-7e31-7000-8000-0000000000" + last)
	}
}

func TestBrokerIssuesRepositoryCapabilityAndRevokesRobot(t *testing.T) {
	t.Parallel()
	fake := newFakeHarbor(t)
	harbor := fake.client(t)
	leases := NewMemoryLeaseStore()
	broker, err := NewBroker(BrokerConfig{
		Harbor: harbor, Leases: leases, Clock: func() time.Time { return registryNow }, NewID: fixedTokenID("05"), MaxConcurrentIssues: 2,
	})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	capability, err := broker.Issue(t.Context(), validRegistryScope())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	expectedRepository, _ := RepositoryName(registryProjectID, "api")
	if capability.LeaseID != "tok_019b01da-7e31-7000-8000-000000000005" || capability.Repository != expectedRepository || capability.Token == "" || capability.Registry != fake.server.URL {
		t.Fatalf("capability=%#v", capability)
	}
	if _, found, err := leases.Get(t.Context(), capability.LeaseID); err != nil || !found || len(fake.robots) != 1 {
		t.Fatalf("lease found=%v error=%v robots=%#v", found, err, fake.robots)
	}
	if err := broker.Revoke(t.Context(), capability.LeaseID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, found, _ := leases.Get(t.Context(), capability.LeaseID); found || len(fake.robots) != 0 {
		t.Fatalf("revoked lease remains: found=%v robots=%#v", found, fake.robots)
	}
	if err := broker.Revoke(t.Context(), capability.LeaseID); err != nil {
		t.Fatalf("idempotent Revoke: %v", err)
	}
}

func TestBrokerCleansRobotWhenTokenScopeIsBroader(t *testing.T) {
	t.Parallel()
	fake := newFakeHarbor(t)
	fake.wrongTokenScope = true
	broker, err := NewBroker(BrokerConfig{
		Harbor: fake.client(t), Leases: NewMemoryLeaseStore(), Clock: func() time.Time { return registryNow },
		NewID: fixedTokenID("06"), MaxConcurrentIssues: 1,
	})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	if _, err := broker.Issue(t.Context(), validRegistryScope()); err == nil {
		t.Fatal("expected broader token rejection")
	}
	if len(fake.robots) != 0 || fake.robotDeletes != 1 {
		t.Fatalf("failed issuance leaked robot: %#v", fake)
	}
}

func TestBrokerReissueRevokesPriorBusinessLease(t *testing.T) {
	t.Parallel()
	fake := newFakeHarbor(t)
	ids := []string{"07", "08"}
	broker, err := NewBroker(BrokerConfig{
		Harbor: fake.client(t), Leases: NewMemoryLeaseStore(), Clock: func() time.Time { return registryNow }, MaxConcurrentIssues: 1,
		NewID: func() (platformid.ID, error) {
			id := ids[0]
			ids = ids[1:]
			return fixedTokenID(id)()
		},
	})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	first, err := broker.Issue(t.Context(), validRegistryScope())
	if err != nil {
		t.Fatalf("Issue first: %v", err)
	}
	second, err := broker.Issue(t.Context(), validRegistryScope())
	if err != nil {
		t.Fatalf("Issue second: %v", err)
	}
	if first.LeaseID == second.LeaseID || fake.robotCreates != 2 || fake.robotDeletes != 1 || len(fake.robots) != 1 {
		t.Fatalf("first=%#v second=%#v fake=%#v", first, second, fake)
	}
}

func TestBrokerSweepExpiredRevokesDurableRobot(t *testing.T) {
	t.Parallel()
	fake := newFakeHarbor(t)
	clock := registryNow
	broker, err := NewBroker(BrokerConfig{
		Harbor: fake.client(t), Leases: NewMemoryLeaseStore(), Clock: func() time.Time { return clock }, NewID: fixedTokenID("09"), MaxConcurrentIssues: 1,
	})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	capability, err := broker.Issue(t.Context(), validRegistryScope())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	clock = capability.ExpiresAt.Add(time.Second)
	cleaned, err := broker.SweepExpired(t.Context(), 100)
	if err != nil || cleaned != 1 || len(fake.robots) != 0 {
		t.Fatalf("cleaned=%d error=%v robots=%#v", cleaned, err, fake.robots)
	}
}

func TestBoltLeaseStorePersistsIndexesAcrossRestart(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "registry-leases.db")
	store, err := NewBoltLeaseStore(path, 100)
	if err != nil {
		t.Fatalf("NewBoltLeaseStore: %v", err)
	}
	projectName, _ := ProjectName(registryOrgID)
	repository, _ := RepositoryName(registryProjectID, "api")
	lease := RobotLease{
		Version: CurrentLeaseVersion, LeaseID: "tok_019b01da-7e31-7000-8000-000000000010", BusinessKey: "fixture-key",
		OrganizationID: registryOrgID, BuildID: registryBuildID, ProjectName: projectName, Repository: repository,
		RobotID: 42, ExpiresAt: registryNow.Add(time.Minute).Format(time.RFC3339),
	}
	if err := store.Put(t.Context(), lease); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	store, err = NewBoltLeaseStore(path, 100)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer store.Close()
	loaded, found, err := store.GetByBusinessKey(t.Context(), lease.BusinessKey)
	if err != nil || !found || loaded.LeaseID != lease.LeaseID {
		t.Fatalf("loaded=%#v found=%v error=%v", loaded, found, err)
	}
	expired, err := store.Expired(context.Background(), registryNow.Add(2*time.Minute), 10)
	if err != nil || len(expired) != 1 || expired[0].RobotID != lease.RobotID {
		t.Fatalf("expired=%#v error=%v", expired, err)
	}
	if err := store.Remove(t.Context(), lease.LeaseID); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, found, err := store.GetByBusinessKey(t.Context(), lease.BusinessKey); err != nil || found {
		t.Fatalf("removed business index found=%v error=%v", found, err)
	}
}

func TestValidatePublicationScopeRejectsForeignShapesAndTTL(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*PublicationScope){
		"organization": func(scope *PublicationScope) { scope.OrganizationID = registryProjectID },
		"project":      func(scope *PublicationScope) { scope.ProjectID = registryOrgID },
		"build":        func(scope *PublicationScope) { scope.BuildID = registryProjectID },
		"attempt":      func(scope *PublicationScope) { scope.Attempt = 0 },
		"output":       func(scope *PublicationScope) { scope.OutputName = "../escape" },
		"expiry":       func(scope *PublicationScope) { scope.ExpiresAt = registryNow.Add(MaxCapabilityTTL + time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			scope := validRegistryScope()
			mutate(&scope)
			if err := ValidatePublicationScope(scope, registryNow); err == nil {
				t.Fatal("expected invalid scope rejection")
			}
		})
	}
}
