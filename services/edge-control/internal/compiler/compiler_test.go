package compiler

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	orgID     = "org_019b01da-7e31-7000-8000-000000000001"
	policySHA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func route(id, host, path string, kind MatchKind) RouteIntent {
	return RouteIntent{
		ID: id, OrganizationID: orgID, Hostname: host, Match: kind, Path: path,
		Targets: []Target{{
			ReleaseID: "rel_019b01da-7e31-7000-8000-000000000010",
			ClusterID: "cluster-central-us",
			Weight:    100,
		}},
	}
}

func intent(routes ...RouteIntent) Intent {
	return Intent{
		GenerationID:    "edg_019b01da-7e31-7000-8000-000000000020",
		CompilerVersion: "0.1.0", SchemaVersion: "edge.lrail.dev/v1", PolicyDigest: policySHA,
		CreatedAt: time.Date(2026, 7, 12, 20, 0, 0, 0, time.UTC), Routes: routes,
	}
}

func TestCompileCanonicalizesAndOrdersRoutes(t *testing.T) {
	t.Parallel()
	exact := route("rte_019b01da-7e31-7000-8000-000000000001", "API.Example.com.", "/v1/users", MatchExact)
	prefixShort := route("rte_019b01da-7e31-7000-8000-000000000002", "api.example.com", "/v1", MatchPrefix)
	prefixLong := route("rte_019b01da-7e31-7000-8000-000000000003", "api.example.com", "/v1/admin", MatchPrefix)
	wildcard := route("rte_019b01da-7e31-7000-8000-000000000004", "*.example.com", "/", MatchPrefix)
	compiled, err := Compile(intent(wildcard, prefixShort, prefixLong, exact))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	got := make([]string, 0, len(compiled.Routes))
	for _, item := range compiled.Routes {
		got = append(got, item.ID)
	}
	want := []string{exact.ID, prefixLong.ID, prefixShort.ID, wildcard.ID}
	if !slices.Equal(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
	if !strings.HasPrefix(compiled.CanonicalDigest, "sha256:") || compiled.Routes[0].Hostname != "api.example.com" {
		t.Fatalf("compiled = %+v", compiled)
	}

	reversed, err := Compile(intent(exact, prefixLong, prefixShort, wildcard))
	if err != nil {
		t.Fatalf("Compile reversed: %v", err)
	}
	if reversed.CanonicalDigest != compiled.CanonicalDigest {
		t.Fatalf("canonical digest changed: %s != %s", reversed.CanonicalDigest, compiled.CanonicalDigest)
	}
}

func TestCompileRejectsAmbiguityOwnershipAndUnsafeInput(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*Intent){
		"bad generation": func(value *Intent) { value.GenerationID = "edge-latest" },
		"bad policy":     func(value *Intent) { value.PolicyDigest = "latest" },
		"duplicate": func(value *Intent) {
			copy := value.Routes[0]
			copy.ID = "rte_019b01da-7e31-7000-8000-000000000002"
			value.Routes = append(value.Routes, copy)
		},
		"cross tenant": func(value *Intent) {
			copy := value.Routes[0]
			copy.ID = "rte_019b01da-7e31-7000-8000-000000000002"
			copy.OrganizationID = "org_019b01da-7e31-7000-8000-000000000099"
			copy.Path = "/other"
			value.Routes = append(value.Routes, copy)
		},
		"unsafe path": func(value *Intent) { value.Routes[0].Path = "/a/%2f/b" },
		"bad host":    func(value *Intent) { value.Routes[0].Hostname = "127.0.0.1" },
		"bad weights": func(value *Intent) { value.Routes[0].Targets[0].Weight = 99 },
		"duplicate release": func(value *Intent) {
			value.Routes[0].Targets = append(value.Routes[0].Targets, value.Routes[0].Targets[0])
		},
		"regex no priority": func(value *Intent) { value.Routes[0].Match = MatchRegex },
	}
	for name, mutate := range tests {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			value := intent(route(
				"rte_019b01da-7e31-7000-8000-000000000001",
				"api.example.com",
				"/",
				MatchPrefix,
			))
			mutate(&value)
			if _, err := Compile(value); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Compile error = %v", err)
			}
		})
	}
}

func TestCompileAcceptsWeightedTargetsAndExplicitRegex(t *testing.T) {
	t.Parallel()
	value := route("rte_019b01da-7e31-7000-8000-000000000001", "api.example.com", "^/users/[0-9]+$", MatchRegex)
	value.Priority = 10
	value.Targets = []Target{
		{ReleaseID: "rel_019b01da-7e31-7000-8000-000000000011", ClusterID: "canary", Weight: 5},
		{ReleaseID: "rel_019b01da-7e31-7000-8000-000000000010", ClusterID: "stable", Weight: 95},
	}
	compiled, err := Compile(intent(value))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if compiled.Routes[0].Targets[0].Weight != 95 {
		t.Fatalf("targets were not canonicalized: %+v", compiled.Routes[0].Targets)
	}
}

func TestCompileRejectsCrossTenantWildcardOverlapInEitherOrder(t *testing.T) {
	t.Parallel()
	wildcard := route("rte_019b01da-7e31-7000-8000-000000000001", "*.example.com", "/", MatchPrefix)
	exact := route("rte_019b01da-7e31-7000-8000-000000000002", "api.example.com", "/", MatchPrefix)
	exact.OrganizationID = "org_019b01da-7e31-7000-8000-000000000099"
	for name, routes := range map[string][]RouteIntent{
		"wildcard first": {wildcard, exact},
		"exact first":    {exact, wildcard},
	} {
		routes := routes
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Compile(intent(routes...)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Compile error = %v", err)
			}
		})
	}
}
