package targetbundle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

const (
	cellID = "cell_019b01da-7e31-7000-8000-000000000041"
	envID  = "env_019b01da-7e31-7000-8000-000000000003"
)

func keypair() (ed25519.PublicKey, ed25519.PrivateKey) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	return private.Public().(ed25519.PublicKey), private
}

func validBundle(now time.Time) Bundle {
	port := uint16(3000)
	return Bundle{
		APIVersion:     APIVersion,
		BundleID:       "tgt_019b01da-7e31-7000-8000-000000000040",
		CellID:         cellID,
		OrganizationID: "org_019b01da-7e31-7000-8000-000000000001",
		ProjectID:      "prj_019b01da-7e31-7000-8000-000000000002",
		EnvironmentID:  envID,
		Generation:     1,
		IssuedAt:       now.Add(-time.Minute),
		ExpiresAt:      now.Add(time.Hour),
		PolicyDigest:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Services: []Service{{
			ID:             "svc_019b01da-7e31-7000-8000-000000000004",
			RevisionDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			ConfigDigest:   "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			Processes: []Process{{
				Name: "web", Kind: "web", Command: []string{"bin/rails", "server"}, Port: &port,
				RuntimeClass: "sandbox",
				Resources:    Resources{CPUMillis: 500, MemoryBytes: 512 * 1024 * 1024, EphemeralStorageBytes: 1024 * 1024 * 1024},
				Replicas:     Replicas{Minimum: 2, Maximum: 10},
			}},
		}},
		Routes: []Route{{
			ID: "rte_019b01da-7e31-7000-8000-000000000042", ServiceID: "svc_019b01da-7e31-7000-8000-000000000004",
			Hostname: "app.example.com", PathPrefix: "/", Protocol: "https",
		}},
		SecretRefs:    []VersionedRef{},
		Volumes:       []GenerationRef{},
		AddonBindings: []GenerationRef{},
		Schedules:     []GenerationRef{},
		Artifacts: []Artifact{{
			Digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Platform: "linux/amd64",
			SignatureRef: "oci://signature", ProvenanceRef: "oci://provenance", SBOMRef: "oci://sbom", PolicyRef: "oci://policy",
		}},
	}
}

func signedJSON(t *testing.T, bundle Bundle, private ed25519.PrivateKey) []byte {
	t.Helper()
	if err := Sign(&bundle, "target-key-1", private); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return data
}

func validator(now time.Time, public ed25519.PublicKey, store Store) Validator {
	return Validator{CellID: cellID, Keys: map[string]ed25519.PublicKey{"target-key-1": public}, Store: store, Now: func() time.Time { return now }}
}

func TestAcceptVerifiesPersistsAndDeduplicates(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 12, 20, 0, 0, 0, time.UTC)
	public, private := keypair()
	store := NewMemoryStore()
	data := signedJSON(t, validBundle(now), private)
	first, err := validator(now, public, store).Accept(context.Background(), data)
	if err != nil {
		t.Fatalf("Accept first: %v", err)
	}
	if first.Replay || first.Digest == "" || first.Bundle.Generation != 1 {
		t.Fatalf("unexpected first acceptance: %+v", first)
	}
	second, err := validator(now, public, store).Accept(context.Background(), data)
	if err != nil {
		t.Fatalf("Accept replay: %v", err)
	}
	if !second.Replay || second.Digest != first.Digest {
		t.Fatalf("replay = %+v", second)
	}
}

func TestAcceptEnforcesMonotonicGeneration(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 12, 20, 0, 0, 0, time.UTC)
	public, private := keypair()
	store := NewMemoryStore()
	check := validator(now, public, store)
	if _, err := check.Accept(context.Background(), signedJSON(t, validBundle(now), private)); err != nil {
		t.Fatalf("Accept first: %v", err)
	}
	second := validBundle(now)
	second.BundleID = "tgt_019b01da-7e31-7000-8000-000000000050"
	second.Generation = 2
	previous := uint64(1)
	second.PreviousGeneration = &previous
	if _, err := check.Accept(context.Background(), signedJSON(t, second, private)); err != nil {
		t.Fatalf("Accept second: %v", err)
	}
	stale := second
	stale.BundleID = "tgt_019b01da-7e31-7000-8000-000000000051"
	stale.Generation = 3
	wrong := uint64(1)
	stale.PreviousGeneration = &wrong
	if _, err := check.Accept(context.Background(), signedJSON(t, stale, private)); !errors.Is(err, ErrRejected) {
		t.Fatalf("stale error = %v", err)
	}
}

func TestAcceptRejectsTamperingAudienceExpiryAndEvidence(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 12, 20, 0, 0, 0, time.UTC)
	public, private := keypair()
	tests := map[string]func(*Bundle){
		"wrong cell":       func(bundle *Bundle) { bundle.CellID = "cell_019b01da-7e31-7000-8000-000000000099" },
		"expired":          func(bundle *Bundle) { bundle.ExpiresAt = now.Add(-time.Second) },
		"long validity":    func(bundle *Bundle) { bundle.ExpiresAt = bundle.IssuedAt.Add(MaxValidity + time.Second) },
		"bad policy":       func(bundle *Bundle) { bundle.PolicyDigest = "latest" },
		"missing artifact": func(bundle *Bundle) { bundle.Artifacts = nil },
		"unknown service artifact": func(bundle *Bundle) {
			bundle.Services[0].RevisionDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
		},
		"bad process":           func(bundle *Bundle) { bundle.Services[0].Processes[0].Resources.MemoryBytes = 1 },
		"unknown route service": func(bundle *Bundle) { bundle.Routes[0].ServiceID = "svc_019b01da-7e31-7000-8000-000000000099" },
	}
	for name, mutate := range tests {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			bundle := validBundle(now)
			mutate(&bundle)
			data := signedJSON(t, bundle, private)
			if _, err := validator(now, public, NewMemoryStore()).Accept(context.Background(), data); !errors.Is(err, ErrRejected) {
				t.Fatalf("Accept error = %v", err)
			}
		})
	}

	t.Run("tampered after signing", func(t *testing.T) {
		t.Parallel()
		data := signedJSON(t, validBundle(now), private)
		data = bytes.Replace(data, []byte(`"generation":1`), []byte(`"generation":9`), 1)
		if _, err := validator(now, public, NewMemoryStore()).Accept(context.Background(), data); !errors.Is(err, ErrRejected) {
			t.Fatalf("tamper error = %v", err)
		}
	})
}

func TestAcceptRejectsUnknownFieldsAndIncompleteValidator(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	public, private := keypair()
	data := signedJSON(t, validBundle(now), private)
	data = bytes.Replace(data, []byte(`{"api_version"`), []byte(`{"unknown":true,"api_version"`), 1)
	if _, err := validator(now, public, NewMemoryStore()).Accept(context.Background(), data); !errors.Is(err, ErrRejected) {
		t.Fatalf("unknown field error = %v", err)
	}
	if _, err := (Validator{}).Accept(context.Background(), []byte(`{}`)); !errors.Is(err, ErrRejected) {
		t.Fatalf("incomplete validator error = %v", err)
	}
}

func TestConcurrentNextGenerationsSerializeAtomically(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 12, 20, 0, 0, 0, time.UTC)
	public, private := keypair()
	store := NewMemoryStore()
	check := validator(now, public, store)
	if _, err := check.Accept(context.Background(), signedJSON(t, validBundle(now), private)); err != nil {
		t.Fatalf("Accept first: %v", err)
	}
	previous := uint64(1)
	bundles := []Bundle{validBundle(now), validBundle(now)}
	for index := range bundles {
		bundles[index].Generation = 2
		bundles[index].PreviousGeneration = &previous
		bundles[index].BundleID = []string{
			"tgt_019b01da-7e31-7000-8000-000000000060",
			"tgt_019b01da-7e31-7000-8000-000000000061",
		}[index]
	}
	var wait sync.WaitGroup
	results := make(chan error, 2)
	payloads := make([][]byte, 0, len(bundles))
	for _, bundle := range bundles {
		payloads = append(payloads, signedJSON(t, bundle, private))
	}
	for _, payload := range payloads {
		payload := payload
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := check.Accept(context.Background(), payload)
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("accepted %d competing generations, want exactly 1", succeeded)
	}
}
