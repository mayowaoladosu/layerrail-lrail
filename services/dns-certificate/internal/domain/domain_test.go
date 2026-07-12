package domain

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
)

func TestCanonicalizeIDNAAndWildcard(t *testing.T) {
	t.Parallel()
	got, err := Canonicalize("BÜCHER.example.", false)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if got.ASCII != "xn--bcher-kva.example" || got.Base != "xn--bcher-kva.example" || got.Wildcard {
		t.Fatalf("Canonicalize = %+v", got)
	}
	wildcard, err := Canonicalize("*.api.example.com", true)
	if err != nil {
		t.Fatalf("Canonicalize wildcard: %v", err)
	}
	if wildcard.ASCII != "*.api.example.com" || wildcard.Base != "example.com" || !wildcard.Wildcard {
		t.Fatalf("wildcard = %+v", wildcard)
	}
}

func TestCanonicalizeRejectsUnsafeClaims(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		" com ", "com", "localhost", "127.0.0.1", "*.example.com", "foo.*.example.com", "-bad.example", "bad..example.com",
	} {
		value := value
		t.Run(strings.ReplaceAll(value, "/", "_"), func(t *testing.T) {
			t.Parallel()
			if _, err := Canonicalize(value, false); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Canonicalize(%q) error = %v", value, err)
			}
		})
	}
}

func TestOwnershipChallengeIsSingleUseAndStoresNoToken(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 12, 20, 0, 0, 0, time.UTC)
	organizationID, err := platformid.NewAt("org", now, bytes.NewReader(bytes.Repeat([]byte{0x10}, 16)))
	if err != nil {
		t.Fatalf("organization ID: %v", err)
	}
	name, err := Canonicalize("app.example.com", false)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	key := bytes.Repeat([]byte{0x44}, 32)
	challenge, token, err := NewChallenge(
		organizationID,
		name,
		now,
		15*time.Minute,
		bytes.NewReader(bytes.Repeat([]byte{0x22}, challengeBytes)),
		key,
	)
	if err != nil {
		t.Fatalf("NewChallenge: %v", err)
	}
	if token == "" || challenge.RecordName != "_lrail-challenge.app.example.com" {
		t.Fatalf("challenge = %+v, token empty=%t", challenge, token == "")
	}
	if strings.Contains(string(challenge.Verifier[:]), token) {
		t.Fatal("challenge token appears in persisted verifier")
	}
	if err := challenge.Verify("wrong", now.Add(time.Minute), key); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong proof error = %v", err)
	}
	if err := challenge.Verify(token, now.Add(time.Minute), key); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := challenge.Verify(token, now.Add(2*time.Minute), key); !errors.Is(err, ErrInvalid) {
		t.Fatalf("replay error = %v", err)
	}
}

func TestOwnershipChallengeRejectsInvalidPolicy(t *testing.T) {
	t.Parallel()
	name, err := Canonicalize("app.example.com", false)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	now := time.Now().UTC()
	if _, _, err := NewChallenge("prj_019b01da-7e31-7000-8000-000000000001", name, now, time.Minute, bytes.NewReader(make([]byte, 32)), make([]byte, 32)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong resource prefix error = %v", err)
	}
	organizationID := platformid.ID("org_019b01da-7e31-7000-8000-000000000001")
	if _, _, err := NewChallenge(organizationID, name, now, 0, bytes.NewReader(make([]byte, 32)), make([]byte, 32)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("TTL error = %v", err)
	}
	challenge, token, err := NewChallenge(organizationID, name, now, time.Minute, bytes.NewReader(make([]byte, 32)), bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatalf("NewChallenge: %v", err)
	}
	if err := challenge.Verify(token, now.Add(2*time.Minute), bytes.Repeat([]byte{1}, 32)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expiry error = %v", err)
	}
	if err := challenge.Verify(token, now, []byte("short")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short HMAC key error = %v", err)
	}
}
