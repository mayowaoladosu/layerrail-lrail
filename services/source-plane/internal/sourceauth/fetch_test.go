package sourceauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRubyGoFetchGrantFixture(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "contracts", "fixtures", "source-fetch-grant.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		KeyBase64URL string     `json:"key_base64url"`
		Grant        FetchGrant `json:"grant"`
		TokenChunks  []string   `json:"token_chunks"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	key, err := base64.RawURLEncoding.DecodeString(fixture.KeyBase64URL)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Join(fixture.TokenChunks, "")
	verified, err := VerifyFetchGrant(key, token, fixture.Grant.ExpiresAt.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(verified, fixture.Grant) {
		t.Fatalf("verified grant changed: %#v", verified)
	}
	signed, err := SignFetchGrantAt(key, fixture.Grant, fixture.Grant.ExpiresAt.Add(-15*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if signed != token {
		t.Fatalf("Go grant differs from Rails fixture\nwant %s\n got %s", token, signed)
	}
}

func TestGoFetchResultFixture(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "contracts", "fixtures", "source-fetch-result.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		PublicKeyBase64URL string      `json:"public_key_base64url"`
		KeyID              string      `json:"key_id"`
		Result             FetchResult `json:"result"`
		Signature          string      `json:"signature"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(fixture.PublicKeyBase64URL)
	if err != nil {
		t.Fatal(err)
	}
	signed := SignedFetchResult{KeyID: fixture.KeyID, Result: fixture.Result, Signature: fixture.Signature}
	if err := VerifyFetchResult(ed25519.PublicKey(publicKey), signed); err != nil {
		t.Fatal(err)
	}
}

func TestFetchGrantRoundTripTamperExpiryAndScope(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 13, 1, 0, 0, 0, time.UTC)
	secret := []byte(strings.Repeat("f", 32))
	grant := validFetchGrant(now)
	token, err := SignFetchGrantAt(secret, grant, now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyFetchGrant(secret, token, now)
	if err != nil {
		t.Fatal(err)
	}
	if verified.FetchID != grant.FetchID || verified.Repository != grant.Repository || verified.CommitSHA != grant.CommitSHA {
		t.Fatalf("verified fetch grant changed: %#v", verified)
	}

	parts := strings.Split(token, ".")
	replacement := "A"
	if strings.HasPrefix(parts[2], replacement) {
		replacement = "B"
	}
	parts[2] = replacement + parts[2][1:]
	if _, err := VerifyFetchGrant(secret, strings.Join(parts, "."), now); !errors.Is(err, ErrInvalidFetchGrant) {
		t.Fatalf("tampered fetch grant error = %v", err)
	}
	if _, err := VerifyFetchGrant(secret, token, grant.ExpiresAt); !errors.Is(err, ErrExpiredFetchGrant) {
		t.Fatalf("expired fetch grant error = %v", err)
	}
	grant.Repository = "https://github.com/example/repository"
	if _, err := SignFetchGrantAt(secret, grant, now); !errors.Is(err, ErrInvalidFetchGrant) {
		t.Fatalf("unsafe repository error = %v", err)
	}
}

func TestSignedFetchResultRoundTripAndTamperRejection(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	result := validFetchResult()
	signed, err := SignFetchResult(privateKey, "source-finalizer-2026-01", result)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyFetchResult(publicKey, signed); err != nil {
		t.Fatal(err)
	}
	signed.Result.ResolvedCommitSHA = strings.Repeat("b", 40)
	if err := VerifyFetchResult(publicKey, signed); !errors.Is(err, ErrInvalidFetchResult) {
		t.Fatalf("tampered fetch result error = %v", err)
	}
}

func validFetchGrant(now time.Time) FetchGrant {
	return FetchGrant{
		Version:            1,
		Audience:           Audience,
		FetchID:            "fet_019b01da-7e31-7000-8000-000000000001",
		OrganizationID:     "org_019b01da-7e31-7000-8000-000000000002",
		ProjectID:          "prj_019b01da-7e31-7000-8000-000000000003",
		CreatorID:          "acct_019b01da-7e31-7000-8000-000000000004",
		SourceConnectionID: "src_019b01da-7e31-7000-8000-000000000005",
		Provider:           "github",
		InstallationID:     "123456",
		Repository:         "example/repository",
		CommitSHA:          strings.Repeat("a", 40),
		RootDirectory:      "",
		ExpiresAt:          now.Add(15 * time.Minute),
	}
}

func validFetchResult() FetchResult {
	at := time.Date(2026, 7, 13, 1, 0, 0, 0, time.UTC)
	return FetchResult{
		Version:            1,
		FetchID:            "fet_019b01da-7e31-7000-8000-000000000001",
		OrganizationID:     "org_019b01da-7e31-7000-8000-000000000002",
		ProjectID:          "prj_019b01da-7e31-7000-8000-000000000003",
		SourceConnectionID: "src_019b01da-7e31-7000-8000-000000000005",
		Provider:           "github",
		Repository:         "example/repository",
		RequestedCommitSHA: strings.Repeat("a", 40),
		ResolvedCommitSHA:  strings.Repeat("a", 40),
		TreeSHA:            strings.Repeat("b", 40),
		Author:             "Example Author",
		AuthoredAt:         at,
		SnapshotSHA256:     "sha256:" + strings.Repeat("c", 64),
		ManifestSHA256:     "sha256:" + strings.Repeat("d", 64),
		ArchiveSHA256:      "sha256:" + strings.Repeat("e", 64),
		ManifestRef:        "s3://source/snapshots/c/manifest.json",
		ArchiveRef:         "s3://source/snapshots/c/source.tar.gz",
		SizeBytes:          1_024,
		PolicyVersion:      "source-v1",
		Submodules:         []Submodule{},
		LFSDigests:         []string{},
		Warnings:           []string{},
		TokenExpiresAt:     at.Add(time.Hour),
		FinalizedAt:        at,
	}
}
