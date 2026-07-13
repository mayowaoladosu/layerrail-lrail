package sourceauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

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
