package sourceauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSignedResultRoundTripAndTamperRejection(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	result := validResult()
	signed, err := SignResult(privateKey, "source-finalizer-2026-01", result)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyResult(publicKey, signed); err != nil {
		t.Fatal(err)
	}
	signed.Result.SizeBytes++
	if err := VerifyResult(publicKey, signed); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("tampered result error = %v", err)
	}
}

func TestSignedResultRejectsWrongKeyAndInvalidIdentity(t *testing.T) {
	t.Parallel()
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	otherPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	result := validResult()
	signed, err := SignResult(privateKey, "source-finalizer-2026-01", result)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyResult(otherPublic, signed); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("wrong-key error = %v", err)
	}
	result.ProjectID = result.OrganizationID
	if _, err := SignResult(privateKey, "source-finalizer-2026-01", result); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("wrong resource type error = %v", err)
	}
}

func validResult() FinalizationResult {
	return FinalizationResult{
		Version:        1,
		SessionID:      "upl_019b01da-7e31-7000-8000-000000000001",
		OrganizationID: "org_019b01da-7e31-7000-8000-000000000002",
		ProjectID:      "prj_019b01da-7e31-7000-8000-000000000003",
		SnapshotSHA256: "sha256:" + strings.Repeat("a", 64),
		ManifestSHA256: "sha256:" + strings.Repeat("b", 64),
		ArchiveSHA256:  "sha256:" + strings.Repeat("c", 64),
		ManifestRef:    "s3://source/snapshots/sha256-a/manifest.json",
		ArchiveRef:     "s3://source/snapshots/sha256-a/source.tar.gz",
		SizeBytes:      1_024,
		PolicyVersion:  "source-v1",
		FinalizedAt:    time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC),
	}
}
