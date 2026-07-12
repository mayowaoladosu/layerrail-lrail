package sourceauth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestUploadGrantRoundTripAndTamperRejection(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	secret := []byte(strings.Repeat("s", 32))
	grant := validGrant(now)
	token, err := SignGrantAt(secret, grant, now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyGrant(secret, token, now)
	if err != nil {
		t.Fatal(err)
	}
	if verified.SessionID != grant.SessionID || verified.ExpectedArchiveSHA256 != grant.ExpectedArchiveSHA256 {
		t.Fatalf("verified grant changed: %#v", verified)
	}

	parts := strings.Split(token, ".")
	replacement := "A"
	if strings.HasPrefix(parts[2], replacement) {
		replacement = "B"
	}
	parts[2] = replacement + parts[2][1:]
	tampered := strings.Join(parts, ".")
	if _, err := VerifyGrant(secret, tampered, now); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("tampered grant error = %v", err)
	}
	if _, err := VerifyGrant(secret, token, grant.ExpiresAt); !errors.Is(err, ErrExpiredGrant) {
		t.Fatalf("expired grant error = %v", err)
	}
}

func TestUploadGrantRejectsWrongScopeAndUnboundedValues(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	secret := []byte(strings.Repeat("s", 32))
	grant := validGrant(now)
	grant.ProjectID = grant.OrganizationID
	if _, err := SignGrantAt(secret, grant, now); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("cross-type project error = %v", err)
	}
	grant = validGrant(now)
	grant.ExpiresAt = now.Add(31 * time.Minute)
	if _, err := SignGrantAt(secret, grant, now); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("long-lived grant error = %v", err)
	}
	grant = validGrant(now)
	grant.ExpectedParts = 257
	if _, err := SignGrantAt(secret, grant, now); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("part limit error = %v", err)
	}
}

func validGrant(now time.Time) UploadGrant {
	return UploadGrant{
		Version:               1,
		Audience:              Audience,
		SessionID:             "upl_019b01da-7e31-7000-8000-000000000001",
		OrganizationID:        "org_019b01da-7e31-7000-8000-000000000002",
		ProjectID:             "prj_019b01da-7e31-7000-8000-000000000003",
		CreatorID:             "acct_019b01da-7e31-7000-8000-000000000004",
		RootDirectory:         "",
		ExcludedCount:         3,
		ExpectedArchiveBytes:  1_024,
		ExpectedArchiveSHA256: "sha256:" + strings.Repeat("a", 64),
		ExpectedParts:         2,
		ExpiresAt:             now.Add(15 * time.Minute),
	}
}
