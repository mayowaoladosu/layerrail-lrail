// Package sourceauth authenticates bounded upload sessions and signed finalizer results.
package sourceauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
)

const (
	grantVersion = "v1"
	Audience     = "lrail-source-gateway"
	MaxPartBytes = 16 << 20
	MaxParts     = 256
)

var (
	ErrInvalidGrant = errors.New("invalid source upload grant")
	ErrExpiredGrant = errors.New("source upload grant expired")
)

type UploadGrant struct {
	Version               int       `json:"version"`
	Audience              string    `json:"audience"`
	SessionID             string    `json:"session_id"`
	OrganizationID        string    `json:"organization_id"`
	ProjectID             string    `json:"project_id"`
	CreatorID             string    `json:"creator_id"`
	RootDirectory         string    `json:"root_directory"`
	ExcludedCount         int       `json:"excluded_count"`
	ExpectedArchiveBytes  int64     `json:"expected_archive_bytes"`
	ExpectedArchiveSHA256 string    `json:"expected_archive_sha256"`
	ExpectedParts         int       `json:"expected_parts"`
	ExpiresAt             time.Time `json:"expires_at"`
}

func SignGrant(secret []byte, grant UploadGrant) (string, error) {
	return SignGrantAt(secret, grant, time.Now().UTC())
}

func SignGrantAt(secret []byte, grant UploadGrant, now time.Time) (string, error) {
	if len(secret) < 32 {
		return "", fmt.Errorf("%w: signing key is shorter than 32 bytes", ErrInvalidGrant)
	}
	grant.ExpiresAt = grant.ExpiresAt.UTC().Truncate(time.Second)
	if err := validateGrant(grant, now.UTC(), true); err != nil {
		return "", err
	}
	payload, err := canonicaljson.Marshal(grant)
	if err != nil {
		return "", fmt.Errorf("canonicalize source grant: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(grantVersion + "." + encoded))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return grantVersion + "." + encoded + "." + signature, nil
}

func VerifyGrant(secret []byte, token string, now time.Time) (UploadGrant, error) {
	if len(secret) < 32 {
		return UploadGrant{}, fmt.Errorf("%w: verification key is shorter than 32 bytes", ErrInvalidGrant)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != grantVersion {
		return UploadGrant{}, ErrInvalidGrant
	}
	provided, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return UploadGrant{}, ErrInvalidGrant
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return UploadGrant{}, ErrInvalidGrant
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return UploadGrant{}, ErrInvalidGrant
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var grant UploadGrant
	if err := decoder.Decode(&grant); err != nil {
		return UploadGrant{}, ErrInvalidGrant
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return UploadGrant{}, ErrInvalidGrant
	}
	if err := validateGrant(grant, now.UTC(), true); err != nil {
		return UploadGrant{}, err
	}
	return grant, nil
}

func validateGrant(grant UploadGrant, now time.Time, enforceTime bool) error {
	if grant.Version != 1 || grant.Audience != Audience || grant.ExpectedArchiveBytes <= 0 ||
		grant.ExpectedArchiveBytes > 1<<30 || grant.ExpectedParts < 1 || grant.ExpectedParts > MaxParts ||
		grant.ExpectedArchiveBytes > int64(grant.ExpectedParts)*MaxPartBytes || grant.ExcludedCount < 0 ||
		!validDigest(grant.ExpectedArchiveSHA256) {
		return ErrInvalidGrant
	}
	if !hasPrefix(grant.SessionID, "upl") || !hasPrefix(grant.OrganizationID, "org") || !hasPrefix(grant.ProjectID, "prj") ||
		!hasPrefix(grant.CreatorID, "acct") || !safeRoot(grant.RootDirectory) {
		return ErrInvalidGrant
	}
	if grant.ExpiresAt.IsZero() || grant.ExpiresAt.After(now.Add(30*time.Minute)) {
		return ErrInvalidGrant
	}
	if enforceTime && !grant.ExpiresAt.After(now) {
		return ErrExpiredGrant
	}
	return nil
}

func safeRoot(value string) bool {
	if value == "" {
		return true
	}
	cleaned := path.Clean(value)
	return utf8.ValidString(value) && cleaned == value && cleaned != "." && cleaned != ".." &&
		!path.IsAbs(cleaned) && !strings.HasPrefix(cleaned, "../") && !strings.Contains(cleaned, "\\") &&
		!strings.Contains(cleaned, ":") && !strings.ContainsRune(cleaned, '\x00') && len([]byte(cleaned)) <= 512
}

func hasPrefix(value string, prefix string) bool {
	identifier, err := platformid.Parse(value)
	return err == nil && identifier.Prefix() == prefix
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}
