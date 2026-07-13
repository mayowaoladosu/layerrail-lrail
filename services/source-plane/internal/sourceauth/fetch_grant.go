package sourceauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
)

const fetchGrantVersion = "f1"

var (
	ErrInvalidFetchGrant = errors.New("invalid source fetch grant")
	ErrExpiredFetchGrant = errors.New("source fetch grant expired")
	fetchRepository      = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?/[A-Za-z0-9_.-]{1,100}$`)
	fetchCommit          = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	installationID       = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
)

type FetchGrant struct {
	Version            int       `json:"version"`
	Audience           string    `json:"audience"`
	FetchID            string    `json:"fetch_id"`
	OrganizationID     string    `json:"organization_id"`
	ProjectID          string    `json:"project_id"`
	CreatorID          string    `json:"creator_id"`
	SourceConnectionID string    `json:"source_connection_id"`
	Provider           string    `json:"provider"`
	InstallationID     string    `json:"installation_id"`
	Repository         string    `json:"repository"`
	CommitSHA          string    `json:"commit_sha"`
	RootDirectory      string    `json:"root_directory"`
	ExpiresAt          time.Time `json:"expires_at"`
}

func SignFetchGrant(secret []byte, grant FetchGrant) (string, error) {
	return SignFetchGrantAt(secret, grant, time.Now().UTC())
}

func SignFetchGrantAt(secret []byte, grant FetchGrant, now time.Time) (string, error) {
	if len(secret) < 32 {
		return "", fmt.Errorf("%w: signing key is shorter than 32 bytes", ErrInvalidFetchGrant)
	}
	if err := validateFetchGrant(grant, now.UTC(), true); err != nil {
		return "", err
	}
	payload, err := canonicaljson.Marshal(grant)
	if err != nil {
		return "", fmt.Errorf("canonicalize source fetch grant: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(fetchGrantVersion + "." + encoded))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return fetchGrantVersion + "." + encoded + "." + signature, nil
}

func VerifyFetchGrant(secret []byte, token string, now time.Time) (FetchGrant, error) {
	if len(secret) < 32 {
		return FetchGrant{}, fmt.Errorf("%w: verification key is shorter than 32 bytes", ErrInvalidFetchGrant)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != fetchGrantVersion {
		return FetchGrant{}, ErrInvalidFetchGrant
	}
	provided, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return FetchGrant{}, ErrInvalidFetchGrant
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return FetchGrant{}, ErrInvalidFetchGrant
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return FetchGrant{}, ErrInvalidFetchGrant
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var grant FetchGrant
	if err := decoder.Decode(&grant); err != nil {
		return FetchGrant{}, ErrInvalidFetchGrant
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return FetchGrant{}, ErrInvalidFetchGrant
	}
	if err := validateFetchGrant(grant, now.UTC(), true); err != nil {
		return FetchGrant{}, err
	}
	return grant, nil
}

func validateFetchGrant(grant FetchGrant, now time.Time, enforceTime bool) error {
	repositoryParts := strings.SplitN(grant.Repository, "/", 2)
	if grant.Version != 1 || grant.Audience != Audience || grant.Provider != "github" ||
		!hasPrefix(grant.FetchID, "fet") || !hasPrefix(grant.OrganizationID, "org") ||
		!hasPrefix(grant.ProjectID, "prj") || !hasPrefix(grant.CreatorID, "acct") ||
		!hasPrefix(grant.SourceConnectionID, "src") || !installationID.MatchString(grant.InstallationID) ||
		!fetchRepository.MatchString(grant.Repository) || strings.HasSuffix(strings.ToLower(grant.Repository), ".git") ||
		len(repositoryParts) != 2 || repositoryParts[1] == "." || repositoryParts[1] == ".." ||
		!fetchCommit.MatchString(grant.CommitSHA) || !safeRoot(grant.RootDirectory) {
		return ErrInvalidFetchGrant
	}
	if _, err := strconv.ParseUint(grant.InstallationID, 10, 64); err != nil {
		return ErrInvalidFetchGrant
	}
	if grant.ExpiresAt.IsZero() || grant.ExpiresAt.After(now.Add(30*time.Minute)) {
		return ErrInvalidFetchGrant
	}
	if enforceTime && !grant.ExpiresAt.After(now) {
		return ErrExpiredFetchGrant
	}
	return nil
}
