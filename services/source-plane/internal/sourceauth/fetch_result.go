package sourceauth

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
)

var ErrInvalidFetchResult = errors.New("invalid signed source fetch result")

type Submodule struct {
	Path       string `json:"path"`
	Repository string `json:"repository"`
	CommitSHA  string `json:"commit_sha"`
}

type FetchResult struct {
	Version            int         `json:"version"`
	FetchID            string      `json:"fetch_id"`
	OrganizationID     string      `json:"organization_id"`
	ProjectID          string      `json:"project_id"`
	SourceConnectionID string      `json:"source_connection_id"`
	Provider           string      `json:"provider"`
	Repository         string      `json:"repository"`
	RequestedCommitSHA string      `json:"requested_commit_sha"`
	ResolvedCommitSHA  string      `json:"resolved_commit_sha"`
	TreeSHA            string      `json:"tree_sha"`
	Author             string      `json:"author"`
	AuthoredAt         time.Time   `json:"authored_at"`
	SnapshotSHA256     string      `json:"snapshot_sha256"`
	ManifestSHA256     string      `json:"manifest_sha256"`
	ArchiveSHA256      string      `json:"archive_sha256"`
	ManifestRef        string      `json:"manifest_ref"`
	ArchiveRef         string      `json:"archive_ref"`
	SizeBytes          int64       `json:"size_bytes"`
	PolicyVersion      string      `json:"policy_version"`
	Submodules         []Submodule `json:"submodules"`
	LFSDigests         []string    `json:"lfs_digests"`
	Warnings           []string    `json:"warnings"`
	TokenExpiresAt     time.Time   `json:"token_expires_at"`
	FinalizedAt        time.Time   `json:"finalized_at"`
}

type SignedFetchResult struct {
	KeyID     string      `json:"key_id"`
	Result    FetchResult `json:"result"`
	Signature string      `json:"signature"`
}

func SignFetchResult(privateKey ed25519.PrivateKey, keyID string, result FetchResult) (SignedFetchResult, error) {
	if len(privateKey) != ed25519.PrivateKeySize || keyID == "" {
		return SignedFetchResult{}, ErrInvalidFetchResult
	}
	if err := validateFetchResult(result); err != nil {
		return SignedFetchResult{}, err
	}
	payload, err := canonicaljson.Marshal(result)
	if err != nil {
		return SignedFetchResult{}, fmt.Errorf("canonicalize source fetch result: %w", err)
	}
	signature := ed25519.Sign(privateKey, payload)
	return SignedFetchResult{
		KeyID:     keyID,
		Result:    result,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}, nil
}

func VerifyFetchResult(publicKey ed25519.PublicKey, signed SignedFetchResult) error {
	if len(publicKey) != ed25519.PublicKeySize || signed.KeyID == "" {
		return ErrInvalidFetchResult
	}
	if err := validateFetchResult(signed.Result); err != nil {
		return err
	}
	payload, err := canonicaljson.Marshal(signed.Result)
	if err != nil {
		return ErrInvalidFetchResult
	}
	signature, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		return ErrInvalidFetchResult
	}
	return nil
}

func validateFetchResult(result FetchResult) error {
	if result.Version != 1 || !hasPrefix(result.FetchID, "fet") || !hasPrefix(result.OrganizationID, "org") ||
		!hasPrefix(result.ProjectID, "prj") || !hasPrefix(result.SourceConnectionID, "src") ||
		result.Provider != "github" || !fetchRepository.MatchString(result.Repository) ||
		!fetchCommit.MatchString(result.RequestedCommitSHA) || !fetchCommit.MatchString(result.ResolvedCommitSHA) ||
		result.RequestedCommitSHA != result.ResolvedCommitSHA || !fetchCommit.MatchString(result.TreeSHA) ||
		!validDigest(result.SnapshotSHA256) || !validDigest(result.ManifestSHA256) ||
		!validDigest(result.ArchiveSHA256) || result.ManifestRef == "" || result.ArchiveRef == "" ||
		result.SizeBytes <= 0 || result.PolicyVersion == "" || result.AuthoredAt.IsZero() ||
		result.TokenExpiresAt.IsZero() || result.FinalizedAt.IsZero() ||
		!slices.IsSorted(result.Warnings) || !slices.IsSorted(result.LFSDigests) {
		return ErrInvalidFetchResult
	}
	for _, digest := range result.LFSDigests {
		if !validDigest(digest) {
			return ErrInvalidFetchResult
		}
	}
	for _, submodule := range result.Submodules {
		if submodule.Path == "" || !fetchRepository.MatchString(submodule.Repository) ||
			!fetchCommit.MatchString(submodule.CommitSHA) {
			return ErrInvalidFetchResult
		}
	}
	return nil
}
