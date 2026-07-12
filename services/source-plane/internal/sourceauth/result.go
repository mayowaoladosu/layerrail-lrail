package sourceauth

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
)

var ErrInvalidResult = errors.New("invalid signed source result")

type FinalizationResult struct {
	Version        int       `json:"version"`
	SessionID      string    `json:"session_id"`
	OrganizationID string    `json:"organization_id"`
	ProjectID      string    `json:"project_id"`
	SnapshotSHA256 string    `json:"snapshot_sha256"`
	ManifestSHA256 string    `json:"manifest_sha256"`
	ArchiveSHA256  string    `json:"archive_sha256"`
	ManifestRef    string    `json:"manifest_ref"`
	ArchiveRef     string    `json:"archive_ref"`
	SizeBytes      int64     `json:"size_bytes"`
	PolicyVersion  string    `json:"policy_version"`
	FinalizedAt    time.Time `json:"finalized_at"`
}

type SignedResult struct {
	KeyID     string             `json:"key_id"`
	Result    FinalizationResult `json:"result"`
	Signature string             `json:"signature"`
}

func SignResult(privateKey ed25519.PrivateKey, keyID string, result FinalizationResult) (SignedResult, error) {
	if len(privateKey) != ed25519.PrivateKeySize || keyID == "" {
		return SignedResult{}, ErrInvalidResult
	}
	if err := validateResult(result); err != nil {
		return SignedResult{}, err
	}
	payload, err := canonicaljson.Marshal(result)
	if err != nil {
		return SignedResult{}, fmt.Errorf("canonicalize source result: %w", err)
	}
	signature := ed25519.Sign(privateKey, payload)
	return SignedResult{KeyID: keyID, Result: result, Signature: base64.RawURLEncoding.EncodeToString(signature)}, nil
}

func VerifyResult(publicKey ed25519.PublicKey, signed SignedResult) error {
	if len(publicKey) != ed25519.PublicKeySize || signed.KeyID == "" {
		return ErrInvalidResult
	}
	if err := validateResult(signed.Result); err != nil {
		return err
	}
	payload, err := canonicaljson.Marshal(signed.Result)
	if err != nil {
		return ErrInvalidResult
	}
	signature, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		return ErrInvalidResult
	}
	return nil
}

func validateResult(result FinalizationResult) error {
	if result.Version != 1 || !hasPrefix(result.SessionID, "upl") || !hasPrefix(result.OrganizationID, "org") ||
		!hasPrefix(result.ProjectID, "prj") || !validDigest(result.SnapshotSHA256) ||
		!validDigest(result.ManifestSHA256) || !validDigest(result.ArchiveSHA256) || result.ManifestRef == "" ||
		result.ArchiveRef == "" || result.SizeBytes <= 0 || result.PolicyVersion == "" || result.FinalizedAt.IsZero() {
		return ErrInvalidResult
	}
	return nil
}
