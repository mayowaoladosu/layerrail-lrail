package sourceupload

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/objectstore"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/snapshotstore"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourcearchive"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourceauth"
)

type Finalizer struct {
	Store        objectstore.Store
	ScratchDir   string
	Policy       sourcearchive.Policy
	PrivateKey   ed25519.PrivateKey
	SigningKeyID string
	Now          func() time.Time
}

func (finalizer *Finalizer) Finalize(
	ctx context.Context,
	grant sourceauth.UploadGrant,
	parts []Part,
) (sourceauth.SignedResult, error) {
	if finalizer.Store == nil || len(finalizer.PrivateKey) != ed25519.PrivateKeySize || finalizer.SigningKeyID == "" {
		return sourceauth.SignedResult{}, errors.New("source finalizer configuration is incomplete")
	}
	if completed, found, err := finalizer.completedResult(ctx, grant); err != nil {
		return sourceauth.SignedResult{}, err
	} else if found {
		if err := finalizer.Store.Delete(ctx, partKeys(grant)); err != nil {
			return sourceauth.SignedResult{}, err
		}
		return completed, nil
	}
	reader, err := NewPartsReader(ctx, finalizer.Store, grant, parts)
	if err != nil {
		return sourceauth.SignedResult{}, err
	}
	defer reader.Close()

	stored, err := (&snapshotstore.Writer{
		Store:      finalizer.Store,
		ScratchDir: finalizer.ScratchDir,
		Policy:     finalizer.Policy,
	}).Write(ctx, snapshotstore.Input{
		Reader:                reader,
		ExpectedArchiveBytes:  grant.ExpectedArchiveBytes,
		ExpectedArchiveSHA256: grant.ExpectedArchiveSHA256,
		Metadata: sourcearchive.Metadata{
			SourceKind:    "local",
			RootDirectory: grant.RootDirectory,
			CreatorID:     grant.CreatorID,
			ExcludedCount: grant.ExcludedCount,
		},
	})
	if err != nil {
		return sourceauth.SignedResult{}, err
	}

	now := time.Now().UTC()
	if finalizer.Now != nil {
		now = finalizer.Now().UTC()
	}
	signed, err := sourceauth.SignResult(finalizer.PrivateKey, finalizer.SigningKeyID, sourceauth.FinalizationResult{
		Version:        1,
		SessionID:      grant.SessionID,
		OrganizationID: grant.OrganizationID,
		ProjectID:      grant.ProjectID,
		SnapshotSHA256: stored.Source.SnapshotSHA256,
		ManifestSHA256: stored.Source.ManifestSHA256,
		ArchiveSHA256:  stored.Source.ArchiveSHA256,
		ManifestRef:    stored.ManifestRef,
		ArchiveRef:     stored.ArchiveRef,
		SizeBytes:      stored.SizeBytes,
		PolicyVersion:  finalizer.Policy.Version,
		FinalizedAt:    now,
	})
	if err != nil {
		return sourceauth.SignedResult{}, err
	}
	receipt, err := canonicaljson.Marshal(signed)
	if err != nil {
		return sourceauth.SignedResult{}, fmt.Errorf("canonicalize source finalization receipt: %w", err)
	}
	receiptDigest := sha256.Sum256(receipt)
	if err := finalizer.Store.PutImmutable(
		ctx,
		finalizationKey(grant),
		bytes.NewReader(receipt),
		int64(len(receipt)),
		"sha256:"+hex.EncodeToString(receiptDigest[:]),
		"application/json",
	); err != nil {
		return sourceauth.SignedResult{}, err
	}
	if err := finalizer.Store.Delete(ctx, partKeys(grant)); err != nil {
		return sourceauth.SignedResult{}, err
	}
	return signed, nil
}

func (finalizer *Finalizer) completedResult(
	ctx context.Context,
	grant sourceauth.UploadGrant,
) (sourceauth.SignedResult, bool, error) {
	reader, info, err := finalizer.Store.Open(ctx, finalizationKey(grant))
	if errors.Is(err, objectstore.ErrNotFound) {
		return sourceauth.SignedResult{}, false, nil
	}
	if err != nil {
		return sourceauth.SignedResult{}, false, err
	}
	defer reader.Close()
	if info.Size <= 0 || info.Size > 64<<10 {
		return sourceauth.SignedResult{}, false, errors.New("stored source finalization receipt exceeds limit")
	}
	decoder := json.NewDecoder(io.LimitReader(reader, 64<<10))
	decoder.DisallowUnknownFields()
	var signed sourceauth.SignedResult
	if err := decoder.Decode(&signed); err != nil {
		return sourceauth.SignedResult{}, false, fmt.Errorf("decode source finalization receipt: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return sourceauth.SignedResult{}, false, errors.New("source finalization receipt contains trailing data")
	}
	if err := sourceauth.VerifyResult(finalizer.PrivateKey.Public().(ed25519.PublicKey), signed); err != nil {
		return sourceauth.SignedResult{}, false, err
	}
	if signed.Result.SessionID != grant.SessionID || signed.Result.OrganizationID != grant.OrganizationID ||
		signed.Result.ProjectID != grant.ProjectID || signed.Result.ArchiveSHA256 != grant.ExpectedArchiveSHA256 ||
		signed.Result.SizeBytes != grant.ExpectedArchiveBytes || signed.Result.PolicyVersion != finalizer.Policy.Version {
		return sourceauth.SignedResult{}, false, sourceauth.ErrInvalidResult
	}
	return signed, true, nil
}

func finalizationKey(grant sourceauth.UploadGrant) string {
	return path.Join("finalizations", grant.OrganizationID, grant.SessionID+".json")
}

func partKeys(grant sourceauth.UploadGrant) []string {
	keys := make([]string, grant.ExpectedParts)
	for index := range grant.ExpectedParts {
		keys[index] = PartKey(grant, index+1)
	}
	return keys
}
