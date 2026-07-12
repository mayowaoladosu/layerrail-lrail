package sourceupload

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/objectstore"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourceauth"
)

type PresignedPart struct {
	Number    int       `json:"number"`
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

func PresignParts(ctx context.Context, store objectstore.Store, grant sourceauth.UploadGrant, now time.Time) ([]PresignedPart, error) {
	if store == nil {
		return nil, errors.New("source object store is required")
	}
	expiry := grant.ExpiresAt.Sub(now.UTC())
	if expiry < time.Second || expiry > 30*time.Minute {
		return nil, sourceauth.ErrInvalidGrant
	}
	parts := make([]PresignedPart, grant.ExpectedParts)
	for index := range grant.ExpectedParts {
		number := index + 1
		location, err := store.PresignPut(ctx, PartKey(grant, number), expiry)
		if err != nil {
			return nil, fmt.Errorf("presign source part %d: %w", number, err)
		}
		parts[index] = PresignedPart{Number: number, URL: location.String(), ExpiresAt: grant.ExpiresAt}
	}
	return parts, nil
}
