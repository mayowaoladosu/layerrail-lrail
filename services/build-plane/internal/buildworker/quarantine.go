package buildworker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
)

type FileQuarantiner struct {
	Root  string
	Clock func() time.Time
}

func (quarantiner FileQuarantiner) Quarantine(ctx context.Context, buildID, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if reason == "" {
		return errors.New("quarantine reason is empty")
	}
	target, err := scopedBuildPath(quarantiner.Root, buildID)
	if err != nil {
		return err
	}
	if quarantiner.Clock == nil {
		quarantiner.Clock = time.Now
	}
	if err := os.MkdirAll(quarantiner.Root, 0o700); err != nil {
		return err
	}
	contents, err := canonicaljson.Marshal(struct {
		Version       int    `json:"version"`
		BuildID       string `json:"build_id"`
		Reason        string `json:"reason"`
		QuarantinedAt string `json:"quarantined_at"`
	}{Version: 1, BuildID: buildID, Reason: reason, QuarantinedAt: quarantiner.Clock().UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return err
	}
	return writeAtomicFile(filepath.Join(filepath.Dir(target), buildID+".quarantined.json"), contents, 0o600)
}
