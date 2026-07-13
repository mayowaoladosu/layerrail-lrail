package buildworker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const DefaultScratchBytes int64 = 20 << 30
const DefaultScratchInodes int64 = 1_000_000
const DefaultQuotaInterval = time.Second
const scratchMeasureAttempts = 5
const scratchMeasureRetryDelay = 5 * time.Millisecond

var ErrScratchQuota = errors.New("scratch quota exceeded")

type ScratchQuota struct {
	MaxBytes     int64
	MaxInodes    int64
	PollInterval time.Duration
}

type ScratchUsage struct {
	Bytes  int64
	Inodes int64
}

func normalizeScratchQuota(quota ScratchQuota) (ScratchQuota, error) {
	if quota.MaxBytes == 0 {
		quota.MaxBytes = DefaultScratchBytes
	}
	if quota.MaxInodes == 0 {
		quota.MaxInodes = DefaultScratchInodes
	}
	if quota.PollInterval == 0 {
		quota.PollInterval = DefaultQuotaInterval
	}
	if quota.MaxBytes < 1 || quota.MaxBytes > DefaultScratchBytes || quota.MaxInodes < 1 || quota.MaxInodes > DefaultScratchInodes ||
		quota.PollInterval < time.Millisecond || quota.PollInterval > time.Minute {
		return ScratchQuota{}, errors.New("scratch quota is outside safety bounds")
	}
	return quota, nil
}

func monitorScratch(parent context.Context, root string, quota ScratchQuota) (context.Context, context.CancelCauseFunc, <-chan ScratchUsage) {
	ctx, cancel := context.WithCancelCause(parent)
	violations := make(chan ScratchUsage, 1)
	go func() {
		defer close(violations)
		ticker := time.NewTicker(quota.PollInterval)
		defer ticker.Stop()
		for {
			usage, err := measureScratchWithRetry(ctx, root)
			if err != nil {
				cancel(fmt.Errorf("%w: scratch inspection failed: %v", ErrScratchQuota, err))
				return
			}
			if usage.Bytes > quota.MaxBytes || usage.Inodes > quota.MaxInodes {
				violations <- usage
				cancel(fmt.Errorf("%w: bytes=%d/%d inodes=%d/%d", ErrScratchQuota, usage.Bytes, quota.MaxBytes, usage.Inodes, quota.MaxInodes))
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return ctx, cancel, violations
}

func measureScratchWithRetry(ctx context.Context, root string) (ScratchUsage, error) {
	var lastErr error
	for attempt := range scratchMeasureAttempts {
		usage, err := measureScratch(root)
		if err == nil {
			return usage, nil
		}
		lastErr = err
		if attempt+1 == scratchMeasureAttempts {
			break
		}
		timer := time.NewTimer(scratchMeasureRetryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ScratchUsage{}, context.Cause(ctx)
		case <-timer.C:
		}
	}
	return ScratchUsage{}, lastErr
}

func measureScratch(root string) (ScratchUsage, error) {
	usage := ScratchUsage{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if ignorableOverlayWorkError(root, path, walkErr) {
				return filepath.SkipDir
			}
			if path != root && errors.Is(walkErr, os.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		usage.Inodes++
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			if path != root && errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if info.Size() < 0 || usage.Bytes > DefaultScratchBytes-info.Size() {
			return errors.New("scratch usage overflow")
		}
		usage.Bytes += info.Size()
		return nil
	})
	return usage, err
}

func ignorableOverlayWorkError(root, candidate string, err error) bool {
	if !errors.Is(err, os.ErrPermission) {
		return false
	}
	relative, relativeErr := filepath.Rel(root, candidate)
	if relativeErr != nil {
		return false
	}
	parts := strings.Split(filepath.ToSlash(relative), "/")
	if len(parts) != 7 || parts[0] != "buildkit" || parts[1] != "runc-overlayfs" || parts[2] != "snapshots" || parts[3] != "snapshots" || parts[5] != "work" || parts[6] != "work" {
		return false
	}
	snapshot, parseErr := strconv.ParseUint(parts[4], 10, 64)
	return parseErr == nil && snapshot > 0
}
