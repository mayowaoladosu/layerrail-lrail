package buildworker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestMeasureScratchCountsBytesAndInodes(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "dir"), 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "dir", "file"), []byte("12345"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	usage, err := measureScratch(root)
	if err != nil {
		t.Fatalf("measureScratch: %v", err)
	}
	if usage.Bytes != 5 || usage.Inodes != 3 {
		t.Fatalf("usage = %#v", usage)
	}
}

func TestMonitorScratchCancelsOnByteAndInodeLimits(t *testing.T) {
	t.Parallel()
	tests := map[string]ScratchQuota{
		"bytes":  {MaxBytes: 4, MaxInodes: 10, PollInterval: time.Millisecond},
		"inodes": {MaxBytes: 100, MaxInodes: 2, PollInterval: time.Millisecond},
	}
	for name, quota := range tests {
		quota := quota
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Mkdir(filepath.Join(root, "dir"), 0o700); err != nil {
				t.Fatalf("Mkdir: %v", err)
			}
			if err := os.WriteFile(filepath.Join(root, "dir", "file"), []byte("12345"), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			ctx, cancel, violations := monitorScratch(context.Background(), root, quota)
			defer cancel(nil)
			select {
			case usage := <-violations:
				if usage.Bytes != 5 || usage.Inodes != 3 {
					t.Fatalf("usage = %#v", usage)
				}
			case <-time.After(time.Second):
				t.Fatal("quota monitor did not cancel")
			}
			<-ctx.Done()
			if !errors.Is(context.Cause(ctx), ErrScratchQuota) {
				t.Fatalf("cause = %v", context.Cause(ctx))
			}
		})
	}
}

func TestMeasureScratchCountsSymlinkWithoutFollowingIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ordinary Windows test users cannot create symlinks")
	}
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	usage, err := measureScratch(root)
	if err != nil || usage.Inodes != 2 || usage.Bytes >= 1<<20 {
		t.Fatalf("usage=%#v error=%v", usage, err)
	}
}

func TestMeasureScratchToleratesConcurrentDescendantDeletionButNotMissingRoot(t *testing.T) {
	root := t.TempDir()
	for iteration := range 20 {
		directory := filepath.Join(root, "churn")
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		for index := range 100 {
			if err := os.WriteFile(filepath.Join(directory, fmt.Sprintf("%03d-%03d", iteration, index)), []byte("x"), 0o600); err != nil {
				t.Fatalf("WriteFile iteration %d: %v", iteration, err)
			}
		}
		removed := make(chan error, 1)
		go func() { removed <- os.RemoveAll(directory) }()
		if _, err := measureScratchWithRetry(context.Background(), root); err != nil {
			t.Fatalf("measureScratchWithRetry during deletion: %v", err)
		}
		if err := <-removed; err != nil {
			t.Fatalf("RemoveAll: %v", err)
		}
	}
	missing := filepath.Join(root, "missing")
	if _, err := measureScratch(missing); err == nil {
		t.Fatal("expected missing quota root rejection")
	}
}

func TestOverlayWorkPermissionExceptionIsExact(t *testing.T) {
	t.Parallel()
	root := filepath.Join("var", "lib", "lrail-worker")
	allowed := filepath.Join(root, "buildkit", "runc-overlayfs", "snapshots", "snapshots", "3", "work", "work")
	if !ignorableOverlayWorkError(root, allowed, os.ErrPermission) {
		t.Fatal("exact BuildKit overlay work path was not recognized")
	}
	for _, candidate := range []string{
		filepath.Join(root, "buildkit", "runc-overlayfs", "snapshots", "snapshots", "not-a-number", "work", "work"),
		filepath.Join(root, "buildkit", "runc-overlayfs", "snapshots", "snapshots", "3", "fs"),
		filepath.Join(root, "customer", "work", "work"),
	} {
		if ignorableOverlayWorkError(root, candidate, os.ErrPermission) {
			t.Fatalf("overbroad quota permission exception: %s", candidate)
		}
	}
	if ignorableOverlayWorkError(root, allowed, os.ErrNotExist) {
		t.Fatal("non-permission error was ignored")
	}
}
