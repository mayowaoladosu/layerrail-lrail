package buildworker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type scrubberFunc func(context.Context, string) ([]string, error)

func (function scrubberFunc) Scrub(ctx context.Context, buildID string) ([]string, error) {
	return function(ctx, buildID)
}

type inspectorFunc func(context.Context, string) ([]Residue, error)

func (function inspectorFunc) Inspect(ctx context.Context, buildID string) ([]Residue, error) {
	return function(ctx, buildID)
}

type quarantineRecorder struct {
	buildID string
	reason  string
	err     error
}

func (recorder *quarantineRecorder) Quarantine(_ context.Context, buildID, reason string) error {
	recorder.buildID = buildID
	recorder.reason = reason
	return recorder.err
}

func TestResidueCleanerProvesDirectoryClean(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	target := filepath.Join(root, testBuildID, "attempt-1")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "residue"), []byte("fake"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	quarantine := new(quarantineRecorder)
	cleaner, err := NewResidueCleaner(DirectoryScrubber{Root: root}, DirectoryInspector{Root: root}, quarantine)
	if err != nil {
		t.Fatalf("NewResidueCleaner: %v", err)
	}
	report := cleaner.Cleanup(context.Background(), testBuildID)
	if report.Status != CleanupClean || len(report.Residue) != 0 || len(report.RemovedPaths) != 1 || quarantine.buildID != "" {
		t.Fatalf("cleanup report = %#v, quarantine = %#v", report, quarantine)
	}
	if _, err := os.Lstat(filepath.Join(root, testBuildID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scratch remains: %v", err)
	}
}

func TestResidueCleanerQuarantinesEveryUnprovenCleanup(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		scrubber  scrubberFunc
		inspector inspectorFunc
		reason    string
	}{
		"scrub": {
			scrubber:  func(context.Context, string) ([]string, error) { return nil, errors.New("fake scrub failure") },
			inspector: func(context.Context, string) ([]Residue, error) { return []Residue{}, nil },
			reason:    "scrub failed",
		},
		"inspect": {
			scrubber:  func(context.Context, string) ([]string, error) { return []string{"scratch"}, nil },
			inspector: func(context.Context, string) ([]Residue, error) { return nil, errors.New("fake inspect failure") },
			reason:    "inspection failed",
		},
		"residue": {
			scrubber: func(context.Context, string) ([]string, error) { return []string{"scratch"}, nil },
			inspector: func(context.Context, string) ([]Residue, error) {
				return []Residue{{Kind: "mount", Target: "fake-target", Detail: "still mounted"}}, nil
			},
			reason: "residue count 1",
		},
	}
	for name, testCase := range tests {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			quarantine := new(quarantineRecorder)
			cleaner, err := NewResidueCleaner(testCase.scrubber, testCase.inspector, quarantine)
			if err != nil {
				t.Fatalf("NewResidueCleaner: %v", err)
			}
			report := cleaner.Cleanup(context.Background(), testBuildID)
			if report.Status != CleanupQuarantined || !strings.Contains(report.QuarantineReason, testCase.reason) || quarantine.buildID != testBuildID {
				t.Fatalf("cleanup report = %#v, quarantine = %#v", report, quarantine)
			}
		})
	}
}

func TestResidueCleanerQuarantinesAfterCanceledCleanup(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	quarantine := new(quarantineRecorder)
	cleaner, err := NewResidueCleaner(
		scrubberFunc(func(ctx context.Context, _ string) ([]string, error) { return nil, ctx.Err() }),
		inspectorFunc(func(ctx context.Context, _ string) ([]Residue, error) { return nil, ctx.Err() }),
		quarantine,
	)
	if err != nil {
		t.Fatalf("NewResidueCleaner: %v", err)
	}
	report := cleaner.Cleanup(ctx, testBuildID)
	if report.Status != CleanupQuarantined || quarantine.buildID != testBuildID {
		t.Fatalf("cleanup report = %#v, quarantine = %#v", report, quarantine)
	}
}

func TestCleanupScopeRejectsTraversalAndInvalidIDs(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for _, buildID := range []string{"bld_invalid", "../outside", "bld_019b01da-7e31-7000-8000-000000000001/child"} {
		if _, err := (DirectoryScrubber{Root: root}).Scrub(context.Background(), buildID); err == nil {
			t.Fatalf("expected scope rejection for %q", buildID)
		}
	}
}
