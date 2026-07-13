package buildworker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
)

const DefaultQuarantineTimeout = 15 * time.Second

type CleanupStatus string

const (
	CleanupClean       CleanupStatus = "clean"
	CleanupQuarantined CleanupStatus = "quarantined"
)

type Residue struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Detail string `json:"detail"`
}

type CleanupReport struct {
	BuildID          string        `json:"build_id"`
	Status           CleanupStatus `json:"status"`
	Residue          []Residue     `json:"residue"`
	RemovedPaths     []string      `json:"removed_paths"`
	QuarantineReason string        `json:"quarantine_reason,omitempty"`
}

type Scrubber interface {
	Scrub(ctx context.Context, buildID string) ([]string, error)
}

type ResidueInspector interface {
	Inspect(ctx context.Context, buildID string) ([]Residue, error)
}

type Quarantiner interface {
	Quarantine(ctx context.Context, buildID, reason string) error
}

type ResidueCleaner struct {
	scrubber    Scrubber
	inspector   ResidueInspector
	quarantiner Quarantiner
}

func NewResidueCleaner(scrubber Scrubber, inspector ResidueInspector, quarantiner Quarantiner) (*ResidueCleaner, error) {
	if scrubber == nil || inspector == nil || quarantiner == nil {
		return nil, errors.New("cleanup dependencies are incomplete")
	}
	return &ResidueCleaner{scrubber: scrubber, inspector: inspector, quarantiner: quarantiner}, nil
}

func (cleaner *ResidueCleaner) Cleanup(ctx context.Context, buildID string) CleanupReport {
	report := CleanupReport{BuildID: buildID, Status: CleanupClean, Residue: []Residue{}, RemovedPaths: []string{}}
	removed, scrubErr := cleaner.scrubber.Scrub(ctx, buildID)
	report.RemovedPaths = append(report.RemovedPaths, removed...)
	residue, inspectErr := cleaner.inspector.Inspect(ctx, buildID)
	report.Residue = append(report.Residue, residue...)
	if scrubErr == nil && inspectErr == nil && len(residue) == 0 {
		return report
	}
	report.Status = CleanupQuarantined
	report.QuarantineReason = cleanupReason(scrubErr, inspectErr, residue)
	quarantineContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), DefaultQuarantineTimeout)
	defer cancel()
	if err := cleaner.quarantiner.Quarantine(quarantineContext, buildID, report.QuarantineReason); err != nil {
		report.QuarantineReason += "; quarantine failed"
	}
	return report
}

func cleanupReason(scrubErr, inspectErr error, residue []Residue) string {
	parts := make([]string, 0, 3)
	if scrubErr != nil {
		parts = append(parts, "scrub failed")
	}
	if inspectErr != nil {
		parts = append(parts, "inspection failed")
	}
	if len(residue) > 0 {
		parts = append(parts, fmt.Sprintf("residue count %d", len(residue)))
	}
	return strings.Join(parts, "; ")
}

type DirectoryScrubber struct {
	Root string
}

func (scrubber DirectoryScrubber) Scrub(ctx context.Context, buildID string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	target, err := scopedBuildPath(scrubber.Root, buildID)
	if err != nil {
		return nil, err
	}
	if err := os.RemoveAll(target); err != nil {
		return nil, err
	}
	return []string{target}, nil
}

type DirectoryInspector struct {
	Root string
}

func (inspector DirectoryInspector) Inspect(ctx context.Context, buildID string) ([]Residue, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	target, err := scopedBuildPath(inspector.Root, buildID)
	if err != nil {
		return nil, err
	}
	_, statErr := os.Lstat(target)
	if errors.Is(statErr, os.ErrNotExist) {
		return []Residue{}, nil
	}
	if statErr != nil {
		return nil, statErr
	}
	return []Residue{{Kind: "filesystem", Target: target, Detail: "build scratch remains"}}, nil
}

func scopedBuildPath(root, buildID string) (string, error) {
	parsed, parseErr := platformid.Parse(buildID)
	if root == "" || parseErr != nil || parsed.Prefix() != "bld" || strings.ContainsAny(buildID, `/\\:`) {
		return "", errors.New("invalid cleanup scope")
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	target := filepath.Join(absoluteRoot, buildID)
	relative, err := filepath.Rel(absoluteRoot, target)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", errors.New("cleanup target escaped root")
	}
	return target, nil
}
