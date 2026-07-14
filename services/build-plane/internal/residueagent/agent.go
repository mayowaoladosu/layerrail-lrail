// Package residueagent scrubs and proves cleanup of one terminated build Pod.
package residueagent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
)

const MaxCgroupEntries = 100_000

var podUIDPattern = regexp.MustCompile(`^[a-f0-9][a-f0-9-]{15,63}$`)
var podNamePattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)

type Request struct {
	BuildID  string
	PodUID   string
	PodName  string
	NodeName string
}

type RuntimeCleaner interface {
	CleanupPod(ctx context.Context, podUID string) ([]string, error)
	InspectPod(ctx context.Context, podUID string) ([]buildworker.Residue, error)
}

type MountCleaner interface {
	UnmountUnder(ctx context.Context, root string) ([]string, error)
	InspectUnder(ctx context.Context, root string) ([]buildworker.Residue, error)
}

type Config struct {
	NodeName        string
	KubeletPodsRoot string
	CgroupRoot      string
}

type Agent struct {
	config  Config
	runtime RuntimeCleaner
	mounts  MountCleaner
}

func New(config Config, runtime RuntimeCleaner, mounts MountCleaner) (*Agent, error) {
	if config.NodeName == "" || runtime == nil || mounts == nil {
		return nil, errors.New("residue agent configuration is incomplete")
	}
	podsRoot, err := secureExistingRoot(config.KubeletPodsRoot)
	if err != nil {
		return nil, fmt.Errorf("invalid kubelet pods root: %w", err)
	}
	cgroupRoot, err := secureExistingRoot(config.CgroupRoot)
	if err != nil {
		return nil, fmt.Errorf("invalid cgroup root: %w", err)
	}
	config.KubeletPodsRoot = podsRoot
	config.CgroupRoot = cgroupRoot
	return &Agent{config: config, runtime: runtime, mounts: mounts}, nil
}

func (agent *Agent) Cleanup(ctx context.Context, request Request) buildworker.CleanupReport {
	report := buildworker.CleanupReport{BuildID: request.BuildID, Status: buildworker.CleanupClean, Residue: []buildworker.Residue{}, RemovedPaths: []string{}}
	if err := validateRequest(request, agent.config.NodeName); err != nil {
		return quarantineReport(report, "invalid residue cleanup scope", buildworker.Residue{Kind: "scope", Detail: "request rejected"})
	}
	podRoot, err := scopedPath(agent.config.KubeletPodsRoot, request.PodUID)
	if err != nil {
		return quarantineReport(report, "invalid pod residue path", buildworker.Residue{Kind: "scope", Detail: "pod path rejected"})
	}
	removedRuntime, runtimeErr := agent.runtime.CleanupPod(ctx, request.PodUID)
	report.RemovedPaths = append(report.RemovedPaths, removedRuntime...)
	removedMounts, mountErr := agent.mounts.UnmountUnder(ctx, podRoot)
	report.RemovedPaths = append(report.RemovedPaths, removedMounts...)
	podErr := removePodRoot(ctx, podRoot)
	removedCgroups, cgroupErr := scrubCgroups(ctx, agent.config.CgroupRoot, request.PodUID)
	report.RemovedPaths = append(report.RemovedPaths, removedCgroups...)

	runtimeResidue, runtimeInspectErr := agent.runtime.InspectPod(ctx, request.PodUID)
	mountResidue, mountInspectErr := agent.mounts.InspectUnder(ctx, podRoot)
	cgroupResidue, cgroupInspectErr := inspectCgroups(ctx, agent.config.CgroupRoot, request.PodUID)
	report.Residue = append(report.Residue, runtimeResidue...)
	report.Residue = append(report.Residue, mountResidue...)
	report.Residue = append(report.Residue, cgroupResidue...)
	if _, statErr := os.Lstat(podRoot); statErr == nil {
		report.Residue = append(report.Residue, buildworker.Residue{Kind: "kubelet_pod", Target: podRoot, Detail: "pod volume root remains"})
	} else if !errors.Is(statErr, os.ErrNotExist) {
		report.Residue = append(report.Residue, buildworker.Residue{Kind: "kubelet_pod", Target: podRoot, Detail: "pod volume root cannot be inspected"})
	}
	allErrors := errors.Join(runtimeErr, mountErr, podErr, cgroupErr, runtimeInspectErr, mountInspectErr, cgroupInspectErr)
	if allErrors != nil || len(report.Residue) > 0 {
		report.Status = buildworker.CleanupQuarantined
		report.QuarantineReason = cleanupFailureReason(
			runtimeErr, mountErr, podErr, cgroupErr,
			runtimeInspectErr, mountInspectErr, cgroupInspectErr,
			len(report.Residue) > 0,
		)
	}
	sort.Strings(report.RemovedPaths)
	return report
}

func cleanupFailureReason(runtimeErr, mountErr, podErr, cgroupErr, runtimeInspectErr, mountInspectErr, cgroupInspectErr error, residue bool) string {
	failures := []string{}
	for _, failure := range []struct {
		name string
		err  error
	}{
		{name: "runtime cleanup", err: runtimeErr},
		{name: "mount cleanup", err: mountErr},
		{name: "pod-root cleanup", err: podErr},
		{name: "cgroup cleanup", err: cgroupErr},
		{name: "runtime inspection", err: runtimeInspectErr},
		{name: "mount inspection", err: mountInspectErr},
		{name: "cgroup inspection", err: cgroupInspectErr},
	} {
		if failure.err != nil {
			failures = append(failures, failure.name)
		}
	}
	if residue {
		failures = append(failures, "residue remained")
	}
	if len(failures) == 0 {
		return "node residue cleanup or verification failed"
	}
	return "node residue cleanup or verification failed: " + strings.Join(failures, ", ")
}

func validateRequest(request Request, nodeName string) error {
	parsed, err := platformid.Parse(request.BuildID)
	if err != nil || parsed.Prefix() != "bld" || !podUIDPattern.MatchString(request.PodUID) || !podNamePattern.MatchString(request.PodName) || request.NodeName != nodeName {
		return errors.New("invalid residue request identity")
	}
	return nil
}

func secureExistingRoot(root string) (string, error) {
	if root == "" {
		return "", errors.New("root is empty")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("root is absent, not a directory, or a symlink")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(absolute) {
		return "", errors.New("root traverses a symlink")
	}
	return absolute, nil
}

func scopedPath(root, identifier string) (string, error) {
	target := filepath.Join(root, identifier)
	relative, err := filepath.Rel(root, target)
	if err != nil || relative != identifier || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", errors.New("target escaped residue root")
	}
	return target, nil
}

func removePodRoot(ctx context.Context, podRoot string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := os.Lstat(podRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("pod residue root is unsafe")
	}
	return os.RemoveAll(podRoot)
}

func cgroupMatches(name, podUID string) bool {
	for _, identifier := range []string{podUID, strings.ReplaceAll(podUID, "-", "_")} {
		marker := "pod" + identifier
		if name == marker || name == marker+".slice" || strings.HasSuffix(name, "-"+marker+".slice") {
			return true
		}
	}
	return false
}

func findCgroups(ctx context.Context, root, podUID string) ([]string, error) {
	matches := []string{}
	entries := 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		entries++
		if entries > MaxCgroupEntries {
			return errors.New("cgroup inspection limit exceeded")
		}
		if entry.IsDir() && path != root && cgroupMatches(entry.Name(), podUID) {
			matches = append(matches, path)
			return filepath.SkipDir
		}
		return nil
	})
	sort.Slice(matches, func(left, right int) bool { return len(matches[left]) > len(matches[right]) })
	return matches, err
}

func scrubCgroups(ctx context.Context, root, podUID string) ([]string, error) {
	roots, err := findCgroups(ctx, root, podUID)
	if err != nil {
		return nil, err
	}
	removed := []string{}
	var cleanupErrors []error
	for _, podRoot := range roots {
		directories, walkErr := cgroupDirectories(ctx, podRoot)
		if walkErr != nil {
			cleanupErrors = append(cleanupErrors, walkErr)
			continue
		}
		for _, target := range directories {
			if err := killCgroupProcesses(ctx, target); err != nil {
				cleanupErrors = append(cleanupErrors, err)
				continue
			}
			if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
				cleanupErrors = append(cleanupErrors, err)
				continue
			}
			removed = append(removed, target)
		}
	}
	return removed, errors.Join(cleanupErrors...)
}

func cgroupDirectories(ctx context.Context, root string) ([]string, error) {
	directories := []string{}
	entries := 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		entries++
		if entries > MaxCgroupEntries {
			return errors.New("cgroup cleanup limit exceeded")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("cgroup subtree contains a symlink")
		}
		if entry.IsDir() {
			directories = append(directories, path)
		}
		return nil
	})
	sort.Slice(directories, func(left, right int) bool { return len(directories[left]) > len(directories[right]) })
	return directories, err
}

func inspectCgroups(ctx context.Context, root, podUID string) ([]buildworker.Residue, error) {
	matches, err := findCgroups(ctx, root, podUID)
	residue := make([]buildworker.Residue, 0, len(matches))
	for _, target := range matches {
		residue = append(residue, buildworker.Residue{Kind: "cgroup", Target: target, Detail: "pod cgroup remains"})
	}
	return residue, err
}

func quarantineReport(report buildworker.CleanupReport, reason string, residue buildworker.Residue) buildworker.CleanupReport {
	report.Status = buildworker.CleanupQuarantined
	report.QuarantineReason = reason
	report.Residue = append(report.Residue, residue)
	return report
}
