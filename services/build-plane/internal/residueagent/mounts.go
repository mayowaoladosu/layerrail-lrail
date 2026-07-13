package residueagent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
)

type ProcMountCleaner struct {
	MountInfoPath string
}

func (cleaner ProcMountCleaner) UnmountUnder(ctx context.Context, root string) ([]string, error) {
	mounts, err := cleaner.mountsUnder(ctx, root)
	if err != nil {
		return nil, err
	}
	sort.Slice(mounts, func(left, right int) bool { return len(mounts[left]) > len(mounts[right]) })
	removed := []string{}
	var unmountErrors []error
	for _, target := range mounts {
		if err := unmountPath(target); err != nil {
			unmountErrors = append(unmountErrors, fmt.Errorf("unmount %s: %w", target, err))
			continue
		}
		removed = append(removed, target)
	}
	return removed, errors.Join(unmountErrors...)
}

func (cleaner ProcMountCleaner) InspectUnder(ctx context.Context, root string) ([]buildworker.Residue, error) {
	mounts, err := cleaner.mountsUnder(ctx, root)
	residue := make([]buildworker.Residue, 0, len(mounts))
	for _, target := range mounts {
		residue = append(residue, buildworker.Residue{Kind: "mount", Target: target, Detail: "pod mount remains"})
	}
	return residue, err
}

func (cleaner ProcMountCleaner) mountsUnder(ctx context.Context, root string) ([]string, error) {
	if cleaner.MountInfoPath == "" {
		cleaner.MountInfoPath = "/proc/self/mountinfo"
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(cleaner.MountInfoPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	result := []string{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			return nil, errors.New("mountinfo contains a malformed record")
		}
		target, err := decodeMountPath(fields[4])
		if err != nil {
			return nil, err
		}
		absoluteTarget, err := filepath.Abs(target)
		if err != nil {
			return nil, err
		}
		relative, err := filepath.Rel(absoluteRoot, absoluteTarget)
		if err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative) {
			result = append(result, absoluteTarget)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func decodeMountPath(value string) (string, error) {
	var result strings.Builder
	for index := 0; index < len(value); {
		if value[index] != '\\' {
			result.WriteByte(value[index])
			index++
			continue
		}
		if index+3 >= len(value) {
			return "", errors.New("mount path escape is truncated")
		}
		decoded, err := strconv.ParseUint(value[index+1:index+4], 8, 8)
		if err != nil {
			return "", errors.New("mount path escape is invalid")
		}
		result.WriteByte(byte(decoded))
		index += 4
	}
	return result.String(), nil
}
