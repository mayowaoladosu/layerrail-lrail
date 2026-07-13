//go:build linux

package residueagent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func killCgroupProcesses(ctx context.Context, target string) error {
	killPath := filepath.Join(target, "cgroup.kill")
	if _, err := os.Stat(killPath); err == nil {
		if err := os.WriteFile(killPath, []byte("1"), 0o200); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else {
		contents, readErr := os.ReadFile(filepath.Join(target, "cgroup.procs"))
		if errors.Is(readErr, os.ErrNotExist) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
		for _, field := range strings.Fields(string(contents)) {
			pid, parseErr := strconv.Atoi(field)
			if parseErr != nil || pid <= 1 {
				return errors.New("cgroup contains an invalid process identity")
			}
			if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
				return err
			}
		}
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()
	for {
		contents, err := os.ReadFile(filepath.Join(target, "cgroup.procs"))
		if errors.Is(err, os.ErrNotExist) || (err == nil && len(strings.TrimSpace(string(contents))) == 0) {
			return nil
		}
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout.C:
			return errors.New("cgroup processes did not exit")
		case <-ticker.C:
		}
	}
}
