package buildworker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const DefaultGuardTerminationGrace = 10 * time.Second

type GuardOptions struct {
	Root               string
	Quota              ScratchQuota
	Command            string
	Arguments          []string
	Stdout             io.Writer
	Stderr             io.Writer
	TerminationGrace   time.Duration
	PrepareDirectories []string
}

func RunQuotaGuard(ctx context.Context, options GuardOptions) error {
	quota, err := normalizeScratchQuota(options.Quota)
	if err != nil || options.Root == "" || options.Command == "" || options.Stdout == nil || options.Stderr == nil {
		return errors.New("quota guard configuration is invalid")
	}
	if options.TerminationGrace == 0 {
		options.TerminationGrace = DefaultGuardTerminationGrace
	}
	if options.TerminationGrace < time.Millisecond || options.TerminationGrace > time.Minute {
		return errors.New("quota guard termination grace is outside bounds")
	}
	if err := emptyGuardRoot(options.Root); err != nil {
		return fmt.Errorf("prepare guarded root: %w", err)
	}
	if err := prepareGuardDirectories(options.Root, options.PrepareDirectories); err != nil {
		return fmt.Errorf("prepare guarded directories: %w", err)
	}
	command := exec.Command(options.Command, options.Arguments...)
	command.Stdout = options.Stdout
	command.Stderr = options.Stderr
	if err := command.Start(); err != nil {
		return fmt.Errorf("start guarded process: %w", err)
	}
	processDone := make(chan error, 1)
	go func() { processDone <- command.Wait() }()
	guardContext, stopGuard, _ := monitorScratch(ctx, options.Root, quota)
	defer stopGuard(nil)
	select {
	case processErr := <-processDone:
		return processErr
	case <-guardContext.Done():
		cause := context.Cause(guardContext)
		_ = terminateProcess(command.Process)
		timer := time.NewTimer(options.TerminationGrace)
		defer timer.Stop()
		select {
		case <-processDone:
		case <-timer.C:
			_ = command.Process.Kill()
			<-processDone
		}
		if cause == nil {
			cause = context.Canceled
		}
		return cause
	}
}

func prepareGuardDirectories(root string, directories []string) error {
	for _, directory := range directories {
		cleaned := filepath.Clean(directory)
		if cleaned == "." || cleaned == ".." || filepath.IsAbs(cleaned) || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
			return errors.New("guarded directory escaped its root")
		}
		target := filepath.Join(root, cleaned)
		if !inside(root, target) {
			return errors.New("guarded directory escaped its root")
		}
		if err := os.MkdirAll(target, 0o700); err != nil {
			return err
		}
	}
	return nil
}
func emptyGuardRoot(root string) error {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("guarded root is not a real directory")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}
