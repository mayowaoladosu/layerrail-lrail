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
const DefaultGuardMonitorReadyTimeout = 30 * time.Second

const guardReadyContents = "lrail-quota-monitor-ready\n"

type GuardOptions struct {
	Root               string
	Quota              ScratchQuota
	Command            string
	Arguments          []string
	Stdout             io.Writer
	Stderr             io.Writer
	TerminationGrace   time.Duration
	PrepareDirectories []string
	MonitorCommand     string
	MonitorArguments   []string
	MonitorReadyFile   string
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
	if options.MonitorCommand != "" {
		return runExternallyMonitoredGuard(ctx, options)
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

func runExternallyMonitoredGuard(ctx context.Context, options GuardOptions) error {
	if options.MonitorReadyFile == "" || !inside(options.Root, options.MonitorReadyFile) {
		return errors.New("external quota monitor ready path escaped its root")
	}
	monitor := exec.Command(options.MonitorCommand, options.MonitorArguments...)
	monitor.Stdout = options.Stdout
	monitor.Stderr = options.Stderr
	if err := monitor.Start(); err != nil {
		return fmt.Errorf("start quota monitor: %w", err)
	}
	monitorDone := make(chan error, 1)
	go func() { monitorDone <- monitor.Wait() }()
	monitorExited, err := waitForGuardMonitor(ctx, options.MonitorReadyFile, monitorDone)
	if err != nil {
		if !monitorExited {
			_ = stopGuardProcess(monitor, monitorDone, options.TerminationGrace)
		}
		return err
	}
	if err := os.Remove(options.MonitorReadyFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = stopGuardProcess(monitor, monitorDone, options.TerminationGrace)
		return errors.New("remove quota monitor readiness proof")
	}

	command := exec.Command(options.Command, options.Arguments...)
	command.Stdout = options.Stdout
	command.Stderr = options.Stderr
	if err := command.Start(); err != nil {
		_ = stopGuardProcess(monitor, monitorDone, options.TerminationGrace)
		return fmt.Errorf("start guarded process: %w", err)
	}
	processDone := make(chan error, 1)
	go func() { processDone <- command.Wait() }()
	select {
	case processErr := <-processDone:
		_ = stopGuardProcess(monitor, monitorDone, options.TerminationGrace)
		return processErr
	case monitorErr := <-monitorDone:
		_ = stopGuardProcess(command, processDone, options.TerminationGrace)
		if monitorErr == nil {
			monitorErr = errors.New("quota monitor stopped unexpectedly")
		}
		return monitorErr
	case <-ctx.Done():
		_ = stopGuardProcess(command, processDone, options.TerminationGrace)
		_ = stopGuardProcess(monitor, monitorDone, options.TerminationGrace)
		return context.Cause(ctx)
	}
}

func waitForGuardMonitor(ctx context.Context, readyFile string, monitorDone <-chan error) (bool, error) {
	readyContext, cancel := context.WithTimeout(ctx, DefaultGuardMonitorReadyTimeout)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		contents, err := os.ReadFile(readyFile)
		if err == nil {
			info, statErr := os.Lstat(readyFile)
			if statErr != nil || !info.Mode().IsRegular() || string(contents) != guardReadyContents {
				return false, errors.New("quota monitor readiness proof is invalid")
			}
			return false, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return false, errors.New("inspect quota monitor readiness proof")
		}
		select {
		case monitorErr := <-monitorDone:
			if monitorErr == nil {
				monitorErr = errors.New("quota monitor stopped before readiness")
			}
			return true, monitorErr
		case <-readyContext.Done():
			return false, errors.New("quota monitor did not become ready within its safety bound")
		case <-ticker.C:
		}
	}
}

func stopGuardProcess(command *exec.Cmd, done <-chan error, grace time.Duration) error {
	_ = terminateProcess(command.Process)
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		_ = command.Process.Kill()
		return <-done
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
