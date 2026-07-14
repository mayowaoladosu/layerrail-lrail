package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildegress"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "lrail build worker stopped:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if len(os.Args) > 1 && os.Args[1] == "--inside-rootlesskit" {
		return runInsideRootlessKit(ctx, os.Args[2:])
	}
	root := os.Getenv("LRAIL_QUOTA_ROOT")
	maxBytes, err := requiredPositiveInt64("LRAIL_SCRATCH_BYTES")
	if err != nil {
		return err
	}
	maxInodes, err := requiredPositiveInt64("LRAIL_SCRATCH_INODES")
	if err != nil {
		return err
	}
	interval := buildworker.DefaultQuotaInterval
	if value := os.Getenv("LRAIL_QUOTA_INTERVAL"); value != "" {
		interval, err = time.ParseDuration(value)
		if err != nil {
			return errors.New("LRAIL_QUOTA_INTERVAL is invalid")
		}
	}
	quota := buildworker.ScratchQuota{MaxBytes: maxBytes, MaxInodes: maxInodes, PollInterval: interval}
	readyFile := root + "/quota-monitor.ready"
	if len(os.Args) > 1 && os.Args[1] == "--quota-monitor" {
		return buildworker.RunScratchQuotaMonitor(ctx, root, readyFile, quota)
	}
	singleIDMapping, err := optionalStrictBool("LRAIL_ROOTLESSKIT_SINGLE_ID", false)
	if err != nil {
		return err
	}
	if singleIDMapping {
		if err := requireXattrSupport(root); err != nil {
			return err
		}
	}
	// Production keeps the build in a child PID namespace so it cannot observe
	// the peer quota monitor. The functional gVisor overlay explicitly disables
	// unsupported nesting; signed build commands remain non-root there.
	usePIDNamespace, err := optionalStrictBool("LRAIL_ROOTLESS_PIDNS", true)
	if err != nil {
		return err
	}
	rootlesskitArguments := []string{"--state-dir=" + root + "/build-rootlesskit"}
	if usePIDNamespace {
		rootlesskitArguments = append([]string{"--pidns"}, rootlesskitArguments...)
	}
	arguments := append(rootlesskitArguments, []string{
		"/usr/local/bin/lrail-buildkit-wrapper", "--inside-rootlesskit",
	}...)
	arguments = append(arguments, os.Args[1:]...)
	return buildworker.RunQuotaGuard(ctx, buildworker.GuardOptions{
		Root: root, Quota: quota,
		Command: "rootlesskit", Arguments: arguments, Stdout: os.Stdout, Stderr: os.Stderr,
		PrepareDirectories: []string{"buildkit", "run", "tmp"},
		MonitorCommand:     "rootlesskit", MonitorArguments: []string{
			"--state-dir=" + root + "/quota-rootlesskit",
			"/usr/local/bin/lrail-buildkit-wrapper", "--quota-monitor",
		}, MonitorReadyFile: readyFile,
	})
}

func runInsideRootlessKit(ctx context.Context, buildkitArguments []string) error {
	clientCertificate, err := readBoundedFile(os.Getenv("LRAIL_EGRESS_CLIENT_CERT"))
	if err != nil {
		return err
	}
	clientKey, err := readBoundedFile(os.Getenv("LRAIL_EGRESS_CLIENT_KEY"))
	if err != nil {
		return err
	}
	serverCA, err := readBoundedFile(os.Getenv("LRAIL_EGRESS_SERVER_CA"))
	if err != nil {
		return err
	}
	tlsConfig, err := buildegress.LoadClientTLSConfig(clientCertificate, clientKey, serverCA, os.Getenv("LRAIL_EGRESS_PROXY_SERVER_NAME"))
	if err != nil {
		return err
	}
	forwarder, err := buildegress.NewForwarder(os.Getenv("LRAIL_EGRESS_PROXY_ADDRESS"), tlsConfig)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", buildegress.LocalProxyAddress)
	if err != nil {
		return errors.New("listen for worker-local egress proxy")
	}
	defer listener.Close()
	workerContext, stopWorker := context.WithCancel(ctx)
	defer stopWorker()
	forwarderErrors := make(chan error, 1)
	go func() { forwarderErrors <- forwarder.Serve(workerContext, listener) }()
	command := exec.CommandContext(workerContext, "buildkitd", buildkitArguments...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		stopWorker()
		<-forwarderErrors
		return errors.New("start BuildKit daemon")
	}
	workerErrors := make(chan error, 1)
	go func() { workerErrors <- command.Wait() }()
	select {
	case workerErr := <-workerErrors:
		stopWorker()
		forwarderErr := <-forwarderErrors
		if workerErr == nil && ctx.Err() == nil {
			workerErr = errors.New("BuildKit daemon stopped unexpectedly")
		}
		return errors.Join(workerErr, forwarderErr)
	case forwarderErr := <-forwarderErrors:
		stopWorker()
		workerErr := <-workerErrors
		if forwarderErr == nil && ctx.Err() == nil {
			forwarderErr = errors.New("worker-local egress proxy stopped unexpectedly")
		}
		return errors.Join(forwarderErr, workerErr)
	}
}

func requiredPositiveInt64(name string) (int64, error) {
	value, err := strconv.ParseInt(os.Getenv(name), 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return value, nil
}

func optionalStrictBool(name string, fallback bool) (bool, error) {
	switch os.Getenv(name) {
	case "":
		return fallback, nil
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be true or false", name)
	}
}

func readBoundedFile(path string) ([]byte, error) {
	contents, err := os.ReadFile(path)
	if err != nil || len(contents) == 0 || len(contents) > 64<<10 {
		return nil, errors.New("worker egress credential is unavailable or oversized")
	}
	return contents, nil
}
