package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	lrailv1 "github.com/mayowaoladosu/layerrail-lrail/gen/go/lrail/v1"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildtransport"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/residueagent"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const maxRPCBytes = 1 << 20

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "lrail residue agent stopped:", err)
		os.Exit(1)
	}
}

func run() error {
	nodeName := os.Getenv("LRAIL_NODE_NAME")
	listenAddress := os.Getenv("LRAIL_LISTEN_ADDRESS")
	if listenAddress == "" {
		listenAddress = ":9444"
	}
	allowedClients := splitNonEmpty(os.Getenv("LRAIL_ALLOWED_CLIENT_URIS"))
	tlsConfig, err := buildtransport.NewReloadingServerTLSConfig(
		os.Getenv("LRAIL_TLS_CERT"), os.Getenv("LRAIL_TLS_KEY"), os.Getenv("LRAIL_TLS_CLIENT_CA"), allowedClients,
	)
	if err != nil {
		return fmt.Errorf("configure residue agent mTLS: %w", err)
	}
	cri, err := residueagent.NewCRIRuntime(os.Getenv("LRAIL_CRI_SOCKET"), residueagent.DefaultCRITimeout)
	if err != nil {
		return err
	}
	defer cri.Close()
	agent, err := residueagent.New(residueagent.Config{
		NodeName: nodeName, KubeletPodsRoot: os.Getenv("LRAIL_KUBELET_PODS_ROOT"), CgroupRoot: os.Getenv("LRAIL_CGROUP_ROOT"),
	}, cri, residueagent.ProcMountCleaner{MountInfoPath: os.Getenv("LRAIL_MOUNTINFO_PATH")})
	if err != nil {
		return err
	}
	service, err := residueagent.NewServer(agent)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("listen for residue RPC: %w", err)
	}
	defer listener.Close()
	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)), grpc.MaxRecvMsgSize(maxRPCBytes), grpc.MaxSendMsgSize(maxRPCBytes),
	)
	lrailv1.RegisterBuildResidueServiceServer(server, service)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}
	stopped := make(chan struct{})
	go func() {
		server.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
		return nil
	case <-time.After(10 * time.Second):
		server.Stop()
		return errors.New("residue agent forced shutdown after grace")
	}
}

func splitNonEmpty(value string) []string {
	result := []string{}
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}
