package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	lrailv1 "github.com/mayowaoladosu/layerrail-lrail/gen/go/lrail/v1"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildsigning"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildsupply"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildtransport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
)

const maxSigningRPCBytes = buildsupply.MaxEvidenceBytes + 128<<10

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "lrail evidence signer stopped:", err)
		os.Exit(1)
	}
}

func run() error {
	httpClient, err := openBaoHTTPClient(os.Getenv("LRAIL_OPENBAO_CA_FILE"))
	if err != nil {
		return err
	}
	authority, err := buildsigning.NewOpenBaoAuthority(buildsigning.OpenBaoConfig{
		Address: os.Getenv("LRAIL_OPENBAO_ADDRESS"), KubernetesRole: os.Getenv("LRAIL_OPENBAO_ROLE"),
		AuthMount: os.Getenv("LRAIL_OPENBAO_AUTH_MOUNT"), TransitMount: os.Getenv("LRAIL_OPENBAO_TRANSIT_MOUNT"),
		KeyName: os.Getenv("LRAIL_OPENBAO_SIGNING_KEY"), KeyID: os.Getenv("LRAIL_SIGNER_KEY_ID"),
		JWTPath: os.Getenv("LRAIL_OPENBAO_JWT_FILE"), RequestTimeout: 20 * time.Second, MaxTokenTTL: 5 * time.Minute,
	}, httpClient)
	if err != nil {
		return err
	}
	service, err := buildsigning.NewServer(authority, 16)
	if err != nil {
		return err
	}
	serverTLS, err := buildtransport.NewReloadingServerTLSConfig(
		os.Getenv("LRAIL_SERVER_CERT"), os.Getenv("LRAIL_SERVER_KEY"), os.Getenv("LRAIL_CLIENT_CA"),
		splitCSV(os.Getenv("LRAIL_ALLOWED_CONTROLLER_URIS")),
	)
	if err != nil {
		return err
	}
	listenAddress := strings.TrimSpace(os.Getenv("LRAIL_LISTEN_ADDRESS"))
	if listenAddress == "" {
		listenAddress = ":9446"
	}
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return errors.New("listen for evidence signing RPC")
	}
	defer listener.Close()
	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(serverTLS)), grpc.MaxRecvMsgSize(maxSigningRPCBytes), grpc.MaxSendMsgSize(128<<10),
	)
	lrailv1.RegisterBuildEvidenceSigningServiceServer(server, service)
	healthServer := health.NewServer()
	healthServer.SetServingStatus("lrail.v1.BuildEvidenceSigningService", healthv1.HealthCheckResponse_SERVING)
	healthv1.RegisterHealthServer(server, healthServer)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()
	select {
	case err := <-serveErrors:
		return err
	case <-ctx.Done():
	}
	healthServer.Shutdown()
	stopped := make(chan struct{})
	go func() { server.GracefulStop(); close(stopped) }()
	select {
	case <-stopped:
		return nil
	case <-time.After(20 * time.Second):
		server.Stop()
		return errors.New("evidence signer forced shutdown after grace")
	}
}

func openBaoHTTPClient(caPath string) (*http.Client, error) {
	contents, err := os.ReadFile(caPath)
	if err != nil || len(contents) == 0 || len(contents) > 1<<20 {
		return nil, errors.New("read evidence signer OpenBao CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(contents) {
		return nil, errors.New("parse evidence signer OpenBao CA")
	}
	return &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, ForceAttemptHTTP2: true},
	}, nil
}

func splitCSV(value string) []string {
	result := []string{}
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}
