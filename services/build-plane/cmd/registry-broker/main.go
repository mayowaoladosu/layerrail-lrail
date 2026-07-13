package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	lrailv1 "github.com/mayowaoladosu/layerrail-lrail/gen/go/lrail/v1"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildregistry"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildtransport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
)

const maxRegistryRPCBytes = 128 << 10

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "lrail registry capability broker stopped:", err)
		os.Exit(1)
	}
}

func run() error {
	clock := time.Now
	adminUsername, err := readCredential(os.Getenv("LRAIL_HARBOR_ADMIN_USERNAME_FILE"))
	if err != nil {
		return err
	}
	adminPassword, err := readCredentialBytes(os.Getenv("LRAIL_HARBOR_ADMIN_PASSWORD_FILE"))
	if err != nil {
		return err
	}
	defer zero(adminPassword)
	storageLimit, err := strconv.ParseInt(os.Getenv("LRAIL_HARBOR_PROJECT_STORAGE_LIMIT"), 10, 64)
	if err != nil || storageLimit < 1 {
		return errors.New("LRAIL_HARBOR_PROJECT_STORAGE_LIMIT is invalid")
	}
	harborHTTP, err := harborHTTPClient(os.Getenv("LRAIL_HARBOR_CA_FILE"))
	if err != nil {
		return err
	}
	harbor, err := buildregistry.NewHarborClient(buildregistry.HarborConfig{
		Endpoint: os.Getenv("LRAIL_HARBOR_API_ENDPOINT"), Registry: os.Getenv("LRAIL_HARBOR_REGISTRY"),
		AdminUsername: adminUsername, AdminPassword: adminPassword, HTTPClient: harborHTTP, Clock: clock, StorageLimit: storageLimit,
	})
	if err != nil {
		return err
	}
	defer harbor.Close()
	leases, err := buildregistry.NewBoltLeaseStore(os.Getenv("LRAIL_REGISTRY_LEASE_STATE_FILE"), 10_000_000)
	if err != nil {
		return err
	}
	defer leases.Close()
	broker, err := buildregistry.NewBroker(buildregistry.BrokerConfig{
		Harbor: harbor, Leases: leases, Clock: clock, MaxConcurrentIssues: 16,
	})
	if err != nil {
		return err
	}
	if _, err := broker.SweepExpired(context.Background(), 10_000); err != nil {
		return errors.New("initial expired registry capability cleanup failed")
	}
	service, err := buildregistry.NewCapabilityServer(broker)
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
		listenAddress = ":9445"
	}
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return errors.New("listen for registry capability RPC")
	}
	defer listener.Close()
	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(serverTLS)), grpc.MaxRecvMsgSize(maxRegistryRPCBytes), grpc.MaxSendMsgSize(maxRegistryRPCBytes),
	)
	lrailv1.RegisterBuildRegistryCapabilityServiceServer(server, service)
	healthServer := health.NewServer()
	healthServer.SetServingStatus("lrail.v1.BuildRegistryCapabilityService", healthv1.HealthCheckResponse_SERVING)
	healthv1.RegisterHealthServer(server, healthServer)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()
	sweepErrors := make(chan error, 1)
	go sweepExpired(ctx, broker, sweepErrors)
	select {
	case err := <-serveErrors:
		return err
	case err := <-sweepErrors:
		return err
	case <-ctx.Done():
	}
	healthServer.Shutdown()
	stopped := make(chan struct{})
	go func() { server.GracefulStop(); close(stopped) }()
	select {
	case <-stopped:
		return nil
	case <-time.After(15 * time.Second):
		server.Stop()
		return errors.New("registry capability broker forced shutdown after grace")
	}
}

func sweepExpired(ctx context.Context, broker *buildregistry.Broker, errorsSeen chan<- error) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweepContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			_, err := broker.SweepExpired(sweepContext, 10_000)
			cancel()
			if err != nil {
				errorsSeen <- errors.New("expired registry capability cleanup failed")
				return
			}
		}
	}
}

func harborHTTPClient(caPath string) (*http.Client, error) {
	contents, err := os.ReadFile(caPath)
	if err != nil || len(contents) == 0 || len(contents) > 1<<20 {
		return nil, errors.New("read Harbor CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(contents) {
		return nil, errors.New("parse Harbor CA")
	}
	return &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, ForceAttemptHTTP2: true},
	}, nil
}

func readCredential(path string) (string, error) {
	contents, err := readCredentialBytes(path)
	if err != nil {
		return "", err
	}
	defer zero(contents)
	return string(contents), nil
}

func readCredentialBytes(path string) ([]byte, error) {
	contents, err := os.ReadFile(path)
	if err != nil || len(contents) == 0 || len(contents) > 4096 {
		return nil, errors.New("registry broker credential is unavailable or oversized")
	}
	value := bytes.TrimSpace(contents)
	if len(value) == 0 || bytes.ContainsAny(value, "\r\n") {
		zero(contents)
		return nil, errors.New("registry broker credential is malformed")
	}
	result := append([]byte(nil), value...)
	zero(contents)
	return result, nil
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

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
