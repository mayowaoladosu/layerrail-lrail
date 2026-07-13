package buildkube

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	"github.com/moby/buildkit/client"
)

type WorkerConnector interface {
	Connect(ctx context.Context, endpoint string, tlsConfig *tls.Config) (buildworker.Executor, io.Closer, error)
}

type BuildKitConnector struct {
	Sources      buildworker.SourceStore
	Cleaner      buildworker.Cleaner
	Committer    buildworker.ArtifactCommitter
	Caches       buildworker.CacheProvider
	ScratchRoot  string
	SolveTimeout time.Duration
}

func (connector BuildKitConnector) Connect(ctx context.Context, endpoint string, tlsConfig *tls.Config) (buildworker.Executor, io.Closer, error) {
	if connector.Sources == nil || connector.Cleaner == nil || connector.Committer == nil || connector.Caches == nil || connector.ScratchRoot == "" || endpoint == "" || tlsConfig == nil || tlsConfig.ServerName == "" {
		return nil, nil, errors.New("BuildKit connector is incomplete")
	}
	configuredTLS := tlsConfig.Clone()
	configuredTLS.MinVersion = tls.VersionTLS13
	dialer := new(net.Dialer)
	buildkitClient, err := client.New(ctx, "tcp://"+endpoint, client.WithContextDialer(func(dialContext context.Context, _ string) (net.Conn, error) {
		connection, err := dialer.DialContext(dialContext, "tcp", endpoint)
		if err != nil {
			return nil, err
		}
		secured := tls.Client(connection, configuredTLS)
		if err := secured.HandshakeContext(dialContext); err != nil {
			_ = connection.Close()
			return nil, err
		}
		return secured, nil
	}))
	if err != nil {
		return nil, nil, fmt.Errorf("create BuildKit client: %w", err)
	}
	if _, err := buildkitClient.Info(ctx); err != nil {
		_ = buildkitClient.Close()
		return nil, nil, fmt.Errorf("verify BuildKit worker: %w", err)
	}
	executor, err := buildworker.NewBuildKitExecutor(buildkitClient, connector.Sources, connector.Cleaner, connector.Committer, connector.Caches, connector.ScratchRoot, connector.SolveTimeout)
	if err != nil {
		_ = buildkitClient.Close()
		return nil, nil, err
	}
	return executor, buildkitClient, nil
}
