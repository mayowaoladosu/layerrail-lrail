package buildkube

import (
	"context"
	"errors"
	"testing"

	"github.com/moby/buildkit/client"
)

type infoClientStub struct {
	failures int
	calls    int
}

func (stub *infoClientStub) Info(context.Context) (*client.Info, error) {
	stub.calls++
	if stub.calls <= stub.failures {
		return nil, errors.New("not ready")
	}
	return &client.Info{}, nil
}

func TestWaitForBuildKitInfoRetriesTransientStartup(t *testing.T) {
	t.Parallel()
	stub := &infoClientStub{failures: 2}
	if err := waitForBuildKitInfo(context.Background(), stub); err != nil {
		t.Fatalf("waitForBuildKitInfo: %v", err)
	}
	if stub.calls != 3 {
		t.Fatalf("calls = %d", stub.calls)
	}
}

func TestWaitForBuildKitInfoHonorsCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForBuildKitInfo(ctx, &infoClientStub{failures: 100}); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}
