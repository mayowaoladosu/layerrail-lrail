package buildregistry

import (
	"context"
	"net"
	"testing"
	"time"

	lrailv1 "github.com/mayowaoladosu/layerrail-lrail/gen/go/lrail/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestCapabilityGRPCRoundTripIssuesAndRevokes(t *testing.T) {
	t.Parallel()
	fake := newFakeHarbor(t)
	broker, err := NewBroker(BrokerConfig{
		Harbor: fake.client(t), Leases: NewMemoryLeaseStore(), Clock: func() time.Time { return registryNow },
		NewID: fixedTokenID("11"), MaxConcurrentIssues: 1,
	})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	client, cleanup := registryGRPCFixture(t, broker)
	defer cleanup()
	adapter, err := NewGRPCCapabilityBroker(client, func() time.Time { return registryNow })
	if err != nil {
		t.Fatalf("NewGRPCCapabilityBroker: %v", err)
	}
	capability, err := adapter.Issue(t.Context(), validRegistryScope())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if capability.Token == "" || capability.LeaseID != "tok_019b01da-7e31-7000-8000-000000000011" || len(fake.robots) != 1 {
		t.Fatalf("capability=%#v robots=%#v", capability, fake.robots)
	}
	if err := adapter.Revoke(t.Context(), capability.LeaseID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(fake.robots) != 0 {
		t.Fatalf("robot remains: %#v", fake.robots)
	}
}

func TestCapabilityServerRejectsMalformedRequestWithoutHarborCall(t *testing.T) {
	t.Parallel()
	fake := newFakeHarbor(t)
	broker, _ := NewBroker(BrokerConfig{
		Harbor: fake.client(t), Leases: NewMemoryLeaseStore(), Clock: func() time.Time { return registryNow }, NewID: fixedTokenID("12"), MaxConcurrentIssues: 1,
	})
	client, cleanup := registryGRPCFixture(t, broker)
	defer cleanup()
	_, err := client.IssuePushCapability(t.Context(), &lrailv1.IssueRegistryPushCapabilityRequest{ExpiresAt: "not-time"})
	if status.Code(err) != codes.InvalidArgument || fake.projectCreates != 0 || fake.robotCreates != 0 {
		t.Fatalf("error=%v fake=%#v", err, fake)
	}
}

func registryGRPCFixture(t *testing.T, broker *Broker) (lrailv1.BuildRegistryCapabilityServiceClient, func()) {
	t.Helper()
	service, err := NewCapabilityServer(broker)
	if err != nil {
		t.Fatalf("NewCapabilityServer: %v", err)
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	lrailv1.RegisterBuildRegistryCapabilityServiceServer(server, service)
	go func() { _ = server.Serve(listener) }()
	connection, err := grpc.NewClient("passthrough:///registry-test", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}))
	if err != nil {
		server.Stop()
		_ = listener.Close()
		t.Fatalf("grpc.NewClient: %v", err)
	}
	return lrailv1.NewBuildRegistryCapabilityServiceClient(connection), func() {
		_ = connection.Close()
		server.Stop()
		_ = listener.Close()
	}
}
