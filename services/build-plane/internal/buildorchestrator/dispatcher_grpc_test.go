package buildorchestrator

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	lrailv1 "github.com/mayowaoladosu/layerrail-lrail/gen/go/lrail/v1"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type dispatcherServer struct {
	lrailv1.UnimplementedBuildCellServiceServer
	terminal       *lrailv1.BuildCellResult
	breakStream    bool
	canceledBuild  string
	canceledGen    uint64
	canceledReason string
}

func (server *dispatcherServer) ExecuteAssignment(request *lrailv1.ExecuteBuildAssignmentRequest, stream grpc.ServerStreamingServer[lrailv1.BuildCellEvent]) error {
	envelope, err := buildcell.DecodeEnvelope(request.GetCanonicalEnvelope())
	if err != nil || envelope.Payload.BuildID != server.terminal.GetBuildId() {
		return status.Error(codes.InvalidArgument, "bad envelope")
	}
	if server.breakStream {
		return status.Error(codes.Unavailable, "injected stream loss")
	}
	if err := stream.Send(&lrailv1.BuildCellEvent{Sequence: 1, Attempt: 1, Phase: "solving", Kind: "progress", OccurredAt: time.Now().UTC().Format(time.RFC3339Nano)}); err != nil {
		return err
	}
	return stream.Send(&lrailv1.BuildCellEvent{Sequence: 2, Attempt: 1, Phase: "complete", Kind: "terminal", OccurredAt: time.Now().UTC().Format(time.RFC3339Nano), Result: server.terminal})
}

func (server *dispatcherServer) GetAssignment(_ context.Context, request *lrailv1.GetBuildAssignmentRequest) (*lrailv1.GetBuildAssignmentResponse, error) {
	if request.GetBuildId() != server.terminal.GetBuildId() {
		return &lrailv1.GetBuildAssignmentResponse{Found: false}, nil
	}
	return &lrailv1.GetBuildAssignmentResponse{Found: true, Active: false, Result: server.terminal}, nil
}

func (server *dispatcherServer) CancelAssignment(_ context.Context, request *lrailv1.CancelBuildAssignmentRequest) (*lrailv1.CancelBuildAssignmentResponse, error) {
	server.canceledBuild = request.GetBuildId()
	server.canceledGen = request.GetGeneration()
	server.canceledReason = request.GetReason()
	return &lrailv1.CancelBuildAssignmentResponse{Accepted: true}, nil
}

func TestGRPCCellDispatcherStreamsRecoversAndCancelsExactGeneration(t *testing.T) {
	t.Parallel()
	terminal := &lrailv1.BuildCellResult{BuildId: testBuildID, Phase: "complete", Attempts: 1}
	server := &dispatcherServer{terminal: terminal}
	client, closeServer := dispatcherClient(t, server)
	defer closeServer()
	dispatcher, err := NewGRPCCellDispatcher(client, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("NewGRPCCellDispatcher: %v", err)
	}
	envelope := buildcell.Envelope{KeyID: "test", Payload: buildcell.Payload{BuildID: testBuildID}, Signature: "test"}
	events := 0
	result, err := dispatcher.Execute(context.Background(), envelope, func(*lrailv1.BuildCellEvent) error { events++; return nil })
	if err != nil || result.GetBuildId() != testBuildID || events != 2 {
		t.Fatalf("Execute: result=%#v events=%d err=%v", result, events, err)
	}
	server.breakStream = true
	events = 0
	result, err = dispatcher.Execute(context.Background(), envelope, func(*lrailv1.BuildCellEvent) error { events++; return nil })
	if err != nil || result.GetBuildId() != testBuildID || events != 0 {
		t.Fatalf("recovered Execute: result=%#v events=%d err=%v", result, events, err)
	}
	accepted, err := dispatcher.Cancel(context.Background(), testBuildID, 7, "user requested cancellation")
	if err != nil || !accepted || server.canceledBuild != testBuildID || server.canceledGen != 7 || server.canceledReason != "user requested cancellation" {
		t.Fatalf("Cancel: accepted=%v server=%#v err=%v", accepted, server, err)
	}
}

func TestGRPCCellDispatcherStopsWhenEventPersistenceFails(t *testing.T) {
	t.Parallel()
	server := &dispatcherServer{terminal: &lrailv1.BuildCellResult{BuildId: testBuildID, Phase: "complete", Attempts: 1}}
	client, closeServer := dispatcherClient(t, server)
	defer closeServer()
	dispatcher, _ := NewGRPCCellDispatcher(client, 10*time.Millisecond)
	expected := errors.New("durable event store unavailable")
	_, err := dispatcher.Execute(context.Background(), buildcell.Envelope{Payload: buildcell.Payload{BuildID: testBuildID}}, func(*lrailv1.BuildCellEvent) error { return expected })
	if !errors.Is(err, expected) {
		t.Fatalf("Execute error = %v", err)
	}
}

func dispatcherClient(t *testing.T, implementation lrailv1.BuildCellServiceServer) (lrailv1.BuildCellServiceClient, func()) {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	lrailv1.RegisterBuildCellServiceServer(server, implementation)
	go func() { _ = server.Serve(listener) }()
	connection, err := grpc.NewClient("passthrough:///bufnet", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}))
	if err != nil {
		server.Stop()
		t.Fatalf("grpc.NewClient: %v", err)
	}
	return lrailv1.NewBuildCellServiceClient(connection), func() {
		_ = connection.Close()
		server.Stop()
		_ = listener.Close()
	}
}
