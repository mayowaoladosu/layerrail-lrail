// Package buildtransport exposes the internal mTLS-only build-cell gRPC boundary.
package buildtransport

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	lrailv1 "github.com/mayowaoladosu/layerrail-lrail/gen/go/lrail/v1"
	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcontrol"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const MaxCancelReasonBytes = 512

type activeRun struct {
	generation uint64
	cancel     chan struct{}
	once       sync.Once
}

func (run *activeRun) requestCancel() {
	run.once.Do(func() { close(run.cancel) })
}

type Server struct {
	lrailv1.UnimplementedBuildCellServiceServer
	controller assignmentRunner
	verifier   *buildcell.Verifier
	runs       buildcontrol.RunStore
	mu         sync.Mutex
	active     map[string]*activeRun
}

type assignmentRunner interface {
	Run(ctx context.Context, request buildcontrol.RunRequest) (buildcontrol.Result, error)
}

func NewServer(controller assignmentRunner, verifier *buildcell.Verifier, runs buildcontrol.RunStore) (*Server, error) {
	if controller == nil || verifier == nil || runs == nil {
		return nil, errors.New("build transport dependencies are incomplete")
	}
	return &Server{controller: controller, verifier: verifier, runs: runs, active: make(map[string]*activeRun)}, nil
}

func (server *Server) ExecuteAssignment(request *lrailv1.ExecuteBuildAssignmentRequest, stream lrailv1.BuildCellService_ExecuteAssignmentServer) error {
	if request == nil || stream == nil {
		return status.Error(codes.InvalidArgument, "assignment request is required")
	}
	envelope, err := buildcell.DecodeEnvelope(request.GetCanonicalEnvelope())
	if err != nil {
		return status.Error(codes.InvalidArgument, "assignment envelope is invalid")
	}
	verified, err := server.verifier.Verify(envelope)
	if err != nil {
		return status.Error(codes.PermissionDenied, "assignment is not authorized for this cell")
	}
	active := &activeRun{generation: verified.Payload.Generation, cancel: make(chan struct{})}
	server.mu.Lock()
	if _, exists := server.active[verified.Payload.BuildID]; exists {
		server.mu.Unlock()
		return status.Error(codes.AlreadyExists, "assignment is already active")
	}
	server.active[verified.Payload.BuildID] = active
	server.mu.Unlock()
	defer func() {
		server.mu.Lock()
		delete(server.active, verified.Payload.BuildID)
		server.mu.Unlock()
	}()

	var sendMu sync.Mutex
	var sendErr error
	var lastSequence uint64
	sink := func(event buildworker.Event) {
		sendMu.Lock()
		defer sendMu.Unlock()
		if sendErr != nil {
			return
		}
		lastSequence = event.Sequence
		if err := stream.Send(eventMessage(event)); err != nil {
			sendErr = err
			active.requestCancel()
		}
	}
	result, runErr := server.controller.Run(stream.Context(), buildcontrol.RunRequest{
		Envelope: envelope, Cancellation: active.cancel, Events: sink,
	})
	if runErr != nil {
		if errors.Is(runErr, buildcontrol.ErrInProgress) {
			return status.Error(codes.AlreadyExists, "assignment is already in progress")
		}
		if errors.Is(runErr, context.Canceled) || errors.Is(stream.Context().Err(), context.Canceled) {
			return status.Error(codes.Canceled, "assignment stream canceled")
		}
		return status.Error(codes.Internal, "assignment controller failed")
	}
	sendMu.Lock()
	defer sendMu.Unlock()
	if sendErr != nil {
		return sendErr
	}
	return stream.Send(&lrailv1.BuildCellEvent{
		Sequence: lastSequence + 1, Attempt: result.Attempts, Phase: string(result.Phase), Kind: "result",
		OccurredAt: result.FinishedAt.UTC().Format(time.RFC3339Nano), Result: resultMessage(result),
	})
}

func (server *Server) CancelAssignment(ctx context.Context, request *lrailv1.CancelBuildAssignmentRequest) (*lrailv1.CancelBuildAssignmentResponse, error) {
	reason := strings.TrimSpace(request.GetReason())
	if request == nil || request.GetGeneration() == 0 || reason == "" || len(reason) > MaxCancelReasonBytes || !utf8.ValidString(reason) || strings.ContainsRune(reason, '\x00') || !validBuildID(request.GetBuildId()) {
		return nil, status.Error(codes.InvalidArgument, "cancellation identity is invalid")
	}
	persisted, err := server.runs.RequestCancel(ctx, request.GetBuildId(), request.GetGeneration(), time.Now().UTC())
	if err != nil {
		return nil, status.Error(codes.Internal, "cancellation state is unavailable")
	}
	server.mu.Lock()
	active, exists := server.active[request.GetBuildId()]
	server.mu.Unlock()
	activeMatch := exists && active.generation == request.GetGeneration()
	if activeMatch {
		active.requestCancel()
	}
	return &lrailv1.CancelBuildAssignmentResponse{Accepted: persisted || activeMatch}, nil
}

func (server *Server) GetAssignment(ctx context.Context, request *lrailv1.GetBuildAssignmentRequest) (*lrailv1.GetBuildAssignmentResponse, error) {
	if request == nil || !validBuildID(request.GetBuildId()) {
		return nil, status.Error(codes.InvalidArgument, "build identity is invalid")
	}
	record, found, err := server.runs.Lookup(ctx, request.GetBuildId())
	if err != nil {
		return nil, status.Error(codes.Internal, "assignment state is unavailable")
	}
	server.mu.Lock()
	_, active := server.active[request.GetBuildId()]
	server.mu.Unlock()
	response := &lrailv1.GetBuildAssignmentResponse{Found: found, Active: active}
	if found && record.Result.Terminal() {
		response.Result = resultMessage(record.Result)
	}
	return response, nil
}

func eventMessage(event buildworker.Event) *lrailv1.BuildCellEvent {
	stream := uint32(0)
	if event.Stream > 0 {
		stream = uint32(event.Stream)
	}
	return &lrailv1.BuildCellEvent{
		Sequence: event.Sequence, Attempt: event.Attempt, Phase: string(event.Phase), Kind: event.Kind,
		Output: event.Output, Vertex: event.Vertex, Name: event.Name, Current: event.Current, Total: event.Total,
		Cached: event.Cached, Stream: stream, Line: event.Line, Code: event.Code, Message: event.Message,
		OccurredAt: event.OccurredAt.UTC().Format(time.RFC3339Nano),
	}
}

func resultMessage(result buildcontrol.Result) *lrailv1.BuildCellResult {
	outputs := make([]*lrailv1.BuildCellOutput, 0, len(result.Worker.Outputs))
	for _, output := range result.Worker.Outputs {
		outputs = append(outputs, &lrailv1.BuildCellOutput{
			Name: output.Name, Kind: output.Kind, ArtifactRef: output.ArtifactRef,
			ArtifactDigest: output.ArtifactDigest, ArtifactSize: output.ArtifactSize, ConfigDigest: output.ConfigDigest,
			ManifestDigest: output.ManifestDigest, LayerDigests: append([]string(nil), output.LayerDigests...),
			PublicationManifestRef: output.PublicationManifestRef,
		})
	}
	return &lrailv1.BuildCellResult{
		BuildId: result.BuildID, PayloadDigest: result.PayloadDigest, Phase: string(result.Phase), Attempts: result.Attempts,
		WorkerIdentity: result.WorkerIdentity, Outputs: outputs, ErrorCode: result.ErrorCode,
		StartedAt: result.StartedAt.UTC().Format(time.RFC3339Nano), FinishedAt: result.FinishedAt.UTC().Format(time.RFC3339Nano), Replay: result.Replay,
		LogsDigest: result.LogsDigest, CacheHits: result.Worker.Cache.Hits, CacheMisses: result.Worker.Cache.Misses,
		Cleanup: &lrailv1.BuildCellCleanup{
			Status: string(result.Cleanup.Status), ResidueCount: uint32(len(result.Cleanup.Residue)), QuarantineReason: result.Cleanup.QuarantineReason,
		},
	}
}

func validBuildID(value string) bool {
	parsed, err := platformid.Parse(value)
	return err == nil && parsed.Prefix() == "bld"
}
