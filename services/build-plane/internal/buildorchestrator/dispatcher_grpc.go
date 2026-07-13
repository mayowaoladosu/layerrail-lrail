package buildorchestrator

import (
	"context"
	"errors"
	"io"
	"time"

	lrailv1 "github.com/mayowaoladosu/layerrail-lrail/gen/go/lrail/v1"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
)

const DefaultRecoveryInterval = time.Second

type GRPCCellDispatcher struct {
	client           lrailv1.BuildCellServiceClient
	recoveryInterval time.Duration
}

func NewGRPCCellDispatcher(client lrailv1.BuildCellServiceClient, recoveryInterval time.Duration) (*GRPCCellDispatcher, error) {
	if client == nil {
		return nil, errors.New("BuildCell client is absent")
	}
	if recoveryInterval == 0 {
		recoveryInterval = DefaultRecoveryInterval
	}
	if recoveryInterval < 10*time.Millisecond || recoveryInterval > 10*time.Second {
		return nil, errors.New("BuildCell recovery interval is outside bounds")
	}
	return &GRPCCellDispatcher{client: client, recoveryInterval: recoveryInterval}, nil
}

func (dispatcher *GRPCCellDispatcher) Execute(ctx context.Context, envelope buildcell.Envelope, events func(*lrailv1.BuildCellEvent) error) (*lrailv1.BuildCellResult, error) {
	if ctx == nil || events == nil {
		return nil, errors.New("BuildCell execution context or event sink is absent")
	}
	encoded, err := buildcell.EncodeEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	stream, err := dispatcher.client.ExecuteAssignment(ctx, &lrailv1.ExecuteBuildAssignmentRequest{CanonicalEnvelope: encoded})
	if err != nil {
		return dispatcher.recover(ctx, envelope.Payload.BuildID, err)
	}
	var terminal *lrailv1.BuildCellResult
	for {
		event, receiveErr := stream.Recv()
		if errors.Is(receiveErr, io.EOF) {
			if terminal == nil {
				return dispatcher.recover(ctx, envelope.Payload.BuildID, errors.New("BuildCell stream ended without a terminal result"))
			}
			return terminal, nil
		}
		if receiveErr != nil {
			if terminal != nil {
				return terminal, nil
			}
			return dispatcher.recover(ctx, envelope.Payload.BuildID, receiveErr)
		}
		if event == nil {
			return nil, errors.New("BuildCell stream emitted an absent event")
		}
		if event.GetResult() != nil {
			terminal = event.GetResult()
		}
		if err := events(event); err != nil {
			return nil, err
		}
	}
}

func (dispatcher *GRPCCellDispatcher) Cancel(ctx context.Context, buildID string, generation uint64, reason string) (bool, error) {
	response, err := dispatcher.client.CancelAssignment(ctx, &lrailv1.CancelBuildAssignmentRequest{
		BuildId: buildID, Generation: generation, Reason: reason,
	})
	if err != nil || response == nil {
		return false, errors.New("cancel BuildCell assignment")
	}
	return response.GetAccepted(), nil
}

func (dispatcher *GRPCCellDispatcher) recover(ctx context.Context, buildID string, original error) (*lrailv1.BuildCellResult, error) {
	ticker := time.NewTicker(dispatcher.recoveryInterval)
	defer ticker.Stop()
	for {
		response, err := dispatcher.client.GetAssignment(ctx, &lrailv1.GetBuildAssignmentRequest{BuildId: buildID})
		if err == nil && response != nil {
			if response.GetFound() && response.GetResult() != nil && terminalCellPhase(response.GetResult().GetPhase()) {
				return response.GetResult(), nil
			}
			if !response.GetFound() {
				return nil, errors.Join(errors.New("BuildCell lost the submitted assignment"), original)
			}
		}
		select {
		case <-ctx.Done():
			return nil, errors.Join(ctx.Err(), original)
		case <-ticker.C:
		}
	}
}

func terminalCellPhase(value string) bool {
	return value == "complete" || value == "failed" || value == "canceled" || value == "quarantined"
}

var _ CellDispatcher = (*GRPCCellDispatcher)(nil)
