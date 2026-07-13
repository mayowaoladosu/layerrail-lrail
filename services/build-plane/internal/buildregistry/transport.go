package buildregistry

import (
	"context"
	"errors"
	"strings"
	"time"

	lrailv1 "github.com/mayowaoladosu/layerrail-lrail/gen/go/lrail/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type CapabilityServer struct {
	lrailv1.UnimplementedBuildRegistryCapabilityServiceServer
	broker *Broker
}

func NewCapabilityServer(broker *Broker) (*CapabilityServer, error) {
	if broker == nil {
		return nil, errors.New("registry capability server broker is absent")
	}
	return &CapabilityServer{broker: broker}, nil
}

func (server *CapabilityServer) IssuePushCapability(ctx context.Context, request *lrailv1.IssueRegistryPushCapabilityRequest) (*lrailv1.IssueRegistryPushCapabilityResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "Registry capability request is invalid.")
	}
	expiresAt, err := time.Parse(time.RFC3339, request.GetExpiresAt())
	if err != nil || expiresAt.Format(time.RFC3339) != request.GetExpiresAt() {
		return nil, status.Error(codes.InvalidArgument, "Registry capability request is invalid.")
	}
	capability, err := server.broker.Issue(ctx, PublicationScope{
		OrganizationID: request.GetOrganizationId(), ProjectID: request.GetProjectId(), BuildID: request.GetBuildId(),
		Attempt: request.GetAttempt(), OutputName: request.GetOutputName(), ExpiresAt: expiresAt,
	})
	if err != nil {
		if strings.Contains(err.Error(), "capacity is busy") {
			return nil, status.Error(codes.ResourceExhausted, "Registry capability capacity is busy.")
		}
		if strings.Contains(err.Error(), "scope is invalid") || strings.Contains(err.Error(), "identity is invalid") {
			return nil, status.Error(codes.InvalidArgument, "Registry capability request is invalid.")
		}
		return nil, status.Error(codes.Unavailable, "Registry capability could not be issued.")
	}
	return &lrailv1.IssueRegistryPushCapabilityResponse{
		LeaseId: capability.LeaseID, Registry: capability.Registry, Repository: capability.Repository,
		BearerToken: capability.Token, ExpiresAt: capability.ExpiresAt.UTC().Format(time.RFC3339),
	}, nil
}

func (server *CapabilityServer) RevokeCapability(ctx context.Context, request *lrailv1.RevokeRegistryCapabilityRequest) (*lrailv1.RevokeRegistryCapabilityResponse, error) {
	if request == nil || request.GetLeaseId() == "" {
		return nil, status.Error(codes.InvalidArgument, "Registry capability lease is invalid.")
	}
	if err := server.broker.Revoke(ctx, request.GetLeaseId()); err != nil {
		if strings.Contains(err.Error(), "identity is invalid") {
			return nil, status.Error(codes.InvalidArgument, "Registry capability lease is invalid.")
		}
		return nil, status.Error(codes.Unavailable, "Registry capability could not be revoked.")
	}
	return &lrailv1.RevokeRegistryCapabilityResponse{Revoked: true}, nil
}

type GRPCCapabilityBroker struct {
	client lrailv1.BuildRegistryCapabilityServiceClient
	clock  func() time.Time
}

func NewGRPCCapabilityBroker(client lrailv1.BuildRegistryCapabilityServiceClient, clock func() time.Time) (*GRPCCapabilityBroker, error) {
	if client == nil {
		return nil, errors.New("registry capability gRPC client is absent")
	}
	if clock == nil {
		clock = time.Now
	}
	return &GRPCCapabilityBroker{client: client, clock: clock}, nil
}

func (broker *GRPCCapabilityBroker) Issue(ctx context.Context, scope PublicationScope) (PushCapability, error) {
	now := broker.clock().UTC()
	if err := ValidatePublicationScope(scope, now); err != nil {
		return PushCapability{}, err
	}
	response, err := broker.client.IssuePushCapability(ctx, &lrailv1.IssueRegistryPushCapabilityRequest{
		OrganizationId: scope.OrganizationID, ProjectId: scope.ProjectID, BuildId: scope.BuildID,
		Attempt: scope.Attempt, OutputName: scope.OutputName, ExpiresAt: scope.ExpiresAt.UTC().Format(time.RFC3339),
	})
	if err != nil || response == nil {
		return PushCapability{}, fmtRegistryError("issue registry capability", err)
	}
	expiresAt, parseErr := time.Parse(time.RFC3339, response.GetExpiresAt())
	if parseErr != nil || expiresAt.Format(time.RFC3339) != response.GetExpiresAt() {
		return PushCapability{}, errors.New("registry capability response expiry is invalid")
	}
	capability := PushCapability{
		LeaseID: response.GetLeaseId(), Registry: response.GetRegistry(), Repository: response.GetRepository(),
		Token: response.GetBearerToken(), ExpiresAt: expiresAt,
	}
	if err := validatePushCapability(capability, scope, now); err != nil {
		return PushCapability{}, err
	}
	return capability, nil
}

func (broker *GRPCCapabilityBroker) Revoke(ctx context.Context, leaseID string) error {
	response, err := broker.client.RevokeCapability(ctx, &lrailv1.RevokeRegistryCapabilityRequest{LeaseId: leaseID})
	if err != nil || response == nil || !response.GetRevoked() {
		return fmtRegistryError("revoke registry capability", err)
	}
	return nil
}

func fmtRegistryError(operation string, err error) error {
	if err == nil {
		return errors.New(operation + " failed")
	}
	return errors.New(operation + " failed: " + status.Code(err).String())
}

var _ lrailv1.BuildRegistryCapabilityServiceServer = (*CapabilityServer)(nil)
var _ CapabilityBroker = (*GRPCCapabilityBroker)(nil)
