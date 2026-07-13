package residueagent

import (
	"context"

	lrailv1 "github.com/mayowaoladosu/layerrail-lrail/gen/go/lrail/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Server struct {
	lrailv1.UnimplementedBuildResidueServiceServer
	agent *Agent
}

func NewServer(agent *Agent) (*Server, error) {
	if agent == nil {
		return nil, status.Error(codes.InvalidArgument, "residue agent is required")
	}
	return &Server{agent: agent}, nil
}

func (server *Server) CleanupResidue(ctx context.Context, request *lrailv1.CleanupBuildResidueRequest) (*lrailv1.CleanupBuildResidueResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "residue request is required")
	}
	internal := Request{BuildID: request.GetBuildId(), PodUID: request.GetPodUid(), PodName: request.GetPodName(), NodeName: request.GetNodeName()}
	if err := validateRequest(internal, server.agent.config.NodeName); err != nil {
		return nil, status.Error(codes.InvalidArgument, "residue request identity is invalid")
	}
	report := server.agent.Cleanup(ctx, internal)
	residues := make([]*lrailv1.BuildResidue, 0, len(report.Residue))
	for _, residue := range report.Residue {
		residues = append(residues, &lrailv1.BuildResidue{Kind: residue.Kind, Target: residue.Target, Detail: residue.Detail})
	}
	return &lrailv1.CleanupBuildResidueResponse{
		Cleanup:  &lrailv1.BuildCellCleanup{Status: string(report.Status), ResidueCount: uint32(len(report.Residue)), QuarantineReason: report.QuarantineReason},
		Residues: residues, RemovedPaths: append([]string(nil), report.RemovedPaths...),
	}, nil
}
