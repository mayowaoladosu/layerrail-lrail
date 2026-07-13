// Package buildsigning owns the non-exportable key seam used by WP-040 evidence.
package buildsigning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"time"

	lrailv1 "github.com/mayowaoladosu/layerrail-lrail/gen/go/lrail/v1"
	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildsupply"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const DefaultSignTimeout = 30 * time.Second
const MaxSigningAttempt = 5

var outputNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Material struct {
	KeyID        string
	KeyVersion   int
	Algorithm    string
	PublicKeyPEM []byte
	Signature    []byte
}

type Authority interface {
	Sign(ctx context.Context, payload []byte) (Material, error)
}

type Server struct {
	lrailv1.UnimplementedBuildEvidenceSigningServiceServer
	authority Authority
	capacity  chan struct{}
}

func NewServer(authority Authority, maxConcurrent int) (*Server, error) {
	if authority == nil || maxConcurrent < 1 || maxConcurrent > 64 {
		return nil, errors.New("build signing server configuration is incomplete")
	}
	return &Server{authority: authority, capacity: make(chan struct{}, maxConcurrent)}, nil
}

func (server *Server) SignEvidence(ctx context.Context, request *lrailv1.SignBuildEvidenceRequest) (*lrailv1.SignBuildEvidenceResponse, error) {
	if request == nil || validateSigningRequest(request.GetOrganizationId(), request.GetProjectId(), request.GetBuildId(), request.GetAttempt(), request.GetOutputName(), request.GetKind(), request.GetSubjectDigest(), request.GetPayload(), request.GetPayloadDigest()) != nil {
		return nil, status.Error(codes.InvalidArgument, "signing request is invalid")
	}
	select {
	case server.capacity <- struct{}{}:
		defer func() { <-server.capacity }()
	default:
		return nil, status.Error(codes.ResourceExhausted, "signing capacity is busy")
	}
	material, err := server.authority.Sign(ctx, request.GetPayload())
	if err != nil {
		return nil, status.Error(codes.Unavailable, "signing authority is unavailable")
	}
	if material.KeyID == "" || material.KeyVersion < 1 || material.Algorithm != buildsupply.SignatureAlgorithm ||
		len(material.PublicKeyPEM) == 0 || len(material.PublicKeyPEM) > 16<<10 || len(material.Signature) == 0 {
		return nil, status.Error(codes.Internal, "signing authority returned invalid identity")
	}
	if _, err := buildsupply.VerifySignature(material.PublicKeyPEM, request.GetPayload(), material.Signature); err != nil {
		return nil, status.Error(codes.Internal, "signing authority returned unverifiable material")
	}
	return &lrailv1.SignBuildEvidenceResponse{
		KeyId: material.KeyID, KeyVersion: uint32(material.KeyVersion), Algorithm: material.Algorithm,
		PublicKeyPem: append([]byte(nil), material.PublicKeyPEM...), Signature: append([]byte(nil), material.Signature...),
	}, nil
}

type GRPCSigner struct {
	client  lrailv1.BuildEvidenceSigningServiceClient
	timeout time.Duration
}

func NewGRPCSigner(client lrailv1.BuildEvidenceSigningServiceClient, timeout time.Duration) (*GRPCSigner, error) {
	if client == nil {
		return nil, errors.New("build signing client is absent")
	}
	if timeout == 0 {
		timeout = DefaultSignTimeout
	}
	if timeout < time.Second || timeout > time.Minute {
		return nil, errors.New("build signing client timeout is outside bounds")
	}
	return &GRPCSigner{client: client, timeout: timeout}, nil
}

func (signer *GRPCSigner) Sign(ctx context.Context, request buildsupply.SigningRequest) (buildsupply.Signature, error) {
	payloadDigest := bytesDigest(request.Payload)
	if err := validateSigningRequest(request.OrganizationID, request.ProjectID, request.BuildID, request.Attempt, request.OutputName, request.Kind, request.SubjectDigest, request.Payload, payloadDigest); err != nil {
		return buildsupply.Signature{}, err
	}
	requestContext, cancel := context.WithTimeout(ctx, signer.timeout)
	defer cancel()
	response, err := signer.client.SignEvidence(requestContext, &lrailv1.SignBuildEvidenceRequest{
		OrganizationId: request.OrganizationID, ProjectId: request.ProjectID, BuildId: request.BuildID,
		Attempt: request.Attempt, OutputName: request.OutputName, Kind: request.Kind, SubjectDigest: request.SubjectDigest,
		Payload: append([]byte(nil), request.Payload...), PayloadDigest: payloadDigest,
	})
	if err != nil || response == nil || response.GetKeyVersion() == 0 {
		return buildsupply.Signature{}, errors.New("build signing RPC failed")
	}
	return buildsupply.Signature{
		KeyID: response.GetKeyId(), KeyVersion: int(response.GetKeyVersion()), Algorithm: response.GetAlgorithm(),
		PublicKeyPEM: append([]byte(nil), response.GetPublicKeyPem()...), Value: append([]byte(nil), response.GetSignature()...),
	}, nil
}

func validateSigningRequest(organizationID, projectID, buildID string, attempt uint32, outputName, kind, subjectDigest string, payload []byte, payloadDigest string) error {
	organization, organizationErr := platformid.Parse(organizationID)
	project, projectErr := platformid.Parse(projectID)
	build, buildErr := platformid.Parse(buildID)
	if organizationErr != nil || organization.Prefix() != "org" || projectErr != nil || project.Prefix() != "prj" ||
		buildErr != nil || build.Prefix() != "bld" || attempt == 0 || attempt > MaxSigningAttempt ||
		!outputNamePattern.MatchString(outputName) || !digestPattern.MatchString(subjectDigest) ||
		len(payload) == 0 || len(payload) > buildsupply.MaxEvidenceBytes || payloadDigest != bytesDigest(payload) {
		return errors.New("build signing request identity is invalid")
	}
	return buildsupply.ValidateSigningPayload(kind, subjectDigest, payload)
}

func bytesDigest(contents []byte) string {
	digest := sha256.Sum256(contents)
	return "sha256:" + hex.EncodeToString(digest[:])
}

var _ buildsupply.Signer = (*GRPCSigner)(nil)
