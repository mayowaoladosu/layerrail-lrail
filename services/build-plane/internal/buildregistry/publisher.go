package buildregistry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildsupply"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
)

const DefaultPublicationTimeout = 10 * time.Minute

type Publisher struct {
	broker         CapabilityBroker
	registry       *DistributionClient
	clock          func() time.Time
	maxBytes       int64
	capability     time.Duration
	cleanup        time.Duration
	staging        string
	static         StaticManifestStore
	evidence       buildsupply.Generator
	registryOrigin string
}

type PublisherConfig struct {
	Broker         CapabilityBroker
	Registry       *DistributionClient
	Clock          func() time.Time
	MaxBytes       int64
	CapabilityTTL  time.Duration
	Cleanup        time.Duration
	StagingRoot    string
	StaticStore    StaticManifestStore
	Evidence       buildsupply.Generator
	RegistryOrigin string
}

func NewPublisher(config PublisherConfig) (*Publisher, error) {
	if config.Broker == nil || config.Registry == nil || config.Evidence == nil {
		return nil, errors.New("registry publisher dependencies are incomplete")
	}
	registryOrigin, err := normalizeRegistryURL(config.RegistryOrigin)
	if err != nil {
		return nil, errors.New("registry publisher origin is invalid")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.MaxBytes == 0 {
		config.MaxBytes = buildworker.DefaultMaxCommittedArtifactBytes
	}
	if config.MaxBytes < 1 || config.MaxBytes > buildworker.DefaultMaxCommittedArtifactBytes {
		return nil, errors.New("registry publication byte limit is outside policy")
	}
	if config.CapabilityTTL == 0 {
		config.CapabilityTTL = 10 * time.Minute
	}
	if config.CapabilityTTL < time.Minute || config.CapabilityTTL > MaxCapabilityTTL {
		return nil, errors.New("registry publication capability TTL is outside policy")
	}
	if config.Cleanup == 0 {
		config.Cleanup = DefaultCleanupTimeout
	}
	if config.Cleanup < time.Second || config.Cleanup > time.Minute {
		return nil, errors.New("registry publication cleanup timeout is outside policy")
	}
	staging := ""
	if config.StagingRoot != "" {
		absolute, err := filepath.Abs(config.StagingRoot)
		if err != nil || os.MkdirAll(absolute, 0o700) != nil {
			return nil, errors.New("registry publication staging root is invalid")
		}
		resolved, err := filepath.EvalSymlinks(absolute)
		if err != nil || filepath.Clean(resolved) != filepath.Clean(absolute) {
			return nil, errors.New("registry publication staging root traverses a symlink")
		}
		staging = absolute
	}
	return &Publisher{
		broker: config.Broker, registry: config.Registry, clock: config.Clock, maxBytes: config.MaxBytes,
		capability: config.CapabilityTTL, cleanup: config.Cleanup, staging: staging, static: config.StaticStore,
		evidence: config.Evidence, registryOrigin: registryOrigin,
	}, nil
}

func (publisher *Publisher) Commit(ctx context.Context, artifact buildworker.ExportedArtifact) (committed buildworker.CommittedArtifact, resultErr error) {
	if err := buildworker.ValidateExportedArtifact(artifact, publisher.maxBytes); err != nil {
		return buildworker.CommittedArtifact{}, err
	}
	publicationPath := artifact.Path
	publicationDigest := artifact.Digest
	publicationSize := artifact.Size
	identity := buildworker.OCIArtifactIdentity{}
	staticFiles := []StaticFile(nil)
	if artifact.Kind == "oci_image" {
		var err error
		identity, err = buildworker.InspectOCIArtifact(artifact.Path)
		if err != nil {
			return buildworker.CommittedArtifact{}, fmt.Errorf("%w: inspect OCI publication: %v", ErrRegistry, err)
		}
	} else {
		if publisher.staging == "" || publisher.static == nil {
			return buildworker.CommittedArtifact{}, errors.New("static registry publication is not configured")
		}
		prepared, err := prepareStaticOCI(ctx, artifact, publisher.staging)
		if err != nil {
			return buildworker.CommittedArtifact{}, err
		}
		defer os.Remove(prepared.path)
		if err := buildworker.ValidateExportedArtifact(artifact, publisher.maxBytes); err != nil {
			return buildworker.CommittedArtifact{}, errors.New("static source changed during OCI packaging")
		}
		publicationPath = prepared.path
		publicationDigest = prepared.digest
		publicationSize = prepared.size
		identity = prepared.identity
		staticFiles = prepared.files
	}
	projectName, err := ProjectName(artifact.OrganizationID)
	if err != nil {
		return buildworker.CommittedArtifact{}, err
	}
	repository, err := RepositoryName(artifact.ProjectID, artifact.OutputName)
	if err != nil {
		return buildworker.CommittedArtifact{}, err
	}
	fullName, err := fullRepository(projectName, repository)
	if err != nil {
		return buildworker.CommittedArtifact{}, err
	}
	repositoryReference := strings.TrimPrefix(publisher.registryOrigin, "https://") + "/" + fullName
	evidenceRequest := buildsupply.GenerateRequest{
		Artifact: artifact, OCIPath: publicationPath, OCIArchiveDigest: publicationDigest, OCIArchiveSize: publicationSize,
		Identity: identity, RepositoryReference: repositoryReference,
	}
	bundle, err := publisher.evidence.Generate(ctx, evidenceRequest)
	if err != nil {
		return buildworker.CommittedArtifact{}, err
	}
	if err := buildsupply.ValidateBundle(evidenceRequest, bundle); err != nil {
		return buildworker.CommittedArtifact{}, fmt.Errorf("%w: generated evidence bundle is invalid", ErrRegistry)
	}
	if err := buildworker.ValidateExportedArtifact(artifact, publisher.maxBytes); err != nil {
		return buildworker.CommittedArtifact{}, errors.New("build output changed during evidence generation")
	}
	now := publisher.clock().UTC()
	scope := PublicationScope{
		OrganizationID: artifact.OrganizationID, ProjectID: artifact.ProjectID, BuildID: artifact.BuildID,
		Attempt: artifact.Attempt, OutputName: artifact.OutputName, ExpiresAt: now.Add(publisher.capability).Truncate(time.Second),
	}
	capability, err := publisher.broker.Issue(ctx, scope)
	if err != nil {
		return buildworker.CommittedArtifact{}, err
	}
	if err := validatePushCapability(capability, scope, now); err != nil {
		cleanupContext, cancel := context.WithTimeout(context.Background(), publisher.cleanup)
		defer cancel()
		revokeErr := publisher.broker.Revoke(cleanupContext, capability.LeaseID)
		capability.Token = ""
		return buildworker.CommittedArtifact{}, errors.Join(err, revokeErr)
	}
	defer func() {
		capability.Token = ""
		cleanupContext, cancel := context.WithTimeout(context.Background(), publisher.cleanup)
		defer cancel()
		if err := publisher.broker.Revoke(cleanupContext, capability.LeaseID); err != nil {
			committed = buildworker.CommittedArtifact{}
			resultErr = errors.Join(resultErr, fmt.Errorf("%w: revoke publication capability: %v", ErrRegistry, err))
		}
	}()
	if capability.Registry != publisher.registryOrigin || capability.Repository != repository {
		return buildworker.CommittedArtifact{}, errors.New("registry publication capability origin differs from configuration")
	}
	exists, err := publisher.registry.ManifestExists(ctx, capability, projectName, identity)
	if err != nil {
		return buildworker.CommittedArtifact{}, err
	}
	if err := buildworker.VisitOCIArtifactBlobs(ctx, publicationPath, identity, func(descriptor buildworker.OCIArtifactDescriptor, reader io.Reader) error {
		return publisher.registry.EnsureBlob(ctx, capability, projectName, descriptor, reader)
	}); err != nil {
		return buildworker.CommittedArtifact{}, fmt.Errorf("%w: publish OCI blobs: %v", ErrRegistry, err)
	}
	if !exists {
		if err := publisher.registry.PutManifest(ctx, capability, projectName, identity); err != nil {
			return buildworker.CommittedArtifact{}, err
		}
	}
	if err := buildworker.ValidateExportedArtifact(artifact, publisher.maxBytes); err != nil {
		return buildworker.CommittedArtifact{}, errors.New("build output changed during registry publication")
	}
	reference := repositoryReference + "@" + identity.ManifestDigest
	evidenceReferences, err := publisher.publishEvidence(ctx, capability, projectName, repositoryReference, identity, bundle)
	if err != nil {
		return buildworker.CommittedArtifact{}, err
	}
	publicationManifestRef := ""
	if artifact.Kind == "static_bundle" {
		publicationManifestRef, err = publisher.static.PutImmutable(ctx, StaticPublicationManifest{
			Version: StaticManifestVersion, OrganizationID: artifact.OrganizationID, ProjectID: artifact.ProjectID, BuildID: artifact.BuildID,
			OutputName: artifact.OutputName, SourceDigest: artifact.Digest, SourceSize: artifact.Size,
			OCIReference: reference, ManifestDigest: identity.ManifestDigest, Files: staticFiles,
		})
		if err != nil || publicationManifestRef == "" {
			return buildworker.CommittedArtifact{}, fmt.Errorf("%w: commit static publication manifest", ErrRegistry)
		}
	}
	return buildworker.CommittedArtifact{
		Reference: reference, Digest: artifact.Digest, Size: artifact.Size, ManifestDigest: identity.ManifestDigest,
		PublicationManifestRef: publicationManifestRef,
		SupplyChain: buildworker.SupplyChainResult{
			PolicyState: bundle.PolicyState, ScanState: bundle.ScanState, PolicyDigest: bundle.PolicyDigest,
			SignerKeyID: bundle.SignerKeyID, SignerKeyVersion: bundle.SignerKeyVersion,
			SignerPublicKeyDigest: bundle.SignerPublicKeyDigest, Evidence: evidenceReferences,
		},
	}, nil
}

var _ buildworker.ArtifactCommitter = (*Publisher)(nil)
