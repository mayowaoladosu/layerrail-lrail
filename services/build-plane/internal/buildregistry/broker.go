package buildregistry

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
)

const DefaultCleanupTimeout = 30 * time.Second

type harborAuthority interface {
	Registry() string
	EnsureProject(ctx context.Context, organizationID string) (string, error)
	CreatePushRobot(ctx context.Context, projectName, buildID string) (harborRobotCreated, error)
	RepositoryToken(ctx context.Context, robot harborRobotCreated, projectName, repository string, requestedExpiry time.Time) (string, time.Time, error)
	DeleteRobot(ctx context.Context, robotID int64) error
}

type Broker struct {
	harbor  harborAuthority
	leases  LeaseStore
	clock   func() time.Time
	newID   func() (platformid.ID, error)
	issuing chan struct{}
	mu      sync.Mutex
	cleanup time.Duration
}

type BrokerConfig struct {
	Harbor              harborAuthority
	Leases              LeaseStore
	Clock               func() time.Time
	NewID               func() (platformid.ID, error)
	MaxConcurrentIssues int
	CleanupTimeout      time.Duration
}

func NewBroker(config BrokerConfig) (*Broker, error) {
	if config.Harbor == nil || config.Leases == nil || config.MaxConcurrentIssues < 1 || config.MaxConcurrentIssues > 64 {
		return nil, errors.New("registry capability broker configuration is incomplete")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.NewID == nil {
		config.NewID = func() (platformid.ID, error) { return platformid.New("tok") }
	}
	if config.CleanupTimeout == 0 {
		config.CleanupTimeout = DefaultCleanupTimeout
	}
	if config.CleanupTimeout < time.Second || config.CleanupTimeout > time.Minute {
		return nil, errors.New("registry capability cleanup timeout is outside bounds")
	}
	return &Broker{
		harbor: config.Harbor, leases: config.Leases, clock: config.Clock, newID: config.NewID,
		issuing: make(chan struct{}, config.MaxConcurrentIssues), cleanup: config.CleanupTimeout,
	}, nil
}

func (broker *Broker) Issue(ctx context.Context, scope PublicationScope) (PushCapability, error) {
	now := broker.clock().UTC()
	if err := ValidatePublicationScope(scope, now); err != nil {
		return PushCapability{}, err
	}
	select {
	case broker.issuing <- struct{}{}:
		defer func() { <-broker.issuing }()
	default:
		return PushCapability{}, fmt.Errorf("%w: registry broker capacity is busy", ErrRegistry)
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return PushCapability{}, err
	}
	key := businessKey(scope)
	if existing, found, err := broker.leases.GetByBusinessKey(ctx, key); err != nil {
		return PushCapability{}, err
	} else if found {
		if err := broker.revokeLease(ctx, existing); err != nil {
			return PushCapability{}, err
		}
	}
	projectName, err := broker.harbor.EnsureProject(ctx, scope.OrganizationID)
	if err != nil {
		return PushCapability{}, err
	}
	repository, err := RepositoryName(scope.ProjectID, scope.OutputName)
	if err != nil {
		return PushCapability{}, err
	}
	robot, err := broker.harbor.CreatePushRobot(ctx, projectName, scope.BuildID)
	if err != nil {
		return PushCapability{}, err
	}
	leaseID, err := broker.newID()
	if err != nil || leaseID.Prefix() != "tok" {
		cleanupErr := broker.deleteRobot(robot.ID)
		return PushCapability{}, errors.Join(errors.New("create registry lease identity"), cleanupErr)
	}
	lease := RobotLease{
		Version: CurrentLeaseVersion, LeaseID: string(leaseID), BusinessKey: key, OrganizationID: scope.OrganizationID,
		BuildID: scope.BuildID, ProjectName: projectName, Repository: repository, RobotID: robot.ID,
		ExpiresAt: scope.ExpiresAt.UTC().Truncate(time.Second).Format(time.RFC3339),
	}
	if err := broker.leases.Put(ctx, lease); err != nil {
		cleanupErr := broker.deleteRobot(robot.ID)
		return PushCapability{}, errors.Join(err, cleanupErr)
	}
	token, expiresAt, tokenErr := broker.harbor.RepositoryToken(ctx, robot, projectName, repository, scope.ExpiresAt)
	robot.Secret = ""
	if tokenErr != nil {
		cleanupErr := broker.revokeLease(context.WithoutCancel(ctx), lease)
		return PushCapability{}, errors.Join(tokenErr, cleanupErr)
	}
	capability := PushCapability{
		LeaseID: lease.LeaseID, Registry: broker.harbor.Registry(), Repository: repository, Token: token, ExpiresAt: expiresAt,
	}
	if err := validatePushCapability(capability, scope, now); err != nil {
		cleanupErr := broker.revokeLease(context.WithoutCancel(ctx), lease)
		return PushCapability{}, errors.Join(err, cleanupErr)
	}
	return capability, nil
}

func (broker *Broker) Revoke(ctx context.Context, leaseID string) error {
	lease, err := platformid.Parse(leaseID)
	if err != nil || lease.Prefix() != "tok" {
		return errors.New("registry capability lease identity is invalid")
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	record, found, err := broker.leases.Get(ctx, leaseID)
	if err != nil || !found {
		return err
	}
	return broker.revokeLease(ctx, record)
}

func (broker *Broker) SweepExpired(ctx context.Context, limit int) (int, error) {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	expired, err := broker.leases.Expired(ctx, broker.clock().UTC(), limit)
	if err != nil {
		return 0, err
	}
	cleaned := 0
	var cleanupErrors []error
	for _, lease := range expired {
		if err := broker.revokeLease(ctx, lease); err != nil {
			cleanupErrors = append(cleanupErrors, err)
			continue
		}
		cleaned++
	}
	return cleaned, errors.Join(cleanupErrors...)
}

func (broker *Broker) revokeLease(ctx context.Context, lease RobotLease) error {
	cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), broker.cleanup)
	defer cancel()
	if err := broker.harbor.DeleteRobot(cleanupContext, lease.RobotID); err != nil {
		return err
	}
	if err := broker.leases.Remove(cleanupContext, lease.LeaseID); err != nil {
		return fmt.Errorf("%w: remove revoked registry lease: %v", ErrRegistry, err)
	}
	return nil
}

func (broker *Broker) deleteRobot(robotID int64) error {
	cleanupContext, cancel := context.WithTimeout(context.Background(), broker.cleanup)
	defer cancel()
	return broker.harbor.DeleteRobot(cleanupContext, robotID)
}
