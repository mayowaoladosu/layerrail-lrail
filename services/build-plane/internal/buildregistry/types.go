// Package buildregistry publishes immutable build outputs through Harbor
// without exposing Harbor administrator or robot credentials to workers.
package buildregistry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
)

const (
	CurrentLeaseVersion = 1
	MaxCapabilityTTL    = 15 * time.Minute
	MaxHarborBodyBytes  = 1 << 20
	DefaultHTTPTimeout  = 20 * time.Second
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var outputNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var harborNamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,253}[a-z0-9])?$`)
var repositoryPattern = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$`)

var (
	ErrRegistry   = errors.New("build registry operation failed")
	ErrConflict   = errors.New("immutable registry publication conflicts")
	ErrProtection = errors.New("artifact is protected from deletion")
)

type PublicationScope struct {
	OrganizationID string
	ProjectID      string
	BuildID        string
	Attempt        uint32
	OutputName     string
	ExpiresAt      time.Time
}

type PushCapability struct {
	LeaseID    string
	Registry   string
	Repository string
	Token      string
	ExpiresAt  time.Time
}

type CapabilityBroker interface {
	Issue(ctx context.Context, scope PublicationScope) (PushCapability, error)
	Revoke(ctx context.Context, leaseID string) error
}

type RobotLease struct {
	Version        int    `json:"version"`
	LeaseID        string `json:"lease_id"`
	BusinessKey    string `json:"business_key"`
	OrganizationID string `json:"organization_id"`
	BuildID        string `json:"build_id"`
	ProjectName    string `json:"project_name"`
	Repository     string `json:"repository"`
	RobotID        int64  `json:"robot_id"`
	ExpiresAt      string `json:"expires_at"`
}

type LeaseStore interface {
	Put(ctx context.Context, lease RobotLease) error
	Get(ctx context.Context, leaseID string) (RobotLease, bool, error)
	GetByBusinessKey(ctx context.Context, businessKey string) (RobotLease, bool, error)
	Remove(ctx context.Context, leaseID string) error
	Expired(ctx context.Context, now time.Time, limit int) ([]RobotLease, error)
}

func ProjectName(organizationID string) (string, error) {
	organization, err := platformid.Parse(organizationID)
	if err != nil || organization.Prefix() != "org" {
		return "", errors.New("registry organization identity is invalid")
	}
	digest := sha256.Sum256([]byte(organizationID))
	return "lrail-" + hex.EncodeToString(digest[:]), nil
}

func RepositoryName(projectID, outputName string) (string, error) {
	project, err := platformid.Parse(projectID)
	if err != nil || project.Prefix() != "prj" || !outputNamePattern.MatchString(outputName) {
		return "", errors.New("registry repository identity is invalid")
	}
	digest := sha256.Sum256([]byte(projectID))
	return "builds/" + hex.EncodeToString(digest[:16]) + "/" + outputName, nil
}

func ValidatePublicationScope(scope PublicationScope, now time.Time) error {
	organization, organizationErr := platformid.Parse(scope.OrganizationID)
	project, projectErr := platformid.Parse(scope.ProjectID)
	build, buildErr := platformid.Parse(scope.BuildID)
	expiresAt := scope.ExpiresAt.UTC()
	if organizationErr != nil || organization.Prefix() != "org" || projectErr != nil || project.Prefix() != "prj" ||
		buildErr != nil || build.Prefix() != "bld" || scope.Attempt == 0 || !outputNamePattern.MatchString(scope.OutputName) ||
		!expiresAt.After(now.UTC()) || expiresAt.Sub(now.UTC()) > MaxCapabilityTTL {
		return errors.New("registry publication scope is invalid")
	}
	return nil
}

func validatePushCapability(capability PushCapability, scope PublicationScope, now time.Time) error {
	lease, leaseErr := platformid.Parse(capability.LeaseID)
	endpoint, endpointErr := url.Parse(capability.Registry)
	expectedRepository, repositoryErr := RepositoryName(scope.ProjectID, scope.OutputName)
	if leaseErr != nil || lease.Prefix() != "tok" || endpointErr != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.Path != "" ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.User != nil || repositoryErr != nil || capability.Repository != expectedRepository ||
		!repositoryPattern.MatchString(capability.Repository) || capability.Token == "" || len(capability.Token) > 64<<10 ||
		!capability.ExpiresAt.After(now.UTC()) || capability.ExpiresAt.After(scope.ExpiresAt.UTC()) || capability.ExpiresAt.Sub(now.UTC()) > MaxCapabilityTTL {
		return errors.New("registry push capability is invalid")
	}
	return nil
}

func businessKey(scope PublicationScope) string {
	return fmt.Sprintf("%s:%d:%s", scope.BuildID, scope.Attempt, scope.OutputName)
}

func fullRepository(projectName, repository string) (string, error) {
	if !harborNamePattern.MatchString(projectName) || !repositoryPattern.MatchString(repository) {
		return "", errors.New("Harbor repository scope is invalid")
	}
	return projectName + "/" + repository, nil
}

func validDigest(value string) bool { return digestPattern.MatchString(value) }

func normalizeRegistryURL(value string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return "", errors.New("Harbor registry URL must be an HTTPS origin")
	}
	return parsed.String(), nil
}
