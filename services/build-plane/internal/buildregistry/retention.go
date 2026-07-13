package buildregistry

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
)

const DeletionRecordVersion = 1

var protectionReasons = []string{
	"active_release", "backup_restore", "in_flight_workflow", "legal_hold", "pinned_revision", "retained_deployment", "rollback_window",
}

type DigestProtection struct {
	OrganizationID string   `json:"organization_id"`
	Digest         string   `json:"digest"`
	Reasons        []string `json:"reasons"`
}

type ProtectionSet struct {
	protected map[string]DigestProtection
}

func NewProtectionSet(entries []DigestProtection) (ProtectionSet, error) {
	result := ProtectionSet{protected: make(map[string]DigestProtection, len(entries))}
	for _, entry := range entries {
		organization, err := platformid.Parse(entry.OrganizationID)
		reasons := append([]string(nil), entry.Reasons...)
		slices.Sort(reasons)
		reasons = slices.Compact(reasons)
		if err != nil || organization.Prefix() != "org" || !validDigest(entry.Digest) || len(reasons) == 0 || len(reasons) > len(protectionReasons) {
			return ProtectionSet{}, errors.New("artifact protection entry is invalid")
		}
		for _, reason := range reasons {
			if !slices.Contains(protectionReasons, reason) {
				return ProtectionSet{}, errors.New("artifact protection reason is invalid")
			}
		}
		entry.Reasons = reasons
		key := protectionKey(entry.OrganizationID, entry.Digest)
		if _, duplicate := result.protected[key]; duplicate {
			return ProtectionSet{}, errors.New("artifact protection entry is duplicated")
		}
		result.protected[key] = entry
	}
	return result, nil
}

func (set ProtectionSet) Protection(organizationID, digest string) (DigestProtection, bool) {
	entry, found := set.protected[protectionKey(organizationID, digest)]
	return entry, found
}

func protectionKey(organizationID, digest string) string { return organizationID + "\x00" + digest }

type RetentionCandidate struct {
	OrganizationID       string
	ProjectID            string
	OutputName           string
	Digest               string
	ReferencesDeleted    bool
	ReplicationConverged bool
	MetadataBackupRef    string
	Reason               string
}

type DeletionRecord struct {
	Version        int    `json:"version"`
	State          string `json:"state"`
	OrganizationID string `json:"organization_id"`
	ProjectID      string `json:"project_id"`
	OutputName     string `json:"output_name"`
	Repository     string `json:"repository"`
	Digest         string `json:"digest"`
	Reason         string `json:"reason"`
	MetadataBackup string `json:"metadata_backup_ref"`
	OccurredAt     string `json:"occurred_at"`
}

type DeletionJournal interface {
	Record(ctx context.Context, record DeletionRecord) error
}

type ArtifactDeletionBackend interface {
	DeleteArtifact(ctx context.Context, projectName, repository, digest string) error
}

type RetentionCoordinator struct {
	backend ArtifactDeletionBackend
	journal DeletionJournal
	clock   func() time.Time
}

func NewRetentionCoordinator(backend ArtifactDeletionBackend, journal DeletionJournal, clock func() time.Time) (*RetentionCoordinator, error) {
	if backend == nil || journal == nil {
		return nil, errors.New("retention coordinator dependencies are incomplete")
	}
	if clock == nil {
		clock = time.Now
	}
	return &RetentionCoordinator{backend: backend, journal: journal, clock: clock}, nil
}

func (coordinator *RetentionCoordinator) Delete(ctx context.Context, candidate RetentionCandidate, protections ProtectionSet) error {
	projectName, repository, err := validateRetentionCandidate(candidate)
	if err != nil {
		return err
	}
	if protection, protected := protections.Protection(candidate.OrganizationID, candidate.Digest); protected {
		return fmt.Errorf("%w: %s", ErrProtection, strings.Join(protection.Reasons, ","))
	}
	base := DeletionRecord{
		Version: DeletionRecordVersion, OrganizationID: candidate.OrganizationID, ProjectID: candidate.ProjectID,
		OutputName: candidate.OutputName, Repository: repository, Digest: candidate.Digest, Reason: candidate.Reason,
		MetadataBackup: candidate.MetadataBackupRef,
	}
	base.State = "deletion_authorized"
	base.OccurredAt = coordinator.clock().UTC().Format(time.RFC3339Nano)
	if err := coordinator.journal.Record(ctx, base); err != nil {
		return fmt.Errorf("%w: persist deletion authorization", ErrRegistry)
	}
	if err := coordinator.backend.DeleteArtifact(ctx, projectName, repository, candidate.Digest); err != nil {
		return err
	}
	base.State = "artifact_deleted"
	base.OccurredAt = coordinator.clock().UTC().Format(time.RFC3339Nano)
	if err := coordinator.journal.Record(ctx, base); err != nil {
		return fmt.Errorf("%w: persist artifact deletion tombstone", ErrRegistry)
	}
	return nil
}

func validateRetentionCandidate(candidate RetentionCandidate) (string, string, error) {
	projectName, projectErr := ProjectName(candidate.OrganizationID)
	repository, repositoryErr := RepositoryName(candidate.ProjectID, candidate.OutputName)
	backup, backupErr := url.Parse(candidate.MetadataBackupRef)
	if projectErr != nil || repositoryErr != nil || !validDigest(candidate.Digest) || !candidate.ReferencesDeleted || !candidate.ReplicationConverged ||
		backupErr != nil || backup.Scheme != "s3" || backup.Host == "" || backup.Path == "" || backup.RawQuery != "" || backup.Fragment != "" || backup.User != nil ||
		candidate.Reason == "" || len(candidate.Reason) > 512 {
		return "", "", errors.New("artifact retention candidate is unsafe")
	}
	return projectName, repository, nil
}

func (client *HarborClient) DeleteArtifact(ctx context.Context, projectName, repository, digest string) error {
	if !harborNamePattern.MatchString(projectName) || !repositoryPattern.MatchString(repository) || !validDigest(digest) {
		return errors.New("Harbor artifact deletion scope is invalid")
	}
	encodedRepository := url.PathEscape(url.PathEscape(repository))
	status, err := client.doJSON(ctx, http.MethodDelete,
		"/api/v2.0/projects/"+projectName+"/repositories/"+encodedRepository+"/artifacts/"+url.PathEscape(digest), nil, nil,
		map[string]string{"X-Is-Resource-Name": "true"},
	)
	if err != nil || status != http.StatusOK && status != http.StatusNotFound {
		return fmt.Errorf("%w: delete Harbor artifact", ErrRegistry)
	}
	return nil
}

var _ ArtifactDeletionBackend = (*HarborClient)(nil)
