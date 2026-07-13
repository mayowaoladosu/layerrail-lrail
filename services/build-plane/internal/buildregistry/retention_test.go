package buildregistry

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
)

type deletionBackend struct {
	calls []RetentionCandidate
	err   error
}

func (backend *deletionBackend) DeleteArtifact(_ context.Context, projectName, repository, digest string) error {
	backend.calls = append(backend.calls, RetentionCandidate{OutputName: projectName, MetadataBackupRef: repository, Digest: digest})
	return backend.err
}

type deletionJournal struct {
	records []DeletionRecord
	failAt  int
}

func (journal *deletionJournal) Record(_ context.Context, record DeletionRecord) error {
	if journal.failAt > 0 && len(journal.records)+1 == journal.failAt {
		return errors.New("journal unavailable")
	}
	if err := validateDeletionRecord(record); err != nil {
		return err
	}
	journal.records = append(journal.records, record)
	return nil
}

func validRetentionCandidate() RetentionCandidate {
	return RetentionCandidate{
		OrganizationID: registryOrgID, ProjectID: registryProjectID, OutputName: "api", Digest: "sha256:" + strings.Repeat("a", 64),
		ReferencesDeleted: true, ReplicationConverged: true, MetadataBackupRef: "s3://registry-backup/metadata/backup.json", Reason: "retention_expired",
	}
}

func TestRetentionCoordinatorDeniesEveryProtectedDigest(t *testing.T) {
	t.Parallel()
	candidate := validRetentionCandidate()
	backend := new(deletionBackend)
	journal := new(deletionJournal)
	coordinator, _ := NewRetentionCoordinator(backend, journal, func() time.Time { return registryNow })
	for _, reason := range protectionReasons {
		protections, err := NewProtectionSet([]DigestProtection{{OrganizationID: candidate.OrganizationID, Digest: candidate.Digest, Reasons: []string{reason}}})
		if err != nil {
			t.Fatalf("NewProtectionSet %s: %v", reason, err)
		}
		if err := coordinator.Delete(t.Context(), candidate, protections); !errors.Is(err, ErrProtection) {
			t.Fatalf("reason=%s error=%v", reason, err)
		}
	}
	if len(backend.calls) != 0 || len(journal.records) != 0 {
		t.Fatalf("protected deletion had effects: backend=%#v journal=%#v", backend.calls, journal.records)
	}
}

func TestRetentionCoordinatorJournalsAuthorizationAndTombstone(t *testing.T) {
	t.Parallel()
	candidate := validRetentionCandidate()
	backend := new(deletionBackend)
	journal := new(deletionJournal)
	coordinator, _ := NewRetentionCoordinator(backend, journal, func() time.Time { return registryNow })
	protections, _ := NewProtectionSet(nil)
	if err := coordinator.Delete(t.Context(), candidate, protections); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	expectedRepository, _ := RepositoryName(candidate.ProjectID, candidate.OutputName)
	if len(backend.calls) != 1 || backend.calls[0].MetadataBackupRef != expectedRepository || len(journal.records) != 2 ||
		journal.records[0].State != "deletion_authorized" || journal.records[1].State != "artifact_deleted" || journal.records[1].Repository != expectedRepository {
		t.Fatalf("backend=%#v journal=%#v", backend.calls, journal.records)
	}
}

func TestRetentionCoordinatorFailsBeforeDeleteWhenAuthorizationCannotPersist(t *testing.T) {
	t.Parallel()
	backend := new(deletionBackend)
	journal := &deletionJournal{failAt: 1}
	coordinator, _ := NewRetentionCoordinator(backend, journal, func() time.Time { return registryNow })
	protections, _ := NewProtectionSet(nil)
	if err := coordinator.Delete(t.Context(), validRetentionCandidate(), protections); err == nil || len(backend.calls) != 0 {
		t.Fatalf("error=%v backend=%#v", err, backend.calls)
	}
}

func TestRetentionCoordinatorRejectsUnprovenCleanupGates(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*RetentionCandidate){
		"references":  func(candidate *RetentionCandidate) { candidate.ReferencesDeleted = false },
		"replication": func(candidate *RetentionCandidate) { candidate.ReplicationConverged = false },
		"backup":      func(candidate *RetentionCandidate) { candidate.MetadataBackupRef = "" },
		"foreign":     func(candidate *RetentionCandidate) { candidate.OrganizationID = registryProjectID },
		"digest":      func(candidate *RetentionCandidate) { candidate.Digest = "sha256:bad" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := validRetentionCandidate()
			mutate(&candidate)
			backend := new(deletionBackend)
			coordinator, _ := NewRetentionCoordinator(backend, new(deletionJournal), func() time.Time { return registryNow })
			protections, _ := NewProtectionSet(nil)
			if err := coordinator.Delete(t.Context(), candidate, protections); err == nil || len(backend.calls) != 0 {
				t.Fatalf("error=%v backend=%#v", err, backend.calls)
			}
		})
	}
}

func TestHarborArtifactDeletionUsesDoubleEncodedRepository(t *testing.T) {
	t.Parallel()
	fake := newFakeHarbor(t)
	client := fake.client(t)
	projectName, _ := ProjectName(registryOrgID)
	repository, _ := RepositoryName(registryProjectID, "api")
	digest := "sha256:" + strings.Repeat("a", 64)
	if err := client.DeleteArtifact(t.Context(), projectName, repository, digest); err != nil {
		t.Fatalf("DeleteArtifact: %v", err)
	}
	if fake.artifactDeletes != 1 || !strings.Contains(fake.artifactDeleteURI, "builds%252F") || !strings.Contains(fake.artifactDeleteURI, "sha256:") {
		t.Fatalf("delete URI=%q calls=%d", fake.artifactDeleteURI, fake.artifactDeletes)
	}
}

type mapStaticObjectClient struct {
	mu      sync.Mutex
	objects map[string][]byte
	info    map[string]minio.ObjectInfo
}

func newMapStaticObjectClient() *mapStaticObjectClient {
	return &mapStaticObjectClient{objects: map[string][]byte{}, info: map[string]minio.ObjectInfo{}}
}

func (client *mapStaticObjectClient) PutObject(_ context.Context, _, key string, reader io.Reader, size int64, options minio.PutObjectOptions) (minio.UploadInfo, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if _, exists := client.objects[key]; exists {
		return minio.UploadInfo{}, minio.ErrorResponse{Code: "PreconditionFailed"}
	}
	contents, err := io.ReadAll(reader)
	if err != nil || int64(len(contents)) != size {
		return minio.UploadInfo{}, errors.New("invalid object")
	}
	client.objects[key] = contents
	client.info[key] = minio.ObjectInfo{Size: size, UserMetadata: options.UserMetadata}
	return minio.UploadInfo{Size: size}, nil
}

func (client *mapStaticObjectClient) StatObject(_ context.Context, _, key string, _ minio.StatObjectOptions) (minio.ObjectInfo, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.info[key], nil
}

func TestS3DeletionJournalAppendsAuthorizationAndTombstoneImmutably(t *testing.T) {
	t.Parallel()
	client := newMapStaticObjectClient()
	journal, err := NewS3DeletionJournal(client, "registry-audit", "tombstones/v1")
	if err != nil {
		t.Fatalf("NewS3DeletionJournal: %v", err)
	}
	record := DeletionRecord{
		Version: DeletionRecordVersion, State: "deletion_authorized", OrganizationID: registryOrgID, ProjectID: registryProjectID,
		OutputName: "api", Repository: "builds/fixture/api", Digest: "sha256:" + strings.Repeat("a", 64), Reason: "retention_expired",
		MetadataBackup: "s3://backup/metadata.json", OccurredAt: registryNow.Format(time.RFC3339Nano),
	}
	if err := journal.Record(t.Context(), record); err != nil {
		t.Fatalf("Record authorization: %v", err)
	}
	if err := journal.Record(t.Context(), record); err != nil {
		t.Fatalf("idempotent Record: %v", err)
	}
	record.State = "artifact_deleted"
	if err := journal.Record(t.Context(), record); err != nil {
		t.Fatalf("Record tombstone: %v", err)
	}
	if len(client.objects) != 2 {
		t.Fatalf("journal objects=%d", len(client.objects))
	}
}
