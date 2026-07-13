package buildregistry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
	"github.com/minio/minio-go/v7"
)

type S3DeletionJournal struct {
	client StaticObjectClient
	bucket string
	prefix string
}

func NewS3DeletionJournal(client StaticObjectClient, bucket, prefix string) (*S3DeletionJournal, error) {
	prefix = strings.Trim(prefix, "/")
	if client == nil || bucket == "" || strings.ContainsAny(bucket, `/\\`) || prefix == "" || path.Clean(prefix) != prefix || strings.HasPrefix(prefix, "../") {
		return nil, errors.New("artifact deletion journal configuration is invalid")
	}
	return &S3DeletionJournal{client: client, bucket: bucket, prefix: prefix}, nil
}

func (journal *S3DeletionJournal) Record(ctx context.Context, record DeletionRecord) error {
	if err := validateDeletionRecord(record); err != nil {
		return err
	}
	contents, err := canonicaljson.Marshal(record)
	if err != nil {
		return errors.New("canonicalize artifact deletion record")
	}
	contentDigest := "sha256:" + sha256Text(string(contents))
	identity := record
	identity.OccurredAt = ""
	identityContents, err := canonicaljson.Marshal(identity)
	if err != nil {
		return errors.New("canonicalize artifact deletion identity")
	}
	identityDigest := "sha256:" + sha256Text(string(identityContents))
	key := path.Join(
		journal.prefix, sha256Text(record.OrganizationID), sha256Text(record.ProjectID), strings.TrimPrefix(record.Digest, "sha256:"),
		record.State+"-"+strings.TrimPrefix(identityDigest, "sha256:")+".json",
	)
	options := minio.PutObjectOptions{ContentType: "application/vnd.lrail.artifact-tombstone.v1+json", UserMetadata: map[string]string{"sha256": contentDigest, "identity-sha256": identityDigest}}
	options.SetMatchETagExcept("*")
	if _, err := journal.client.PutObject(ctx, journal.bucket, key, bytes.NewReader(contents), int64(len(contents)), options); err == nil {
		return nil
	} else if minio.ToErrorResponse(err).Code != "PreconditionFailed" {
		return fmt.Errorf("%w: write artifact deletion journal", ErrRegistry)
	}
	stat, err := journal.client.StatObject(ctx, journal.bucket, key, minio.StatObjectOptions{})
	if err != nil || stat.Size <= 0 || stat.Size > MaxHarborBodyBytes || !validDigest(staticMetadataValue(stat, "sha256")) ||
		staticMetadataValue(stat, "identity-sha256") != identityDigest {
		return ErrConflict
	}
	return nil
}

func validateDeletionRecord(record DeletionRecord) error {
	organization, organizationErr := platformid.Parse(record.OrganizationID)
	project, projectErr := platformid.Parse(record.ProjectID)
	occurredAt, timeErr := time.Parse(time.RFC3339Nano, record.OccurredAt)
	if record.Version != DeletionRecordVersion || record.State != "deletion_authorized" && record.State != "artifact_deleted" ||
		organizationErr != nil || organization.Prefix() != "org" || projectErr != nil || project.Prefix() != "prj" ||
		!outputNamePattern.MatchString(record.OutputName) || !repositoryPattern.MatchString(record.Repository) || !validDigest(record.Digest) ||
		record.Reason == "" || record.MetadataBackup == "" || timeErr != nil || occurredAt.UTC().Format(time.RFC3339Nano) != record.OccurredAt {
		return errors.New("artifact deletion record is invalid")
	}
	return nil
}

var _ DeletionJournal = (*S3DeletionJournal)(nil)
