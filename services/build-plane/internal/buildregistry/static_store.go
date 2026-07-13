package buildregistry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
	"github.com/minio/minio-go/v7"
)

type StaticObjectClient interface {
	PutObject(ctx context.Context, bucketName, objectName string, reader io.Reader, objectSize int64, opts minio.PutObjectOptions) (minio.UploadInfo, error)
	StatObject(ctx context.Context, bucketName, objectName string, opts minio.StatObjectOptions) (minio.ObjectInfo, error)
}

type S3StaticManifestStore struct {
	client StaticObjectClient
	bucket string
	prefix string
}

func NewS3StaticManifestStore(client StaticObjectClient, bucket, prefix string) (*S3StaticManifestStore, error) {
	prefix = strings.Trim(prefix, "/")
	if client == nil || bucket == "" || strings.ContainsAny(bucket, `/\\`) || prefix == "" || path.Clean(prefix) != prefix || strings.HasPrefix(prefix, "../") {
		return nil, errors.New("static manifest store configuration is invalid")
	}
	return &S3StaticManifestStore{client: client, bucket: bucket, prefix: prefix}, nil
}

func (store *S3StaticManifestStore) PutImmutable(ctx context.Context, manifest StaticPublicationManifest) (string, error) {
	if err := validateStaticPublicationManifest(manifest); err != nil {
		return "", err
	}
	contents, err := canonicaljson.Marshal(manifest)
	if err != nil {
		return "", errors.New("canonicalize static publication manifest")
	}
	digest := sha256Text(string(contents))
	organizationHash := sha256Text(manifest.OrganizationID)
	projectHash := sha256Text(manifest.ProjectID)
	key := path.Join(store.prefix, organizationHash, projectHash, manifest.BuildID, manifest.OutputName, digest+".json")
	options := minio.PutObjectOptions{ContentType: "application/vnd.lrail.static.publication.v1+json", UserMetadata: map[string]string{"sha256": "sha256:" + digest}}
	options.SetMatchETagExcept("*")
	if _, err := store.client.PutObject(ctx, store.bucket, key, bytes.NewReader(contents), int64(len(contents)), options); err == nil {
		return "s3://" + store.bucket + "/" + key, nil
	} else if minio.ToErrorResponse(err).Code != "PreconditionFailed" {
		return "", fmt.Errorf("%w: put static publication manifest", ErrRegistry)
	}
	stat, err := store.client.StatObject(ctx, store.bucket, key, minio.StatObjectOptions{})
	if err != nil || stat.Size != int64(len(contents)) || staticMetadataValue(stat, "sha256") != "sha256:"+digest {
		return "", ErrConflict
	}
	return "s3://" + store.bucket + "/" + key, nil
}

func validateStaticPublicationManifest(manifest StaticPublicationManifest) error {
	organization, organizationErr := platformid.Parse(manifest.OrganizationID)
	project, projectErr := platformid.Parse(manifest.ProjectID)
	build, buildErr := platformid.Parse(manifest.BuildID)
	if manifest.Version != StaticManifestVersion || organizationErr != nil || organization.Prefix() != "org" || projectErr != nil || project.Prefix() != "prj" ||
		buildErr != nil || build.Prefix() != "bld" || !outputNamePattern.MatchString(manifest.OutputName) || !validDigest(manifest.SourceDigest) ||
		manifest.SourceSize <= 0 || !validDigest(manifest.ManifestDigest) || !strings.HasSuffix(manifest.OCIReference, "@"+manifest.ManifestDigest) ||
		len(manifest.Files) == 0 || len(manifest.Files) > 100_000 {
		return errors.New("static publication manifest identity is invalid")
	}
	var total int64
	previous := ""
	for _, file := range manifest.Files {
		if file.Path == "" || file.Path <= previous || path.Clean(file.Path) != file.Path || strings.HasPrefix(file.Path, "../") || strings.Contains(file.Path, "\\") ||
			!validDigest(file.Digest) || file.Size < 0 || file.Mode != 0o444 && file.Mode != 0o555 || total > manifest.SourceSize-file.Size {
			return errors.New("static publication file entry is invalid")
		}
		total += file.Size
		previous = file.Path
	}
	if total != manifest.SourceSize {
		return errors.New("static publication file sizes differ from source")
	}
	return nil
}

func staticMetadataValue(info minio.ObjectInfo, key string) string {
	for name, value := range info.UserMetadata {
		if strings.EqualFold(name, key) {
			return value
		}
	}
	return ""
}
