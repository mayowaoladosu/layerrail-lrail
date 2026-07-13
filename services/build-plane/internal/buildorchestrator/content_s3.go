package buildorchestrator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcontent"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	"github.com/minio/minio-go/v7"
)

var mediaTypePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,127}$`)

type S3Client interface {
	buildcontent.ObjectClient
	PutObject(ctx context.Context, bucketName, objectName string, reader io.Reader, objectSize int64, opts minio.PutObjectOptions) (minio.UploadInfo, error)
}

type S3Content struct {
	sources buildworker.SourceStore
	client  S3Client
	store   *buildcontent.Store
	bucket  string
	prefix  string
}

func NewS3Content(sources buildworker.SourceStore, client S3Client, bucket, prefix string) (*S3Content, error) {
	if sources == nil || client == nil || bucket == "" || prefix == "" || strings.HasPrefix(prefix, "/") || strings.HasSuffix(prefix, "/") ||
		strings.Contains(prefix, "//") || strings.Contains(prefix, "..") {
		return nil, errors.New("orchestrator S3 content configuration is invalid")
	}
	store, err := buildcontent.NewStore(client, bucket, prefix)
	if err != nil {
		return nil, err
	}
	return &S3Content{sources: sources, client: client, store: store, bucket: bucket, prefix: prefix}, nil
}

func (content *S3Content) Materialize(ctx context.Context, source Source, destination string) error {
	return (buildworker.TarGzipMaterializer{}).Materialize(ctx, content.sources, buildcell.SourceArtifact{
		SnapshotDigest: source.SnapshotDigest, ArchiveDigest: source.ArchiveDigest,
		ArchiveRef: source.ArchiveRef, SizeBytes: source.SizeBytes,
	}, destination)
}

func (content *S3Content) MirrorSource(ctx context.Context, source Source, objectName string) (buildcell.SourceArtifact, error) {
	reader, err := content.sources.Open(ctx, buildcell.SourceArtifact{
		SnapshotDigest: source.SnapshotDigest, ArchiveDigest: source.ArchiveDigest,
		ArchiveRef: source.ArchiveRef, SizeBytes: source.SizeBytes,
	})
	if err != nil {
		return buildcell.SourceArtifact{}, errors.New("open source for cell mirroring")
	}
	defer reader.Close()
	object, err := content.put(ctx, objectName, "application/vnd.lrail.source.tar+gzip", reader, source.SizeBytes, source.ArchiveDigest)
	if err != nil {
		return buildcell.SourceArtifact{}, err
	}
	return buildcell.SourceArtifact{
		SnapshotDigest: source.SnapshotDigest, ArchiveDigest: object.Digest,
		ArchiveRef: object.Reference, SizeBytes: object.Size,
	}, nil
}

func (content *S3Content) PutImmutable(ctx context.Context, objectName, mediaType string, contents []byte) (StoredObject, error) {
	if len(contents) == 0 || len(contents) > MaxStoredObjectBytes {
		return StoredObject{}, errors.New("orchestrator object is absent or oversized")
	}
	digest := digestBytes(contents)
	return content.put(ctx, objectName, mediaType, bytes.NewReader(contents), int64(len(contents)), digest)
}

func (content *S3Content) put(ctx context.Context, objectName, mediaType string, reader io.Reader, size int64, expectedDigest string) (StoredObject, error) {
	if ctx == nil || !validObjectName(objectName) || !mediaTypePattern.MatchString(mediaType) || size <= 0 || size > buildcontent.MaxObjectBytes ||
		!digestPattern.MatchString(expectedDigest) || !strings.Contains(objectName, strings.TrimPrefix(expectedDigest, "sha256:")) {
		return StoredObject{}, errors.New("orchestrator immutable object identity is invalid")
	}
	fullName := content.prefix + "/" + objectName
	upload, err := content.client.PutObject(ctx, content.bucket, fullName, reader, size, minio.PutObjectOptions{
		ContentType: mediaType, DisableMultipart: true, DisableContentSha256: true, SendContentMd5: true,
		UserMetadata: map[string]string{"lrail-sha256": expectedDigest, "lrail-immutable": "true"},
	})
	if err != nil || upload.Size != size {
		return StoredObject{}, errors.New("write immutable build object")
	}
	reference := "s3://" + content.bucket + "/" + fullName
	readback, err := content.store.OpenObject(ctx, reference, size)
	if err != nil {
		return StoredObject{}, errors.New("open immutable build object for verification")
	}
	hash := sha256.New()
	written, copyErr := io.Copy(hash, io.LimitReader(readback, size+1))
	closeErr := readback.Close()
	actualDigest := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if copyErr != nil || closeErr != nil || written != size || actualDigest != expectedDigest {
		return StoredObject{}, fmt.Errorf("immutable build object verification failed: bytes=%d/%d digest=%s/%s read=%v close=%v", written, size, actualDigest, expectedDigest, copyErr, closeErr)
	}
	return StoredObject{Reference: reference, Digest: actualDigest, Size: written}, nil
}

func validObjectName(value string) bool {
	if value == "" || len(value) > 1024 || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.Contains(value, "//") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return objectPartPattern.MatchString(value)
}

var _ Content = (*S3Content)(nil)
