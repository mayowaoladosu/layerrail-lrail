package objectstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
)

type MinIO struct {
	storage   *minio.Client
	presigner *minio.Client
	bucket    string
}

func NewMinIO(storage *minio.Client, presigner *minio.Client, bucket string) (*MinIO, error) {
	if storage == nil || presigner == nil || bucket == "" {
		return nil, errors.New("source object store configuration is incomplete")
	}
	return &MinIO{storage: storage, presigner: presigner, bucket: bucket}, nil
}

func (store *MinIO) PresignPut(ctx context.Context, key string, expiry time.Duration) (*url.URL, error) {
	if err := validKey(key); err != nil {
		return nil, err
	}
	location, err := store.presigner.PresignedPutObject(ctx, store.bucket, key, expiry)
	if err != nil {
		return nil, fmt.Errorf("presign source part: %w", err)
	}
	return location, nil
}

func (store *MinIO) Open(ctx context.Context, key string) (io.ReadCloser, Info, error) {
	if err := validKey(key); err != nil {
		return nil, Info{}, err
	}
	stat, err := store.storage.StatObject(ctx, store.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		if isMissing(err) {
			return nil, Info{}, ErrNotFound
		}
		return nil, Info{}, fmt.Errorf("stat source object: %w", err)
	}
	object, err := store.storage.GetObject(ctx, store.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, Info{}, fmt.Errorf("open source object: %w", err)
	}
	return object, Info{Size: stat.Size, SHA256: metadataValue(stat, "sha256")}, nil
}

func (store *MinIO) PutImmutable(
	ctx context.Context,
	key string,
	reader io.Reader,
	size int64,
	sha256 string,
	contentType string,
) error {
	if err := validKey(key); err != nil {
		return err
	}
	if size < 0 || sha256 == "" || contentType == "" {
		return errors.New("immutable source object metadata is incomplete")
	}
	options := minio.PutObjectOptions{
		ContentType:  contentType,
		UserMetadata: map[string]string{"sha256": sha256},
	}
	options.SetMatchETagExcept("*")
	if _, err := store.storage.PutObject(ctx, store.bucket, key, reader, size, options); err == nil {
		return nil
	} else if minio.ToErrorResponse(err).Code != "PreconditionFailed" {
		return fmt.Errorf("put immutable source object: %w", err)
	}

	stat, err := store.storage.StatObject(ctx, store.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		return fmt.Errorf("stat immutable source object after conflict: %w", err)
	}
	if stat.Size != size || metadataValue(stat, "sha256") != sha256 {
		return ErrImmutableConflict
	}
	return nil
}

func (store *MinIO) Delete(ctx context.Context, keys []string) error {
	objects := make(chan minio.ObjectInfo)
	go func() {
		defer close(objects)
		for _, key := range keys {
			objects <- minio.ObjectInfo{Key: key}
		}
	}()
	for removeError := range store.storage.RemoveObjects(ctx, store.bucket, objects, minio.RemoveObjectsOptions{}) {
		if removeError.Err != nil && !isMissing(removeError.Err) {
			return fmt.Errorf("delete source part %q: %w", removeError.ObjectName, removeError.Err)
		}
	}
	return nil
}

func (store *MinIO) Ready(ctx context.Context) error {
	exists, err := store.storage.BucketExists(ctx, store.bucket)
	if err != nil {
		return fmt.Errorf("check source bucket: %w", err)
	}
	if !exists {
		return fmt.Errorf("source bucket %q does not exist", store.bucket)
	}
	return nil
}

func (store *MinIO) Ref(key string) string { return "s3://" + store.bucket + "/" + key }

func validKey(key string) error {
	if key == "" || strings.HasPrefix(key, "/") || strings.Contains(key, "\\") || strings.Contains(key, "..") {
		return errors.New("invalid source object key")
	}
	return nil
}

func isMissing(err error) bool {
	code := minio.ToErrorResponse(err).Code
	return code == "NoSuchKey" || code == "NoSuchObject" || code == "NotFound"
}

func metadataValue(info minio.ObjectInfo, key string) string {
	for name, value := range info.UserMetadata {
		if strings.EqualFold(name, key) {
			return value
		}
	}
	return ""
}
