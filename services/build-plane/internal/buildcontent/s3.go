// Package buildcontent reads signed immutable build inputs from an internal S3 gateway.
package buildcontent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
	"github.com/minio/minio-go/v7"
)

const MaxObjectBytes int64 = 1 << 30

type ObjectClient interface {
	GetObject(ctx context.Context, bucketName, objectName string, opts minio.GetObjectOptions) (*minio.Object, error)
}

type Store struct {
	client ObjectClient
	bucket string
	prefix string
}

func NewStore(client ObjectClient, bucket, prefix string) (*Store, error) {
	prefix = strings.Trim(prefix, "/")
	if client == nil || bucket == "" || prefix == "" || strings.ContainsAny(bucket, `/\\`) || path.Clean(prefix) != prefix || strings.HasPrefix(prefix, "../") {
		return nil, errors.New("build content store configuration is invalid")
	}
	return &Store{client: client, bucket: bucket, prefix: prefix + "/"}, nil
}

func (store *Store) OpenObject(ctx context.Context, reference string, maxBytes int64) (io.ReadCloser, error) {
	if maxBytes <= 0 || maxBytes > MaxObjectBytes {
		return nil, errors.New("build content object limit is invalid")
	}
	objectName, err := store.objectName(reference)
	if err != nil {
		return nil, err
	}
	object, err := store.client.GetObject(ctx, store.bucket, objectName, minio.GetObjectOptions{})
	if err != nil {
		return nil, errors.New("open build content object")
	}
	stat, err := object.Stat()
	if err != nil {
		_ = object.Close()
		return nil, errors.New("stat build content object")
	}
	if stat.Size < 0 || stat.Size > maxBytes {
		_ = object.Close()
		return nil, errors.New("build content object is outside size limits")
	}
	return object, nil
}

func (store *Store) objectName(reference string) (string, error) {
	parsed, err := url.Parse(reference)
	if err != nil || parsed.Scheme != "s3" || parsed.Host != store.bucket || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return "", errors.New("build content reference is invalid")
	}
	objectName := strings.TrimPrefix(parsed.EscapedPath(), "/")
	decoded, err := url.PathUnescape(objectName)
	if err != nil || decoded == "" || path.Clean(decoded) != decoded || strings.Contains(decoded, "//") || !strings.HasPrefix(decoded, store.prefix) {
		return "", errors.New("build content reference is outside the cell prefix")
	}
	return decoded, nil
}

type ArtifactStore struct{ Store *Store }

func (adapter ArtifactStore) Open(ctx context.Context, reference string, maxBytes int64) (io.ReadCloser, error) {
	if adapter.Store == nil {
		return nil, errors.New("build artifact store is unavailable")
	}
	return adapter.Store.OpenObject(ctx, reference, maxBytes)
}

type SourceStore struct{ Store *Store }

func (adapter SourceStore) Open(ctx context.Context, source buildcell.SourceArtifact) (io.ReadCloser, error) {
	if adapter.Store == nil || source.SizeBytes <= 0 {
		return nil, errors.New("build source store is unavailable")
	}
	reader, err := adapter.Store.OpenObject(ctx, source.ArchiveRef, source.SizeBytes)
	if err != nil {
		return nil, fmt.Errorf("open immutable source: %w", err)
	}
	return reader, nil
}
