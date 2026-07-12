// Package objectstore provides direct upload and immutable snapshot object operations.
package objectstore

import (
	"context"
	"errors"
	"io"
	"net/url"
	"time"
)

var (
	ErrNotFound          = errors.New("source object not found")
	ErrImmutableConflict = errors.New("immutable source object conflicts with existing content")
)

type Info struct {
	Size   int64
	SHA256 string
}

type Store interface {
	PresignPut(ctx context.Context, key string, expiry time.Duration) (*url.URL, error)
	Open(ctx context.Context, key string) (io.ReadCloser, Info, error)
	PutImmutable(ctx context.Context, key string, reader io.Reader, size int64, sha256 string, contentType string) error
	Delete(ctx context.Context, keys []string) error
	Ready(ctx context.Context) error
	Ref(key string) string
}
