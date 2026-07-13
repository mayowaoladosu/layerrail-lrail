// Package snapshotstore validates and atomically stores immutable source snapshots.
package snapshotstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/objectstore"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourcearchive"
)

type Writer struct {
	Store      objectstore.Store
	ScratchDir string
	Policy     sourcearchive.Policy
}

type Input struct {
	Reader                io.Reader
	ExpectedArchiveBytes  int64
	ExpectedArchiveSHA256 string
	Metadata              sourcearchive.Metadata
}

type Result struct {
	Source      sourcearchive.Result
	ArchiveRef  string
	ManifestRef string
	SizeBytes   int64
}

func (writer *Writer) Write(ctx context.Context, input Input) (Result, error) {
	if writer == nil || writer.Store == nil || writer.ScratchDir == "" || input.Reader == nil {
		return Result{}, errors.New("snapshot writer configuration is incomplete")
	}
	temporary, err := os.CreateTemp(writer.ScratchDir, "lrail-source-*.tar.gz")
	if err != nil {
		return Result{}, fmt.Errorf("create source snapshot scratch file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	defer temporary.Close()
	if err := temporary.Chmod(0o600); err != nil {
		return Result{}, fmt.Errorf("secure source snapshot scratch file: %w", err)
	}

	result, err := sourcearchive.Finalize(io.TeeReader(input.Reader, temporary), sourcearchive.Options{
		ExpectedArchiveBytes:  input.ExpectedArchiveBytes,
		ExpectedArchiveSHA256: input.ExpectedArchiveSHA256,
		Metadata:              input.Metadata,
		Policy:                writer.Policy,
	})
	if err != nil {
		return Result{}, err
	}
	if err := temporary.Sync(); err != nil {
		return Result{}, fmt.Errorf("sync source snapshot scratch file: %w", err)
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		return Result{}, fmt.Errorf("rewind source snapshot scratch file: %w", err)
	}

	digestKey := strings.TrimPrefix(result.SnapshotSHA256, "sha256:")
	archiveKey := path.Join("snapshots", "sha256", digestKey, "source.tar.gz")
	manifestKey := path.Join("snapshots", "sha256", digestKey, "manifest.json")
	if err := writer.Store.PutImmutable(
		ctx,
		archiveKey,
		temporary,
		input.ExpectedArchiveBytes,
		result.ArchiveSHA256,
		"application/gzip",
	); err != nil {
		return Result{}, err
	}
	if err := writer.Store.PutImmutable(
		ctx,
		manifestKey,
		bytes.NewReader(result.CanonicalManifest),
		int64(len(result.CanonicalManifest)),
		result.ManifestSHA256,
		"application/json",
	); err != nil {
		return Result{}, err
	}
	return Result{
		Source:      result,
		ArchiveRef:  writer.Store.Ref(archiveKey),
		ManifestRef: writer.Store.Ref(manifestKey),
		SizeBytes:   input.ExpectedArchiveBytes,
	}, nil
}
