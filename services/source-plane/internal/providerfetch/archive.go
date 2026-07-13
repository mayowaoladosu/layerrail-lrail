package providerfetch

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha1" // Git object identity is SHA-1 for current GitHub repositories.
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourcearchive"
)

const lfsPointerPrefix = "version https://git-lfs.github.com/spec/v1\n"

type treeObject struct {
	Mode string
	SHA  string
	Size int64
}

type normalizedArchive struct {
	File   *os.File
	Size   int64
	SHA256 string
}

type stagedEntry struct {
	Path string
	Mode int64
	Size int64
	File *os.File
}

func normalizeArchive(
	ctx context.Context,
	reader io.Reader,
	scratchDir string,
	policy sourcearchive.Policy,
	tree map[string]treeObject,
) (_ normalizedArchive, returnedError error) {
	if reader == nil || scratchDir == "" || len(tree) == 0 {
		return normalizedArchive{}, ErrInvalidRequest
	}
	compressedCount := &countingReader{Reader: io.LimitReader(&contextReader{ctx: ctx, reader: reader}, policy.MaxArchiveBytes+1)}
	buffered := bufio.NewReader(compressedCount)
	decompressor, err := gzip.NewReader(buffered)
	if err != nil {
		return normalizedArchive{}, fmt.Errorf("%w: provider archive is not gzip", ErrRepositoryPolicy)
	}
	decompressor.Multistream(false)
	defer decompressor.Close()

	entries := make([]stagedEntry, 0, len(tree))
	defer func() {
		for _, entry := range entries {
			name := entry.File.Name()
			_ = entry.File.Close()
			_ = os.Remove(name)
		}
	}()
	seen := make(map[string]struct{}, len(tree))
	archiveRoot := ""
	var expanded int64
	tarReader := tar.NewReader(decompressor)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return normalizedArchive{}, fmt.Errorf("%w: read provider tar", ErrRepositoryPolicy)
		}
		normalized, err := sourcearchive.NormalizePath(header.Name, header.Typeflag == tar.TypeDir, policy.MaxPathBytes+256)
		if err != nil {
			return normalizedArchive{}, err
		}
		segments := strings.SplitN(normalized, "/", 2)
		if archiveRoot == "" {
			archiveRoot = segments[0]
		}
		if segments[0] != archiveRoot {
			return normalizedArchive{}, fmt.Errorf("%w: provider archive has multiple roots", ErrRepositoryPolicy)
		}
		if len(segments) == 1 {
			if header.Typeflag != tar.TypeDir {
				return normalizedArchive{}, fmt.Errorf("%w: provider archive root is not a directory", ErrRepositoryPolicy)
			}
			continue
		}
		relative, err := sourcearchive.NormalizePath(segments[1], header.Typeflag == tar.TypeDir, policy.MaxPathBytes)
		if err != nil {
			return normalizedArchive{}, err
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return normalizedArchive{}, fmt.Errorf("%w: unsupported provider archive entry", ErrRepositoryPolicy)
		}
		if header.Linkname != "" || header.Mode&0o7000 != 0 || header.Size < 0 || header.Size > policy.MaxFileBytes {
			return normalizedArchive{}, fmt.Errorf("%w: unsafe provider archive entry", ErrRepositoryPolicy)
		}
		expected, found := tree[relative]
		if !found || expected.Size != header.Size {
			return normalizedArchive{}, fmt.Errorf("%w: provider archive differs from resolved tree", ErrRepositoryPolicy)
		}
		if _, duplicate := seen[relative]; duplicate {
			return normalizedArchive{}, fmt.Errorf("%w: duplicate provider archive path", ErrRepositoryPolicy)
		}
		if expanded > policy.MaxExpandedBytes-header.Size {
			return normalizedArchive{}, fmt.Errorf("%w: provider tree exceeds expanded limit", ErrRepositoryPolicy)
		}
		entryFile, err := os.CreateTemp(scratchDir, "lrail-provider-entry-*")
		if err != nil {
			return normalizedArchive{}, fmt.Errorf("create provider scratch entry: %w", err)
		}
		if err := entryFile.Chmod(0o600); err != nil {
			_ = entryFile.Close()
			_ = os.Remove(entryFile.Name())
			return normalizedArchive{}, fmt.Errorf("secure provider scratch entry: %w", err)
		}
		entry := stagedEntry{Path: relative, Mode: 0o644, Size: header.Size, File: entryFile}
		entries = append(entries, entry)
		objectHash, err := gitObjectHash(expected.SHA, header.Size)
		if err != nil {
			return normalizedArchive{}, err
		}
		prefix := &prefixWriter{limit: 512}
		written, err := io.CopyN(io.MultiWriter(entryFile, objectHash, prefix), tarReader, header.Size)
		if err != nil || written != header.Size {
			return normalizedArchive{}, fmt.Errorf("%w: truncated provider archive entry", ErrRepositoryPolicy)
		}
		if strings.HasPrefix(string(prefix.bytes), lfsPointerPrefix) {
			return normalizedArchive{}, fmt.Errorf("%w: %s", ErrLFSUnsupported, relative)
		}
		if !strings.EqualFold(hex.EncodeToString(objectHash.Sum(nil)), expected.SHA) {
			return normalizedArchive{}, fmt.Errorf("%w: provider blob digest mismatch", ErrRepositoryPolicy)
		}
		if expected.Mode == "100755" {
			entries[len(entries)-1].Mode = 0o755
		}
		seen[relative] = struct{}{}
		expanded += header.Size
	}
	if _, err := io.Copy(io.Discard, decompressor); err != nil {
		return normalizedArchive{}, fmt.Errorf("%w: finish provider gzip", ErrRepositoryPolicy)
	}
	if err := decompressor.Close(); err != nil {
		return normalizedArchive{}, fmt.Errorf("%w: close provider gzip", ErrRepositoryPolicy)
	}
	if _, err := buffered.Peek(1); !errors.Is(err, io.EOF) || compressedCount.Count > policy.MaxArchiveBytes {
		return normalizedArchive{}, fmt.Errorf("%w: provider archive has trailing data or exceeds limit", ErrRepositoryPolicy)
	}
	if len(seen) != len(tree) {
		return normalizedArchive{}, fmt.Errorf("%w: provider archive omitted resolved tree entries", ErrRepositoryPolicy)
	}

	sort.Slice(entries, func(left, right int) bool { return entries[left].Path < entries[right].Path })
	output, err := os.CreateTemp(scratchDir, "lrail-provider-normalized-*.tar.gz")
	if err != nil {
		return normalizedArchive{}, fmt.Errorf("create normalized provider archive: %w", err)
	}
	outputPath := output.Name()
	keepOutput := false
	defer func() {
		if returnedError != nil || !keepOutput {
			_ = output.Close()
			_ = os.Remove(outputPath)
		}
	}()
	if err := output.Chmod(0o600); err != nil {
		return normalizedArchive{}, fmt.Errorf("secure normalized provider archive: %w", err)
	}
	archiveHash := sha256.New()
	counter := &countingWriter{Writer: io.MultiWriter(output, archiveHash)}
	compressor := gzip.NewWriter(counter)
	compressor.Header.ModTime = time.Unix(0, 0).UTC()
	compressor.Header.OS = 255
	tarWriter := tar.NewWriter(compressor)
	for _, entry := range entries {
		if _, err := entry.File.Seek(0, io.SeekStart); err != nil {
			return normalizedArchive{}, fmt.Errorf("rewind provider entry: %w", err)
		}
		if err := tarWriter.WriteHeader(&tar.Header{
			Name:       entry.Path,
			Mode:       entry.Mode,
			Size:       entry.Size,
			Typeflag:   tar.TypeReg,
			ModTime:    time.Unix(0, 0).UTC(),
			AccessTime: time.Unix(0, 0).UTC(),
			ChangeTime: time.Unix(0, 0).UTC(),
			Uid:        0,
			Gid:        0,
			Uname:      "root",
			Gname:      "root",
			Format:     tar.FormatPAX,
		}); err != nil {
			return normalizedArchive{}, fmt.Errorf("write normalized provider header: %w", err)
		}
		if _, err := io.CopyN(tarWriter, entry.File, entry.Size); err != nil {
			return normalizedArchive{}, fmt.Errorf("write normalized provider entry: %w", err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		return normalizedArchive{}, fmt.Errorf("close normalized provider tar: %w", err)
	}
	if err := compressor.Close(); err != nil {
		return normalizedArchive{}, fmt.Errorf("close normalized provider gzip: %w", err)
	}
	if err := output.Sync(); err != nil {
		return normalizedArchive{}, fmt.Errorf("sync normalized provider archive: %w", err)
	}
	if _, err := output.Seek(0, io.SeekStart); err != nil {
		return normalizedArchive{}, fmt.Errorf("rewind normalized provider archive: %w", err)
	}
	keepOutput = true
	return normalizedArchive{
		File:   output,
		Size:   counter.Count,
		SHA256: "sha256:" + hex.EncodeToString(archiveHash.Sum(nil)),
	}, nil
}

func gitObjectHash(expected string, size int64) (hash.Hash, error) {
	var value hash.Hash
	switch len(expected) {
	case sha1.Size * 2:
		value = sha1.New() // #nosec G505 -- Git's object identifier is intentionally SHA-1.
	case sha256.Size * 2:
		value = sha256.New()
	default:
		return nil, fmt.Errorf("%w: invalid provider object digest", ErrRepositoryPolicy)
	}
	_, _ = fmt.Fprintf(value, "blob %d\x00", size)
	return value, nil
}

type prefixWriter struct {
	bytes []byte
	limit int
}

func (writer *prefixWriter) Write(value []byte) (int, error) {
	remaining := writer.limit - len(writer.bytes)
	if remaining > 0 {
		if remaining > len(value) {
			remaining = len(value)
		}
		writer.bytes = append(writer.bytes, value[:remaining]...)
	}
	return len(value), nil
}

type countingReader struct {
	Reader io.Reader
	Count  int64
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	count, err := reader.Reader.Read(buffer)
	reader.Count += int64(count)
	return count, err
}

type countingWriter struct {
	Writer io.Writer
	Count  int64
}

func (writer *countingWriter) Write(buffer []byte) (int, error) {
	count, err := writer.Writer.Write(buffer)
	writer.Count += int64(count)
	return count, err
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	select {
	case <-reader.ctx.Done():
		return 0, reader.ctx.Err()
	default:
		return reader.reader.Read(buffer)
	}
}
