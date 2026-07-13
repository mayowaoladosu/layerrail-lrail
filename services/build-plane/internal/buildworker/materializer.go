package buildworker

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
	"golang.org/x/text/unicode/norm"
)

const (
	MaxSourceFiles        = 50_000
	MaxSourceFileSize     = 128 << 20
	MaxSourceArchiveBytes = 1 << 30
	MaxSourceBytes        = 2 << 30
)

type TarGzipMaterializer struct{}

func (TarGzipMaterializer) Materialize(ctx context.Context, store SourceStore, source buildcell.SourceArtifact, destination string) error {
	if store == nil {
		return errors.New("source store is nil")
	}
	if source.SizeBytes <= 0 || source.SizeBytes > MaxSourceArchiveBytes {
		return errors.New("source archive size is outside policy")
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return fmt.Errorf("create source destination: %w", err)
	}
	entries, err := os.ReadDir(destination)
	if err != nil || len(entries) != 0 {
		return errors.New("source destination must be empty")
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = os.RemoveAll(destination)
		}
	}()

	reader, err := store.Open(ctx, source)
	if err != nil {
		return fmt.Errorf("open source archive: %w", err)
	}
	defer reader.Close()
	staged, err := os.CreateTemp(filepath.Dir(destination), ".lrail-source-*.tar.gz")
	if err != nil {
		return fmt.Errorf("create source staging file: %w", err)
	}
	stagedPath := staged.Name()
	defer os.Remove(stagedPath)

	archiveHash := sha256.New()
	written, copyErr := copyWithContext(ctx, io.MultiWriter(staged, archiveHash), io.LimitReader(reader, source.SizeBytes+1))
	closeErr := staged.Close()
	if copyErr != nil || closeErr != nil {
		return errors.New("stage source archive failed")
	}
	if written != source.SizeBytes {
		return fmt.Errorf("source archive size mismatch: got %d", written)
	}
	actualDigest := "sha256:" + hex.EncodeToString(archiveHash.Sum(nil))
	if actualDigest != source.ArchiveDigest {
		return errors.New("source archive digest mismatch")
	}

	archiveFile, err := os.Open(stagedPath)
	if err != nil {
		return fmt.Errorf("reopen source archive: %w", err)
	}
	defer archiveFile.Close()
	buffered := bufio.NewReader(archiveFile)
	compressed, err := gzip.NewReader(buffered)
	if err != nil {
		return fmt.Errorf("open source gzip: %w", err)
	}
	compressed.Multistream(false)
	if err := extractTar(ctx, tar.NewReader(compressed), destination); err != nil {
		_ = compressed.Close()
		return err
	}
	if _, err := copyWithContext(ctx, io.Discard, compressed); err != nil {
		_ = compressed.Close()
		return fmt.Errorf("finish source gzip: %w", err)
	}
	if err := compressed.Close(); err != nil {
		return fmt.Errorf("close source gzip: %w", err)
	}
	if _, err := buffered.Peek(1); !errors.Is(err, io.EOF) {
		return errors.New("source archive has trailing compressed data")
	}
	succeeded = true
	return nil
}

func extractTar(ctx context.Context, reader *tar.Reader, destination string) error {
	seen := make(map[string]struct{})
	var expanded int64
	count := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read source tar: %w", err)
		}
		count++
		if count > MaxSourceFiles {
			return errors.New("source archive file limit exceeded")
		}
		directory := header.Typeflag == tar.TypeDir
		relative, err := normalizeSourcePath(header.Name, directory)
		if err != nil {
			return fmt.Errorf("unsafe source path: %w", err)
		}
		if relative == "" && directory {
			continue
		}
		key := strings.ToLower(relative)
		if _, exists := seen[key]; exists {
			return errors.New("source archive contains duplicate portable path")
		}
		seen[key] = struct{}{}
		target := filepath.Join(destination, filepath.FromSlash(relative))
		if !inside(destination, target) {
			return errors.New("source archive path escaped destination")
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return fmt.Errorf("create source directory: %w", err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > MaxSourceFileSize || expanded > MaxSourceBytes-header.Size || header.Linkname != "" || header.Mode&0o7000 != 0 {
				return errors.New("source archive file violates limits")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return fmt.Errorf("create source parent: %w", err)
			}
			mode := os.FileMode(0o600)
			if header.Mode&0o111 != 0 {
				mode = 0o700
			}
			file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
			if err != nil {
				return fmt.Errorf("create source file: %w", err)
			}
			written, copyErr := copyWithContext(ctx, file, io.LimitReader(reader, header.Size))
			closeErr := file.Close()
			if copyErr != nil || closeErr != nil || written != header.Size {
				return errors.New("write source file failed")
			}
			expanded += header.Size
		default:
			return errors.New("source archive contains unsupported entry type")
		}
	}
}

func normalizeSourcePath(raw string, directory bool) (string, error) {
	if !utf8.ValidString(raw) || strings.ContainsRune(raw, '\x00') || strings.Contains(raw, "\\") {
		return "", errors.New("invalid encoding or separator")
	}
	normalized := norm.NFC.String(raw)
	cleaned := path.Clean(normalized)
	if directory && cleaned == "." {
		return "", nil
	}
	if cleaned == "." || path.IsAbs(cleaned) || cleaned == ".." || strings.HasPrefix(cleaned, "../") ||
		strings.Contains(cleaned, ":") || unsafePortableSourcePath(cleaned) ||
		cleaned != strings.TrimSuffix(normalized, "/") || len([]byte(cleaned)) > 512 {
		return "", errors.New("path is unsafe, non-portable, or non-canonical")
	}
	return cleaned, nil
}

func unsafePortableSourcePath(value string) bool {
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") {
			return true
		}
		for _, character := range segment {
			if character < 0x20 || character == 0x7f {
				return true
			}
		}
		base := strings.ToLower(strings.TrimSuffix(segment, path.Ext(segment)))
		if base == "con" || base == "prn" || base == "aux" || base == "nul" ||
			(len(base) == 4 && (strings.HasPrefix(base, "com") || strings.HasPrefix(base, "lpt")) && base[3] >= '1' && base[3] <= '9') {
			return true
		}
	}
	return false
}

func copyWithContext(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	buffer := make([]byte, 64*1024)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			count, writeErr := destination.Write(buffer[:read])
			written += int64(count)
			if writeErr != nil {
				return written, writeErr
			}
			if count != read {
				return written, io.ErrShortWrite
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return written, nil
			}
			return written, readErr
		}
	}
}

func inside(root, target string) bool {
	root, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	target, err = filepath.Abs(target)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(root, target)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}
