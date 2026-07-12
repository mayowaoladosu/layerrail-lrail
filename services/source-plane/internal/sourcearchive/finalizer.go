package sourcearchive

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

var (
	sourceKindPattern = regexp.MustCompile(`^(local|git|promoted|migration)$`)
	accountIDPattern  = regexp.MustCompile(`^acct_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	commitPattern     = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	policyPattern     = regexp.MustCompile(`^[a-z][a-z0-9.-]{1,63}$`)
)

func Finalize(reader io.Reader, options Options) (Result, error) {
	policy := options.Policy
	if err := validatePolicy(policy); err != nil {
		return Result{}, err
	}
	if err := validateMetadata(options.Metadata); err != nil {
		return Result{}, err
	}
	if options.ExpectedArchiveBytes <= 0 || options.ExpectedArchiveBytes > policy.MaxArchiveBytes {
		return Result{}, &ValidationError{Kind: ErrArchiveSize, Info: "expected compressed size is outside policy"}
	}
	if !validDigest(options.ExpectedArchiveSHA256) {
		return Result{}, &ValidationError{Kind: ErrArchiveDigest, Info: "expected digest must be sha256"}
	}

	archiveHash := sha256.New()
	counted := &countingReader{Reader: io.TeeReader(io.LimitReader(reader, policy.MaxArchiveBytes+1), archiveHash)}
	buffered := bufio.NewReader(counted)
	compressed, err := gzip.NewReader(buffered)
	if err != nil {
		return Result{}, &ValidationError{Kind: ErrArchiveFormat, Info: err.Error()}
	}
	compressed.Multistream(false)

	manifest, err := readTar(tar.NewReader(compressed), options.Metadata, policy)
	if err != nil {
		_ = compressed.Close()
		return Result{}, err
	}
	if _, err := io.Copy(io.Discard, compressed); err != nil {
		_ = compressed.Close()
		return Result{}, &ValidationError{Kind: ErrArchiveFormat, Info: err.Error()}
	}
	if err := compressed.Close(); err != nil {
		return Result{}, &ValidationError{Kind: ErrArchiveFormat, Info: err.Error()}
	}
	if _, err := buffered.Peek(1); !errors.Is(err, io.EOF) {
		return Result{}, &ValidationError{Kind: ErrArchiveFormat, Info: "trailing compressed data"}
	}
	if counted.Count != options.ExpectedArchiveBytes {
		return Result{}, &ValidationError{Kind: ErrArchiveSize, Info: fmt.Sprintf("received %d bytes", counted.Count)}
	}

	archiveDigest := digestString(archiveHash)
	if archiveDigest != options.ExpectedArchiveSHA256 {
		return Result{}, &ValidationError{Kind: ErrArchiveDigest}
	}
	if manifest.IncludedBytes > options.ExpectedArchiveBytes*policy.MaxCompressionRatio {
		return Result{}, &ValidationError{Kind: ErrCompressionRatio}
	}

	canonicalManifest, err := canonicaljson.Marshal(manifest)
	if err != nil {
		return Result{}, fmt.Errorf("canonicalize source manifest: %w", err)
	}
	canonicalMetadata, err := canonicaljson.Marshal(options.Metadata)
	if err != nil {
		return Result{}, fmt.Errorf("canonicalize source metadata: %w", err)
	}
	manifestDigest := sha256.Sum256(canonicalManifest)
	snapshotHash := sha256.New()
	_, _ = snapshotHash.Write(canonicalManifest)
	_, _ = snapshotHash.Write([]byte("\n"))
	_, _ = snapshotHash.Write(canonicalMetadata)
	_, _ = snapshotHash.Write([]byte("\n" + policy.Version))

	return Result{
		Manifest:          manifest,
		CanonicalManifest: canonicalManifest,
		CanonicalMetadata: canonicalMetadata,
		ArchiveSHA256:     archiveDigest,
		ManifestSHA256:    "sha256:" + hex.EncodeToString(manifestDigest[:]),
		SnapshotSHA256:    digestString(snapshotHash),
	}, nil
}

func readTar(reader *tar.Reader, metadata Metadata, policy Policy) (Manifest, error) {
	entries := make([]Entry, 0)
	warnings := make([]string, 0)
	seen := make(map[string]string)
	fold := cases.Fold()
	var expanded int64
	entryCount := 0

	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, &ValidationError{Kind: ErrArchiveFormat, Info: err.Error()}
		}
		entryCount++
		if entryCount > policy.MaxEntries {
			return Manifest{}, &ValidationError{Kind: ErrEntryLimit}
		}

		normalized, err := normalizePath(header.Name, header.Typeflag == tar.TypeDir, policy.MaxPathBytes)
		if err != nil {
			return Manifest{}, err
		}
		if normalized == "" && header.Typeflag == tar.TypeDir {
			continue
		}
		collisionKey := fold.String(normalized)
		if previous, exists := seen[collisionKey]; exists {
			return Manifest{}, &ValidationError{Kind: ErrDuplicatePath, Path: normalized, Info: "collides with " + previous}
		}
		seen[collisionKey] = normalized

		switch header.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg, tar.TypeRegA:
			// Continue below.
		default:
			return Manifest{}, &ValidationError{Kind: ErrEntryType, Path: normalized, Info: fmt.Sprintf("tar type %d", header.Typeflag)}
		}
		if header.Linkname != "" || header.Mode&0o7000 != 0 {
			return Manifest{}, &ValidationError{Kind: ErrEntryType, Path: normalized, Info: "link or privileged mode"}
		}
		if header.Size < 0 || header.Size > policy.MaxFileBytes {
			return Manifest{}, &ValidationError{Kind: ErrExpandedSize, Path: normalized, Info: "file exceeds limit"}
		}
		if expanded > policy.MaxExpandedBytes-header.Size {
			return Manifest{}, &ValidationError{Kind: ErrExpandedSize, Path: normalized}
		}
		if secretPath(normalized) {
			return Manifest{}, &ValidationError{Kind: ErrSecretMaterial, Path: normalized, Info: "blocked credential path"}
		}

		fileHash := sha256.New()
		scanner := &secretScanner{path: normalized}
		written, err := io.CopyN(io.MultiWriter(fileHash, scanner), reader, header.Size)
		if err != nil {
			if errors.Is(err, ErrSecretMaterial) {
				return Manifest{}, err
			}
			return Manifest{}, &ValidationError{Kind: ErrArchiveFormat, Path: normalized, Info: err.Error()}
		}
		if written != header.Size {
			return Manifest{}, &ValidationError{Kind: ErrArchiveFormat, Path: normalized, Info: "truncated file"}
		}
		mode := int64(0o644)
		if header.Mode&0o111 != 0 {
			mode = 0o755
			warnings = append(warnings, "executable source file: "+normalized)
		}
		entries = append(entries, Entry{
			Path:   normalized,
			Type:   "file",
			Mode:   mode,
			Size:   header.Size,
			SHA256: digestString(fileHash),
		})
		expanded += header.Size
	}

	sort.Slice(entries, func(left, right int) bool { return entries[left].Path < entries[right].Path })
	sort.Strings(warnings)
	return Manifest{
		Version:       ManifestVersion,
		PolicyVersion: policy.Version,
		RootDirectory: metadata.RootDirectory,
		Entries:       entries,
		IncludedCount: len(entries),
		IncludedBytes: expanded,
		ExcludedCount: metadata.ExcludedCount,
		Warnings:      warnings,
		Scan:          Scan{Status: "passed", Findings: []Finding{}},
	}, nil
}

func normalizePath(raw string, directory bool, maxBytes int) (string, error) {
	if !utf8.ValidString(raw) || strings.ContainsRune(raw, '\x00') || strings.Contains(raw, "\\") {
		return "", &ValidationError{Kind: ErrPathUnsafe, Path: raw, Info: "invalid encoding or separator"}
	}
	normalized := norm.NFC.String(raw)
	cleaned := path.Clean(normalized)
	if directory && cleaned == "." {
		return "", nil
	}
	if cleaned == "." || path.IsAbs(cleaned) || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", &ValidationError{Kind: ErrPathUnsafe, Path: raw}
	}
	if strings.Contains(cleaned, ":") || unsafePortablePath(cleaned) {
		return "", &ValidationError{Kind: ErrPathUnsafe, Path: raw, Info: "path is not portable"}
	}
	if cleaned != strings.TrimSuffix(normalized, "/") || len([]byte(cleaned)) > maxBytes {
		return "", &ValidationError{Kind: ErrPathUnsafe, Path: raw, Info: "path is not canonical"}
	}
	return cleaned, nil
}

func validatePolicy(policy Policy) error {
	if !policyPattern.MatchString(policy.Version) || policy.MaxArchiveBytes <= 0 || policy.MaxExpandedBytes <= 0 ||
		policy.MaxFileBytes <= 0 || policy.MaxEntries <= 0 || policy.MaxPathBytes <= 0 || policy.MaxCompressionRatio <= 0 ||
		policy.MaxFileBytes > policy.MaxExpandedBytes || policy.MaxArchiveBytes > 1<<30 ||
		policy.MaxExpandedBytes > 2<<30 || policy.MaxFileBytes > 128<<20 || policy.MaxEntries > 50_000 ||
		policy.MaxPathBytes > 512 || policy.MaxCompressionRatio > 1_000 {
		return ErrPolicyInvalid
	}
	return nil
}

func validateMetadata(metadata Metadata) error {
	if !sourceKindPattern.MatchString(metadata.SourceKind) || !accountIDPattern.MatchString(metadata.CreatorID) ||
		metadata.ExcludedCount < 0 {
		return ErrMetadataInvalid
	}
	if metadata.SourceKind == "git" &&
		(metadata.Repository == "" || !commitPattern.MatchString(metadata.CommitSHA)) {
		return ErrMetadataInvalid
	}
	if metadata.RootDirectory != "" {
		if _, err := normalizePath(metadata.RootDirectory, false, 512); err != nil {
			return fmt.Errorf("%w: root directory: %v", ErrMetadataInvalid, err)
		}
	}
	return nil
}

func unsafePortablePath(value string) bool {
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

func validDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func digestString(value hash.Hash) string { return "sha256:" + hex.EncodeToString(value.Sum(nil)) }

type countingReader struct {
	Reader io.Reader
	Count  int64
}

func (r *countingReader) Read(buffer []byte) (int, error) {
	count, err := r.Reader.Read(buffer)
	r.Count += int64(count)
	return count, err
}
