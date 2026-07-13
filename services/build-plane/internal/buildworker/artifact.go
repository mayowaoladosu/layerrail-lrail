package buildworker

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
)

const DefaultMaxCommittedArtifactBytes int64 = 20 << 30
const MaxCommittedArtifactFiles = 100_000

var artifactDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var artifactOutputPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

type DirectoryArtifactCommitter struct {
	root     string
	maxBytes int64
}

func NewDirectoryArtifactCommitter(root string, maxBytes int64) (*DirectoryArtifactCommitter, error) {
	if root == "" {
		return nil, errors.New("artifact root is empty")
	}
	if maxBytes == 0 {
		maxBytes = DefaultMaxCommittedArtifactBytes
	}
	if maxBytes <= 0 || maxBytes > DefaultMaxCommittedArtifactBytes {
		return nil, errors.New("artifact byte limit is outside policy")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, errors.New("artifact root is invalid")
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, fmt.Errorf("create artifact root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(absolute) {
		return nil, errors.New("artifact root may not traverse a symlink")
	}
	return &DirectoryArtifactCommitter{root: absolute, maxBytes: maxBytes}, nil
}

func (committer *DirectoryArtifactCommitter) Commit(ctx context.Context, artifact ExportedArtifact) (CommittedArtifact, error) {
	if err := validateExportedArtifact(artifact, committer.maxBytes); err != nil {
		return CommittedArtifact{}, err
	}
	digestHex := strings.TrimPrefix(artifact.Digest, "sha256:")
	parent := filepath.Join(committer.root, artifact.OrganizationID, artifact.BuildID, artifact.OutputName)
	if err := ensureOwnedDirectoryTree(committer.root, parent); err != nil {
		return CommittedArtifact{}, err
	}
	destination := filepath.Join(parent, digestHex)
	if committed, exists, err := inspectCommittedArtifact(destination, artifact); exists || err != nil {
		return committed, err
	}

	temporary, err := os.MkdirTemp(parent, ".commit-*")
	if err != nil {
		return CommittedArtifact{}, fmt.Errorf("create artifact staging directory: %w", err)
	}
	defer removeArtifactTree(temporary)
	stagedPath := filepath.Join(temporary, artifactFileName(artifact.Kind))
	if artifact.Kind == "oci_image" {
		if err := copyArtifactFile(ctx, artifact.Path, stagedPath, 0o600); err != nil {
			return CommittedArtifact{}, err
		}
	} else if err := copyArtifactDirectory(ctx, artifact.Path, stagedPath); err != nil {
		return CommittedArtifact{}, err
	}
	stagedDigest, stagedSize, err := exportedArtifactDigest(stagedPath, artifact.Kind)
	if err != nil || stagedDigest != artifact.Digest || stagedSize != artifact.Size {
		return CommittedArtifact{}, errors.New("committed artifact copy changed identity")
	}
	if err := protectCommittedTree(temporary); err != nil {
		return CommittedArtifact{}, err
	}
	if err := os.Rename(temporary, destination); err != nil {
		if committed, exists, inspectErr := inspectCommittedArtifact(destination, artifact); exists || inspectErr != nil {
			return committed, inspectErr
		}
		return CommittedArtifact{}, fmt.Errorf("publish committed artifact: %w", err)
	}
	if err := syncArtifactDirectory(parent); err != nil {
		return CommittedArtifact{}, err
	}
	committed, exists, err := inspectCommittedArtifact(destination, artifact)
	if err != nil || !exists {
		return CommittedArtifact{}, errors.New("published artifact is not retrievable")
	}
	return committed, nil
}

func validateExportedArtifact(artifact ExportedArtifact, maxBytes int64) error {
	organization, organizationErr := platformid.Parse(artifact.OrganizationID)
	project, projectErr := platformid.Parse(artifact.ProjectID)
	build, buildErr := platformid.Parse(artifact.BuildID)
	info, statErr := os.Lstat(artifact.Path)
	if organizationErr != nil || organization.Prefix() != "org" || projectErr != nil || project.Prefix() != "prj" || buildErr != nil || build.Prefix() != "bld" ||
		artifact.Attempt == 0 || !artifactOutputPattern.MatchString(artifact.OutputName) ||
		(artifact.Kind != "oci_image" && artifact.Kind != "static_bundle") || !artifactDigestPattern.MatchString(artifact.Digest) ||
		artifact.Size < 0 || artifact.Size > maxBytes || artifact.Path == "" || statErr != nil || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("exported artifact identity is invalid")
	}
	if (artifact.Kind == "oci_image" && !info.Mode().IsRegular()) || (artifact.Kind == "static_bundle" && !info.IsDir()) {
		return errors.New("exported artifact shape does not match its kind")
	}
	actualDigest, actualSize, err := exportedArtifactDigest(artifact.Path, artifact.Kind)
	if err != nil || actualDigest != artifact.Digest || actualSize != artifact.Size {
		return errors.New("exported artifact does not match its declared identity")
	}
	return nil
}

// ValidateExportedArtifact exposes the exact build-output validation used by
// commit adapters without exposing filesystem implementation details.
func ValidateExportedArtifact(artifact ExportedArtifact, maxBytes int64) error {
	return validateExportedArtifact(artifact, maxBytes)
}

func inspectCommittedArtifact(destination string, artifact ExportedArtifact) (CommittedArtifact, bool, error) {
	info, err := os.Lstat(destination)
	if errors.Is(err, os.ErrNotExist) {
		return CommittedArtifact{}, false, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return CommittedArtifact{}, true, errors.New("committed artifact location is invalid")
	}
	artifactPath := filepath.Join(destination, artifactFileName(artifact.Kind))
	artifactInfo, err := os.Lstat(artifactPath)
	if err != nil || artifactInfo.Mode()&os.ModeSymlink != 0 {
		return CommittedArtifact{}, true, errors.New("committed artifact is absent or unsafe")
	}
	digest, size, err := exportedArtifactDigest(artifactPath, artifact.Kind)
	if err != nil || digest != artifact.Digest || size != artifact.Size {
		return CommittedArtifact{}, true, errors.New("committed artifact identity conflicts with existing content")
	}
	return CommittedArtifact{
		Reference: artifactReference(artifact), Path: artifactPath, Digest: digest, Size: size,
	}, true, nil
}

func artifactFileName(kind string) string {
	if kind == "oci_image" {
		return "artifact.oci.tar"
	}
	return "bundle"
}

func copyArtifactFile(ctx context.Context, sourcePath, destinationPath string, mode os.FileMode) error {
	sourceInfo, err := os.Lstat(sourcePath)
	if err != nil || !sourceInfo.Mode().IsRegular() || sourceInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("artifact source file is unsafe")
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("open artifact source: %w", err)
	}
	defer source.Close()
	openedInfo, err := source.Stat()
	if err != nil || !os.SameFile(sourceInfo, openedInfo) {
		return errors.New("artifact source changed while opening")
	}
	destination, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("create artifact destination: %w", err)
	}
	_, copyErr := copyWithContext(ctx, destination, source)
	syncErr := destination.Sync()
	closeErr := destination.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("copy artifact file failed")
	}
	return nil
}

func copyArtifactDirectory(ctx context.Context, sourceRoot, destinationRoot string) error {
	if err := os.Mkdir(destinationRoot, 0o700); err != nil {
		return fmt.Errorf("create artifact bundle: %w", err)
	}
	fileCount := 0
	return filepath.WalkDir(sourceRoot, func(sourcePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if sourcePath == sourceRoot {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("artifact bundle contains a symlink")
		}
		relative, err := filepath.Rel(sourceRoot, sourcePath)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("artifact bundle path escaped its root")
		}
		destinationPath := filepath.Join(destinationRoot, relative)
		if entry.IsDir() {
			return os.Mkdir(destinationPath, 0o700)
		}
		if !entry.Type().IsRegular() {
			return errors.New("artifact bundle contains a non-regular file")
		}
		fileCount++
		if fileCount > MaxCommittedArtifactFiles {
			return errors.New("artifact bundle file limit exceeded")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		mode := normalizedArtifactMode(info.Mode()) | 0o200
		return copyArtifactFile(ctx, sourcePath, destinationPath, mode)
	})
}

func ensureOwnedDirectoryTree(root, target string) error {
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return errors.New("artifact destination escaped its root")
	}
	current := root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		if err := os.Mkdir(current, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create artifact destination: %w", err)
		}
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("artifact destination contains an unsafe component")
		}
	}
	return nil
}

func protectCommittedTree(root string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	var directories []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			directories = append(directories, path)
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		return os.Chmod(path, normalizedArtifactMode(info.Mode()))
	})
	if err != nil {
		return fmt.Errorf("protect committed artifact: %w", err)
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if err := os.Chmod(directories[index], 0o500); err != nil {
			return fmt.Errorf("protect committed artifact directory: %w", err)
		}
	}
	return nil
}

func removeArtifactTree(root string) {
	if runtime.GOOS != "windows" {
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr == nil {
				if entry.IsDir() {
					_ = os.Chmod(path, 0o700)
				} else {
					_ = os.Chmod(path, 0o600)
				}
			}
			return nil
		})
	}
	_ = os.RemoveAll(root)
}

func syncArtifactDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open artifact directory: %w", err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return errors.New("sync artifact directory failed")
	}
	return nil
}

func artifactReference(artifact ExportedArtifact) string {
	return (&url.URL{
		Scheme: "lrail-artifact", Host: artifact.OrganizationID,
		Path: "/" + artifact.BuildID + "/" + artifact.OutputName + "/" + strings.TrimPrefix(artifact.Digest, "sha256:"),
	}).String()
}
