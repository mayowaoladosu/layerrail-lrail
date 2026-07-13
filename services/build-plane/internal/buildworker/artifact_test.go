package buildworker

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

const testBuildID = "bld_019b01da-7e31-7000-8000-000000000001"
const testOrgID = "org_019b01da-7e31-7000-8000-000000000003"
const testArtifactProjectID = "prj_019b01da-7e31-7000-8000-000000000004"

func artifactCommitter(t *testing.T, maxBytes int64) *DirectoryArtifactCommitter {
	t.Helper()
	root := filepath.Join(t.TempDir(), "artifacts")
	committer, err := NewDirectoryArtifactCommitter(root, maxBytes)
	if err != nil {
		t.Fatalf("NewDirectoryArtifactCommitter: %v", err)
	}
	t.Cleanup(func() { removeArtifactTree(root) })
	return committer
}

func TestDirectoryArtifactCommitterCommitsOCIIdempotently(t *testing.T) {
	t.Parallel()
	source := filepath.Join(t.TempDir(), "artifact.tar")
	contents := []byte("fake-oci-layout-for-unit-test")
	if err := os.WriteFile(source, contents, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	artifact := ExportedArtifact{
		OrganizationID: testOrgID, ProjectID: testArtifactProjectID, BuildID: testBuildID, Attempt: 1,
		OutputName: "api", Kind: "oci_image", Path: source,
		Digest: digestBytes(contents), Size: int64(len(contents)),
	}
	committer := artifactCommitter(t, 0)
	first, err := committer.Commit(context.Background(), artifact)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	second, err := committer.Commit(context.Background(), artifact)
	if err != nil {
		t.Fatalf("idempotent Commit: %v", err)
	}
	if first != second || !strings.HasPrefix(first.Reference, "lrail-artifact://"+testOrgID+"/"+testBuildID+"/api/") || strings.Contains(first.Reference, filepath.ToSlash(committer.root)) || first.Path == source {
		t.Fatalf("committed artifact = %#v, second = %#v", first, second)
	}
	persisted, err := os.ReadFile(first.Path)
	if err != nil || string(persisted) != string(contents) {
		t.Fatalf("persisted artifact = %q, %v", persisted, err)
	}
}

func TestDirectoryArtifactCommitterPreservesStaticIdentity(t *testing.T) {
	t.Parallel()
	source := t.TempDir()
	if err := os.Mkdir(filepath.Join(source, "bin"), 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(source, "index.html"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("Write index: %v", err)
	}
	if err := os.WriteFile(filepath.Join(source, "bin", "run"), []byte("run"), 0o700); err != nil {
		t.Fatalf("Write executable: %v", err)
	}
	digest, size, err := directoryDigest(source)
	if err != nil {
		t.Fatalf("directoryDigest: %v", err)
	}
	artifact := ExportedArtifact{
		OrganizationID: testOrgID, ProjectID: testArtifactProjectID, BuildID: testBuildID, Attempt: 1,
		OutputName: "site", Kind: "static_bundle", Path: source, Digest: digest, Size: size,
	}
	committed, err := artifactCommitter(t, 0).Commit(context.Background(), artifact)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	actualDigest, actualSize, err := directoryDigest(committed.Path)
	if err != nil || actualDigest != digest || actualSize != size {
		t.Fatalf("committed identity = %s/%d, %v", actualDigest, actualSize, err)
	}
}

func TestDirectoryArtifactCommitterRejectsTamperingLimitsAndCancellation(t *testing.T) {
	t.Parallel()
	source := filepath.Join(t.TempDir(), "artifact.tar")
	contents := []byte("artifact")
	if err := os.WriteFile(source, contents, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	valid := ExportedArtifact{
		OrganizationID: testOrgID, ProjectID: testArtifactProjectID, BuildID: testBuildID, Attempt: 1,
		OutputName: "api", Kind: "oci_image", Path: source,
		Digest: digestBytes(contents), Size: int64(len(contents)),
	}
	tests := map[string]func(ExportedArtifact) (ArtifactCommitter, ExportedArtifact, context.Context){
		"digest": func(artifact ExportedArtifact) (ArtifactCommitter, ExportedArtifact, context.Context) {
			artifact.Digest = testIRDigest
			return artifactCommitter(t, 0), artifact, context.Background()
		},
		"scope": func(artifact ExportedArtifact) (ArtifactCommitter, ExportedArtifact, context.Context) {
			artifact.OrganizationID = "org_invalid"
			return artifactCommitter(t, 0), artifact, context.Background()
		},
		"limit": func(artifact ExportedArtifact) (ArtifactCommitter, ExportedArtifact, context.Context) {
			return artifactCommitter(t, int64(len(contents)-1)), artifact, context.Background()
		},
		"canceled": func(artifact ExportedArtifact) (ArtifactCommitter, ExportedArtifact, context.Context) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return artifactCommitter(t, 0), artifact, ctx
		},
	}
	for name, prepare := range tests {
		prepare := prepare
		t.Run(name, func(t *testing.T) {
			committer, artifact, ctx := prepare(valid)
			if _, err := committer.Commit(ctx, artifact); err == nil {
				t.Fatal("expected commit rejection")
			}
		})
	}
}

func TestDirectoryArtifactCommitterSerializesSameDigest(t *testing.T) {
	t.Parallel()
	source := filepath.Join(t.TempDir(), "artifact.tar")
	contents := []byte("concurrent-artifact")
	if err := os.WriteFile(source, contents, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	artifact := ExportedArtifact{
		OrganizationID: testOrgID, ProjectID: testArtifactProjectID, BuildID: testBuildID, Attempt: 1,
		OutputName: "api", Kind: "oci_image", Path: source,
		Digest: digestBytes(contents), Size: int64(len(contents)),
	}
	committer := artifactCommitter(t, 0)
	const workers = 16
	results := make(chan CommittedArtifact, workers)
	errorsSeen := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := committer.Commit(context.Background(), artifact)
			results <- result
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(results)
	close(errorsSeen)
	var expected CommittedArtifact
	for result := range results {
		if expected.Reference == "" {
			expected = result
		}
		if result != expected {
			t.Fatalf("result mismatch: %#v != %#v", result, expected)
		}
	}
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("Commit: %v", err)
		}
	}
}

func TestDirectoryArtifactCommitterRejectsSymlinkBundle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ordinary Windows test users cannot create symlinks")
	}
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "target"), []byte("target"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink("target", filepath.Join(source, "link")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	artifact := ExportedArtifact{
		OrganizationID: testOrgID, ProjectID: testArtifactProjectID, BuildID: testBuildID, Attempt: 1,
		OutputName: "site", Kind: "static_bundle", Path: source,
		Digest: testIRDigest, Size: 1,
	}
	if _, err := artifactCommitter(t, 0).Commit(context.Background(), artifact); err == nil {
		t.Fatal("expected symlink rejection")
	}
}
