package buildworker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
)

func cacheLock() llbcompiler.DefinitionLock {
	return llbcompiler.DefinitionLock{
		Version: llbcompiler.CurrentLockVersion, CompilerVersion: "0.1.0",
		PolicyDigest: testPolicyDigest,
		Caches:       []llbcompiler.CacheCapability{{NodeID: "n2", Name: "modules", Target: "/cache", Sharing: "locked", Scope: "organization", Namespace: "lrail-cache-" + strings.Repeat("a", 64)}},
	}
}

func cacheProvider(t *testing.T) *DirectoryCacheProvider {
	t.Helper()
	root := filepath.Join(t.TempDir(), "cache")
	provider, err := NewDirectoryCacheProvider(root)
	if err != nil {
		t.Fatalf("NewDirectoryCacheProvider: %v", err)
	}
	t.Cleanup(func() { removeArtifactTree(root) })
	return provider
}

func writeFakeBuildKitCache(t *testing.T, root string) {
	t.Helper()
	config := []byte(`{"layers":[]}`)
	configDigest := digestBytes(config)
	configPath := filepath.Join(root, "blobs", "sha256", strings.TrimPrefix(configDigest, "sha256:"))
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatalf("Write config: %v", err)
	}
	manifest := map[string]any{
		"schemaVersion": 2, "mediaType": ocispecs.MediaTypeImageManifest,
		"config": map[string]any{"mediaType": "application/vnd.buildkit.cacheconfig.v0", "digest": configDigest, "size": len(config)},
		"layers": []any{},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal manifest: %v", err)
	}
	manifestDigest := digestBytes(manifestBytes)
	manifestPath := filepath.Join(root, "blobs", "sha256", strings.TrimPrefix(manifestDigest, "sha256:"))
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("Write manifest: %v", err)
	}
	layout := map[string]any{"imageLayoutVersion": "1.0.0"}
	index := map[string]any{
		"schemaVersion": 2, "mediaType": ocispecs.MediaTypeImageIndex,
		"manifests": []any{map[string]any{"mediaType": ocispecs.MediaTypeImageManifest, "digest": manifestDigest, "size": len(manifestBytes)}},
	}
	for name, value := range map[string]any{"oci-layout": layout, "index.json": index} {
		contents, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if err := os.WriteFile(filepath.Join(root, name), contents, 0o600); err != nil {
			t.Fatalf("Write %s: %v", name, err)
		}
	}
}

func TestDirectoryCacheProviderPublishesImmutableVerifiedRecord(t *testing.T) {
	t.Parallel()
	provider := cacheProvider(t)
	lease, err := provider.Acquire(context.Background(), cacheLock(), testBuildID, "site", 1)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if len(lease.Imports()) != 0 || len(lease.Exports()) != 1 || lease.Exports()[0].Type != "local" {
		t.Fatalf("initial lease imports=%#v exports=%#v", lease.Imports(), lease.Exports())
	}
	writeFakeBuildKitCache(t, lease.Exports()[0].Attrs["dest"])
	if err := lease.Complete(true); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	next, err := provider.Acquire(context.Background(), cacheLock(), testBuildID, "site", 2)
	if err != nil {
		t.Fatalf("second Acquire: %v", err)
	}
	if len(next.Imports()) != 1 || next.Imports()[0].Type != "local" || len(next.Exports()) != 1 {
		t.Fatalf("next imports=%#v exports=%#v", next.Imports(), next.Exports())
	}
	if strings.Contains(next.Imports()[0].Attrs["src"], "staging") {
		t.Fatalf("cache import is mutable staging: %#v", next.Imports())
	}
	if err := next.Complete(false); err != nil {
		t.Fatalf("abort cache lease: %v", err)
	}
}

func TestDirectoryCacheProviderRejectsPoisonedRecord(t *testing.T) {
	t.Parallel()
	provider := cacheProvider(t)
	lease, err := provider.Acquire(context.Background(), cacheLock(), testBuildID, "site", 1)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	writeFakeBuildKitCache(t, lease.Exports()[0].Attrs["dest"])
	if err := lease.Complete(true); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	currentEntries, err := filepath.Glob(filepath.Join(provider.root, "*", "records", "*", "index.json"))
	if err != nil || len(currentEntries) != 1 {
		t.Fatalf("cache index paths = %#v, %v", currentEntries, err)
	}
	if err := os.Chmod(currentEntries[0], 0o600); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if err := os.WriteFile(currentEntries[0], []byte(`{"schemaVersion":2,"manifests":[]}`), 0o600); err != nil {
		t.Fatalf("poison cache: %v", err)
	}
	if _, err := provider.Acquire(context.Background(), cacheLock(), testBuildID, "site", 2); err == nil {
		t.Fatal("expected poisoned cache rejection")
	}
}

func TestDirectoryCacheProviderRejectsUnreferencedBlob(t *testing.T) {
	t.Parallel()
	provider := cacheProvider(t)
	lease, err := provider.Acquire(context.Background(), cacheLock(), testBuildID, "site", 1)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	root := lease.Exports()[0].Attrs["dest"]
	writeFakeBuildKitCache(t, root)
	extra := []byte("unreferenced-cache-content")
	extraPath := filepath.Join(root, "blobs", "sha256", strings.TrimPrefix(digestBytes(extra), "sha256:"))
	if err := os.WriteFile(extraPath, extra, 0o600); err != nil {
		t.Fatalf("Write extra blob: %v", err)
	}
	if err := lease.Complete(true); err == nil {
		t.Fatal("expected unreferenced cache blob rejection")
	}
}

func TestRejectingCacheProviderFailsClosed(t *testing.T) {
	t.Parallel()
	if _, err := (RejectingCacheProvider{}).Acquire(context.Background(), cacheLock(), testBuildID, "site", 1); err == nil {
		t.Fatal("expected signed cache rejection")
	}
	lock := cacheLock()
	lock.Caches = nil
	lease, err := (RejectingCacheProvider{}).Acquire(context.Background(), lock, testBuildID, "site", 1)
	if err != nil || len(lease.Imports()) != 0 || len(lease.Exports()) != 0 || lease.Complete(true) != nil {
		t.Fatalf("empty cache lease = %#v, %v", lease, err)
	}
}

func TestDirectoryCacheProviderDoesNotExportSecretBearingGraphs(t *testing.T) {
	t.Parallel()
	lock := cacheLock()
	lock.Secrets = []llbcompiler.SecretCapability{{
		NodeID: "n3", Name: "token", MountID: "token", Target: "/run/secrets/token", Required: true,
	}}
	lease, err := cacheProvider(t).Acquire(context.Background(), lock, testBuildID, "site", 1)
	if err != nil || len(lease.Imports()) != 0 || len(lease.Exports()) != 0 || lease.Complete(true) != nil {
		t.Fatalf("secret-bearing cache lease=%#v error=%v", lease, err)
	}
}
