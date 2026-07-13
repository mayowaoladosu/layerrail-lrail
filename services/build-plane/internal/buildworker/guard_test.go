package buildworker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGuardRootPreparationCreatesOnlyScopedWritableDirectories(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "stale"), []byte("stale"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := emptyGuardRoot(root); err != nil {
		t.Fatalf("emptyGuardRoot: %v", err)
	}
	if err := prepareGuardDirectories(root, []string{"buildkit", "run", "tmp"}); err != nil {
		t.Fatalf("prepareGuardDirectories: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 3 {
		t.Fatalf("guard entries=%#v error=%v", entries, err)
	}
	for _, name := range []string{"buildkit", "run", "tmp"} {
		info, err := os.Stat(filepath.Join(root, name))
		if err != nil || !info.IsDir() {
			t.Fatalf("guard directory %q info=%#v error=%v", name, info, err)
		}
	}
	if err := prepareGuardDirectories(root, []string{"../outside"}); err == nil {
		t.Fatal("expected guarded directory traversal rejection")
	}
}
