package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRealTrivyDatabaseUpdaterPublishesAtomicBoundedGenerations(t *testing.T) {
	if os.Getenv("LRAIL_TRIVY_DB_INTEGRATION") != "1" {
		t.Skip("set LRAIL_TRIVY_DB_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	image := os.Getenv("LRAIL_TRIVY_DB_UPDATER_IMAGE")
	if image == "" {
		t.Fatal("LRAIL_TRIVY_DB_UPDATER_IMAGE is required")
	}
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "platform", "kubernetes", "build-cell", "base", "scripts", "update-trivy-db.sh")
	if info, err := os.Stat(script); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("updater script is unavailable: %v", err)
	}
	volume := fmt.Sprintf("lrail-wp040-trivy-db-%d", os.Getpid())
	removeTrivyDBVolume(context.Background(), volume)
	if output, err := exec.CommandContext(ctx, "docker", "volume", "create", volume).CombinedOutput(); err != nil {
		t.Fatalf("create updater volume: %v: %s", err, output)
	}
	t.Cleanup(func() { removeTrivyDBVolume(context.Background(), volume) })
	for attempt := 0; attempt < 2; attempt++ {
		arguments := []string{
			"run", "--rm", "-e", "TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db:2",
			"-v", volume + ":/var/lib/lrail-trivy", "-v", script + ":/etc/lrail-trivy/update.sh:ro",
			"--entrypoint", "/bin/sh", image, "/etc/lrail-trivy/update.sh",
		}
		if output, err := exec.CommandContext(ctx, "docker", arguments...).CombinedOutput(); err != nil {
			t.Fatalf("updater attempt %d: %v: %s", attempt+1, err, output)
		}
		if attempt == 0 {
			arguments = []string{
				"run", "--rm", "-v", volume + ":/var/lib/lrail-trivy", "--entrypoint", "/bin/sh", image,
				"-ec", "mkdir -p /var/lib/lrail-trivy/.db-Orphan12/db; printf partial > /var/lib/lrail-trivy/.db-Orphan12/db/trivy.db",
			}
			if output, err := exec.CommandContext(ctx, "docker", arguments...).CombinedOutput(); err != nil {
				t.Fatalf("inject interrupted refresh residue: %v: %s", err, output)
			}
		}
	}
	verification := strings.Join([]string{
		"root=/var/lib/lrail-trivy",
		`test -L "$root/current"`, `test -L "$root/previous"`,
		`current=$(readlink "$root/current")`, `previous=$(readlink "$root/previous")`, `test "$current" != "$previous"`,
		`test -s "$root/current/db/metadata.json"`, `test -s "$root/current/db/trivy.db"`, `test -s "$root/current/db/trivy.db.sha256"`,
		`test -s "$root/previous/db/metadata.json"`, `test -s "$root/previous/db/trivy.db"`, `test -s "$root/previous/db/trivy.db.sha256"`,
		`test ! -e "$root/.db-Orphan12"`,
		`count=$(find "$root" -maxdepth 1 -type d -name ".db-*" | wc -l)`, `test "$count" -eq 2`,
		`printf "current=%s previous=%s versions=%s\n" "$current" "$previous" "$count"`,
	}, "; ")
	arguments := []string{
		"run", "--rm", "-v", volume + ":/var/lib/lrail-trivy:ro", "--entrypoint", "/bin/sh",
		image, "-ec", verification,
	}
	output, err := exec.CommandContext(ctx, "docker", arguments...).CombinedOutput()
	if err != nil {
		t.Fatalf("verify updater generations: %v: %s", err, output)
	}
	if !strings.Contains(string(output), "versions=2") {
		t.Fatalf("unexpected updater identity: %s", output)
	}
	arguments = []string{
		"run", "--rm", "-v", volume + ":/var/lib/lrail-trivy", "--entrypoint", "/bin/sh", image,
		"-ec", "ln -s /tmp /var/lib/lrail-trivy/.db-Evil1234",
	}
	if output, err := exec.CommandContext(ctx, "docker", arguments...).CombinedOutput(); err != nil {
		t.Fatalf("inject nested DB generation symlink: %v: %s", err, output)
	}
	arguments = []string{
		"run", "--rm", "-e", "TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db:2",
		"-v", volume + ":/var/lib/lrail-trivy", "-v", script + ":/etc/lrail-trivy/update.sh:ro",
		"--entrypoint", "/bin/sh", image, "/etc/lrail-trivy/update.sh",
	}
	if output, err := exec.CommandContext(ctx, "docker", arguments...).CombinedOutput(); err == nil {
		t.Fatalf("updater accepted nested DB generation symlink: %s", output)
	}
}

func removeTrivyDBVolume(ctx context.Context, name string) {
	_, _ = exec.CommandContext(ctx, "docker", "volume", "rm", "-f", name).CombinedOutput()
}
