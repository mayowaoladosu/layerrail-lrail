package buildsupply

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type scannerCommand struct {
	executable  string
	arguments   []string
	environment []string
}

type fakeCommandRunner struct {
	commands []scannerCommand
	sbom     []byte
	trivy    []byte
}

func (runner *fakeCommandRunner) Run(_ context.Context, executable string, arguments, environment []string, _ int64) ([]byte, error) {
	runner.commands = append(runner.commands, scannerCommand{executable: executable, arguments: append([]string(nil), arguments...), environment: append([]string(nil), environment...)})
	switch {
	case len(arguments) == 1 && arguments[0] == "version":
		return []byte("Application: syft\nVersion: 1.46.0\n"), nil
	case len(arguments) == 1 && arguments[0] == "--version":
		return []byte("Version: 0.72.0\n"), nil
	case len(arguments) > 0 && arguments[0] == "scan":
		return runner.sbom, nil
	case len(arguments) > 0 && arguments[0] == "image":
		return runner.trivy, nil
	default:
		return nil, fmt.Errorf("unexpected command")
	}
}

func TestCommandScannerUsesOfflinePinnedToolsAndVerifiedLayout(t *testing.T) {
	t.Parallel()
	signer := newTestSigner(t)
	request := supplyRequest(t, signer)
	root := t.TempDir()
	syft := writeScannerFixture(t, root, "syft", "binary")
	trivy := writeScannerFixture(t, root, "trivy", "binary")
	cache := filepath.Join(root, "cache")
	work := filepath.Join(root, "work")
	if err := os.Mkdir(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	metadata := writeScannerFixture(t, cache, "metadata.json", `{"Version":2,"NextUpdate":"2026-07-14T00:00:00Z","UpdatedAt":"2026-07-13T00:00:00Z","DownloadedAt":"2026-07-13T01:00:00Z"}`)
	_ = writeScannerFixture(t, cache, "trivy.db", "verified vulnerability database")
	_ = writeScannerFixture(t, cache, "trivy.db.sha256", "sha256:"+strings.Repeat("d", 64)+"\n")
	secretConfig := writeScannerFixture(t, root, "trivy-secret.yaml", "rules: []\n")
	runner := &fakeCommandRunner{
		sbom:  []byte(`{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"random","documentNamespace":"https://random.invalid/uuid","creationInfo":{"created":"2026-07-13T11:00:00Z","creators":["Tool: syft-1.46.0"]},"packages":[]}`),
		trivy: []byte(`{"SchemaVersion":2,"Results":[]}`),
	}
	scanner, err := newCommandScanner(CommandScannerConfig{
		SyftPath: syft, TrivyPath: trivy, TrivyCacheDir: cache, TrivyDBMetadata: metadata,
		SecretConfigPath: secretConfig, WorkRoot: work, Clock: func() time.Time { return time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC) },
	}, runner)
	if err != nil {
		t.Fatalf("newCommandScanner: %v", err)
	}
	if info, statErr := os.Stat(work); statErr != nil || !info.IsDir() {
		t.Fatalf("scanner workspace was not created safely: %v", statErr)
	}
	analysis, err := scanner.Analyze(t.Context(), ScanRequest{
		OCIPath: request.OCIPath, OCIArchiveDigest: request.OCIArchiveDigest, OCIArchiveSize: request.OCIArchiveSize,
		ManifestDigest: request.Identity.ManifestDigest, OutputName: "api", TargetPlatform: "linux/amd64", SyftVersion: "1.46.0", TrivyVersion: "0.72.0",
	})
	if err != nil || len(analysis.SBOM) == 0 || len(analysis.Scan) == 0 || len(runner.commands) != 5 {
		t.Fatalf("analysis=%#v commands=%#v error=%v", analysis, runner.commands, err)
	}
	artifactCommand := strings.Join(runner.commands[3].arguments, " ")
	for _, required := range []string{"--offline-scan", "--skip-db-update", "--skip-check-update", "--scanners vuln,secret,license", "--image-config-scanners secret", "@" + request.Identity.ManifestDigest} {
		if !strings.Contains(artifactCommand, required) {
			t.Fatalf("artifact Trivy command lacks %q: %s", required, artifactCommand)
		}
	}
	configurationCommand := strings.Join(runner.commands[4].arguments, " ")
	for _, required := range []string{"--scanners misconfig", "--image-config-scanners misconfig", "--skip-files **", "@" + request.Identity.ManifestDigest} {
		if !strings.Contains(configurationCommand, required) {
			t.Fatalf("configuration Trivy command lacks %q: %s", required, configurationCommand)
		}
	}
	for _, command := range runner.commands {
		if strings.Contains(strings.Join(command.environment, "\x00"), "TOKEN") || strings.Contains(strings.Join(command.environment, "\x00"), "PASSWORD") {
			t.Fatalf("tool environment contains credential-like data: %#v", command.environment)
		}
	}
}

func TestMergeTrivyReportsPreservesArtifactAndImageConfigFindings(t *testing.T) {
	t.Parallel()
	artifact := []byte(`{"SchemaVersion":2,"Results":[{"Target":"app","Vulnerabilities":[{"VulnerabilityID":"CVE-test","PkgID":"pkg@1","PkgName":"pkg","InstalledVersion":"1","Severity":"LOW"}]}]}`)
	configuration := []byte(`{"SchemaVersion":2,"Results":[{"Target":"app","Misconfigurations":[{"ID":"DS-0026","Title":"No HEALTHCHECK defined","Severity":"LOW","Status":"FAIL"}]}]}`)
	merged, err := mergeTrivyReports(artifact, configuration)
	if err != nil || !strings.Contains(string(merged), "CVE-test") || !strings.Contains(string(merged), "DS-0026") {
		t.Fatalf("merged=%s error=%v", merged, err)
	}
	if _, err := mergeTrivyReports(artifact, []byte(`{"SchemaVersion":1,"Results":[]}`)); err == nil {
		t.Fatal("expected unsupported report rejection")
	}
}

func TestCommandScannerSnapshotsVersionedDatabaseAcrossAtomicRotation(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	syft := writeScannerFixture(t, root, "syft", "binary")
	trivy := writeScannerFixture(t, root, "trivy", "binary")
	secretConfig := writeScannerFixture(t, root, "trivy-secret.yaml", "rules: []\n")
	first := writeScannerDatabaseGeneration(t, root, ".db-Ab12Cd34", "a")
	second := writeScannerDatabaseGeneration(t, root, ".db-Ef56Gh78", "b")
	current := filepath.Join(root, "current")
	if err := os.Symlink(filepath.Base(first), current); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	scanner, err := newCommandScanner(CommandScannerConfig{
		SyftPath: syft, TrivyPath: trivy, TrivyCacheDir: current,
		TrivyDBMetadata: filepath.Join(current, "db", "metadata.json"), SecretConfigPath: secretConfig,
		WorkRoot: filepath.Join(root, "work"), Clock: func() time.Time { return time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC) },
	}, &fakeCommandRunner{})
	if err != nil {
		t.Fatalf("newCommandScanner: %v", err)
	}
	paths, err := scanner.trivyDatabasePaths()
	if err != nil || paths.Cache != first {
		t.Fatalf("paths=%#v error=%v", paths, err)
	}
	if err := os.Remove(current); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(second), current); err != nil {
		t.Fatal(err)
	}
	identity, err := scanner.trivyDatabaseIdentity(paths)
	if err != nil || identity.Digest != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("snapshot identity=%#v error=%v", identity, err)
	}
	newPaths, err := scanner.trivyDatabasePaths()
	if err != nil || newPaths.Cache != second {
		t.Fatalf("rotated paths=%#v error=%v", newPaths, err)
	}
}

func TestCommandScannerRejectsStaleDatabaseBeforeToolAnalysis(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	syft := writeScannerFixture(t, root, "syft", "binary")
	trivy := writeScannerFixture(t, root, "trivy", "binary")
	cache := filepath.Join(root, "cache")
	work := filepath.Join(root, "work")
	_ = os.Mkdir(cache, 0o700)
	_ = os.Mkdir(work, 0o700)
	metadata := writeScannerFixture(t, cache, "metadata.json", `{"Version":2,"NextUpdate":"2026-07-11T00:00:00Z","UpdatedAt":"2026-07-10T00:00:00Z","DownloadedAt":"2026-07-10T01:00:00Z"}`)
	_ = writeScannerFixture(t, cache, "trivy.db", "stale vulnerability database")
	_ = writeScannerFixture(t, cache, "trivy.db.sha256", "sha256:"+strings.Repeat("e", 64)+"\n")
	secretConfig := writeScannerFixture(t, root, "trivy-secret.yaml", "rules: []\n")
	runner := &fakeCommandRunner{}
	scanner, err := newCommandScanner(CommandScannerConfig{
		SyftPath: syft, TrivyPath: trivy, TrivyCacheDir: cache, TrivyDBMetadata: metadata,
		SecretConfigPath: secretConfig, WorkRoot: work, MaxDBAge: 24 * time.Hour,
		Clock: func() time.Time { return time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC) },
	}, runner)
	if err != nil {
		t.Fatal(err)
	}
	if err := scanner.CheckTools(t.Context(), "1.46.0", "0.72.0"); err == nil || len(runner.commands) != 2 {
		t.Fatalf("error=%v commands=%#v", err, runner.commands)
	}
}

func writeScannerFixture(t *testing.T, root, name, contents string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeScannerDatabaseGeneration(t *testing.T, root, name, digestCharacter string) string {
	t.Helper()
	generation := filepath.Join(root, name)
	database := filepath.Join(generation, "db")
	if err := os.MkdirAll(database, 0o700); err != nil {
		t.Fatal(err)
	}
	_ = writeScannerFixture(t, database, "metadata.json", `{"Version":2,"NextUpdate":"2026-07-14T00:00:00Z","UpdatedAt":"2026-07-13T00:00:00Z","DownloadedAt":"2026-07-13T01:00:00Z"}`)
	_ = writeScannerFixture(t, database, "trivy.db", "versioned vulnerability database "+name)
	_ = writeScannerFixture(t, database, "trivy.db.sha256", "sha256:"+strings.Repeat(digestCharacter, 64)+"\n")
	return generation
}
