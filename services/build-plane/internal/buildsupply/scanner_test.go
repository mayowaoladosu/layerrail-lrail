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
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	metadata := writeScannerFixture(t, cache, "metadata.json", `{"Version":2,"NextUpdate":"2026-07-14T00:00:00Z","UpdatedAt":"2026-07-13T00:00:00Z","DownloadedAt":"2026-07-13T01:00:00Z"}`)
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
	analysis, err := scanner.Analyze(t.Context(), ScanRequest{
		OCIPath: request.OCIPath, OCIArchiveDigest: request.OCIArchiveDigest, OCIArchiveSize: request.OCIArchiveSize,
		ManifestDigest: request.Identity.ManifestDigest, OutputName: "api", TargetPlatform: "linux/amd64", SyftVersion: "1.46.0", TrivyVersion: "0.72.0",
	})
	if err != nil || len(analysis.SBOM) == 0 || len(analysis.Scan) == 0 || len(runner.commands) != 4 {
		t.Fatalf("analysis=%#v commands=%#v error=%v", analysis, runner.commands, err)
	}
	trivyCommand := strings.Join(runner.commands[3].arguments, " ")
	for _, required := range []string{"--offline-scan", "--skip-db-update", "--skip-check-update", "--scanners vuln,secret,license,misconfig", "@" + request.Identity.ManifestDigest} {
		if !strings.Contains(trivyCommand, required) {
			t.Fatalf("Trivy command lacks %q: %s", required, trivyCommand)
		}
	}
	for _, command := range runner.commands {
		if strings.Contains(strings.Join(command.environment, "\x00"), "TOKEN") || strings.Contains(strings.Join(command.environment, "\x00"), "PASSWORD") {
			t.Fatalf("tool environment contains credential-like data: %#v", command.environment)
		}
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
