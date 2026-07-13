package buildsupply

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
)

const DefaultScanTimeout = 15 * time.Minute

var semanticVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type CommandScannerConfig struct {
	SyftPath         string
	TrivyPath        string
	TrivyCacheDir    string
	TrivyDBMetadata  string
	SecretConfigPath string
	WorkRoot         string
	ScanTimeout      time.Duration
	MaxDBAge         time.Duration
	Clock            func() time.Time
}

type CommandScanner struct {
	config CommandScannerConfig
	runner commandRunner
}

type commandRunner interface {
	Run(ctx context.Context, executable string, arguments, environment []string, maxBytes int64) ([]byte, error)
}

type osCommandRunner struct{}

func NewCommandScanner(config CommandScannerConfig) (*CommandScanner, error) {
	return newCommandScanner(config, osCommandRunner{})
}

func newCommandScanner(config CommandScannerConfig, runner commandRunner) (*CommandScanner, error) {
	if runner == nil || !filepath.IsAbs(config.SyftPath) || !filepath.IsAbs(config.TrivyPath) ||
		!filepath.IsAbs(config.TrivyCacheDir) || !filepath.IsAbs(config.TrivyDBMetadata) ||
		!filepath.IsAbs(config.SecretConfigPath) || !filepath.IsAbs(config.WorkRoot) {
		return nil, errors.New("scanner paths must be absolute")
	}
	if config.ScanTimeout == 0 {
		config.ScanTimeout = DefaultScanTimeout
	}
	if config.MaxDBAge == 0 {
		config.MaxDBAge = 48 * time.Hour
	}
	if config.ScanTimeout < time.Minute || config.ScanTimeout > 30*time.Minute || config.MaxDBAge < time.Hour || config.MaxDBAge > 7*24*time.Hour {
		return nil, errors.New("scanner time policy is outside bounds")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	for _, path := range []string{config.SyftPath, config.TrivyPath, config.TrivyCacheDir, config.TrivyDBMetadata, config.SecretConfigPath, config.WorkRoot} {
		if err := rejectSymlinkPath(path); err != nil {
			return nil, err
		}
	}
	return &CommandScanner{config: config, runner: runner}, nil
}

func (scanner *CommandScanner) CheckTools(ctx context.Context, expectedSyft, expectedTrivy string) error {
	if !semanticVersionPattern.MatchString(expectedSyft) || !semanticVersionPattern.MatchString(expectedTrivy) {
		return errors.New("scanner expected versions are invalid")
	}
	checkContext, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	syft, err := scanner.runner.Run(checkContext, scanner.config.SyftPath, []string{"version"}, scanner.environment(), 1<<20)
	if err != nil || !versionOutputContains(syft, expectedSyft) {
		return errors.New("Syft executable version differs from policy")
	}
	trivy, err := scanner.runner.Run(checkContext, scanner.config.TrivyPath, []string{"--version"}, scanner.environment(), 1<<20)
	if err != nil || !versionOutputContains(trivy, expectedTrivy) {
		return errors.New("Trivy executable version differs from policy")
	}
	_, err = scanner.trivyDatabaseIdentity()
	return err
}

func (scanner *CommandScanner) Analyze(ctx context.Context, request ScanRequest) (Analysis, error) {
	if err := validateScanRequest(request); err != nil {
		return Analysis{}, err
	}
	if err := scanner.CheckTools(ctx, request.SyftVersion, request.TrivyVersion); err != nil {
		return Analysis{}, err
	}
	identity, err := buildworker.InspectOCIArtifact(request.OCIPath)
	if err != nil || identity.ManifestDigest != request.ManifestDigest {
		return Analysis{}, errors.New("scanner OCI subject identity differs")
	}
	work, err := os.MkdirTemp(scanner.config.WorkRoot, ".lrail-scan-*")
	if err != nil {
		return Analysis{}, errors.New("create scanner workspace")
	}
	defer os.RemoveAll(work)
	layout := filepath.Join(work, "oci")
	if err := buildworker.ExtractOCIArtifact(ctx, request.OCIPath, layout, request.OCIArchiveDigest, request.OCIArchiveSize, identity); err != nil {
		return Analysis{}, err
	}
	scanContext, cancel := context.WithTimeout(ctx, scanner.config.ScanTimeout)
	defer cancel()
	syftRaw, err := scanner.runner.Run(scanContext, scanner.config.SyftPath, []string{
		"scan", "oci-archive:" + request.OCIPath, "--quiet", "--output", "spdx-json",
		"--source-name", request.OutputName, "--source-version", request.ManifestDigest,
	}, scanner.environment(), MaxToolOutputBytes)
	if err != nil {
		return Analysis{}, errors.New("Syft SBOM generation failed")
	}
	sbom, err := normalizeSPDXDocument(syftRaw, request)
	if err != nil {
		return Analysis{}, err
	}
	trivyRaw, err := scanner.runner.Run(scanContext, scanner.config.TrivyPath, []string{
		"image", "--input", layout + "@" + request.ManifestDigest, "--format", "json",
		"--scanners", "vuln,secret,license,misconfig", "--image-config-scanners", "secret,misconfig",
		"--license-full", "--cache-dir", scanner.config.TrivyCacheDir, "--cache-backend", "memory",
		"--secret-config", scanner.config.SecretConfigPath, "--skip-db-update", "--skip-java-db-update",
		"--skip-check-update", "--skip-vex-repo-update", "--offline-scan", "--disable-telemetry",
		"--no-progress", "--quiet", "--max-image-size", "20GB",
	}, scanner.environment(), MaxToolOutputBytes)
	if err != nil {
		return Analysis{}, errors.New("Trivy image analysis failed")
	}
	database, err := scanner.trivyDatabaseIdentity()
	if err != nil {
		return Analysis{}, err
	}
	report, summary, err := normalizeTrivyReport(trivyRaw, request, database)
	if err != nil {
		return Analysis{}, err
	}
	if len(sbom) > MaxEvidenceBytes || len(report) > MaxEvidenceBytes {
		return Analysis{}, errors.New("normalized scanner evidence exceeds bounds")
	}
	return Analysis{SBOM: sbom, Scan: report, Summary: summary}, nil
}

func (scanner *CommandScanner) environment() []string {
	return []string{
		"HOME=" + scanner.config.WorkRoot,
		"SYFT_CHECK_FOR_APP_UPDATE=false",
		"SYFT_GOLANG_SEARCH_REMOTE_LICENSES=false",
		"TRIVY_DISABLE_TELEMETRY=true",
	}
}

func (scanner *CommandScanner) trivyDatabaseIdentity() (databaseIdentity, error) {
	contents, err := os.ReadFile(scanner.config.TrivyDBMetadata)
	if err != nil || len(contents) == 0 || len(contents) > 1<<20 {
		return databaseIdentity{}, errors.New("Trivy database metadata is unavailable")
	}
	var metadata struct {
		Version      int       `json:"Version"`
		UpdatedAt    time.Time `json:"UpdatedAt"`
		NextUpdate   time.Time `json:"NextUpdate"`
		DownloadedAt time.Time `json:"DownloadedAt"`
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil || metadata.Version < 2 || metadata.UpdatedAt.IsZero() || metadata.DownloadedAt.IsZero() || metadata.NextUpdate.IsZero() {
		return databaseIdentity{}, errors.New("Trivy database metadata is invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return databaseIdentity{}, errors.New("Trivy database metadata has trailing data")
	}
	now := scanner.config.Clock().UTC()
	if metadata.UpdatedAt.After(now.Add(5*time.Minute)) || now.Sub(metadata.UpdatedAt) > scanner.config.MaxDBAge {
		return databaseIdentity{}, errors.New("Trivy vulnerability database is stale")
	}
	digest := sha256.Sum256(contents)
	return databaseIdentity{Digest: "sha256:" + hex.EncodeToString(digest[:]), UpdatedAt: metadata.UpdatedAt.UTC().Format(time.RFC3339)}, nil
}

func (osCommandRunner) Run(ctx context.Context, executable string, arguments, environment []string, maxBytes int64) ([]byte, error) {
	if maxBytes < 1 || maxBytes > MaxToolOutputBytes {
		return nil, errors.New("tool output limit is invalid")
	}
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Env = append([]string(nil), environment...)
	var stdout boundedBuffer
	stdout.max = maxBytes
	var stderr boundedBuffer
	stderr.max = 64 << 10
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if err != nil || stdout.exceeded || stderr.exceeded {
		return nil, fmt.Errorf("evidence tool execution failed")
	}
	return append([]byte(nil), stdout.Bytes()...), nil
}

type boundedBuffer struct {
	bytes.Buffer
	max      int64
	exceeded bool
}

func (buffer *boundedBuffer) Write(contents []byte) (int, error) {
	remaining := buffer.max - int64(buffer.Len())
	if remaining <= 0 {
		buffer.exceeded = true
		return len(contents), nil
	}
	write := contents
	if int64(len(write)) > remaining {
		write = write[:remaining]
		buffer.exceeded = true
	}
	_, _ = buffer.Buffer.Write(write)
	return len(contents), nil
}

func validateScanRequest(request ScanRequest) error {
	if request.OCIPath == "" || !digestPattern.MatchString(request.OCIArchiveDigest) || request.OCIArchiveSize <= 0 ||
		!digestPattern.MatchString(request.ManifestDigest) || request.OutputName == "" || request.TargetPlatform == "" ||
		!semanticVersionPattern.MatchString(request.SyftVersion) || !semanticVersionPattern.MatchString(request.TrivyVersion) {
		return errors.New("scanner request identity is invalid")
	}
	return nil
}

func versionOutputContains(output []byte, expected string) bool {
	for _, field := range strings.Fields(string(output)) {
		if strings.TrimPrefix(strings.TrimSpace(field), "v") == expected {
			return true
		}
	}
	return false
}

func rejectSymlinkPath(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("scanner path is unavailable or symlinked")
	}
	return nil
}

var _ Scanner = (*CommandScanner)(nil)
