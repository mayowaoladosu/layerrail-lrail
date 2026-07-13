package buildorchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	DetectorSchemaVersion = "detector.lrail.dev/v2"
	DetectorVersion       = "0.2.0"
	MaxDetectorOutput     = 16 << 20
)

var semanticVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
var rulesetVersionPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}\.[1-9][0-9]*$`)

type Detector interface {
	Detect(ctx context.Context, snapshotRoot, snapshotID, selectedRoot string) (DetectionResult, []byte, error)
}

type CommandDetector struct {
	Executable string
	Timeout    time.Duration
	Path       string
}

type DetectionResult struct {
	SchemaVersion       string            `json:"schema_version"`
	ProposalVersion     int               `json:"proposal_version"`
	DetectorVersion     string            `json:"detector_version"`
	RulesetVersion      string            `json:"ruleset_version"`
	SourceSnapshotID    string            `json:"source_snapshot_id"`
	SnapshotRoot        string            `json:"snapshot_root"`
	Plugins             []DetectorPlugin  `json:"plugins"`
	Services            []DetectedService `json:"services"`
	EvidenceGraph       json.RawMessage   `json:"evidence_graph"`
	Warnings            []json.RawMessage `json:"warnings"`
	Unresolved          []json.RawMessage `json:"unresolved"`
	UnsupportedFeatures []string          `json:"unsupported_features"`
	SuggestedAddons     []json.RawMessage `json:"suggested_addons"`
	FilesConsidered     []string          `json:"files_considered"`
	GeneratedManifest   json.RawMessage   `json:"generated_manifest"`
	Blocked             bool              `json:"blocked"`
}

type DetectorPlugin struct {
	Plugin  string `json:"plugin"`
	Version string `json:"version"`
}

type DetectedService struct {
	Name                string            `json:"name"`
	Root                string            `json:"root"`
	Kind                string            `json:"kind"`
	Language            string            `json:"language"`
	Framework           string            `json:"framework"`
	Runtime             DetectedRuntime   `json:"runtime"`
	Build               DetectedBuild     `json:"build"`
	Processes           []DetectedProcess `json:"processes"`
	DependsOn           []string          `json:"depends_on"`
	Confidence          float64           `json:"confidence"`
	EvidenceIDs         []string          `json:"evidence_ids"`
	UnsupportedFeatures []string          `json:"unsupported_features"`
	FilesConsidered     []string          `json:"files_considered"`
	Ambiguous           bool              `json:"ambiguous"`
}

type DetectedRuntime struct {
	Name          string  `json:"name"`
	Version       *string `json:"version"`
	VersionSource *string `json:"version_source"`
}

type DetectedBuild struct {
	Strategy       string   `json:"strategy"`
	InstallCommand []string `json:"install_command"`
	BuildCommand   []string `json:"build_command"`
	OutputPath     *string  `json:"output_path"`
	CachePaths     []string `json:"cache_paths"`
	RequiredFiles  []string `json:"required_files"`
}

type DetectedProcess struct {
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	Command    []string `json:"command"`
	Port       *int     `json:"port"`
	Protocol   string   `json:"protocol"`
	HealthPath *string  `json:"health_path"`
}

func NewCommandDetector(executable, pathValue string, timeout time.Duration) (*CommandDetector, error) {
	if executable == "" || strings.ContainsAny(executable, "\x00\r\n") || !strings.Contains(executable, "lrail-detector") {
		return nil, errors.New("detector executable is invalid")
	}
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	if timeout < time.Second || timeout > 5*time.Minute || pathValue == "" || strings.ContainsAny(pathValue, "\x00\r\n") {
		return nil, errors.New("detector execution policy is invalid")
	}
	return &CommandDetector{Executable: executable, Timeout: timeout, Path: pathValue}, nil
}

func (detector *CommandDetector) Detect(ctx context.Context, snapshotRoot, snapshotID, selectedRoot string) (DetectionResult, []byte, error) {
	if ctx == nil || snapshotRoot == "" || !validRelativePath(selectedRoot, true) {
		return DetectionResult{}, nil, errors.New("detector request is invalid")
	}
	executionContext, cancel := context.WithTimeout(ctx, detector.Timeout)
	defer cancel()
	stdout := &boundedBuffer{limit: MaxDetectorOutput}
	stderr := &boundedBuffer{limit: MaxEventMessageBytes}
	command := exec.CommandContext(executionContext, detector.Executable, snapshotRoot, "--snapshot-id", snapshotID, "--root", selectedRoot)
	command.Env = []string{"LANG=C.UTF-8", "LC_ALL=C.UTF-8", "PYTHONHASHSEED=0", "PYTHONUTF8=1", "PATH=" + detector.Path}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		if executionContext.Err() != nil {
			return DetectionResult{}, nil, executionContext.Err()
		}
		return DetectionResult{}, nil, errors.New("detector process returned an error")
	}
	raw := bytes.TrimSpace(stdout.Bytes())
	if len(raw) == 0 || len(raw) > MaxDetectorOutput {
		return DetectionResult{}, nil, errors.New("detector output is absent or oversized")
	}
	var result DetectionResult
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return DetectionResult{}, nil, errors.New("detector output violates the owned contract")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return DetectionResult{}, nil, errors.New("detector output has trailing data")
	}
	if err := result.Validate(snapshotID, selectedRoot); err != nil {
		return DetectionResult{}, nil, err
	}
	return result, append([]byte(nil), raw...), nil
}

func (result DetectionResult) Validate(snapshotID, selectedRoot string) error {
	if result.SchemaVersion != DetectorSchemaVersion || result.ProposalVersion != 1 || result.DetectorVersion != DetectorVersion ||
		!rulesetVersionPattern.MatchString(result.RulesetVersion) || result.SourceSnapshotID != snapshotID || result.SnapshotRoot != selectedRoot ||
		len(result.Services) > 64 || len(result.Plugins) == 0 || len(result.Plugins) > 32 {
		return errors.New("detector output identity or bounds are invalid")
	}
	pluginNames := make([]string, 0, len(result.Plugins))
	for _, plugin := range result.Plugins {
		if !semanticVersionPattern.MatchString(plugin.Version) || !eventKindPattern.MatchString(plugin.Plugin) {
			return errors.New("detector plugin identity is invalid")
		}
		pluginNames = append(pluginNames, plugin.Plugin)
	}
	if !slices.IsSorted(pluginNames) || len(slices.Compact(append([]string(nil), pluginNames...))) != len(pluginNames) {
		return errors.New("detector plugins are not canonical")
	}
	serviceNames := make([]string, 0, len(result.Services))
	proposalBlocked := len(result.Unresolved) != 0 || len(result.Services) == 0 || len(result.UnsupportedFeatures) != 0
	for _, service := range result.Services {
		if !outputNamePattern.MatchString(service.Name) || !validRelativePath(service.Root, true) ||
			service.Confidence < 0 || service.Confidence > 1 || len(service.Processes) == 0 || len(service.Processes) > 32 ||
			!slices.Contains([]string{"ruby", "node", "python", "go", "static", "docker"}, service.Language) ||
			service.Runtime.Name != service.Language || !slices.Contains([]string{"auto", "dockerfile", "starlark"}, service.Build.Strategy) {
			return errors.New("detector service proposal is invalid")
		}
		proposalBlocked = proposalBlocked || service.Ambiguous || len(service.UnsupportedFeatures) != 0
		serviceNames = append(serviceNames, service.Name)
	}
	proposalBlocked = proposalBlocked || result.GeneratedManifest == nil || string(result.GeneratedManifest) == "null"
	if result.Blocked != proposalBlocked {
		return errors.New("detector blocked state is inconsistent")
	}
	seenServices := make(map[string]struct{}, len(serviceNames))
	for _, name := range serviceNames {
		if _, duplicate := seenServices[name]; duplicate {
			return errors.New("detector service names are not unique")
		}
		seenServices[name] = struct{}{}
	}
	if len(seenServices) != len(serviceNames) {
		return errors.New("detector service names are not unique")
	}
	return nil
}

type boundedBuffer struct {
	contents bytes.Buffer
	limit    int
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	remaining := buffer.limit - buffer.contents.Len()
	if remaining <= 0 {
		return 0, errors.New("bounded process output exceeded")
	}
	if len(value) > remaining {
		_, _ = buffer.contents.Write(value[:remaining])
		return remaining, errors.New("bounded process output exceeded")
	}
	return buffer.contents.Write(value)
}

func (buffer *boundedBuffer) Bytes() []byte  { return buffer.contents.Bytes() }
func (buffer *boundedBuffer) String() string { return buffer.contents.String() }

var _ Detector = (*CommandDetector)(nil)
