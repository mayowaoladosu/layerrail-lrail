package buildsupply

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
)

type databaseIdentity struct {
	Digest         string `json:"digest"`
	MetadataDigest string `json:"metadata_digest"`
	UpdatedAt      string `json:"updated_at"`
}

type normalizedScanReport struct {
	Version           int                          `json:"version"`
	Subject           evidenceSubject              `json:"subject"`
	Tool              toolIdentity                 `json:"tool"`
	Database          databaseIdentity             `json:"database"`
	Summary           ScanSummary                  `json:"summary"`
	Vulnerabilities   []normalizedVulnerability    `json:"vulnerabilities"`
	Secrets           []normalizedSecret           `json:"secrets"`
	Misconfigurations []normalizedMisconfiguration `json:"misconfigurations"`
	Licenses          []normalizedLicense          `json:"licenses"`
}

type evidenceSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type toolIdentity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type normalizedVulnerability struct {
	ID               string `json:"id"`
	Package          string `json:"package"`
	InstalledVersion string `json:"installed_version"`
	FixedVersion     string `json:"fixed_version,omitempty"`
	Status           string `json:"status,omitempty"`
	Severity         string `json:"severity"`
	Target           string `json:"target"`
}

type normalizedSecret struct {
	RuleID    string `json:"rule_id"`
	Category  string `json:"category"`
	Severity  string `json:"severity"`
	Target    string `json:"target"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
}

type normalizedMisconfiguration struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
	Target   string `json:"target"`
	Title    string `json:"title,omitempty"`
}

type normalizedLicense struct {
	Name           string  `json:"name"`
	Classification string  `json:"classification"`
	Severity       string  `json:"severity"`
	Package        string  `json:"package,omitempty"`
	Path           string  `json:"path,omitempty"`
	Confidence     float64 `json:"confidence,omitempty"`
	Target         string  `json:"target"`
}

type trivyReport struct {
	SchemaVersion int `json:"SchemaVersion"`
	Results       []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgID            string `json:"PkgID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Status           string `json:"Status"`
			Severity         string `json:"Severity"`
		} `json:"Vulnerabilities"`
		Secrets []struct {
			RuleID    string `json:"RuleID"`
			Category  string `json:"Category"`
			Severity  string `json:"Severity"`
			StartLine int    `json:"StartLine"`
			EndLine   int    `json:"EndLine"`
		} `json:"Secrets"`
		Misconfigurations []struct {
			ID       string `json:"ID"`
			AVDID    string `json:"AVDID"`
			Title    string `json:"Title"`
			Severity string `json:"Severity"`
			Status   string `json:"Status"`
		} `json:"Misconfigurations"`
		Licenses []struct {
			Severity   string  `json:"Severity"`
			Category   string  `json:"Category"`
			PkgName    string  `json:"PkgName"`
			FilePath   string  `json:"FilePath"`
			Name       string  `json:"Name"`
			Confidence float64 `json:"Confidence"`
		} `json:"Licenses"`
	} `json:"Results"`
}

func normalizeSPDXDocument(contents []byte, request ScanRequest) ([]byte, error) {
	if len(contents) == 0 || len(contents) > MaxToolOutputBytes {
		return nil, errors.New("Syft SPDX output is absent or oversized")
	}
	var document map[string]any
	if err := decodeExternalJSON(contents, &document); err != nil {
		return nil, errors.New("Syft SPDX output is malformed")
	}
	if document["spdxVersion"] != "SPDX-2.3" || document["dataLicense"] != "CC0-1.0" || document["SPDXID"] != "SPDXRef-DOCUMENT" {
		return nil, errors.New("Syft SPDX identity is unsupported")
	}
	creation, ok := document["creationInfo"].(map[string]any)
	if !ok {
		return nil, errors.New("Syft SPDX creation identity is absent")
	}
	creators, ok := creation["creators"].([]any)
	if !ok {
		return nil, errors.New("Syft SPDX creator identity is absent")
	}
	expectedCreator := "Tool: syft-" + request.SyftVersion
	found := false
	for _, creator := range creators {
		found = found || creator == expectedCreator
	}
	if !found {
		return nil, errors.New("Syft SPDX tool version differs from policy")
	}
	creation["created"] = "1970-01-01T00:00:00Z"
	document["name"] = request.OutputName
	document["documentNamespace"] = "https://lrail.internal/sbom/" + strings.TrimPrefix(request.ManifestDigest, "sha256:")
	return canonicaljson.Marshal(document)
}

func normalizeTrivyReport(contents []byte, request ScanRequest, database databaseIdentity) ([]byte, ScanSummary, error) {
	if len(contents) == 0 || len(contents) > MaxToolOutputBytes || !digestPattern.MatchString(database.Digest) ||
		!digestPattern.MatchString(database.MetadataDigest) || database.UpdatedAt == "" {
		return nil, ScanSummary{}, errors.New("Trivy report or database identity is invalid")
	}
	var external trivyReport
	if err := decodeExternalJSON(contents, &external); err != nil || external.SchemaVersion != 2 {
		return nil, ScanSummary{}, errors.New("Trivy JSON report is malformed or unsupported")
	}
	report := normalizedScanReport{
		Version: CurrentEvidenceVersion,
		Subject: evidenceSubject{Name: request.OutputName, Digest: map[string]string{"sha256": strings.TrimPrefix(request.ManifestDigest, "sha256:")}},
		Tool:    toolIdentity{Name: "trivy", Version: request.TrivyVersion}, Database: database,
		Summary:         ScanSummary{Vulnerabilities: map[string]int{}, Misconfigurations: map[string]int{}, Licenses: map[string]int{}},
		Vulnerabilities: []normalizedVulnerability{}, Secrets: []normalizedSecret{}, Misconfigurations: []normalizedMisconfiguration{}, Licenses: []normalizedLicense{},
	}
	for _, result := range external.Results {
		target, err := boundedExternalText(result.Target, 4096)
		if err != nil {
			return nil, ScanSummary{}, errors.New("Trivy target is invalid")
		}
		for _, finding := range result.Vulnerabilities {
			severity := normalizeSeverity(finding.Severity)
			id, idErr := boundedExternalText(finding.VulnerabilityID, 256)
			pkg, pkgErr := boundedExternalText(firstNonEmpty(finding.PkgName, finding.PkgID), 1024)
			installed, installedErr := boundedExternalText(finding.InstalledVersion, 1024)
			fixed, fixedErr := boundedExternalText(finding.FixedVersion, 1024)
			status, statusErr := boundedExternalText(finding.Status, 128)
			if severity == "" || idErr != nil || pkgErr != nil || installedErr != nil || fixedErr != nil || statusErr != nil || id == "" || pkg == "" || installed == "" {
				return nil, ScanSummary{}, errors.New("Trivy vulnerability finding is invalid")
			}
			report.Vulnerabilities = append(report.Vulnerabilities, normalizedVulnerability{ID: id, Package: pkg, InstalledVersion: installed, FixedVersion: fixed, Status: status, Severity: severity, Target: target})
			report.Summary.Vulnerabilities[severity]++
		}
		for _, finding := range result.Secrets {
			severity := normalizeSeverity(finding.Severity)
			ruleID, ruleErr := boundedExternalText(finding.RuleID, 256)
			category, categoryErr := boundedExternalText(finding.Category, 256)
			if severity == "" || ruleErr != nil || categoryErr != nil || ruleID == "" || finding.StartLine < 0 || finding.EndLine < finding.StartLine {
				return nil, ScanSummary{}, errors.New("Trivy secret finding is invalid")
			}
			report.Secrets = append(report.Secrets, normalizedSecret{RuleID: ruleID, Category: category, Severity: severity, Target: target, StartLine: finding.StartLine, EndLine: finding.EndLine})
			report.Summary.Secrets++
		}
		for _, finding := range result.Misconfigurations {
			severity := normalizeSeverity(finding.Severity)
			id, idErr := boundedExternalText(firstNonEmpty(finding.ID, finding.AVDID), 256)
			status, statusErr := boundedExternalText(strings.ToUpper(finding.Status), 128)
			title, titleErr := boundedExternalText(finding.Title, 1024)
			if severity == "" || idErr != nil || statusErr != nil || titleErr != nil || id == "" || status == "" {
				return nil, ScanSummary{}, errors.New("Trivy misconfiguration finding is invalid")
			}
			report.Misconfigurations = append(report.Misconfigurations, normalizedMisconfiguration{ID: id, Severity: severity, Status: status, Target: target, Title: title})
			if status != "PASS" {
				report.Summary.Misconfigurations[severity]++
			}
		}
		for _, finding := range result.Licenses {
			severity := normalizeSeverity(finding.Severity)
			name, nameErr := boundedExternalText(finding.Name, 1024)
			classification, classificationErr := boundedExternalText(finding.Category, 128)
			pkg, pkgErr := boundedExternalText(finding.PkgName, 1024)
			filePath, pathErr := boundedExternalText(finding.FilePath, 4096)
			if severity == "" || nameErr != nil || classificationErr != nil || pkgErr != nil || pathErr != nil || name == "" || classification == "" || finding.Confidence < 0 || finding.Confidence > 1 {
				return nil, ScanSummary{}, errors.New("Trivy license finding is invalid")
			}
			report.Licenses = append(report.Licenses, normalizedLicense{Name: name, Classification: classification, Severity: severity, Package: pkg, Path: filePath, Confidence: finding.Confidence, Target: target})
			report.Summary.Licenses[classification]++
		}
	}
	sortNormalizedReport(&report)
	normalized, err := canonicaljson.Marshal(report)
	if err != nil {
		return nil, ScanSummary{}, errors.New("canonicalize normalized Trivy report")
	}
	return normalized, report.Summary, nil
}

func sortNormalizedReport(report *normalizedScanReport) {
	slices.SortFunc(report.Vulnerabilities, func(left, right normalizedVulnerability) int {
		return strings.Compare(fmt.Sprintf("%s\x00%s\x00%s\x00%s", left.Target, left.ID, left.Package, left.InstalledVersion), fmt.Sprintf("%s\x00%s\x00%s\x00%s", right.Target, right.ID, right.Package, right.InstalledVersion))
	})
	slices.SortFunc(report.Secrets, func(left, right normalizedSecret) int {
		return strings.Compare(fmt.Sprintf("%s\x00%s\x00%09d", left.Target, left.RuleID, left.StartLine), fmt.Sprintf("%s\x00%s\x00%09d", right.Target, right.RuleID, right.StartLine))
	})
	slices.SortFunc(report.Misconfigurations, func(left, right normalizedMisconfiguration) int {
		return strings.Compare(left.Target+"\x00"+left.ID, right.Target+"\x00"+right.ID)
	})
	slices.SortFunc(report.Licenses, func(left, right normalizedLicense) int {
		return strings.Compare(left.Target+"\x00"+left.Name+"\x00"+left.Package+"\x00"+left.Path, right.Target+"\x00"+right.Name+"\x00"+right.Package+"\x00"+right.Path)
	})
}

func decodeExternalJSON(contents []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("external JSON has trailing data")
	}
	return nil
}

func normalizeSeverity(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if slices.Contains([]string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}, value) {
		return value
	}
	return ""
}

func boundedExternalText(value string, limit int) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) > limit || strings.ContainsRune(value, '\x00') {
		return "", errors.New("external text is outside bounds")
	}
	return value, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func bytesDigest(contents []byte) string {
	digest := sha256.Sum256(contents)
	return "sha256:" + hex.EncodeToString(digest[:])
}
