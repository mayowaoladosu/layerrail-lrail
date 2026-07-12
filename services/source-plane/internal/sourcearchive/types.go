// Package sourcearchive validates hostile source archives and creates immutable manifests.
package sourcearchive

import "time"

const ManifestVersion = 1

type Policy struct {
	Version             string
	MaxArchiveBytes     int64
	MaxExpandedBytes    int64
	MaxFileBytes        int64
	MaxEntries          int
	MaxPathBytes        int
	MaxCompressionRatio int64
}

func DefaultPolicy() Policy {
	return Policy{
		Version:             "source-v1",
		MaxArchiveBytes:     1 << 30,
		MaxExpandedBytes:    2 << 30,
		MaxFileBytes:        128 << 20,
		MaxEntries:          50_000,
		MaxPathBytes:        512,
		MaxCompressionRatio: 100,
	}
}

type Metadata struct {
	SourceKind    string    `json:"source_kind"`
	Provider      string    `json:"provider,omitempty"`
	Repository    string    `json:"repository,omitempty"`
	CommitSHA     string    `json:"commit_sha,omitempty"`
	Author        string    `json:"author,omitempty"`
	AuthoredAt    time.Time `json:"authored_at,omitempty"`
	RootDirectory string    `json:"root_directory"`
	CreatorID     string    `json:"creator_id"`
	ExcludedCount int       `json:"excluded_count"`
}

type Entry struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Mode   int64  `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Finding struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

type Scan struct {
	Status   string    `json:"status"`
	Findings []Finding `json:"findings"`
}

type Manifest struct {
	Version       int      `json:"version"`
	PolicyVersion string   `json:"policy_version"`
	RootDirectory string   `json:"root_directory"`
	Entries       []Entry  `json:"entries"`
	IncludedCount int      `json:"included_count"`
	IncludedBytes int64    `json:"included_bytes"`
	ExcludedCount int      `json:"excluded_count"`
	Warnings      []string `json:"warnings"`
	Scan          Scan     `json:"scan"`
}

type Options struct {
	ExpectedArchiveBytes  int64
	ExpectedArchiveSHA256 string
	Metadata              Metadata
	Policy                Policy
}

type Result struct {
	Manifest          Manifest
	CanonicalManifest []byte
	CanonicalMetadata []byte
	ArchiveSHA256     string
	ManifestSHA256    string
	SnapshotSHA256    string
}
