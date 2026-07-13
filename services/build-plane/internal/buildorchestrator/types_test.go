package buildorchestrator

import (
	"strings"
	"testing"
	"time"
)

const (
	testBuildID      = "bld_019b01da-7e31-7000-8000-000000000001"
	testOrgID        = "org_019b01da-7e31-7000-8000-000000000002"
	testProjectID    = "prj_019b01da-7e31-7000-8000-000000000003"
	testDeploymentID = "dep_019b01da-7e31-7000-8000-000000000004"
	testOperationID  = "op_019b01da-7e31-7000-8000-000000000005"
	testSnapshotID   = "snp_019b01da-7e31-7000-8000-000000000006"
	testDigest       = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func validRequest(now time.Time) Request {
	return Request{
		Version: CurrentRequestVersion, BuildID: testBuildID, OrganizationID: testOrgID,
		ProjectID: testProjectID, DeploymentID: testDeploymentID, OperationID: testOperationID, Generation: 1,
		Source: Source{
			SnapshotID: testSnapshotID, SnapshotDigest: testDigest, ManifestDigest: testDigest,
			ArchiveDigest: testDigest, ArchiveRef: "s3://lrail-source/snapshots/archive.tar.gz", SizeBytes: 1024,
			SelectedRoot: ".",
		},
		Configuration:  ConfigurationIntent{Mode: "auto", AcceptDetected: true},
		TargetPlatform: "linux/amd64", Deadline: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
}

func TestRequestValidationOwnsCompleteImmutableIntent(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	if err := validRequest(now).Validate(now); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	tests := map[string]func(*Request){
		"foreign prefix":     func(request *Request) { request.BuildID = testProjectID },
		"mutable source":     func(request *Request) { request.Source.SnapshotDigest = "main" },
		"unsafe root":        func(request *Request) { request.Source.SelectedRoot = "../foreign" },
		"unbounded deadline": func(request *Request) { request.Deadline = now.Add(3 * time.Hour).Format(time.RFC3339Nano) },
		"hidden build file":  func(request *Request) { request.Configuration.BuildFile = "Lrailfile.star" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := validRequest(now)
			mutate(&request)
			if err := request.Validate(now); err == nil {
				t.Fatal("expected request rejection")
			}
		})
	}
}

func TestEventValidationRejectsUnsafeOrInconsistentStreams(t *testing.T) {
	t.Parallel()
	event := Event{
		Version: CurrentEventVersion, BuildID: testBuildID, Generation: 1, Sequence: 1, Attempt: 1,
		Stage: "detecting", Kind: "progress", Message: "Inspecting immutable snapshot",
		OccurredAt: time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	event.Line = strings.Repeat("x", MaxEventLineBytes+1)
	if err := event.Validate(); err == nil {
		t.Fatal("expected oversized line rejection")
	}
}
