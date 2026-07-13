package residueagent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	lrailv1 "github.com/mayowaoladosu/layerrail-lrail/gen/go/lrail/v1"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const residueBuildID = "bld_019b01da-7e31-7000-8000-000000000001"
const residuePodUID = "019b01da-7e31-7000-8000-000000000099"
const residuePodName = "build-test-a1-pod"
const residueNode = "build-node-1"

type fakeRuntimeCleaner struct {
	cleanupCalls int
	removed      []string
	cleanupErr   error
	residue      []buildworker.Residue
	inspectErr   error
}

func (runtime *fakeRuntimeCleaner) CleanupPod(_ context.Context, _ string) ([]string, error) {
	runtime.cleanupCalls++
	return append([]string(nil), runtime.removed...), runtime.cleanupErr
}

func (runtime *fakeRuntimeCleaner) InspectPod(_ context.Context, _ string) ([]buildworker.Residue, error) {
	return append([]buildworker.Residue(nil), runtime.residue...), runtime.inspectErr
}

type fakeMountCleaner struct {
	removed    []string
	cleanupErr error
	residue    []buildworker.Residue
	inspectErr error
}

func (mounts *fakeMountCleaner) UnmountUnder(_ context.Context, _ string) ([]string, error) {
	return append([]string(nil), mounts.removed...), mounts.cleanupErr
}

func (mounts *fakeMountCleaner) InspectUnder(_ context.Context, _ string) ([]buildworker.Residue, error) {
	return append([]buildworker.Residue(nil), mounts.residue...), mounts.inspectErr
}

func residueAgentFixture(t *testing.T, runtime RuntimeCleaner, mounts MountCleaner) (*Agent, string, string) {
	t.Helper()
	podsRoot := filepath.Join(t.TempDir(), "pods")
	cgroupRoot := filepath.Join(t.TempDir(), "cgroup")
	if err := os.MkdirAll(filepath.Join(podsRoot, residuePodUID, "volumes", "secret"), 0o700); err != nil {
		t.Fatalf("MkdirAll pod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(podsRoot, residuePodUID, "volumes", "secret", "token"), []byte("fake-test-token"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	podCgroup := filepath.Join(cgroupRoot, "kubepods-pod"+strings.ReplaceAll(residuePodUID, "-", "_")+".slice")
	if err := os.MkdirAll(filepath.Join(podCgroup, "container.scope"), 0o700); err != nil {
		t.Fatalf("MkdirAll cgroup: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(cgroupRoot, "kubepods-pod"+strings.ReplaceAll(residuePodUID, "-", "_")+"0.slice"), 0o700); err != nil {
		t.Fatalf("MkdirAll unrelated cgroup: %v", err)
	}
	agent, err := New(Config{NodeName: residueNode, KubeletPodsRoot: podsRoot, CgroupRoot: cgroupRoot}, runtime, mounts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return agent, podsRoot, cgroupRoot
}

func validResidueRequest() Request {
	return Request{BuildID: residueBuildID, PodUID: residuePodUID, PodName: residuePodName, NodeName: residueNode}
}

func TestAgentScrubsPodVolumesRuntimeNetworkAndCgroups(t *testing.T) {
	t.Parallel()
	runtime := &fakeRuntimeCleaner{removed: []string{"cri://container/fake", "cri://sandbox/fake"}}
	mounts := &fakeMountCleaner{removed: []string{"/fake/pod/mount"}}
	agent, podsRoot, cgroupRoot := residueAgentFixture(t, runtime, mounts)
	report := agent.Cleanup(context.Background(), validResidueRequest())
	if report.Status != buildworker.CleanupClean || len(report.Residue) != 0 || runtime.cleanupCalls != 1 || len(report.RemovedPaths) != 5 {
		t.Fatalf("report = %#v, runtime = %#v", report, runtime)
	}
	if _, err := os.Lstat(filepath.Join(podsRoot, residuePodUID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pod root remains: %v", err)
	}
	matches, err := findCgroups(context.Background(), cgroupRoot, residuePodUID)
	if err != nil || len(matches) != 0 {
		t.Fatalf("cgroups remain: %#v, %v", matches, err)
	}
	unrelated := filepath.Join(cgroupRoot, "kubepods-pod"+strings.ReplaceAll(residuePodUID, "-", "_")+"0.slice")
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("unrelated cgroup was removed: %v", err)
	}
}

func TestAgentQuarantinesEveryUnprovenCleanup(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		runtime *fakeRuntimeCleaner
		mounts  *fakeMountCleaner
	}{
		"runtime failure": {runtime: &fakeRuntimeCleaner{cleanupErr: errors.New("fake CRI failure")}, mounts: &fakeMountCleaner{}},
		"network residue": {runtime: &fakeRuntimeCleaner{residue: []buildworker.Residue{{Kind: "network_sandbox", Target: "fake"}}}, mounts: &fakeMountCleaner{}},
		"mount residue":   {runtime: &fakeRuntimeCleaner{}, mounts: &fakeMountCleaner{residue: []buildworker.Residue{{Kind: "mount", Target: "fake"}}}},
	}
	for name, testCase := range tests {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			agent, _, _ := residueAgentFixture(t, testCase.runtime, testCase.mounts)
			report := agent.Cleanup(context.Background(), validResidueRequest())
			if report.Status != buildworker.CleanupQuarantined || report.QuarantineReason == "" {
				t.Fatalf("report = %#v", report)
			}
		})
	}
}

func TestAgentRejectsScopeBeforeTouchingRuntime(t *testing.T) {
	t.Parallel()
	runtime := new(fakeRuntimeCleaner)
	agent, podsRoot, _ := residueAgentFixture(t, runtime, &fakeMountCleaner{})
	request := validResidueRequest()
	request.PodUID = "../outside"
	report := agent.Cleanup(context.Background(), request)
	if report.Status != buildworker.CleanupQuarantined || runtime.cleanupCalls != 0 {
		t.Fatalf("report = %#v, runtime=%#v", report, runtime)
	}
	if _, err := os.Stat(filepath.Join(podsRoot, residuePodUID)); err != nil {
		t.Fatalf("valid pod root was touched: %v", err)
	}
}

func TestProcMountCleanerSelectsOnlyScopedMounts(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "pod root")
	if err := os.MkdirAll(filepath.Join(root, "volume"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	mountInfo := filepath.Join(t.TempDir(), "mountinfo")
	escapedRoot := strings.ReplaceAll(filepath.ToSlash(root), " ", `\040`)
	contents := "36 25 0:32 / " + escapedRoot + "/volume rw,relatime - tmpfs tmpfs rw\n" +
		"37 25 0:33 / /outside rw,relatime - tmpfs tmpfs rw\n"
	if err := os.WriteFile(mountInfo, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cleaner := ProcMountCleaner{MountInfoPath: mountInfo}
	residue, err := cleaner.InspectUnder(context.Background(), root)
	if err != nil || len(residue) != 1 || !strings.HasSuffix(filepath.ToSlash(residue[0].Target), "/volume") {
		t.Fatalf("residue = %#v, %v", residue, err)
	}
}

func TestResidueServerReturnsCleanupProof(t *testing.T) {
	t.Parallel()
	agent, _, _ := residueAgentFixture(t, &fakeRuntimeCleaner{}, &fakeMountCleaner{})
	server, err := NewServer(agent)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	response, err := server.CleanupResidue(context.Background(), &lrailv1.CleanupBuildResidueRequest{
		BuildId: residueBuildID, PodUid: residuePodUID, PodName: residuePodName, NodeName: residueNode,
	})
	if err != nil || response.GetCleanup().GetStatus() != string(buildworker.CleanupClean) || response.GetCleanup().GetResidueCount() != 0 {
		t.Fatalf("response=%#v error=%v", response, err)
	}
	if _, err := server.CleanupResidue(context.Background(), &lrailv1.CleanupBuildResidueRequest{BuildId: residueBuildID, PodUid: "../outside", PodName: residuePodName, NodeName: residueNode}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid scope code=%s error=%v", status.Code(err), err)
	}
}
