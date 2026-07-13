package integration

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/solver/pb"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"google.golang.org/protobuf/proto"
)

const integrationBuildID = "bld_019b01da-7e31-7000-8000-000000000001"
const integrationCellID = "cell_019b01da-7e31-7000-8000-000000000002"
const integrationOrgID = "org_019b01da-7e31-7000-8000-000000000003"
const integrationProjectID = "prj_019b01da-7e31-7000-8000-000000000004"
const integrationOperationID = "op_019b01da-7e31-7000-8000-000000000005"
const integrationIR = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const integrationPolicy = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
const integrationPrefix = "s3://lrail-build/integration/"

type byteSource struct{ contents []byte }

func (source byteSource) Open(context.Context, buildcell.SourceArtifact) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(source.contents)), nil
}

type cleanScratch struct{ root string }

func (cleaner cleanScratch) Cleanup(_ context.Context, buildID string) buildworker.CleanupReport {
	target := filepath.Join(cleaner.root, buildID)
	err := os.RemoveAll(target)
	status := buildworker.CleanupClean
	reason := ""
	residue := []buildworker.Residue{}
	if err != nil {
		status = buildworker.CleanupQuarantined
		reason = "scratch removal failed"
		residue = append(residue, buildworker.Residue{Kind: "filesystem", Target: target})
	}
	return buildworker.CleanupReport{BuildID: buildID, Status: status, Residue: residue, RemovedPaths: []string{target}, QuarantineReason: reason}
}

func TestRealRootlessBuildKitSolveAndResidue(t *testing.T) {
	if os.Getenv("LRAIL_BUILDKIT_INTEGRATION") != "1" {
		t.Skip("set LRAIL_BUILDKIT_INTEGRATION=1")
	}
	address := os.Getenv("LRAIL_BUILDKIT_ADDRESS")
	if address == "" {
		address = "tcp://127.0.0.1:12345"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	buildkit, err := client.New(ctx, address)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	defer buildkit.Close()
	workers, err := buildkit.ListWorkers(ctx)
	if err != nil || len(workers) == 0 {
		t.Fatalf("ListWorkers=%#v error=%v", workers, err)
	}
	rootless := false
	for _, worker := range workers {
		rootless = rootless || worker.Labels["org.mobyproject.buildkit.worker.executor"] == "oci"
	}
	if !rootless {
		t.Fatalf("no OCI rootless worker: %#v", workers)
	}

	assignment, archive := integrationAssignment(t)
	scratchRoot := filepath.Join(t.TempDir(), "scratch")
	artifactRoot := filepath.Join(t.TempDir(), "artifacts")
	committer, err := buildworker.NewDirectoryArtifactCommitter(artifactRoot, 0)
	if err != nil {
		t.Fatalf("NewDirectoryArtifactCommitter: %v", err)
	}
	executor, err := buildworker.NewBuildKitExecutor(buildkit, byteSource{contents: archive}, cleanScratch{root: scratchRoot}, committer, buildworker.RejectingCacheProvider{}, scratchRoot, time.Minute)
	if err != nil {
		t.Fatalf("NewBuildKitExecutor: %v", err)
	}
	var events []buildworker.Event
	result, err := executor.Execute(ctx, buildworker.Request{Assignment: assignment, Attempt: 1, Secrets: map[string][]byte{}, Events: func(event buildworker.Event) { events = append(events, event) }})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Phase != buildworker.PhaseComplete || result.Cleanup.Status != buildworker.CleanupClean || !strings.HasPrefix(result.LogsDigest, "sha256:") || len(result.Outputs) != 1 || result.Outputs[0].ArtifactDigest == "" || result.Outputs[0].ArtifactSize <= 0 {
		t.Fatalf("result=%#v", result)
	}
	contents, err := os.ReadFile(filepath.Join(result.Outputs[0].ArtifactPath, "index.html"))
	if err != nil || string(contents) != "rootless-buildkit-ok" {
		t.Fatalf("artifact=%q error=%v", contents, err)
	}
	if _, err := os.Lstat(filepath.Join(scratchRoot, integrationBuildID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scratch residue=%v", err)
	}
	if len(events) == 0 || events[len(events)-1].Phase != buildworker.PhaseComplete {
		t.Fatalf("events=%#v", events)
	}
}

func TestRealRootlessBuildKitOCIExportIdentity(t *testing.T) {
	if os.Getenv("LRAIL_BUILDKIT_INTEGRATION") != "1" {
		t.Skip("set LRAIL_BUILDKIT_INTEGRATION=1")
	}
	address := os.Getenv("LRAIL_BUILDKIT_ADDRESS")
	if address == "" {
		address = "tcp://127.0.0.1:12345"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	buildkit, err := client.New(ctx, address)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	defer buildkit.Close()
	assignment, archive := integrationOCIAssignment(t)
	scratchRoot := filepath.Join(t.TempDir(), "scratch")
	committer, err := buildworker.NewDirectoryArtifactCommitter(filepath.Join(t.TempDir(), "artifacts"), 0)
	if err != nil {
		t.Fatalf("NewDirectoryArtifactCommitter: %v", err)
	}
	executor, err := buildworker.NewBuildKitExecutor(buildkit, byteSource{contents: archive}, cleanScratch{root: scratchRoot}, committer, buildworker.RejectingCacheProvider{}, scratchRoot, time.Minute)
	if err != nil {
		t.Fatalf("NewBuildKitExecutor: %v", err)
	}
	result, err := executor.Execute(ctx, buildworker.Request{Assignment: assignment, Attempt: 1, Secrets: map[string][]byte{}, Events: func(buildworker.Event) {}})
	if err != nil || result.Phase != buildworker.PhaseComplete || len(result.Outputs) != 1 {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	output := result.Outputs[0]
	if output.Kind != "oci_image" || !strings.HasPrefix(output.ArtifactDigest, "sha256:") || !strings.HasPrefix(output.ConfigDigest, "sha256:") || !strings.HasPrefix(output.ManifestDigest, "sha256:") || len(output.LayerDigests) == 0 || !strings.HasPrefix(result.LogsDigest, "sha256:") {
		t.Fatalf("OCI identity is incomplete: %#v", result)
	}
}

func TestRealRootlessBuildKitMaliciousFixtureCannotReachAmbientAuthority(t *testing.T) {
	if os.Getenv("LRAIL_BUILDKIT_INTEGRATION") != "1" {
		t.Skip("set LRAIL_BUILDKIT_INTEGRATION=1")
	}
	address := os.Getenv("LRAIL_BUILDKIT_ADDRESS")
	if address == "" {
		address = "tcp://127.0.0.1:12345"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	buildkit, err := client.New(ctx, address)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	defer buildkit.Close()
	image := llb.Image(
		"docker.io/library/alpine@sha256:eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f",
		llb.Platform(ocispecs.Platform{OS: "linux", Architecture: "amd64"}), llb.ResolveModeForcePull,
	)
	command := `set -u
: >/proof.txt
if test -f /var/run/secrets/kubernetes.io/serviceaccount/token; then echo token=present >>/proof.txt; else echo token=absent >>/proof.txt; fi
if test -r /var/run/docker.sock; then echo docker=present >>/proof.txt; else echo docker=absent >>/proof.txt; fi
if test -r /run/containerd/containerd.sock; then echo containerd=present >>/proof.txt; else echo containerd=absent >>/proof.txt; fi
if test -f /host/etc/shadow; then echo host=present >>/proof.txt; else echo host=absent >>/proof.txt; fi
if command -v wget >/dev/null 2>&1; then
	if wget -T 1 -qO /metadata http://169.254.169.254/latest/meta-data/ 2>/dev/null; then
		echo metadata=reachable >>/proof.txt
	else
		echo metadata=blocked >>/proof.txt
	fi
else
	echo metadata=no-client >>/proof.txt
fi`
	state := image.Run(llb.Args([]string{"/bin/sh", "-c", command}), llb.Network(pb.NetMode_NONE)).Root()
	definition, err := state.Marshal(ctx)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	exportDirectory := t.TempDir()
	statuses := make(chan *client.SolveStatus)
	done := make(chan struct{})
	var solveLogs bytes.Buffer
	go func() {
		for status := range statuses {
			for _, log := range status.Logs {
				solveLogs.Write(log.Data)
			}
		}
		close(done)
	}()
	_, err = buildkit.Solve(ctx, definition, client.SolveOpt{Exports: []client.ExportEntry{{Type: client.ExporterLocal, OutputDir: exportDirectory}}}, statuses)
	<-done
	if err != nil {
		t.Fatalf("malicious fixture solve: %v\nlogs:\n%s", err, solveLogs.String())
	}
	proof, err := os.ReadFile(filepath.Join(exportDirectory, "proof.txt"))
	if err != nil {
		t.Fatalf("proof read: %v", err)
	}
	proofText := string(proof)
	for _, required := range []string{"token=absent", "docker=absent", "containerd=absent", "host=absent"} {
		if !strings.Contains(proofText, required) {
			t.Fatalf("proof lacks %q: %s", required, proofText)
		}
	}
	if !strings.Contains(proofText, "metadata=blocked") && !strings.Contains(proofText, "metadata=no-client") {
		t.Fatalf("metadata probe failed open: %s", proofText)
	}
}

func TestRealRootlessBuildKitWorkerKillRetriesSameAssignmentCleanly(t *testing.T) {
	if os.Getenv("LRAIL_BUILDKIT_INTEGRATION") != "1" {
		t.Skip("set LRAIL_BUILDKIT_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	const containerName = "lrail-wp038-kill-conformance"
	const address = "tcp://127.0.0.1:12346"
	removeBuildKitContainer(context.Background(), containerName)
	t.Cleanup(func() { removeBuildKitContainer(context.Background(), containerName) })
	assignment, archive := integrationRunAssignment(t)
	scratchRoot := filepath.Join(t.TempDir(), "scratch")
	artifactRoot := filepath.Join(t.TempDir(), "artifacts")
	committer, err := buildworker.NewDirectoryArtifactCommitter(artifactRoot, 0)
	if err != nil {
		t.Fatalf("NewDirectoryArtifactCommitter: %v", err)
	}

	firstClient := startBuildKitContainer(t, ctx, containerName, "12346")
	firstExecutor, err := buildworker.NewBuildKitExecutor(firstClient, byteSource{contents: archive}, cleanScratch{root: scratchRoot}, committer, buildworker.RejectingCacheProvider{}, scratchRoot, time.Minute)
	if err != nil {
		t.Fatalf("NewBuildKitExecutor first: %v", err)
	}
	var killOnce sync.Once
	firstResult, firstErr := firstExecutor.Execute(ctx, buildworker.Request{
		Assignment: assignment, Attempt: 1, Secrets: map[string][]byte{},
		Events: func(event buildworker.Event) {
			if event.Kind == "output_started" {
				killOnce.Do(func() {
					if output, err := exec.CommandContext(context.Background(), "docker", "kill", containerName).CombinedOutput(); err != nil {
						t.Errorf("docker kill: %v: %s", err, output)
					}
				})
			}
		},
	})
	_ = firstClient.Close()
	if firstErr == nil || firstResult.ErrorCode != "worker_lost" || firstResult.Cleanup.Status != buildworker.CleanupClean {
		t.Fatalf("first result=%#v error=%v", firstResult, firstErr)
	}
	removeBuildKitContainer(context.Background(), containerName)
	assertBuildKitContainerAbsent(t, containerName)
	if _, err := os.Lstat(filepath.Join(scratchRoot, integrationBuildID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("first-attempt scratch residue=%v", err)
	}

	secondClient := startBuildKitContainer(t, ctx, containerName, "12346")
	secondExecutor, err := buildworker.NewBuildKitExecutor(secondClient, byteSource{contents: archive}, cleanScratch{root: scratchRoot}, committer, buildworker.RejectingCacheProvider{}, scratchRoot, time.Minute)
	if err != nil {
		t.Fatalf("NewBuildKitExecutor second: %v", err)
	}
	secondResult, secondErr := secondExecutor.Execute(ctx, buildworker.Request{Assignment: assignment, Attempt: 2, Secrets: map[string][]byte{}, Events: func(buildworker.Event) {}})
	_ = secondClient.Close()
	if secondErr != nil || secondResult.Phase != buildworker.PhaseComplete || secondResult.Attempt != 2 || secondResult.Cleanup.Status != buildworker.CleanupClean {
		t.Fatalf("second result=%#v error=%v", secondResult, secondErr)
	}
	proof, err := os.ReadFile(filepath.Join(secondResult.Outputs[0].ArtifactPath, "proof.txt"))
	if err != nil || string(proof) != "worker-retry-ok" {
		t.Fatalf("proof=%q error=%v", proof, err)
	}
	removeBuildKitContainer(context.Background(), containerName)
	assertBuildKitContainerAbsent(t, containerName)
	if _, err := os.Lstat(filepath.Join(scratchRoot, integrationBuildID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("second-attempt scratch residue=%v", err)
	}
}

func TestRealRootlessBuildKitDirectoryCacheRoundTripAcrossFreshWorkers(t *testing.T) {
	if os.Getenv("LRAIL_BUILDKIT_INTEGRATION") != "1" {
		t.Skip("set LRAIL_BUILDKIT_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	const containerName = "lrail-wp038-cache-conformance"
	removeBuildKitContainer(context.Background(), containerName)
	t.Cleanup(func() { removeBuildKitContainer(context.Background(), containerName) })
	provider, err := buildworker.NewDirectoryCacheProvider(filepath.Join(t.TempDir(), "cache"))
	if err != nil {
		t.Fatalf("NewDirectoryCacheProvider: %v", err)
	}
	lock := llbcompiler.DefinitionLock{
		CompilerVersion: "0.1.0", PolicyDigest: integrationPolicy,
		Caches: []llbcompiler.CacheCapability{{
			NodeID: "n2", Name: "modules", Target: "/cache", Sharing: "locked", Scope: "organization",
			Namespace: "lrail-cache-" + strings.Repeat("a", 64),
		}},
	}
	image := llb.Image(
		"docker.io/library/alpine@sha256:eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f",
		llb.Platform(ocispecs.Platform{OS: "linux", Architecture: "amd64"}), llb.ResolveModeForcePull,
	)
	built := image.Run(
		llb.Args([]string{"/bin/sh", "-c", "printf cache-round-trip-ok >/cache-proof.txt"}),
		llb.Network(pb.NetMode_NONE),
	).Root()
	state := llb.Scratch().File(llb.Copy(built, "/cache-proof.txt", "/cache-proof.txt"))
	definition, err := state.Marshal(ctx)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	firstLease, err := provider.Acquire(ctx, lock, integrationBuildID, "site", 1)
	if err != nil {
		t.Fatalf("first cache Acquire: %v", err)
	}
	firstClient := startBuildKitContainer(t, ctx, containerName, "12347")
	if cached, err := solveCacheFixture(ctx, firstClient, definition, firstLease, t.TempDir()); err != nil || cached {
		t.Fatalf("first cache solve cached=%t error=%v", cached, err)
	}
	if err := firstLease.Complete(true); err != nil {
		t.Fatalf("first cache Complete: %v", err)
	}
	_ = firstClient.Close()
	removeBuildKitContainer(context.Background(), containerName)
	assertBuildKitContainerAbsent(t, containerName)

	secondLease, err := provider.Acquire(ctx, lock, integrationBuildID, "site", 2)
	if err != nil || len(secondLease.Imports()) != 1 {
		t.Fatalf("second cache Acquire imports=%#v error=%v", secondLease.Imports(), err)
	}
	secondClient := startBuildKitContainer(t, ctx, containerName, "12347")
	cached, solveErr := solveCacheFixture(ctx, secondClient, definition, secondLease, t.TempDir())
	if solveErr != nil || !cached {
		t.Fatalf("second cache solve cached=%t error=%v", cached, solveErr)
	}
	if err := secondLease.Complete(true); err != nil {
		t.Fatalf("second cache Complete: %v", err)
	}
	_ = secondClient.Close()
}

func solveCacheFixture(ctx context.Context, buildkit *client.Client, definition *llb.Definition, lease buildworker.CacheLease, outputDirectory string) (bool, error) {
	statuses := make(chan *client.SolveStatus)
	statusDone := make(chan bool, 1)
	go func() {
		cached := false
		for status := range statuses {
			for _, vertex := range status.Vertexes {
				cached = cached || vertex.Cached
			}
		}
		statusDone <- cached
	}()
	_, err := buildkit.Solve(ctx, definition, client.SolveOpt{
		Exports:      []client.ExportEntry{{Type: client.ExporterLocal, OutputDir: outputDirectory}},
		CacheImports: lease.Imports(), CacheExports: lease.Exports(),
	}, statuses)
	return <-statusDone, err
}

func startBuildKitContainer(t *testing.T, ctx context.Context, name, port string) *client.Client {
	t.Helper()
	arguments := []string{
		"run", "-d", "--name", name, "--privileged", "--security-opt", "seccomp=unconfined", "--security-opt", "apparmor=unconfined",
		"-p", "127.0.0.1:" + port + ":1234",
		"moby/buildkit:v0.31.1-rootless@sha256:946cf909534b789c9b84af75e6d4f8cb23c3b9cb387daec5ba0f4878a3e4647c",
		"--addr", "tcp://0.0.0.0:1234", "--oci-worker-no-process-sandbox",
	}
	if output, err := exec.CommandContext(ctx, "docker", arguments...).CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v: %s", err, output)
	}
	address := "tcp://127.0.0.1:" + port
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		buildkit, err := client.New(ctx, address)
		if err == nil {
			if _, err := buildkit.Info(ctx); err == nil {
				return buildkit
			}
			_ = buildkit.Close()
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatalf("BuildKit container %s did not become ready", name)
	return nil
}

func removeBuildKitContainer(ctx context.Context, name string) {
	_, _ = exec.CommandContext(ctx, "docker", "rm", "-f", name).CombinedOutput()
}

func assertBuildKitContainerAbsent(t *testing.T, name string) {
	t.Helper()
	output, err := exec.Command("docker", "inspect", name).CombinedOutput()
	if err == nil {
		t.Fatalf("BuildKit container remains: %s", output)
	}
}

func integrationAssignment(t *testing.T) (buildcell.ResolvedAssignment, []byte) {
	t.Helper()
	state := llb.Scratch().File(llb.Mkfile("/index.html", 0o644, []byte("rootless-buildkit-ok")))
	return resolveIntegrationState(t, state, []llbcompiler.BaseMaterial{}, []llbcompiler.NetworkCapability{})
}

func integrationOCIAssignment(t *testing.T) (buildcell.ResolvedAssignment, []byte) {
	t.Helper()
	state := llb.Scratch().File(llb.Mkfile("/app", 0o755, []byte("application")))
	config := []byte(`{"architecture":"amd64","config":{"Cmd":["/app"]},"os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
	return resolveIntegrationOutput(t, state, []llbcompiler.BaseMaterial{}, []llbcompiler.NetworkCapability{}, "oci_image", config)
}

func integrationRunAssignment(t *testing.T) (buildcell.ResolvedAssignment, []byte) {
	t.Helper()
	const imageDigest = "sha256:eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"
	imageReference := "docker.io/library/alpine@" + imageDigest
	image := llb.Image(imageReference, llb.Platform(ocispecs.Platform{OS: "linux", Architecture: "amd64"}), llb.ResolveModeForcePull)
	built := image.Run(
		llb.Args([]string{"/bin/sh", "-c", "sleep 3; printf worker-retry-ok >/proof.txt"}),
		llb.Network(pb.NetMode_NONE),
		llb.WithCustomName("lrail run n1 network=none gateway= hosts="),
	).Root()
	state := llb.Scratch().File(llb.Copy(built, "/proof.txt", "/proof.txt"))
	material := llbcompiler.BaseMaterial{
		RequestedRef: imageReference, ResolvedRef: imageReference, Digest: imageDigest, Registry: "docker.io",
		Classification: "customer", Platforms: []string{"linux/amd64"}, SignatureIdentity: "integration-fixture",
	}
	resolutionDigest, err := llbcompiler.ResolutionDigest(material)
	if err != nil {
		t.Fatalf("ResolutionDigest: %v", err)
	}
	material.ResolutionDigest = resolutionDigest
	network := llbcompiler.NetworkCapability{NodeID: "n1", Profile: "none", Hosts: []string{}}
	return resolveIntegrationState(t, state, []llbcompiler.BaseMaterial{material}, []llbcompiler.NetworkCapability{network})
}

func resolveIntegrationState(t *testing.T, state llb.State, materials []llbcompiler.BaseMaterial, network []llbcompiler.NetworkCapability) (buildcell.ResolvedAssignment, []byte) {
	return resolveIntegrationOutput(t, state, materials, network, "static_bundle", []byte(`{"config":{"Cmd":["true"]}}`))
}

func resolveIntegrationOutput(t *testing.T, state llb.State, materials []llbcompiler.BaseMaterial, network []llbcompiler.NetworkCapability, outputKind string, config []byte) (buildcell.ResolvedAssignment, []byte) {
	t.Helper()
	archive := tarGzip(t, map[string]string{"input.txt": "immutable source"})
	sourceDigest := digest(archive)
	definition, err := state.Marshal(context.Background(), llb.Platform(ocispecs.Platform{OS: "linux", Architecture: "amd64"}))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	head, err := definition.Head()
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	definitionBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(definition.ToPB())
	if err != nil {
		t.Fatalf("Marshal definition: %v", err)
	}
	lock := llbcompiler.DefinitionLock{
		Version: llbcompiler.CurrentLockVersion, CompilerVersion: "0.1.0", IRDigest: integrationIR, PolicyDigest: integrationPolicy,
		SourceSnapshot: sourceDigest, TargetPlatform: "linux/amd64", BuildArguments: []llbcompiler.NameValue{}, BaseMaterials: materials,
		Network: network, Caches: []llbcompiler.CacheCapability{}, Secrets: []llbcompiler.SecretCapability{},
		Outputs: []llbcompiler.OutputLock{{Name: "site", Kind: outputKind, StateID: "n1", LLBDigest: digest(definitionBytes), ConfigDigest: digest(config)}},
	}
	lockDigest, _ := llbcompiler.LockDigest(lock)
	output := buildcell.OutputArtifact{Name: "site", Kind: outputKind, LLBDigest: digest(definitionBytes), Head: string(head), LLBRef: integrationPrefix + "site.llb", ConfigDigest: digest(config), ConfigRef: integrationPrefix + "site.json"}
	now := time.Now().UTC().Truncate(time.Second)
	payload := buildcell.Payload{
		Version: buildcell.CurrentAssignmentVersion, BuildID: integrationBuildID, CellID: integrationCellID, OrganizationID: integrationOrgID,
		ProjectID: integrationProjectID, OperationID: integrationOperationID, Generation: 1, Nonce: strings.Repeat("a", 64), IssuedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), DefinitionDigest: lockDigest, Lock: lock,
		Source: buildcell.SourceArtifact{SnapshotDigest: sourceDigest, ArchiveDigest: sourceDigest, ArchiveRef: integrationPrefix + "source.tar.gz", SizeBytes: int64(len(archive))}, Outputs: []buildcell.OutputArtifact{output},
	}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	envelope, _ := buildcell.Sign(payload, "integration-v1", privateKey)
	verifier, err := buildcell.NewVerifier(buildcell.VerifierOptions{CellID: integrationCellID, Keys: map[string]ed25519.PublicKey{"integration-v1": privateKey.Public().(ed25519.PublicKey)}, ObjectPrefix: integrationPrefix, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	verified, err := verifier.Verify(envelope)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	store := mapStore{output.LLBRef: definitionBytes, output.ConfigRef: config}
	resolved, err := buildcell.Resolve(context.Background(), verified, store)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return resolved, archive
}

type mapStore map[string][]byte

func (store mapStore) Open(_ context.Context, reference string, _ int64) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(store[reference])), nil
}

func tarGzip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	archive := tar.NewWriter(compressed)
	for name, value := range files {
		contents := []byte(value)
		if err := archive.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(contents))}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write(contents); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
