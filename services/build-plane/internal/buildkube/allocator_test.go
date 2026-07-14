package buildkube

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcontrol"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
)

type fakeExecutor struct {
	called bool
}

func (executor *fakeExecutor) Execute(_ context.Context, request buildworker.Request) (buildworker.Result, error) {
	executor.called = true
	return buildworker.Result{BuildID: kubeBuildID, Attempt: request.Attempt, Phase: buildworker.PhaseComplete, Cleanup: cleanResidueReport()}, nil
}

type closerRecorder struct {
	closed bool
	err    error
}

func (closer *closerRecorder) Close() error {
	closer.closed = true
	return closer.err
}

type connectorRecorder struct {
	endpoint string
	tls      *tls.Config
	executor buildworker.Executor
	closer   io.Closer
	err      error
}

type certificateIssuerStub struct {
	request CertificateRequest
}

func (issuer *certificateIssuerStub) Issue(_ context.Context, request CertificateRequest) (IssuedCertificates, error) {
	issuer.request = request
	return IssuedCertificates{
		Material:     safeTLSMaterial(),
		ClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: request.DNSName},
	}, nil
}

func (connector *connectorRecorder) Connect(_ context.Context, endpoint string, tlsConfig *tls.Config) (buildworker.Executor, io.Closer, error) {
	connector.endpoint = endpoint
	connector.tls = tlsConfig
	return connector.executor, connector.closer, connector.err
}

type residueRecorder struct {
	mu     sync.Mutex
	calls  []ResidueRequest
	report buildworker.CleanupReport
	err    error
}

func (recorder *residueRecorder) Cleanup(_ context.Context, request ResidueRequest) (buildworker.CleanupReport, error) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.calls = append(recorder.calls, request)
	return recorder.report, recorder.err
}

type quarantineRecorder struct {
	mu       sync.Mutex
	nodeName string
	buildID  string
	reason   string
	err      error
}

func (recorder *quarantineRecorder) Quarantine(_ context.Context, nodeName, buildID, reason string) error {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.nodeName = nodeName
	recorder.buildID = buildID
	recorder.reason = reason
	return recorder.err
}

func cleanResidueReport() buildworker.CleanupReport {
	return buildworker.CleanupReport{BuildID: kubeBuildID, Status: buildworker.CleanupClean, Residue: []buildworker.Residue{}, RemovedPaths: []string{"node://fake/clean"}}
}

func allocatorFixture(t *testing.T, connector *connectorRecorder, residue *residueRecorder, quarantine *quarantineRecorder) (*Allocator, *kubernetesfake.Clientset, buildcontrol.AllocationRequest, string) {
	t.Helper()
	assignment := kubeAssignment(t, []llbcompiler.NetworkCapability{})
	request := buildcontrol.AllocationRequest{Assignment: assignment, Attempt: 1, LeaseID: "lease-test", Network: []llbcompiler.NetworkCapability{}, Caches: []llbcompiler.CacheCapability{}}
	name := resourceName(kubeBuildID, 1)
	labels := map[string]string{
		"app.kubernetes.io/name": "lrail-build-worker", "app.kubernetes.io/component": "buildkit",
		"lrail.dev/build-id": labelHash(kubeBuildID), "lrail.dev/assignment": name, "lrail.dev/organization": labelHash(kubeOrgID),
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name + "-pod", Namespace: "lrail-build", UID: types.UID("fake-pod-uid"), Labels: labels, Annotations: map[string]string{"lrail.dev/build-id": kubeBuildID}},
		Spec:       corev1.PodSpec{NodeName: "build-node-1"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
	client := kubernetesfake.NewClientset(pod, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "build-node-1"}})
	scheme := runtime.NewScheme()
	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{CiliumNetworkPolicyGVR: "CiliumNetworkPolicyList"})
	issuer := new(certificateIssuerStub)
	allocator, err := NewAllocator(client, dynamicClient, safeConfig(), issuer, connector, residue, quarantine, func() time.Time { return kubeNow }, time.Second)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	return allocator, client, request, name
}

func TestAllocatorCreatesConnectsAndCleansDisposableWorker(t *testing.T) {
	t.Parallel()
	executor := new(fakeExecutor)
	closer := new(closerRecorder)
	connector := &connectorRecorder{executor: executor, closer: closer}
	residue := &residueRecorder{report: cleanResidueReport()}
	quarantine := new(quarantineRecorder)
	allocator, client, request, name := allocatorFixture(t, connector, residue, quarantine)
	worker, err := allocator.Allocate(context.Background(), request)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if worker.Identity() != "fake-pod-uid" || connector.tls == nil || connector.tls.MinVersion != tls.VersionTLS13 || !strings.Contains(connector.endpoint, name+".lrail-build.svc.cluster.local:1234") {
		t.Fatalf("worker=%q endpoint=%q tls=%#v", worker.Identity(), connector.endpoint, connector.tls)
	}
	job, err := client.BatchV1().Jobs("lrail-build").Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("worker Job absent: %v", err)
	}
	issuer := allocator.issuer.(*certificateIssuerStub)
	if !issuer.request.ExpiresAt.Equal(kubeNow.Add(time.Hour)) || job.Spec.ActiveDeadlineSeconds == nil || *job.Spec.ActiveDeadlineSeconds != int64(time.Hour/time.Second) {
		t.Fatalf("worker certificate/deadline was not bounded by the signed assignment: request=%#v job=%#v", issuer.request, job.Spec.ActiveDeadlineSeconds)
	}
	if _, err := client.RbacV1().Roles("lrail-build").Get(context.Background(), name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("worker unexpectedly received a Role: %v", err)
	}
	if _, err := worker.Execute(context.Background(), buildworker.Request{Assignment: request.Assignment, Attempt: 1, Secrets: map[string][]byte{}, Events: func(buildworker.Event) {}}); err != nil || !executor.called {
		t.Fatalf("Execute: %v", err)
	}
	report, err := worker.Release(context.Background())
	if err != nil || report.Status != buildworker.CleanupClean || !closer.closed || len(residue.calls) != 1 || quarantine.nodeName != "" {
		t.Fatalf("release report=%#v error=%v closer=%#v residue=%#v quarantine=%#v", report, err, closer, residue, quarantine)
	}
	for _, lookup := range []func() error{
		func() error {
			_, err := client.BatchV1().Jobs("lrail-build").Get(context.Background(), name, metav1.GetOptions{})
			return err
		},
		func() error {
			_, err := client.CoreV1().Secrets("lrail-build").Get(context.Background(), name+"-tls", metav1.GetOptions{})
			return err
		},
		func() error {
			_, err := client.CoreV1().ServiceAccounts("lrail-build").Get(context.Background(), name, metav1.GetOptions{})
			return err
		},
	} {
		if err := lookup(); !apierrors.IsNotFound(err) {
			t.Fatalf("worker resource remains: %v", err)
		}
	}
}

func TestAllocatorRollsBackWhenConnectorFails(t *testing.T) {
	t.Parallel()
	connector := &connectorRecorder{err: errors.New("fake TLS connection failure")}
	residue := &residueRecorder{report: cleanResidueReport()}
	allocator, client, request, name := allocatorFixture(t, connector, residue, new(quarantineRecorder))
	if _, err := allocator.Allocate(context.Background(), request); err == nil {
		t.Fatal("expected allocation failure")
	}
	if _, err := client.BatchV1().Jobs("lrail-build").Get(context.Background(), name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("failed allocation Job remains: %v", err)
	}
	if len(residue.calls) != 1 {
		t.Fatalf("residue calls = %#v", residue.calls)
	}
}

func TestAllocatorProvesNodeCleanupWhenPodFailsBeforeReadiness(t *testing.T) {
	t.Parallel()
	connector := &connectorRecorder{executor: new(fakeExecutor), closer: new(closerRecorder)}
	residue := &residueRecorder{report: cleanResidueReport()}
	allocator, client, request, name := allocatorFixture(t, connector, residue, new(quarantineRecorder))
	pod, err := client.CoreV1().Pods("lrail-build").Get(context.Background(), name+"-pod", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get Pod: %v", err)
	}
	pod.Status.Phase = corev1.PodFailed
	pod.Status.Conditions = nil
	if _, err := client.CoreV1().Pods("lrail-build").Update(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("Update Pod: %v", err)
	}
	if _, err := allocator.Allocate(context.Background(), request); err == nil {
		t.Fatal("expected failed pre-ready allocation")
	}
	if len(residue.calls) != 1 || residue.calls[0].PodUID != types.UID("fake-pod-uid") || residue.calls[0].NodeName != "build-node-1" {
		t.Fatalf("residue calls = %#v", residue.calls)
	}
}

func TestAllocatorRemovesOrphanedAttemptResourcesWithoutJob(t *testing.T) {
	t.Parallel()
	connector := &connectorRecorder{executor: new(fakeExecutor), closer: new(closerRecorder)}
	residue := &residueRecorder{report: cleanResidueReport()}
	allocator, client, request, _ := allocatorFixture(t, connector, residue, new(quarantineRecorder))
	staleName := resourceName(kubeBuildID, 9)
	staleLabels := map[string]string{
		"app.kubernetes.io/name": "lrail-build-worker", "lrail.dev/build-id": labelHash(kubeBuildID),
		"lrail.dev/assignment": staleName,
	}
	if _, err := client.CoreV1().ServiceAccounts("lrail-build").Create(context.Background(), &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: staleName, Namespace: "lrail-build", Labels: staleLabels},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Create stale service account: %v", err)
	}
	if _, err := client.CoreV1().Secrets("lrail-build").Create(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: staleName + "-tls", Namespace: "lrail-build", Labels: staleLabels},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Create stale secret: %v", err)
	}
	worker, err := allocator.Allocate(context.Background(), request)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if _, err := client.CoreV1().ServiceAccounts("lrail-build").Get(context.Background(), staleName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("stale service account remains: %v", err)
	}
	if _, err := client.CoreV1().Secrets("lrail-build").Get(context.Background(), staleName+"-tls", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("stale TLS secret remains: %v", err)
	}
	if _, err := worker.Release(context.Background()); err != nil {
		t.Fatalf("Release: %v", err)
	}
}

func TestAllocatorQuarantinesNodeWhenResidueRemains(t *testing.T) {
	t.Parallel()
	connector := &connectorRecorder{executor: new(fakeExecutor), closer: new(closerRecorder)}
	residue := &residueRecorder{report: buildworker.CleanupReport{
		BuildID: kubeBuildID, Status: buildworker.CleanupQuarantined,
		Residue: []buildworker.Residue{{Kind: "snapshot", Target: "fake-snapshot", Detail: "still present"}}, QuarantineReason: "fake residue",
	}}
	quarantine := new(quarantineRecorder)
	allocator, _, request, _ := allocatorFixture(t, connector, residue, quarantine)
	worker, err := allocator.Allocate(context.Background(), request)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	report, err := worker.ForceTerminate(context.Background())
	if err == nil || report.Status != buildworker.CleanupQuarantined || !strings.Contains(report.QuarantineReason, "fake residue") || quarantine.nodeName != "build-node-1" || quarantine.buildID != kubeBuildID {
		t.Fatalf("report=%#v error=%v quarantine=%#v", report, err, quarantine)
	}
}

func TestAllocatorSurfacesNodeQuarantineFailure(t *testing.T) {
	t.Parallel()
	connector := &connectorRecorder{executor: new(fakeExecutor), closer: new(closerRecorder)}
	residue := &residueRecorder{report: buildworker.CleanupReport{
		BuildID: kubeBuildID, Status: buildworker.CleanupQuarantined,
		Residue: []buildworker.Residue{{Kind: "mount", Target: "fake"}}, QuarantineReason: "fake residue",
	}}
	quarantine := &quarantineRecorder{err: errors.New("fake taint failure")}
	allocator, _, request, _ := allocatorFixture(t, connector, residue, quarantine)
	worker, err := allocator.Allocate(context.Background(), request)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	report, err := worker.Release(context.Background())
	if err == nil || report.Status != buildworker.CleanupQuarantined || !strings.Contains(report.QuarantineReason, "node taint failed") {
		t.Fatalf("report=%#v error=%v", report, err)
	}
}

func TestKubernetesNodeQuarantinerAddsNoScheduleTaint(t *testing.T) {
	t.Parallel()
	client := kubernetesfake.NewClientset(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1"}})
	quarantiner := KubernetesNodeQuarantiner{Client: client}
	if err := quarantiner.Quarantine(context.Background(), "node-1", kubeBuildID, "fake cleanup failure"); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if err := quarantiner.Quarantine(context.Background(), "node-1", kubeBuildID, "fake cleanup failure"); err != nil {
		t.Fatalf("idempotent Quarantine: %v", err)
	}
	node, err := client.CoreV1().Nodes().Get(context.Background(), "node-1", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get node: %v", err)
	}
	if len(node.Spec.Taints) != 1 || node.Spec.Taints[0].Key != "lrail.dev/build-quarantined" || node.Spec.Taints[0].Effect != corev1.TaintEffectNoSchedule {
		t.Fatalf("taints = %#v", node.Spec.Taints)
	}
}

var _ = batchv1.Job{}
