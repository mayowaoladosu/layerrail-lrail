package buildkube

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcontrol"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildegress"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
)

const DefaultReadyTimeout = 5 * time.Minute

type ResidueRequest struct {
	BuildID  string
	PodUID   types.UID
	PodName  string
	NodeName string
}

type ResidueAgent interface {
	Cleanup(ctx context.Context, request ResidueRequest) (buildworker.CleanupReport, error)
}

type NodeQuarantiner interface {
	Quarantine(ctx context.Context, nodeName, buildID, reason string) error
}

type Allocator struct {
	client       kubernetes.Interface
	dynamic      dynamic.Interface
	config       Config
	issuer       CertificateIssuer
	connector    WorkerConnector
	residue      ResidueAgent
	quarantiner  NodeQuarantiner
	clock        func() time.Time
	readyTimeout time.Duration
}

func NewAllocator(client kubernetes.Interface, dynamicClient dynamic.Interface, config Config, issuer CertificateIssuer, connector WorkerConnector, residue ResidueAgent, quarantiner NodeQuarantiner, clock func() time.Time, readyTimeout time.Duration) (*Allocator, error) {
	if client == nil || dynamicClient == nil || issuer == nil || connector == nil || residue == nil || quarantiner == nil {
		return nil, errors.New("Kubernetes allocator dependencies are incomplete")
	}
	normalized, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	if clock == nil {
		clock = time.Now
	}
	if readyTimeout == 0 {
		readyTimeout = DefaultReadyTimeout
	}
	if readyTimeout < time.Second || readyTimeout > DefaultReadyTimeout {
		return nil, errors.New("Kubernetes worker readiness timeout is outside bounds")
	}
	return &Allocator{client: client, dynamic: dynamicClient, config: normalized, issuer: issuer, connector: connector, residue: residue, quarantiner: quarantiner, clock: clock, readyTimeout: readyTimeout}, nil
}

func (allocator *Allocator) Allocate(ctx context.Context, request buildcontrol.AllocationRequest) (buildcontrol.Worker, error) {
	if err := request.Assignment.Validate(); err != nil || request.Attempt == 0 {
		return nil, errors.New("Kubernetes worker assignment is invalid")
	}
	name := resourceName(request.Assignment.Verified.Payload.BuildID, request.Attempt)
	endpoint := fmt.Sprintf("%s.%s.svc.cluster.local", name, allocator.config.Namespace)
	now := allocator.clock().UTC()
	egressPolicy, err := buildegress.NewPolicy(
		request.Assignment.Verified.Payload.BuildID, request.Assignment.Verified.Payload.OrganizationID, name,
		request.Assignment.Verified.PayloadDigest, request.Assignment.Verified.Payload.Generation, now.Add(-time.Minute), request.ExpiresAt,
		request.Assignment.Verified.Payload.Lock, allocator.config.AllowedPrivateEndpoints,
	)
	if err != nil {
		return nil, fmt.Errorf("construct worker egress policy: %w", err)
	}
	issued, err := allocator.issuer.Issue(ctx, CertificateRequest{WorkerName: name, DNSName: endpoint, ExpiresAt: request.ExpiresAt, Egress: egressPolicy})
	if err != nil || issued.ClientConfig == nil {
		return nil, buildcontrol.WrapWorkerAllocationError(buildcontrol.AllocationCertificateIssue, errors.New("issue worker certificates"))
	}
	resources, err := BuildResources(allocator.config, request, issued.Material, now)
	if err != nil {
		return nil, buildcontrol.WrapWorkerAllocationError(buildcontrol.AllocationResourcePrepare, err)
	}
	if err := allocator.cleanupStaleAttempts(ctx, request.Assignment.Verified.Payload.BuildID, name); err != nil {
		return nil, buildcontrol.WrapWorkerAllocationError(buildcontrol.AllocationStaleCleanup, err)
	}
	if err := allocator.createResources(ctx, resources); err != nil {
		cleanupContext, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = allocator.deleteResources(cleanupContext, resources, nil, true)
		return nil, buildcontrol.WrapWorkerAllocationError(buildcontrol.AllocationResourceCreate, err)
	}
	readyContext, cancelReady := context.WithTimeout(ctx, allocator.readyTimeout)
	pod, err := allocator.waitReady(readyContext, resources)
	cancelReady()
	if err != nil {
		cleanupContext, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = allocator.deleteResources(cleanupContext, resources, pod, true)
		return nil, buildcontrol.WrapWorkerAllocationError(buildcontrol.AllocationReadiness, err)
	}
	executor, closer, err := allocator.connector.Connect(ctx, fmt.Sprintf("%s:%d", endpoint, BuildKitPort), issued.ClientConfig)
	if err != nil {
		cleanupContext, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = allocator.deleteResources(cleanupContext, resources, pod, true)
		if buildcontrol.WorkerAllocationErrorCode(err) == "worker_allocate" {
			err = buildcontrol.WrapWorkerAllocationError(buildcontrol.AllocationConnect, err)
		}
		return nil, err
	}
	return &kubernetesWorker{
		identity: string(pod.UID), buildID: request.Assignment.Verified.Payload.BuildID, pod: pod.DeepCopy(),
		resources: resources, executor: executor, closer: closer, allocator: allocator,
	}, nil
}

func (allocator *Allocator) CleanupBuild(ctx context.Context, buildID string) (buildworker.CleanupReport, error) {
	report := buildworker.CleanupReport{BuildID: buildID, Status: buildworker.CleanupClean, Residue: []buildworker.Residue{}, RemovedPaths: []string{}}
	parsed, err := platformid.Parse(buildID)
	if err != nil || parsed.Prefix() != "bld" {
		return report, errors.New("Kubernetes stale worker cleanup identity is invalid")
	}
	if err := allocator.cleanupStaleAttempts(ctx, buildID, ""); err != nil {
		report.Status = buildworker.CleanupQuarantined
		report.Residue = append(report.Residue, buildworker.Residue{Kind: "worker_resource", Detail: "stale worker cleanup failed"})
		report.QuarantineReason = "stale worker cleanup could not be proven"
		return report, err
	}
	return report, nil
}

func (allocator *Allocator) createResources(ctx context.Context, resources Resources) error {
	created := make([]string, 0, 6)
	if _, err := allocator.client.CoreV1().ServiceAccounts(allocator.config.Namespace).Create(ctx, resources.ServiceAccount, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create worker service account: %w", err)
	}
	created = append(created, "serviceaccount")
	if _, err := allocator.client.CoreV1().Secrets(allocator.config.Namespace).Create(ctx, resources.TLSSecret, metav1.CreateOptions{}); err != nil {
		return rollbackCreateError("secret", err, created)
	}
	created = append(created, "secret")
	if _, err := allocator.client.CoreV1().Services(allocator.config.Namespace).Create(ctx, resources.Service, metav1.CreateOptions{}); err != nil {
		return rollbackCreateError("service", err, created)
	}
	created = append(created, "service")
	if _, err := allocator.client.NetworkingV1().NetworkPolicies(allocator.config.Namespace).Create(ctx, resources.NetworkPolicy, metav1.CreateOptions{}); err != nil {
		return rollbackCreateError("network policy", err, created)
	}
	created = append(created, "networkpolicy")
	if _, err := allocator.dynamic.Resource(CiliumNetworkPolicyGVR).Namespace(allocator.config.Namespace).Create(ctx, resources.CiliumPolicy, metav1.CreateOptions{}); err != nil {
		return rollbackCreateError("Cilium network policy", err, created)
	}
	created = append(created, "ciliumnetworkpolicy")
	if _, err := allocator.client.BatchV1().Jobs(allocator.config.Namespace).Create(ctx, resources.Job, metav1.CreateOptions{}); err != nil {
		return rollbackCreateError("job", err, created)
	}
	return nil
}

func rollbackCreateError(kind string, err error, created []string) error {
	return fmt.Errorf("create worker %s after %s: %w", kind, strings.Join(created, ","), err)
}

func (allocator *Allocator) waitReady(ctx context.Context, resources Resources) (*corev1.Pod, error) {
	var readyPod *corev1.Pod
	err := wait.PollUntilContextCancel(ctx, 250*time.Millisecond, true, func(ctx context.Context) (bool, error) {
		job, err := allocator.client.BatchV1().Jobs(allocator.config.Namespace).Get(ctx, resources.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if job.Status.Failed > 0 {
			return false, errors.New("BuildKit worker job failed before readiness")
		}
		list, err := allocator.client.CoreV1().Pods(allocator.config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: labels.Set(resources.Labels).String()})
		if err != nil {
			return false, err
		}
		for index := range list.Items {
			pod := &list.Items[index]
			if pod.UID != "" && pod.Spec.NodeName != "" {
				readyPod = pod.DeepCopy()
			}
			if pod.Status.Phase == corev1.PodFailed {
				return false, errors.New("BuildKit worker pod failed before readiness")
			}
			if pod.Status.Phase != corev1.PodRunning || pod.Spec.NodeName == "" {
				continue
			}
			for _, condition := range pod.Status.Conditions {
				if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
					return true, nil
				}
			}
		}
		return false, nil
	})
	if err != nil {
		return readyPod, fmt.Errorf("wait for BuildKit worker readiness: %w", err)
	}
	return readyPod, nil
}

func (allocator *Allocator) cleanupStaleAttempts(ctx context.Context, buildID, currentName string) error {
	selector := labels.Set(map[string]string{"lrail.dev/build-id": labelHash(buildID)}).String()
	names := make(map[string]struct{})
	podsByName := make(map[string]*corev1.Pod)
	jobs, err := allocator.client.BatchV1().Jobs(allocator.config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return fmt.Errorf("list stale worker jobs: %w", err)
	}
	for index := range jobs.Items {
		names[jobs.Items[index].Name] = struct{}{}
	}
	pods, err := allocator.client.CoreV1().Pods(allocator.config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return fmt.Errorf("list stale worker pods: %w", err)
	}
	for index := range pods.Items {
		pod := pods.Items[index].DeepCopy()
		name := pod.Labels["lrail.dev/assignment"]
		if name == "" {
			return errors.New("stale worker Pod lacks assignment identity")
		}
		if _, duplicate := podsByName[name]; duplicate {
			return errors.New("multiple stale worker Pods share an assignment identity")
		}
		names[name] = struct{}{}
		podsByName[name] = pod
	}
	serviceAccounts, err := allocator.client.CoreV1().ServiceAccounts(allocator.config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return fmt.Errorf("list stale worker service accounts: %w", err)
	}
	for index := range serviceAccounts.Items {
		names[serviceAccounts.Items[index].Name] = struct{}{}
	}
	services, err := allocator.client.CoreV1().Services(allocator.config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return fmt.Errorf("list stale worker services: %w", err)
	}
	for index := range services.Items {
		names[services.Items[index].Name] = struct{}{}
	}
	secrets, err := allocator.client.CoreV1().Secrets(allocator.config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return fmt.Errorf("list stale worker secrets: %w", err)
	}
	for index := range secrets.Items {
		name, found := strings.CutSuffix(secrets.Items[index].Name, "-tls")
		if !found || name == "" {
			return errors.New("stale worker Secret lacks TLS assignment identity")
		}
		names[name] = struct{}{}
	}
	policies, err := allocator.client.NetworkingV1().NetworkPolicies(allocator.config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return fmt.Errorf("list stale worker network policies: %w", err)
	}
	for index := range policies.Items {
		names[policies.Items[index].Name] = struct{}{}
	}
	ciliumPolicies, err := allocator.dynamic.Resource(CiliumNetworkPolicyGVR).Namespace(allocator.config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return fmt.Errorf("list stale worker Cilium policies: %w", err)
	}
	for _, item := range ciliumPolicies.Items {
		names[item.GetName()] = struct{}{}
	}
	delete(names, currentName)
	for name := range names {
		report, cleanupErr := allocator.deleteResources(ctx, Resources{Name: name}, podsByName[name], true)
		if cleanupErr != nil || report.Status != buildworker.CleanupClean {
			return errors.New("stale worker cleanup could not be proven")
		}
	}
	return nil
}

func (allocator *Allocator) deleteResources(ctx context.Context, resources Resources, pod *corev1.Pod, force bool) (buildworker.CleanupReport, error) {
	report := buildworker.CleanupReport{Status: buildworker.CleanupClean, Residue: []buildworker.Residue{}, RemovedPaths: []string{}}
	if pod != nil {
		report.BuildID = pod.Annotations["lrail.dev/build-id"]
	}
	propagation := metav1.DeletePropagationBackground
	grace := int64(DefaultTerminationGrace)
	if force {
		grace = 0
	}
	deleteOptions := metav1.DeleteOptions{PropagationPolicy: &propagation, GracePeriodSeconds: &grace}
	deleteCalls := []struct {
		kind string
		call func() error
	}{
		{"job", func() error {
			return allocator.client.BatchV1().Jobs(allocator.config.Namespace).Delete(ctx, resources.Name, deleteOptions)
		}},
		{"service", func() error {
			return allocator.client.CoreV1().Services(allocator.config.Namespace).Delete(ctx, resources.Name, metav1.DeleteOptions{})
		}},
		{"networkpolicy", func() error {
			return allocator.client.NetworkingV1().NetworkPolicies(allocator.config.Namespace).Delete(ctx, resources.Name, metav1.DeleteOptions{})
		}},
		{"ciliumnetworkpolicy", func() error {
			return allocator.dynamic.Resource(CiliumNetworkPolicyGVR).Namespace(allocator.config.Namespace).Delete(ctx, resources.Name, metav1.DeleteOptions{})
		}},
		{"secret", func() error {
			return allocator.client.CoreV1().Secrets(allocator.config.Namespace).Delete(ctx, resources.Name+"-tls", metav1.DeleteOptions{})
		}},
		{"serviceaccount", func() error {
			return allocator.client.CoreV1().ServiceAccounts(allocator.config.Namespace).Delete(ctx, resources.Name, metav1.DeleteOptions{})
		}},
	}
	var cleanupErrors []error
	for _, deletion := range deleteCalls {
		if err := deletion.call(); err != nil && !apierrors.IsNotFound(err) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("delete %s: %w", deletion.kind, err))
		} else {
			report.RemovedPaths = append(report.RemovedPaths, "kubernetes://"+allocator.config.Namespace+"/"+deletion.kind+"/"+resources.Name)
		}
	}
	resourceWaitErr := wait.PollUntilContextCancel(ctx, 100*time.Millisecond, true, func(ctx context.Context) (bool, error) {
		checks := []func() error{
			func() error {
				_, err := allocator.client.BatchV1().Jobs(allocator.config.Namespace).Get(ctx, resources.Name, metav1.GetOptions{})
				return err
			},
			func() error {
				_, err := allocator.client.CoreV1().Services(allocator.config.Namespace).Get(ctx, resources.Name, metav1.GetOptions{})
				return err
			},
			func() error {
				_, err := allocator.client.NetworkingV1().NetworkPolicies(allocator.config.Namespace).Get(ctx, resources.Name, metav1.GetOptions{})
				return err
			},
			func() error {
				_, err := allocator.dynamic.Resource(CiliumNetworkPolicyGVR).Namespace(allocator.config.Namespace).Get(ctx, resources.Name, metav1.GetOptions{})
				return err
			},
			func() error {
				_, err := allocator.client.CoreV1().Secrets(allocator.config.Namespace).Get(ctx, resources.Name+"-tls", metav1.GetOptions{})
				return err
			},
			func() error {
				_, err := allocator.client.CoreV1().ServiceAccounts(allocator.config.Namespace).Get(ctx, resources.Name, metav1.GetOptions{})
				return err
			},
		}
		for _, check := range checks {
			err := check()
			if err == nil {
				return false, nil
			}
			if !apierrors.IsNotFound(err) {
				return false, err
			}
		}
		return true, nil
	})
	if resourceWaitErr != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("verify worker resource deletion: %w", resourceWaitErr))
	}
	if pod != nil {
		podGrace := int64(0)
		if err := allocator.client.CoreV1().Pods(allocator.config.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{GracePeriodSeconds: &podGrace}); err != nil && !apierrors.IsNotFound(err) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("delete worker pod: %w", err))
		}
		waitErr := wait.PollUntilContextCancel(ctx, 100*time.Millisecond, true, func(ctx context.Context) (bool, error) {
			_, err := allocator.client.CoreV1().Pods(allocator.config.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
			return apierrors.IsNotFound(err), ignoreNotFound(err)
		})
		if waitErr != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("wait for worker pod deletion: %w", waitErr))
		}
		residueReport, err := allocator.residue.Cleanup(ctx, ResidueRequest{BuildID: report.BuildID, PodUID: pod.UID, PodName: pod.Name, NodeName: pod.Spec.NodeName})
		if err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("node residue cleanup: %w", err))
		} else {
			report.Residue = append(report.Residue, residueReport.Residue...)
			report.RemovedPaths = append(report.RemovedPaths, residueReport.RemovedPaths...)
			if residueReport.Status != buildworker.CleanupClean {
				report.QuarantineReason = residueReport.QuarantineReason
				cleanupErrors = append(cleanupErrors, errors.New("node residue remains"))
			}
		}
	}
	if len(cleanupErrors) > 0 || len(report.Residue) > 0 {
		report.Status = buildworker.CleanupQuarantined
		if report.QuarantineReason == "" {
			report.QuarantineReason = "Kubernetes worker cleanup could not be proven"
		} else {
			report.QuarantineReason = "Kubernetes worker cleanup could not be proven: " + report.QuarantineReason
		}
		if pod != nil && pod.Spec.NodeName != "" {
			if err := allocator.quarantiner.Quarantine(context.WithoutCancel(ctx), pod.Spec.NodeName, report.BuildID, report.QuarantineReason); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("quarantine unsafe build node: %w", err))
				report.QuarantineReason += "; node taint failed"
			}
		}
		return report, errors.Join(cleanupErrors...)
	}
	return report, nil
}

func ignoreNotFound(err error) error {
	if err == nil || apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

type kubernetesWorker struct {
	identity      string
	buildID       string
	pod           *corev1.Pod
	resources     Resources
	executor      buildworker.Executor
	closer        io.Closer
	allocator     *Allocator
	cleanupOnce   sync.Once
	cleanupReport buildworker.CleanupReport
	cleanupErr    error
}

func (worker *kubernetesWorker) Identity() string { return worker.identity }

func (worker *kubernetesWorker) Execute(ctx context.Context, request buildworker.Request) (buildworker.Result, error) {
	return worker.executor.Execute(ctx, request)
}

func (worker *kubernetesWorker) ForceTerminate(ctx context.Context) (buildworker.CleanupReport, error) {
	return worker.cleanup(ctx, true)
}

func (worker *kubernetesWorker) Release(ctx context.Context) (buildworker.CleanupReport, error) {
	return worker.cleanup(ctx, false)
}

func (worker *kubernetesWorker) cleanup(ctx context.Context, force bool) (buildworker.CleanupReport, error) {
	worker.cleanupOnce.Do(func() {
		closeErr := worker.closer.Close()
		worker.cleanupReport, worker.cleanupErr = worker.allocator.deleteResources(ctx, worker.resources, worker.pod, force)
		if closeErr != nil {
			worker.cleanupReport.Status = buildworker.CleanupQuarantined
			worker.cleanupReport.QuarantineReason = "BuildKit client did not close cleanly"
			worker.cleanupErr = errors.Join(worker.cleanupErr, closeErr)
		}
	})
	return worker.cleanupReport, worker.cleanupErr
}

type KubernetesNodeQuarantiner struct {
	Client kubernetes.Interface
}

func (quarantiner KubernetesNodeQuarantiner) Quarantine(ctx context.Context, nodeName, buildID, reason string) error {
	if quarantiner.Client == nil || nodeName == "" || buildID == "" || reason == "" {
		return errors.New("node quarantine request is invalid")
	}
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		node, err := quarantiner.Client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		for _, taint := range node.Spec.Taints {
			if taint.Key == "lrail.dev/build-quarantined" {
				return nil
			}
		}
		node.Spec.Taints = append(node.Spec.Taints, corev1.Taint{Key: "lrail.dev/build-quarantined", Value: "true", Effect: corev1.TaintEffectNoSchedule, TimeAdded: &metav1.Time{Time: time.Now().UTC()}})
		if node.Annotations == nil {
			node.Annotations = map[string]string{}
		}
		node.Annotations["lrail.dev/quarantine-build"] = buildID
		node.Annotations["lrail.dev/quarantine-reason"] = reason
		_, err = quarantiner.Client.CoreV1().Nodes().Update(ctx, node, metav1.UpdateOptions{})
		return err
	})
}

var _ runtime.Object = (*batchv1.Job)(nil)
var _ runtime.Object = (*corev1.Service)(nil)
var _ runtime.Object = (*networkingv1.NetworkPolicy)(nil)
var _ runtime.Object = (*unstructured.Unstructured)(nil)
