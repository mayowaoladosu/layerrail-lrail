package residueagent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	runtimev1 "k8s.io/cri-api/pkg/apis/runtime/v1"
)

const PodUIDLabel = "io.kubernetes.pod.uid"
const DefaultCRITimeout = 30 * time.Second
const MaxCRIResourcesPerPod = 1024

type CRIRuntime struct {
	client  runtimev1.RuntimeServiceClient
	closer  interface{ Close() error }
	timeout time.Duration
}

func NewCRIRuntime(socketPath string, timeout time.Duration) (*CRIRuntime, error) {
	if !filepath.IsAbs(socketPath) {
		return nil, errors.New("CRI socket path must be absolute")
	}
	info, err := os.Lstat(socketPath)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("CRI endpoint is absent, not a socket, or a symlink")
	}
	if timeout == 0 {
		timeout = DefaultCRITimeout
	}
	if timeout < time.Second || timeout > time.Minute {
		return nil, errors.New("CRI timeout is outside bounds")
	}
	dialer := new(net.Dialer)
	connection, err := grpc.NewClient("passthrough:///lrail-cri",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("create CRI client: %w", err)
	}
	return &CRIRuntime{client: runtimev1.NewRuntimeServiceClient(connection), closer: connection, timeout: timeout}, nil
}

func (runtime *CRIRuntime) Close() error {
	return runtime.closer.Close()
}

func (runtime *CRIRuntime) CleanupPod(ctx context.Context, podUID string) ([]string, error) {
	operationContext, cancel := context.WithTimeout(ctx, runtime.timeout)
	defer cancel()
	containers, sandboxes, err := runtime.resources(operationContext, podUID)
	if err != nil {
		return nil, err
	}
	removed := []string{}
	var cleanupErrors []error
	for _, container := range containers {
		if _, err := runtime.client.StopContainer(operationContext, &runtimev1.StopContainerRequest{ContainerId: container.Id, Timeout: 0}); err != nil && !isCRINotFound(err) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("stop CRI container %s: %w", container.Id, err))
			continue
		}
		if _, err := runtime.client.RemoveContainer(operationContext, &runtimev1.RemoveContainerRequest{ContainerId: container.Id}); err != nil && !isCRINotFound(err) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove CRI container %s: %w", container.Id, err))
			continue
		}
		removed = append(removed, "cri://container/"+container.Id)
	}
	for _, sandbox := range sandboxes {
		if _, err := runtime.client.StopPodSandbox(operationContext, &runtimev1.StopPodSandboxRequest{PodSandboxId: sandbox.Id}); err != nil && !isCRINotFound(err) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("stop CRI sandbox %s: %w", sandbox.Id, err))
			continue
		}
		if _, err := runtime.client.RemovePodSandbox(operationContext, &runtimev1.RemovePodSandboxRequest{PodSandboxId: sandbox.Id}); err != nil && !isCRINotFound(err) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove CRI sandbox %s: %w", sandbox.Id, err))
			continue
		}
		removed = append(removed, "cri://sandbox/"+sandbox.Id)
	}
	return removed, errors.Join(cleanupErrors...)
}

func (runtime *CRIRuntime) InspectPod(ctx context.Context, podUID string) ([]buildworker.Residue, error) {
	operationContext, cancel := context.WithTimeout(ctx, runtime.timeout)
	defer cancel()
	containers, sandboxes, err := runtime.resources(operationContext, podUID)
	residue := make([]buildworker.Residue, 0, len(containers)+len(sandboxes))
	for _, container := range containers {
		residue = append(residue, buildworker.Residue{Kind: "cri_container", Target: container.Id, Detail: "Pod container remains"})
	}
	for _, sandbox := range sandboxes {
		residue = append(residue, buildworker.Residue{Kind: "network_sandbox", Target: sandbox.Id, Detail: "Pod network sandbox remains"})
	}
	return residue, err
}

func (runtime *CRIRuntime) resources(ctx context.Context, podUID string) ([]*runtimev1.Container, []*runtimev1.PodSandbox, error) {
	containersResponse, err := runtime.client.ListContainers(ctx, &runtimev1.ListContainersRequest{Filter: &runtimev1.ContainerFilter{LabelSelector: map[string]string{PodUIDLabel: podUID}}})
	if err != nil || containersResponse == nil {
		return nil, nil, errors.New("list CRI containers")
	}
	sandboxesResponse, err := runtime.client.ListPodSandbox(ctx, &runtimev1.ListPodSandboxRequest{Filter: &runtimev1.PodSandboxFilter{LabelSelector: map[string]string{PodUIDLabel: podUID}}})
	if err != nil || sandboxesResponse == nil {
		return nil, nil, errors.New("list CRI sandboxes")
	}
	if len(containersResponse.Containers) > MaxCRIResourcesPerPod || len(sandboxesResponse.Items) > MaxCRIResourcesPerPod {
		return nil, nil, errors.New("CRI returned an unbounded Pod resource set")
	}
	for _, container := range containersResponse.Containers {
		if container == nil || container.Id == "" || container.Labels[PodUIDLabel] != podUID {
			return nil, nil, errors.New("CRI returned a container outside the requested Pod")
		}
	}
	for _, sandbox := range sandboxesResponse.Items {
		if sandbox == nil || sandbox.Id == "" || sandbox.Labels[PodUIDLabel] != podUID {
			return nil, nil, errors.New("CRI returned a sandbox outside the requested Pod")
		}
	}
	return containersResponse.Containers, sandboxesResponse.Items, nil
}

func isCRINotFound(err error) bool {
	return status.Code(err) == codes.NotFound
}
