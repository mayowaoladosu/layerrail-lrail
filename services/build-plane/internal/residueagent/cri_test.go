package residueagent

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	runtimev1 "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type fakeCRIClient struct {
	runtimev1.RuntimeServiceClient
	podUID            string
	containers        []*runtimev1.Container
	sandboxes         []*runtimev1.PodSandbox
	stoppedContainers []string
	removedContainers []string
	stoppedSandboxes  []string
	removedSandboxes  []string
	alreadyRemoved    bool
}

func (client *fakeCRIClient) ListContainers(_ context.Context, request *runtimev1.ListContainersRequest, _ ...grpc.CallOption) (*runtimev1.ListContainersResponse, error) {
	if request.GetFilter().GetLabelSelector()[PodUIDLabel] != client.podUID {
		return nil, errors.New("unexpected container filter")
	}
	return &runtimev1.ListContainersResponse{Containers: client.containers}, nil
}

func (client *fakeCRIClient) ListPodSandbox(_ context.Context, request *runtimev1.ListPodSandboxRequest, _ ...grpc.CallOption) (*runtimev1.ListPodSandboxResponse, error) {
	if request.GetFilter().GetLabelSelector()[PodUIDLabel] != client.podUID {
		return nil, errors.New("unexpected sandbox filter")
	}
	return &runtimev1.ListPodSandboxResponse{Items: client.sandboxes}, nil
}

func (client *fakeCRIClient) StopContainer(_ context.Context, request *runtimev1.StopContainerRequest, _ ...grpc.CallOption) (*runtimev1.StopContainerResponse, error) {
	client.stoppedContainers = append(client.stoppedContainers, request.ContainerId)
	if client.alreadyRemoved {
		return nil, status.Error(codes.NotFound, "already removed")
	}
	return &runtimev1.StopContainerResponse{}, nil
}

func (client *fakeCRIClient) RemoveContainer(_ context.Context, request *runtimev1.RemoveContainerRequest, _ ...grpc.CallOption) (*runtimev1.RemoveContainerResponse, error) {
	client.removedContainers = append(client.removedContainers, request.ContainerId)
	client.containers = nil
	if client.alreadyRemoved {
		return nil, status.Error(codes.NotFound, "already removed")
	}
	return &runtimev1.RemoveContainerResponse{}, nil
}

func (client *fakeCRIClient) StopPodSandbox(_ context.Context, request *runtimev1.StopPodSandboxRequest, _ ...grpc.CallOption) (*runtimev1.StopPodSandboxResponse, error) {
	client.stoppedSandboxes = append(client.stoppedSandboxes, request.PodSandboxId)
	if client.alreadyRemoved {
		return nil, status.Error(codes.NotFound, "already removed")
	}
	return &runtimev1.StopPodSandboxResponse{}, nil
}

func (client *fakeCRIClient) RemovePodSandbox(_ context.Context, request *runtimev1.RemovePodSandboxRequest, _ ...grpc.CallOption) (*runtimev1.RemovePodSandboxResponse, error) {
	client.removedSandboxes = append(client.removedSandboxes, request.PodSandboxId)
	client.sandboxes = nil
	if client.alreadyRemoved {
		return nil, status.Error(codes.NotFound, "already removed")
	}
	return &runtimev1.RemovePodSandboxResponse{}, nil
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func TestCRIRuntimeRemovesExactPodContainersAndNetworkSandbox(t *testing.T) {
	t.Parallel()
	client := &fakeCRIClient{
		podUID:     residuePodUID,
		containers: []*runtimev1.Container{{Id: "container-1", Labels: map[string]string{PodUIDLabel: residuePodUID}}},
		sandboxes:  []*runtimev1.PodSandbox{{Id: "sandbox-1", Labels: map[string]string{PodUIDLabel: residuePodUID}}},
	}
	runtime := &CRIRuntime{client: client, closer: nopCloser{}, timeout: time.Second}
	removed, err := runtime.CleanupPod(context.Background(), residuePodUID)
	if err != nil || len(removed) != 2 || len(client.stoppedContainers) != 1 || len(client.removedContainers) != 1 || len(client.stoppedSandboxes) != 1 || len(client.removedSandboxes) != 1 {
		t.Fatalf("removed=%#v error=%v client=%#v", removed, err, client)
	}
	residue, err := runtime.InspectPod(context.Background(), residuePodUID)
	if err != nil || len(residue) != 0 {
		t.Fatalf("residue=%#v error=%v", residue, err)
	}
}

func TestCRIRuntimeRejectsOutOfScopeRuntimeResponse(t *testing.T) {
	t.Parallel()
	client := &fakeCRIClient{
		podUID:     residuePodUID,
		containers: []*runtimev1.Container{{Id: "container-other", Labels: map[string]string{PodUIDLabel: "other-pod"}}},
		sandboxes:  []*runtimev1.PodSandbox{},
	}
	runtime := &CRIRuntime{client: client, closer: nopCloser{}, timeout: time.Second}
	if _, err := runtime.CleanupPod(context.Background(), residuePodUID); err == nil {
		t.Fatal("expected out-of-scope response rejection")
	}
	if len(client.stoppedContainers) != 0 || len(client.removedContainers) != 0 {
		t.Fatalf("out-of-scope container was touched: %#v", client)
	}
}

func TestCRIRuntimeTreatsAlreadyRemovedResourcesAsClean(t *testing.T) {
	t.Parallel()
	client := &fakeCRIClient{
		podUID: residuePodUID, alreadyRemoved: true,
		containers: []*runtimev1.Container{{Id: "container-gone", Labels: map[string]string{PodUIDLabel: residuePodUID}}},
		sandboxes:  []*runtimev1.PodSandbox{{Id: "sandbox-gone", Labels: map[string]string{PodUIDLabel: residuePodUID}}},
	}
	runtime := &CRIRuntime{client: client, closer: nopCloser{}, timeout: time.Second}
	removed, err := runtime.CleanupPod(context.Background(), residuePodUID)
	if err != nil || len(removed) != 2 || len(client.removedContainers) != 1 || len(client.removedSandboxes) != 1 {
		t.Fatalf("removed=%#v error=%v client=%#v", removed, err, client)
	}
}
