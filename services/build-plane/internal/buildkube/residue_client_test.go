package buildkube

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"testing"

	lrailv1 "github.com/mayowaoladosu/layerrail-lrail/gen/go/lrail/v1"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
)

type fakeResidueClient struct {
	lrailv1.BuildResidueServiceClient
	response *lrailv1.CleanupBuildResidueResponse
	err      error
}

func (client *fakeResidueClient) CleanupResidue(context.Context, *lrailv1.CleanupBuildResidueRequest, ...grpc.CallOption) (*lrailv1.CleanupBuildResidueResponse, error) {
	return client.response, client.err
}

type residueResolverFunc func(context.Context, string) (lrailv1.BuildResidueServiceClient, io.Closer, error)

func (function residueResolverFunc) Resolve(ctx context.Context, nodeName string) (lrailv1.BuildResidueServiceClient, io.Closer, error) {
	return function(ctx, nodeName)
}

func TestGRPCResidueAgentMapsCompleteProof(t *testing.T) {
	t.Parallel()
	resolver := residueResolverFunc(func(_ context.Context, nodeName string) (lrailv1.BuildResidueServiceClient, io.Closer, error) {
		if nodeName != "node-1" {
			return nil, nil, errors.New("wrong node")
		}
		return &fakeResidueClient{response: &lrailv1.CleanupBuildResidueResponse{
			Cleanup:      &lrailv1.BuildCellCleanup{Status: string(buildworker.CleanupClean), ResidueCount: 0},
			RemovedPaths: []string{"cri://sandbox/fake"},
		}}, nopCloser{}, nil
	})
	report, err := (GRPCResidueAgent{Resolver: resolver}).Cleanup(context.Background(), ResidueRequest{
		BuildID: kubeBuildID, PodUID: types.UID("fake-pod-uid"), PodName: "fake-pod", NodeName: "node-1",
	})
	if err != nil || report.Status != buildworker.CleanupClean || len(report.RemovedPaths) != 1 {
		t.Fatalf("report=%#v error=%v", report, err)
	}
}

func TestGRPCResidueAgentRejectsInconsistentResponse(t *testing.T) {
	t.Parallel()
	resolver := residueResolverFunc(func(context.Context, string) (lrailv1.BuildResidueServiceClient, io.Closer, error) {
		return &fakeResidueClient{response: &lrailv1.CleanupBuildResidueResponse{
			Cleanup: &lrailv1.BuildCellCleanup{Status: string(buildworker.CleanupClean), ResidueCount: 1},
		}}, nopCloser{}, nil
	})
	if _, err := (GRPCResidueAgent{Resolver: resolver}).Cleanup(context.Background(), ResidueRequest{BuildID: kubeBuildID, NodeName: "node-1"}); err == nil {
		t.Fatal("expected inconsistent response rejection")
	}
}

func TestKubernetesResidueResolverRequiresOneReadyAgentOnNode(t *testing.T) {
	t.Parallel()
	labels := map[string]string{"app.kubernetes.io/name": "lrail-residue-agent"}
	ready := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "agent-1", Namespace: "lrail-build-system", Labels: labels},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
	client := kubernetesfake.NewClientset(&ready)
	resolver := KubernetesResidueResolver{Client: client, Namespace: "lrail-build-system", Labels: labels, TLSConfig: &tls.Config{ServerName: "residue-agent.lrail.internal", MinVersion: tls.VersionTLS13}}
	_, closer, err := resolver.Resolve(context.Background(), "node-1")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	_ = closer.Close()
	duplicate := ready.DeepCopy()
	duplicate.Name = "agent-2"
	if _, err := client.CoreV1().Pods("lrail-build-system").Create(context.Background(), duplicate, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Create duplicate: %v", err)
	}
	if _, _, err := resolver.Resolve(context.Background(), "node-1"); err == nil {
		t.Fatal("expected duplicate agent rejection")
	}
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }
