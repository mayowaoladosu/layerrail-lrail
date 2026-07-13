package buildkube

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"

	lrailv1 "github.com/mayowaoladosu/layerrail-lrail/gen/go/lrail/v1"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

const DefaultResidueAgentPort = 9444

type ResidueResolver interface {
	Resolve(ctx context.Context, nodeName string) (lrailv1.BuildResidueServiceClient, io.Closer, error)
}

type GRPCResidueAgent struct {
	Resolver ResidueResolver
}

func (agent GRPCResidueAgent) Cleanup(ctx context.Context, request ResidueRequest) (buildworker.CleanupReport, error) {
	if agent.Resolver == nil {
		return buildworker.CleanupReport{}, errors.New("residue client resolver is absent")
	}
	client, closer, err := agent.Resolver.Resolve(ctx, request.NodeName)
	if err != nil {
		return buildworker.CleanupReport{}, err
	}
	defer closer.Close()
	response, err := client.CleanupResidue(ctx, &lrailv1.CleanupBuildResidueRequest{
		BuildId: request.BuildID, PodUid: string(request.PodUID), PodName: request.PodName, NodeName: request.NodeName,
	})
	if err != nil || response == nil || response.Cleanup == nil || int(response.Cleanup.ResidueCount) != len(response.Residues) {
		return buildworker.CleanupReport{}, errors.New("residue agent response is absent or inconsistent")
	}
	report := buildworker.CleanupReport{
		BuildID: request.BuildID, Status: buildworker.CleanupStatus(response.Cleanup.Status),
		QuarantineReason: response.Cleanup.QuarantineReason, RemovedPaths: append([]string(nil), response.RemovedPaths...), Residue: []buildworker.Residue{},
	}
	for _, residue := range response.Residues {
		if residue == nil || residue.Kind == "" {
			return buildworker.CleanupReport{}, errors.New("residue agent returned an invalid finding")
		}
		report.Residue = append(report.Residue, buildworker.Residue{Kind: residue.Kind, Target: residue.Target, Detail: residue.Detail})
	}
	if report.Status != buildworker.CleanupClean && report.Status != buildworker.CleanupQuarantined {
		return buildworker.CleanupReport{}, errors.New("residue agent returned an unknown cleanup status")
	}
	return report, nil
}

type KubernetesResidueResolver struct {
	Client    kubernetes.Interface
	Namespace string
	Labels    map[string]string
	TLSConfig *tls.Config
	Port      int
}

func (resolver KubernetesResidueResolver) Resolve(ctx context.Context, nodeName string) (lrailv1.BuildResidueServiceClient, io.Closer, error) {
	if resolver.Client == nil || resolver.Namespace == "" || len(resolver.Labels) == 0 || resolver.TLSConfig == nil || resolver.TLSConfig.ServerName == "" || nodeName == "" {
		return nil, nil, errors.New("Kubernetes residue resolver is incomplete")
	}
	if resolver.Port == 0 {
		resolver.Port = DefaultResidueAgentPort
	}
	if resolver.Port < 1 || resolver.Port > 65535 {
		return nil, nil, errors.New("residue agent port is invalid")
	}
	pods, err := resolver.Client.CoreV1().Pods(resolver.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.Set(resolver.Labels).String(), FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("list residue agents: %w", err)
	}
	endpoint := ""
	for index := range pods.Items {
		pod := &pods.Items[index]
		if pod.Spec.NodeName != nodeName || pod.Status.Phase != "Running" || pod.Status.PodIP == "" {
			continue
		}
		ready := false
		for _, condition := range pod.Status.Conditions {
			ready = ready || condition.Type == "Ready" && condition.Status == "True"
		}
		if !ready {
			continue
		}
		if endpoint != "" {
			return nil, nil, errors.New("multiple ready residue agents found for one node")
		}
		address, err := netip.ParseAddr(pod.Status.PodIP)
		if err != nil {
			return nil, nil, errors.New("residue agent Pod IP is invalid")
		}
		endpoint = net.JoinHostPort(address.String(), fmt.Sprintf("%d", resolver.Port))
	}
	if endpoint == "" {
		return nil, nil, errors.New("ready residue agent is unavailable on worker node")
	}
	tlsConfig := resolver.TLSConfig.Clone()
	tlsConfig.MinVersion = tls.VersionTLS13
	connection, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, nil, fmt.Errorf("connect to residue agent: %w", err)
	}
	return lrailv1.NewBuildResidueServiceClient(connection), connection, nil
}
