// Package buildkube allocates isolated disposable BuildKit workers on Kubernetes.
package buildkube

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcontrol"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildegress"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
	ocidigest "github.com/opencontainers/go-digest"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

const (
	BuildKitPort                  = 1234
	DefaultActiveDeadline         = time.Hour
	DefaultTTLAfterFinished       = 300
	DefaultTerminationGrace       = 30
	DefaultScratchBytes     int64 = 20 << 30
	DefaultScratchInodes          = 1_000_000
	CiliumPolicyAPIVersion        = "cilium.io/v2"
	CiliumPolicyKind              = "CiliumNetworkPolicy"
)

var CiliumNetworkPolicyGVR = schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"}
var dnsNamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)

type Config struct {
	Namespace               string
	ControllerNamespace     string
	ControllerLabels        map[string]string
	RuntimeClass            string
	WorkerImage             string
	ImagePullSecret         string
	SeccompProfile          string
	AppArmorProfile         string
	NodeSelector            map[string]string
	Tolerations             []corev1.Toleration
	PriorityClass           string
	ClusterDNSCIDR          string
	AllowedPrivateEndpoints map[string]PrivateEndpoint
	ScratchBytes            int64
	ScratchInodes           int64
	CPURequest              string
	CPULimit                string
	MemoryRequest           string
	MemoryLimit             string
	EphemeralRequest        string
	EphemeralLimit          string
	ActiveDeadline          time.Duration
}

type PrivateEndpoint = buildegress.PrivateEndpoint

type TLSMaterial struct {
	CA               []byte
	ServerCert       []byte
	ServerKey        []byte
	EgressClientCert []byte
	EgressClientKey  []byte
	EgressServerCA   []byte
}

type Resources struct {
	Name           string
	Labels         map[string]string
	ServiceAccount *corev1.ServiceAccount
	TLSSecret      *corev1.Secret
	Service        *corev1.Service
	NetworkPolicy  *networkingv1.NetworkPolicy
	CiliumPolicy   *unstructured.Unstructured
	Job            *batchv1.Job
}

func BuildResources(config Config, request buildcontrol.AllocationRequest, tlsMaterial TLSMaterial, now time.Time) (Resources, error) {
	config, err := normalizeConfig(config)
	if err != nil {
		return Resources{}, err
	}
	if err := request.Assignment.Validate(); err != nil || request.Attempt == 0 || request.LeaseID == "" || !request.ExpiresAt.After(now) ||
		len(tlsMaterial.CA) == 0 || len(tlsMaterial.ServerCert) == 0 || len(tlsMaterial.ServerKey) == 0 || len(tlsMaterial.EgressClientCert) == 0 ||
		len(tlsMaterial.EgressClientKey) == 0 || len(tlsMaterial.EgressServerCA) == 0 {
		return Resources{}, errors.New("worker allocation request is invalid")
	}
	if !equalNetwork(request.Network, request.Assignment.Verified.Payload.Lock.Network) || !equalCaches(request.Caches, request.Assignment.Verified.Payload.Lock.Caches) {
		return Resources{}, errors.New("worker allocation capabilities do not match the signed lock")
	}
	name := resourceName(request.Assignment.Verified.Payload.BuildID, request.Attempt)
	labels := map[string]string{
		"app.kubernetes.io/name":      "lrail-build-worker",
		"app.kubernetes.io/component": "buildkit",
		"lrail.dev/build-id":          labelHash(request.Assignment.Verified.Payload.BuildID),
		"lrail.dev/assignment":        name,
		"lrail.dev/organization":      labelHash(request.Assignment.Verified.Payload.OrganizationID),
	}
	annotations := map[string]string{
		"lrail.dev/build-id":          request.Assignment.Verified.Payload.BuildID,
		"lrail.dev/definition-digest": request.Assignment.Verified.Payload.DefinitionDigest,
		"lrail.dev/payload-digest":    request.Assignment.Verified.PayloadDigest,
		"lrail.dev/generation":        fmt.Sprintf("%d", request.Assignment.Verified.Payload.Generation),
	}
	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta:                   metav1.ObjectMeta{Name: name, Namespace: config.Namespace, Labels: cloneMap(labels)},
		AutomountServiceAccountToken: ptr.To(false),
		ImagePullSecrets:             []corev1.LocalObjectReference{{Name: config.ImagePullSecret}},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name + "-tls", Namespace: config.Namespace, Labels: cloneMap(labels)},
		Type:       corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"ca.pem": append([]byte(nil), tlsMaterial.CA...), "server.pem": append([]byte(nil), tlsMaterial.ServerCert...), "server-key.pem": append([]byte(nil), tlsMaterial.ServerKey...),
			"egress-client.pem": append([]byte(nil), tlsMaterial.EgressClientCert...), "egress-client-key.pem": append([]byte(nil), tlsMaterial.EgressClientKey...),
			"egress-ca.pem": append([]byte(nil), tlsMaterial.EgressServerCA...),
		},
	}
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: config.Namespace, Labels: cloneMap(labels)},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP, Selector: cloneMap(labels), PublishNotReadyAddresses: false,
			Ports: []corev1.ServicePort{{Name: "buildkit", Protocol: corev1.ProtocolTCP, Port: BuildKitPort, TargetPort: intstr.FromInt32(BuildKitPort)}},
		},
	}
	networkPolicy := buildNetworkPolicy(config, name, labels)
	ciliumPolicy, err := buildCiliumPolicy(config, name, labels, request)
	if err != nil {
		return Resources{}, err
	}
	job, err := buildJob(config, name, labels, annotations, request, now)
	if err != nil {
		return Resources{}, err
	}
	return Resources{Name: name, Labels: labels, ServiceAccount: serviceAccount, TLSSecret: secret, Service: service, NetworkPolicy: networkPolicy, CiliumPolicy: ciliumPolicy, Job: job}, nil
}

func normalizeConfig(config Config) (Config, error) {
	if config.ScratchBytes == 0 {
		config.ScratchBytes = DefaultScratchBytes
	}
	if config.ScratchInodes == 0 {
		config.ScratchInodes = DefaultScratchInodes
	}
	if config.ActiveDeadline == 0 {
		config.ActiveDeadline = DefaultActiveDeadline
	}
	if config.Namespace == "" || config.ControllerNamespace == "" || len(config.ControllerLabels) == 0 || config.RuntimeClass == "" ||
		!dnsNamePattern.MatchString(config.ImagePullSecret) || config.SeccompProfile == "" || config.AppArmorProfile == "" || len(config.NodeSelector) == 0 ||
		config.ClusterDNSCIDR == "" || config.ScratchBytes < 1 || config.ScratchBytes > DefaultScratchBytes ||
		config.ScratchInodes < 1 || config.ScratchInodes > DefaultScratchInodes || config.ActiveDeadline <= 0 || config.ActiveDeadline > DefaultActiveDeadline {
		return Config{}, errors.New("Kubernetes build-cell configuration is incomplete or unsafe")
	}
	workerImage, err := reference.ParseNormalizedNamed(config.WorkerImage)
	digested, pinned := workerImage.(reference.Digested)
	if err != nil || !pinned || digested.Digest().Algorithm() != ocidigest.SHA256 || digested.Digest().Validate() != nil {
		return Config{}, errors.New("Kubernetes worker image is not pinned to a valid SHA-256 digest")
	}
	for _, value := range []string{config.CPURequest, config.CPULimit, config.MemoryRequest, config.MemoryLimit, config.EphemeralRequest, config.EphemeralLimit} {
		if _, err := resource.ParseQuantity(value); err != nil {
			return Config{}, errors.New("Kubernetes worker resource quantity is invalid")
		}
	}
	dnsPrefix, err := netip.ParsePrefix(config.ClusterDNSCIDR)
	if err != nil || dnsPrefix.Bits() != dnsPrefix.Addr().BitLen() || !dnsPrefix.Addr().IsPrivate() || dnsPrefix.Addr().IsLoopback() || dnsPrefix.Addr().IsLinkLocalUnicast() || dnsPrefix.Addr().IsMulticast() || dnsPrefix.Addr().IsUnspecified() {
		return Config{}, errors.New("cluster DNS CIDR is invalid")
	}
	for gateway, endpoint := range config.AllowedPrivateEndpoints {
		if gateway == "" || len(endpoint.CIDRs) == 0 || len(endpoint.Ports) == 0 {
			return Config{}, errors.New("private endpoint mapping is invalid")
		}
		endpoint.CIDRs = sortedUnique(endpoint.CIDRs)
		for _, cidr := range endpoint.CIDRs {
			privatePrefix, prefixErr := netip.ParsePrefix(cidr)
			if !allowedPrivateEndpointCIDR(cidr) || prefixErr != nil || privatePrefix.Overlaps(dnsPrefix) {
				return Config{}, errors.New("private endpoint CIDR is invalid or outside private ranges")
			}
		}
		slices.Sort(endpoint.Ports)
		endpoint.Ports = slices.Compact(endpoint.Ports)
		for _, port := range endpoint.Ports {
			if port < 1 || port > 65535 {
				return Config{}, errors.New("private endpoint port is invalid")
			}
		}
		endpoint.Hosts = sortedUnique(endpoint.Hosts)
		for _, host := range endpoint.Hosts {
			_, addressErr := netip.ParseAddr(host)
			if !dnsNamePattern.MatchString(host) || host == "localhost" || strings.HasSuffix(host, ".localhost") || addressErr == nil {
				return Config{}, errors.New("private endpoint host is invalid")
			}
		}
		config.AllowedPrivateEndpoints[gateway] = endpoint
	}
	return config, nil
}

func buildJob(config Config, name string, labels, annotations map[string]string, request buildcontrol.AllocationRequest, now time.Time) (*batchv1.Job, error) {
	remaining := request.ExpiresAt.Sub(now)
	if remaining > config.ActiveDeadline {
		remaining = config.ActiveDeadline
	}
	activeSeconds := int64(remaining.Round(time.Second) / time.Second)
	if activeSeconds < 1 {
		return nil, errors.New("worker assignment deadline has elapsed")
	}
	seccompProfile := seccompProfile(config.SeccompProfile)
	appArmorProfile := appArmorProfile(config.AppArmorProfile)
	strictGroups := corev1.SupplementalGroupsPolicyStrict
	root := int64(1000)
	group := int64(1000)
	nonRoot := true
	allowEscalation := false
	readOnly := true
	terminationLog := corev1.TerminationMessageFallbackToLogsOnError
	stateLimit := *resource.NewQuantity(config.ScratchBytes, resource.BinarySI)
	resources := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU: resource.MustParse(config.CPURequest), corev1.ResourceMemory: resource.MustParse(config.MemoryRequest),
			corev1.ResourceEphemeralStorage: resource.MustParse(config.EphemeralRequest),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU: resource.MustParse(config.CPULimit), corev1.ResourceMemory: resource.MustParse(config.MemoryLimit),
			corev1.ResourceEphemeralStorage: resource.MustParse(config.EphemeralLimit),
		},
	}
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: config.Namespace, Labels: cloneMap(labels), Annotations: cloneMap(annotations)},
		Spec: batchv1.JobSpec{
			BackoffLimit: ptr.To(int32(0)), ActiveDeadlineSeconds: ptr.To(activeSeconds), TTLSecondsAfterFinished: ptr.To(int32(DefaultTTLAfterFinished)),
			CompletionMode: ptr.To(batchv1.NonIndexedCompletion),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: cloneMap(labels), Annotations: cloneMap(annotations)},
				Spec: corev1.PodSpec{
					ServiceAccountName: name, AutomountServiceAccountToken: ptr.To(false), RestartPolicy: corev1.RestartPolicyNever,
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: config.ImagePullSecret}},
					RuntimeClassName: ptr.To(config.RuntimeClass), EnableServiceLinks: ptr.To(false), HostNetwork: false, HostPID: false, HostIPC: false,
					ShareProcessNamespace: ptr.To(false), DNSPolicy: corev1.DNSClusterFirst, PriorityClassName: config.PriorityClass,
					NodeSelector: cloneMap(config.NodeSelector), Tolerations: append([]corev1.Toleration(nil), config.Tolerations...),
					TerminationGracePeriodSeconds: ptr.To(int64(DefaultTerminationGrace)),
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: &nonRoot, RunAsUser: &root, RunAsGroup: &group, FSGroup: &group,
						FSGroupChangePolicy: ptr.To(corev1.FSGroupChangeOnRootMismatch), SupplementalGroupsPolicy: &strictGroups,
						SeccompProfile: seccompProfile, AppArmorProfile: appArmorProfile,
					},
					Containers: []corev1.Container{{
						Name: "buildkit", Image: config.WorkerImage, ImagePullPolicy: corev1.PullIfNotPresent,
						Args: []string{
							"--addr", fmt.Sprintf("tcp://0.0.0.0:%d", BuildKitPort), "--oci-worker-no-process-sandbox",
							"--root", "/var/lib/lrail-worker/buildkit",
							"--tlscacert", "/run/lrail-tls/ca.pem", "--tlscert", "/run/lrail-tls/server.pem", "--tlskey", "/run/lrail-tls/server-key.pem",
						},
						Env: []corev1.EnvVar{
							{Name: "LRAIL_QUOTA_ROOT", Value: "/var/lib/lrail-worker"},
							{Name: "LRAIL_SCRATCH_BYTES", Value: fmt.Sprintf("%d", config.ScratchBytes)},
							{Name: "LRAIL_SCRATCH_INODES", Value: fmt.Sprintf("%d", config.ScratchInodes)},
							{Name: "XDG_RUNTIME_DIR", Value: "/var/lib/lrail-worker/run"},
							{Name: "TMPDIR", Value: "/var/lib/lrail-worker/tmp"},
							{Name: "HTTP_PROXY", Value: llbcompiler.BuildEgressProxyURL},
							{Name: "HTTPS_PROXY", Value: llbcompiler.BuildEgressProxyURL},
							{Name: "http_proxy", Value: llbcompiler.BuildEgressProxyURL},
							{Name: "https_proxy", Value: llbcompiler.BuildEgressProxyURL},
							{Name: "NO_PROXY", Value: "127.0.0.1,localhost"},
							{Name: "no_proxy", Value: "127.0.0.1,localhost"},
							{Name: "LRAIL_EGRESS_PROXY_ADDRESS", Value: buildegress.ProxyAddress},
							{Name: "LRAIL_EGRESS_PROXY_SERVER_NAME", Value: buildegress.ProxyServerName},
							{Name: "LRAIL_EGRESS_CLIENT_CERT", Value: "/run/lrail-tls/egress-client.pem"},
							{Name: "LRAIL_EGRESS_CLIENT_KEY", Value: "/run/lrail-tls/egress-client-key.pem"},
							{Name: "LRAIL_EGRESS_SERVER_CA", Value: "/run/lrail-tls/egress-ca.pem"},
						},
						Ports: []corev1.ContainerPort{{Name: "buildkit", ContainerPort: BuildKitPort, Protocol: corev1.ProtocolTCP}},
						SecurityContext: &corev1.SecurityContext{
							RunAsNonRoot: &nonRoot, RunAsUser: &root, RunAsGroup: &group, AllowPrivilegeEscalation: &allowEscalation,
							ReadOnlyRootFilesystem: &readOnly, Privileged: ptr.To(false), ProcMount: ptr.To(corev1.DefaultProcMount),
							Capabilities:   &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
							SeccompProfile: seccompProfile.DeepCopy(), AppArmorProfile: appArmorProfile.DeepCopy(),
						},
						Resources: resources, TerminationMessagePolicy: terminationLog,
						ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromString("buildkit")}}, InitialDelaySeconds: 2, PeriodSeconds: 2, TimeoutSeconds: 1, FailureThreshold: 30},
						VolumeMounts: []corev1.VolumeMount{
							{Name: "state", MountPath: "/var/lib/lrail-worker"}, {Name: "tmp", MountPath: "/tmp"},
							{Name: "tls", MountPath: "/run/lrail-tls", ReadOnly: true},
						},
					}},
					Volumes: []corev1.Volume{
						{Name: "state", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &stateLimit}}},
						{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory, SizeLimit: resource.NewQuantity(64<<20, resource.BinarySI)}}},
						{Name: "tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: name + "-tls", DefaultMode: ptr.To(int32(0o440))}}},
					},
				},
			},
		},
	}, nil
}

func buildNetworkPolicy(config Config, name string, labels map[string]string) *networkingv1.NetworkPolicy {
	controllerNamespace := metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": config.ControllerNamespace}}
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: config.Namespace, Labels: cloneMap(labels)},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: cloneMap(labels)},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From:  []networkingv1.NetworkPolicyPeer{{NamespaceSelector: &controllerNamespace, PodSelector: &metav1.LabelSelector{MatchLabels: cloneMap(config.ControllerLabels)}}},
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To(intstr.FromInt32(BuildKitPort))}},
			}},
		},
	}
}

func seccompProfile(value string) *corev1.SeccompProfile {
	if value == "RuntimeDefault" {
		return &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
	}
	return &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeLocalhost, LocalhostProfile: ptr.To(value)}
}

func appArmorProfile(value string) *corev1.AppArmorProfile {
	if value == "RuntimeDefault" {
		return &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeRuntimeDefault}
	}
	return &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeLocalhost, LocalhostProfile: ptr.To(value)}
}

func buildCiliumPolicy(config Config, name string, labels map[string]string, request buildcontrol.AllocationRequest) (*unstructured.Unstructured, error) {
	for _, capability := range request.Network {
		if capability.Profile == "private" {
			if _, allowed := config.AllowedPrivateEndpoints[capability.GatewayID]; !allowed {
				return nil, errors.New("private network capability has no configured endpoint mapping")
			}
		}
	}
	egress := []any{
		map[string]any{
			"toEndpoints": []any{map[string]any{"matchLabels": map[string]any{"k8s:io.kubernetes.pod.namespace": "kube-system", "k8s:k8s-app": "kube-dns"}}},
			"toPorts": []any{map[string]any{
				"ports": []any{map[string]any{"port": "53", "protocol": "UDP"}, map[string]any{"port": "53", "protocol": "TCP"}},
				"rules": map[string]any{"dns": []any{map[string]any{"matchName": buildegress.ProxyServerName}}},
			}},
		},
		map[string]any{
			"toEndpoints": []any{map[string]any{"matchLabels": map[string]any{
				"k8s:io.kubernetes.pod.namespace": buildegress.ProxyNamespace,
				"k8s:app.kubernetes.io/name":      buildegress.ProxyServiceName,
			}}},
			"toPorts": []any{map[string]any{"ports": []any{map[string]any{"port": fmt.Sprintf("%d", buildegress.ProxyPort), "protocol": "TCP"}}}},
		},
	}
	// Customer destinations are intentionally absent: every networked solve
	// must traverse the certificate-bound policy proxy above.
	privateDeny := []any{}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "::1/128", "fe80::/10", "ff00::/8"} {
		privateDeny = append(privateDeny, map[string]any{"cidr": cidr})
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": CiliumPolicyAPIVersion, "kind": CiliumPolicyKind,
		"metadata": map[string]any{"name": name, "namespace": config.Namespace, "labels": stringMapAny(labels)},
		"spec": map[string]any{
			"endpointSelector": map[string]any{"matchLabels": stringMapAny(labels)},
			"ingress": []any{map[string]any{
				"fromEndpoints": []any{map[string]any{"matchLabels": mergeAny(map[string]any{"k8s:io.kubernetes.pod.namespace": config.ControllerNamespace}, stringMapAny(config.ControllerLabels))}},
				"toPorts":       []any{map[string]any{"ports": []any{map[string]any{"port": fmt.Sprintf("%d", BuildKitPort), "protocol": "TCP"}}}},
			}},
			"egress":     egress,
			"egressDeny": []any{map[string]any{"toCIDRSet": privateDeny}},
		},
	}}, nil
}

func prefixContains(parentText, childText string) bool {
	parent, parentErr := netip.ParsePrefix(parentText)
	child, childErr := netip.ParsePrefix(childText)
	return parentErr == nil && childErr == nil && parent.Addr().BitLen() == child.Addr().BitLen() && parent.Bits() <= child.Bits() && parent.Contains(child.Addr())
}

func allowedPrivateEndpointCIDR(value string) bool {
	for _, parent := range []string{"10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"} {
		if prefixContains(parent, value) {
			return true
		}
	}
	return false
}

func resourceName(buildID string, attempt uint32) string {
	identifier := strings.TrimPrefix(buildID, "bld_")
	return fmt.Sprintf("build-%s-a%d", identifier, attempt)
}

func labelHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:16])
}

func sortedUnique(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return slices.Compact(result)
}

func cloneMap(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func stringMapAny(values map[string]string) map[string]any {
	result := make(map[string]any, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func mergeAny(left, right map[string]any) map[string]any {
	result := make(map[string]any, len(left)+len(right))
	for key, value := range left {
		result[key] = value
	}
	for key, value := range right {
		result[key] = value
	}
	return result
}

func equalNetwork(left, right []llbcompiler.NetworkCapability) bool {
	return slices.EqualFunc(left, right, func(left, right llbcompiler.NetworkCapability) bool {
		return left.NodeID == right.NodeID && left.Profile == right.Profile && left.GatewayID == right.GatewayID && slices.Equal(left.Hosts, right.Hosts)
	})
}

func equalCaches(left, right []llbcompiler.CacheCapability) bool { return slices.Equal(left, right) }
