package buildkube

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcontrol"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildegress"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/solver/pb"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

const kubeBuildID = "bld_019b01da-7e31-7000-8000-000000000001"
const kubeCellID = "cell_019b01da-7e31-7000-8000-000000000002"
const kubeOrgID = "org_019b01da-7e31-7000-8000-000000000003"
const kubeProjectID = "prj_019b01da-7e31-7000-8000-000000000004"
const kubeOperationID = "op_019b01da-7e31-7000-8000-000000000005"
const kubeSnapshot = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const kubeIR = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const kubePolicy = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
const kubePrefix = "s3://lrail-build/cell-kube/"

var kubeNow = time.Date(2026, 7, 13, 5, 0, 0, 0, time.UTC)
var kubePrivateKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize))

type kubeArtifactStore map[string][]byte

func (store kubeArtifactStore) Open(_ context.Context, reference string, _ int64) (io.ReadCloser, error) {
	contents, exists := store[reference]
	if !exists {
		return nil, errors.New("missing fake artifact")
	}
	return io.NopCloser(bytes.NewReader(contents)), nil
}

func kubeAssignment(t *testing.T, network []llbcompiler.NetworkCapability) buildcell.ResolvedAssignment {
	t.Helper()
	state := llb.Scratch().File(llb.Mkfile("/site", 0o644, []byte("site")))
	for _, capability := range network {
		mode := pb.NetMode_UNSET
		if capability.Profile == "none" {
			mode = pb.NetMode_NONE
		}
		options := []llb.RunOption{
			llb.Args([]string{"/bin/true"}), llb.Network(mode),
			llb.WithCustomName("lrail run " + capability.NodeID + " network=" + capability.Profile + " gateway=" + capability.GatewayID + " hosts=" + strings.Join(capability.Hosts, ",")),
		}
		if capability.Profile != "none" {
			options = append(options, llb.WithProxy(llb.ProxyEnv{HTTPProxy: llbcompiler.BuildEgressProxyURL, HTTPSProxy: llbcompiler.BuildEgressProxyURL}))
		}
		state = state.Run(options...).Root()
	}
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
	config := []byte(`{"config":{"Cmd":["true"]}}`)
	llbDigest := digestBytes(definitionBytes)
	configDigest := digestBytes(config)
	lock := llbcompiler.DefinitionLock{
		Version: llbcompiler.CurrentLockVersion, CompilerVersion: "0.1.0", IRDigest: kubeIR, PolicyDigest: kubePolicy,
		SourceSnapshot: kubeSnapshot, TargetPlatform: "linux/amd64", BuildArguments: []llbcompiler.NameValue{},
		BaseMaterials: []llbcompiler.BaseMaterial{}, Network: network, Caches: []llbcompiler.CacheCapability{}, Secrets: []llbcompiler.SecretCapability{},
		SupplyChain: llbcompiler.PlatformSupplyChainPolicy([]string{"sha256:1111111111111111111111111111111111111111111111111111111111111111"}),
		Outputs:     []llbcompiler.OutputLock{{Name: "site", Kind: "static_bundle", StateID: "n1", LLBDigest: llbDigest, ConfigDigest: configDigest}},
	}
	lockDigest, err := llbcompiler.LockDigest(lock)
	if err != nil {
		t.Fatalf("LockDigest: %v", err)
	}
	output := buildcell.OutputArtifact{Name: "site", Kind: "static_bundle", LLBDigest: llbDigest, Head: string(head), LLBRef: kubePrefix + "site.llb", ConfigDigest: configDigest, ConfigRef: kubePrefix + "site.json"}
	payload := buildcell.Payload{
		Version: buildcell.CurrentAssignmentVersion, BuildID: kubeBuildID, CellID: kubeCellID, OrganizationID: kubeOrgID,
		ProjectID: kubeProjectID, OperationID: kubeOperationID, Generation: 1, Nonce: strings.Repeat("a", 64),
		IssuedAt: kubeNow.Format(time.RFC3339), ExpiresAt: kubeNow.Add(time.Hour).Format(time.RFC3339), DefinitionDigest: lockDigest, Lock: lock,
		Source:  buildcell.SourceArtifact{SnapshotDigest: kubeSnapshot, ArchiveDigest: kubeIR, ArchiveRef: kubePrefix + "source.tar.gz", SizeBytes: 100},
		Outputs: []buildcell.OutputArtifact{output},
	}
	envelope, err := buildcell.Sign(payload, "kube-test-v1", kubePrivateKey)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	verifier, err := buildcell.NewVerifier(buildcell.VerifierOptions{
		CellID: kubeCellID, Keys: map[string]ed25519.PublicKey{"kube-test-v1": kubePrivateKey.Public().(ed25519.PublicKey)},
		ObjectPrefix: kubePrefix, Clock: func() time.Time { return kubeNow },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	verified, err := verifier.Verify(envelope)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	resolved, err := buildcell.Resolve(context.Background(), verified, kubeArtifactStore{output.LLBRef: definitionBytes, output.ConfigRef: config})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return resolved
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func safeConfig() Config {
	return Config{
		Namespace: "lrail-build", ControllerNamespace: "lrail-build-control",
		ControllerLabels: map[string]string{"app.kubernetes.io/name": "lrail-build-control"},
		RuntimeClass:     "kata-qemu", WorkerImage: "ghcr.io/mayowaoladosu/lrail-build-worker@sha256:" + strings.Repeat("1", 64),
		ImagePullSecret: "lrail-build-images",
		SeccompProfile:  "profiles/lrail-buildkit-rootless.json", AppArmorProfile: "lrail-buildkit-rootless",
		NodeSelector:  map[string]string{"lrail.dev/pool": "build", "lrail.dev/kata": "true"},
		Tolerations:   []corev1.Toleration{{Key: "lrail.dev/build", Operator: corev1.TolerationOpEqual, Value: "true", Effect: corev1.TaintEffectNoSchedule}},
		PriorityClass: "lrail-build", ClusterDNSCIDR: "10.96.0.10/32",
		AllowedPrivateEndpoints: map[string]PrivateEndpoint{
			"private-gateway": {CIDRs: []string{"10.20.30.40/32"}, Ports: []int32{443}},
		},
		CPURequest: "1", CPULimit: "4", MemoryRequest: "1Gi", MemoryLimit: "8Gi", EphemeralRequest: "4Gi", EphemeralLimit: "24Gi",
	}
}

func safeTLSMaterial() TLSMaterial {
	return TLSMaterial{
		CA: []byte("fake-ca"), ServerCert: []byte("fake-cert"), ServerKey: []byte("fake-key"),
		EgressClientCert: []byte("fake-egress-cert"), EgressClientKey: []byte("fake-egress-key"), EgressServerCA: []byte("fake-egress-ca"),
	}
}

func TestBuildResourcesEnforcesKataRestrictedWorkerAndNoAPIAuthority(t *testing.T) {
	t.Parallel()
	assignment := kubeAssignment(t, []llbcompiler.NetworkCapability{})
	request := buildcontrol.AllocationRequest{Assignment: assignment, Attempt: 1, LeaseID: "lease-test", Network: []llbcompiler.NetworkCapability{}, Caches: []llbcompiler.CacheCapability{}}
	resources, err := BuildResources(safeConfig(), request, safeTLSMaterial(), kubeNow)
	if err != nil {
		t.Fatalf("BuildResources: %v", err)
	}
	pod := resources.Job.Spec.Template.Spec
	if pod.RuntimeClassName == nil || *pod.RuntimeClassName != "kata-qemu" || pod.HostNetwork || pod.HostPID || pod.HostIPC || pod.ShareProcessNamespace == nil || *pod.ShareProcessNamespace || pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
		t.Fatalf("unsafe pod isolation: %#v", pod)
	}
	if resources.ServiceAccount.AutomountServiceAccountToken == nil || *resources.ServiceAccount.AutomountServiceAccountToken || len(pod.Containers) != 1 {
		t.Fatalf("service-account or container shape unsafe")
	}
	if len(resources.ServiceAccount.ImagePullSecrets) != 1 || resources.ServiceAccount.ImagePullSecrets[0].Name != "lrail-build-images" || len(pod.ImagePullSecrets) != 1 || pod.ImagePullSecrets[0].Name != "lrail-build-images" {
		t.Fatalf("worker image pull authority is absent or ambiguous")
	}
	container := pod.Containers[0]
	if container.SecurityContext == nil || container.SecurityContext.Privileged == nil || *container.SecurityContext.Privileged ||
		container.SecurityContext.AllowPrivilegeEscalation == nil || *container.SecurityContext.AllowPrivilegeEscalation ||
		container.SecurityContext.ReadOnlyRootFilesystem == nil || !*container.SecurityContext.ReadOnlyRootFilesystem ||
		len(container.SecurityContext.Capabilities.Drop) != 1 || container.SecurityContext.Capabilities.Drop[0] != "ALL" ||
		container.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeLocalhost || container.SecurityContext.AppArmorProfile.Type != corev1.AppArmorProfileTypeLocalhost {
		t.Fatalf("unsafe container security context: %#v", container.SecurityContext)
	}
	for _, volume := range pod.Volumes {
		if volume.HostPath != nil {
			t.Fatalf("host path mounted: %#v", volume)
		}
	}
	if pod.Volumes[0].EmptyDir == nil || pod.Volumes[0].EmptyDir.SizeLimit == nil || pod.Volumes[0].EmptyDir.SizeLimit.Value() != DefaultScratchBytes {
		t.Fatalf("scratch size limit = %#v", pod.Volumes[0])
	}
	if len(container.VolumeMounts) != 3 || container.VolumeMounts[0].MountPath != "/var/lib/lrail-worker" || pod.Volumes[1].Name != "tmp" || pod.Volumes[1].EmptyDir == nil || pod.Volumes[1].EmptyDir.Medium != corev1.StorageMediumMemory || pod.Volumes[2].Secret == nil || pod.Volumes[2].Secret.DefaultMode == nil || *pod.Volumes[2].Secret.DefaultMode != 0o440 {
		t.Fatalf("worker writable/TLS volumes are unsafe: mounts=%#v volumes=%#v", container.VolumeMounts, pod.Volumes)
	}
	environment := map[string]string{}
	for _, variable := range container.Env {
		environment[variable.Name] = variable.Value
	}
	if environment["LRAIL_QUOTA_ROOT"] != "/var/lib/lrail-worker" || environment["LRAIL_ROOTLESS_PIDNS"] != "true" ||
		environment["LRAIL_ROOTLESSKIT_SINGLE_ID"] != "true" || environment["XDG_RUNTIME_DIR"] != "/var/lib/lrail-worker/run" ||
		environment["TMPDIR"] != "/var/lib/lrail-worker/tmp" {
		t.Fatalf("worker writable paths escape quota root: %#v", environment)
	}
	if environment["HTTP_PROXY"] != llbcompiler.BuildEgressProxyURL || environment["HTTPS_PROXY"] != llbcompiler.BuildEgressProxyURL ||
		environment["LRAIL_EGRESS_PROXY_ADDRESS"] != buildegress.ProxyAddress || environment["LRAIL_EGRESS_PROXY_SERVER_NAME"] != buildegress.ProxyServerName {
		t.Fatalf("worker policy proxy is incomplete: %#v", environment)
	}
	encoded, err := json.Marshal(resources)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	text := string(encoded)
	for _, forbidden := range []string{"/var/run/docker.sock", "hostPath", "automountServiceAccountToken\":true", "privileged\":true", "fake-customer-secret"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("forbidden resource content %q", forbidden)
		}
	}
	if resources.NetworkPolicy == nil || resources.CiliumPolicy == nil || resources.Service.Spec.Ports[0].Port != BuildKitPort {
		t.Fatalf("network boundary is incomplete")
	}
	if len(resources.NetworkPolicy.Spec.PolicyTypes) != 1 || resources.NetworkPolicy.Spec.PolicyTypes[0] != networkingv1.PolicyTypeIngress || len(resources.NetworkPolicy.Spec.Egress) != 0 {
		t.Fatalf("Kubernetes NetworkPolicy must not intersect Cilium worker egress: %#v", resources.NetworkPolicy.Spec)
	}
}

func TestAppArmorProfileSupportsExplicitFunctionalLabDisabledMode(t *testing.T) {
	if profile := appArmorProfile("Disabled"); profile != nil {
		t.Fatalf("profile=%#v", profile)
	}
}

func TestFunctionalGVisorRootlessBootstrapUsesOnlyRequiredSandboxCapabilities(t *testing.T) {
	t.Parallel()
	config := safeConfig()
	config.RuntimeClass = "gvisor"
	config.AppArmorProfile = "Disabled"
	config.FunctionalGVisorRootlessBootstrap = true
	config.NodeSelector = map[string]string{"lrail.dev/pool": "build", "lrail.dev/gvisor": "true"}
	resources, err := BuildResources(config, buildcontrol.AllocationRequest{
		Assignment: kubeAssignment(t, []llbcompiler.NetworkCapability{}), Attempt: 1,
		LeaseID: "lease-functional",
	}, safeTLSMaterial(), kubeNow)
	if err != nil {
		t.Fatalf("BuildResources: %v", err)
	}
	security := resources.Job.Spec.Template.Spec.Containers[0].SecurityContext
	environment := map[string]string{}
	for _, variable := range resources.Job.Spec.Template.Spec.Containers[0].Env {
		environment[variable.Name] = variable.Value
	}
	if security.AllowPrivilegeEscalation == nil || !*security.AllowPrivilegeEscalation ||
		!slices.Equal(security.Capabilities.Drop, []corev1.Capability{"ALL"}) ||
		!slices.Equal(security.Capabilities.Add, []corev1.Capability{"SETGID", "SETUID"}) ||
		security.AppArmorProfile != nil || environment["LRAIL_ROOTLESS_PIDNS"] != "false" ||
		environment["LRAIL_ROOTLESSKIT_SINGLE_ID"] != "false" {
		t.Fatalf("functional rootless bootstrap context = %#v", security)
	}
	config.RuntimeClass = "kata-qemu"
	if _, err := BuildResources(config, buildcontrol.AllocationRequest{}, safeTLSMaterial(), kubeNow); err == nil {
		t.Fatal("functional rootless bootstrap was accepted outside gVisor")
	}
}

func TestBuildResourcesRealizesPrivateCapabilityAndBlocksAmbientPrivateRanges(t *testing.T) {
	t.Parallel()
	network := []llbcompiler.NetworkCapability{{NodeID: "n2", Profile: "private", GatewayID: "private-gateway", Hosts: []string{}}}
	assignment := kubeAssignment(t, network)
	request := buildcontrol.AllocationRequest{Assignment: assignment, Attempt: 1, LeaseID: "lease-test", Network: network, Caches: []llbcompiler.CacheCapability{}}
	resources, err := BuildResources(safeConfig(), request, safeTLSMaterial(), kubeNow)
	if err != nil {
		t.Fatalf("BuildResources: %v", err)
	}
	encoded, _ := json.Marshal(resources.CiliumPolicy.Object)
	text := string(encoded)
	for _, required := range []string{buildegress.ProxyServerName, `"port":"8443"`, "169.254.0.0/16", "egressDeny", "lrail-build-egress"} {
		if !strings.Contains(text, required) {
			t.Fatalf("policy lacks %q: %s", required, text)
		}
	}
	for _, forbidden := range []string{"10.20.30.40/32", "registry.lrail-system.svc.cluster.local", "toFQDNs"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("worker policy grants direct destination %q: %s", forbidden, text)
		}
	}
}

func TestBuildResourcesRejectsUnsafePrivateEndpointMappings(t *testing.T) {
	t.Parallel()
	assignment := kubeAssignment(t, []llbcompiler.NetworkCapability{})
	request := buildcontrol.AllocationRequest{Assignment: assignment, Attempt: 1, LeaseID: "lease-test", Network: []llbcompiler.NetworkCapability{}, Caches: []llbcompiler.CacheCapability{}}
	for name, endpoint := range map[string]PrivateEndpoint{
		"metadata":    {CIDRs: []string{"169.254.169.254/32"}, Ports: []int32{443}},
		"public":      {CIDRs: []string{"8.8.8.8/32"}, Ports: []int32{443}},
		"cluster DNS": {CIDRs: []string{"10.96.0.10/32"}, Ports: []int32{443}},
		"all ports":   {CIDRs: []string{"10.20.30.40/32"}, Ports: nil},
	} {
		t.Run(name, func(t *testing.T) {
			config := safeConfig()
			config.AllowedPrivateEndpoints = map[string]PrivateEndpoint{"unsafe": endpoint}
			if _, err := BuildResources(config, request, safeTLSMaterial(), kubeNow); err == nil {
				t.Fatal("expected unsafe private endpoint rejection")
			}
		})
	}
}

func TestBuildResourcesRejectsBroadDNSAndInvalidRegistryExceptions(t *testing.T) {
	t.Parallel()
	assignment := kubeAssignment(t, []llbcompiler.NetworkCapability{})
	request := buildcontrol.AllocationRequest{Assignment: assignment, Attempt: 1, LeaseID: "lease-test", Network: []llbcompiler.NetworkCapability{}, Caches: []llbcompiler.CacheCapability{}}
	for name, mutate := range map[string]func(*Config){
		"broad DNS":  func(config *Config) { config.ClusterDNSCIDR = "10.0.0.0/8" },
		"public DNS": func(config *Config) { config.ClusterDNSCIDR = "8.8.8.8/32" },
		"bad private host": func(config *Config) {
			config.AllowedPrivateEndpoints["private-gateway"] = PrivateEndpoint{CIDRs: []string{"10.20.30.40/32"}, Ports: []int32{443}, Hosts: []string{"*.example.invalid"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := safeConfig()
			mutate(&config)
			if _, err := BuildResources(config, request, safeTLSMaterial(), kubeNow); err == nil {
				t.Fatal("expected egress exception rejection")
			}
		})
	}
}

func TestBuildResourcesRejectsUnpinnedImageAndCapabilityMismatch(t *testing.T) {
	t.Parallel()
	assignment := kubeAssignment(t, []llbcompiler.NetworkCapability{})
	request := buildcontrol.AllocationRequest{Assignment: assignment, Attempt: 1, LeaseID: "lease-test", Network: []llbcompiler.NetworkCapability{}, Caches: []llbcompiler.CacheCapability{}}
	config := safeConfig()
	config.WorkerImage = "moby/buildkit:latest"
	if _, err := BuildResources(config, request, safeTLSMaterial(), kubeNow); err == nil {
		t.Fatal("expected unpinned image rejection")
	}
	config = safeConfig()
	request.Network = []llbcompiler.NetworkCapability{{NodeID: "n2", Profile: "none", Hosts: []string{}}}
	if _, err := BuildResources(config, request, safeTLSMaterial(), kubeNow); err == nil {
		t.Fatal("expected capability mismatch rejection")
	}
	config = safeConfig()
	config.WorkerImage = "ghcr.io/mayowaoladosu/lrail-build-worker@sha256:not-a-digest"
	request.Network = []llbcompiler.NetworkCapability{}
	if _, err := BuildResources(config, request, safeTLSMaterial(), kubeNow); err == nil {
		t.Fatal("expected malformed digest rejection")
	}
}
