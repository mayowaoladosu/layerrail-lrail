package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	lrailv1 "github.com/mayowaoladosu/layerrail-lrail/gen/go/lrail/v1"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcap"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcontent"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcontrol"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildegress"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildkube"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildregistry"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildtransport"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"google.golang.org/grpc"
	grpccredentials "google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const maxRPCBytes = buildcell.MaxEnvelopeBytes + 64*1024

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "lrail build-cell server stopped:", err)
		os.Exit(1)
	}
}

func run() error {
	clock := time.Now
	cellID, err := required("LRAIL_CELL_ID")
	if err != nil {
		return err
	}
	objectPrefix, err := required("LRAIL_OBJECT_PREFIX")
	if err != nil {
		return err
	}
	assignmentKeys, err := loadPublicKeys(os.Getenv("LRAIL_ASSIGNMENT_KEYS_FILE"))
	if err != nil {
		return err
	}
	verifier, err := buildcell.NewVerifier(buildcell.VerifierOptions{CellID: cellID, Keys: assignmentKeys, ObjectPrefix: objectPrefix, Clock: clock})
	if err != nil {
		return err
	}

	runStore, err := buildcontrol.NewBoltRunStore(os.Getenv("LRAIL_RUN_STATE_FILE"), 10_000_000)
	if err != nil {
		return err
	}
	defer runStore.Close()
	replayStore, err := buildcell.NewBoltReplayStore(os.Getenv("LRAIL_REPLAY_STATE_FILE"), clock, 10_000_000)
	if err != nil {
		return err
	}
	defer replayStore.Close()

	contentStore, sourceStore, artifactStore, objectClient, objectBucket, objectPath, err := contentAdapters(objectPrefix)
	if err != nil {
		return err
	}
	_ = contentStore
	cleaner, err := buildworker.NewResidueCleaner(
		buildworker.DirectoryScrubber{Root: os.Getenv("LRAIL_SCRATCH_ROOT")},
		buildworker.DirectoryInspector{Root: os.Getenv("LRAIL_SCRATCH_ROOT")},
		buildworker.FileQuarantiner{Root: os.Getenv("LRAIL_QUARANTINE_ROOT"), Clock: clock},
	)
	if err != nil {
		return err
	}
	registryTLS, err := buildtransport.NewReloadingClientTLSConfig(
		os.Getenv("LRAIL_REGISTRY_CLIENT_CERT"), os.Getenv("LRAIL_REGISTRY_CLIENT_KEY"), os.Getenv("LRAIL_REGISTRY_BROKER_CA"),
		os.Getenv("LRAIL_REGISTRY_BROKER_SERVER_NAME"), splitCSV(os.Getenv("LRAIL_REGISTRY_BROKER_SERVER_URIS")),
	)
	if err != nil {
		return err
	}
	registryConnection, err := grpc.NewClient(
		os.Getenv("LRAIL_REGISTRY_BROKER_ADDRESS"), grpc.WithTransportCredentials(grpccredentials.NewTLS(registryTLS)),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(128<<10), grpc.MaxCallSendMsgSize(128<<10)),
	)
	if err != nil {
		return errors.New("connect to registry capability broker")
	}
	defer registryConnection.Close()
	registryBroker, err := buildregistry.NewGRPCCapabilityBroker(lrailv1.NewBuildRegistryCapabilityServiceClient(registryConnection), clock)
	if err != nil {
		return err
	}
	distributionHTTP, err := registryHTTPClient(os.Getenv("LRAIL_HARBOR_CA_FILE"))
	if err != nil {
		return err
	}
	distribution, err := buildregistry.NewDistributionClient(distributionHTTP)
	if err != nil {
		return err
	}
	staticStore, err := buildregistry.NewS3StaticManifestStore(objectClient, objectBucket, objectPath+"/static-publications/v1")
	if err != nil {
		return err
	}
	committer, err := buildregistry.NewPublisher(buildregistry.PublisherConfig{
		Broker: registryBroker, Registry: distribution, Clock: clock,
		StagingRoot: os.Getenv("LRAIL_REGISTRY_STAGING_ROOT"), StaticStore: staticStore,
	})
	if err != nil {
		return err
	}
	cacheProvider, err := buildworker.NewDirectoryCacheProvider(os.Getenv("LRAIL_CACHE_ROOT"))
	if err != nil {
		return err
	}

	baoClient, err := openBaoHTTPClient(os.Getenv("LRAIL_OPENBAO_CA_FILE"))
	if err != nil {
		return err
	}
	capabilities, err := buildcap.NewOpenBaoBroker(buildcap.OpenBaoConfig{
		Address: os.Getenv("LRAIL_OPENBAO_ADDRESS"), KubernetesRole: os.Getenv("LRAIL_OPENBAO_ROLE"),
		AuthMount: os.Getenv("LRAIL_OPENBAO_AUTH_MOUNT"), KVMount: os.Getenv("LRAIL_OPENBAO_KV_MOUNT"),
		SecretPrefix: os.Getenv("LRAIL_OPENBAO_SECRET_PREFIX"), JWTPath: os.Getenv("LRAIL_OPENBAO_JWT_FILE"),
	}, baoClient, clock)
	if err != nil {
		return err
	}

	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		return errors.New("load in-cluster Kubernetes configuration")
	}
	kubeConfig.UserAgent = "lrail-build-cell/0.1.0"
	kubeConfig.QPS = 20
	kubeConfig.Burst = 40
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return errors.New("create Kubernetes client")
	}
	dynamicClient, err := dynamic.NewForConfig(kubeConfig)
	if err != nil {
		return errors.New("create Kubernetes dynamic client")
	}

	residueTLS, err := buildtransport.NewReloadingClientTLSConfig(
		os.Getenv("LRAIL_RESIDUE_CLIENT_CERT"), os.Getenv("LRAIL_RESIDUE_CLIENT_KEY"), os.Getenv("LRAIL_RESIDUE_SERVER_CA"),
		os.Getenv("LRAIL_RESIDUE_SERVER_NAME"), splitCSV(os.Getenv("LRAIL_RESIDUE_SERVER_URIS")),
	)
	if err != nil {
		return err
	}
	residue := buildkube.GRPCResidueAgent{Resolver: buildkube.KubernetesResidueResolver{
		Client: kubeClient, Namespace: os.Getenv("LRAIL_RESIDUE_NAMESPACE"),
		Labels: map[string]string{"app.kubernetes.io/name": "lrail-residue-agent"}, TLSConfig: residueTLS,
	}}
	connector := buildkube.BuildKitConnector{
		Sources: sourceStore, Cleaner: cleaner, Committer: committer, Caches: cacheProvider,
		ScratchRoot: os.Getenv("LRAIL_SCRATCH_ROOT"), SolveTimeout: time.Hour,
	}
	allocatorConfig, err := kubernetesAllocatorConfig()
	if err != nil {
		return err
	}
	loadEgressIssuer := func() (*buildegress.CertificateAuthority, error) {
		egressIssuerCertificate, err := readRequiredBytes(os.Getenv("LRAIL_EGRESS_CLIENT_CA_CERT"))
		if err != nil {
			return nil, err
		}
		egressIssuerKey, err := readRequiredBytes(os.Getenv("LRAIL_EGRESS_CLIENT_CA_KEY"))
		if err != nil {
			return nil, err
		}
		egressServerCA, err := readRequiredBytes(os.Getenv("LRAIL_EGRESS_SERVER_CA"))
		if err != nil {
			return nil, err
		}
		return buildegress.NewCertificateAuthority(egressIssuerCertificate, egressIssuerKey, egressServerCA, clock)
	}
	if _, err := loadEgressIssuer(); err != nil {
		return err
	}
	allocator, err := buildkube.NewAllocator(
		kubeClient, dynamicClient, allocatorConfig, buildkube.PolicyCertificateIssuer{
			Worker: buildkube.EphemeralCertificateIssuer{Clock: clock}, LoadEgress: loadEgressIssuer,
		}, connector, residue,
		buildkube.KubernetesNodeQuarantiner{Client: kubeClient}, clock, buildkube.DefaultReadyTimeout,
	)
	if err != nil {
		return err
	}

	controller, err := buildcontrol.New(buildcontrol.Options{
		Verifier: verifier, Replay: replayStore, Runs: runStore, Artifacts: artifactStore,
		Capabilities: capabilities, Workers: allocator, Clock: clock,
	})
	if err != nil {
		return err
	}
	transport, err := buildtransport.NewServer(controller, verifier, runStore)
	if err != nil {
		return err
	}
	serverTLS, err := buildtransport.NewReloadingServerTLSConfig(
		os.Getenv("LRAIL_SERVER_CERT"), os.Getenv("LRAIL_SERVER_KEY"), os.Getenv("LRAIL_CLIENT_CA"),
		splitCSV(os.Getenv("LRAIL_ALLOWED_BROKER_URIS")),
	)
	if err != nil {
		return err
	}
	listenAddress := os.Getenv("LRAIL_LISTEN_ADDRESS")
	if listenAddress == "" {
		listenAddress = ":9443"
	}
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return errors.New("listen for build-cell RPC")
	}
	defer listener.Close()
	grpcServer := grpc.NewServer(
		grpc.Creds(grpccredentials.NewTLS(serverTLS)), grpc.MaxRecvMsgSize(maxRPCBytes), grpc.MaxSendMsgSize(maxRPCBytes),
	)
	lrailv1.RegisterBuildCellServiceServer(grpcServer, transport)
	healthServer := health.NewServer()
	healthServer.SetServingStatus("lrail.v1.BuildCellService", healthv1.HealthCheckResponse_SERVING)
	healthv1.RegisterHealthServer(grpcServer, healthServer)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- grpcServer.Serve(listener) }()
	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}
	healthServer.Shutdown()
	stopped := make(chan struct{})
	go func() { grpcServer.GracefulStop(); close(stopped) }()
	select {
	case <-stopped:
		return nil
	case <-time.After(30 * time.Second):
		grpcServer.Stop()
		return errors.New("build-cell server forced shutdown after grace")
	}
}

func contentAdapters(objectPrefix string) (*buildcontent.Store, buildcontent.SourceStore, buildcontent.ArtifactStore, *minio.Client, string, string, error) {
	parsed, err := url.Parse(objectPrefix)
	if err != nil || parsed.Scheme != "s3" || parsed.Host == "" || parsed.Path == "" {
		return nil, buildcontent.SourceStore{}, buildcontent.ArtifactStore{}, nil, "", "", errors.New("object prefix is invalid")
	}
	accessKey, err := readRequiredFile(os.Getenv("LRAIL_S3_ACCESS_KEY_FILE"))
	if err != nil {
		return nil, buildcontent.SourceStore{}, buildcontent.ArtifactStore{}, nil, "", "", err
	}
	secretKey, err := readRequiredFile(os.Getenv("LRAIL_S3_SECRET_KEY_FILE"))
	if err != nil {
		return nil, buildcontent.SourceStore{}, buildcontent.ArtifactStore{}, nil, "", "", err
	}
	secure, err := strconv.ParseBool(os.Getenv("LRAIL_S3_SECURE"))
	if err != nil {
		return nil, buildcontent.SourceStore{}, buildcontent.ArtifactStore{}, nil, "", "", errors.New("LRAIL_S3_SECURE is invalid")
	}
	client, err := minio.New(os.Getenv("LRAIL_S3_ENDPOINT"), &minio.Options{Creds: credentials.NewStaticV4(accessKey, secretKey, ""), Secure: secure, Region: os.Getenv("LRAIL_S3_REGION")})
	if err != nil {
		return nil, buildcontent.SourceStore{}, buildcontent.ArtifactStore{}, nil, "", "", errors.New("create S3 content client")
	}
	store, err := buildcontent.NewStore(client, parsed.Host, strings.Trim(parsed.Path, "/"))
	if err != nil {
		return nil, buildcontent.SourceStore{}, buildcontent.ArtifactStore{}, nil, "", "", err
	}
	return store, buildcontent.SourceStore{Store: store}, buildcontent.ArtifactStore{Store: store}, client, parsed.Host, strings.Trim(parsed.Path, "/"), nil
}

func registryHTTPClient(caPath string) (*http.Client, error) {
	contents, err := os.ReadFile(caPath)
	if err != nil || len(contents) == 0 || len(contents) > 1<<20 {
		return nil, errors.New("read Harbor CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(contents) {
		return nil, errors.New("parse Harbor CA")
	}
	return &http.Client{
		Timeout:   2 * time.Minute,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, ForceAttemptHTTP2: true},
	}, nil
}

func kubernetesAllocatorConfig() (buildkube.Config, error) {
	nodeSelector := map[string]string{}
	if err := loadJSONFile(os.Getenv("LRAIL_NODE_SELECTOR_FILE"), &nodeSelector); err != nil {
		return buildkube.Config{}, err
	}
	privateEndpoints := map[string]buildkube.PrivateEndpoint{}
	if value := os.Getenv("LRAIL_PRIVATE_ENDPOINTS_FILE"); value != "" {
		if err := loadJSONFile(value, &privateEndpoints); err != nil {
			return buildkube.Config{}, err
		}
	}
	return buildkube.Config{
		Namespace: os.Getenv("LRAIL_BUILD_NAMESPACE"), ControllerNamespace: os.Getenv("LRAIL_CONTROLLER_NAMESPACE"),
		ControllerLabels: map[string]string{"app.kubernetes.io/name": "lrail-build-control"},
		RuntimeClass:     os.Getenv("LRAIL_BUILD_RUNTIME_CLASS"), WorkerImage: os.Getenv("LRAIL_BUILD_WORKER_IMAGE"),
		ImagePullSecret: os.Getenv("LRAIL_BUILD_IMAGE_PULL_SECRET"),
		SeccompProfile:  os.Getenv("LRAIL_BUILD_SECCOMP_PROFILE"), AppArmorProfile: os.Getenv("LRAIL_BUILD_APPARMOR_PROFILE"),
		NodeSelector: nodeSelector, Tolerations: []corev1.Toleration{{Key: "lrail.dev/build", Operator: corev1.TolerationOpEqual, Value: "true", Effect: corev1.TaintEffectNoSchedule}},
		PriorityClass: "lrail-build", ClusterDNSCIDR: os.Getenv("LRAIL_CLUSTER_DNS_CIDR"),
		AllowedPrivateEndpoints: privateEndpoints, CPURequest: "1", CPULimit: "4", MemoryRequest: "1Gi", MemoryLimit: "8Gi", EphemeralRequest: "4Gi", EphemeralLimit: "24Gi",
	}, nil
}

func openBaoHTTPClient(caPath string) (*http.Client, error) {
	contents, err := os.ReadFile(caPath)
	if err != nil {
		return nil, errors.New("read OpenBao CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(contents) {
		return nil, errors.New("parse OpenBao CA")
	}
	return &http.Client{Timeout: buildcap.DefaultRequestTimeout, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, ForceAttemptHTTP2: true}}, nil
}

func loadPublicKeys(filePath string) (map[string]ed25519.PublicKey, error) {
	var encoded map[string]string
	if err := loadJSONFile(filePath, &encoded); err != nil {
		return nil, err
	}
	keys := make(map[string]ed25519.PublicKey, len(encoded))
	for keyID, value := range encoded {
		decoded, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, errors.New("assignment public key file is invalid")
		}
		keys[keyID] = ed25519.PublicKey(decoded)
	}
	return keys, nil
}

func loadJSONFile(filePath string, destination any) error {
	contents, err := os.ReadFile(filePath)
	if err != nil || len(contents) == 0 || len(contents) > 1<<20 {
		return errors.New("configuration JSON file is unavailable or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("configuration JSON file is malformed")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("configuration JSON file has trailing data")
	}
	return nil
}

func readRequiredFile(filePath string) (string, error) {
	contents, err := readRequiredBytes(filePath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(contents)), nil
}

func readRequiredBytes(filePath string) ([]byte, error) {
	contents, err := os.ReadFile(filePath)
	if err != nil || len(contents) == 0 || len(contents) > 64*1024 {
		return nil, errors.New("required credential file is unavailable or oversized")
	}
	return contents, nil
}

func required(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

func splitCSV(value string) []string {
	result := []string{}
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}
