package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcontent"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildorchestrator"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildsigning"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildsupply"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildtransport"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"google.golang.org/grpc"
	grpccredentials "google.golang.org/grpc/credentials"
)

const maxConfigBytes int64 = 2 << 20

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "lrail build broker stopped:", err)
		os.Exit(1)
	}
}

func run() error {
	clock := time.Now
	cellID, err := required("LRAIL_CELL_ID")
	if err != nil {
		return err
	}
	sourcePrefix, err := parseS3Prefix(os.Getenv("LRAIL_SOURCE_OBJECT_PREFIX"))
	if err != nil {
		return errors.New("source object prefix is invalid")
	}
	cellPrefix, err := parseS3Prefix(os.Getenv("LRAIL_OBJECT_PREFIX"))
	if err != nil {
		return errors.New("cell object prefix is invalid")
	}
	sourceClient, err := s3Client("SOURCE")
	if err != nil {
		return err
	}
	cellClient, err := s3Client("CELL")
	if err != nil {
		return err
	}
	sourceReader, err := buildcontent.NewStore(sourceClient, sourcePrefix.bucket, sourcePrefix.path)
	if err != nil {
		return err
	}
	content, err := buildorchestrator.NewS3Content(buildcontent.SourceStore{Store: sourceReader}, cellClient, cellPrefix.bucket, cellPrefix.path)
	if err != nil {
		return err
	}

	detector, err := buildorchestrator.NewCommandDetector(
		os.Getenv("LRAIL_DETECTOR_EXECUTABLE"), os.Getenv("LRAIL_DETECTOR_PATH"), 2*time.Minute,
	)
	if err != nil {
		return err
	}
	var policy llbcompiler.Policy
	if err := loadStrictJSON(os.Getenv("LRAIL_BUILD_POLICY_FILE"), &policy); err != nil {
		return errors.New("load build policy")
	}
	var catalog buildorchestrator.BaseCatalog
	if err := loadStrictJSON(os.Getenv("LRAIL_BASE_CATALOG_FILE"), &catalog); err != nil {
		return errors.New("load base catalog")
	}
	compiler, err := buildorchestrator.NewDefinitionCompiler(
		policy, catalog, os.Getenv("LRAIL_DSL_COMPILER_VERSION"), os.Getenv("LRAIL_LLB_COMPILER_VERSION"),
	)
	if err != nil {
		return err
	}

	baoHTTP, err := tlsHTTPClient(os.Getenv("LRAIL_ASSIGNMENT_OPENBAO_CA_FILE"), 30*time.Second)
	if err != nil {
		return err
	}
	authority, err := buildsigning.NewOpenBaoAuthority(buildsigning.OpenBaoConfig{
		Address: os.Getenv("LRAIL_ASSIGNMENT_OPENBAO_ADDRESS"), KubernetesRole: os.Getenv("LRAIL_ASSIGNMENT_OPENBAO_ROLE"),
		AuthMount: os.Getenv("LRAIL_ASSIGNMENT_OPENBAO_AUTH_MOUNT"), TransitMount: os.Getenv("LRAIL_ASSIGNMENT_OPENBAO_TRANSIT_MOUNT"),
		KeyName: os.Getenv("LRAIL_ASSIGNMENT_OPENBAO_KEY_NAME"), KeyID: os.Getenv("LRAIL_ASSIGNMENT_KEY_ID"),
		JWTPath: os.Getenv("LRAIL_ASSIGNMENT_OPENBAO_JWT_FILE"), RequestTimeout: 30 * time.Second, MaxTokenTTL: 5 * time.Minute,
	}, baoHTTP)
	if err != nil {
		return err
	}
	preflightContext, preflightCancel := context.WithTimeout(context.Background(), 30*time.Second)
	preflight, preflightErr := authority.Sign(preflightContext, []byte("lrail-assignment-key-preflight-v1"))
	preflightCancel()
	preflightDigest, verifyErr := buildsupply.VerifySignature(preflight.PublicKeyPEM, []byte("lrail-assignment-key-preflight-v1"), preflight.Signature)
	if preflightErr != nil || verifyErr != nil || preflight.KeyID != os.Getenv("LRAIL_ASSIGNMENT_KEY_ID") ||
		preflight.Algorithm != buildsupply.SignatureAlgorithm || preflightDigest != os.Getenv("LRAIL_ASSIGNMENT_PUBLIC_KEY_DIGEST") {
		return errors.New("assignment signing authority preflight failed")
	}

	cellTLS, err := buildtransport.NewReloadingClientTLSConfig(
		os.Getenv("LRAIL_BUILDCELL_CLIENT_CERT"), os.Getenv("LRAIL_BUILDCELL_CLIENT_KEY"), os.Getenv("LRAIL_BUILDCELL_CA"),
		os.Getenv("LRAIL_BUILDCELL_SERVER_NAME"), splitCSV(os.Getenv("LRAIL_BUILDCELL_SERVER_URIS")),
	)
	if err != nil {
		return err
	}
	cellConnection, err := grpc.NewClient(
		os.Getenv("LRAIL_BUILDCELL_ADDRESS"), grpc.WithTransportCredentials(grpccredentials.NewTLS(cellTLS)),
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(buildcellEnvelopeLimit()), grpc.MaxCallRecvMsgSize(buildcellEnvelopeLimit())),
	)
	if err != nil {
		return errors.New("connect to BuildCell")
	}
	defer cellConnection.Close()
	dispatcher, err := buildorchestrator.NewGRPCCellDispatcher(lrailv1.NewBuildCellServiceClient(cellConnection), time.Second)
	if err != nil {
		return err
	}

	store, err := buildorchestrator.NewBoltBrokerStore(os.Getenv("LRAIL_BUILD_BROKER_STATE_FILE"), 10_000_000, 10_000_000)
	if err != nil {
		return err
	}
	defer store.Close()
	orchestrator, err := buildorchestrator.New(buildorchestrator.OrchestratorOptions{
		Content: content, Detector: detector, Compiler: compiler, Signer: authority, Dispatcher: dispatcher, Checkpoints: store,
		CellID: cellID, AssignmentKeyID: os.Getenv("LRAIL_ASSIGNMENT_KEY_ID"),
		AssignmentPublicKeyDigest: os.Getenv("LRAIL_ASSIGNMENT_PUBLIC_KEY_DIGEST"), ScratchRoot: os.Getenv("LRAIL_BUILD_BROKER_SCRATCH_ROOT"),
		Clock: clock,
	})
	if err != nil {
		return err
	}
	broker, err := buildorchestrator.NewBroker(buildorchestrator.BrokerOptions{Store: store, Runner: orchestrator, Clock: clock})
	if err != nil {
		return err
	}
	defer func() {
		closeContext, closeCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer closeCancel()
		_ = broker.Close(closeContext)
	}()
	if err := broker.Resume(context.Background(), 10_000); err != nil {
		return errors.New("resume durable build runs")
	}
	handler, err := buildorchestrator.NewHTTPHandler(broker, 1024)
	if err != nil {
		return err
	}

	serverTLS, err := buildtransport.NewReloadingServerTLSConfig(
		os.Getenv("LRAIL_SERVER_CERT"), os.Getenv("LRAIL_SERVER_KEY"), os.Getenv("LRAIL_CLIENT_CA"),
		splitCSV(os.Getenv("LRAIL_ALLOWED_CLIENT_URIS")),
	)
	if err != nil {
		return err
	}
	address := os.Getenv("LRAIL_LISTEN_ADDRESS")
	if address == "" {
		address = ":9444"
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return errors.New("listen for build broker HTTP")
	}
	defer listener.Close()
	tlsListener := tls.NewListener(listener, serverTLS)
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 45 * time.Second,
		WriteTimeout: 45 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10,
		ErrorLog: log.New(os.Stderr, "build-broker-http: ", log.LstdFlags),
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(tlsListener) }()
	select {
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	shutdownErr := server.Shutdown(shutdownContext)
	brokerContext, brokerCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer brokerCancel()
	brokerErr := broker.Close(brokerContext)
	return errors.Join(shutdownErr, brokerErr)
}

type objectPrefix struct {
	bucket string
	path   string
}

func parseS3Prefix(value string) (objectPrefix, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed == nil {
		return objectPrefix{}, errors.New("S3 prefix is invalid")
	}
	pathValue := strings.Trim(parsed.Path, "/")
	invalidSegment := false
	for _, segment := range strings.Split(pathValue, "/") {
		invalidSegment = invalidSegment || segment == "" || segment == "." || segment == ".."
	}
	if parsed.Scheme != "s3" || parsed.Host == "" || pathValue == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || strings.Contains(pathValue, "//") || invalidSegment {
		return objectPrefix{}, errors.New("S3 prefix is invalid")
	}
	return objectPrefix{bucket: parsed.Host, path: pathValue}, nil
}

func s3Client(scope string) (*minio.Client, error) {
	access, err := readRequiredFile(os.Getenv("LRAIL_" + scope + "_S3_ACCESS_KEY_FILE"))
	if err != nil {
		return nil, err
	}
	secret, err := readRequiredFile(os.Getenv("LRAIL_" + scope + "_S3_SECRET_KEY_FILE"))
	if err != nil {
		return nil, err
	}
	secure, err := strconv.ParseBool(os.Getenv("LRAIL_" + scope + "_S3_SECURE"))
	if err != nil {
		return nil, errors.New("S3 secure setting is invalid")
	}
	client, err := minio.New(os.Getenv("LRAIL_"+scope+"_S3_ENDPOINT"), &minio.Options{
		Creds: credentials.NewStaticV4(access, secret, ""), Secure: secure, Region: os.Getenv("LRAIL_" + scope + "_S3_REGION"),
	})
	access, secret = "", ""
	if err != nil {
		return nil, errors.New("create S3 client")
	}
	return client, nil
}

func tlsHTTPClient(caFile string, timeout time.Duration) (*http.Client, error) {
	contents, err := os.ReadFile(caFile)
	if err != nil || len(contents) == 0 || len(contents) > 1<<20 {
		return nil, errors.New("read TLS CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(contents) {
		return nil, errors.New("parse TLS CA")
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots},
			ForceAttemptHTTP2: true, MaxIdleConns: 16, MaxIdleConnsPerHost: 8, IdleConnTimeout: 30 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func loadStrictJSON(filePath string, destination any) error {
	contents, err := os.ReadFile(filePath)
	if err != nil || len(contents) == 0 || int64(len(contents)) > maxConfigBytes {
		return errors.New("configuration JSON is unavailable or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("configuration JSON is malformed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("configuration JSON has trailing data")
	}
	return nil
}

func readRequiredFile(filePath string) (string, error) {
	contents, err := os.ReadFile(filePath)
	if err != nil || len(contents) == 0 || len(contents) > 1<<20 {
		return "", errors.New("required credential file is unavailable")
	}
	value := strings.TrimSpace(string(contents))
	for index := range contents {
		contents[index] = 0
	}
	if value == "" {
		return "", errors.New("required credential file is empty")
	}
	return value, nil
}

func required(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

func splitCSV(value string) []string {
	result := make([]string, 0)
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func buildcellEnvelopeLimit() int { return 17 << 20 }
