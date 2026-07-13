package main

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/httpapi"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/objectstore"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourcearchive"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourceupload"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		healthcheck()
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	config, err := loadConfig()
	if err != nil {
		logger.Error("invalid source gateway configuration", "error", err.Error())
		os.Exit(1)
	}
	if err := verifyScratch(config.scratchDir); err != nil {
		logger.Error("source scratch is unavailable", "error", err.Error())
		os.Exit(1)
	}
	storage, err := minio.New(config.internalEndpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(config.accessKey, config.secretKey, ""),
		Secure: config.internalTLS,
		Region: config.region,
	})
	if err != nil {
		logger.Error("create internal source object client", "error", err.Error())
		os.Exit(1)
	}
	presigner, err := minio.New(config.publicEndpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(config.accessKey, config.secretKey, ""),
		Secure: config.publicTLS,
		Region: config.region,
	})
	if err != nil {
		logger.Error("create public source object signer", "error", err.Error())
		os.Exit(1)
	}
	store, err := objectstore.NewMinIO(storage, presigner, config.bucket)
	if err != nil {
		logger.Error("create source object store", "error", err.Error())
		os.Exit(1)
	}
	finalizer := &sourceupload.Finalizer{
		Store:        store,
		ScratchDir:   config.scratchDir,
		Policy:       sourcearchive.DefaultPolicy(),
		PrivateKey:   config.privateKey,
		SigningKeyID: config.signingKeyID,
	}
	providerFetcher, err := buildProviderFetcher(config, store)
	if err != nil {
		logger.Error("create provider source fetcher", "error", err.Error())
		os.Exit(1)
	}
	api, err := httpapi.New(httpapi.Config{
		Store:                   store,
		GrantKey:                config.grantKey,
		Finalizer:               finalizer,
		Logger:                  logger,
		MaxConcurrentFinalizers: config.maxFinalizers,
		ProviderFetcher:         providerFetcher,
		MaxConcurrentFetchers:   config.maxFetchers,
	})
	if err != nil {
		logger.Error("create source HTTP API", "error", err.Error())
		os.Exit(1)
	}

	server := &http.Server{
		Addr:              config.listenAddress,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	shutdownContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-shutdownContext.Done()
		context, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := server.Shutdown(context); err != nil {
			logger.Error("source gateway shutdown failed", "error", err.Error())
		}
	}()
	logger.Info("source gateway listening", "address", config.listenAddress, "signing_key_id", config.signingKeyID)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("source gateway stopped unexpectedly", "error", err.Error())
		os.Exit(1)
	}
}

func healthcheck() {
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get("http://127.0.0.1:8080/ready")
	if err != nil || response.StatusCode != http.StatusOK {
		os.Exit(1)
	}
	_ = response.Body.Close()
}

type configuration struct {
	listenAddress    string
	internalEndpoint string
	publicEndpoint   string
	internalTLS      bool
	publicTLS        bool
	accessKey        string
	secretKey        string
	bucket           string
	region           string
	scratchDir       string
	grantKey         []byte
	privateKey       ed25519.PrivateKey
	signingKeyID     string
	maxFinalizers    int
	maxFetchers      int
}

func loadConfig() (configuration, error) {
	grantKey, err := decodeSecret("LRAIL_SOURCE_GRANT_KEY", 32)
	if err != nil {
		return configuration{}, err
	}
	privateKey, err := decodeSecret("LRAIL_SOURCE_SIGNING_PRIVATE_KEY", ed25519.PrivateKeySize)
	if err != nil {
		return configuration{}, err
	}
	expectedPrivateKey := ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize])
	if subtle.ConstantTimeCompare(expectedPrivateKey, privateKey) != 1 {
		return configuration{}, errors.New("LRAIL_SOURCE_SIGNING_PRIVATE_KEY is not a valid Ed25519 private key")
	}
	internalTLS, err := strconv.ParseBool(envOr("LRAIL_SOURCE_S3_INTERNAL_TLS", "true"))
	if err != nil {
		return configuration{}, errors.New("LRAIL_SOURCE_S3_INTERNAL_TLS must be true or false")
	}
	publicTLS, err := strconv.ParseBool(envOr("LRAIL_SOURCE_S3_PUBLIC_TLS", "true"))
	if err != nil {
		return configuration{}, errors.New("LRAIL_SOURCE_S3_PUBLIC_TLS must be true or false")
	}
	maxFinalizers, err := strconv.Atoi(envOr("LRAIL_SOURCE_MAX_FINALIZERS", "4"))
	if err != nil {
		return configuration{}, errors.New("LRAIL_SOURCE_MAX_FINALIZERS must be an integer")
	}
	maxFetchers, err := strconv.Atoi(envOr("LRAIL_SOURCE_MAX_FETCHERS", "2"))
	if err != nil {
		return configuration{}, errors.New("LRAIL_SOURCE_MAX_FETCHERS must be an integer")
	}
	config := configuration{
		listenAddress:    envOr("LRAIL_SOURCE_LISTEN_ADDRESS", ":8080"),
		internalEndpoint: os.Getenv("LRAIL_SOURCE_S3_INTERNAL_ENDPOINT"),
		publicEndpoint:   os.Getenv("LRAIL_SOURCE_S3_PUBLIC_ENDPOINT"),
		internalTLS:      internalTLS,
		publicTLS:        publicTLS,
		accessKey:        os.Getenv("LRAIL_SOURCE_S3_ACCESS_KEY"),
		secretKey:        os.Getenv("LRAIL_SOURCE_S3_SECRET_KEY"),
		bucket:           os.Getenv("LRAIL_SOURCE_S3_BUCKET"),
		region:           envOr("LRAIL_SOURCE_S3_REGION", "us-east-1"),
		scratchDir:       os.Getenv("LRAIL_SOURCE_SCRATCH_DIR"),
		grantKey:         grantKey,
		privateKey:       ed25519.PrivateKey(privateKey),
		signingKeyID:     os.Getenv("LRAIL_SOURCE_SIGNING_KEY_ID"),
		maxFinalizers:    maxFinalizers,
		maxFetchers:      maxFetchers,
	}
	if config.internalEndpoint == "" || config.publicEndpoint == "" || config.accessKey == "" || config.secretKey == "" ||
		config.bucket == "" || config.scratchDir == "" || config.signingKeyID == "" {
		return configuration{}, errors.New("required source gateway environment is missing")
	}
	return config, nil
}

func verifyScratch(directory string) error {
	if directory == "" {
		return errors.New("source scratch directory is required")
	}
	file, err := os.CreateTemp(directory, ".lrail-ready-*")
	if err != nil {
		return err
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		return err
	}
	return os.Remove(name)
}

func decodeSecret(name string, expectedBytes int) ([]byte, error) {
	value := os.Getenv(name)
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != expectedBytes {
		return nil, errors.New(name + " must be unpadded base64url with the required key length")
	}
	return decoded, nil
}

func envOr(name string, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
