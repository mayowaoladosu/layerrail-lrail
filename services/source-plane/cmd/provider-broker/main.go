package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/providerbroker"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/providerfetch"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		healthcheck()
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	config, err := loadConfig()
	if err != nil {
		logger.Error("invalid provider broker configuration", "error", err.Error())
		os.Exit(1)
	}
	api, err := providerbroker.New(providerbroker.Config{
		GrantKey: config.grantKey,
		Tokens: &providerfetch.GitHubAppTokenSource{
			BaseURL:    config.githubAPI,
			Client:     config.client,
			AppID:      config.appID,
			PrivateKey: config.privateKey,
		},
		MaxConcurrentIssues: config.maxIssues,
	})
	if err != nil {
		logger.Error("create provider broker API", "error", err.Error())
		os.Exit(1)
	}
	server := &http.Server{
		Addr:              config.listenAddress,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      45 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	shutdownContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-shutdownContext.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			logger.Error("provider broker shutdown failed", "error", err.Error())
		}
	}()
	logger.Info("provider broker listening", "address", config.listenAddress)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("provider broker stopped unexpectedly", "error", err.Error())
		os.Exit(1)
	}
}

func healthcheck() {
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get("http://127.0.0.1:8081/ready")
	if err != nil || response.StatusCode != http.StatusOK {
		os.Exit(1)
	}
	_ = response.Body.Close()
}

type configuration struct {
	listenAddress string
	grantKey      []byte
	githubAPI     *url.URL
	client        *http.Client
	appID         string
	privateKey    *rsa.PrivateKey
	maxIssues     int
}

func loadConfig() (configuration, error) {
	grantKey, err := decodeSecret("LRAIL_SOURCE_GRANT_KEY", 32)
	if err != nil {
		return configuration{}, err
	}
	githubAPI, err := url.Parse(envOr("LRAIL_GITHUB_API_URL", "https://api.github.com"))
	if err != nil || githubAPI.Hostname() == "" || githubAPI.User != nil || githubAPI.RawQuery != "" || githubAPI.Fragment != "" {
		return configuration{}, errors.New("LRAIL_GITHUB_API_URL is invalid")
	}
	loopback := isLoopback(githubAPI.Hostname())
	if net.ParseIP(githubAPI.Hostname()) != nil && !loopback {
		return configuration{}, errors.New("LRAIL_GITHUB_API_URL must use a DNS host")
	}
	if githubAPI.Scheme != "https" && !(githubAPI.Scheme == "http" && loopback) {
		return configuration{}, errors.New("LRAIL_GITHUB_API_URL must use HTTPS or loopback HTTP")
	}
	proxyValue := os.Getenv("LRAIL_SOURCE_EGRESS_PROXY_URL")
	if proxyValue == "" && !loopback {
		return configuration{}, errors.New("LRAIL_SOURCE_EGRESS_PROXY_URL is required for remote provider access")
	}
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS13},
	}
	if proxyValue != "" {
		proxyURL, parseErr := url.Parse(proxyValue)
		if parseErr != nil || proxyURL.Hostname() == "" || proxyURL.User != nil ||
			(proxyURL.Scheme != "http" && proxyURL.Scheme != "https") {
			return configuration{}, errors.New("LRAIL_SOURCE_EGRESS_PROXY_URL is invalid")
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	privateKey, err := readPrivateKey(os.Getenv("LRAIL_GITHUB_APP_PRIVATE_KEY_FILE"))
	if err != nil {
		return configuration{}, err
	}
	maxIssues, err := strconv.Atoi(envOr("LRAIL_PROVIDER_BROKER_MAX_ISSUES", "8"))
	if err != nil {
		return configuration{}, errors.New("LRAIL_PROVIDER_BROKER_MAX_ISSUES must be an integer")
	}
	appID := os.Getenv("LRAIL_GITHUB_APP_ID")
	if appID == "" {
		return configuration{}, errors.New("LRAIL_GITHUB_APP_ID is required")
	}
	return configuration{
		listenAddress: envOr("LRAIL_PROVIDER_BROKER_LISTEN_ADDRESS", ":8081"),
		grantKey:      grantKey,
		githubAPI:     githubAPI,
		client: &http.Client{
			Transport: transport,
			Timeout:   40 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		appID:      appID,
		privateKey: privateKey,
		maxIssues:  maxIssues,
	}, nil
}

func readPrivateKey(filename string) (*rsa.PrivateKey, error) {
	if filename == "" {
		return nil, errors.New("LRAIL_GITHUB_APP_PRIVATE_KEY_FILE is required")
	}
	contents, err := os.ReadFile(filename)
	if err != nil {
		return nil, errors.New("read GitHub App private-key secret file")
	}
	block, _ := pem.Decode(contents)
	if block == nil {
		return nil, errors.New("GitHub App private-key secret file is not PEM")
	}
	if key, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes); parseErr == nil {
		if key.N.BitLen() < 2048 {
			return nil, errors.New("GitHub App private key is shorter than 2048 bits")
		}
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("GitHub App private-key secret file is invalid")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok || key.N.BitLen() < 2048 {
		return nil, errors.New("GitHub App private-key secret file must contain a 2048-bit RSA key")
	}
	return key, nil
}

func decodeSecret(name string, expectedBytes int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(os.Getenv(name))
	if err != nil || len(decoded) != expectedBytes {
		return nil, errors.New(name + " must be unpadded base64url with the required key length")
	}
	return decoded, nil
}

func isLoopback(host string) bool {
	return strings.EqualFold(host, "localhost") || host == "127.0.0.1" || host == "::1"
}

func envOr(name string, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
