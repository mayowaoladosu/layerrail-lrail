package main

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/objectstore"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/providerfetch"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourcearchive"
)

func buildProviderFetcher(config configuration, store objectstore.Store) (*providerfetch.Fetcher, error) {
	brokerValue := os.Getenv("LRAIL_PROVIDER_BROKER_URL")
	if brokerValue == "" {
		return nil, nil
	}
	brokerURL, err := url.Parse(brokerValue)
	if err != nil || brokerURL.Hostname() == "" || brokerURL.User != nil || brokerURL.RawQuery != "" || brokerURL.Fragment != "" {
		return nil, errors.New("LRAIL_PROVIDER_BROKER_URL is invalid")
	}
	insecureBroker := os.Getenv("LRAIL_PROVIDER_BROKER_INSECURE_LOCAL") == "true"
	if brokerURL.Scheme != "https" && !(brokerURL.Scheme == "http" && insecureBroker) {
		return nil, errors.New("LRAIL_PROVIDER_BROKER_URL must use HTTPS unless local insecure mode is explicit")
	}
	brokerClient := &http.Client{
		Transport: secureTransport(nil),
		Timeout:   45 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	baseURL, err := url.Parse(envOr("LRAIL_GITHUB_API_URL", "https://api.github.com"))
	if err != nil || baseURL.Hostname() == "" || baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, errors.New("LRAIL_GITHUB_API_URL is invalid")
	}
	loopback := providerLoopback(baseURL.Hostname())
	if net.ParseIP(baseURL.Hostname()) != nil && !loopback {
		return nil, errors.New("LRAIL_GITHUB_API_URL must use a DNS host")
	}
	if baseURL.Scheme != "https" && !(baseURL.Scheme == "http" && loopback) {
		return nil, errors.New("LRAIL_GITHUB_API_URL must use HTTPS or loopback HTTP")
	}
	proxyValue := os.Getenv("LRAIL_SOURCE_EGRESS_PROXY_URL")
	if proxyValue == "" && !loopback {
		return nil, errors.New("LRAIL_SOURCE_EGRESS_PROXY_URL is required for remote provider fetching")
	}
	var proxyURL *url.URL
	if proxyValue != "" {
		proxyURL, err = url.Parse(proxyValue)
		if err != nil || proxyURL.Hostname() == "" || proxyURL.User != nil ||
			(proxyURL.Scheme != "http" && proxyURL.Scheme != "https") {
			return nil, errors.New("LRAIL_SOURCE_EGRESS_PROXY_URL is invalid")
		}
	}
	providerClient := &http.Client{
		Transport: secureTransport(proxyURL),
		Timeout:   14 * time.Minute,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	allowedHosts := strings.FieldsFunc(os.Getenv("LRAIL_GITHUB_ARCHIVE_HOSTS"), func(value rune) bool {
		return value == ',' || value == ' '
	})
	if len(allowedHosts) == 0 {
		if loopback {
			allowedHosts = []string{baseURL.Hostname()}
		} else {
			allowedHosts = []string{"codeload.github.com"}
		}
	}
	for _, host := range allowedHosts {
		if host == "" || strings.ContainsAny(host, "/:@[]") || (net.ParseIP(host) != nil && !loopback) {
			return nil, errors.New("LRAIL_GITHUB_ARCHIVE_HOSTS contains an invalid host")
		}
	}
	return &providerfetch.Fetcher{
		Store:      store,
		ScratchDir: config.scratchDir,
		Policy:     sourcearchive.DefaultPolicy(),
		Tokens: &providerfetch.BrokerTokenSource{
			BaseURL:  brokerURL,
			Client:   brokerClient,
			GrantKey: config.grantKey,
		},
		Client:              providerClient,
		BaseURL:             baseURL,
		AllowedArchiveHosts: allowedHosts,
		PrivateKey:          config.privateKey,
		SigningKeyID:        config.signingKeyID,
	}, nil
}

func secureTransport(proxyURL *url.URL) *http.Transport {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS13},
	}
	if proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	return transport
}

func providerLoopback(host string) bool {
	return strings.EqualFold(host, "localhost") || host == "127.0.0.1" || host == "::1"
}
