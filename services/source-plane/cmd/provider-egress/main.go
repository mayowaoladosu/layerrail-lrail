package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/provideregress"
)

type policyResolver struct{ resolver *net.Resolver }

func (resolver policyResolver) LookupNetIP(ctx context.Context, network, host string) ([]net.IP, error) {
	addresses, err := resolver.resolver.LookupNetIP(ctx, network, host)
	if err != nil {
		return nil, err
	}
	result := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		result = append(result, net.IP(address.AsSlice()))
	}
	return result, nil
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		healthcheck()
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	proxy, listenAddress, err := loadProxy()
	if err != nil {
		logger.Error("invalid provider egress configuration", "error", err.Error())
		os.Exit(1)
	}
	handler := serverHandler(proxy.Handler())
	server := &http.Server{
		Addr: listenAddress, Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	shutdownContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-shutdownContext.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			logger.Error("provider egress shutdown failed", "error", err.Error())
		}
	}()
	logger.Info("provider egress listening", "address", listenAddress)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("provider egress stopped unexpectedly", "error", err.Error())
		os.Exit(1)
	}
}

func serverHandler(proxy http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet && (request.URL.Path == "/live" || request.URL.Path == "/ready") {
			healthy(response, request)
			return
		}
		proxy.ServeHTTP(response, request)
	})
}

func loadProxy() (*provideregress.Proxy, string, error) {
	maxConcurrent, err := strconv.Atoi(envOr("LRAIL_PROVIDER_EGRESS_MAX_CONCURRENT", "16"))
	if err != nil {
		return nil, "", errors.New("LRAIL_PROVIDER_EGRESS_MAX_CONCURRENT must be an integer")
	}
	allowed := strings.FieldsFunc(os.Getenv("LRAIL_PROVIDER_EGRESS_ALLOWED_HOSTS"), func(value rune) bool {
		return value == ',' || value == ' '
	})
	proxy, err := provideregress.New(provideregress.Config{
		AllowedHosts: allowed, Resolver: policyResolver{resolver: net.DefaultResolver}, MaxConcurrent: maxConcurrent,
	})
	if err != nil {
		return nil, "", err
	}
	return proxy, envOr("LRAIL_PROVIDER_EGRESS_LISTEN_ADDRESS", ":8082"), nil
}

func healthy(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Content-Type", "text/plain; charset=utf-8")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write([]byte("ok\n"))
}

func healthcheck() {
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get("http://127.0.0.1:8082/ready")
	if err != nil || response.StatusCode != http.StatusOK {
		os.Exit(1)
	}
	_ = response.Body.Close()
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
