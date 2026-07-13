package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildegress"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "lrail build egress proxy stopped:", err)
		os.Exit(1)
	}
}

func run() error {
	tlsConfig, err := buildegress.LoadReloadingServerTLSConfig(
		os.Getenv("LRAIL_SERVER_CERT"), os.Getenv("LRAIL_SERVER_KEY"), os.Getenv("LRAIL_CLIENT_CA"),
	)
	if err != nil {
		return err
	}
	dnsAddress := os.Getenv("LRAIL_DNS_SERVER")
	if _, port, splitErr := net.SplitHostPort(dnsAddress); splitErr != nil || port != "53" {
		return errors.New("trusted DNS production endpoint must use port 53")
	}
	resolver, err := buildegress.NewResolver(dnsAddress)
	if err != nil {
		return err
	}
	dnsContext, cancelDNS := context.WithTimeout(context.Background(), 5*time.Second)
	_, dnsErr := resolver.LookupNetIP(dnsContext, "ip", buildegress.ProxyServerName)
	cancelDNS()
	if dnsErr != nil {
		return errors.New("trusted DNS readiness check failed")
	}
	proxy, err := buildegress.NewProxy(buildegress.ProxyOptions{
		Resolver: resolver, Dialer: &net.Dialer{Timeout: buildegress.DefaultConnectTimeout, KeepAlive: 30 * time.Second},
		Audit: &buildegress.JSONAuditSink{Writer: os.Stdout},
	})
	if err != nil {
		return err
	}
	listenAddress := strings.TrimSpace(os.Getenv("LRAIL_LISTEN_ADDRESS"))
	if listenAddress == "" {
		listenAddress = ":8443"
	}
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return errors.New("listen for build egress CONNECT")
	}
	defer listener.Close()
	securedListener := tls.NewListener(listener, tlsConfig)
	server := buildegress.NewHTTPServer(proxy)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(securedListener) }()
	select {
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			_ = server.Close()
			return errors.New("shut down build egress proxy")
		}
		err := <-serveErrors
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
