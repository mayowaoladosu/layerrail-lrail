package buildegress

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Forwarder is the worker-local, loopback-only bridge that adds the worker's
// mTLS capability before relaying a CONNECT to the policy proxy.
type Forwarder struct {
	upstream  string
	tlsConfig *tls.Config
	dialer    *net.Dialer
}

func NewForwarder(upstream string, tlsConfig *tls.Config) (*Forwarder, error) {
	if upstream == "" || tlsConfig == nil || tlsConfig.ServerName == "" || len(tlsConfig.Certificates) != 1 || tlsConfig.RootCAs == nil {
		return nil, errors.New("egress forwarder configuration is incomplete")
	}
	if _, _, err := net.SplitHostPort(upstream); err != nil {
		return nil, errors.New("egress forwarder upstream is invalid")
	}
	configured := tlsConfig.Clone()
	configured.MinVersion = tls.VersionTLS13
	configured.NextProtos = []string{"http/1.1"}
	return &Forwarder{upstream: upstream, tlsConfig: configured, dialer: &net.Dialer{Timeout: DefaultConnectTimeout, KeepAlive: 30 * time.Second}}, nil
}

func (forwarder *Forwarder) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodConnect {
		http.Error(response, "CONNECT required", http.StatusMethodNotAllowed)
		return
	}
	if _, _, _, err := parseConnectAuthority(request.Host); err != nil {
		http.Error(response, "invalid CONNECT authority", http.StatusBadRequest)
		return
	}
	raw, err := forwarder.dialer.DialContext(request.Context(), "tcp", forwarder.upstream)
	if err != nil {
		http.Error(response, "egress proxy unavailable", http.StatusBadGateway)
		return
	}
	secured := tls.Client(raw, forwarder.tlsConfig)
	if err := secured.HandshakeContext(request.Context()); err != nil {
		_ = raw.Close()
		http.Error(response, "egress proxy authentication failed", http.StatusBadGateway)
		return
	}
	if _, err := fmt.Fprintf(secured, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", request.Host, request.Host); err != nil {
		_ = secured.Close()
		http.Error(response, "egress proxy request failed", http.StatusBadGateway)
		return
	}
	upstreamReader := bufio.NewReaderSize(secured, 8<<10)
	upstreamResponse, err := http.ReadResponse(upstreamReader, request)
	if err != nil {
		_ = secured.Close()
		http.Error(response, "egress proxy response failed", http.StatusBadGateway)
		return
	}
	if upstreamResponse.Body != nil {
		defer upstreamResponse.Body.Close()
	}
	if upstreamResponse.StatusCode != http.StatusOK {
		_ = secured.Close()
		http.Error(response, "egress denied", upstreamResponse.StatusCode)
		return
	}
	hijacker, ok := response.(http.Hijacker)
	if !ok {
		_ = secured.Close()
		http.Error(response, "tunneling unavailable", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = secured.Close()
		return
	}
	deadline := time.Now().Add(DefaultTunnelLifetime)
	_ = client.SetDeadline(deadline)
	_ = secured.SetDeadline(deadline)
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || buffered.Flush() != nil {
		_ = client.Close()
		_ = secured.Close()
		return
	}
	copyDone := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(secured, client); copyDone <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstreamReader); copyDone <- struct{}{} }()
	<-copyDone
	_ = client.Close()
	_ = secured.Close()
	<-copyDone
}

// Serve closes promptly on cancellation and returns unexpected listener errors.
func (forwarder *Forwarder) Serve(ctx context.Context, listener net.Listener) error {
	if ctx == nil || listener == nil {
		return errors.New("egress forwarder listener is unavailable")
	}
	server := NewHTTPServer(forwarder)
	stopped := make(chan error, 1)
	go func() { stopped <- server.Serve(listener) }()
	select {
	case err := <-stopped:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			_ = server.Close()
			return err
		}
		err := <-stopped
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

var _ http.Handler = (*Forwarder)(nil)
