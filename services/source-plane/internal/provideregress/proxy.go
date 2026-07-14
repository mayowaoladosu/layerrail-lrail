// Package provideregress implements the source plane's exact-host CONNECT proxy.
package provideregress

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/netpolicy"
)

const (
	DefaultMaxConcurrent = 16
	DefaultDialTimeout   = 15 * time.Second
	DefaultTunnelTimeout = 15 * time.Minute
)

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type Config struct {
	AllowedHosts  []string
	Resolver      netpolicy.Resolver
	Dialer        Dialer
	MaxConcurrent int
	DialTimeout   time.Duration
	TunnelTimeout time.Duration
}

type Proxy struct {
	allowed       []string
	policy        netpolicy.Policy
	dialer        Dialer
	semaphore     chan struct{}
	dialTimeout   time.Duration
	tunnelTimeout time.Duration
}

func New(config Config) (*Proxy, error) {
	if config.Resolver == nil {
		return nil, errors.New("provider egress resolver is required")
	}
	allowed := make([]string, 0, len(config.AllowedHosts))
	for _, value := range config.AllowedHosts {
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
		if host == "" || strings.ContainsAny(host, "/:@[]") || net.ParseIP(host) != nil || slices.Contains(allowed, host) {
			return nil, errors.New("provider egress host allowlist is invalid")
		}
		allowed = append(allowed, host)
	}
	if len(allowed) == 0 || len(allowed) > 16 {
		return nil, errors.New("provider egress host allowlist is outside bounds")
	}
	slices.Sort(allowed)
	if config.Dialer == nil {
		config.Dialer = &net.Dialer{Timeout: DefaultDialTimeout, KeepAlive: 30 * time.Second}
	}
	if config.MaxConcurrent == 0 {
		config.MaxConcurrent = DefaultMaxConcurrent
	}
	if config.DialTimeout == 0 {
		config.DialTimeout = DefaultDialTimeout
	}
	if config.TunnelTimeout == 0 {
		config.TunnelTimeout = DefaultTunnelTimeout
	}
	if config.MaxConcurrent < 1 || config.MaxConcurrent > 128 || config.DialTimeout < time.Second || config.DialTimeout > time.Minute ||
		config.TunnelTimeout < time.Minute || config.TunnelTimeout > 30*time.Minute {
		return nil, errors.New("provider egress resource policy is outside bounds")
	}
	return &Proxy{
		allowed: allowed, policy: netpolicy.DefaultPolicy(config.Resolver), dialer: config.Dialer,
		semaphore: make(chan struct{}, config.MaxConcurrent), dialTimeout: config.DialTimeout, tunnelTimeout: config.TunnelTimeout,
	}, nil
}

func (proxy *Proxy) Handler() http.Handler { return http.HandlerFunc(proxy.serveHTTP) }

func (proxy *Proxy) serveHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodConnect || request.Body == nil {
		http.Error(response, "CONNECT required", http.StatusMethodNotAllowed)
		return
	}
	select {
	case proxy.semaphore <- struct{}{}:
		defer func() { <-proxy.semaphore }()
	default:
		http.Error(response, "proxy capacity unavailable", http.StatusServiceUnavailable)
		return
	}
	decision, err := proxy.authorize(request.Context(), request.Host)
	if err != nil {
		http.Error(response, "destination denied", http.StatusForbidden)
		return
	}
	upstream, err := proxy.dial(request.Context(), decision)
	if err != nil {
		http.Error(response, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	hijacker, ok := response.(http.Hijacker)
	if !ok {
		http.Error(response, "tunnel unavailable", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	deadline := time.Now().Add(proxy.tunnelTimeout)
	_ = client.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || buffered.Flush() != nil {
		return
	}
	relay(client, buffered.Reader, upstream)
}

func (proxy *Proxy) authorize(ctx context.Context, authority string) (netpolicy.Decision, error) {
	if len(authority) == 0 || len(authority) > 512 {
		return netpolicy.Decision{}, errors.New("provider egress authority is invalid")
	}
	parsed, err := url.Parse("https://" + authority)
	if err != nil || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return netpolicy.Decision{}, errors.New("provider egress authority is invalid")
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	port, err := strconv.ParseUint(parsed.Port(), 10, 16)
	if err != nil || port != 443 || !slices.Contains(proxy.allowed, host) {
		return netpolicy.Decision{}, errors.New("provider egress authority is denied")
	}
	return proxy.policy.Validate(ctx, "https://"+net.JoinHostPort(host, "443"))
}

func (proxy *Proxy) dial(ctx context.Context, decision netpolicy.Decision) (net.Conn, error) {
	dialContext, cancel := context.WithTimeout(ctx, proxy.dialTimeout)
	defer cancel()
	var failures []error
	for index := range decision.Addresses {
		address, err := decision.DialAddress(index)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		connection, err := proxy.dialer.DialContext(dialContext, "tcp", address)
		if err == nil {
			return connection, nil
		}
		failures = append(failures, err)
	}
	return nil, fmt.Errorf("provider egress dial failed: %w", errors.Join(failures...))
}

func relay(client net.Conn, clientReader *bufio.Reader, upstream net.Conn) {
	complete := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, clientReader)
		complete <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		complete <- struct{}{}
	}()
	<-complete
}
