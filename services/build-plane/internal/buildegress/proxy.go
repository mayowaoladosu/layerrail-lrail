package buildegress

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
)

const (
	DefaultConnectTimeout = 10 * time.Second
	DefaultTunnelLifetime = time.Hour
)

// Resolver resolves a requested domain afresh for each CONNECT.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Dialer opens the already validated numeric destination.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// AuditSink durably accepts one domain-level decision before egress is opened.
type AuditSink interface {
	Record(ctx context.Context, event AuditEvent) error
}

// AuditEvent intentionally excludes paths, query strings, headers, and data.
type AuditEvent struct {
	Version        int      `json:"version"`
	Timestamp      string   `json:"timestamp"`
	BuildID        string   `json:"build_id,omitempty"`
	OrganizationID string   `json:"organization_id,omitempty"`
	WorkerName     string   `json:"worker_name,omitempty"`
	PayloadDigest  string   `json:"payload_digest,omitempty"`
	Generation     uint64   `json:"generation,omitempty"`
	Domain         string   `json:"domain,omitempty"`
	RequestedIP    string   `json:"requested_ip,omitempty"`
	ResolvedIPs    []string `json:"resolved_ips"`
	ConnectedIP    string   `json:"connected_ip,omitempty"`
	Port           uint16   `json:"port,omitempty"`
	Profiles       []string `json:"profiles"`
	GatewayID      string   `json:"gateway_id,omitempty"`
	Action         string   `json:"action"`
	Reason         string   `json:"reason"`
}

// Proxy enforces the policy embedded in a verified mTLS client certificate.
type Proxy struct {
	resolver       Resolver
	dialer         Dialer
	audit          AuditSink
	clock          func() time.Time
	connectTimeout time.Duration
	tunnelLifetime time.Duration
}

// ProxyOptions are trusted cell configuration, not assignment input.
type ProxyOptions struct {
	Resolver       Resolver
	Dialer         Dialer
	Audit          AuditSink
	Clock          func() time.Time
	ConnectTimeout time.Duration
	TunnelLifetime time.Duration
}

func NewProxy(options ProxyOptions) (*Proxy, error) {
	if options.Resolver == nil || options.Dialer == nil || options.Audit == nil {
		return nil, errors.New("egress proxy dependencies are incomplete")
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.ConnectTimeout == 0 {
		options.ConnectTimeout = DefaultConnectTimeout
	}
	if options.TunnelLifetime == 0 {
		options.TunnelLifetime = DefaultTunnelLifetime
	}
	if options.ConnectTimeout < time.Second || options.ConnectTimeout > time.Minute || options.TunnelLifetime < time.Minute || options.TunnelLifetime > DefaultTunnelLifetime {
		return nil, errors.New("egress proxy timeouts are outside safe bounds")
	}
	return &Proxy{
		resolver: options.Resolver, dialer: options.Dialer, audit: options.Audit, clock: options.Clock,
		connectTimeout: options.ConnectTimeout, tunnelLifetime: options.TunnelLifetime,
	}, nil
}

func (proxy *Proxy) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	event := AuditEvent{Version: 1, Timestamp: proxy.clock().UTC().Format(time.RFC3339Nano), ResolvedIPs: []string{}, Profiles: []string{}, Action: "denied", Reason: "invalid_request"}
	policy, err := proxy.clientPolicy(request)
	if err != nil {
		proxy.deny(response, request, event, http.StatusForbidden, "client_identity")
		return
	}
	event.BuildID = policy.BuildID
	event.OrganizationID = policy.OrganizationID
	event.WorkerName = policy.WorkerName
	event.PayloadDigest = policy.PayloadDigest
	event.Generation = policy.Generation
	if request.Method != http.MethodConnect {
		proxy.deny(response, request, event, http.StatusMethodNotAllowed, "connect_required")
		return
	}
	host, port, address, err := parseConnectAuthority(request.Host)
	if err != nil {
		proxy.deny(response, request, event, http.StatusBadRequest, "authority_invalid")
		return
	}
	event.Port = port
	var candidates []netip.Addr
	if address.IsValid() {
		address = address.Unmap()
		event.RequestedIP = address.String()
		gateway, allowed := policy.privateDestination(address, port)
		if !allowed || forbiddenAddress(address) && !allowedPrivateAddress(address) {
			proxy.deny(response, request, event, http.StatusForbidden, "ip_not_mapped")
			return
		}
		event.GatewayID = gateway.GatewayID
		event.Profiles = []string{"private"}
		candidates = []netip.Addr{address}
	} else {
		event.Domain = host
		destination, publicAllowed := policy.publicDestination(host, port)
		privateGateway, privateAllowed := policy.privateDomainDestination(host, port)
		if !publicAllowed && !privateAllowed {
			proxy.deny(response, request, event, http.StatusForbidden, "domain_not_allowed")
			return
		}
		if publicAllowed {
			event.Profiles = append([]string(nil), destination.Profiles...)
		} else {
			event.Profiles = []string{"private"}
			event.GatewayID = privateGateway.GatewayID
		}
		resolveContext, cancel := context.WithTimeout(request.Context(), proxy.connectTimeout)
		resolved, resolveErr := proxy.resolver.LookupNetIP(resolveContext, "ip", host)
		cancel()
		if resolveErr != nil || len(resolved) == 0 || len(resolved) > MaxResolvedAddresses {
			proxy.deny(response, request, event, http.StatusBadGateway, "dns_failed")
			return
		}
		seen := make(map[netip.Addr]struct{}, len(resolved))
		for _, candidate := range resolved {
			candidate = candidate.Unmap()
			if !candidate.IsValid() || publicAllowed && forbiddenAddress(candidate) {
				proxy.deny(response, request, event, http.StatusForbidden, "dns_address_forbidden")
				return
			}
			if privateAllowed && !privateDestinationContains(privateGateway, candidate) {
				proxy.deny(response, request, event, http.StatusForbidden, "private_dns_mismatch")
				return
			}
			seen[candidate] = struct{}{}
		}
		for candidate := range seen {
			candidates = append(candidates, candidate)
		}
		slices.SortFunc(candidates, func(left, right netip.Addr) int { return left.Compare(right) })
	}
	for _, candidate := range candidates {
		event.ResolvedIPs = append(event.ResolvedIPs, candidate.String())
	}
	upstream, _, err := proxy.connect(request.Context(), candidates, port, func(candidate netip.Addr) error {
		attempt := event
		attempt.ConnectedIP = candidate.String()
		attempt.Action = "allowed"
		attempt.Reason = "policy_match"
		return proxy.audit.Record(request.Context(), attempt)
	})
	if err != nil {
		if errors.Is(err, errAuditUnavailable) {
			http.Error(response, "egress audit unavailable", http.StatusServiceUnavailable)
			return
		}
		proxy.deny(response, request, event, http.StatusBadGateway, "connect_failed")
		return
	}
	proxy.tunnel(response, request, upstream, policy, event)
}

func (proxy *Proxy) clientPolicy(request *http.Request) (Policy, error) {
	if request.TLS == nil || len(request.TLS.VerifiedChains) != 1 || len(request.TLS.VerifiedChains[0]) == 0 || len(request.TLS.PeerCertificates) == 0 {
		return Policy{}, errors.New("verified client certificate is absent")
	}
	return PolicyFromCertificate(request.TLS.PeerCertificates[0], proxy.clock())
}

var errAuditUnavailable = errors.New("egress audit unavailable")

func (proxy *Proxy) connect(ctx context.Context, candidates []netip.Addr, port uint16, beforeDial func(netip.Addr) error) (net.Conn, netip.Addr, error) {
	var failures []error
	for _, candidate := range candidates {
		if err := beforeDial(candidate); err != nil {
			return nil, netip.Addr{}, errAuditUnavailable
		}
		connectContext, cancel := context.WithTimeout(ctx, proxy.connectTimeout)
		connection, err := proxy.dialer.DialContext(connectContext, "tcp", formatAuthority(candidate.String(), port))
		cancel()
		if err == nil {
			return connection, candidate, nil
		}
		failures = append(failures, err)
	}
	return nil, netip.Addr{}, errors.Join(failures...)
}

func (proxy *Proxy) deny(response http.ResponseWriter, request *http.Request, event AuditEvent, status int, reason string) {
	event.Action = "denied"
	event.Reason = reason
	if err := proxy.audit.Record(request.Context(), event); err != nil {
		status = http.StatusServiceUnavailable
	}
	http.Error(response, "egress denied", status)
}

func (proxy *Proxy) tunnel(response http.ResponseWriter, request *http.Request, upstream net.Conn, policy Policy, event AuditEvent) {
	hijacker, ok := response.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(response, "tunneling unavailable", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	lifetime := proxy.tunnelLifetime
	if remaining := time.Unix(policy.ExpiresAtUnix, 0).Sub(proxy.clock()); remaining < lifetime {
		lifetime = remaining
	}
	deadline := time.Now().Add(lifetime)
	_ = client.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || buffered.Flush() != nil {
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	if event.Domain != "" {
		clientHello, err := readValidatedClientHello(client, event.Domain)
		if err != nil {
			event.Action = "denied"
			event.Reason = "tls_sni_mismatch"
			_ = proxy.audit.Record(context.WithoutCancel(request.Context()), event)
			_ = client.Close()
			_ = upstream.Close()
			return
		}
		if _, err := upstream.Write(clientHello); err != nil {
			_ = client.Close()
			_ = upstream.Close()
			return
		}
	}
	copyDone := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, client); copyDone <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); copyDone <- struct{}{} }()
	<-copyDone
	_ = client.Close()
	_ = upstream.Close()
	<-copyDone
}

func parseConnectAuthority(authority string) (string, uint16, netip.Addr, error) {
	if authority == "" || authority != strings.TrimSpace(authority) || strings.ContainsAny(authority, "/\\@?#") {
		return "", 0, netip.Addr{}, errors.New("CONNECT authority is invalid")
	}
	host, portText, err := net.SplitHostPort(authority)
	if err != nil || host == "" {
		return "", 0, netip.Addr{}, errors.New("CONNECT authority requires host and port")
	}
	portValue, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || portValue == 0 {
		return "", 0, netip.Addr{}, errors.New("CONNECT authority port is invalid")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Unmap().String(), uint16(portValue), address.Unmap(), nil
	}
	host = strings.ToLower(host)
	if !validHostname(host) {
		return "", 0, netip.Addr{}, errors.New("CONNECT domain is invalid")
	}
	return host, uint16(portValue), netip.Addr{}, nil
}

func forbiddenAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return true
	}
	for _, prefix := range forbiddenPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func allowedPrivateAddress(address netip.Addr) bool {
	address = address.Unmap()
	for _, parentText := range []string{"10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"} {
		if netip.MustParsePrefix(parentText).Contains(address) {
			return true
		}
	}
	return false
}

var forbiddenPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:2::/48"), netip.MustParsePrefix("2001:10::/28"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("fec0::/10"),
}

// JSONAuditSink emits one canonical JSON object per decision. A failed write
// fails the corresponding allowed connection closed.
type JSONAuditSink struct {
	Writer io.Writer
	mu     sync.Mutex
}

func (sink *JSONAuditSink) Record(_ context.Context, event AuditEvent) error {
	if sink == nil || sink.Writer == nil || event.Version != 1 || event.Timestamp == "" || event.Action == "" || event.Reason == "" || event.ResolvedIPs == nil || event.Profiles == nil {
		return errors.New("egress audit event is incomplete")
	}
	contents, err := canonicaljson.Marshal(event)
	if err != nil {
		return err
	}
	contents = append(contents, '\n')
	sink.mu.Lock()
	defer sink.mu.Unlock()
	written, err := sink.Writer.Write(contents)
	if err != nil || written != len(contents) {
		return errors.New("write egress audit event")
	}
	return nil
}

// NewHTTPServer applies conservative parser and connection limits.
func NewHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10,
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
}

var _ http.Handler = (*Proxy)(nil)
var _ Resolver = (*net.Resolver)(nil)
var _ Dialer = (*net.Dialer)(nil)
