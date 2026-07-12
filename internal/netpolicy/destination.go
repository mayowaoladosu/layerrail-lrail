// Package netpolicy centralizes destination validation for webhooks, schedules,
// source providers, tunnels, and other controlled egress.
package netpolicy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

const (
	DefaultMaxURLBytes = 2048
	DefaultMaxIPs      = 16
)

var (
	ErrDenied       = errors.New("destination denied")
	blockedPrefixes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
)

type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]net.IP, error)
}

type Policy struct {
	Resolver     Resolver
	AllowHTTP    bool
	AllowedPorts []uint16
	MaxURLBytes  int
	MaxIPs       int
}

type Decision struct {
	URL       *url.URL
	Host      string
	Port      uint16
	Addresses []netip.Addr
}

func DefaultPolicy(resolver Resolver) Policy {
	return Policy{
		Resolver:     resolver,
		AllowedPorts: []uint16{443},
		MaxURLBytes:  DefaultMaxURLBytes,
		MaxIPs:       DefaultMaxIPs,
	}
}

func (policy Policy) Validate(ctx context.Context, rawURL string) (Decision, error) {
	if ctx == nil {
		return Decision{}, deniedf("context is nil")
	}
	if policy.Resolver == nil {
		return Decision{}, deniedf("resolver is required")
	}
	maxURLBytes := policy.MaxURLBytes
	if maxURLBytes == 0 {
		maxURLBytes = DefaultMaxURLBytes
	}
	maxIPs := policy.MaxIPs
	if maxIPs == 0 {
		maxIPs = DefaultMaxIPs
	}
	if len(rawURL) == 0 || len(rawURL) > maxURLBytes {
		return Decision{}, deniedf("URL size is outside policy")
	}
	if strings.Contains(rawURL, "#") {
		return Decision{}, deniedf("fragments are not allowed")
	}
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return Decision{}, deniedf("invalid URL")
	}
	if parsed.Scheme != "https" && !(policy.AllowHTTP && parsed.Scheme == "http") {
		return Decision{}, deniedf("scheme %q is not allowed", parsed.Scheme)
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return Decision{}, deniedf("userinfo and fragments are not allowed")
	}
	hostname := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if hostname == "" {
		return Decision{}, deniedf("hostname is required")
	}
	asciiHost, err := idna.Lookup.ToASCII(hostname)
	if err != nil || len(asciiHost) > 253 {
		return Decision{}, deniedf("hostname is not valid IDNA")
	}

	port, err := destinationPort(parsed)
	if err != nil {
		return Decision{}, err
	}
	allowedPorts := policy.AllowedPorts
	if len(allowedPorts) == 0 {
		allowedPorts = []uint16{443}
		if policy.AllowHTTP {
			allowedPorts = append(allowedPorts, 80)
		}
	}
	if !slices.Contains(allowedPorts, port) {
		return Decision{}, deniedf("port %d is not allowed", port)
	}

	addresses, err := policy.resolve(ctx, asciiHost, maxIPs)
	if err != nil {
		return Decision{}, err
	}
	normalized := *parsed
	normalized.Scheme = strings.ToLower(parsed.Scheme)
	if (normalized.Scheme == "https" && port == 443) || (normalized.Scheme == "http" && port == 80) {
		normalized.Host = asciiHost
	} else {
		normalized.Host = net.JoinHostPort(asciiHost, strconv.Itoa(int(port)))
	}
	return Decision{URL: &normalized, Host: asciiHost, Port: port, Addresses: addresses}, nil
}

func (decision Decision) DialAddress(index int) (string, error) {
	if index < 0 || index >= len(decision.Addresses) {
		return "", deniedf("resolved address index is outside decision")
	}
	return net.JoinHostPort(decision.Addresses[index].String(), strconv.Itoa(int(decision.Port))), nil
}

func (policy Policy) resolve(ctx context.Context, hostname string, maxIPs int) ([]netip.Addr, error) {
	if literal, err := netip.ParseAddr(hostname); err == nil {
		literal = literal.Unmap()
		if err := validateAddress(literal); err != nil {
			return nil, err
		}
		return []netip.Addr{literal}, nil
	}
	resolved, err := policy.Resolver.LookupNetIP(ctx, "ip", hostname)
	if err != nil {
		return nil, deniedf("DNS resolution failed")
	}
	if len(resolved) == 0 || len(resolved) > maxIPs {
		return nil, deniedf("DNS answer count is outside policy")
	}
	unique := make(map[netip.Addr]struct{}, len(resolved))
	for _, item := range resolved {
		address, ok := netip.AddrFromSlice(item)
		if !ok {
			return nil, deniedf("DNS returned an invalid address")
		}
		address = address.Unmap()
		if err := validateAddress(address); err != nil {
			return nil, err
		}
		unique[address] = struct{}{}
	}
	addresses := make([]netip.Addr, 0, len(unique))
	for address := range unique {
		addresses = append(addresses, address)
	}
	slices.SortFunc(addresses, func(first, second netip.Addr) int {
		return first.Compare(second)
	})
	return addresses, nil
}

func destinationPort(parsed *url.URL) (uint16, error) {
	portText := parsed.Port()
	if portText == "" {
		if parsed.Scheme == "https" {
			return 443, nil
		}
		return 80, nil
	}
	value, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || value == 0 {
		return 0, deniedf("port is invalid")
	}
	return uint16(value), nil
}

func validateAddress(address netip.Addr) error {
	if !address.IsValid() || address.IsUnspecified() || address.IsLoopback() ||
		address.IsPrivate() || address.IsLinkLocalUnicast() ||
		address.IsLinkLocalMulticast() || address.IsMulticast() {
		return deniedf("address is not public unicast")
	}
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(address) {
			return deniedf("address range is reserved by policy")
		}
	}
	return nil
}

func deniedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrDenied, fmt.Sprintf(format, args...))
}
