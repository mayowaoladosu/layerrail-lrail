// Package buildegress provides the build cell's policy-enforcing CONNECT proxy.
package buildegress

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
)

const (
	CurrentPolicyVersion = 1
	MaxPolicyBytes       = 16 << 10
	MaxDestinations      = 256
	MaxResolvedAddresses = 32
	ProxyNamespace       = "lrail-build-control"
	ProxyServiceName     = "lrail-build-egress"
	ProxyServerName      = ProxyServiceName + "." + ProxyNamespace + ".svc.cluster.local"
	ProxyPort            = 8443
	ProxyAddress         = ProxyServerName + ".:8443"
	LocalProxyAddress    = "127.0.0.1:3128"
)

var hostnamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)
var workerNamePattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
var sha256Pattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// PrivateEndpoint is a site-owned mapping for one approved private gateway.
type PrivateEndpoint struct {
	CIDRs []string `json:"cidrs"`
	Ports []int32  `json:"ports"`
	Hosts []string `json:"hosts,omitempty"`
}

// Policy is a short-lived, certificate-bound build egress capability.
type Policy struct {
	Version          int                  `json:"version"`
	BuildID          string               `json:"build_id"`
	OrganizationID   string               `json:"organization_id"`
	WorkerName       string               `json:"worker_name"`
	PayloadDigest    string               `json:"payload_digest"`
	Generation       uint64               `json:"generation"`
	NotBeforeUnix    int64                `json:"not_before_unix"`
	ExpiresAtUnix    int64                `json:"expires_at_unix"`
	Destinations     []Destination        `json:"destinations"`
	PrivateGateways  []PrivateDestination `json:"private_gateways"`
	NetworkAuthority []NetworkAuthority   `json:"network_authority"`
}

// Destination identifies an exact public DNS name and TCP port set.
type Destination struct {
	Domain   string   `json:"domain"`
	Ports    []uint16 `json:"ports"`
	Profiles []string `json:"profiles"`
}

// PrivateDestination identifies exact private prefixes and TCP ports.
type PrivateDestination struct {
	GatewayID string   `json:"gateway_id"`
	CIDRs     []string `json:"cidrs"`
	Ports     []uint16 `json:"ports"`
	Domains   []string `json:"domains"`
}

// NetworkAuthority retains the signed per-vertex network authority for audit.
type NetworkAuthority struct {
	NodeID    string   `json:"node_id"`
	Profile   string   `json:"profile"`
	Hosts     []string `json:"hosts"`
	GatewayID string   `json:"gateway_id,omitempty"`
}

// NewPolicy converts an already verified assignment lock into the capability
// carried by a worker's short-lived egress client certificate.
func NewPolicy(buildID, organizationID, workerName, payloadDigest string, generation uint64, notBefore, expiresAt time.Time, lock llbcompiler.DefinitionLock, privateMappings map[string]PrivateEndpoint) (Policy, error) {
	policy := Policy{
		Version: CurrentPolicyVersion, BuildID: buildID, OrganizationID: organizationID, WorkerName: workerName,
		PayloadDigest: payloadDigest, Generation: generation, NotBeforeUnix: notBefore.UTC().Truncate(time.Second).Unix(),
		ExpiresAtUnix: expiresAt.UTC().Truncate(time.Second).Unix(), Destinations: []Destination{},
		PrivateGateways: []PrivateDestination{}, NetworkAuthority: []NetworkAuthority{},
	}
	destinations := make(map[string]map[uint16]map[string]struct{})
	addDestination := func(domain string, port uint16, profile string) {
		ports := destinations[domain]
		if ports == nil {
			ports = make(map[uint16]map[string]struct{})
			destinations[domain] = ports
		}
		profiles := ports[port]
		if profiles == nil {
			profiles = make(map[string]struct{})
			ports[port] = profiles
		}
		profiles[profile] = struct{}{}
	}
	for _, material := range lock.BaseMaterials {
		host, port, err := parseRegistryAuthority(material.Registry)
		if err != nil {
			return Policy{}, errors.New("base registry egress authority is invalid")
		}
		addDestination(host, port, "base")
		if material.Registry == "docker.io" {
			addDestination("auth.docker.io", 443, "base")
			addDestination("production.cloudfront.docker.com", 443, "base")
		}
		if material.Registry == "ghcr.io" {
			addDestination("pkg-containers.githubusercontent.com", 443, "base")
		}
	}
	privateByGateway := make(map[string]PrivateDestination)
	for _, capability := range lock.Network {
		authority := NetworkAuthority{
			NodeID: capability.NodeID, Profile: capability.Profile, Hosts: append([]string(nil), capability.Hosts...), GatewayID: capability.GatewayID,
		}
		policy.NetworkAuthority = append(policy.NetworkAuthority, authority)
		switch capability.Profile {
		case "none":
		case "packages", "allowlist":
			for _, host := range capability.Hosts {
				addDestination(host, 443, capability.Profile)
			}
		case "private":
			mapped, exists := privateMappings[capability.GatewayID]
			if !exists {
				return Policy{}, errors.New("private egress gateway has no site mapping")
			}
			private, err := normalizePrivateDestination(capability.GatewayID, mapped)
			if err != nil {
				return Policy{}, err
			}
			if existing, exists := privateByGateway[capability.GatewayID]; exists && !equalPrivateDestination(existing, private) {
				return Policy{}, errors.New("private egress gateway mapping is inconsistent")
			}
			privateByGateway[capability.GatewayID] = private
		default:
			return Policy{}, errors.New("network authority contains an unsupported profile")
		}
	}
	for domain, ports := range destinations {
		destination := Destination{Domain: domain, Ports: make([]uint16, 0, len(ports)), Profiles: []string{}}
		profileSet := make(map[string]struct{})
		for port, profiles := range ports {
			destination.Ports = append(destination.Ports, port)
			for profile := range profiles {
				profileSet[profile] = struct{}{}
			}
		}
		for profile := range profileSet {
			destination.Profiles = append(destination.Profiles, profile)
		}
		slices.Sort(destination.Ports)
		sort.Strings(destination.Profiles)
		policy.Destinations = append(policy.Destinations, destination)
	}
	sort.Slice(policy.Destinations, func(left, right int) bool {
		return policy.Destinations[left].Domain < policy.Destinations[right].Domain
	})
	for _, gatewayID := range sortedKeys(privateByGateway) {
		policy.PrivateGateways = append(policy.PrivateGateways, privateByGateway[gatewayID])
	}
	sort.Slice(policy.NetworkAuthority, func(left, right int) bool {
		return policy.NetworkAuthority[left].NodeID < policy.NetworkAuthority[right].NodeID
	})
	if err := policy.Validate(); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

// Validate rejects non-canonical or excessive certificate capabilities.
func (policy Policy) Validate() error {
	buildID, buildErr := platformid.Parse(policy.BuildID)
	organizationID, organizationErr := platformid.Parse(policy.OrganizationID)
	if policy.Version != CurrentPolicyVersion || buildErr != nil || buildID.Prefix() != "bld" || organizationErr != nil || organizationID.Prefix() != "org" ||
		!workerNamePattern.MatchString(policy.WorkerName) || !sha256Pattern.MatchString(policy.PayloadDigest) || policy.Generation == 0 ||
		policy.NotBeforeUnix <= 0 || policy.ExpiresAtUnix <= policy.NotBeforeUnix || policy.ExpiresAtUnix-policy.NotBeforeUnix > int64((maxPolicyLifetime+time.Minute)/time.Second) ||
		len(policy.Destinations) > MaxDestinations || len(policy.PrivateGateways) > MaxDestinations || len(policy.NetworkAuthority) > MaxDestinations {
		return errors.New("egress policy identity, lifetime, or size is invalid")
	}
	previousDomain := ""
	for _, destination := range policy.Destinations {
		if !validHostname(destination.Domain) || destination.Domain <= previousDomain || len(destination.Ports) == 0 || !strictPorts(destination.Ports) ||
			len(destination.Profiles) == 0 || !strictStrings(destination.Profiles) {
			return errors.New("egress policy public destination is invalid")
		}
		for _, profile := range destination.Profiles {
			if profile != "base" && profile != "packages" && profile != "allowlist" {
				return errors.New("egress policy public destination profile is invalid")
			}
		}
		previousDomain = destination.Domain
	}
	previousGateway := ""
	for _, gateway := range policy.PrivateGateways {
		if gateway.GatewayID == "" || gateway.GatewayID <= previousGateway || len(gateway.CIDRs) == 0 || len(gateway.Ports) == 0 || !strictStrings(gateway.CIDRs) || !strictPorts(gateway.Ports) || !strictOptionalStrings(gateway.Domains) {
			return errors.New("egress policy private destination is invalid")
		}
		for _, cidr := range gateway.CIDRs {
			if !allowedPrivatePrefix(cidr) {
				return errors.New("egress policy private prefix is invalid")
			}
		}
		for _, domain := range gateway.Domains {
			if !validHostname(domain) {
				return errors.New("egress policy private domain is invalid")
			}
		}
		previousGateway = gateway.GatewayID
	}
	previousNode := ""
	for _, authority := range policy.NetworkAuthority {
		if authority.NodeID == "" || authority.NodeID <= previousNode || !slices.Contains([]string{"none", "packages", "allowlist", "private"}, authority.Profile) || !strictOptionalStrings(authority.Hosts) {
			return errors.New("egress policy network authority is invalid")
		}
		for _, host := range authority.Hosts {
			if !validHostname(host) {
				return errors.New("egress policy network host is invalid")
			}
		}
		if (authority.Profile == "none" && (len(authority.Hosts) != 0 || authority.GatewayID != "")) ||
			(authority.Profile != "none" && authority.GatewayID == "") || (authority.Profile == "private" && len(authority.Hosts) != 0) {
			return errors.New("egress policy network authority shape is invalid")
		}
		previousNode = authority.NodeID
	}
	encoded, err := canonicaljson.Marshal(policy)
	if err != nil || len(encoded) > MaxPolicyBytes {
		return errors.New("egress policy cannot be encoded within its limit")
	}
	return nil
}

func decodePolicy(contents []byte) (Policy, error) {
	if len(contents) == 0 || len(contents) > MaxPolicyBytes {
		return Policy{}, errors.New("egress policy extension is absent or oversized")
	}
	canonical, err := canonicaljson.Normalize(contents)
	if err != nil || !bytes.Equal(canonical, contents) {
		return Policy{}, errors.New("egress policy extension is not canonical JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var policy Policy
	if err := decoder.Decode(&policy); err != nil {
		return Policy{}, errors.New("egress policy extension is malformed")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Policy{}, errors.New("egress policy extension has trailing data")
	}
	if err := policy.Validate(); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

func normalizePrivateDestination(gatewayID string, endpoint PrivateEndpoint) (PrivateDestination, error) {
	private := PrivateDestination{
		GatewayID: gatewayID, CIDRs: append([]string(nil), endpoint.CIDRs...), Ports: make([]uint16, 0, len(endpoint.Ports)), Domains: append([]string(nil), endpoint.Hosts...),
	}
	sort.Strings(private.CIDRs)
	private.CIDRs = slices.Compact(private.CIDRs)
	sort.Strings(private.Domains)
	private.Domains = slices.Compact(private.Domains)
	for _, port := range endpoint.Ports {
		if port < 1 || port > 65535 {
			return PrivateDestination{}, errors.New("private egress port is invalid")
		}
		private.Ports = append(private.Ports, uint16(port))
	}
	slices.Sort(private.Ports)
	private.Ports = slices.Compact(private.Ports)
	if gatewayID == "" || len(private.CIDRs) == 0 || len(private.Ports) == 0 {
		return PrivateDestination{}, errors.New("private egress gateway mapping is empty")
	}
	for _, cidr := range private.CIDRs {
		if !allowedPrivatePrefix(cidr) {
			return PrivateDestination{}, errors.New("private egress CIDR is not an exact private prefix")
		}
	}
	for _, domain := range private.Domains {
		if !validHostname(domain) {
			return PrivateDestination{}, errors.New("private egress domain is invalid")
		}
	}
	return private, nil
}

func parseRegistryAuthority(authority string) (string, uint16, error) {
	authority = strings.ToLower(strings.TrimSpace(authority))
	if authority == "docker.io" {
		return "registry-1.docker.io", 443, nil
	}
	if validHostname(authority) {
		return authority, 443, nil
	}
	host, portText, err := net.SplitHostPort(authority)
	if err != nil || !validHostname(host) {
		return "", 0, errors.New("registry authority is invalid")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port != 443 {
		return "", 0, errors.New("public registry must use HTTPS port 443")
	}
	return host, uint16(port), nil
}

func validHostname(value string) bool {
	return hostnamePattern.MatchString(value) && value != "localhost" && !strings.HasSuffix(value, ".localhost")
}

func allowedPrivatePrefix(value string) bool {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
		return false
	}
	for _, parentText := range []string{"10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"} {
		parent := netip.MustParsePrefix(parentText)
		if parent.Addr().BitLen() == prefix.Addr().BitLen() && parent.Bits() <= prefix.Bits() && parent.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

func strictPorts(values []uint16) bool {
	if len(values) == 0 {
		return false
	}
	previous := uint16(0)
	for _, value := range values {
		if value == 0 || value <= previous {
			return false
		}
		previous = value
	}
	return true
}

func strictStrings(values []string) bool {
	if len(values) == 0 {
		return false
	}
	return strictOptionalStrings(values)
}

func strictOptionalStrings(values []string) bool {
	previous := ""
	for _, value := range values {
		if value == "" || value <= previous {
			return false
		}
		previous = value
	}
	return true
}

func equalPrivateDestination(left, right PrivateDestination) bool {
	return left.GatewayID == right.GatewayID && slices.Equal(left.CIDRs, right.CIDRs) && slices.Equal(left.Ports, right.Ports) && slices.Equal(left.Domains, right.Domains)
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (policy Policy) publicDestination(domain string, port uint16) (Destination, bool) {
	index, found := slices.BinarySearchFunc(policy.Destinations, domain, func(destination Destination, target string) int {
		return strings.Compare(destination.Domain, target)
	})
	if !found || !slices.Contains(policy.Destinations[index].Ports, port) {
		return Destination{}, false
	}
	return policy.Destinations[index], true
}

func (policy Policy) privateDestination(address netip.Addr, port uint16) (PrivateDestination, bool) {
	address = address.Unmap()
	for _, gateway := range policy.PrivateGateways {
		if !slices.Contains(gateway.Ports, port) {
			continue
		}
		for _, cidr := range gateway.CIDRs {
			prefix := netip.MustParsePrefix(cidr)
			if prefix.Contains(address) {
				return gateway, true
			}
		}
	}
	return PrivateDestination{}, false
}

func (policy Policy) privateDomainDestination(domain string, port uint16) (PrivateDestination, bool) {
	for _, gateway := range policy.PrivateGateways {
		if slices.Contains(gateway.Ports, port) && slices.Contains(gateway.Domains, domain) {
			return gateway, true
		}
	}
	return PrivateDestination{}, false
}

func privateDestinationContains(gateway PrivateDestination, address netip.Addr) bool {
	address = address.Unmap()
	for _, cidr := range gateway.CIDRs {
		if netip.MustParsePrefix(cidr).Contains(address) {
			return true
		}
	}
	return false
}

func formatAuthority(host string, port uint16) string {
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}

const maxPolicyLifetime = time.Hour
