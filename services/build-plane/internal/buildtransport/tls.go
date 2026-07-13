package buildtransport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
)

const MaxAllowedPeerIdentities = 16

func NewServerTLSConfig(certificate tls.Certificate, clientRoots *x509.CertPool, allowedClientURIs []string) (*tls.Config, error) {
	allowed, err := validatePeerURIs(allowedClientURIs)
	if err != nil || clientRoots == nil || len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
		return nil, errors.New("mTLS server identity configuration is incomplete")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientRoots,
		NextProtos:   []string{"h2"},
		VerifyConnection: func(state tls.ConnectionState) error {
			return verifyPeerURI(state, allowed)
		},
	}, nil
}

func NewClientTLSConfig(certificate tls.Certificate, serverRoots *x509.CertPool, serverName string, allowedServerURIs []string) (*tls.Config, error) {
	allowed, err := validatePeerURIs(allowedServerURIs)
	if err != nil || serverRoots == nil || serverName == "" || len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
		return nil, errors.New("mTLS client identity configuration is incomplete")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      serverRoots,
		ServerName:   serverName,
		NextProtos:   []string{"h2"},
		VerifyConnection: func(state tls.ConnectionState) error {
			return verifyPeerURI(state, allowed)
		},
	}, nil
}

func validatePeerURIs(values []string) (map[string]struct{}, error) {
	if len(values) == 0 || len(values) > MaxAllowedPeerIdentities {
		return nil, errors.New("peer URI allowlist is empty or oversized")
	}
	allowed := make(map[string]struct{}, len(values))
	for _, value := range values {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme != "spiffe" || parsed.Host == "" || parsed.Path == "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil || parsed.String() != value {
			return nil, fmt.Errorf("invalid peer URI identity %q", value)
		}
		if path.Clean(parsed.Path) != parsed.Path || strings.Contains(parsed.Path, "//") || parsed.Path == "/" || strings.HasSuffix(parsed.Path, "/") {
			return nil, fmt.Errorf("non-canonical peer URI identity %q", value)
		}
		if _, duplicate := allowed[value]; duplicate {
			return nil, errors.New("peer URI allowlist contains a duplicate")
		}
		allowed[value] = struct{}{}
	}
	return allowed, nil
}

func verifyPeerURI(state tls.ConnectionState, allowed map[string]struct{}) error {
	if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return errors.New("peer certificate chain is not verified")
	}
	leaf := state.VerifiedChains[0][0]
	if len(leaf.URIs) != 1 {
		return errors.New("peer certificate must contain exactly one URI identity")
	}
	if _, accepted := allowed[leaf.URIs[0].String()]; accepted {
		return nil
	}
	return errors.New("peer certificate URI is not authorized")
}
