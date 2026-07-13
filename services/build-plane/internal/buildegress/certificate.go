package buildegress

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
)

var policyExtensionOID = []int{1, 3, 6, 1, 4, 1, 61117, 1, 38, 1}

// ClientMaterial is mounted only in the trusted BuildKit worker process.
type ClientMaterial struct {
	Certificate []byte
	PrivateKey  []byte
	ServerCA    []byte
}

// CertificateAuthority issues short-lived policy-bearing egress identities.
type CertificateAuthority struct {
	certificate *x509.Certificate
	chainPEM    []byte
	signer      crypto.Signer
	serverCA    []byte
	clock       func() time.Time
}

// NewCertificateAuthority loads the cell-owned egress issuer and proxy trust
// roots. The issuer key never enters a worker or the egress proxy.
func NewCertificateAuthority(issuerChainPEM, issuerKeyPEM, serverCAPEM []byte, clock func() time.Time) (*CertificateAuthority, error) {
	certificates, err := parseCertificates(issuerChainPEM)
	if err != nil || len(certificates) == 0 {
		return nil, errors.New("parse egress client issuer certificate")
	}
	issuer := certificates[0]
	if !issuer.IsCA || issuer.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("egress client issuer is not a certificate authority")
	}
	keyBlock, _ := pem.Decode(issuerKeyPEM)
	if keyBlock == nil {
		return nil, errors.New("egress client issuer private key is absent")
	}
	key, err := parseSigner(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	certificatePublic, err := x509.MarshalPKIXPublicKey(issuer.PublicKey)
	if err != nil {
		return nil, errors.New("marshal egress issuer public key")
	}
	keyPublic, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil || !bytes.Equal(certificatePublic, keyPublic) {
		return nil, errors.New("egress issuer certificate and private key differ")
	}
	serverRoots := x509.NewCertPool()
	if len(serverCAPEM) == 0 || !serverRoots.AppendCertsFromPEM(serverCAPEM) {
		return nil, errors.New("egress proxy server trust roots are invalid")
	}
	if clock == nil {
		clock = time.Now
	}
	return &CertificateAuthority{
		certificate: issuer, chainPEM: append([]byte(nil), issuerChainPEM...), signer: key,
		serverCA: append([]byte(nil), serverCAPEM...), clock: clock,
	}, nil
}

// Issue creates a client-auth leaf whose signed extension is the complete
// destination capability interpreted by the proxy.
func (authority *CertificateAuthority) Issue(ctx context.Context, policy Policy) (ClientMaterial, error) {
	if authority == nil || authority.certificate == nil || authority.signer == nil {
		return ClientMaterial{}, errors.New("egress certificate authority is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return ClientMaterial{}, err
	}
	if err := policy.Validate(); err != nil {
		return ClientMaterial{}, err
	}
	now := authority.clock().UTC().Truncate(time.Second)
	if issuerNotBefore := authority.certificate.NotBefore.UTC().Truncate(time.Second).Unix(); policy.NotBeforeUnix < issuerNotBefore {
		policy.NotBeforeUnix = issuerNotBefore
	}
	if err := policy.Validate(); err != nil {
		return ClientMaterial{}, err
	}
	notBefore := time.Unix(policy.NotBeforeUnix, 0).UTC()
	expiresAt := time.Unix(policy.ExpiresAtUnix, 0).UTC()
	if now.Before(notBefore.Add(-time.Minute)) || !expiresAt.After(now) || notBefore.Before(authority.certificate.NotBefore) || expiresAt.After(authority.certificate.NotAfter) {
		return ClientMaterial{}, errors.New("egress policy lifetime is outside issuer validity")
	}
	policyBytes, err := canonicaljson.Marshal(policy)
	if err != nil || len(policyBytes) > MaxPolicyBytes {
		return ClientMaterial{}, errors.New("encode egress certificate policy")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ClientMaterial{}, errors.New("generate egress client key")
	}
	serial, err := certificateSerial()
	if err != nil {
		return ClientMaterial{}, err
	}
	identity, _ := url.Parse("spiffe://lrail.internal/build-egress/" + policy.WorkerName)
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: policy.WorkerName}, NotBefore: notBefore, NotAfter: expiresAt,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identity},
		ExtraExtensions: []pkix.Extension{{Id: policyExtensionOID, Critical: false, Value: policyBytes}},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, authority.certificate, &key.PublicKey, authority.signer)
	if err != nil {
		return ClientMaterial{}, errors.New("issue egress client certificate")
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return ClientMaterial{}, errors.New("marshal egress client key")
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	certificatePEM = append(certificatePEM, authority.chainPEM...)
	return ClientMaterial{
		Certificate: certificatePEM, PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), ServerCA: append([]byte(nil), authority.serverCA...),
	}, nil
}

// PolicyFromCertificate reads and validates the signed capability after the
// normal TLS chain and client-auth verification has succeeded.
func PolicyFromCertificate(certificate *x509.Certificate, now time.Time) (Policy, error) {
	if certificate == nil || len(certificate.URIs) != 1 || len(certificate.DNSNames) != 0 {
		return Policy{}, errors.New("egress client identity is malformed")
	}
	var extension []byte
	for _, candidate := range certificate.Extensions {
		if candidate.Id.Equal(policyExtensionOID) {
			if extension != nil {
				return Policy{}, errors.New("egress client identity repeats its policy")
			}
			extension = candidate.Value
		}
	}
	policy, err := decodePolicy(extension)
	if err != nil {
		return Policy{}, err
	}
	expectedURI := "spiffe://lrail.internal/build-egress/" + policy.WorkerName
	now = now.UTC()
	if certificate.URIs[0].String() != expectedURI || certificate.Subject.CommonName != policy.WorkerName ||
		certificate.NotBefore.Unix() != policy.NotBeforeUnix || certificate.NotAfter.Unix() != policy.ExpiresAtUnix ||
		now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return Policy{}, errors.New("egress client identity differs from its signed policy")
	}
	if !containsUsage(certificate.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return Policy{}, errors.New("egress client identity lacks client authentication usage")
	}
	return policy, nil
}

// LoadClientTLSConfig builds the worker forwarder's upstream identity.
func LoadClientTLSConfig(certificatePEM, keyPEM, serverCAPEM []byte, serverName string) (*tls.Config, error) {
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return nil, errors.New("load egress client identity")
	}
	roots := x509.NewCertPool()
	if len(serverCAPEM) == 0 || !roots.AppendCertsFromPEM(serverCAPEM) || !validHostname(serverName) {
		return nil, errors.New("egress proxy server trust configuration is invalid")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, RootCAs: roots,
		ServerName: serverName, NextProtos: []string{"http/1.1"},
	}, nil
}

// LoadServerTLSConfig requires a verified egress client certificate before
// HTTP parsing. PolicyFromCertificate then validates its signed capability.
func LoadServerTLSConfig(certificatePEM, keyPEM, clientCAPEM []byte) (*tls.Config, error) {
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return nil, errors.New("load egress proxy server identity")
	}
	clientRoots := x509.NewCertPool()
	if len(clientCAPEM) == 0 || !clientRoots.AppendCertsFromPEM(clientCAPEM) {
		return nil, errors.New("egress client trust roots are invalid")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientCAs: clientRoots,
		ClientAuth: tls.RequireAndVerifyClientCert, NextProtos: []string{"http/1.1"},
	}, nil
}

// LoadReloadingServerTLSConfig observes projected Secret rotation for each new
// connection while preserving the same strict TLS and client-auth policy.
func LoadReloadingServerTLSConfig(certificatePath, keyPath, clientCAPath string) (*tls.Config, error) {
	load := func() (*tls.Config, error) {
		certificatePEM, err := readCertificateFile(certificatePath)
		if err != nil {
			return nil, err
		}
		keyPEM, err := readCertificateFile(keyPath)
		if err != nil {
			return nil, err
		}
		clientCAPEM, err := readCertificateFile(clientCAPath)
		if err != nil {
			return nil, err
		}
		return LoadServerTLSConfig(certificatePEM, keyPEM, clientCAPEM)
	}
	configured, err := load()
	if err != nil {
		return nil, err
	}
	configured.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		rotated, err := load()
		if err != nil {
			return nil, errors.New("reload egress proxy mTLS identity")
		}
		rotated.Time = configured.Time
		return rotated, nil
	}
	return configured, nil
}

func parseCertificates(contents []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	remaining := contents
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return nil, errors.New("certificate chain contains non-PEM data")
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			return nil, errors.New("certificate chain contains a non-certificate block")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
	}
	return certificates, nil
}

func parseSigner(contents []byte) (crypto.Signer, error) {
	key, err := x509.ParsePKCS8PrivateKey(contents)
	if err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
	}
	if key, ecErr := x509.ParseECPrivateKey(contents); ecErr == nil {
		return key, nil
	}
	if key, rsaErr := x509.ParsePKCS1PrivateKey(contents); rsaErr == nil {
		return key, nil
	}
	return nil, errors.New("egress client issuer private key is unsupported")
}

func certificateSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil || serial.Sign() == 0 {
		return nil, errors.New("generate egress certificate serial")
	}
	return serial, nil
}

func containsUsage(usages []x509.ExtKeyUsage, expected x509.ExtKeyUsage) bool {
	for _, usage := range usages {
		if usage == expected {
			return true
		}
	}
	return false
}

func readCertificateFile(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("egress TLS file path is empty")
	}
	contents, err := os.ReadFile(path)
	if err != nil || len(contents) == 0 || len(contents) > 64<<10 {
		return nil, errors.New("egress TLS file is unavailable or oversized")
	}
	return contents, nil
}
