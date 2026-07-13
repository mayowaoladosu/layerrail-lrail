package buildtransport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const serverIdentity = "spiffe://lrail.test/build-cell/cell-test"
const brokerIdentity = "spiffe://lrail.test/control/build-broker"
const intruderIdentity = "spiffe://lrail.test/runtime/untrusted"

type testPKI struct {
	caPool   *x509.CertPool
	ca       *x509.Certificate
	caKey    *ecdsa.PrivateKey
	server   tls.Certificate
	broker   tls.Certificate
	intruder tls.Certificate
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey CA: %v", err)
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake WP-038 test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate CA: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate CA: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return testPKI{
		caPool: pool, ca: ca, caKey: caKey,
		server:   issueCertificate(t, ca, caKey, 2, "localhost", serverIdentity, x509.ExtKeyUsageServerAuth),
		broker:   issueCertificate(t, ca, caKey, 3, "broker", brokerIdentity, x509.ExtKeyUsageClientAuth),
		intruder: issueCertificate(t, ca, caKey, 4, "intruder", intruderIdentity, x509.ExtKeyUsageClientAuth),
	}
}

func issueCertificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, serial int64, commonName, identity string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey leaf: %v", err)
	}
	identityURI, err := url.Parse(identity)
	if err != nil {
		t.Fatalf("Parse URI: %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, URIs: []*url.URL{identityURI},
	}
	if usage == x509.ExtKeyUsageServerAuth {
		template.DNSNames = []string{"localhost"}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate leaf: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return certificate
}

func handshake(serverConfig, clientConfig *tls.Config) error {
	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()
	server := tls.Server(serverSide, serverConfig)
	client := tls.Client(clientSide, clientConfig)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	errorsSeen := make(chan error, 2)
	go func() { errorsSeen <- server.HandshakeContext(ctx) }()
	go func() { errorsSeen <- client.HandshakeContext(ctx) }()
	first := <-errorsSeen
	second := <-errorsSeen
	return errors.Join(first, second)
}

func TestMutualTLSRequiresVerifiedSPIFFEIdentities(t *testing.T) {
	t.Parallel()
	pki := newTestPKI(t)
	serverConfig, err := NewServerTLSConfig(pki.server, pki.caPool, []string{brokerIdentity})
	if err != nil {
		t.Fatalf("NewServerTLSConfig: %v", err)
	}
	clientConfig, err := NewClientTLSConfig(pki.broker, pki.caPool, "localhost", []string{serverIdentity})
	if err != nil {
		t.Fatalf("NewClientTLSConfig: %v", err)
	}
	if serverConfig.MinVersion != tls.VersionTLS13 || serverConfig.ClientAuth != tls.RequireAndVerifyClientCert || clientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("unsafe TLS configuration: server=%#v client=%#v", serverConfig, clientConfig)
	}
	if err := handshake(serverConfig, clientConfig); err != nil {
		t.Fatalf("authorized mTLS handshake: %v", err)
	}

	intruderConfig, err := NewClientTLSConfig(pki.intruder, pki.caPool, "localhost", []string{serverIdentity})
	if err != nil {
		t.Fatalf("NewClientTLSConfig intruder: %v", err)
	}
	if err := handshake(serverConfig, intruderConfig); err == nil {
		t.Fatal("expected unauthorized client URI rejection")
	}

	wrongServerIdentity, err := NewClientTLSConfig(pki.broker, pki.caPool, "localhost", []string{"spiffe://lrail.test/build-cell/other"})
	if err != nil {
		t.Fatalf("NewClientTLSConfig wrong server: %v", err)
	}
	if err := handshake(serverConfig, wrongServerIdentity); err == nil {
		t.Fatal("expected unauthorized server URI rejection")
	}

	noCertificate := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pki.caPool, ServerName: "localhost", NextProtos: []string{"h2"}}
	if err := handshake(serverConfig, noCertificate); err == nil {
		t.Fatal("expected missing client certificate rejection")
	}
}

func TestMutualTLSRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()
	pki := newTestPKI(t)
	if _, err := NewServerTLSConfig(tls.Certificate{}, pki.caPool, []string{brokerIdentity}); err == nil {
		t.Fatal("expected missing server identity rejection")
	}
	if _, err := NewServerTLSConfig(pki.server, pki.caPool, []string{"https://example.invalid/client"}); err == nil {
		t.Fatal("expected non-SPIFFE identity rejection")
	}
	if _, err := NewServerTLSConfig(pki.server, pki.caPool, []string{"spiffe://lrail.test/build/../admin"}); err == nil {
		t.Fatal("expected non-canonical SPIFFE identity rejection")
	}
	if _, err := NewClientTLSConfig(pki.broker, nil, "localhost", []string{serverIdentity}); err == nil {
		t.Fatal("expected missing root pool rejection")
	}
}

func TestReloadingTLSConfigsObserveProjectedCertificateRotation(t *testing.T) {
	t.Parallel()
	pki := newTestPKI(t)
	root := t.TempDir()
	serverCert := filepath.Join(root, "server.pem")
	serverKey := filepath.Join(root, "server-key.pem")
	clientCert := filepath.Join(root, "client.pem")
	clientKey := filepath.Join(root, "client-key.pem")
	caPath := filepath.Join(root, "ca.pem")
	writeTLSIdentity(t, serverCert, serverKey, pki.server)
	writeTLSIdentity(t, clientCert, clientKey, pki.broker)
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.ca.Raw}), 0o600); err != nil {
		t.Fatalf("WriteFile CA: %v", err)
	}
	serverConfig, err := NewReloadingServerTLSConfig(serverCert, serverKey, caPath, []string{brokerIdentity})
	if err != nil {
		t.Fatalf("NewReloadingServerTLSConfig: %v", err)
	}
	clientConfig, err := NewReloadingClientTLSConfig(clientCert, clientKey, caPath, "localhost", []string{serverIdentity})
	if err != nil {
		t.Fatalf("NewReloadingClientTLSConfig: %v", err)
	}
	if err := handshake(serverConfig, clientConfig); err != nil {
		t.Fatalf("initial handshake: %v", err)
	}

	writeTLSIdentity(t, clientCert, clientKey, pki.intruder)
	if err := handshake(serverConfig, clientConfig); err == nil {
		t.Fatal("expected rotated unauthorized client rejection")
	}
	writeTLSIdentity(t, clientCert, clientKey, pki.broker)
	if err := handshake(serverConfig, clientConfig); err != nil {
		t.Fatalf("restored client handshake: %v", err)
	}

	wrongServer := issueCertificate(t, pki.ca, pki.caKey, 5, "localhost", "spiffe://lrail.test/build-cell/rotated-wrong", x509.ExtKeyUsageServerAuth)
	writeTLSIdentity(t, serverCert, serverKey, wrongServer)
	if err := handshake(serverConfig, clientConfig); err == nil {
		t.Fatal("expected rotated unauthorized server rejection")
	}
}

func writeTLSIdentity(t *testing.T, certificatePath, keyPath string, certificate tls.Certificate) {
	t.Helper()
	certificatePEM := []byte{}
	for _, contents := range certificate.Certificate {
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: contents})...)
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	if err := os.WriteFile(certificatePath, certificatePEM, 0o600); err != nil {
		t.Fatalf("WriteFile certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}), 0o600); err != nil {
		t.Fatalf("WriteFile key: %v", err)
	}
}
