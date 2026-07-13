package buildegress

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
)

const egressBuildID = "bld_019b01da-7e31-7000-8000-000000000001"
const egressOrgID = "org_019b01da-7e31-7000-8000-000000000002"
const egressPayload = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var egressNow = time.Date(2026, 7, 13, 9, 0, 0, 0, time.UTC)

type sequenceResolver struct {
	mu        sync.Mutex
	responses [][]netip.Addr
	calls     []string
}

func (resolver *sequenceResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	resolver.calls = append(resolver.calls, network+":"+host)
	if len(resolver.responses) == 0 {
		return nil, errors.New("unexpected DNS query")
	}
	result := append([]netip.Addr(nil), resolver.responses[0]...)
	resolver.responses = resolver.responses[1:]
	return result, nil
}

type echoDialer struct {
	mu      sync.Mutex
	calls   []string
	failAll bool
}

func (dialer *echoDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	dialer.mu.Lock()
	dialer.calls = append(dialer.calls, network+":"+address)
	fail := dialer.failAll
	dialer.mu.Unlock()
	if fail {
		return nil, errors.New("dial failed")
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		buffer := make([]byte, 32<<10)
		for {
			count, err := server.Read(buffer)
			if count > 0 {
				if _, writeErr := server.Write(buffer[:count]); writeErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	return client, nil
}

type memoryAudit struct {
	mu     sync.Mutex
	events []AuditEvent
	fail   bool
}

func (audit *memoryAudit) Record(_ context.Context, event AuditEvent) error {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	audit.events = append(audit.events, event)
	if audit.fail {
		return errors.New("audit unavailable")
	}
	return nil
}

func TestProxyRevalidatesDNSAndBlocksRebinding(t *testing.T) {
	resolver := &sequenceResolver{responses: [][]netip.Addr{{netip.MustParseAddr("93.184.216.34")}, {netip.MustParseAddr("169.254.169.254")}}}
	dialer := &echoDialer{}
	audit := &memoryAudit{}
	forwardAddress, closeProxy := startProxyFixture(t, resolver, dialer, audit, publicPolicy(t))
	defer closeProxy()

	connection, response := connectThroughForwarder(t, forwardAddress, "packages.example.invalid:443")
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		t.Fatalf("first CONNECT status=%d body=%q audit=%#v resolver=%#v dialer=%#v", response.StatusCode, body, audit.events, resolver.calls, dialer.calls)
	}
	roundTripClientHello(t, connection, "packages.example.invalid")
	_ = connection.Close()

	second, denied := connectThroughForwarder(t, forwardAddress, "packages.example.invalid:443")
	_ = second.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("rebound CONNECT status = %d", denied.StatusCode)
	}
	if len(resolver.calls) != 2 || len(dialer.calls) != 1 {
		t.Fatalf("resolver=%#v dialer=%#v", resolver.calls, dialer.calls)
	}
	if len(audit.events) != 2 || audit.events[0].Action != "allowed" || audit.events[0].Domain != "packages.example.invalid" || audit.events[0].ConnectedIP != "93.184.216.34" || audit.events[0].PayloadDigest != egressPayload ||
		audit.events[1].Action != "denied" || audit.events[1].Reason != "dns_address_forbidden" {
		t.Fatalf("audit events = %#v", audit.events)
	}
}

func TestProxyDeniesUnlistedDomainBeforeDNSAndMixedAnswers(t *testing.T) {
	resolver := &sequenceResolver{responses: [][]netip.Addr{{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("10.0.0.8")}}}
	dialer := &echoDialer{}
	audit := &memoryAudit{}
	forwardAddress, closeProxy := startProxyFixture(t, resolver, dialer, audit, publicPolicy(t))
	defer closeProxy()

	connection, response := connectThroughForwarder(t, forwardAddress, "undeclared.example.invalid:443")
	_ = connection.Close()
	if response.StatusCode != http.StatusForbidden || len(resolver.calls) != 0 || len(dialer.calls) != 0 {
		t.Fatalf("unlisted status=%d resolver=%#v dialer=%#v", response.StatusCode, resolver.calls, dialer.calls)
	}
	connection, response = connectThroughForwarder(t, forwardAddress, "packages.example.invalid:443")
	_ = connection.Close()
	if response.StatusCode != http.StatusForbidden || len(resolver.calls) != 1 || len(dialer.calls) != 0 {
		t.Fatalf("mixed-answer status=%d resolver=%#v dialer=%#v", response.StatusCode, resolver.calls, dialer.calls)
	}
}

func TestProxyAllowsOnlyExactPrivateMapping(t *testing.T) {
	resolver := &sequenceResolver{}
	dialer := &echoDialer{}
	audit := &memoryAudit{}
	forwardAddress, closeProxy := startProxyFixture(t, resolver, dialer, audit, privatePolicy(t))
	defer closeProxy()

	connection, response := connectThroughForwarder(t, forwardAddress, "10.20.30.40:8443")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("mapped CONNECT status=%d audit=%#v resolver=%#v dialer=%#v", response.StatusCode, audit.events, resolver.calls, dialer.calls)
	}
	_ = connection.Close()
	for _, authority := range []string{"10.20.30.41:8443", "10.20.30.40:443", "169.254.169.254:8443", "93.184.216.34:8443"} {
		connection, response = connectThroughForwarder(t, forwardAddress, authority)
		_ = connection.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("%s status = %d", authority, response.StatusCode)
		}
	}
	if len(resolver.calls) != 0 || len(dialer.calls) != 1 || audit.events[0].GatewayID != "private-gateway" || audit.events[0].RequestedIP != "10.20.30.40" {
		t.Fatalf("resolver=%#v dialer=%#v audit=%#v", resolver.calls, dialer.calls, audit.events)
	}
}

func TestProxyPrivateDomainMustResolveInsideExactMapping(t *testing.T) {
	resolver := &sequenceResolver{responses: [][]netip.Addr{{netip.MustParseAddr("10.20.30.40")}, {netip.MustParseAddr("10.20.30.41")}}}
	dialer := &echoDialer{}
	audit := &memoryAudit{}
	forwardAddress, closeProxy := startProxyFixture(t, resolver, dialer, audit, privatePolicy(t))
	defer closeProxy()

	connection, response := connectThroughForwarder(t, forwardAddress, "packages.internal.example:8443")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("mapped private domain status=%d audit=%#v resolver=%#v dialer=%#v", response.StatusCode, audit.events, resolver.calls, dialer.calls)
	}
	roundTripClientHello(t, connection, "packages.internal.example")
	_ = connection.Close()
	connection, response = connectThroughForwarder(t, forwardAddress, "packages.internal.example:8443")
	_ = connection.Close()
	if response.StatusCode != http.StatusForbidden || len(dialer.calls) != 1 || audit.events[1].Reason != "private_dns_mismatch" {
		t.Fatalf("rebound status=%d dialer=%#v audit=%#v", response.StatusCode, dialer.calls, audit.events)
	}
}

func TestProxyRejectsDomainFrontingSNI(t *testing.T) {
	resolver := &sequenceResolver{responses: [][]netip.Addr{{netip.MustParseAddr("93.184.216.34")}}}
	dialer := &echoDialer{}
	audit := &memoryAudit{}
	forwardAddress, closeProxy := startProxyFixture(t, resolver, dialer, audit, publicPolicy(t))
	defer closeProxy()
	connection, response := connectThroughForwarder(t, forwardAddress, "packages.example.invalid:443")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", response.StatusCode)
	}
	clientHello := makeClientHello(t, "fronted.example.invalid")
	if _, err := connection.Write(clientHello); err != nil {
		t.Fatalf("write ClientHello: %v", err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1)
	if count, err := connection.Read(buffer); count != 0 || err == nil {
		t.Fatalf("fronted tunnel remained open: count=%d error=%v", count, err)
	}
	_ = connection.Close()
	if len(audit.events) != 2 || audit.events[1].Action != "denied" || audit.events[1].Reason != "tls_sni_mismatch" {
		t.Fatalf("audit events = %#v", audit.events)
	}
}

func TestProxyFailsClosedWhenAuditCannotRecord(t *testing.T) {
	resolver := &sequenceResolver{responses: [][]netip.Addr{{netip.MustParseAddr("93.184.216.34")}}}
	dialer := &echoDialer{}
	audit := &memoryAudit{fail: true}
	forwardAddress, closeProxy := startProxyFixture(t, resolver, dialer, audit, publicPolicy(t))
	defer closeProxy()
	connection, response := connectThroughForwarder(t, forwardAddress, "packages.example.invalid:443")
	_ = connection.Close()
	if response.StatusCode != http.StatusServiceUnavailable || len(dialer.calls) != 0 {
		t.Fatalf("status=%d dialer=%#v", response.StatusCode, dialer.calls)
	}
}

func TestCertificatePolicyRoundTripAndTamperRejection(t *testing.T) {
	rootCert, rootKey, rootPEM, rootKeyPEM := testRootCA(t)
	_ = rootCert
	_ = rootKey
	authority, err := NewCertificateAuthority(rootPEM, rootKeyPEM, rootPEM, func() time.Time { return egressNow })
	if err != nil {
		t.Fatalf("NewCertificateAuthority: %v", err)
	}
	policy := publicPolicy(t)
	material, err := authority.Issue(context.Background(), policy)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	block, _ := pem.Decode(material.Certificate)
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	parsed, err := PolicyFromCertificate(certificate, egressNow)
	if err != nil || parsed.BuildID != policy.BuildID || !slices.Equal(parsed.Destinations[0].Profiles, policy.Destinations[0].Profiles) {
		t.Fatalf("parsed=%#v error=%v", parsed, err)
	}
	if _, err := PolicyFromCertificate(certificate, time.Unix(policy.ExpiresAtUnix, 0)); err == nil {
		t.Fatal("expected expired egress client identity rejection")
	}
	tampered := *certificate
	tampered.Extensions = append([]pkix.Extension(nil), certificate.Extensions...)
	for index := range tampered.Extensions {
		if tampered.Extensions[index].Id.Equal(policyExtensionOID) {
			tampered.Extensions[index].Value = append([]byte(nil), tampered.Extensions[index].Value...)
			tampered.Extensions[index].Value[len(tampered.Extensions[index].Value)-1] ^= 1
		}
	}
	if _, err := PolicyFromCertificate(&tampered, egressNow); err == nil {
		t.Fatal("expected tampered policy rejection")
	}
}

func TestReloadingProxyTLSConfigObservesServerRotation(t *testing.T) {
	t.Parallel()
	_, _, rootPEM, rootKeyPEM := testRootCA(t)
	serverPEM, serverKeyPEM := testServerCertificate(t, rootPEM, rootKeyPEM, "proxy.example.invalid")
	authority, err := NewCertificateAuthority(rootPEM, rootKeyPEM, rootPEM, func() time.Time { return egressNow })
	if err != nil {
		t.Fatalf("NewCertificateAuthority: %v", err)
	}
	clientMaterial, err := authority.Issue(context.Background(), publicPolicy(t))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	root := t.TempDir()
	certificatePath := filepath.Join(root, "server.pem")
	keyPath := filepath.Join(root, "server-key.pem")
	caPath := filepath.Join(root, "ca.pem")
	writeProxyTLSFile(t, certificatePath, serverPEM)
	writeProxyTLSFile(t, keyPath, serverKeyPEM)
	writeProxyTLSFile(t, caPath, rootPEM)
	serverConfig, err := LoadReloadingServerTLSConfig(certificatePath, keyPath, caPath)
	if err != nil {
		t.Fatalf("LoadReloadingServerTLSConfig: %v", err)
	}
	clientConfig, err := LoadClientTLSConfig(clientMaterial.Certificate, clientMaterial.PrivateKey, rootPEM, "proxy.example.invalid")
	if err != nil {
		t.Fatalf("LoadClientTLSConfig: %v", err)
	}
	serverConfig.Time = func() time.Time { return egressNow }
	clientConfig.Time = func() time.Time { return egressNow }
	if err := proxyTLSHandshake(serverConfig, clientConfig); err != nil {
		t.Fatalf("initial handshake: %v", err)
	}
	wrongPEM, wrongKeyPEM := testServerCertificate(t, rootPEM, rootKeyPEM, "wrong.example.invalid")
	writeProxyTLSFile(t, certificatePath, wrongPEM)
	writeProxyTLSFile(t, keyPath, wrongKeyPEM)
	if err := proxyTLSHandshake(serverConfig, clientConfig); err == nil {
		t.Fatal("expected rotated wrong-name server rejection")
	}
}

func TestPolicyClientChainsThroughDedicatedIntermediate(t *testing.T) {
	t.Parallel()
	root, rootKey, rootPEM, _ := testRootCA(t)
	intermediatePEM, intermediateKeyPEM := testIntermediateCA(t, root, rootKey)
	chainPEM := append(append([]byte(nil), intermediatePEM...), rootPEM...)
	authority, err := NewCertificateAuthority(chainPEM, intermediateKeyPEM, rootPEM, func() time.Time { return egressNow })
	if err != nil {
		t.Fatalf("NewCertificateAuthority: %v", err)
	}
	material, err := authority.Issue(context.Background(), publicPolicy(t))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	leafBlock, remainder := pem.Decode(material.Certificate)
	intermediateBlock, _ := pem.Decode(remainder)
	if leafBlock == nil || intermediateBlock == nil {
		t.Fatal("issued client chain is incomplete")
	}
	leaf, _ := x509.ParseCertificate(leafBlock.Bytes)
	intermediate, _ := x509.ParseCertificate(intermediateBlock.Bytes)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: egressNow,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("Verify client chain: %v", err)
	}
}

func startProxyFixture(t *testing.T, resolver Resolver, dialer Dialer, audit AuditSink, policy Policy) (string, func()) {
	t.Helper()
	_, _, rootPEM, rootKeyPEM := testRootCA(t)
	serverCertPEM, serverKeyPEM := testServerCertificate(t, rootPEM, rootKeyPEM, "proxy.example.invalid")
	authority, err := NewCertificateAuthority(rootPEM, rootKeyPEM, rootPEM, func() time.Time { return egressNow })
	if err != nil {
		t.Fatalf("NewCertificateAuthority: %v", err)
	}
	clientMaterial, err := authority.Issue(context.Background(), policy)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	serverTLS, err := LoadServerTLSConfig(serverCertPEM, serverKeyPEM, rootPEM)
	if err != nil {
		t.Fatalf("LoadServerTLSConfig: %v", err)
	}
	clientTLS, err := LoadClientTLSConfig(clientMaterial.Certificate, clientMaterial.PrivateKey, rootPEM, "proxy.example.invalid")
	if err != nil {
		t.Fatalf("LoadClientTLSConfig: %v", err)
	}
	serverTLS.Time = func() time.Time { return egressNow }
	clientTLS.Time = func() time.Time { return egressNow }
	proxy, err := NewProxy(ProxyOptions{Resolver: resolver, Dialer: dialer, Audit: audit, Clock: func() time.Time { return egressNow }})
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	tlsListener := tls.NewListener(proxyListener, serverTLS)
	proxyServer := NewHTTPServer(proxy)
	go func() { _ = proxyServer.Serve(tlsListener) }()

	forwarder, err := NewForwarder(proxyListener.Addr().String(), clientTLS)
	if err != nil {
		t.Fatalf("NewForwarder: %v", err)
	}
	forwardListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("forward listen: %v", err)
	}
	forwardContext, cancelForward := context.WithCancel(context.Background())
	go func() { _ = forwarder.Serve(forwardContext, forwardListener) }()
	return forwardListener.Addr().String(), func() {
		cancelForward()
		_ = forwardListener.Close()
		_ = proxyServer.Close()
		_ = proxyListener.Close()
	}
}

func connectThroughForwarder(t *testing.T, forwardAddress, authority string) (net.Conn, *http.Response) {
	t.Helper()
	connection, err := net.DialTimeout("tcp", forwardAddress, 5*time.Second)
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	if _, err := io.WriteString(connection, "CONNECT "+authority+" HTTP/1.1\r\nHost: "+authority+"\r\n\r\n"); err != nil {
		_ = connection.Close()
		t.Fatalf("write CONNECT: %v", err)
	}
	request := &http.Request{Method: http.MethodConnect}
	response, err := http.ReadResponse(bufio.NewReader(connection), request)
	if err != nil {
		_ = connection.Close()
		t.Fatalf("read CONNECT: %v", err)
	}
	return connection, response
}

func roundTripClientHello(t *testing.T, connection net.Conn, serverName string) {
	t.Helper()
	clientHello := makeClientHello(t, serverName)
	if _, err := connection.Write(clientHello); err != nil {
		t.Fatalf("write ClientHello: %v", err)
	}
	echo := make([]byte, len(clientHello))
	if _, err := io.ReadFull(connection, echo); err != nil || !slices.Equal(echo, clientHello) {
		t.Fatalf("ClientHello echo differs: error=%v", err)
	}
}

func makeClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	secure := tls.Client(client, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName})
	done := make(chan error, 1)
	go func() { done <- secure.Handshake() }()
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	header := make([]byte, 5)
	if _, err := io.ReadFull(server, header); err != nil {
		t.Fatalf("read generated ClientHello header: %v", err)
	}
	length := int(header[3])<<8 | int(header[4])
	payload := make([]byte, length)
	if _, err := io.ReadFull(server, payload); err != nil {
		t.Fatalf("read generated ClientHello payload: %v", err)
	}
	_ = server.Close()
	_ = client.Close()
	<-done
	return append(header, payload...)
}

func publicPolicy(t *testing.T) Policy {
	t.Helper()
	lock := llbcompiler.DefinitionLock{
		BaseMaterials: []llbcompiler.BaseMaterial{{Registry: "registry.example.invalid"}},
		Network:       []llbcompiler.NetworkCapability{{NodeID: "n1", Profile: "packages", Hosts: []string{"packages.example.invalid"}, GatewayID: "packages-gateway"}},
	}
	policy, err := NewPolicy(egressBuildID, egressOrgID, "build-fixture-a1", egressPayload, 1, egressNow.Add(-time.Minute), egressNow.Add(10*time.Minute), lock, nil)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	return policy
}

func privatePolicy(t *testing.T) Policy {
	t.Helper()
	lock := llbcompiler.DefinitionLock{Network: []llbcompiler.NetworkCapability{{NodeID: "n1", Profile: "private", Hosts: []string{}, GatewayID: "private-gateway"}}}
	policy, err := NewPolicy(egressBuildID, egressOrgID, "build-fixture-a1", egressPayload, 1, egressNow.Add(-time.Minute), egressNow.Add(10*time.Minute), lock,
		map[string]PrivateEndpoint{"private-gateway": {CIDRs: []string{"10.20.30.40/32"}, Ports: []int32{8443}, Hosts: []string{"packages.internal.example"}}})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	return policy
}

func testRootCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "egress test root"}, NotBefore: egressNow.Add(-time.Hour), NotAfter: egressNow.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certificate, _ := x509.ParseCertificate(der)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return certificate, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func testServerCertificate(t *testing.T, rootPEM, rootKeyPEM []byte, dnsName string) ([]byte, []byte) {
	t.Helper()
	rootBlock, _ := pem.Decode(rootPEM)
	root, _ := x509.ParseCertificate(rootBlock.Bytes)
	keyBlock, _ := pem.Decode(rootKeyPEM)
	parsedKey, _ := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	rootKey := parsedKey.(*ecdsa.PrivateKey)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	identity, _ := url.Parse("spiffe://lrail.internal/build-egress-proxy")
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: dnsName}, NotBefore: egressNow.Add(-time.Hour), NotAfter: egressNow.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{dnsName}, URIs: []*url.URL{identity},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certificate = append(certificate, rootPEM...)
	return certificate, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func testIntermediateCA(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "egress intermediate"},
		NotBefore: egressNow.Add(-time.Hour), NotAfter: egressNow.Add(12 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func writeProxyTLSFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func proxyTLSHandshake(serverConfig, clientConfig *tls.Config) error {
	serverConnection, clientConnection := net.Pipe()
	defer serverConnection.Close()
	defer clientConnection.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	errorsSeen := make(chan error, 2)
	go func() { errorsSeen <- tls.Server(serverConnection, serverConfig).HandshakeContext(ctx) }()
	go func() { errorsSeen <- tls.Client(clientConnection, clientConfig).HandshakeContext(ctx) }()
	return errors.Join(<-errorsSeen, <-errorsSeen)
}

func TestJSONAuditSinkCanonicalLineAndValidation(t *testing.T) {
	var output strings.Builder
	sink := &JSONAuditSink{Writer: &output}
	event := AuditEvent{Version: 1, Timestamp: egressNow.Format(time.RFC3339), ResolvedIPs: []string{}, Profiles: []string{}, Action: "denied", Reason: "test"}
	if err := sink.Record(context.Background(), event); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if !strings.HasSuffix(output.String(), "\n") || !strings.Contains(output.String(), `"reason":"test"`) {
		t.Fatalf("audit output = %q", output.String())
	}
}

func TestNewResolverRequiresLiteralPrivateDNS(t *testing.T) {
	t.Parallel()
	if _, err := NewResolver("10.96.0.10:53"); err != nil {
		t.Fatalf("private DNS rejected: %v", err)
	}
	if _, err := NewResolver("10.96.0.10:5353"); err != nil {
		t.Fatalf("private DNS test port rejected: %v", err)
	}
	for _, address := range []string{"", "kube-dns.kube-system.svc:53", "8.8.8.8:53", "127.0.0.1:53", "169.254.169.254:53", "10.96.0.10:0"} {
		if _, err := NewResolver(address); err == nil {
			t.Fatalf("expected DNS endpoint rejection for %q", address)
		}
	}
}

func TestForbiddenAddressRejectsSpecialPurposeRanges(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"0.0.0.1", "10.0.0.1", "100.100.100.200", "127.0.0.1", "169.254.169.254", "172.16.0.1", "192.168.0.1",
		"192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "240.0.0.1", "::1", "fc00::1", "fe80::1", "fec0::1", "2001:db8::1", "3fff::1",
	} {
		if !forbiddenAddress(netip.MustParseAddr(value)) {
			t.Errorf("special-purpose address allowed: %s", value)
		}
	}
	for _, value := range []string{"93.184.216.34", "2606:4700:4700::1111"} {
		if forbiddenAddress(netip.MustParseAddr(value)) {
			t.Errorf("public address rejected: %s", value)
		}
	}
}
