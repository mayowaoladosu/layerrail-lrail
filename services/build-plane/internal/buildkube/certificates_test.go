package buildkube

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildegress"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
)

func TestEphemeralCertificateIssuerBindsWorkerAndControllerIdentity(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 13, 7, 0, 0, 0, time.UTC)
	request := CertificateRequest{
		WorkerName: "build-fixture-a1", DNSName: "build-fixture-a1.lrail-build.svc",
		ExpiresAt: now.Add(10 * time.Minute),
	}
	issued, err := (EphemeralCertificateIssuer{Clock: func() time.Time { return now }}).Issue(context.Background(), request)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	caBlock, _ := pem.Decode(issued.Material.CA)
	serverBlock, _ := pem.Decode(issued.Material.ServerCert)
	if caBlock == nil || serverBlock == nil || issued.ClientConfig == nil || len(issued.ClientConfig.Certificates) != 1 {
		t.Fatalf("issued certificates are incomplete: %#v", issued)
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("Parse CA: %v", err)
	}
	server, err := x509.ParseCertificate(serverBlock.Bytes)
	if err != nil {
		t.Fatalf("Parse server: %v", err)
	}
	client, err := x509.ParseCertificate(issued.ClientConfig.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("Parse client: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := server.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, DNSName: request.DNSName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("Verify server: %v", err)
	}
	if _, err := client.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("Verify client: %v", err)
	}
	serverURI := "spiffe://lrail.internal/build-worker/" + request.WorkerName
	clientURI := "spiffe://lrail.internal/build-controller/" + request.WorkerName
	if len(server.URIs) != 1 || server.URIs[0].String() != serverURI || len(client.URIs) != 1 || client.URIs[0].String() != clientURI ||
		!server.NotAfter.Equal(request.ExpiresAt) || !client.NotAfter.Equal(request.ExpiresAt) || issued.ClientConfig.ServerName != request.DNSName {
		t.Fatalf("certificate scope mismatch: server=%#v client=%#v config=%#v", server, client, issued.ClientConfig)
	}
}

func TestEphemeralCertificateIssuerRejectsOverlongAndExpiredRequests(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 13, 7, 0, 0, 0, time.UTC)
	issuer := EphemeralCertificateIssuer{Clock: func() time.Time { return now }}
	for _, expiresAt := range []time.Time{now, now.Add(DefaultActiveDeadline + time.Second)} {
		if _, err := issuer.Issue(context.Background(), CertificateRequest{WorkerName: "worker", DNSName: "worker.lrail-build.svc", ExpiresAt: expiresAt}); err == nil {
			t.Fatalf("expected expiry rejection for %s", expiresAt)
		}
	}
}

func TestPolicyCertificateIssuerAddsAssignmentBoundEgressIdentity(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 13, 7, 0, 0, 0, time.UTC)
	caPEM, keyPEM := testEgressCA(t, now)
	egressCA, err := buildegress.NewCertificateAuthority(caPEM, keyPEM, caPEM, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewCertificateAuthority: %v", err)
	}
	policy, err := buildegress.NewPolicy(
		kubeBuildID, kubeOrgID, "build-fixture-a1", "sha256:bad", 1,
		now.Add(-time.Minute), now.Add(10*time.Minute), llbcompiler.DefinitionLock{}, nil,
	)
	if err == nil {
		t.Fatal("expected malformed payload digest rejection")
	}
	policy, err = buildegress.NewPolicy(
		kubeBuildID, kubeOrgID, "build-fixture-a1", kubePolicy, 1,
		now.Add(-time.Minute), now.Add(10*time.Minute), llbcompiler.DefinitionLock{}, nil,
	)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	loads := 0
	issued, err := (PolicyCertificateIssuer{
		Worker: EphemeralCertificateIssuer{Clock: func() time.Time { return now }},
		LoadEgress: func() (*buildegress.CertificateAuthority, error) {
			loads++
			return egressCA, nil
		},
	}).Issue(context.Background(), CertificateRequest{
		WorkerName: "build-fixture-a1", DNSName: "build-fixture-a1.lrail-build.svc", ExpiresAt: now.Add(10 * time.Minute), Egress: policy,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	block, _ := pem.Decode(issued.Material.EgressClientCert)
	if loads != 1 || block == nil || len(issued.Material.EgressClientKey) == 0 || len(issued.Material.EgressServerCA) == 0 || len(issued.Material.ServerCert) == 0 {
		t.Fatalf("combined certificate material is incomplete: %#v", issued.Material)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	parsed, err := buildegress.PolicyFromCertificate(certificate, now)
	if err != nil || parsed.BuildID != kubeBuildID || parsed.PayloadDigest != kubePolicy {
		t.Fatalf("parsed=%#v error=%v", parsed, err)
	}
}

func testEgressCA(t *testing.T, now time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "egress test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
