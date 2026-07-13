package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestS3HTTPTransportRequiresExplicitTrustAndTLS13(t *testing.T) {
	t.Parallel()
	if _, err := s3HTTPTransport(filepath.Join(t.TempDir(), "missing-ca.pem"), true); err == nil {
		t.Fatal("expected secure S3 transport without a CA to fail")
	}
	certificate := buildCellTestCertificate(t)
	transport, err := s3HTTPTransport(certificate, true)
	if err != nil || transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS13 ||
		transport.DialContext == nil || transport.TLSHandshakeTimeout != 10*time.Second || transport.ResponseHeaderTimeout != 30*time.Second {
		t.Fatalf("secure transport=%#v error=%v", transport, err)
	}
	plain, err := s3HTTPTransport("", false)
	if err != nil || plain.TLSClientConfig != nil {
		t.Fatalf("plain transport=%#v error=%v", plain, err)
	}
}

func buildCellTestCertificate(t *testing.T) string {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
