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

func TestParseS3PrefixRejectsAuthorityAndPathConfusion(t *testing.T) {
	t.Parallel()
	valid, err := parseS3Prefix("s3://lrail-build/cell-a/inputs")
	if err != nil || valid.bucket != "lrail-build" || valid.path != "cell-a/inputs" {
		t.Fatalf("parseS3Prefix valid: %#v err=%v", valid, err)
	}
	for _, value := range []string{
		"https://lrail-build/cell-a", "s3://access:secret@lrail-build/cell-a", "s3://lrail-build/cell-a/../other",
		"s3://lrail-build/cell-a?version=1", "s3://lrail-build", "s3:///cell-a", "s3://lrail-build/cell-a//input",
	} {
		if _, err := parseS3Prefix(value); err == nil {
			t.Fatalf("expected S3 prefix rejection for %q", value)
		}
	}
}

func TestS3TransportRequiresExplicitTrustAndTLS13(t *testing.T) {
	t.Parallel()
	if _, err := tlsTransport(filepath.Join(t.TempDir(), "missing-ca.pem"), true); err == nil {
		t.Fatal("expected secure S3 transport without a CA to fail")
	}
	certificate := testCertificate(t)
	transport, err := tlsTransport(certificate, true)
	if err != nil || transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS13 ||
		transport.DialContext == nil || transport.TLSHandshakeTimeout != 10*time.Second || transport.ResponseHeaderTimeout != 30*time.Second {
		t.Fatalf("secure transport=%#v error=%v", transport, err)
	}
	plain, err := tlsTransport("", false)
	if err != nil || plain.TLSClientConfig != nil {
		t.Fatalf("plain transport=%#v error=%v", plain, err)
	}
}

func testCertificate(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
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
	contents := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadStrictJSONRejectsUnknownAndTrailingData(t *testing.T) {
	t.Parallel()
	type config struct {
		Version int `json:"version"`
	}
	directory := t.TempDir()
	write := func(name, contents string) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		return path
	}
	var value config
	if err := loadStrictJSON(write("valid.json", `{"version":1}`), &value); err != nil || value.Version != 1 {
		t.Fatalf("load valid: value=%#v err=%v", value, err)
	}
	for name, contents := range map[string]string{
		"unknown.json":  `{"version":1,"secret":"forbidden"}`,
		"trailing.json": `{"version":1}{"version":2}`,
		"empty.json":    ``,
	} {
		if err := loadStrictJSON(write(name, contents), &config{}); err == nil {
			t.Fatalf("expected strict JSON rejection for %s", name)
		}
	}
}
