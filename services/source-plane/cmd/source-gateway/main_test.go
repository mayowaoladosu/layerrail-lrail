package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func TestLoadConfigValidatesTLSAndPrivateKey(t *testing.T) {
	setValidEnvironment(t)
	config, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !config.internalTLS || !config.publicTLS || config.region != "us-east-1" {
		t.Fatalf("unexpected config: %#v", config)
	}

	t.Setenv("LRAIL_SOURCE_S3_PUBLIC_TLS", "typo")
	if _, err := loadConfig(); err == nil {
		t.Fatal("expected invalid TLS flag rejection")
	}
}

func TestLoadConfigRejectsInconsistentEd25519PrivateKey(t *testing.T) {
	setValidEnvironment(t)
	invalid := make([]byte, ed25519.PrivateKeySize)
	for index := range invalid {
		invalid[index] = byte(index + 1)
	}
	t.Setenv("LRAIL_SOURCE_SIGNING_PRIVATE_KEY", base64.RawURLEncoding.EncodeToString(invalid))
	if _, err := loadConfig(); err == nil {
		t.Fatal("expected invalid private key rejection")
	}
}

func TestVerifyScratchRequiresWritableDirectory(t *testing.T) {
	if err := verifyScratch(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := verifyScratch(""); err == nil {
		t.Fatal("expected missing scratch directory rejection")
	}
}

func setValidEnvironment(t *testing.T) {
	t.Helper()
	seed := []byte(strings.Repeat("s", ed25519.SeedSize))
	privateKey := ed25519.NewKeyFromSeed(seed)
	t.Setenv("LRAIL_SOURCE_GRANT_KEY", base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("g", 32))))
	t.Setenv("LRAIL_SOURCE_SIGNING_PRIVATE_KEY", base64.RawURLEncoding.EncodeToString(privateKey))
	t.Setenv("LRAIL_SOURCE_S3_INTERNAL_ENDPOINT", "minio:9000")
	t.Setenv("LRAIL_SOURCE_S3_PUBLIC_ENDPOINT", "objects.example.test")
	t.Setenv("LRAIL_SOURCE_S3_INTERNAL_TLS", "true")
	t.Setenv("LRAIL_SOURCE_S3_PUBLIC_TLS", "true")
	t.Setenv("LRAIL_SOURCE_S3_ACCESS_KEY", "access")
	t.Setenv("LRAIL_SOURCE_S3_SECRET_KEY", "secret")
	t.Setenv("LRAIL_SOURCE_S3_BUCKET", "source")
	t.Setenv("LRAIL_SOURCE_SCRATCH_DIR", t.TempDir())
	t.Setenv("LRAIL_SOURCE_SIGNING_KEY_ID", "test")
	t.Setenv("LRAIL_SOURCE_MAX_FINALIZERS", "2")
}
