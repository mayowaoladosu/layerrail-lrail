package sourcearchive

import (
	"errors"
	"strings"
	"testing"
)

func TestSecretScannerFindsMarkerAcrossWriteBoundaries(t *testing.T) {
	t.Parallel()
	scanner := &secretScanner{path: "split.txt"}
	if _, err := scanner.Write([]byte("prefix -----BEGIN OPEN")); err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.Write([]byte("SSH PRIVATE KEY----- suffix")); !errors.Is(err, ErrSecretMaterial) {
		t.Fatalf("scanner error = %v", err)
	}
}

func TestSecretScannerFindsLrailAPIKeyAcrossWriteBoundaries(t *testing.T) {
	t.Parallel()
	scanner := &secretScanner{path: "credentials.txt"}
	if _, err := scanner.Write([]byte("prefix lrail_key_" + strings.Repeat("A", 12))); err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.Write([]byte("_" + strings.Repeat("b", 43) + " suffix")); !errors.Is(err, ErrSecretMaterial) {
		t.Fatalf("scanner error = %v", err)
	}
}

func TestSecretPathAllowsExamples(t *testing.T) {
	t.Parallel()
	if secretPath("config/.env.example") {
		t.Fatal(".env.example should be allowed")
	}
	if !secretPath("config/.env.local") {
		t.Fatal(".env.local should be blocked")
	}
}
