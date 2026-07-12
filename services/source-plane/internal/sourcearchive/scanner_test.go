package sourcearchive

import (
	"errors"
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

func TestSecretPathAllowsExamples(t *testing.T) {
	t.Parallel()
	if secretPath("config/.env.example") {
		t.Fatal(".env.example should be allowed")
	}
	if !secretPath("config/.env.local") {
		t.Fatal(".env.local should be blocked")
	}
}
