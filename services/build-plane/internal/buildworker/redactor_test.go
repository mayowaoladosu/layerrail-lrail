package buildworker

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestRedactorMasksSplitAndEncodedSecretVariants(t *testing.T) {
	t.Parallel()
	secret := []byte("fake-test-secret/value")
	redactor := NewRedactor(map[string][]byte{"token": secret})
	if lines := redactor.Push("vertex:1", []byte("prefix fake-test-")); len(lines) != 0 {
		t.Fatalf("early lines = %#v", lines)
	}
	lines := redactor.Push("vertex:1", []byte("secret/value suffix\n"))
	if len(lines) != 1 || lines[0] != "prefix [REDACTED] suffix" {
		t.Fatalf("split redaction = %#v", lines)
	}
	variants := []string{
		base64.StdEncoding.EncodeToString(secret),
		base64.RawURLEncoding.EncodeToString(secret),
		hex.EncodeToString(secret),
		url.QueryEscape(string(secret)),
	}
	for _, variant := range variants {
		actual := redactor.RedactString("value=" + variant)
		if strings.Contains(actual, variant) || !strings.Contains(actual, "[REDACTED]") {
			t.Fatalf("variant leaked: %q", actual)
		}
	}
}

func TestRedactorMasksMultilineSecretAndFlushesStreams(t *testing.T) {
	t.Parallel()
	secret := []byte("-----BEGIN FAKE KEY-----\nfake-key-material\n-----END FAKE KEY-----")
	redactor := NewRedactor(map[string][]byte{"key": secret})
	input := append(append([]byte(nil), secret...), '\n')
	lines := redactor.Push("stdout", input)
	if len(lines) != 3 {
		t.Fatalf("lines = %#v", lines)
	}
	for _, line := range lines {
		if line != "[REDACTED]" {
			t.Fatalf("multiline secret leaked: %q", line)
		}
	}
	_ = redactor.Push("stderr", []byte("partial fake-key-material"))
	flushed := redactor.Flush()
	if got := flushed["stderr"]; len(got) != 1 || got[0] != "partial [REDACTED]" {
		t.Fatalf("flushed = %#v", flushed)
	}
}

func TestRedactorDropsOversizedLinesWithoutLeaking(t *testing.T) {
	t.Parallel()
	secret := []byte("fake-oversized-secret")
	redactor := NewRedactor(map[string][]byte{"token": secret})
	payload := bytes.Repeat([]byte("x"), MaxLogLineBytes+1)
	payload = append(payload, secret...)
	payload = append(payload, '\n')
	lines := redactor.Push("stdout", payload)
	if len(lines) != 1 || lines[0] != "[log line omitted: oversized]" {
		t.Fatalf("oversized line result = %#v", lines)
	}
	if flushed := redactor.Flush(); len(flushed) != 0 {
		t.Fatalf("oversized residue = %#v", flushed)
	}
}

func TestRedactorIsConcurrentSafe(t *testing.T) {
	t.Parallel()
	secret := []byte("fake-concurrent-secret")
	redactor := NewRedactor(map[string][]byte{"token": secret})
	var wait sync.WaitGroup
	for index := range 64 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			stream := string(rune('a' + index%8))
			for _, line := range redactor.Push(stream, append(append([]byte(nil), secret...), '\n')) {
				if strings.Contains(line, string(secret)) {
					t.Errorf("secret leaked: %q", line)
				}
			}
		}()
	}
	wait.Wait()
}

func TestRedactorCloseWipesOwnedSecretBuffers(t *testing.T) {
	t.Parallel()
	redactor := NewRedactor(map[string][]byte{"token": []byte("fake-owned-secret")})
	patterns := append([][]byte(nil), redactor.patterns...)
	_ = redactor.Push("stdout", []byte("partial fake-owned-"))
	buffer := redactor.buffers["stdout"].contents
	redactor.Close()
	if redactor.patterns != nil || redactor.buffers != nil {
		t.Fatalf("redactor retained state: %#v", redactor)
	}
	for _, pattern := range patterns {
		if !bytes.Equal(pattern, make([]byte, len(pattern))) {
			t.Fatal("redactor pattern was not wiped")
		}
	}
	if !bytes.Equal(buffer, make([]byte, len(buffer))) {
		t.Fatal("partial log buffer was not wiped")
	}
}
