package sourcearchive

import (
	"bytes"
	"regexp"
	"strings"
)

var blockedContentMarkers = [][]byte{
	[]byte("-----BEGIN PRIVATE KEY-----"),
	[]byte("-----BEGIN RSA PRIVATE KEY-----"),
	[]byte("-----BEGIN EC PRIVATE KEY-----"),
	[]byte("-----BEGIN OPENSSH PRIVATE KEY-----"),
	[]byte("github_pat_"),
	[]byte("ghp_"),
}

var blockedContentPatterns = []*regexp.Regexp{
	regexp.MustCompile(`lrail_key_[A-Za-z0-9]{12}_[A-Za-z0-9_-]{43}`),
}

type secretScanner struct {
	path string
	tail []byte
}

func (s *secretScanner) Write(chunk []byte) (int, error) {
	combined := make([]byte, 0, len(s.tail)+len(chunk))
	combined = append(combined, s.tail...)
	combined = append(combined, chunk...)
	for _, marker := range blockedContentMarkers {
		if bytes.Contains(combined, marker) {
			return 0, &ValidationError{Kind: ErrSecretMaterial, Path: s.path, Info: "blocked credential marker"}
		}
	}
	for _, pattern := range blockedContentPatterns {
		if pattern.Match(combined) {
			return 0, &ValidationError{Kind: ErrSecretMaterial, Path: s.path, Info: "blocked credential marker"}
		}
	}

	const overlap = 128
	if len(combined) > overlap {
		s.tail = append(s.tail[:0], combined[len(combined)-overlap:]...)
	} else {
		s.tail = append(s.tail[:0], combined...)
	}
	return len(chunk), nil
}

func secretPath(path string) bool {
	parts := strings.Split(strings.ToLower(path), "/")
	for _, part := range parts {
		if part == ".git" || part == ".ssh" || part == "id_rsa" || part == "id_ed25519" {
			return true
		}
		if part == ".env" || (strings.HasPrefix(part, ".env.") && !strings.HasSuffix(part, ".example")) {
			return true
		}
	}
	return false
}
