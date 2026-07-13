package buildworker

import (
	"strings"
	"testing"
)

func TestSanitizeProgressTextRemovesURLCredentials(t *testing.T) {
	t.Parallel()
	input := `failed Get "https://user:password@production.cloudfront.docker.com/registry/blob/data?Expires=123&Signature=secret#fragment": Forbidden`
	result := sanitizeProgressText(input)
	if !strings.Contains(result, "https://production.cloudfront.docker.com/registry/blob/data") {
		t.Fatalf("sanitized progress lost safe authority: %q", result)
	}
	for _, forbidden := range []string{"user", "password", "Expires", "Signature", "secret", "fragment", "?", "#"} {
		if strings.Contains(result, forbidden) {
			t.Fatalf("sanitized progress contains %q: %q", forbidden, result)
		}
	}
}
