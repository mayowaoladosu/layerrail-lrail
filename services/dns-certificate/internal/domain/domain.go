// Package domain canonicalizes customer hostnames and manages single-use
// ownership challenges without storing challenge plaintext.
package domain

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

const challengeBytes = 32

var ErrInvalid = errors.New("invalid domain ownership input")

type CanonicalName struct {
	ASCII    string
	Wildcard bool
	Base     string
}

func Canonicalize(value string, allowWildcard bool) (CanonicalName, error) {
	if value == "" || value != strings.TrimSpace(value) {
		return CanonicalName{}, invalidf("hostname is empty or padded")
	}
	value = strings.TrimSuffix(strings.ToLower(value), ".")
	wildcard := strings.HasPrefix(value, "*.")
	if wildcard {
		if !allowWildcard || strings.Count(value, "*") != 1 {
			return CanonicalName{}, invalidf("wildcard is not allowed")
		}
		value = strings.TrimPrefix(value, "*.")
	} else if strings.Contains(value, "*") {
		return CanonicalName{}, invalidf("wildcard must be the complete leftmost label")
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil || ascii == "" || len(ascii) > 253 {
		return CanonicalName{}, invalidf("hostname is not valid IDNA")
	}
	if _, err := netip.ParseAddr(ascii); err == nil {
		return CanonicalName{}, invalidf("IP literals cannot be owned as domains")
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return CanonicalName{}, invalidf("hostname must have a registrable parent")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return CanonicalName{}, invalidf("hostname contains an invalid label")
		}
	}
	suffix, _ := publicsuffix.PublicSuffix(ascii)
	if suffix == ascii {
		return CanonicalName{}, invalidf("public suffix cannot be claimed")
	}
	registrable, err := publicsuffix.EffectiveTLDPlusOne(ascii)
	if err != nil {
		return CanonicalName{}, invalidf("hostname is not registrable")
	}
	canonical := ascii
	if wildcard {
		canonical = "*." + ascii
	}
	return CanonicalName{ASCII: canonical, Wildcard: wildcard, Base: registrable}, nil
}

type Challenge struct {
	OrganizationID platformid.ID
	Domain         string
	RecordName     string
	Verifier       [sha256.Size]byte
	ExpiresAt      time.Time
	ConsumedAt     *time.Time
}

func NewChallenge(organizationID platformid.ID, domainName CanonicalName, now time.Time, ttl time.Duration, randomness io.Reader, hmacKey []byte) (Challenge, string, error) {
	parsed, err := platformid.Parse(string(organizationID))
	if err != nil || parsed.Prefix() != "org" {
		return Challenge{}, "", invalidf("organization ID is invalid")
	}
	if ttl <= 0 || ttl > 24*time.Hour {
		return Challenge{}, "", invalidf("challenge TTL is outside policy")
	}
	if randomness == nil || len(hmacKey) < 32 {
		return Challenge{}, "", invalidf("challenge entropy or HMAC key is insufficient")
	}
	raw := make([]byte, challengeBytes)
	if _, err := io.ReadFull(randomness, raw); err != nil {
		return Challenge{}, "", fmt.Errorf("generate ownership challenge: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	verifier := challengeVerifier(hmacKey, parsed, domainName.ASCII, token)
	base := strings.TrimPrefix(domainName.ASCII, "*.")
	return Challenge{
		OrganizationID: parsed,
		Domain:         domainName.ASCII,
		RecordName:     "_lrail-challenge." + base,
		Verifier:       verifier,
		ExpiresAt:      now.UTC().Add(ttl),
	}, token, nil
}

func (challenge *Challenge) Verify(presented string, now time.Time, hmacKey []byte) error {
	if challenge == nil {
		return invalidf("challenge is nil")
	}
	if len(hmacKey) < 32 {
		return invalidf("challenge HMAC key is insufficient")
	}
	if challenge.ConsumedAt != nil {
		return invalidf("challenge was already consumed")
	}
	if !now.UTC().Before(challenge.ExpiresAt) {
		return invalidf("challenge expired")
	}
	candidate := challengeVerifier(hmacKey, challenge.OrganizationID, challenge.Domain, presented)
	if !hmac.Equal(candidate[:], challenge.Verifier[:]) {
		return invalidf("challenge proof does not match")
	}
	consumed := now.UTC()
	challenge.ConsumedAt = &consumed
	return nil
}

func challengeVerifier(key []byte, organizationID platformid.ID, domainName, token string) [sha256.Size]byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(string(organizationID)))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(domainName))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(token))
	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
