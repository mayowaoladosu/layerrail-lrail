package netpolicy

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

type fakeResolver struct {
	answers map[string][]net.IP
	err     error
}

func (resolver fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]net.IP, error) {
	if resolver.err != nil {
		return nil, resolver.err
	}
	return resolver.answers[host], nil
}

func TestValidateNormalizesAndPinsPublicAddresses(t *testing.T) {
	t.Parallel()
	resolver := fakeResolver{answers: map[string][]net.IP{
		"xn--bcher-kva.test": {
			net.ParseIP("93.184.216.34"),
			net.ParseIP("1.1.1.1"),
			net.ParseIP("93.184.216.34"),
		},
	}}
	decision, err := DefaultPolicy(resolver).Validate(context.Background(), "https://BÜCHER.test./hooks?q=1")
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if decision.Host != "xn--bcher-kva.test" || decision.URL.String() != "https://xn--bcher-kva.test/hooks?q=1" {
		t.Fatalf("unexpected normalization: host=%q url=%q", decision.Host, decision.URL)
	}
	if len(decision.Addresses) != 2 || decision.Addresses[0].String() != "1.1.1.1" {
		t.Fatalf("unexpected pinned addresses: %v", decision.Addresses)
	}
	dial, err := decision.DialAddress(1)
	if err != nil || dial != "93.184.216.34:443" {
		t.Fatalf("DialAddress = %q, %v", dial, err)
	}
}

func TestValidateRejectsSSRFAndMalformedDestinations(t *testing.T) {
	t.Parallel()
	blocked := []string{
		"127.0.0.1",
		"10.0.0.1",
		"169.254.169.254",
		"100.64.0.1",
		"192.0.2.1",
		"224.0.0.1",
		"::1",
		"fc00::1",
		"2001:db8::1",
	}
	for _, address := range blocked {
		address := address
		t.Run(strings.ReplaceAll(address, ":", "_"), func(t *testing.T) {
			t.Parallel()
			resolver := fakeResolver{answers: map[string][]net.IP{"blocked.test": {net.ParseIP(address)}}}
			_, err := DefaultPolicy(resolver).Validate(context.Background(), "https://blocked.test/hook")
			if !errors.Is(err, ErrDenied) {
				t.Fatalf("Validate error = %v", err)
			}
		})
	}

	resolver := fakeResolver{answers: map[string][]net.IP{"public.test": {net.ParseIP("1.1.1.1")}}}
	policy := DefaultPolicy(resolver)
	for _, target := range []string{
		"http://public.test/hook",
		"https://user:pass@public.test/hook",
		"https://public.test:8443/hook",
		"https://public.test/hook#fragment",
		"not a url",
	} {
		if _, err := policy.Validate(context.Background(), target); !errors.Is(err, ErrDenied) {
			t.Fatalf("Validate(%q) error = %v", target, err)
		}
	}
}

func TestValidateRejectsMixedPublicAndPrivateDNSAnswers(t *testing.T) {
	t.Parallel()
	resolver := fakeResolver{answers: map[string][]net.IP{
		"rebind.test": {net.ParseIP("1.1.1.1"), net.ParseIP("10.0.0.2")},
	}}
	if _, err := DefaultPolicy(resolver).Validate(context.Background(), "https://rebind.test"); !errors.Is(err, ErrDenied) {
		t.Fatalf("Validate error = %v", err)
	}
}

func TestValidateSupportsExplicitHTTPPolicy(t *testing.T) {
	t.Parallel()
	resolver := fakeResolver{answers: map[string][]net.IP{"public.test": {net.ParseIP("1.1.1.1")}}}
	policy := DefaultPolicy(resolver)
	policy.AllowHTTP = true
	policy.AllowedPorts = []uint16{80, 443, 8443}
	decision, err := policy.Validate(context.Background(), "http://public.test/path")
	if err != nil || decision.Port != 80 {
		t.Fatalf("Validate = %+v, %v", decision, err)
	}
	decision, err = policy.Validate(context.Background(), "https://public.test:8443/path")
	if err != nil || decision.Port != 8443 {
		t.Fatalf("Validate custom port = %+v, %v", decision, err)
	}
}

func TestValidateRejectsResolverAndDecisionErrors(t *testing.T) {
	t.Parallel()
	policy := DefaultPolicy(fakeResolver{err: errors.New("offline")})
	if _, err := policy.Validate(context.Background(), "https://offline.test"); !errors.Is(err, ErrDenied) {
		t.Fatalf("resolver error = %v", err)
	}
	if _, err := (Policy{}).Validate(context.Background(), "https://public.test"); !errors.Is(err, ErrDenied) {
		t.Fatalf("missing resolver error = %v", err)
	}
	if _, err := DefaultPolicy(fakeResolver{}).Validate(nil, "https://public.test"); !errors.Is(err, ErrDenied) {
		t.Fatalf("nil context error = %v", err)
	}
	decision := Decision{}
	if _, err := decision.DialAddress(0); !errors.Is(err, ErrDenied) {
		t.Fatalf("DialAddress error = %v", err)
	}
}
