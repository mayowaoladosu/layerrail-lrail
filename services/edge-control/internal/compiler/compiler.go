// Package compiler turns verified route intent into a canonical immutable edge
// generation with deterministic precedence and conflict rejection.
package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
	"golang.org/x/net/idna"
)

var ErrInvalid = errors.New("invalid edge generation")

type MatchKind string

const (
	MatchExact  MatchKind = "exact"
	MatchPrefix MatchKind = "prefix"
	MatchRegex  MatchKind = "regex"
)

type Intent struct {
	GenerationID       string
	CompilerVersion    string
	SchemaVersion      string
	PolicyDigest       string
	PreviousGeneration string
	CreatedAt          time.Time
	Routes             []RouteIntent
}

type RouteIntent struct {
	ID             string
	OrganizationID string
	Hostname       string
	Match          MatchKind
	Path           string
	Priority       int
	Targets        []Target
}

type Target struct {
	ReleaseID string `json:"release_id"`
	ClusterID string `json:"cluster_id"`
	Weight    uint32 `json:"weight"`
}

type Generation struct {
	GenerationID       string          `json:"generation_id"`
	CompilerVersion    string          `json:"compiler_version"`
	SchemaVersion      string          `json:"schema_version"`
	PolicyDigest       string          `json:"policy_digest"`
	PreviousGeneration string          `json:"previous_generation,omitempty"`
	CreatedAt          time.Time       `json:"created_at"`
	Routes             []CompiledRoute `json:"routes"`
	CanonicalDigest    string          `json:"canonical_digest"`
}

type CompiledRoute struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Hostname       string    `json:"hostname"`
	Wildcard       bool      `json:"wildcard"`
	Match          MatchKind `json:"match"`
	Path           string    `json:"path"`
	Priority       int       `json:"priority"`
	Targets        []Target  `json:"targets"`
}

func Compile(intent Intent) (Generation, error) {
	if err := validateIdentifier(intent.GenerationID, "edg"); err != nil {
		return Generation{}, err
	}
	if intent.PreviousGeneration != "" {
		if err := validateIdentifier(intent.PreviousGeneration, "edg"); err != nil {
			return Generation{}, err
		}
	}
	if intent.CompilerVersion == "" || intent.SchemaVersion == "" || !validDigest(intent.PolicyDigest) || intent.CreatedAt.IsZero() {
		return Generation{}, invalidf("generation metadata is incomplete")
	}
	if len(intent.Routes) == 0 || len(intent.Routes) > 100_000 {
		return Generation{}, invalidf("route count is outside policy")
	}

	routes := make([]CompiledRoute, 0, len(intent.Routes))
	exactOwners := make(map[string]string)
	wildcardOwners := make(map[string]string)
	directChildOwners := make(map[string]map[string]struct{})
	identities := make(map[string]struct{})
	for _, route := range intent.Routes {
		compiled, err := compileRoute(route)
		if err != nil {
			return Generation{}, err
		}
		if err := claimHostname(compiled, exactOwners, wildcardOwners, directChildOwners); err != nil {
			return Generation{}, err
		}
		identity := fmt.Sprintf("%s\x00%s\x00%s\x00%d", compiled.Hostname, compiled.Match, compiled.Path, compiled.Priority)
		if _, duplicate := identities[identity]; duplicate {
			return Generation{}, invalidf("duplicate or ambiguous route for %s%s", compiled.Hostname, compiled.Path)
		}
		identities[identity] = struct{}{}
		routes = append(routes, compiled)
	}

	slices.SortStableFunc(routes, compareRoutes)
	generation := Generation{
		GenerationID:       intent.GenerationID,
		CompilerVersion:    intent.CompilerVersion,
		SchemaVersion:      intent.SchemaVersion,
		PolicyDigest:       intent.PolicyDigest,
		PreviousGeneration: intent.PreviousGeneration,
		CreatedAt:          intent.CreatedAt.UTC(),
		Routes:             routes,
	}
	canonical, err := canonicaljson.Marshal(generation)
	if err != nil {
		return Generation{}, invalidf("canonicalization failed: %v", err)
	}
	digest := sha256.Sum256(canonical)
	generation.CanonicalDigest = "sha256:" + hex.EncodeToString(digest[:])
	return generation, nil
}

func compileRoute(route RouteIntent) (CompiledRoute, error) {
	if err := validateIdentifier(route.ID, "rte"); err != nil {
		return CompiledRoute{}, err
	}
	if err := validateIdentifier(route.OrganizationID, "org"); err != nil {
		return CompiledRoute{}, err
	}
	hostname, wildcard, err := normalizeHostname(route.Hostname)
	if err != nil {
		return CompiledRoute{}, err
	}
	if route.Match != MatchExact && route.Match != MatchPrefix && route.Match != MatchRegex {
		return CompiledRoute{}, invalidf("route %s has unknown match kind", route.ID)
	}
	if err := validatePath(route.Match, route.Path); err != nil {
		return CompiledRoute{}, invalidf("route %s: %v", route.ID, err)
	}
	if route.Match == MatchRegex && route.Priority == 0 {
		return CompiledRoute{}, invalidf("regex route %s requires explicit priority", route.ID)
	}
	if route.Match != MatchRegex && route.Priority != 0 {
		return CompiledRoute{}, invalidf("priority is reserved for regex routes")
	}
	if len(route.Targets) == 0 || len(route.Targets) > 32 {
		return CompiledRoute{}, invalidf("route %s target count is outside policy", route.ID)
	}
	weight := uint32(0)
	seenTargets := make(map[string]struct{}, len(route.Targets))
	targets := append([]Target(nil), route.Targets...)
	for _, target := range targets {
		if err := validateIdentifier(target.ReleaseID, "rel"); err != nil {
			return CompiledRoute{}, err
		}
		if target.ClusterID == "" || target.Weight == 0 {
			return CompiledRoute{}, invalidf("route %s has an incomplete target", route.ID)
		}
		if _, duplicate := seenTargets[target.ReleaseID]; duplicate {
			return CompiledRoute{}, invalidf("route %s repeats release %s", route.ID, target.ReleaseID)
		}
		seenTargets[target.ReleaseID] = struct{}{}
		weight += target.Weight
	}
	if weight != 100 {
		return CompiledRoute{}, invalidf("route %s target weights sum to %d, not 100", route.ID, weight)
	}
	slices.SortFunc(targets, func(first, second Target) int { return strings.Compare(first.ReleaseID, second.ReleaseID) })
	return CompiledRoute{
		ID: route.ID, OrganizationID: route.OrganizationID, Hostname: hostname, Wildcard: wildcard,
		Match: route.Match, Path: route.Path, Priority: route.Priority, Targets: targets,
	}, nil
}

func normalizeHostname(value string) (string, bool, error) {
	if value == "" || value != strings.TrimSpace(value) {
		return "", false, invalidf("hostname is empty or padded")
	}
	value = strings.TrimSuffix(strings.ToLower(value), ".")
	wildcard := strings.HasPrefix(value, "*.")
	if wildcard {
		if strings.Count(value, "*") != 1 {
			return "", false, invalidf("wildcard hostname is invalid")
		}
		value = strings.TrimPrefix(value, "*.")
	} else if strings.Contains(value, "*") {
		return "", false, invalidf("wildcard must be the complete leftmost label")
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil || ascii == "" || len(ascii) > 253 {
		return "", false, invalidf("hostname is invalid")
	}
	if _, err := netip.ParseAddr(ascii); err == nil || !strings.Contains(ascii, ".") {
		return "", false, invalidf("hostname must be a DNS name")
	}
	if wildcard {
		ascii = "*." + ascii
	}
	return ascii, wildcard, nil
}

func validatePath(kind MatchKind, value string) error {
	if value == "" || strings.Contains(value, "\\") || strings.ContainsAny(value, "\r\n\x00") {
		return invalidf("path is malformed")
	}
	lower := strings.ToLower(value)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%2e") {
		return invalidf("encoded slash, backslash, or dot is not allowed")
	}
	if kind == MatchRegex {
		if len(value) > 1024 {
			return invalidf("regex path exceeds limit")
		}
		if _, err := regexp.Compile(value); err != nil {
			return invalidf("regex path is invalid")
		}
		return nil
	}
	if !strings.HasPrefix(value, "/") {
		return invalidf("literal path must start with a slash")
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.Contains(value, "/../") || strings.HasSuffix(value, "/..") {
		return invalidf("path is not canonical")
	}
	return nil
}

func compareRoutes(first, second CompiledRoute) int {
	firstHostRank, secondHostRank := 0, 0
	if first.Wildcard {
		firstHostRank = 1
	}
	if second.Wildcard {
		secondHostRank = 1
	}
	if firstHostRank != secondHostRank {
		return firstHostRank - secondHostRank
	}
	if len(first.Hostname) != len(second.Hostname) {
		return len(second.Hostname) - len(first.Hostname)
	}
	if order := strings.Compare(first.Hostname, second.Hostname); order != 0 {
		return order
	}
	rank := func(kind MatchKind) int {
		switch kind {
		case MatchExact:
			return 0
		case MatchPrefix:
			return 1
		default:
			return 2
		}
	}
	if rank(first.Match) != rank(second.Match) {
		return rank(first.Match) - rank(second.Match)
	}
	if first.Match == MatchRegex && first.Priority != second.Priority {
		return second.Priority - first.Priority
	}
	if len(first.Path) != len(second.Path) {
		return len(second.Path) - len(first.Path)
	}
	return strings.Compare(first.ID, second.ID)
}

func validateIdentifier(value, prefix string) error {
	identifier, err := platformid.Parse(value)
	if err != nil || identifier.Prefix() != prefix {
		return invalidf("identifier %q must use %s prefix", value, prefix)
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func claimHostname(
	route CompiledRoute,
	exactOwners map[string]string,
	wildcardOwners map[string]string,
	directChildOwners map[string]map[string]struct{},
) error {
	if route.Wildcard {
		suffix := strings.TrimPrefix(route.Hostname, "*.")
		if owner, ok := wildcardOwners[suffix]; ok && owner != route.OrganizationID {
			return invalidf("hostname %s crosses organization ownership", route.Hostname)
		}
		for owner := range directChildOwners[suffix] {
			if owner != route.OrganizationID {
				return invalidf("wildcard %s overlaps another organization", route.Hostname)
			}
		}
		wildcardOwners[suffix] = route.OrganizationID
		return nil
	}
	if owner, ok := exactOwners[route.Hostname]; ok && owner != route.OrganizationID {
		return invalidf("hostname %s crosses organization ownership", route.Hostname)
	}
	if _, suffix, ok := strings.Cut(route.Hostname, "."); ok {
		if owner, exists := wildcardOwners[suffix]; exists && owner != route.OrganizationID {
			return invalidf("hostname %s overlaps another organization's wildcard", route.Hostname)
		}
		if directChildOwners[suffix] == nil {
			directChildOwners[suffix] = make(map[string]struct{})
		}
		directChildOwners[suffix][route.OrganizationID] = struct{}{}
	}
	exactOwners[route.Hostname] = route.OrganizationID
	return nil
}

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
