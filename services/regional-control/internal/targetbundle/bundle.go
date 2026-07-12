// Package targetbundle verifies signed, complete, monotonic desired-state
// generations before any regional resource mutation.
package targetbundle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sync"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
)

const (
	APIVersion     = "regional.lrail.dev/v1"
	MaxBundleBytes = 2 * 1024 * 1024
	MaxValidity    = 24 * time.Hour
	ClockSkew      = 5 * time.Minute
)

var (
	ErrRejected           = errors.New("TargetBundle rejected")
	ErrGenerationConflict = errors.New("TargetBundle generation conflict")
	digestRegexp          = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type Bundle struct {
	APIVersion         string          `json:"api_version"`
	BundleID           string          `json:"bundle_id"`
	CellID             string          `json:"cell_id"`
	OrganizationID     string          `json:"organization_id"`
	ProjectID          string          `json:"project_id"`
	EnvironmentID      string          `json:"environment_id"`
	Generation         uint64          `json:"generation"`
	PreviousGeneration *uint64         `json:"previous_generation"`
	IssuedAt           time.Time       `json:"issued_at"`
	ExpiresAt          time.Time       `json:"expires_at"`
	PolicyDigest       string          `json:"policy_digest"`
	Services           []Service       `json:"services"`
	Routes             []Route         `json:"routes"`
	SecretRefs         []VersionedRef  `json:"secret_refs"`
	Volumes            []GenerationRef `json:"volumes"`
	AddonBindings      []GenerationRef `json:"addon_bindings"`
	Schedules          []GenerationRef `json:"schedules"`
	Artifacts          []Artifact      `json:"artifacts"`
	Signature          Signature       `json:"signature"`
}

type Service struct {
	ID             string    `json:"id"`
	RevisionDigest string    `json:"revision_digest"`
	ConfigDigest   string    `json:"config_digest"`
	Processes      []Process `json:"processes"`
}

type Process struct {
	Name         string    `json:"name"`
	Kind         string    `json:"kind"`
	Command      []string  `json:"command"`
	Port         *uint16   `json:"port"`
	RuntimeClass string    `json:"runtime_class"`
	Resources    Resources `json:"resources"`
	Replicas     Replicas  `json:"replicas"`
}

type Resources struct {
	CPUMillis             uint64 `json:"cpu_millis"`
	MemoryBytes           uint64 `json:"memory_bytes"`
	EphemeralStorageBytes uint64 `json:"ephemeral_storage_bytes"`
}

type Replicas struct {
	Minimum uint32 `json:"minimum"`
	Maximum uint32 `json:"maximum"`
}

type Route struct {
	ID         string `json:"id"`
	ServiceID  string `json:"service_id"`
	Hostname   string `json:"hostname"`
	PathPrefix string `json:"path_prefix"`
	Protocol   string `json:"protocol"`
}

type VersionedRef struct {
	ID      string `json:"id"`
	Version uint64 `json:"version"`
}

type GenerationRef struct {
	ID         string `json:"id"`
	Generation uint64 `json:"generation"`
}

type Artifact struct {
	Digest        string `json:"digest"`
	Platform      string `json:"platform"`
	SignatureRef  string `json:"signature_ref"`
	ProvenanceRef string `json:"provenance_ref"`
	SBOMRef       string `json:"sbom_ref"`
	PolicyRef     string `json:"policy_ref"`
}

type Signature struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"value,omitempty"`
}

type Store interface {
	CompareAndPut(
		ctx context.Context,
		cellID string,
		environmentID string,
		previousGeneration *uint64,
		generation uint64,
		digest string,
	) (replay bool, err error)
}

type Validator struct {
	CellID string
	Keys   map[string]ed25519.PublicKey
	Store  Store
	Now    func() time.Time
}

type Accepted struct {
	Bundle Bundle
	Digest string
	Replay bool
}

func Sign(bundle *Bundle, keyID string, privateKey ed25519.PrivateKey) error {
	if bundle == nil || len(privateKey) != ed25519.PrivateKeySize || keyID == "" {
		return rejectedf("signing input is invalid")
	}
	bundle.Signature = Signature{KeyID: keyID, Algorithm: "ed25519"}
	payload, err := signingBytes(*bundle)
	if err != nil {
		return err
	}
	bundle.Signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return nil
}

func (validator Validator) Accept(ctx context.Context, raw []byte) (Accepted, error) {
	if ctx == nil || validator.Store == nil || validator.Now == nil || validator.CellID == "" {
		return Accepted{}, rejectedf("validator dependencies are incomplete")
	}
	if len(raw) == 0 || len(raw) > MaxBundleBytes {
		return Accepted{}, rejectedf("bundle size is outside policy")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var bundle Bundle
	if err := decoder.Decode(&bundle); err != nil {
		return Accepted{}, rejectedf("bundle JSON is invalid: %v", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Accepted{}, rejectedf("bundle contains trailing JSON")
	}
	if err := validator.validate(bundle); err != nil {
		return Accepted{}, err
	}
	fullCanonical, err := canonicaljson.Marshal(bundle)
	if err != nil {
		return Accepted{}, rejectedf("bundle canonicalization failed: %v", err)
	}
	hash := sha256.Sum256(fullCanonical)
	digest := "sha256:" + hex.EncodeToString(hash[:])
	replay, err := validator.Store.CompareAndPut(
		ctx,
		bundle.CellID,
		bundle.EnvironmentID,
		bundle.PreviousGeneration,
		bundle.Generation,
		digest,
	)
	if err != nil {
		return Accepted{}, rejectedf("persist generation: %v", err)
	}
	return Accepted{Bundle: bundle, Digest: digest, Replay: replay}, nil
}

func (validator Validator) validate(bundle Bundle) error {
	if bundle.APIVersion != APIVersion {
		return rejectedf("unsupported api_version %q", bundle.APIVersion)
	}
	if bundle.CellID != validator.CellID {
		return rejectedf("bundle audience does not match this cell")
	}
	for value, prefix := range map[string]string{
		bundle.BundleID:       "tgt",
		bundle.CellID:         "cell",
		bundle.OrganizationID: "org",
		bundle.ProjectID:      "prj",
		bundle.EnvironmentID:  "env",
	} {
		identifier, err := platformid.Parse(value)
		if err != nil || identifier.Prefix() != prefix {
			return rejectedf("resource identifier %q does not have prefix %s", value, prefix)
		}
	}
	now := validator.Now().UTC()
	if bundle.IssuedAt.After(now.Add(ClockSkew)) || !bundle.ExpiresAt.After(now) {
		return rejectedf("bundle is not currently valid")
	}
	if !bundle.ExpiresAt.After(bundle.IssuedAt) || bundle.ExpiresAt.Sub(bundle.IssuedAt) > MaxValidity {
		return rejectedf("bundle validity window is outside policy")
	}
	if !digestRegexp.MatchString(bundle.PolicyDigest) {
		return rejectedf("policy digest is invalid")
	}
	if len(bundle.Services) == 0 || len(bundle.Artifacts) == 0 {
		return rejectedf("bundle must contain services and artifacts")
	}
	artifacts := make(map[string]struct{}, len(bundle.Artifacts))
	for _, artifact := range bundle.Artifacts {
		if !digestRegexp.MatchString(artifact.Digest) || artifact.SignatureRef == "" ||
			artifact.ProvenanceRef == "" || artifact.SBOMRef == "" || artifact.PolicyRef == "" {
			return rejectedf("artifact evidence is incomplete")
		}
		artifacts[artifact.Digest] = struct{}{}
	}
	services := make(map[string]struct{}, len(bundle.Services))
	for _, service := range bundle.Services {
		identifier, err := platformid.Parse(service.ID)
		if err != nil || identifier.Prefix() != "svc" || !digestRegexp.MatchString(service.ConfigDigest) {
			return rejectedf("service identity or configuration digest is invalid")
		}
		if _, ok := artifacts[service.RevisionDigest]; !ok {
			return rejectedf("service revision does not have a supplied artifact")
		}
		if len(service.Processes) == 0 {
			return rejectedf("service %s has no process groups", service.ID)
		}
		for _, process := range service.Processes {
			if process.Name == "" || process.Resources.CPUMillis == 0 || process.Resources.MemoryBytes < 32*1024*1024 || process.Replicas.Maximum < process.Replicas.Minimum || process.Replicas.Maximum == 0 {
				return rejectedf("service %s has an invalid process envelope", service.ID)
			}
			if (process.Kind == "web" || process.Kind == "private_service") && process.Port == nil {
				return rejectedf("network process %s requires a port", process.Name)
			}
		}
		services[service.ID] = struct{}{}
	}
	for _, route := range bundle.Routes {
		identifier, err := platformid.Parse(route.ID)
		if err != nil || identifier.Prefix() != "rte" || route.Hostname == "" || route.PathPrefix == "" {
			return rejectedf("route identity or match is invalid")
		}
		if _, ok := services[route.ServiceID]; !ok {
			return rejectedf("route references an unknown service")
		}
	}
	for _, secret := range bundle.SecretRefs {
		identifier, err := platformid.Parse(secret.ID)
		if err != nil || identifier.Prefix() != "sec" || secret.Version == 0 {
			return rejectedf("secret reference is invalid")
		}
	}
	if err := validateGenerationRefs(bundle.Volumes, "vol"); err != nil {
		return err
	}
	if err := validateGenerationRefs(bundle.AddonBindings, "add"); err != nil {
		return err
	}
	if err := validateGenerationRefs(bundle.Schedules, "sch"); err != nil {
		return err
	}
	key, ok := validator.Keys[bundle.Signature.KeyID]
	if !ok || bundle.Signature.Algorithm != "ed25519" || len(key) != ed25519.PublicKeySize {
		return rejectedf("signature identity is not trusted")
	}
	signature, err := base64.StdEncoding.DecodeString(bundle.Signature.Value)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return rejectedf("signature encoding is invalid")
	}
	payload, err := signingBytes(bundle)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, payload, signature) {
		return rejectedf("signature verification failed")
	}
	return nil
}

func validateGenerationRefs(references []GenerationRef, prefix string) error {
	for _, reference := range references {
		identifier, err := platformid.Parse(reference.ID)
		if err != nil || identifier.Prefix() != prefix || reference.Generation == 0 {
			return rejectedf("%s generation reference is invalid", prefix)
		}
	}
	return nil
}

func signingBytes(bundle Bundle) ([]byte, error) {
	bundle.Signature.Value = ""
	payload, err := canonicaljson.Marshal(bundle)
	if err != nil {
		return nil, rejectedf("signing payload canonicalization failed: %v", err)
	}
	return payload, nil
}

type MemoryStore struct {
	mu      sync.Mutex
	records map[string]generationRecord
}

type generationRecord struct {
	generation uint64
	digest     string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[string]generationRecord)}
}

func (store *MemoryStore) CompareAndPut(
	ctx context.Context,
	cellID string,
	environmentID string,
	previousGeneration *uint64,
	generation uint64,
	digest string,
) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := cellID + "/" + environmentID
	record, found := store.records[key]
	if found && record.generation == generation && record.digest == digest {
		return true, nil
	}
	if !found {
		if generation != 1 || previousGeneration != nil {
			return false, fmt.Errorf("%w: first generation must be 1 without predecessor", ErrGenerationConflict)
		}
	} else {
		if previousGeneration == nil || *previousGeneration != record.generation {
			return false, fmt.Errorf("%w: predecessor does not match %d", ErrGenerationConflict, record.generation)
		}
		if generation <= record.generation {
			return false, fmt.Errorf("%w: generation %d is not newer than %d", ErrGenerationConflict, generation, record.generation)
		}
	}
	store.records[key] = generationRecord{generation: generation, digest: digest}
	return false, nil
}

func rejectedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRejected, fmt.Sprintf(format, args...))
}
