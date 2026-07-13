// Package buildcell verifies signed build assignments and owns their isolated lifecycle.
package buildcell

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildir"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/solver/pb"
	"google.golang.org/protobuf/proto"
)

const (
	CurrentAssignmentVersion = 1
	DefaultMaxAssignmentTTL  = time.Hour
	DefaultMaxFutureSkew     = 30 * time.Second
	MaxDefinitionBytes       = 16 << 20
	MaxConfigBytes           = 1 << 20
)

var (
	ErrAssignment         = errors.New("invalid build assignment")
	digestPattern         = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	noncePattern          = regexp.MustCompile(`^[0-9a-f]{64}$`)
	keyIDPattern          = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
	outputNamePattern     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	capabilityNamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
	nodeIDPattern         = regexp.MustCompile(`^n[1-9][0-9]{0,3}$`)
	semanticVersion       = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	argumentNamePattern   = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
	hostnamePattern       = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)
	cacheNamespacePattern = regexp.MustCompile(`^lrail-cache-[0-9a-f]{64}$`)
	objectReference       = regexp.MustCompile(`^s3://[a-z0-9][a-z0-9.-]{2,62}/[A-Za-z0-9._/-]+$`)
)

type Payload struct {
	Version          int                        `json:"version"`
	BuildID          string                     `json:"build_id"`
	CellID           string                     `json:"cell_id"`
	OrganizationID   string                     `json:"organization_id"`
	ProjectID        string                     `json:"project_id"`
	OperationID      string                     `json:"operation_id"`
	Generation       uint64                     `json:"generation"`
	Nonce            string                     `json:"nonce"`
	IssuedAt         string                     `json:"issued_at"`
	ExpiresAt        string                     `json:"expires_at"`
	DefinitionDigest string                     `json:"definition_digest"`
	Lock             llbcompiler.DefinitionLock `json:"lock"`
	Source           SourceArtifact             `json:"source"`
	Outputs          []OutputArtifact           `json:"outputs"`
}

type SourceArtifact struct {
	SnapshotDigest string `json:"snapshot_digest"`
	ArchiveDigest  string `json:"archive_digest"`
	ArchiveRef     string `json:"archive_ref"`
	SizeBytes      int64  `json:"size_bytes"`
}

type OutputArtifact struct {
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	LLBDigest    string `json:"llb_digest"`
	Head         string `json:"head"`
	LLBRef       string `json:"llb_ref"`
	ConfigDigest string `json:"config_digest"`
	ConfigRef    string `json:"config_ref"`
}

type Envelope struct {
	KeyID     string  `json:"key_id"`
	Payload   Payload `json:"payload"`
	Signature string  `json:"signature"`
}

type VerifiedAssignment struct {
	Payload       Payload
	PayloadDigest string
	KeyID         string
	verified      bool
}

type VerifierOptions struct {
	CellID        string
	Keys          map[string]ed25519.PublicKey
	ObjectPrefix  string
	Clock         func() time.Time
	MaxTTL        time.Duration
	MaxFutureSkew time.Duration
}

type Verifier struct {
	cellID        string
	keys          map[string]ed25519.PublicKey
	objectPrefix  string
	clock         func() time.Time
	maxTTL        time.Duration
	maxFutureSkew time.Duration
}

type ArtifactStore interface {
	Open(ctx context.Context, reference string, maxBytes int64) (io.ReadCloser, error)
}

type ResolvedOutput struct {
	Name       string
	Kind       string
	Definition []byte
	Config     []byte
}

type ResolvedAssignment struct {
	Verified VerifiedAssignment
	Outputs  []ResolvedOutput
	resolved bool
}

func NewVerifier(options VerifierOptions) (*Verifier, error) {
	if err := validateID(options.CellID, "cell"); err != nil {
		return nil, err
	}
	if len(options.Keys) == 0 || len(options.Keys) > 16 {
		return nil, assignmentError("assignment.key_set", "Verifier requires a bounded public key set.")
	}
	keys := make(map[string]ed25519.PublicKey, len(options.Keys))
	for keyID, key := range options.Keys {
		if !keyIDPattern.MatchString(keyID) || len(key) != ed25519.PublicKeySize {
			return nil, assignmentError("assignment.key_set", "Verifier key identity or public key is invalid.")
		}
		keys[keyID] = append(ed25519.PublicKey(nil), key...)
	}
	if !strings.HasSuffix(options.ObjectPrefix, "/") || !objectReference.MatchString(options.ObjectPrefix+"probe") {
		return nil, assignmentError("assignment.object_prefix", "Verifier object prefix is invalid.")
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.MaxTTL == 0 {
		options.MaxTTL = DefaultMaxAssignmentTTL
	}
	if options.MaxFutureSkew == 0 {
		options.MaxFutureSkew = DefaultMaxFutureSkew
	}
	if options.MaxTTL <= 0 || options.MaxTTL > DefaultMaxAssignmentTTL || options.MaxFutureSkew < 0 || options.MaxFutureSkew > time.Minute {
		return nil, assignmentError("assignment.time_policy", "Verifier time policy is outside safety bounds.")
	}
	return &Verifier{
		cellID:        options.CellID,
		keys:          keys,
		objectPrefix:  options.ObjectPrefix,
		clock:         options.Clock,
		maxTTL:        options.MaxTTL,
		maxFutureSkew: options.MaxFutureSkew,
	}, nil
}

func Sign(payload Payload, keyID string, privateKey ed25519.PrivateKey) (Envelope, error) {
	if !keyIDPattern.MatchString(keyID) || len(privateKey) != ed25519.PrivateKeySize {
		return Envelope{}, assignmentError("assignment.signing_key", "Signing key identity or private key is invalid.")
	}
	canonical, err := canonicaljson.Marshal(payload)
	if err != nil {
		return Envelope{}, fmt.Errorf("canonicalize assignment: %w", err)
	}
	signature := ed25519.Sign(privateKey, canonical)
	return Envelope{
		KeyID:     keyID,
		Payload:   payload,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}, nil
}

func (verifier *Verifier) Verify(envelope Envelope) (VerifiedAssignment, error) {
	key, exists := verifier.keys[envelope.KeyID]
	if !exists {
		return VerifiedAssignment{}, assignmentError("assignment.key_unknown", "Assignment signing key is not accepted by this cell.")
	}
	canonical, err := canonicaljson.Marshal(envelope.Payload)
	if err != nil {
		return VerifiedAssignment{}, assignmentError("assignment.canonical", "Assignment payload cannot be canonicalized.")
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, canonical, signature) {
		return VerifiedAssignment{}, assignmentError("assignment.signature", "Assignment signature is invalid.")
	}
	if err := verifier.validatePayload(envelope.Payload); err != nil {
		return VerifiedAssignment{}, err
	}
	return VerifiedAssignment{
		Payload:       envelope.Payload,
		PayloadDigest: bytesDigest(canonical),
		KeyID:         envelope.KeyID,
		verified:      true,
	}, nil
}

func (verifier *Verifier) validatePayload(payload Payload) error {
	if payload.Version != CurrentAssignmentVersion {
		return assignmentError("assignment.version", "Assignment version is unsupported.")
	}
	for value, prefix := range map[string]string{
		payload.BuildID: "bld", payload.CellID: "cell", payload.OrganizationID: "org",
		payload.ProjectID: "prj", payload.OperationID: "op",
	} {
		if err := validateID(value, prefix); err != nil {
			return err
		}
	}
	if payload.CellID != verifier.cellID {
		return assignmentError("assignment.audience", "Assignment is addressed to another build cell.")
	}
	if payload.Generation == 0 || !noncePattern.MatchString(payload.Nonce) {
		return assignmentError("assignment.replay_identity", "Assignment generation or nonce is invalid.")
	}
	issuedAt, err := parseWholeSecond(payload.IssuedAt)
	if err != nil {
		return err
	}
	expiresAt, err := parseWholeSecond(payload.ExpiresAt)
	if err != nil {
		return err
	}
	now := verifier.clock().UTC()
	if issuedAt.After(now.Add(verifier.maxFutureSkew)) || !expiresAt.After(now) || !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > verifier.maxTTL {
		return assignmentError("assignment.expiry", "Assignment issuance or expiry is outside the accepted window.")
	}
	lockDigest, err := llbcompiler.LockDigest(payload.Lock)
	if err != nil || payload.DefinitionDigest != lockDigest || !digestPattern.MatchString(payload.DefinitionDigest) {
		return assignmentError("assignment.definition_digest", "Assignment definition lock digest does not match its payload.")
	}
	if payload.Source.SnapshotDigest != payload.Lock.SourceSnapshot || !digestPattern.MatchString(payload.Source.ArchiveDigest) || payload.Source.SizeBytes <= 0 || payload.Source.SizeBytes > 1<<30 {
		return assignmentError("assignment.source", "Assignment source artifact is inconsistent or outside limits.")
	}
	if err := verifier.validateReference(payload.Source.ArchiveRef); err != nil {
		return err
	}
	if len(payload.Outputs) == 0 || len(payload.Outputs) > buildir.MaxOutputs || len(payload.Outputs) != len(payload.Lock.Outputs) {
		return assignmentError("assignment.outputs", "Assignment output artifacts do not match the definition lock.")
	}
	outputNames := make(map[string]struct{}, len(payload.Outputs))
	for index, output := range payload.Outputs {
		locked := payload.Lock.Outputs[index]
		if output.Name != locked.Name || output.Kind != locked.Kind || output.LLBDigest != locked.LLBDigest || output.ConfigDigest != locked.ConfigDigest ||
			!outputNamePattern.MatchString(output.Name) || !slices.Contains([]string{"oci_image", "static_bundle"}, output.Kind) ||
			!digestPattern.MatchString(output.LLBDigest) || !digestPattern.MatchString(output.Head) || !digestPattern.MatchString(output.ConfigDigest) {
			return assignmentError("assignment.outputs", "Assignment output artifact identity is inconsistent.")
		}
		if _, duplicate := outputNames[output.Name]; duplicate {
			return assignmentError("assignment.outputs", "Assignment output names must be unique.")
		}
		outputNames[output.Name] = struct{}{}
		if err := verifier.validateReference(output.LLBRef); err != nil {
			return err
		}
		if err := verifier.validateReference(output.ConfigRef); err != nil {
			return err
		}
	}
	if err := validateLock(payload.Lock); err != nil {
		return err
	}
	return nil
}

func (verifier *Verifier) validateReference(reference string) error {
	pathPart := strings.TrimPrefix(reference, "s3://")
	_, pathPart, found := strings.Cut(pathPart, "/")
	invalidPath := !found || strings.Contains(pathPart, "//")
	for _, segment := range strings.Split(pathPart, "/") {
		invalidPath = invalidPath || segment == "." || segment == ".."
	}
	if !objectReference.MatchString(reference) || !strings.HasPrefix(reference, verifier.objectPrefix) || invalidPath {
		return assignmentError("assignment.object_ref", "Assignment object reference is outside the cell content prefix.")
	}
	return nil
}

func Resolve(ctx context.Context, verified VerifiedAssignment, store ArtifactStore) (ResolvedAssignment, error) {
	if store == nil {
		return ResolvedAssignment{}, assignmentError("assignment.store", "Assignment artifact store is unavailable.")
	}
	if err := verified.validateProof(); err != nil {
		return ResolvedAssignment{}, err
	}
	outputs := make([]ResolvedOutput, 0, len(verified.Payload.Outputs))
	definitions := make([][]byte, 0, len(verified.Payload.Outputs))
	for _, output := range verified.Payload.Outputs {
		definition, err := readArtifact(ctx, store, output.LLBRef, MaxDefinitionBytes, output.LLBDigest)
		if err != nil {
			return ResolvedAssignment{}, err
		}
		if err := verifyDefinition(definition, output.Head); err != nil {
			return ResolvedAssignment{}, err
		}
		config, err := readArtifact(ctx, store, output.ConfigRef, MaxConfigBytes, output.ConfigDigest)
		if err != nil {
			return ResolvedAssignment{}, err
		}
		outputs = append(outputs, ResolvedOutput{Name: output.Name, Kind: output.Kind, Definition: definition, Config: config})
		definitions = append(definitions, definition)
	}
	if err := llbcompiler.AuditDefinitions(definitions, verified.Payload.Lock); err != nil {
		return ResolvedAssignment{}, fmt.Errorf("%w: %v", assignmentError("assignment.llb_capability", "Assignment LLB exceeds or omits signed capabilities."), err)
	}
	return ResolvedAssignment{Verified: verified, Outputs: outputs, resolved: true}, nil
}

func (verified VerifiedAssignment) validateProof() error {
	if !verified.verified || verified.KeyID == "" || !digestPattern.MatchString(verified.PayloadDigest) {
		return assignmentError("assignment.proof", "Assignment verification proof is absent.")
	}
	canonical, err := canonicaljson.Marshal(verified.Payload)
	if err != nil || bytesDigest(canonical) != verified.PayloadDigest {
		return assignmentError("assignment.proof", "Assignment changed after signature verification.")
	}
	return nil
}

func (verified VerifiedAssignment) Validate() error {
	return verified.validateProof()
}

func (resolved ResolvedAssignment) Validate() error {
	if !resolved.resolved {
		return assignmentError("assignment.proof", "Assignment resolution proof is absent.")
	}
	if err := resolved.Verified.validateProof(); err != nil {
		return err
	}
	if len(resolved.Outputs) != len(resolved.Verified.Payload.Outputs) {
		return assignmentError("assignment.resolved_outputs", "Resolved output set changed after artifact verification.")
	}
	definitions := make([][]byte, 0, len(resolved.Outputs))
	for index, output := range resolved.Outputs {
		expected := resolved.Verified.Payload.Outputs[index]
		if output.Name != expected.Name || output.Kind != expected.Kind ||
			bytesDigest(output.Definition) != expected.LLBDigest || bytesDigest(output.Config) != expected.ConfigDigest {
			return assignmentError("assignment.resolved_outputs", "Resolved output identity changed after artifact verification.")
		}
		if err := verifyDefinition(output.Definition, expected.Head); err != nil {
			return err
		}
		definitions = append(definitions, output.Definition)
	}
	if err := llbcompiler.AuditDefinitions(definitions, resolved.Verified.Payload.Lock); err != nil {
		return fmt.Errorf("%w: %v", assignmentError("assignment.llb_capability", "Resolved LLB exceeds or omits signed capabilities."), err)
	}
	return nil
}

func verifyDefinition(contents []byte, expectedHead string) error {
	var wire pb.Definition
	if err := proto.Unmarshal(contents, &wire); err != nil || len(wire.Def) == 0 {
		return assignmentError("assignment.llb", "Assignment LLB definition is malformed.")
	}
	var definition llb.Definition
	definition.FromPB(&wire)
	head, err := definition.Head()
	if err != nil || string(head) != expectedHead {
		return assignmentError("assignment.llb_head", "Assignment LLB definition head does not match its signed identity.")
	}
	return nil
}

func readArtifact(ctx context.Context, store ArtifactStore, reference string, limit int64, expectedDigest string) ([]byte, error) {
	reader, err := store.Open(ctx, reference, limit)
	if err != nil {
		return nil, assignmentError("assignment.artifact_read", "Assignment artifact could not be read.")
	}
	defer reader.Close()
	contents, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil || int64(len(contents)) > limit || bytesDigest(contents) != expectedDigest {
		return nil, assignmentError("assignment.artifact_digest", "Assignment artifact is oversized, truncated, or has the wrong digest.")
	}
	return contents, nil
}

func validateLock(lock llbcompiler.DefinitionLock) error {
	if lock.Version != llbcompiler.CurrentLockVersion || !semanticVersion.MatchString(lock.CompilerVersion) ||
		!digestPattern.MatchString(lock.IRDigest) || !digestPattern.MatchString(lock.PolicyDigest) ||
		!digestPattern.MatchString(lock.SourceSnapshot) || !slices.Contains([]string{"linux/amd64", "linux/arm64"}, lock.TargetPlatform) {
		return assignmentError("assignment.lock", "Assignment definition lock contains invalid core identity.")
	}
	if len(lock.BuildArguments) > 64 || len(lock.BaseMaterials) > buildir.MaxNodes || len(lock.Network) > buildir.MaxNodes ||
		len(lock.Caches) > buildir.MaxNodes || len(lock.Secrets) > buildir.MaxNodes || len(lock.Outputs) == 0 || len(lock.Outputs) > buildir.MaxOutputs {
		return assignmentError("assignment.lock", "Assignment definition lock exceeds capability limits.")
	}
	if err := llbcompiler.ValidateSupplyChainPolicy(lock.SupplyChain); err != nil {
		return assignmentError("assignment.lock", "Assignment supply-chain policy is invalid.")
	}
	argumentNames := make(map[string]struct{}, len(lock.BuildArguments))
	for _, argument := range lock.BuildArguments {
		if !argumentNamePattern.MatchString(argument.Name) || !boundedLockText(argument.Value, true) {
			return assignmentError("assignment.lock", "Assignment build argument is invalid.")
		}
		if _, duplicate := argumentNames[argument.Name]; duplicate {
			return assignmentError("assignment.lock", "Assignment build arguments contain a duplicate.")
		}
		argumentNames[argument.Name] = struct{}{}
	}
	materialReferences := make(map[string]struct{}, len(lock.BaseMaterials))
	for _, material := range lock.BaseMaterials {
		if !boundedLockText(material.RequestedRef, false) || !boundedLockText(material.ResolvedRef, false) ||
			!digestPattern.MatchString(material.Digest) || !strings.HasSuffix(material.RequestedRef, "@"+material.Digest) ||
			!strings.HasSuffix(material.ResolvedRef, "@"+material.Digest) || !validRegistry(material.Registry) ||
			!slices.Contains([]string{"curated", "customer"}, material.Classification) || len(material.Platforms) == 0 || len(material.Platforms) > 32 ||
			!boundedLockText(material.SignatureIdentity, false) || !digestPattern.MatchString(material.ResolutionDigest) ||
			(material.SBOMDigest != "" && !digestPattern.MatchString(material.SBOMDigest)) ||
			(material.ProvenanceDigest != "" && !digestPattern.MatchString(material.ProvenanceDigest)) {
			return assignmentError("assignment.lock", "Assignment base material is invalid.")
		}
		for _, platform := range material.Platforms {
			if !boundedLockText(platform, false) {
				return assignmentError("assignment.lock", "Assignment base material platform is invalid.")
			}
		}
		expectedResolution, err := llbcompiler.ResolutionDigest(material)
		if err != nil || expectedResolution != material.ResolutionDigest {
			return assignmentError("assignment.lock", "Assignment base material resolution evidence is invalid.")
		}
		if _, duplicate := materialReferences[material.RequestedRef]; duplicate {
			return assignmentError("assignment.lock", "Assignment base materials contain a duplicate.")
		}
		materialReferences[material.RequestedRef] = struct{}{}
	}
	nodeIDs := make(map[string]struct{}, len(lock.Network)+len(lock.Caches)+len(lock.Secrets))
	for _, network := range lock.Network {
		if !nodeIDPattern.MatchString(network.NodeID) || !slices.Contains([]string{"none", "packages", "allowlist", "private"}, network.Profile) || len(network.Hosts) > 128 {
			return assignmentError("assignment.lock", "Assignment network capability is invalid.")
		}
		for _, host := range network.Hosts {
			if !validEgressHostname(host) {
				return assignmentError("assignment.lock", "Assignment network host is invalid.")
			}
		}
		switch network.Profile {
		case "none":
			if len(network.Hosts) != 0 || network.GatewayID != "" {
				return assignmentError("assignment.lock", "No-network capability may not carry egress authority.")
			}
		case "packages", "allowlist":
			if len(network.Hosts) == 0 || !capabilityNamePattern.MatchString(network.GatewayID) {
				return assignmentError("assignment.lock", "Network capability lacks its bounded gateway or host set.")
			}
		case "private":
			if len(network.Hosts) != 0 || !capabilityNamePattern.MatchString(network.GatewayID) {
				return assignmentError("assignment.lock", "Private network capability is invalid.")
			}
		}
		if _, duplicate := nodeIDs[network.NodeID]; duplicate {
			return assignmentError("assignment.lock", "Assignment capability node is duplicated.")
		}
		nodeIDs[network.NodeID] = struct{}{}
	}
	cacheNamespaces := make(map[string]struct{}, len(lock.Caches))
	for _, cache := range lock.Caches {
		if !nodeIDPattern.MatchString(cache.NodeID) || !capabilityNamePattern.MatchString(cache.Name) || !safeContainerPath(cache.Target, "/") ||
			!slices.Contains([]string{"organization", "project"}, cache.Scope) || !slices.Contains([]string{"locked", "private", "shared"}, cache.Sharing) ||
			!cacheNamespacePattern.MatchString(cache.Namespace) {
			return assignmentError("assignment.lock", "Assignment cache capability is invalid.")
		}
		if _, duplicate := nodeIDs[cache.NodeID]; duplicate {
			return assignmentError("assignment.lock", "Assignment capability node is duplicated.")
		}
		nodeIDs[cache.NodeID] = struct{}{}
		if _, duplicate := cacheNamespaces[cache.Namespace]; duplicate {
			return assignmentError("assignment.lock", "Assignment cache namespace is duplicated.")
		}
		cacheNamespaces[cache.Namespace] = struct{}{}
	}
	secretMounts := make(map[string]struct{}, len(lock.Secrets))
	for _, secret := range lock.Secrets {
		if !nodeIDPattern.MatchString(secret.NodeID) || !capabilityNamePattern.MatchString(secret.Name) || secret.MountID != secret.Name ||
			!safeContainerPath(secret.Target, "/run/secrets/") {
			return assignmentError("assignment.lock", "Assignment secret capability is invalid.")
		}
		if _, duplicate := nodeIDs[secret.NodeID]; duplicate {
			return assignmentError("assignment.lock", "Assignment capability node is duplicated.")
		}
		nodeIDs[secret.NodeID] = struct{}{}
		if _, duplicate := secretMounts[secret.MountID]; duplicate {
			return assignmentError("assignment.lock", "Assignment secret mount is duplicated.")
		}
		secretMounts[secret.MountID] = struct{}{}
	}
	outputNames := make(map[string]struct{}, len(lock.Outputs))
	for _, output := range lock.Outputs {
		if !outputNamePattern.MatchString(output.Name) || !slices.Contains([]string{"oci_image", "static_bundle"}, output.Kind) ||
			!nodeIDPattern.MatchString(output.StateID) || !digestPattern.MatchString(output.LLBDigest) || !digestPattern.MatchString(output.ConfigDigest) {
			return assignmentError("assignment.lock", "Assignment output lock is invalid.")
		}
		if _, duplicate := outputNames[output.Name]; duplicate {
			return assignmentError("assignment.lock", "Assignment output lock is duplicated.")
		}
		outputNames[output.Name] = struct{}{}
	}
	return nil
}

func validRegistry(value string) bool {
	host := value
	if candidate, portText, found := strings.Cut(value, ":"); found {
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return false
		}
		host = candidate
	}
	return validEgressHostname(host)
}

func validEgressHostname(value string) bool {
	if !hostnamePattern.MatchString(value) || value == "localhost" || strings.HasSuffix(value, ".localhost") {
		return false
	}
	_, err := netip.ParseAddr(value)
	return err != nil
}

func boundedLockText(value string, allowEmpty bool) bool {
	return (allowEmpty || value != "") && len(value) <= buildir.MaxStringBytes && utf8.ValidString(value) && !strings.ContainsRune(value, '\x00')
}

func safeContainerPath(value, prefix string) bool {
	return len(value) <= buildir.MaxStringBytes && path.IsAbs(value) && path.Clean(value) == value && value != "/" && strings.HasPrefix(value, prefix)
}

func parseWholeSecond(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Nanosecond() != 0 || value != parsed.UTC().Format(time.RFC3339) {
		return time.Time{}, assignmentError("assignment.timestamp", "Assignment timestamps must be canonical UTC whole seconds.")
	}
	return parsed.UTC(), nil
}

func validateID(value, prefix string) error {
	parsed, err := platformid.Parse(value)
	if err != nil || parsed.Prefix() != prefix {
		return assignmentError("assignment.scope", "Assignment contains an invalid resource identity.")
	}
	return nil
}

func assignmentError(code, message string) error {
	return fmt.Errorf("%w: %s: %s", ErrAssignment, code, message)
}

func bytesDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
