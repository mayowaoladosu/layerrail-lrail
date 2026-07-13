package buildcell

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/solver/pb"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"google.golang.org/protobuf/proto"
)

const testBuildID = "bld_019b01da-7e31-7000-8000-000000000001"
const testCellID = "cell_019b01da-7e31-7000-8000-000000000002"
const testOrgID = "org_019b01da-7e31-7000-8000-000000000003"
const testProjectID = "prj_019b01da-7e31-7000-8000-000000000004"
const testOperationID = "op_019b01da-7e31-7000-8000-000000000005"
const testSnapshotDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testIRDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const testPolicyDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
const testObjectPrefix = "s3://lrail-build/cell-a/"

var testNow = time.Date(2026, 7, 13, 1, 0, 0, 0, time.UTC)
var testPrivateKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
var testPublicKey = testPrivateKey.Public().(ed25519.PublicKey)

type mapStore map[string][]byte

func (store mapStore) Open(_ context.Context, reference string, _ int64) (io.ReadCloser, error) {
	contents, exists := store[reference]
	if !exists {
		return nil, errors.New("missing")
	}
	return io.NopCloser(bytes.NewReader(contents)), nil
}

func validEnvelope(t *testing.T) (Envelope, *Verifier, mapStore) {
	t.Helper()
	definition, head := testDefinition(t)
	config := []byte(`{"config":{"Cmd":["true"]}}`)
	archive := []byte("normalized source archive")
	llbDigest := bytesDigest(definition)
	configDigest := bytesDigest(config)
	lock := llbcompiler.DefinitionLock{
		Version:         llbcompiler.CurrentLockVersion,
		CompilerVersion: "0.1.0",
		IRDigest:        testIRDigest,
		PolicyDigest:    testPolicyDigest,
		SourceSnapshot:  testSnapshotDigest,
		TargetPlatform:  "linux/amd64",
		BuildArguments:  []llbcompiler.NameValue{},
		BaseMaterials:   []llbcompiler.BaseMaterial{},
		Network:         []llbcompiler.NetworkCapability{},
		Caches:          []llbcompiler.CacheCapability{},
		Secrets:         []llbcompiler.SecretCapability{},
		Outputs: []llbcompiler.OutputLock{{
			Name: "site", Kind: "static_bundle", StateID: "n1", LLBDigest: llbDigest, ConfigDigest: configDigest,
		}},
	}
	definitionDigest, err := llbcompiler.LockDigest(lock)
	if err != nil {
		t.Fatalf("LockDigest: %v", err)
	}
	payload := Payload{
		Version: CurrentAssignmentVersion, BuildID: testBuildID, CellID: testCellID,
		OrganizationID: testOrgID, ProjectID: testProjectID, OperationID: testOperationID,
		Generation: 1, Nonce: "d" + string(bytes.Repeat([]byte("e"), 63)),
		IssuedAt: testNow.Format(time.RFC3339), ExpiresAt: testNow.Add(30 * time.Minute).Format(time.RFC3339),
		DefinitionDigest: definitionDigest, Lock: lock,
		Source: SourceArtifact{
			SnapshotDigest: testSnapshotDigest, ArchiveDigest: bytesDigest(archive),
			ArchiveRef: testObjectPrefix + "sources/source.tar.gz", SizeBytes: int64(len(archive)),
		},
		Outputs: []OutputArtifact{{
			Name: "site", Kind: "static_bundle", LLBDigest: llbDigest, Head: head,
			LLBRef: testObjectPrefix + "definitions/site.llb", ConfigDigest: configDigest,
			ConfigRef: testObjectPrefix + "definitions/site.config.json",
		}},
	}
	envelope, err := Sign(payload, "assignment-test-v1", testPrivateKey)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	verifier, err := NewVerifier(VerifierOptions{
		CellID: testCellID, Keys: map[string]ed25519.PublicKey{"assignment-test-v1": testPublicKey},
		ObjectPrefix: testObjectPrefix, Clock: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	store := mapStore{
		payload.Source.ArchiveRef:    archive,
		payload.Outputs[0].LLBRef:    definition,
		payload.Outputs[0].ConfigRef: config,
	}
	return envelope, verifier, store
}

func testDefinition(t *testing.T) ([]byte, string) {
	t.Helper()
	state := llb.Scratch().File(llb.Mkfile("/index.html", 0o644, []byte("ok")))
	definition, err := state.Marshal(context.Background())
	if err != nil {
		t.Fatalf("Marshal LLB: %v", err)
	}
	head, err := definition.Head()
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	contents, err := proto.MarshalOptions{Deterministic: true}.Marshal(definition.ToPB())
	if err != nil {
		t.Fatalf("Marshal definition: %v", err)
	}
	return contents, string(head)
}

func resign(t *testing.T, envelope Envelope) Envelope {
	t.Helper()
	resigned, err := Sign(envelope.Payload, envelope.KeyID, testPrivateKey)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return resigned
}

func TestAssignmentSignVerifyAndResolve(t *testing.T) {
	t.Parallel()
	envelope, verifier, store := validEnvelope(t)
	verified, err := verifier.Verify(envelope)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	resolved, err := Resolve(context.Background(), verified, store)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if verified.PayloadDigest == "" || len(resolved.Outputs) != 1 || len(resolved.Outputs[0].Definition) == 0 {
		t.Fatalf("incomplete resolved assignment: %#v", resolved)
	}
}

func TestAssignmentVerificationRejectsTamperingAndWrongScope(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*Envelope){
		"signature":        func(envelope *Envelope) { envelope.Signature = "AAAA" },
		"unknown key":      func(envelope *Envelope) { envelope.KeyID = "unknown-key" },
		"audience":         func(envelope *Envelope) { envelope.Payload.CellID = "cell_019b01da-7e31-7000-8000-000000000012" },
		"generation":       func(envelope *Envelope) { envelope.Payload.Generation = 0 },
		"nonce":            func(envelope *Envelope) { envelope.Payload.Nonce = "short" },
		"expiry":           func(envelope *Envelope) { envelope.Payload.ExpiresAt = testNow.Format(time.RFC3339) },
		"future":           func(envelope *Envelope) { envelope.Payload.IssuedAt = testNow.Add(time.Minute).Format(time.RFC3339) },
		"definition":       func(envelope *Envelope) { envelope.Payload.DefinitionDigest = testIRDigest },
		"source":           func(envelope *Envelope) { envelope.Payload.Source.SnapshotDigest = testIRDigest },
		"object prefix":    func(envelope *Envelope) { envelope.Payload.Outputs[0].LLBRef = "s3://other-bucket/definition.llb" },
		"object traversal": func(envelope *Envelope) { envelope.Payload.Outputs[0].LLBRef = testObjectPrefix + "../definition.llb" },
	}
	for name, mutate := range tests {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			envelope, verifier, _ := validEnvelope(t)
			mutate(&envelope)
			if _, err := verifier.Verify(envelope); !errors.Is(err, ErrAssignment) {
				t.Fatalf("Verify error = %v", err)
			}
		})
	}
}

func TestAssignmentResolveRejectsDigestAndLLBHeadMismatch(t *testing.T) {
	t.Parallel()
	envelope, verifier, store := validEnvelope(t)
	verified, err := verifier.Verify(envelope)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	store[envelope.Payload.Outputs[0].ConfigRef] = []byte("tampered")
	if _, err := Resolve(context.Background(), verified, store); !errors.Is(err, ErrAssignment) {
		t.Fatalf("config mismatch error = %v", err)
	}

	envelope, verifier, store = validEnvelope(t)
	verified, _ = verifier.Verify(envelope)
	store[envelope.Payload.Outputs[0].LLBRef] = []byte("tampered")
	if _, err := Resolve(context.Background(), verified, store); !errors.Is(err, ErrAssignment) {
		t.Fatalf("definition mismatch error = %v", err)
	}

	definition, _ := testDefinition(t)
	if err := verifyDefinition(definition, testIRDigest); !errors.Is(err, ErrAssignment) {
		t.Fatalf("head mismatch error = %v", err)
	}
}

func TestAssignmentResolveRejectsSignedLLBOutsideCapabilityLock(t *testing.T) {
	t.Parallel()
	envelope, verifier, store := validEnvelope(t)
	state := llb.Scratch().Run(
		llb.Args([]string{"/bin/true"}), llb.Network(pb.NetMode_HOST),
		llb.WithCustomName("lrail run n1 network=none gateway= hosts="),
	).Root()
	definition, err := state.Marshal(context.Background(), llb.Platform(ocispecs.Platform{OS: "linux", Architecture: "amd64"}))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	head, err := definition.Head()
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	definitionBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(definition.ToPB())
	if err != nil {
		t.Fatalf("Marshal definition: %v", err)
	}
	envelope.Payload.Outputs[0].LLBDigest = bytesDigest(definitionBytes)
	envelope.Payload.Outputs[0].Head = string(head)
	envelope.Payload.Lock.Outputs[0].LLBDigest = envelope.Payload.Outputs[0].LLBDigest
	envelope.Payload.DefinitionDigest, err = llbcompiler.LockDigest(envelope.Payload.Lock)
	if err != nil {
		t.Fatalf("LockDigest: %v", err)
	}
	envelope = resign(t, envelope)
	store[envelope.Payload.Outputs[0].LLBRef] = definitionBytes
	verified, err := verifier.Verify(envelope)
	if err != nil {
		t.Fatalf("Verify signed malicious assignment: %v", err)
	}
	if _, err := Resolve(context.Background(), verified, store); !errors.Is(err, ErrAssignment) || !strings.Contains(err.Error(), "LLB execution requests unsupported ambient authority") {
		t.Fatalf("Resolve error = %v", err)
	}
}

func TestAssignmentRejectsSignedMalformedCapabilities(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*Envelope){
		"duplicate output": func(envelope *Envelope) {
			envelope.Payload.Outputs = append(envelope.Payload.Outputs, envelope.Payload.Outputs[0])
			envelope.Payload.Lock.Outputs = append(envelope.Payload.Lock.Outputs, envelope.Payload.Lock.Outputs[0])
			lockDigest, _ := llbcompiler.LockDigest(envelope.Payload.Lock)
			envelope.Payload.DefinitionDigest = lockDigest
		},
		"unsafe secret target": func(envelope *Envelope) {
			envelope.Payload.Lock.Secrets = []llbcompiler.SecretCapability{{
				NodeID: "n2", Name: "token", MountID: "token", Target: "/run/secrets/../host", Required: true,
			}}
			lockDigest, _ := llbcompiler.LockDigest(envelope.Payload.Lock)
			envelope.Payload.DefinitionDigest = lockDigest
		},
		"ambient no-network authority": func(envelope *Envelope) {
			envelope.Payload.Lock.Network = []llbcompiler.NetworkCapability{{NodeID: "n2", Profile: "none", GatewayID: "gateway"}}
			lockDigest, _ := llbcompiler.LockDigest(envelope.Payload.Lock)
			envelope.Payload.DefinitionDigest = lockDigest
		},
		"localhost egress": func(envelope *Envelope) {
			envelope.Payload.Lock.Network = []llbcompiler.NetworkCapability{{NodeID: "n2", Profile: "allowlist", GatewayID: "gateway", Hosts: []string{"localhost"}}}
			lockDigest, _ := llbcompiler.LockDigest(envelope.Payload.Lock)
			envelope.Payload.DefinitionDigest = lockDigest
		},
		"unbounded compiler version": func(envelope *Envelope) {
			envelope.Payload.Lock.CompilerVersion = "latest"
			lockDigest, _ := llbcompiler.LockDigest(envelope.Payload.Lock)
			envelope.Payload.DefinitionDigest = lockDigest
		},
	}
	for name, mutate := range tests {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			envelope, verifier, _ := validEnvelope(t)
			mutate(&envelope)
			envelope = resign(t, envelope)
			if _, err := verifier.Verify(envelope); !errors.Is(err, ErrAssignment) {
				t.Fatalf("Verify error = %v", err)
			}
		})
	}
}

func TestAssignmentProofRejectsForgeryAndMutation(t *testing.T) {
	t.Parallel()
	envelope, verifier, store := validEnvelope(t)
	verified, err := verifier.Verify(envelope)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if _, err := Resolve(context.Background(), VerifiedAssignment{Payload: verified.Payload, PayloadDigest: verified.PayloadDigest, KeyID: verified.KeyID}, store); !errors.Is(err, ErrAssignment) {
		t.Fatalf("forged verification proof error = %v", err)
	}

	mutated := verified
	mutated.Payload.Generation++
	if _, err := Resolve(context.Background(), mutated, store); !errors.Is(err, ErrAssignment) {
		t.Fatalf("mutated payload error = %v", err)
	}

	resolved, err := Resolve(context.Background(), verified, store)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	forged := ResolvedAssignment{Verified: resolved.Verified, Outputs: resolved.Outputs}
	if err := forged.Validate(); !errors.Is(err, ErrAssignment) {
		t.Fatalf("forged resolution proof error = %v", err)
	}
	resolved.Outputs[0].Config[0] ^= 0xff
	if err := resolved.Validate(); !errors.Is(err, ErrAssignment) {
		t.Fatalf("mutated resolved artifact error = %v", err)
	}
}

func TestVerifierRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()
	tests := []VerifierOptions{
		{},
		{CellID: testCellID, Keys: map[string]ed25519.PublicKey{"bad key": testPublicKey}, ObjectPrefix: testObjectPrefix},
		{CellID: testCellID, Keys: map[string]ed25519.PublicKey{"key": testPublicKey}, ObjectPrefix: "https://example.invalid/"},
		{CellID: testCellID, Keys: map[string]ed25519.PublicKey{"key": testPublicKey}, ObjectPrefix: testObjectPrefix, MaxTTL: 2 * time.Hour},
	}
	for _, options := range tests {
		if _, err := NewVerifier(options); !errors.Is(err, ErrAssignment) {
			t.Fatalf("NewVerifier error = %v", err)
		}
	}
}

func TestEnvelopeCodecRequiresBoundedCanonicalJSON(t *testing.T) {
	t.Parallel()
	envelope, _, _ := validEnvelope(t)
	contents, err := EncodeEnvelope(envelope)
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	decoded, err := DecodeEnvelope(contents)
	if err != nil {
		t.Fatalf("DecodeEnvelope: %v", err)
	}
	if decoded.Signature != envelope.Signature || decoded.Payload.BuildID != envelope.Payload.BuildID {
		t.Fatalf("decoded envelope = %#v", decoded)
	}
	tests := [][]byte{
		nil,
		append([]byte(" "), contents...),
		append(append([]byte(nil), contents...), []byte("{}")...),
		append(contents[:len(contents)-1], []byte(`,"unknown":true}`)...),
		bytes.Repeat([]byte("x"), MaxEnvelopeBytes+1),
	}
	for _, invalid := range tests {
		if _, err := DecodeEnvelope(invalid); !errors.Is(err, ErrAssignment) {
			t.Fatalf("DecodeEnvelope(%d bytes) error = %v", len(invalid), err)
		}
	}
}
