package buildorchestrator

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	lrailv1 "github.com/mayowaoladosu/layerrail-lrail/gen/go/lrail/v1"
	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildsigning"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildsupply"
)

const (
	testCellID          = "cell_019b01da-7e31-7000-8000-000000000008"
	testAssignmentKeyID = "assignment-test-v1"
	testObjectPrefix    = "s3://cell-content/cell-a/"
)

type fakeContent struct {
	objects        map[string][]byte
	materializeErr error
}

func newFakeContent() *fakeContent { return &fakeContent{objects: make(map[string][]byte)} }

func (content *fakeContent) Materialize(_ context.Context, _ Source, destination string) error {
	if content.materializeErr != nil {
		return content.materializeErr
	}
	return os.MkdirAll(destination, 0o700)
}

func (content *fakeContent) MirrorSource(_ context.Context, source Source, objectName string) (buildcell.SourceArtifact, error) {
	contents := bytes.Repeat([]byte{'s'}, int(source.SizeBytes))
	content.objects[objectName] = contents
	return buildcell.SourceArtifact{
		SnapshotDigest: source.SnapshotDigest, ArchiveDigest: source.ArchiveDigest,
		ArchiveRef: testObjectPrefix + objectName, SizeBytes: source.SizeBytes,
	}, nil
}

func (content *fakeContent) PutImmutable(_ context.Context, objectName, _ string, contents []byte) (StoredObject, error) {
	digest := digestBytes(contents)
	if existing, found := content.objects[objectName]; found && !bytes.Equal(existing, contents) {
		return StoredObject{}, errors.New("immutable conflict")
	}
	content.objects[objectName] = append([]byte(nil), contents...)
	return StoredObject{Reference: testObjectPrefix + objectName, Digest: digest, Size: int64(len(contents))}, nil
}

func (content *fakeContent) Open(_ context.Context, reference string, maxBytes int64) (io.ReadCloser, error) {
	name := strings.TrimPrefix(reference, testObjectPrefix)
	value, found := content.objects[name]
	if !found || int64(len(value)) > maxBytes {
		return nil, errors.New("object absent")
	}
	return io.NopCloser(bytes.NewReader(value)), nil
}

type fakeDetector struct {
	result DetectionResult
	calls  int
}

func (detector *fakeDetector) Detect(_ context.Context, _ string, snapshotID, selectedRoot string) (DetectionResult, []byte, error) {
	detector.calls++
	result := detector.result
	result.SourceSnapshotID = snapshotID
	result.SnapshotRoot = selectedRoot
	contents, err := json.Marshal(result)
	return result, contents, err
}

type fakeAuthority struct {
	private ed25519.PrivateKey
	public  []byte
	keyID   string
}

func newFakeAuthority(t *testing.T) (*fakeAuthority, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	digest, err := buildsupply.VerifySignature(encoded, []byte("probe"), ed25519.Sign(private, []byte("probe")))
	if err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	return &fakeAuthority{private: private, public: encoded, keyID: testAssignmentKeyID}, digest
}

func (authority *fakeAuthority) Sign(_ context.Context, payload []byte) (buildsigning.Material, error) {
	return buildsigning.Material{
		KeyID: authority.keyID, KeyVersion: 1, Algorithm: buildsupply.SignatureAlgorithm,
		PublicKeyPEM: append([]byte(nil), authority.public...), Signature: ed25519.Sign(authority.private, payload),
	}, nil
}

type fakeDispatcher struct {
	verifier    *buildcell.Verifier
	content     *fakeContent
	now         time.Time
	executeCall int
	cancelCall  int
	resolved    buildcell.ResolvedAssignment
}

func (dispatcher *fakeDispatcher) Execute(ctx context.Context, envelope buildcell.Envelope, emit func(*lrailv1.BuildCellEvent) error) (*lrailv1.BuildCellResult, error) {
	dispatcher.executeCall++
	verified, err := dispatcher.verifier.Verify(envelope)
	if err != nil {
		return nil, err
	}
	dispatcher.resolved, err = buildcell.Resolve(ctx, verified, dispatcher.content)
	if err != nil {
		return nil, err
	}
	for index, line := range []string{"running policy-locked solve", "exporting immutable image"} {
		if err := emit(&lrailv1.BuildCellEvent{
			Sequence: uint64(index + 1), Attempt: 1, Phase: "solving", Kind: "log", Line: line,
			OccurredAt: dispatcher.now.Add(time.Duration(index+1) * time.Second).Format(time.RFC3339Nano),
		}); err != nil {
			return nil, err
		}
	}
	payload := envelope.Payload
	output := payload.Outputs[0]
	manifestDigest := repeatedDigest("d")
	repository := "registry.example.invalid/lrail/api"
	kinds := []string{"policy_decision", "provenance", "sbom", "signature", "vulnerability_scan"}
	evidence := make([]*lrailv1.BuildEvidenceReference, 0, len(kinds))
	for index, kind := range kinds {
		evidence = append(evidence, &lrailv1.BuildEvidenceReference{
			Kind: kind, Reference: repository + "@" + indexedDigest(index+1),
			ManifestDigest: indexedDigest(index + 1), PayloadDigest: indexedDigest(index + 11),
		})
	}
	return &lrailv1.BuildCellResult{
		BuildId: payload.BuildID, PayloadDigest: digestPayload(tCanonical(payload)), Phase: "complete", Attempts: 1,
		WorkerIdentity: "spiffe://lrail.dev/build-worker/test", ErrorCode: "",
		StartedAt: dispatcher.now.Add(time.Second).Format(time.RFC3339Nano), FinishedAt: dispatcher.now.Add(5 * time.Minute).Format(time.RFC3339Nano),
		LogsDigest: repeatedDigest("9"), CacheHits: 1, CacheMisses: 1,
		Cleanup: &lrailv1.BuildCellCleanup{Status: "clean"},
		Outputs: []*lrailv1.BuildCellOutput{{
			Name: output.Name, Kind: output.Kind, ArtifactRef: repository + "@" + manifestDigest,
			ArtifactDigest: repeatedDigest("e"), ArtifactSize: 4096, ConfigDigest: output.ConfigDigest,
			ManifestDigest: manifestDigest, LayerDigests: []string{repeatedDigest("f")},
			SupplyChain: &lrailv1.BuildSupplyChainResult{
				PolicyState: "accepted", ScanState: "passed", PolicyDigest: payload.Lock.PolicyDigest,
				SignerKeyId: payload.Lock.SupplyChain.SignerKeyID, SignerKeyVersion: 1,
				SignerPublicKeyDigest: payload.Lock.SupplyChain.AllowedSignerPublicKeyDigests[0], Evidence: evidence,
			},
		}},
	}, nil
}

func (dispatcher *fakeDispatcher) Cancel(_ context.Context, _ string, _ uint64, _ string) (bool, error) {
	dispatcher.cancelCall++
	return true, nil
}

func newTestOrchestrator(t *testing.T, now time.Time, content *fakeContent, detector *fakeDetector) (*Orchestrator, *fakeDispatcher, *fakeAuthority) {
	t.Helper()
	compiler, err := NewDefinitionCompiler(validPolicy(), validCatalog(t), "0.3.0", "0.2.0")
	if err != nil {
		t.Fatalf("NewDefinitionCompiler: %v", err)
	}
	authority, publicDigest := newFakeAuthority(t)
	publicKey, _, err := parseTestPublicKey(authority.public)
	if err != nil {
		t.Fatalf("parseTestPublicKey: %v", err)
	}
	verifier, err := buildcell.NewVerifier(buildcell.VerifierOptions{
		CellID: testCellID, Keys: map[string]ed25519.PublicKey{testAssignmentKeyID: publicKey},
		ObjectPrefix: testObjectPrefix, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	dispatcher := &fakeDispatcher{verifier: verifier, content: content, now: now}
	orchestrator, err := New(OrchestratorOptions{
		Content: content, Detector: detector, Compiler: compiler, Signer: authority, Dispatcher: dispatcher,
		CellID: testCellID, AssignmentKeyID: testAssignmentKeyID, AssignmentPublicKeyDigest: publicDigest,
		ScratchRoot: t.TempDir(), Clock: func() time.Time { return now }, Nonce: func() (string, error) { return strings.Repeat("a", 64), nil },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return orchestrator, dispatcher, authority
}

func TestOrchestratorRunsSnapshotThroughRealVerifierAndLLBResolution(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	content := newFakeContent()
	detector := &fakeDetector{result: validDetection()}
	orchestrator, dispatcher, _ := newTestOrchestrator(t, now, content, detector)
	request := validRequest(now)
	events := make([]Event, 0)
	result, err := orchestrator.Run(context.Background(), request, func(event Event) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.State != "complete" || len(result.Outputs) != 1 || result.Outputs[0].SupplyChain.PolicyState != "accepted" ||
		dispatcher.executeCall != 1 || len(dispatcher.resolved.Outputs) != 1 || detector.calls != 1 {
		t.Fatalf("result=%#v dispatcher=%#v detector=%#v", result, dispatcher, detector)
	}
	if len(events) < 8 || events[len(events)-1].Terminal == nil || events[len(events)-1].Terminal.State != "complete" {
		t.Fatalf("events = %#v", events)
	}
	for index, event := range events {
		if event.Sequence != uint64(index+1) {
			t.Fatalf("event sequence at %d = %d", index, event.Sequence)
		}
	}
	objectNames := make([]string, 0, len(content.objects))
	for name := range content.objects {
		objectNames = append(objectNames, name)
	}
	if !slices.ContainsFunc(objectNames, func(name string) bool { return strings.HasSuffix(name, "/build/build-ir.json") }) ||
		!slices.ContainsFunc(objectNames, func(name string) bool { return strings.HasSuffix(name, "/outputs/api/llb.pb") }) ||
		!slices.ContainsFunc(objectNames, func(name string) bool { return strings.HasSuffix(name, "/source/archive.tar.gz") }) {
		t.Fatalf("stored objects = %#v", objectNames)
	}
}

func TestOrchestratorPersistsBlockedDetectionAndWaitsWithoutAuthority(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	blocked := validDetection()
	blocked.Blocked = true
	blocked.Services[0].Ambiguous = true
	blocked.Unresolved = []json.RawMessage{[]byte(`{"code":"go.listen-port-unresolved"}`)}
	blocked.GeneratedManifest = []byte("null")
	content := newFakeContent()
	orchestrator, dispatcher, _ := newTestOrchestrator(t, now, content, &fakeDetector{result: blocked})
	result, err := orchestrator.Run(context.Background(), validRequest(now), func(Event) error { return nil })
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.State != "waiting" || result.FailureCode != "detect_confirmation_required" || result.DetectionDigest == "" || dispatcher.executeCall != 0 {
		t.Fatalf("result=%#v dispatcher calls=%d", result, dispatcher.executeCall)
	}
}

func TestOrchestratorRejectsAssignmentSignerSubstitutionAndForwardsCancellation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	content := newFakeContent()
	orchestrator, dispatcher, authority := newTestOrchestrator(t, now, content, &fakeDetector{result: validDetection()})
	authority.keyID = "substituted-key"
	if _, err := orchestrator.Run(context.Background(), validRequest(now), func(Event) error { return nil }); err == nil || dispatcher.executeCall != 0 {
		t.Fatalf("signer substitution was not rejected: err=%v calls=%d", err, dispatcher.executeCall)
	}
	authority.keyID = testAssignmentKeyID
	accepted, err := orchestrator.Cancel(context.Background(), testBuildID, 1, "user requested cancellation")
	if err != nil || !accepted || dispatcher.cancelCall != 1 {
		t.Fatalf("Cancel: accepted=%v err=%v calls=%d", accepted, err, dispatcher.cancelCall)
	}
}

func parseTestPublicKey(contents []byte) (ed25519.PublicKey, string, error) {
	block, _ := pem.Decode(contents)
	if block == nil {
		return nil, "", errors.New("PEM absent")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	public, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok {
		return nil, "", errors.New("public key invalid")
	}
	return public, digestBytes(block.Bytes), nil
}

func repeatedDigest(character string) string { return "sha256:" + strings.Repeat(character, 64) }

func indexedDigest(value int) string {
	return fmt.Sprintf("sha256:%064x", value)
}

func tCanonical(payload buildcell.Payload) []byte {
	contents, err := canonicaljson.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return contents
}

func digestPayload(contents []byte) string { return digestBytes(contents) }

var _ Content = (*fakeContent)(nil)
var _ buildcell.ArtifactStore = (*fakeContent)(nil)
var _ Detector = (*fakeDetector)(nil)
var _ buildsigning.Authority = (*fakeAuthority)(nil)
var _ CellDispatcher = (*fakeDispatcher)(nil)
