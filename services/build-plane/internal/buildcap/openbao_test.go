package buildcap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
)

const capBuildID = "bld_019b01da-7e31-7000-8000-000000000001"
const capCellID = "cell_019b01da-7e31-7000-8000-000000000002"
const capOrgID = "org_019b01da-7e31-7000-8000-000000000003"
const capProjectID = "prj_019b01da-7e31-7000-8000-000000000004"
const capOperationID = "op_019b01da-7e31-7000-8000-000000000005"
const capSnapshot = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const capIR = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const capPolicy = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
const capLLB = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
const capHead = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
const capConfig = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
const capPrefix = "s3://lrail-build/cell-cap/"

var capNow = time.Date(2026, 7, 13, 6, 0, 0, 0, time.UTC)
var capPrivateKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize))

func verifiedCapabilityAssignment(t *testing.T, required bool) buildcell.VerifiedAssignment {
	t.Helper()
	secrets := []llbcompiler.SecretCapability{{NodeID: "n2", Name: "package-token", Target: "/run/secrets/package-token", Required: required, MountID: "package-token"}}
	lock := llbcompiler.DefinitionLock{
		Version: llbcompiler.CurrentLockVersion, CompilerVersion: "0.1.0", IRDigest: capIR, PolicyDigest: capPolicy,
		SourceSnapshot: capSnapshot, TargetPlatform: "linux/amd64", BuildArguments: []llbcompiler.NameValue{},
		BaseMaterials: []llbcompiler.BaseMaterial{}, Network: []llbcompiler.NetworkCapability{}, Caches: []llbcompiler.CacheCapability{}, Secrets: secrets,
		SupplyChain: llbcompiler.PlatformSupplyChainPolicy([]string{"sha256:1111111111111111111111111111111111111111111111111111111111111111"}),
		Outputs:     []llbcompiler.OutputLock{{Name: "site", Kind: "static_bundle", StateID: "n1", LLBDigest: capLLB, ConfigDigest: capConfig}},
	}
	lockDigest, err := llbcompiler.LockDigest(lock)
	if err != nil {
		t.Fatalf("LockDigest: %v", err)
	}
	payload := buildcell.Payload{
		Version: buildcell.CurrentAssignmentVersion, BuildID: capBuildID, CellID: capCellID, OrganizationID: capOrgID,
		ProjectID: capProjectID, OperationID: capOperationID, Generation: 1, Nonce: strings.Repeat("a", 64),
		IssuedAt: capNow.Format(time.RFC3339), ExpiresAt: capNow.Add(30 * time.Minute).Format(time.RFC3339), DefinitionDigest: lockDigest, Lock: lock,
		Source:  buildcell.SourceArtifact{SnapshotDigest: capSnapshot, ArchiveDigest: capIR, ArchiveRef: capPrefix + "source.tar.gz", SizeBytes: 100},
		Outputs: []buildcell.OutputArtifact{{Name: "site", Kind: "static_bundle", LLBDigest: capLLB, Head: capHead, LLBRef: capPrefix + "site.llb", ConfigDigest: capConfig, ConfigRef: capPrefix + "site.json"}},
	}
	envelope, err := buildcell.Sign(payload, "cap-test-v1", capPrivateKey)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	verifier, err := buildcell.NewVerifier(buildcell.VerifierOptions{
		CellID: capCellID, Keys: map[string]ed25519.PublicKey{"cap-test-v1": capPrivateKey.Public().(ed25519.PublicKey)}, ObjectPrefix: capPrefix, Clock: func() time.Time { return capNow },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	verified, err := verifier.Verify(envelope)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return verified
}

type baoServer struct {
	mu           sync.Mutex
	secretStatus int
	revokeStatus int
	loginJWT     string
	secretToken  string
	revokedToken string
	revokeCalls  int
}

func (server *baoServer) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	server.mu.Lock()
	defer server.mu.Unlock()
	response.Header().Set("Content-Type", "application/json")
	switch request.URL.Path {
	case "/v1/auth/kubernetes/login":
		var body map[string]string
		_ = json.NewDecoder(request.Body).Decode(&body)
		server.loginJWT = body["jwt"]
		_, _ = response.Write([]byte(`{"request_id":"fake","auth":{"client_token":"fake-short-lived-token","accessor":"fake-accessor","lease_duration":3600,"policies":["build"]}}`))
	case "/v1/secret/data/builds/" + capOrgID + "/package-token":
		server.secretToken = request.Header.Get("X-Vault-Token")
		if server.secretStatus != 0 {
			response.WriteHeader(server.secretStatus)
			_, _ = response.Write([]byte(`{"errors":["fake unavailable"]}`))
			return
		}
		_, _ = response.Write([]byte(`{"data":{"data":{"value":"fake-package-secret"},"metadata":{"version":1}}}`))
	case "/v1/auth/token/revoke-self":
		server.revokedToken = request.Header.Get("X-Vault-Token")
		server.revokeCalls++
		if server.revokeStatus != 0 {
			response.WriteHeader(server.revokeStatus)
			_, _ = response.Write([]byte(`{"errors":["fake revoke failure"]}`))
			return
		}
		response.WriteHeader(http.StatusNoContent)
	default:
		response.WriteHeader(http.StatusNotFound)
	}
}

func newBroker(t *testing.T, handler *baoServer) (*OpenBaoBroker, func()) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	jwtPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(jwtPath, []byte("fake-kubernetes-jwt"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	broker, err := NewOpenBaoBroker(OpenBaoConfig{
		Address: server.URL, KubernetesRole: "build-cell", AuthMount: "kubernetes", KVMount: "secret", SecretPrefix: "builds", JWTPath: jwtPath,
	}, server.Client(), func() time.Time { return capNow })
	if err != nil {
		server.Close()
		t.Fatalf("NewOpenBaoBroker: %v", err)
	}
	return broker, server.Close
}

func TestOpenBaoBrokerAcquiresJITSecretAndRevokesToken(t *testing.T) {
	t.Parallel()
	handler := new(baoServer)
	broker, closeServer := newBroker(t, handler)
	defer closeServer()
	lease, err := broker.Acquire(context.Background(), verifiedCapabilityAssignment(t, true), 1)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if lease.ID != "fake-accessor" || string(lease.Secrets["package-token"]) != "fake-package-secret" || !lease.ExpiresAt.Equal(capNow.Add(30*time.Minute)) {
		t.Fatalf("lease = %#v", lease)
	}
	if handler.loginJWT != "fake-kubernetes-jwt" || handler.secretToken != "fake-short-lived-token" {
		t.Fatalf("handler = %#v", handler)
	}
	if err := broker.Revoke(context.Background(), lease); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if handler.revokedToken != "fake-short-lived-token" {
		t.Fatalf("revoked token = %q", handler.revokedToken)
	}
	if err := broker.Revoke(context.Background(), lease); err == nil {
		t.Fatal("expected duplicate revocation rejection")
	}
}

func TestOpenBaoBrokerRevokesAuthorityBeforeReturningSecrets(t *testing.T) {
	t.Parallel()
	handler := new(baoServer)
	broker, closeServer := newBroker(t, handler)
	defer closeServer()
	lease, err := broker.Acquire(context.Background(), verifiedCapabilityAssignment(t, true), 1)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := broker.Revoke(context.Background(), lease); err != nil {
		t.Fatalf("Revoke lease marker: %v", err)
	}
	if handler.revokeCalls != 1 || handler.revokedToken != "fake-short-lived-token" {
		t.Fatalf("handler = %#v", handler)
	}
}

func TestOpenBaoBrokerRequiredAndOptionalSecretFailures(t *testing.T) {
	t.Parallel()
	for _, required := range []bool{false, true} {
		required := required
		t.Run(fmt.Sprintf("required=%t", required), func(t *testing.T) {
			handler := &baoServer{secretStatus: http.StatusNotFound}
			broker, closeServer := newBroker(t, handler)
			defer closeServer()
			lease, err := broker.Acquire(context.Background(), verifiedCapabilityAssignment(t, required), 1)
			if required {
				if err == nil || handler.revokedToken == "" {
					t.Fatalf("lease=%#v error=%v handler=%#v", lease, err, handler)
				}
				return
			}
			if err != nil || len(lease.Secrets) != 0 {
				t.Fatalf("lease=%#v error=%v", lease, err)
			}
			if err := broker.Revoke(context.Background(), lease); err != nil {
				t.Fatalf("Revoke: %v", err)
			}
		})
	}
}

func TestOpenBaoBrokerOptionalSecretDoesNotHideAuthorityFailure(t *testing.T) {
	t.Parallel()
	handler := &baoServer{secretStatus: http.StatusServiceUnavailable}
	broker, closeServer := newBroker(t, handler)
	defer closeServer()
	lease, err := broker.Acquire(context.Background(), verifiedCapabilityAssignment(t, false), 1)
	if err == nil || lease.ID != "" || handler.revokedToken != "fake-short-lived-token" {
		t.Fatalf("lease=%#v error=%v handler=%#v", lease, err, handler)
	}
}

func TestOpenBaoBrokerFailedAcquisitionExposesRevocationRetry(t *testing.T) {
	t.Parallel()
	handler := &baoServer{secretStatus: http.StatusNotFound, revokeStatus: http.StatusServiceUnavailable}
	broker, closeServer := newBroker(t, handler)
	defer closeServer()
	lease, err := broker.Acquire(context.Background(), verifiedCapabilityAssignment(t, true), 1)
	if !errors.Is(err, ErrAcquisitionCleanup) || !strings.HasPrefix(lease.ID, "pending-") {
		t.Fatalf("lease=%#v Acquire error=%#v", lease, err)
	}
	handler.mu.Lock()
	handler.revokeStatus = 0
	handler.mu.Unlock()
	if err := broker.Revoke(context.Background(), lease); err != nil {
		t.Fatalf("retry Revoke: %v", err)
	}
}
