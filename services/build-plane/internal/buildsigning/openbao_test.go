package buildsigning

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildsupply"
)

type fakeSigningBao struct {
	mu         sync.Mutex
	server     *httptest.Server
	private    ed25519.PrivateKey
	publicPEM  string
	unsafeKey  bool
	revokeFail bool
	logins     int
	signs      int
	revokes    int
}

func newFakeSigningBao(t *testing.T) *fakeSigningBao {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	der, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeSigningBao{private: private, publicPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}
	fake.server = httptest.NewTLSServer(http.HandlerFunc(fake.handle))
	t.Cleanup(fake.server.Close)
	return fake
}

func (fake *fakeSigningBao) handle(response http.ResponseWriter, request *http.Request) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	response.Header().Set("Content-Type", "application/json")
	switch request.URL.Path {
	case "/v1/auth/kubernetes/login":
		var body map[string]string
		if json.NewDecoder(request.Body).Decode(&body) != nil || body["role"] != "build-evidence-signer" || body["jwt"] != "projected-test-jwt" {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		fake.logins++
		writeTestJSON(response, map[string]any{"auth": map[string]any{"client_token": "short-lived-sign-token", "accessor": "sign-accessor", "lease_duration": 120}})
	case "/v1/transit/keys/build-evidence":
		if request.Header.Get("X-Vault-Token") != "short-lived-sign-token" {
			response.WriteHeader(http.StatusForbidden)
			return
		}
		writeTestJSON(response, map[string]any{"data": map[string]any{
			"type": "ed25519", "derived": false, "exportable": fake.unsafeKey, "allow_plaintext_backup": false,
			"deletion_allowed": false, "supports_signing": true, "latest_version": 2,
			"keys": map[string]any{"2": map[string]any{"public_key": fake.publicPEM}},
		}})
	case "/v1/transit/sign/build-evidence":
		if request.Header.Get("X-Vault-Token") != "short-lived-sign-token" {
			response.WriteHeader(http.StatusForbidden)
			return
		}
		var body struct {
			Input      string `json:"input"`
			KeyVersion int    `json:"key_version"`
		}
		if json.NewDecoder(request.Body).Decode(&body) != nil || body.KeyVersion != 2 {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		payload, err := base64.StdEncoding.DecodeString(body.Input)
		if err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		fake.signs++
		signature := ed25519.Sign(fake.private, payload)
		writeTestJSON(response, map[string]any{"data": map[string]any{"signature": "vault:v2:" + base64.StdEncoding.EncodeToString(signature)}})
	case "/v1/auth/token/revoke-self":
		fake.revokes++
		if fake.revokeFail {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writeTestJSON(response, map[string]any{})
	default:
		response.WriteHeader(http.StatusNotFound)
	}
}

func TestOpenBaoAuthoritySignsWithNonExportableKeyAndRevokesIdentity(t *testing.T) {
	t.Parallel()
	fake := newFakeSigningBao(t)
	authority := fake.authority(t)
	payload := validSimpleSigningPayload(signingSubject)
	material, err := authority.Sign(t.Context(), payload)
	if err != nil || material.KeyID != "lrail-build-evidence" || material.KeyVersion != 2 || fake.logins != 1 || fake.signs != 1 || fake.revokes != 1 {
		t.Fatalf("material=%#v fake=%#v error=%v", material, fake, err)
	}
	if _, err := buildsupply.VerifySignature(material.PublicKeyPEM, payload, material.Signature); err != nil {
		t.Fatal(err)
	}
}

func TestOpenBaoAuthorityFailsClosedForUnsafeKeyAndRevocationFailure(t *testing.T) {
	for name, configure := range map[string]func(*fakeSigningBao){
		"exportable key": func(fake *fakeSigningBao) { fake.unsafeKey = true },
		"revocation":     func(fake *fakeSigningBao) { fake.revokeFail = true },
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakeSigningBao(t)
			configure(fake)
			material, err := fake.authority(t).Sign(t.Context(), validSimpleSigningPayload(signingSubject))
			if err == nil || material.Signature != nil || fake.revokes != 1 {
				t.Fatalf("material=%#v fake=%#v error=%v", material, fake, err)
			}
		})
	}
}

func (fake *fakeSigningBao) authority(t *testing.T) *OpenBaoAuthority {
	t.Helper()
	jwtPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(jwtPath, []byte("projected-test-jwt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	authority, err := NewOpenBaoAuthority(OpenBaoConfig{
		Address: fake.server.URL, KubernetesRole: "build-evidence-signer", AuthMount: "kubernetes", TransitMount: "transit",
		KeyName: "build-evidence", KeyID: "lrail-build-evidence", JWTPath: jwtPath, RequestTimeout: 5 * time.Second, MaxTokenTTL: 5 * time.Minute,
	}, fake.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func writeTestJSON(response http.ResponseWriter, value any) {
	response.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(response).Encode(value)
}
