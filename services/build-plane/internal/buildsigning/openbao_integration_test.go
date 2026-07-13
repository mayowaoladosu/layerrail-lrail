package buildsigning

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildsupply"
)

const openBaoIntegrationImage = "openbao/openbao@sha256:597f62847dd382382056a1d6704d50465908c2040038c4611832a23269a67112"

func TestRealOpenBaoTransitConformsToEvidenceSigningAuthority(t *testing.T) {
	if os.Getenv("LRAIL_OPENBAO_INTEGRATION") != "1" {
		t.Skip("set LRAIL_OPENBAO_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	origin, rootToken := startOpenBaoIntegration(t, ctx)
	client := &http.Client{Timeout: 15 * time.Second}
	openBaoIntegrationRequest(t, ctx, client, origin, rootToken, http.MethodPost, "/v1/sys/mounts/transit", map[string]any{"type": "transit"}, http.StatusNoContent)
	openBaoIntegrationRequest(t, ctx, client, origin, rootToken, http.MethodPost, "/v1/sys/policies/acl/build-evidence-signer", map[string]any{
		"policy": `path "transit/keys/build-evidence" { capabilities = ["read"] }
path "transit/sign/build-evidence" { capabilities = ["update"] }`,
	}, http.StatusNoContent)
	openBaoIntegrationRequest(t, ctx, client, origin, rootToken, http.MethodPost, "/v1/transit/keys/build-evidence", map[string]any{
		"type": "ed25519", "derived": false, "exportable": false, "allow_plaintext_backup": false,
	}, http.StatusOK)

	proxy := &openBaoLoginProxy{origin: origin, rootToken: rootToken, client: client}
	server := httptest.NewTLSServer(proxy)
	t.Cleanup(server.Close)
	jwtPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(jwtPath, []byte("projected-conformance-jwt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	authority, err := NewOpenBaoAuthority(OpenBaoConfig{
		Address: server.URL, KubernetesRole: "build-evidence-signer", AuthMount: "kubernetes", TransitMount: "transit",
		KeyName: "build-evidence", KeyID: "lrail-build-evidence", JWTPath: jwtPath,
		RequestTimeout: 15 * time.Second, MaxTokenTTL: 5 * time.Minute,
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	payload := validSimpleSigningPayload(signingSubject)
	material, err := authority.Sign(t.Context(), payload)
	if err != nil || material.KeyID != "lrail-build-evidence" || material.KeyVersion != 1 || material.Algorithm != buildsupply.SignatureAlgorithm {
		t.Fatalf("material=%#v error=%v", material, err)
	}
	if _, err := buildsupply.VerifySignature(material.PublicKeyPEM, payload, material.Signature); err != nil {
		t.Fatal(err)
	}
	if accessor := proxy.tokenAccessor(); accessor == "" {
		t.Fatal("OpenBao conformance login did not return an accessor")
	} else {
		response := openBaoIntegrationRaw(t, ctx, client, origin, rootToken, http.MethodPost, "/v1/auth/token/lookup-accessor", map[string]any{"accessor": accessor})
		defer response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("short-lived signing token remains active: status=%d", response.StatusCode)
		}
	}
}

type openBaoLoginProxy struct {
	mu        sync.Mutex
	origin    string
	rootToken string
	client    *http.Client
	accessor  string
}

func (proxy *openBaoLoginProxy) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/v1/auth/kubernetes/login" {
		var login map[string]string
		if json.NewDecoder(io.LimitReader(request.Body, 1<<20)).Decode(&login) != nil || login["role"] != "build-evidence-signer" || login["jwt"] != "projected-conformance-jwt" {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		upstream := proxy.request(request.Context(), http.MethodPost, "/v1/auth/token/create", proxy.rootToken, map[string]any{
			"policies": []string{"build-evidence-signer"}, "ttl": "2m", "renewable": false,
		})
		if upstream == nil {
			response.WriteHeader(http.StatusBadGateway)
			return
		}
		contents, readErr := io.ReadAll(io.LimitReader(upstream.Body, 1<<20))
		_ = upstream.Body.Close()
		var issued struct {
			Auth struct {
				Accessor string `json:"accessor"`
			} `json:"auth"`
		}
		if readErr != nil || json.Unmarshal(contents, &issued) != nil || issued.Auth.Accessor == "" {
			response.WriteHeader(http.StatusBadGateway)
			return
		}
		proxy.mu.Lock()
		proxy.accessor = issued.Auth.Accessor
		proxy.mu.Unlock()
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(upstream.StatusCode)
		_, _ = response.Write(contents)
		return
	}
	if request.URL.Path != "/v1/transit/keys/build-evidence" && request.URL.Path != "/v1/transit/sign/build-evidence" && request.URL.Path != "/v1/auth/token/revoke-self" {
		response.WriteHeader(http.StatusNotFound)
		return
	}
	contents, err := io.ReadAll(io.LimitReader(request.Body, 2<<20))
	if err != nil {
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	upstreamRequest, err := http.NewRequestWithContext(request.Context(), request.Method, proxy.origin+request.URL.Path, bytes.NewReader(contents))
	if err != nil {
		response.WriteHeader(http.StatusBadGateway)
		return
	}
	upstreamRequest.Header.Set("Accept", "application/json")
	upstreamRequest.Header.Set("Content-Type", "application/json")
	upstreamRequest.Header.Set("X-Vault-Token", request.Header.Get("X-Vault-Token"))
	upstream, err := proxy.client.Do(upstreamRequest)
	if err != nil {
		response.WriteHeader(http.StatusBadGateway)
		return
	}
	defer upstream.Body.Close()
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(upstream.StatusCode)
	_, _ = io.Copy(response, io.LimitReader(upstream.Body, 2<<20))
}

func (proxy *openBaoLoginProxy) request(ctx context.Context, method, path, token string, body any) *http.Response {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil
	}
	request, err := http.NewRequestWithContext(ctx, method, proxy.origin+path, bytes.NewReader(encoded))
	if err != nil {
		return nil
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Vault-Token", token)
	response, err := proxy.client.Do(request)
	if err != nil {
		return nil
	}
	return response
}

func (proxy *openBaoLoginProxy) tokenAccessor() string {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	return proxy.accessor
}

func startOpenBaoIntegration(t *testing.T, ctx context.Context) (string, string) {
	t.Helper()
	random := make([]byte, 24)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	rootToken := hex.EncodeToString(random)
	name := fmt.Sprintf("lrail-wp040-openbao-%d", os.Getpid())
	_, _ = exec.CommandContext(context.Background(), "docker", "rm", "-f", name).CombinedOutput()
	t.Cleanup(func() { _, _ = exec.Command("docker", "rm", "-f", name).CombinedOutput() })
	output, err := exec.CommandContext(ctx, "docker", "run", "-d", "--name", name, "-p", "127.0.0.1::8200",
		"-e", "BAO_DEV_ROOT_TOKEN_ID="+rootToken, "-e", "BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200", "-e", "BAO_LOG_LEVEL=error",
		openBaoIntegrationImage, "server", "-dev").CombinedOutput()
	if err != nil {
		t.Fatalf("start pinned OpenBao: %v: %s", err, output)
	}
	portOutput, err := exec.CommandContext(ctx, "docker", "port", name, "8200/tcp").CombinedOutput()
	if err != nil {
		t.Fatalf("resolve OpenBao port: %v: %s", err, portOutput)
	}
	_, port, err := net.SplitHostPort(strings.TrimSpace(string(portOutput)))
	if err != nil {
		t.Fatalf("parse OpenBao port: %v", err)
	}
	origin := "http://127.0.0.1:" + port
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/v1/sys/health", nil)
		response, requestErr := client.Do(request)
		if requestErr == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return origin, rootToken
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal("pinned OpenBao did not become ready")
	return "", ""
}

func openBaoIntegrationRequest(t *testing.T, ctx context.Context, client *http.Client, origin, token, method, path string, body any, expected int) {
	t.Helper()
	response := openBaoIntegrationRaw(t, ctx, client, origin, token, method, path, body)
	defer response.Body.Close()
	if response.StatusCode != expected {
		contents, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		t.Fatalf("OpenBao %s status=%d body=%s", path, response.StatusCode, contents)
	}
}

func openBaoIntegrationRaw(t *testing.T, ctx context.Context, client *http.Client, origin, token, method, path string, body any) *http.Response {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(ctx, method, origin+path, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Vault-Token", token)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
