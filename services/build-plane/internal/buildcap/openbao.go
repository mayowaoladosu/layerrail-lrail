// Package buildcap realizes short-lived build capabilities from owned authorities.
package buildcap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcontrol"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
)

const MaxSecretBytes = 500 * 1024
const MaxResponseBytes = 1 << 20
const DefaultRequestTimeout = 15 * time.Second

var ErrAcquisitionCleanup = errors.New("OpenBao acquisition token revocation requires retry")

type OpenBaoConfig struct {
	Address        string
	KubernetesRole string
	AuthMount      string
	KVMount        string
	SecretPrefix   string
	JWTPath        string
	RequestTimeout time.Duration
}

type OpenBaoBroker struct {
	config OpenBaoConfig
	client *http.Client
	clock  func() time.Time
	mu     sync.Mutex
	leases map[string]string
}

func NewOpenBaoBroker(config OpenBaoConfig, client *http.Client, clock func() time.Time) (*OpenBaoBroker, error) {
	address, err := url.Parse(config.Address)
	if err != nil || address.Scheme != "https" || address.Host == "" || address.Path != "" || address.RawQuery != "" || address.Fragment != "" {
		return nil, errors.New("OpenBao address must be an HTTPS origin")
	}
	for _, value := range []string{config.KubernetesRole, config.AuthMount, config.KVMount, config.SecretPrefix} {
		if !safePathComponent(value) {
			return nil, errors.New("OpenBao capability path configuration is invalid")
		}
	}
	if config.JWTPath == "" || !filepath.IsAbs(config.JWTPath) {
		return nil, errors.New("OpenBao Kubernetes JWT path must be absolute")
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = DefaultRequestTimeout
	}
	if config.RequestTimeout < time.Second || config.RequestTimeout > time.Minute {
		return nil, errors.New("OpenBao request timeout is outside bounds")
	}
	if client == nil {
		client = &http.Client{Timeout: config.RequestTimeout}
	}
	if clock == nil {
		clock = time.Now
	}
	config.Address = strings.TrimSuffix(config.Address, "/")
	return &OpenBaoBroker{config: config, client: client, clock: clock, leases: make(map[string]string)}, nil
}

func (broker *OpenBaoBroker) Acquire(ctx context.Context, assignment buildcell.VerifiedAssignment, _ uint32) (buildcontrol.CapabilityLease, error) {
	if err := assignment.Validate(); err != nil {
		return buildcontrol.CapabilityLease{}, errors.New("verified assignment proof is invalid")
	}
	jwt, err := os.ReadFile(broker.config.JWTPath)
	if err != nil || len(bytes.TrimSpace(jwt)) == 0 || len(jwt) > 1<<20 {
		return buildcontrol.CapabilityLease{}, errors.New("OpenBao Kubernetes identity is unavailable")
	}
	defer zeroBytes(jwt)
	loginBody, _ := json.Marshal(map[string]string{"role": broker.config.KubernetesRole, "jwt": string(bytes.TrimSpace(jwt))})
	defer zeroBytes(loginBody)
	var login struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			Accessor      string `json:"accessor"`
			LeaseDuration int64  `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := broker.request(ctx, http.MethodPost, "/v1/auth/"+broker.config.AuthMount+"/login", "", loginBody, &login); err != nil {
		return buildcontrol.CapabilityLease{}, err
	}
	if login.Auth.ClientToken == "" {
		return buildcontrol.CapabilityLease{}, errors.New("OpenBao returned an invalid short-lived identity")
	}
	token := login.Auth.ClientToken
	if login.Auth.Accessor == "" || login.Auth.LeaseDuration < 1 || login.Auth.LeaseDuration > int64(time.Hour/time.Second) {
		return broker.failAcquire(ctx, token, errors.New("OpenBao returned an invalid short-lived identity"))
	}
	lease := buildcontrol.CapabilityLease{
		ID: login.Auth.Accessor, ExpiresAt: broker.clock().UTC().Add(time.Duration(login.Auth.LeaseDuration) * time.Second),
		Secrets: map[string][]byte{}, Network: append([]llbcompiler.NetworkCapability(nil), assignment.Payload.Lock.Network...),
		Caches: append([]llbcompiler.CacheCapability(nil), assignment.Payload.Lock.Caches...),
	}
	assignmentExpiry, err := time.Parse(time.RFC3339, assignment.Payload.ExpiresAt)
	if err != nil {
		return broker.failAcquire(ctx, token, errors.New("assignment expiry is invalid"))
	}
	if lease.ExpiresAt.After(assignmentExpiry) {
		lease.ExpiresAt = assignmentExpiry
	}
	for _, capability := range assignment.Payload.Lock.Secrets {
		secretPath := "/v1/" + broker.config.KVMount + "/data/" + broker.config.SecretPrefix + "/" + assignment.Payload.OrganizationID + "/" + capability.Name
		var response struct {
			Data struct {
				Data struct {
					Value       string `json:"value"`
					ValueBase64 string `json:"value_base64"`
				} `json:"data"`
			} `json:"data"`
		}
		err := broker.request(ctx, http.MethodGet, secretPath, token, nil, &response)
		if err != nil {
			var statusErr *openBaoStatusError
			if !capability.Required && errors.As(err, &statusErr) && statusErr.code == http.StatusNotFound {
				continue
			}
			wipeSecrets(lease.Secrets)
			return broker.failAcquire(ctx, token, errors.New("build secret capability is unavailable"))
		}
		value, err := decodeSecret(response.Data.Data.Value, response.Data.Data.ValueBase64)
		if err != nil {
			wipeSecrets(lease.Secrets)
			return broker.failAcquire(ctx, token, err)
		}
		lease.Secrets[capability.MountID] = value
	}
	broker.mu.Lock()
	if _, duplicate := broker.leases[lease.ID]; duplicate {
		broker.mu.Unlock()
		wipeSecrets(lease.Secrets)
		return broker.failAcquire(ctx, token, errors.New("OpenBao lease accessor was reused"))
	}
	broker.mu.Unlock()
	if err := broker.revokeToken(context.WithoutCancel(ctx), token); err != nil {
		wipeSecrets(lease.Secrets)
		return broker.trackPendingToken(token, errors.New("OpenBao token revocation after secret acquisition failed"))
	}
	broker.mu.Lock()
	if _, duplicate := broker.leases[lease.ID]; duplicate {
		broker.mu.Unlock()
		wipeSecrets(lease.Secrets)
		return buildcontrol.CapabilityLease{}, errors.New("OpenBao lease accessor was reused")
	}
	broker.leases[lease.ID] = ""
	broker.mu.Unlock()
	return lease, nil
}

func (broker *OpenBaoBroker) Revoke(ctx context.Context, lease buildcontrol.CapabilityLease) error {
	if lease.ID == "" {
		return errors.New("OpenBao lease identity is empty")
	}
	broker.mu.Lock()
	token, exists := broker.leases[lease.ID]
	broker.mu.Unlock()
	if !exists {
		return errors.New("OpenBao lease is unknown or already revoked")
	}
	if token == "" {
		broker.mu.Lock()
		delete(broker.leases, lease.ID)
		broker.mu.Unlock()
		return nil
	}
	if err := broker.revokeToken(ctx, token); err != nil {
		return err
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	if current, exists := broker.leases[lease.ID]; !exists || current != token {
		return errors.New("OpenBao lease changed during revocation")
	}
	delete(broker.leases, lease.ID)
	return nil
}

func (broker *OpenBaoBroker) failAcquire(ctx context.Context, token string, acquireErr error) (buildcontrol.CapabilityLease, error) {
	revokeErr := broker.revokeToken(context.WithoutCancel(ctx), token)
	if revokeErr == nil {
		return buildcontrol.CapabilityLease{}, acquireErr
	}
	return broker.trackPendingToken(token, acquireErr)
}

func (broker *OpenBaoBroker) trackPendingToken(token string, acquireErr error) (buildcontrol.CapabilityLease, error) {
	tokenDigest := sha256.Sum256([]byte(token))
	lease := buildcontrol.CapabilityLease{ID: "pending-" + hex.EncodeToString(tokenDigest[:16])}
	broker.mu.Lock()
	existing, duplicate := broker.leases[lease.ID]
	if !duplicate {
		broker.leases[lease.ID] = token
	}
	broker.mu.Unlock()
	if duplicate && existing != token {
		return buildcontrol.CapabilityLease{}, errors.Join(acquireErr, errors.New("OpenBao pending cleanup identity conflicts"))
	}
	return lease, errors.Join(acquireErr, ErrAcquisitionCleanup)
}

func (broker *OpenBaoBroker) revokeToken(ctx context.Context, token string) error {
	return broker.request(ctx, http.MethodPost, "/v1/auth/token/revoke-self", token, []byte(`{}`), nil)
}

func (broker *OpenBaoBroker) request(ctx context.Context, method, requestPath, token string, body []byte, destination any) error {
	requestContext, cancel := context.WithTimeout(ctx, broker.config.RequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, method, broker.config.Address+requestPath, bytes.NewReader(body))
	if err != nil {
		return errors.New("create OpenBao request")
	}
	request.Header.Set("Accept", "application/json")
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("X-Vault-Token", token)
	}
	response, err := broker.client.Do(request)
	if err != nil {
		return errors.New("OpenBao request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, MaxResponseBytes))
		return &openBaoStatusError{code: response.StatusCode}
	}
	if destination == nil {
		read, err := io.Copy(io.Discard, io.LimitReader(response.Body, MaxResponseBytes+1))
		if err != nil || read > MaxResponseBytes {
			return errors.New("OpenBao response is unreadable or oversized")
		}
		return nil
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err := decoder.Decode(destination); err != nil {
		return errors.New("OpenBao returned malformed capability data")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("OpenBao returned trailing capability data")
	}
	return nil
}

type openBaoStatusError struct {
	code int
}

func (failure *openBaoStatusError) Error() string {
	return "OpenBao denied the capability request"
}

func decodeSecret(value, valueBase64 string) ([]byte, error) {
	if (value == "") == (valueBase64 == "") {
		return nil, errors.New("OpenBao secret must contain exactly one value encoding")
	}
	var result []byte
	if valueBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(valueBase64)
		if err != nil {
			return nil, errors.New("OpenBao secret base64 is invalid")
		}
		result = decoded
	} else {
		result = []byte(value)
	}
	if len(result) == 0 || len(result) > MaxSecretBytes {
		zeroBytes(result)
		return nil, errors.New("OpenBao secret size is outside bounds")
	}
	return result, nil
}

func safePathComponent(value string) bool {
	return value != "" && len(value) <= 128 && !strings.ContainsAny(value, `/\\.`) && value != ".."
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func wipeSecrets(values map[string][]byte) {
	for key, value := range values {
		zeroBytes(value)
		delete(values, key)
	}
}
