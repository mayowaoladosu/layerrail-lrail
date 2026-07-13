package buildsigning

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildsupply"
)

const maxOpenBaoResponseBytes int64 = 1 << 20

var signingNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,127}$`)

type OpenBaoConfig struct {
	Address        string
	KubernetesRole string
	AuthMount      string
	TransitMount   string
	KeyName        string
	KeyID          string
	JWTPath        string
	RequestTimeout time.Duration
	MaxTokenTTL    time.Duration
}

type OpenBaoAuthority struct {
	config OpenBaoConfig
	http   *http.Client
}

func NewOpenBaoAuthority(config OpenBaoConfig, client *http.Client) (*OpenBaoAuthority, error) {
	address, err := url.Parse(strings.TrimSpace(config.Address))
	if err != nil || address.Scheme != "https" || address.Host == "" || address.Path != "" || address.RawQuery != "" || address.Fragment != "" || address.User != nil {
		return nil, errors.New("OpenBao signing address must be an HTTPS origin")
	}
	for _, value := range []string{config.KubernetesRole, config.AuthMount, config.TransitMount, config.KeyName, config.KeyID} {
		if !signingNamePattern.MatchString(value) {
			return nil, errors.New("OpenBao signing path identity is invalid")
		}
	}
	if !filepath.IsAbs(config.JWTPath) {
		return nil, errors.New("OpenBao signing Kubernetes JWT path must be absolute")
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 20 * time.Second
	}
	if config.MaxTokenTTL == 0 {
		config.MaxTokenTTL = 5 * time.Minute
	}
	if config.RequestTimeout < time.Second || config.RequestTimeout > time.Minute || config.MaxTokenTTL < time.Minute || config.MaxTokenTTL > 10*time.Minute || client == nil {
		return nil, errors.New("OpenBao signing time or HTTP configuration is invalid")
	}
	configured := *client
	if configured.Timeout == 0 {
		configured.Timeout = config.RequestTimeout
	}
	if configured.Timeout < time.Second || configured.Timeout > time.Minute {
		return nil, errors.New("OpenBao signing HTTP timeout is outside bounds")
	}
	configured.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	config.Address = strings.TrimSuffix(config.Address, "/")
	return &OpenBaoAuthority{config: config, http: &configured}, nil
}

func (authority *OpenBaoAuthority) Sign(ctx context.Context, payload []byte) (material Material, resultErr error) {
	if len(payload) == 0 || len(payload) > buildsupply.MaxEvidenceBytes {
		return Material{}, errors.New("OpenBao signing payload is absent or oversized")
	}
	jwt, err := os.ReadFile(authority.config.JWTPath)
	if err != nil || len(bytes.TrimSpace(jwt)) == 0 || len(jwt) > 1<<20 {
		zeroBytes(jwt)
		return Material{}, errors.New("OpenBao signing Kubernetes identity is unavailable")
	}
	defer zeroBytes(jwt)
	loginBody, err := json.Marshal(map[string]string{"role": authority.config.KubernetesRole, "jwt": string(bytes.TrimSpace(jwt))})
	if err != nil {
		return Material{}, errors.New("encode OpenBao signing login")
	}
	defer zeroBytes(loginBody)
	var login struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			Accessor      string `json:"accessor"`
			LeaseDuration int64  `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := authority.request(ctx, http.MethodPost, "/v1/auth/"+authority.config.AuthMount+"/login", nil, loginBody, &login); err != nil {
		return Material{}, err
	}
	token := []byte(login.Auth.ClientToken)
	login.Auth.ClientToken = ""
	if len(token) == 0 || len(token) > 4096 {
		zeroBytes(token)
		return Material{}, errors.New("OpenBao returned invalid signing identity")
	}
	defer func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), authority.config.RequestTimeout)
		defer cancel()
		revokeErr := authority.request(cleanupContext, http.MethodPost, "/v1/auth/token/revoke-self", token, []byte(`{}`), nil)
		zeroBytes(token)
		if revokeErr != nil {
			material = Material{}
			resultErr = errors.Join(resultErr, errors.New("OpenBao signing token revocation failed"))
		}
	}()
	if login.Auth.Accessor == "" || login.Auth.LeaseDuration < 1 || time.Duration(login.Auth.LeaseDuration)*time.Second > authority.config.MaxTokenTTL {
		return Material{}, errors.New("OpenBao returned invalid signing identity")
	}
	var keyResponse struct {
		Data struct {
			Type                 string `json:"type"`
			Derived              bool   `json:"derived"`
			Exportable           bool   `json:"exportable"`
			AllowPlaintextBackup bool   `json:"allow_plaintext_backup"`
			DeletionAllowed      bool   `json:"deletion_allowed"`
			SupportsSigning      bool   `json:"supports_signing"`
			LatestVersion        int    `json:"latest_version"`
			Keys                 map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	keyPath := "/v1/" + authority.config.TransitMount + "/keys/" + authority.config.KeyName
	if err := authority.request(ctx, http.MethodGet, keyPath, token, nil, &keyResponse); err != nil {
		return Material{}, err
	}
	key := keyResponse.Data
	versionKey := strconv.Itoa(key.LatestVersion)
	publicPEM := []byte(key.Keys[versionKey].PublicKey)
	if key.Type != "ed25519" || key.Derived || key.Exportable || key.AllowPlaintextBackup || key.DeletionAllowed || !key.SupportsSigning ||
		key.LatestVersion < 1 || len(publicPEM) == 0 || len(publicPEM) > 16<<10 {
		return Material{}, errors.New("OpenBao signing key policy is unsafe")
	}
	signBody, err := json.Marshal(map[string]any{
		"input": base64.StdEncoding.EncodeToString(payload), "key_version": key.LatestVersion,
	})
	if err != nil {
		return Material{}, errors.New("encode OpenBao signing request")
	}
	defer zeroBytes(signBody)
	var signResponse struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := authority.request(ctx, http.MethodPost, "/v1/"+authority.config.TransitMount+"/sign/"+authority.config.KeyName, token, signBody, &signResponse); err != nil {
		return Material{}, err
	}
	signature, version, err := decodeOpenBaoSignature(signResponse.Data.Signature)
	if err != nil || version != key.LatestVersion {
		zeroBytes(signature)
		return Material{}, errors.New("OpenBao signing response identity is invalid")
	}
	if _, err := buildsupply.VerifySignature(publicPEM, payload, signature); err != nil {
		zeroBytes(signature)
		return Material{}, errors.New("OpenBao signing response could not be verified")
	}
	return Material{
		KeyID: authority.config.KeyID, KeyVersion: key.LatestVersion, Algorithm: buildsupply.SignatureAlgorithm,
		PublicKeyPEM: append([]byte(nil), publicPEM...), Signature: signature,
	}, nil
}

func (authority *OpenBaoAuthority) request(ctx context.Context, method, requestPath string, token, body []byte, destination any) error {
	requestContext, cancel := context.WithTimeout(ctx, authority.config.RequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, method, authority.config.Address+requestPath, bytes.NewReader(body))
	if err != nil {
		return errors.New("create OpenBao signing request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	if len(token) > 0 {
		request.Header.Set("X-Vault-Token", string(token))
	}
	response, err := authority.http.Do(request)
	if err != nil {
		return errors.New("OpenBao signing request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxOpenBaoResponseBytes))
		return errors.New("OpenBao denied signing request")
	}
	if destination == nil {
		read, err := io.Copy(io.Discard, io.LimitReader(response.Body, maxOpenBaoResponseBytes+1))
		if err != nil || read > maxOpenBaoResponseBytes {
			return errors.New("OpenBao signing response is oversized")
		}
		return nil
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxOpenBaoResponseBytes+1))
	if err := decoder.Decode(destination); err != nil {
		return errors.New("OpenBao signing response is malformed")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("OpenBao signing response has trailing data")
	}
	return nil
}

func decodeOpenBaoSignature(value string) ([]byte, int, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 3 || parts[0] != "vault" || !strings.HasPrefix(parts[1], "v") {
		return nil, 0, errors.New("OpenBao signature envelope is invalid")
	}
	version, err := strconv.Atoi(strings.TrimPrefix(parts[1], "v"))
	decoded, decodeErr := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || decodeErr != nil || version < 1 || len(decoded) != ed25519.SignatureSize {
		zeroBytes(decoded)
		return nil, 0, errors.New("OpenBao signature value is invalid")
	}
	return decoded, version, nil
}

func zeroBytes(contents []byte) {
	for index := range contents {
		contents[index] = 0
	}
}

var _ Authority = (*OpenBaoAuthority)(nil)
