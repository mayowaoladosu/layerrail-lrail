// Package providerbroker holds reusable provider app credentials and issues repository-scoped tokens.
package providerbroker

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/providerfetch"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourceauth"
)

type API struct {
	grantKey []byte
	tokens   providerfetch.TokenSource
	now      func() time.Time
	issuing  chan struct{}
}

type Config struct {
	GrantKey            []byte
	Tokens              providerfetch.TokenSource
	Now                 func() time.Time
	MaxConcurrentIssues int
}

func New(config Config) (*API, error) {
	if len(config.GrantKey) < 32 || config.Tokens == nil ||
		config.MaxConcurrentIssues < 1 || config.MaxConcurrentIssues > 64 {
		return nil, errors.New("provider token broker configuration is incomplete")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &API{
		grantKey: append([]byte(nil), config.GrantKey...),
		tokens:   config.Tokens,
		now:      config.Now,
		issuing:  make(chan struct{}, config.MaxConcurrentIssues),
	}, nil
}

func (api *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /live", api.live)
	mux.HandleFunc("GET /ready", api.live)
	mux.HandleFunc("POST /v1/github/tokens", api.issueGitHubToken)
	return api.securityHeaders(mux)
}

func (api *API) live(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]string{"status": "ready"})
}

func (api *API) issueGitHubToken(response http.ResponseWriter, request *http.Request) {
	grant, ok := api.authenticate(response, request)
	if !ok {
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, 1)
	if count, err := io.Copy(io.Discard, request.Body); err != nil || count != 0 {
		writeError(response, http.StatusBadRequest, "invalid_request", "Provider token requests do not accept a body.")
		return
	}
	select {
	case api.issuing <- struct{}{}:
		defer func() { <-api.issuing }()
	default:
		response.Header().Set("Retry-After", "2")
		writeError(response, http.StatusTooManyRequests, "broker_busy", "Provider token capacity is busy.")
		return
	}
	token, err := api.tokens.Token(request.Context(), grant)
	if err != nil {
		switch {
		case errors.Is(err, providerfetch.ErrProviderAuthentication):
			writeError(response, http.StatusUnprocessableEntity, "provider_authentication_failed", "The provider installation cannot access this repository.")
		default:
			writeError(response, http.StatusServiceUnavailable, "provider_unavailable", "The provider token broker is temporarily unavailable.")
		}
		return
	}
	writeJSON(response, http.StatusCreated, map[string]any{
		"token":      token.Value,
		"expires_at": token.ExpiresAt,
		"repository": strings.ToLower(grant.Repository),
	})
}

func (api *API) authenticate(response http.ResponseWriter, request *http.Request) (sourceauth.FetchGrant, bool) {
	authorization := request.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") || len(authorization) > 8192 {
		writeError(response, http.StatusUnauthorized, "invalid_grant", "Provider token grant is invalid or expired.")
		return sourceauth.FetchGrant{}, false
	}
	grant, err := sourceauth.VerifyFetchGrant(api.grantKey, strings.TrimPrefix(authorization, "Bearer "), api.now().UTC())
	if err != nil {
		writeError(response, http.StatusUnauthorized, "invalid_grant", "Provider token grant is invalid or expired.")
		return sourceauth.FetchGrant{}, false
	}
	return grant, true
}

func (api *API) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(response, request)
	})
}

func writeError(response http.ResponseWriter, status int, code string, message string) {
	writeJSON(response, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func writeJSON(response http.ResponseWriter, status int, body any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(body)
}
