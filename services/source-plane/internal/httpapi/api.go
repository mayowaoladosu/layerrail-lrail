// Package httpapi exposes the authenticated source upload and finalization gateway.
package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/objectstore"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/providerfetch"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourcearchive"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourceauth"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourceupload"
)

const maxFinalizeBody = 64 << 10

type API struct {
	store      objectstore.Store
	grantKey   []byte
	finalizer  *sourceupload.Finalizer
	logger     *slog.Logger
	now        func() time.Time
	finalizing chan struct{}
	fetcher    ProviderFetcher
	fetching   chan struct{}
}

type ProviderFetcher interface {
	Fetch(context.Context, sourceauth.FetchGrant) (sourceauth.SignedFetchResult, error)
}

type Config struct {
	Store                   objectstore.Store
	GrantKey                []byte
	Finalizer               *sourceupload.Finalizer
	Logger                  *slog.Logger
	Now                     func() time.Time
	MaxConcurrentFinalizers int
	ProviderFetcher         ProviderFetcher
	MaxConcurrentFetchers   int
}

func New(config Config) (*API, error) {
	if config.Store == nil || len(config.GrantKey) < 32 || config.Finalizer == nil {
		return nil, errors.New("source HTTP API configuration is incomplete")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.MaxConcurrentFinalizers < 1 || config.MaxConcurrentFinalizers > 64 {
		return nil, errors.New("source finalizer concurrency is outside bounds")
	}
	if config.ProviderFetcher != nil && (config.MaxConcurrentFetchers < 1 || config.MaxConcurrentFetchers > 64) {
		return nil, errors.New("source fetcher concurrency is outside bounds")
	}
	maxFetchers := config.MaxConcurrentFetchers
	if maxFetchers < 1 {
		maxFetchers = 1
	}
	return &API{
		store:      config.Store,
		grantKey:   append([]byte(nil), config.GrantKey...),
		finalizer:  config.Finalizer,
		logger:     config.Logger,
		now:        config.Now,
		finalizing: make(chan struct{}, config.MaxConcurrentFinalizers),
		fetcher:    config.ProviderFetcher,
		fetching:   make(chan struct{}, maxFetchers),
	}, nil
}

func (api *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /live", api.live)
	mux.HandleFunc("GET /ready", api.ready)
	mux.HandleFunc("POST /v1/sessions", api.createSession)
	mux.HandleFunc("POST /v1/finalizations", api.finalize)
	mux.HandleFunc("POST /v1/fetches", api.fetch)
	return api.securityHeaders(mux)
}

func (api *API) fetch(response http.ResponseWriter, request *http.Request) {
	grant, ok := api.authenticateFetch(response, request)
	if !ok {
		return
	}
	if api.fetcher == nil {
		writeError(response, http.StatusServiceUnavailable, "provider_unavailable", "Provider fetching is not configured.")
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, 1)
	if count, err := io.Copy(io.Discard, request.Body); err != nil || count != 0 {
		writeError(response, http.StatusBadRequest, "invalid_request", "Source fetch requests do not accept a body.")
		return
	}
	select {
	case api.fetching <- struct{}{}:
		defer func() { <-api.fetching }()
	default:
		response.Header().Set("Retry-After", "2")
		writeError(response, http.StatusTooManyRequests, "fetcher_busy", "Source fetch capacity is busy.")
		return
	}

	signed, err := api.fetcher.Fetch(request.Context(), grant)
	if err != nil {
		switch {
		case errors.Is(err, providerfetch.ErrProviderAuthentication):
			writeError(response, http.StatusUnprocessableEntity, "provider_authentication_failed", "The provider installation cannot access this repository.")
		case errors.Is(err, providerfetch.ErrReferenceNotFound):
			writeError(response, http.StatusUnprocessableEntity, "source_ref_not_found", "The exact provider commit is unavailable.")
		case errors.Is(err, providerfetch.ErrRepositoryPolicy), errors.Is(err, providerfetch.ErrSubmoduleUnsupported),
			errors.Is(err, providerfetch.ErrLFSUnsupported), errors.Is(err, sourcearchive.ErrPathUnsafe),
			errors.Is(err, sourcearchive.ErrSecretMaterial):
			writeError(response, http.StatusUnprocessableEntity, "unsafe_source", "The provider source did not pass validation.")
		default:
			api.internalError(response, request, err)
		}
		return
	}
	writeJSON(response, http.StatusOK, signed)
}

func (api *API) live(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]any{"status": "live"})
}

func (api *API) ready(response http.ResponseWriter, request *http.Request) {
	if err := api.store.Ready(request.Context()); err != nil {
		api.logger.Error("source object store is not ready", "request_id", requestID(request), "error", err.Error())
		writeError(response, http.StatusServiceUnavailable, "not_ready", "Source storage is not ready.")
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"status": "ready"})
}

func (api *API) createSession(response http.ResponseWriter, request *http.Request) {
	grant, ok := api.authenticate(response, request)
	if !ok {
		return
	}
	parts, err := sourceupload.PresignParts(request.Context(), api.store, grant, api.now().UTC())
	if err != nil {
		api.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusCreated, map[string]any{
		"session_id": grant.SessionID,
		"expires_at": grant.ExpiresAt,
		"parts":      parts,
	})
}

type finalizeRequest struct {
	Parts []sourceupload.Part `json:"parts"`
}

func (api *API) finalize(response http.ResponseWriter, request *http.Request) {
	grant, ok := api.authenticate(response, request)
	if !ok {
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(response, http.StatusUnsupportedMediaType, "unsupported_media_type", "Finalization metadata must be JSON.")
		return
	}
	select {
	case api.finalizing <- struct{}{}:
		defer func() { <-api.finalizing }()
	default:
		response.Header().Set("Retry-After", "2")
		writeError(response, http.StatusTooManyRequests, "finalizer_busy", "Source finalization capacity is busy.")
		return
	}

	var input finalizeRequest
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, maxFinalizeBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request", "Finalization metadata is invalid.")
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeError(response, http.StatusBadRequest, "invalid_request", "Finalization metadata has trailing data.")
		return
	}

	signed, err := api.finalizer.Finalize(request.Context(), grant, input.Parts)
	if err != nil {
		switch {
		case errors.Is(err, sourceupload.ErrInvalidParts), errors.Is(err, sourcearchive.ErrArchiveDigest),
			errors.Is(err, sourcearchive.ErrArchiveSize), errors.Is(err, sourcearchive.ErrArchiveFormat),
			errors.Is(err, sourcearchive.ErrEntryLimit), errors.Is(err, sourcearchive.ErrExpandedSize),
			errors.Is(err, sourcearchive.ErrCompressionRatio), errors.Is(err, sourcearchive.ErrPathUnsafe),
			errors.Is(err, sourcearchive.ErrEntryType), errors.Is(err, sourcearchive.ErrDuplicatePath),
			errors.Is(err, sourcearchive.ErrSecretMaterial):
			writeError(response, http.StatusUnprocessableEntity, "unsafe_source", "Source archive did not pass validation.")
		case errors.Is(err, objectstore.ErrNotFound):
			writeError(response, http.StatusConflict, "parts_incomplete", "One or more source parts are not available.")
		default:
			api.internalError(response, request, err)
		}
		return
	}
	writeJSON(response, http.StatusOK, signed)
}

func (api *API) authenticate(response http.ResponseWriter, request *http.Request) (sourceauth.UploadGrant, bool) {
	authorization := request.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") || len(authorization) > 8192 {
		writeError(response, http.StatusUnauthorized, "invalid_grant", "Source upload grant is invalid or expired.")
		return sourceauth.UploadGrant{}, false
	}
	grant, err := sourceauth.VerifyGrant(api.grantKey, strings.TrimPrefix(authorization, "Bearer "), api.now().UTC())
	if err != nil {
		writeError(response, http.StatusUnauthorized, "invalid_grant", "Source upload grant is invalid or expired.")
		return sourceauth.UploadGrant{}, false
	}
	return grant, true
}

func (api *API) authenticateFetch(response http.ResponseWriter, request *http.Request) (sourceauth.FetchGrant, bool) {
	authorization := request.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") || len(authorization) > 8192 {
		writeError(response, http.StatusUnauthorized, "invalid_grant", "Source fetch grant is invalid or expired.")
		return sourceauth.FetchGrant{}, false
	}
	grant, err := sourceauth.VerifyFetchGrant(api.grantKey, strings.TrimPrefix(authorization, "Bearer "), api.now().UTC())
	if err != nil {
		writeError(response, http.StatusUnauthorized, "invalid_grant", "Source fetch grant is invalid or expired.")
		return sourceauth.FetchGrant{}, false
	}
	return grant, true
}

func (api *API) internalError(response http.ResponseWriter, request *http.Request, err error) {
	api.logger.Error("source gateway request failed", "request_id", requestID(request), "error", err.Error())
	writeError(response, http.StatusInternalServerError, "internal_error", "The source gateway could not complete the request.")
}

func (api *API) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		identifier := requestID(request)
		request = request.WithContext(context.WithValue(request.Context(), requestIDContextKey{}, identifier))
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("X-Frame-Options", "DENY")
		response.Header().Set("X-Request-ID", identifier)
		next.ServeHTTP(response, request)
	})
}

func requestID(request *http.Request) string {
	if value, ok := request.Context().Value(requestIDContextKey{}).(string); ok {
		return value
	}
	value := request.Header.Get("X-Request-ID")
	if len(value) == 36 && value == strings.ToLower(value) && strings.HasPrefix(value, "req_") {
		if _, err := hex.DecodeString(strings.TrimPrefix(value, "req_")); err == nil {
			return value
		}
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "req_00000000000000000000000000000000"
	}
	return "req_" + hex.EncodeToString(random[:])
}

type requestIDContextKey struct{}

func writeError(response http.ResponseWriter, status int, code string, message string) {
	writeJSONStatus(response, status, map[string]any{"error": map[string]any{"code": code, "message": message}})
}

func writeJSON(response http.ResponseWriter, status int, body any) {
	writeJSONStatus(response, status, body)
}

func writeJSONStatus(response http.ResponseWriter, status int, body any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(body)
}
