package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/objectstore"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourcearchive"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourceauth"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourceupload"
)

func TestSessionRequiresGrantAndReturnsBoundedPartURLs(t *testing.T) {
	t.Parallel()
	api, key, grant, store := testAPI(t)
	server := httptest.NewServer(api.Handler())
	defer server.Close()

	unauthorized, err := http.Post(server.URL+"/v1/sessions", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.StatusCode)
	}

	response := authorizedRequest(t, http.MethodPost, server.URL+"/v1/sessions", nil, key, grant)
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("session status = %d, body = %s", response.StatusCode, readBody(response))
	}
	var body struct {
		SessionID string                       `json:"session_id"`
		Parts     []sourceupload.PresignedPart `json:"parts"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.SessionID != grant.SessionID || len(body.Parts) != grant.ExpectedParts {
		t.Fatalf("unexpected session response: %#v", body)
	}
	if store.presigned != grant.ExpectedParts || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("session security state is incomplete: count=%d headers=%v", store.presigned, response.Header)
	}
}

func TestFinalizeRejectsMalformedMetadataBeforeStorage(t *testing.T) {
	t.Parallel()
	api, key, grant, _ := testAPI(t)
	server := httptest.NewServer(api.Handler())
	defer server.Close()

	response := authorizedRequest(
		t,
		http.MethodPost,
		server.URL+"/v1/finalizations",
		bytes.NewBufferString(`{"parts":[],"unknown":true}`),
		key,
		grant,
	)
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed finalization status = %d", response.StatusCode)
	}
}

func TestReadyReflectsObjectStoreFailure(t *testing.T) {
	t.Parallel()
	api, _, _, store := testAPI(t)
	store.readyErr = objectstore.ErrNotFound
	request := httptest.NewRequest(http.MethodGet, "/ready", nil)
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready status = %d", response.Code)
	}
}

func TestProviderFetchRequiresFetchGrantAndReturnsSignedResult(t *testing.T) {
	t.Parallel()
	api, key, uploadGrant, _ := testAPI(t)
	now := uploadGrant.ExpiresAt.Add(-15 * time.Minute)
	fetchGrant := sourceauth.FetchGrant{
		Version:            1,
		Audience:           sourceauth.Audience,
		FetchID:            "fet_019b01da-7e31-7000-8000-000000000010",
		OrganizationID:     uploadGrant.OrganizationID,
		ProjectID:          uploadGrant.ProjectID,
		CreatorID:          uploadGrant.CreatorID,
		SourceConnectionID: "src_019b01da-7e31-7000-8000-000000000011",
		Provider:           "github",
		InstallationID:     "123456",
		Repository:         "example/repository",
		CommitSHA:          strings.Repeat("a", 40),
		ExpiresAt:          now.Add(15 * time.Minute),
	}
	provider := &apiProviderFetcher{result: sourceauth.SignedFetchResult{
		KeyID: "source-test-v1",
		Result: sourceauth.FetchResult{
			Version:            1,
			FetchID:            fetchGrant.FetchID,
			OrganizationID:     fetchGrant.OrganizationID,
			ProjectID:          fetchGrant.ProjectID,
			SourceConnectionID: fetchGrant.SourceConnectionID,
			Provider:           "github",
			Repository:         fetchGrant.Repository,
			RequestedCommitSHA: fetchGrant.CommitSHA,
			ResolvedCommitSHA:  fetchGrant.CommitSHA,
		},
		Signature: "test-signature",
	}}
	api.fetcher = provider
	api.fetching = make(chan struct{}, 1)
	server := httptest.NewServer(api.Handler())
	defer server.Close()

	uploadToken, err := sourceauth.SignGrantAt(key, uploadGrant, now)
	if err != nil {
		t.Fatal(err)
	}
	wrongRequest, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/fetches", nil)
	wrongRequest.Header.Set("Authorization", "Bearer "+uploadToken)
	wrongResponse, err := http.DefaultClient.Do(wrongRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = wrongResponse.Body.Close()
	if wrongResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("upload grant authenticated fetch endpoint: %d", wrongResponse.StatusCode)
	}

	fetchToken, err := sourceauth.SignFetchGrantAt(key, fetchGrant, now)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/fetches", nil)
	request.Header.Set("Authorization", "Bearer "+fetchToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("fetch status = %d, body = %s", response.StatusCode, readBody(response))
	}
	var signed sourceauth.SignedFetchResult
	if err := json.NewDecoder(response.Body).Decode(&signed); err != nil {
		t.Fatal(err)
	}
	if provider.calls != 1 || provider.grant.FetchID != fetchGrant.FetchID || signed.Result.ResolvedCommitSHA != fetchGrant.CommitSHA {
		t.Fatalf("unexpected fetch forwarding: calls=%d grant=%#v result=%#v", provider.calls, provider.grant, signed)
	}
}

func testAPI(t *testing.T) (*API, []byte, sourceauth.UploadGrant, *apiStore) {
	t.Helper()
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	key := []byte(strings.Repeat("k", 32))
	grant := sourceauth.UploadGrant{
		Version:               1,
		Audience:              sourceauth.Audience,
		SessionID:             "upl_019b01da-7e31-7000-8000-000000000001",
		OrganizationID:        "org_019b01da-7e31-7000-8000-000000000002",
		ProjectID:             "prj_019b01da-7e31-7000-8000-000000000003",
		CreatorID:             "acct_019b01da-7e31-7000-8000-000000000004",
		ExpectedArchiveBytes:  2,
		ExpectedArchiveSHA256: "sha256:" + strings.Repeat("a", 64),
		ExpectedParts:         2,
		ExpiresAt:             now.Add(15 * time.Minute),
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := &apiStore{}
	api, err := New(Config{
		Store:    store,
		GrantKey: key,
		Finalizer: &sourceupload.Finalizer{
			Store:        store,
			ScratchDir:   t.TempDir(),
			Policy:       sourcearchive.DefaultPolicy(),
			PrivateKey:   privateKey,
			SigningKeyID: "test",
		},
		Logger:                  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:                     func() time.Time { return now },
		MaxConcurrentFinalizers: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return api, key, grant, store
}

func authorizedRequest(
	t *testing.T,
	method string,
	location string,
	body io.Reader,
	key []byte,
	grant sourceauth.UploadGrant,
) *http.Response {
	t.Helper()
	token, err := sourceauth.SignGrantAt(key, grant, grant.ExpiresAt.Add(-15*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(method, location, body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func readBody(response *http.Response) string {
	body, _ := io.ReadAll(response.Body)
	return string(body)
}

type apiStore struct {
	presigned int
	readyErr  error
}

type apiProviderFetcher struct {
	result sourceauth.SignedFetchResult
	grant  sourceauth.FetchGrant
	calls  int
}

func (fetcher *apiProviderFetcher) Fetch(_ context.Context, grant sourceauth.FetchGrant) (sourceauth.SignedFetchResult, error) {
	fetcher.calls++
	fetcher.grant = grant
	return fetcher.result, nil
}

func (store *apiStore) PresignPut(_ context.Context, key string, _ time.Duration) (*url.URL, error) {
	store.presigned++
	return url.Parse("https://objects.example.test/" + key)
}

func (*apiStore) Open(context.Context, string) (io.ReadCloser, objectstore.Info, error) {
	return nil, objectstore.Info{}, objectstore.ErrNotFound
}

func (*apiStore) PutImmutable(context.Context, string, io.Reader, int64, string, string) error {
	return nil
}

func (*apiStore) Delete(context.Context, []string) error { return nil }
func (store *apiStore) Ready(context.Context) error      { return store.readyErr }
func (*apiStore) Ref(key string) string                  { return "memory://" + key }
