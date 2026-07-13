package providerbroker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/providerfetch"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourceauth"
)

func TestBrokerRequiresFetchGrantAndIssuesScopedToken(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 13, 3, 0, 0, 0, time.UTC)
	key := []byte(strings.Repeat("b", 32))
	grant := sourceauth.FetchGrant{
		Version:            1,
		Audience:           sourceauth.Audience,
		FetchID:            "fet_019b01da-7e31-7000-8000-000000000030",
		OrganizationID:     "org_019b01da-7e31-7000-8000-000000000031",
		ProjectID:          "prj_019b01da-7e31-7000-8000-000000000032",
		CreatorID:          "acct_019b01da-7e31-7000-8000-000000000033",
		SourceConnectionID: "src_019b01da-7e31-7000-8000-000000000034",
		Provider:           "github",
		InstallationID:     "123456",
		Repository:         "example/repository",
		CommitSHA:          strings.Repeat("a", 40),
		ExpiresAt:          now.Add(15 * time.Minute),
	}
	tokens := &recordingTokenSource{token: providerfetch.Token{
		Value:     "ghs_repository_scoped_token_value_123456",
		ExpiresAt: now.Add(time.Hour),
	}}
	api, err := New(Config{GrantKey: key, Tokens: tokens, Now: func() time.Time { return now }, MaxConcurrentIssues: 1})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api.Handler())
	defer server.Close()

	unauthorized, err := http.Post(server.URL+"/v1/github/tokens", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.StatusCode)
	}

	token, err := sourceauth.SignFetchGrantAt(key, grant, now)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/github/tokens", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("token response status=%d headers=%v", response.StatusCode, response.Header)
	}
	var body struct {
		Token      string    `json:"token"`
		ExpiresAt  time.Time `json:"expires_at"`
		Repository string    `json:"repository"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if tokens.calls != 1 || tokens.grant.FetchID != grant.FetchID || body.Token != tokens.token.Value || body.Repository != "example/repository" {
		t.Fatalf("unexpected broker response: body=%#v calls=%d grant=%#v", body, tokens.calls, tokens.grant)
	}
}

type recordingTokenSource struct {
	token providerfetch.Token
	grant sourceauth.FetchGrant
	calls int
}

func (source *recordingTokenSource) Token(_ context.Context, grant sourceauth.FetchGrant) (providerfetch.Token, error) {
	source.calls++
	source.grant = grant
	return source.token, nil
}
