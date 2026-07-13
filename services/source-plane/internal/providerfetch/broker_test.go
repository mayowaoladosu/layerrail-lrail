package providerfetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourceauth"
)

func TestBrokerTokenSourceForwardsOnlySignedFetchScope(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 13, 3, 0, 0, 0, time.UTC)
	grantKey := []byte(strings.Repeat("g", 32))
	grant := conformanceGrant(now, strings.Repeat("a", 40), "020")
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls++
		if request.Method != http.MethodPost || request.URL.Path != "/v1/github/tokens" || request.ContentLength > 0 {
			http.Error(response, "invalid request", http.StatusBadRequest)
			return
		}
		token := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
		verified, err := sourceauth.VerifyFetchGrant(grantKey, token, now)
		if err != nil || verified.FetchID != grant.FetchID || verified.Repository != grant.Repository {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeTestJSON(response, http.StatusCreated, map[string]any{
			"token":      "ghs_repository_scoped_token_value_123456",
			"expires_at": now.Add(time.Hour),
			"repository": strings.ToLower(grant.Repository),
		})
	}))
	defer server.Close()
	baseURL, _ := url.Parse(server.URL)
	source := &BrokerTokenSource{
		BaseURL:  baseURL,
		Client:   server.Client(),
		GrantKey: grantKey,
		Now:      func() time.Time { return now },
	}

	token, err := source.Token(requestContext(t), grant)
	if err != nil {
		t.Fatal(err)
	}
	if token.Value != "ghs_repository_scoped_token_value_123456" || token.ExpiresAt != now.Add(time.Hour) || calls != 1 {
		t.Fatalf("unexpected broker token: %#v calls=%d", token, calls)
	}
}

func requestContext(t *testing.T) context.Context {
	t.Helper()
	return context.Background()
}
