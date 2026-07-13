package providerfetch

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourceauth"
)

// BrokerTokenSource exchanges a short-lived signed fetch grant for one repository-scoped installation token.
type BrokerTokenSource struct {
	BaseURL  *url.URL
	Client   HTTPDoer
	GrantKey []byte
	Now      func() time.Time
}

func (source *BrokerTokenSource) Token(ctx context.Context, grant sourceauth.FetchGrant) (Token, error) {
	if source == nil || source.BaseURL == nil || source.Client == nil || len(source.GrantKey) < 32 {
		return Token{}, errors.New("provider token broker configuration is incomplete")
	}
	now := source.now()
	grantToken, err := sourceauth.SignFetchGrantAt(source.GrantKey, grant, now)
	if err != nil {
		return Token{}, err
	}
	endpoint, err := githubURL(source.BaseURL, "v1", "github", "tokens")
	if err != nil {
		return Token{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), nil)
	if err != nil {
		return Token{}, fmt.Errorf("create provider broker request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+grantToken)
	request.Header.Set("User-Agent", githubUserAgent)
	response, err := source.Client.Do(request)
	if err != nil {
		return Token{}, ErrProviderUnavailable
	}
	if response.StatusCode != http.StatusCreated {
		closeResponse(response)
		switch response.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusUnprocessableEntity:
			return Token{}, ErrProviderAuthentication
		default:
			return Token{}, ErrProviderUnavailable
		}
	}
	var payload struct {
		Token      string    `json:"token"`
		ExpiresAt  time.Time `json:"expires_at"`
		Repository string    `json:"repository"`
	}
	if err := decodeJSON(response, 16<<10, &payload); err != nil {
		return Token{}, ErrProviderUnavailable
	}
	if len(payload.Token) < 20 || len(payload.Token) > 4096 || strings.ContainsAny(payload.Token, "\r\n\t ") ||
		!payload.ExpiresAt.After(now.Add(5*time.Minute)) || payload.ExpiresAt.After(now.Add(2*time.Hour)) ||
		!strings.EqualFold(payload.Repository, grant.Repository) {
		return Token{}, ErrProviderAuthentication
	}
	return Token{Value: payload.Token, ExpiresAt: payload.ExpiresAt.UTC()}, nil
}

func (source *BrokerTokenSource) now() time.Time {
	if source.Now != nil {
		return source.Now().UTC()
	}
	return time.Now().UTC()
}
