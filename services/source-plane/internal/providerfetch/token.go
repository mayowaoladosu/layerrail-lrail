package providerfetch

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourceauth"
)

type Token struct {
	Value     string
	ExpiresAt time.Time
}

type TokenSource interface {
	Token(ctx context.Context, grant sourceauth.FetchGrant) (Token, error)
}

type GitHubAppTokenSource struct {
	BaseURL    *url.URL
	Client     HTTPDoer
	AppID      string
	PrivateKey *rsa.PrivateKey
	Now        func() time.Time
}

func (source *GitHubAppTokenSource) Token(
	ctx context.Context,
	grant sourceauth.FetchGrant,
) (Token, error) {
	if source == nil || source.BaseURL == nil || source.Client == nil || source.AppID == "" ||
		source.PrivateKey == nil || source.PrivateKey.N.BitLen() < 2048 {
		return Token{}, errors.New("GitHub App token source configuration is incomplete")
	}
	parts := strings.Split(grant.Repository, "/")
	if len(parts) != 2 || parts[1] == "" {
		return Token{}, ErrInvalidRequest
	}
	appJWT, err := source.appJWT()
	if err != nil {
		return Token{}, err
	}
	endpoint, err := githubURL(source.BaseURL, "app", "installations", grant.InstallationID, "access_tokens")
	if err != nil {
		return Token{}, err
	}
	request, err := newGitHubRequest(http.MethodPost, endpoint, appJWT, map[string]any{
		"repositories": []string{parts[1]},
		"permissions":  map[string]string{"contents": "read"},
	})
	if err != nil {
		return Token{}, err
	}
	request = request.WithContext(ctx)
	response, err := source.Client.Do(request)
	if err != nil {
		return Token{}, fmt.Errorf("%w: issue installation token", ErrProviderUnavailable)
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
		Token       string    `json:"token"`
		ExpiresAt   time.Time `json:"expires_at"`
		Permissions struct {
			Contents string `json:"contents"`
		} `json:"permissions"`
		Repositories []struct {
			FullName string `json:"full_name"`
		} `json:"repositories"`
	}
	if err := decodeJSON(response, 1<<20, &payload); err != nil {
		return Token{}, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	now := source.now()
	repositoryNames := make([]string, 0, len(payload.Repositories))
	for _, value := range payload.Repositories {
		repositoryNames = append(repositoryNames, strings.ToLower(value.FullName))
	}
	if len(payload.Token) < 20 || len(payload.Token) > 4096 || strings.ContainsAny(payload.Token, "\r\n\t ") ||
		!payload.ExpiresAt.After(now.Add(5*time.Minute)) || payload.ExpiresAt.After(now.Add(2*time.Hour)) ||
		payload.Permissions.Contents != "read" || !slices.Contains(repositoryNames, strings.ToLower(grant.Repository)) {
		return Token{}, ErrProviderAuthentication
	}
	return Token{Value: payload.Token, ExpiresAt: payload.ExpiresAt.UTC()}, nil
}

func (source *GitHubAppTokenSource) appJWT() (string, error) {
	now := source.now()
	header, err := json.Marshal(struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}{Algorithm: "RS256", Type: "JWT"})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(struct {
		IssuedAt  int64  `json:"iat"`
		ExpiresAt int64  `json:"exp"`
		Issuer    string `json:"iss"`
	}{
		IssuedAt:  now.Add(-60 * time.Second).Unix(),
		ExpiresAt: now.Add(9 * time.Minute).Unix(),
		Issuer:    source.AppID,
	})
	if err != nil {
		return "", err
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claims)
	message := encodedHeader + "." + encodedClaims
	digest := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, source.PrivateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign GitHub App JWT: %w", err)
	}
	return message + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (source *GitHubAppTokenSource) now() time.Time {
	if source.Now != nil {
		return source.Now().UTC()
	}
	return time.Now().UTC()
}
