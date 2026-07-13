package providerfetch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const (
	githubAPIVersion = "2022-11-28"
	githubUserAgent  = "LayerRail-Source-Gateway/1"
	maxJSONBody      = 32 << 20
)

type HTTPDoer interface {
	Do(request *http.Request) (*http.Response, error)
}

func githubURL(base *url.URL, segments ...string) (*url.URL, error) {
	if base == nil {
		return nil, ErrInvalidRequest
	}
	location, err := url.JoinPath(base.String(), segments...)
	if err != nil {
		return nil, fmt.Errorf("join provider URL: %w", err)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("parse provider URL: %w", err)
	}
	return parsed, nil
}

func newGitHubRequest(method string, endpoint *url.URL, authorization string, body any) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode provider request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, endpoint.String(), reader)
	if err != nil {
		return nil, fmt.Errorf("create provider request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	request.Header.Set("User-Agent", githubUserAgent)
	request.Header.Set("Authorization", "Bearer "+authorization)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return request, nil
}

func decodeJSON(response *http.Response, limit int64, target any) error {
	defer response.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(response.Body, limit+1))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode provider response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("provider response contains trailing data")
	}
	return nil
}

func closeResponse(response *http.Response) {
	if response == nil || response.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	_ = response.Body.Close()
}
