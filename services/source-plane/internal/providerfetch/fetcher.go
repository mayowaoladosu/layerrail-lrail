package providerfetch

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/objectstore"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/snapshotstore"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourcearchive"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourceauth"
)

type Fetcher struct {
	Store               objectstore.Store
	ScratchDir          string
	Policy              sourcearchive.Policy
	Tokens              TokenSource
	Client              HTTPDoer
	BaseURL             *url.URL
	AllowedArchiveHosts []string
	PrivateKey          ed25519.PrivateKey
	SigningKeyID        string
	Now                 func() time.Time
	lockMu              sync.Mutex
	locks               map[string]*fetchLock
}

type fetchLock struct {
	mutex sync.Mutex
	users int
}

type commitResolution struct {
	SHA        string
	TreeSHA    string
	Author     string
	AuthoredAt time.Time
}

func (fetcher *Fetcher) Fetch(ctx context.Context, grant sourceauth.FetchGrant) (sourceauth.SignedFetchResult, error) {
	if err := fetcher.validateConfiguration(); err != nil {
		return sourceauth.SignedFetchResult{}, err
	}
	release := fetcher.acquire(grant.OrganizationID + "/" + grant.FetchID)
	defer release()
	if completed, found, err := fetcher.completedResult(ctx, grant); err != nil {
		return sourceauth.SignedFetchResult{}, err
	} else if found {
		return completed, nil
	}

	token, err := fetcher.Tokens.Token(ctx, grant)
	if err != nil {
		return sourceauth.SignedFetchResult{}, err
	}
	resolution, err := fetcher.resolveCommit(ctx, token.Value, grant.Repository, grant.CommitSHA)
	if err != nil {
		return sourceauth.SignedFetchResult{}, err
	}
	if resolution.SHA != grant.CommitSHA {
		return sourceauth.SignedFetchResult{}, fmt.Errorf("%w: provider resolved a different commit", ErrRepositoryPolicy)
	}
	tree, err := fetcher.resolveTree(ctx, token.Value, grant.Repository, resolution.TreeSHA)
	if err != nil {
		return sourceauth.SignedFetchResult{}, err
	}
	archiveResponse, err := fetcher.downloadArchive(ctx, token.Value, grant.Repository, resolution.SHA)
	if err != nil {
		return sourceauth.SignedFetchResult{}, err
	}
	defer archiveResponse.Body.Close()
	normalized, err := normalizeArchive(ctx, archiveResponse.Body, fetcher.ScratchDir, fetcher.Policy, tree)
	if err != nil {
		return sourceauth.SignedFetchResult{}, err
	}
	normalizedPath := normalized.File.Name()
	defer normalized.File.Close()
	defer os.Remove(normalizedPath)

	stored, err := (&snapshotstore.Writer{
		Store:      fetcher.Store,
		ScratchDir: fetcher.ScratchDir,
		Policy:     fetcher.Policy,
	}).Write(ctx, snapshotstore.Input{
		Reader:                normalized.File,
		ExpectedArchiveBytes:  normalized.Size,
		ExpectedArchiveSHA256: normalized.SHA256,
		Metadata: sourcearchive.Metadata{
			SourceKind:    "git",
			Provider:      grant.Provider,
			Repository:    strings.ToLower(grant.Repository),
			CommitSHA:     resolution.SHA,
			Author:        resolution.Author,
			AuthoredAt:    resolution.AuthoredAt,
			RootDirectory: grant.RootDirectory,
			CreatorID:     grant.CreatorID,
			ExcludedCount: 0,
		},
	})
	if err != nil {
		return sourceauth.SignedFetchResult{}, err
	}

	now := fetcher.now()
	warnings := append([]string(nil), stored.Source.Manifest.Warnings...)
	sort.Strings(warnings)
	signed, err := sourceauth.SignFetchResult(fetcher.PrivateKey, fetcher.SigningKeyID, sourceauth.FetchResult{
		Version:            1,
		FetchID:            grant.FetchID,
		OrganizationID:     grant.OrganizationID,
		ProjectID:          grant.ProjectID,
		SourceConnectionID: grant.SourceConnectionID,
		Provider:           grant.Provider,
		Repository:         strings.ToLower(grant.Repository),
		RequestedCommitSHA: grant.CommitSHA,
		ResolvedCommitSHA:  resolution.SHA,
		TreeSHA:            resolution.TreeSHA,
		Author:             resolution.Author,
		AuthoredAt:         resolution.AuthoredAt,
		SnapshotSHA256:     stored.Source.SnapshotSHA256,
		ManifestSHA256:     stored.Source.ManifestSHA256,
		ArchiveSHA256:      stored.Source.ArchiveSHA256,
		ManifestRef:        stored.ManifestRef,
		ArchiveRef:         stored.ArchiveRef,
		SizeBytes:          stored.SizeBytes,
		PolicyVersion:      fetcher.Policy.Version,
		Submodules:         []sourceauth.Submodule{},
		LFSDigests:         []string{},
		Warnings:           warnings,
		TokenExpiresAt:     token.ExpiresAt,
		FinalizedAt:        now,
	})
	if err != nil {
		return sourceauth.SignedFetchResult{}, err
	}
	if err := fetcher.storeReceipt(ctx, grant, signed); err != nil {
		if errors.Is(err, objectstore.ErrImmutableConflict) {
			if completed, found, readErr := fetcher.completedResult(ctx, grant); readErr == nil && found {
				return completed, nil
			}
		}
		return sourceauth.SignedFetchResult{}, err
	}
	return signed, nil
}

func (fetcher *Fetcher) resolveCommit(
	ctx context.Context,
	token string,
	repository string,
	commitSHA string,
) (commitResolution, error) {
	owner, name := splitRepository(repository)
	endpoint, err := githubURL(fetcher.BaseURL, "repos", owner, name, "commits", commitSHA)
	if err != nil {
		return commitResolution{}, err
	}
	request, err := newGitHubRequest(http.MethodGet, endpoint, token, nil)
	if err != nil {
		return commitResolution{}, err
	}
	request = request.WithContext(ctx)
	response, err := fetcher.Client.Do(request)
	if err != nil {
		return commitResolution{}, ErrProviderUnavailable
	}
	if response.StatusCode != http.StatusOK {
		closeResponse(response)
		return commitResolution{}, providerReadError(response.StatusCode)
	}
	var payload struct {
		SHA    string `json:"sha"`
		Commit struct {
			Author struct {
				Name string    `json:"name"`
				Date time.Time `json:"date"`
			} `json:"author"`
			Tree struct {
				SHA string `json:"sha"`
			} `json:"tree"`
		} `json:"commit"`
	}
	if err := decodeJSON(response, 4<<20, &payload); err != nil {
		return commitResolution{}, ErrProviderUnavailable
	}
	payload.SHA = strings.ToLower(payload.SHA)
	payload.Commit.Tree.SHA = strings.ToLower(payload.Commit.Tree.SHA)
	if !providerCommitPattern.MatchString(payload.SHA) || !providerCommitPattern.MatchString(payload.Commit.Tree.SHA) ||
		payload.Commit.Author.Date.IsZero() || len(payload.Commit.Author.Name) > 320 || containsControl(payload.Commit.Author.Name) {
		return commitResolution{}, fmt.Errorf("%w: invalid provider commit response", ErrRepositoryPolicy)
	}
	return commitResolution{
		SHA:        payload.SHA,
		TreeSHA:    payload.Commit.Tree.SHA,
		Author:     payload.Commit.Author.Name,
		AuthoredAt: payload.Commit.Author.Date.UTC(),
	}, nil
}

func (fetcher *Fetcher) resolveTree(
	ctx context.Context,
	token string,
	repository string,
	treeSHA string,
) (map[string]treeObject, error) {
	owner, name := splitRepository(repository)
	endpoint, err := githubURL(fetcher.BaseURL, "repos", owner, name, "git", "trees", treeSHA)
	if err != nil {
		return nil, err
	}
	query := endpoint.Query()
	query.Set("recursive", "1")
	endpoint.RawQuery = query.Encode()
	request, err := newGitHubRequest(http.MethodGet, endpoint, token, nil)
	if err != nil {
		return nil, err
	}
	request = request.WithContext(ctx)
	response, err := fetcher.Client.Do(request)
	if err != nil {
		return nil, ErrProviderUnavailable
	}
	if response.StatusCode != http.StatusOK {
		closeResponse(response)
		return nil, providerReadError(response.StatusCode)
	}
	var payload struct {
		SHA       string `json:"sha"`
		Truncated bool   `json:"truncated"`
		Tree      []struct {
			Path string `json:"path"`
			Mode string `json:"mode"`
			Type string `json:"type"`
			SHA  string `json:"sha"`
			Size *int64 `json:"size"`
		} `json:"tree"`
	}
	if err := decodeJSON(response, maxJSONBody, &payload); err != nil {
		return nil, ErrProviderUnavailable
	}
	if payload.Truncated || !strings.EqualFold(payload.SHA, treeSHA) || len(payload.Tree) > fetcher.Policy.MaxEntries*2 {
		return nil, fmt.Errorf("%w: provider tree is incomplete or oversized", ErrRepositoryPolicy)
	}
	objects := make(map[string]treeObject)
	var totalBytes int64
	for _, entry := range payload.Tree {
		normalized, err := sourcearchive.NormalizePath(entry.Path, entry.Type == "tree", fetcher.Policy.MaxPathBytes)
		if err != nil {
			return nil, err
		}
		switch {
		case entry.Type == "tree" && entry.Mode == "040000":
			continue
		case entry.Type == "commit" || entry.Mode == "160000":
			return nil, fmt.Errorf("%w: %s", ErrSubmoduleUnsupported, normalized)
		case entry.Type == "blob" && entry.Mode == "120000":
			return nil, fmt.Errorf("%w: symbolic link %s", ErrRepositoryPolicy, normalized)
		case entry.Type == "blob" && (entry.Mode == "100644" || entry.Mode == "100755"):
			if entry.Size == nil || *entry.Size < 0 || *entry.Size > fetcher.Policy.MaxFileBytes ||
				!providerCommitPattern.MatchString(strings.ToLower(entry.SHA)) {
				return nil, fmt.Errorf("%w: invalid provider tree object", ErrRepositoryPolicy)
			}
			if totalBytes > fetcher.Policy.MaxExpandedBytes-*entry.Size {
				return nil, fmt.Errorf("%w: provider tree exceeds expanded limit", ErrRepositoryPolicy)
			}
			if _, duplicate := objects[normalized]; duplicate {
				return nil, fmt.Errorf("%w: duplicate provider tree path", ErrRepositoryPolicy)
			}
			objects[normalized] = treeObject{Mode: entry.Mode, SHA: strings.ToLower(entry.SHA), Size: *entry.Size}
			totalBytes += *entry.Size
		default:
			return nil, fmt.Errorf("%w: unsupported provider tree object", ErrRepositoryPolicy)
		}
	}
	if len(objects) == 0 || len(objects) > fetcher.Policy.MaxEntries {
		return nil, fmt.Errorf("%w: provider tree has invalid file count", ErrRepositoryPolicy)
	}
	return objects, nil
}

func (fetcher *Fetcher) downloadArchive(
	ctx context.Context,
	token string,
	repository string,
	commitSHA string,
) (*http.Response, error) {
	owner, name := splitRepository(repository)
	endpoint, err := githubURL(fetcher.BaseURL, "repos", owner, name, "tarball", commitSHA)
	if err != nil {
		return nil, err
	}
	request, err := newGitHubRequest(http.MethodGet, endpoint, token, nil)
	if err != nil {
		return nil, err
	}
	request = request.WithContext(ctx)
	response, err := fetcher.Client.Do(request)
	if err != nil {
		return nil, ErrProviderUnavailable
	}
	if response.StatusCode == http.StatusOK {
		if response.Request != nil && response.Request.URL != nil && response.Request.URL.String() != endpoint.String() {
			closeResponse(response)
			return nil, fmt.Errorf("%w: provider client followed an unvalidated redirect", ErrRepositoryPolicy)
		}
		return response, nil
	}
	if response.StatusCode != http.StatusFound && response.StatusCode != http.StatusTemporaryRedirect {
		closeResponse(response)
		return nil, providerReadError(response.StatusCode)
	}
	location, err := response.Location()
	closeResponse(response)
	if err != nil || !fetcher.allowedArchiveLocation(location) {
		return nil, fmt.Errorf("%w: provider archive redirect is not allowed", ErrRepositoryPolicy)
	}
	archiveRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, location.String(), nil)
	if err != nil {
		return nil, ErrProviderUnavailable
	}
	archiveRequest.Header.Set("Accept", "application/gzip")
	archiveRequest.Header.Set("User-Agent", githubUserAgent)
	archiveResponse, err := fetcher.Client.Do(archiveRequest)
	if err != nil {
		return nil, ErrProviderUnavailable
	}
	if archiveResponse.StatusCode != http.StatusOK {
		closeResponse(archiveResponse)
		return nil, providerReadError(archiveResponse.StatusCode)
	}
	return archiveResponse, nil
}

func (fetcher *Fetcher) allowedArchiveLocation(location *url.URL) bool {
	if location == nil || location.User != nil || (location.RawQuery != "" && len(location.RawQuery) > 4096) {
		return false
	}
	if location.Scheme == "https" {
		for _, host := range fetcher.AllowedArchiveHosts {
			if strings.EqualFold(location.Hostname(), host) && (location.Port() == "" || location.Port() == "443") {
				return true
			}
		}
	}
	return fetcher.BaseURL.Scheme == "http" && location.Scheme == "http" &&
		strings.EqualFold(location.Host, fetcher.BaseURL.Host) && isLoopbackHost(location.Hostname())
}

func (fetcher *Fetcher) completedResult(
	ctx context.Context,
	grant sourceauth.FetchGrant,
) (sourceauth.SignedFetchResult, bool, error) {
	reader, info, err := fetcher.Store.Open(ctx, fetchReceiptKey(grant))
	if errors.Is(err, objectstore.ErrNotFound) {
		return sourceauth.SignedFetchResult{}, false, nil
	}
	if err != nil {
		return sourceauth.SignedFetchResult{}, false, err
	}
	defer reader.Close()
	if info.Size <= 0 || info.Size > 128<<10 {
		return sourceauth.SignedFetchResult{}, false, errors.New("stored source fetch receipt exceeds limit")
	}
	decoder := json.NewDecoder(io.LimitReader(reader, 128<<10))
	decoder.DisallowUnknownFields()
	var signed sourceauth.SignedFetchResult
	if err := decoder.Decode(&signed); err != nil {
		return sourceauth.SignedFetchResult{}, false, fmt.Errorf("decode source fetch receipt: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return sourceauth.SignedFetchResult{}, false, errors.New("source fetch receipt contains trailing data")
	}
	if err := sourceauth.VerifyFetchResult(fetcher.PrivateKey.Public().(ed25519.PublicKey), signed); err != nil {
		return sourceauth.SignedFetchResult{}, false, err
	}
	result := signed.Result
	if result.FetchID != grant.FetchID || result.OrganizationID != grant.OrganizationID ||
		result.ProjectID != grant.ProjectID || result.SourceConnectionID != grant.SourceConnectionID ||
		result.Provider != grant.Provider || !strings.EqualFold(result.Repository, grant.Repository) ||
		result.RequestedCommitSHA != grant.CommitSHA || result.PolicyVersion != fetcher.Policy.Version {
		return sourceauth.SignedFetchResult{}, false, sourceauth.ErrInvalidFetchResult
	}
	return signed, true, nil
}

func (fetcher *Fetcher) storeReceipt(
	ctx context.Context,
	grant sourceauth.FetchGrant,
	signed sourceauth.SignedFetchResult,
) error {
	receipt, err := canonicaljson.Marshal(signed)
	if err != nil {
		return fmt.Errorf("canonicalize source fetch receipt: %w", err)
	}
	digest := sha256.Sum256(receipt)
	return fetcher.Store.PutImmutable(
		ctx,
		fetchReceiptKey(grant),
		bytes.NewReader(receipt),
		int64(len(receipt)),
		"sha256:"+hex.EncodeToString(digest[:]),
		"application/json",
	)
}

func (fetcher *Fetcher) validateConfiguration() error {
	if fetcher == nil || fetcher.Store == nil || fetcher.ScratchDir == "" || fetcher.Tokens == nil ||
		fetcher.Client == nil || fetcher.BaseURL == nil || len(fetcher.PrivateKey) != ed25519.PrivateKeySize ||
		fetcher.SigningKeyID == "" || fetcher.Policy.Version == "" {
		return errors.New("provider fetcher configuration is incomplete")
	}
	return nil
}

func (fetcher *Fetcher) now() time.Time {
	if fetcher.Now != nil {
		return fetcher.Now().UTC()
	}
	return time.Now().UTC()
}

func (fetcher *Fetcher) acquire(key string) func() {
	fetcher.lockMu.Lock()
	if fetcher.locks == nil {
		fetcher.locks = make(map[string]*fetchLock)
	}
	lock := fetcher.locks[key]
	if lock == nil {
		lock = &fetchLock{}
		fetcher.locks[key] = lock
	}
	lock.users++
	fetcher.lockMu.Unlock()
	lock.mutex.Lock()
	return func() {
		lock.mutex.Unlock()
		fetcher.lockMu.Lock()
		lock.users--
		if lock.users == 0 {
			delete(fetcher.locks, key)
		}
		fetcher.lockMu.Unlock()
	}
}

func fetchReceiptKey(grant sourceauth.FetchGrant) string {
	return path.Join("fetches", grant.OrganizationID, grant.FetchID+".json")
}

func splitRepository(repository string) (string, string) {
	parts := strings.SplitN(repository, "/", 2)
	return parts[0], parts[1]
}

func providerReadError(status int) error {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return ErrProviderAuthentication
	case http.StatusNotFound, http.StatusGone, http.StatusUnprocessableEntity:
		return ErrReferenceNotFound
	default:
		return ErrProviderUnavailable
	}
}

func isLoopbackHost(host string) bool {
	return strings.EqualFold(host, "localhost") || host == "127.0.0.1" || host == "::1"
}

func containsControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}
