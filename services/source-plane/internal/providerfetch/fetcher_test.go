package providerfetch

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/objectstore"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourcearchive"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourceauth"
)

func TestGitHubProviderConformanceExactCommitReplayAndForcePush(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 13, 2, 0, 0, 0, time.UTC)
	appKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	firstSHA := strings.Repeat("a", 40)
	secondSHA := strings.Repeat("b", 40)
	provider := newFakeGitHub(t, appKey.PublicKey, now, map[string]map[string]fixtureFile{
		firstSHA: {
			"README.md": {body: []byte("first\n"), mode: "100644"},
			"bin/start": {body: []byte("#!/bin/sh\necho first\n"), mode: "100755"},
		},
		secondSHA: {
			"README.md": {body: []byte("second\n"), mode: "100644"},
		},
	})
	defer provider.server.Close()
	store := newMemoryStore()
	scratch := t.TempDir()
	client := provider.server.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	baseURL, _ := url.Parse(provider.server.URL)
	fetcher := &Fetcher{
		Store:               store,
		ScratchDir:          scratch,
		Policy:              sourcearchive.DefaultPolicy(),
		Tokens:              &GitHubAppTokenSource{BaseURL: baseURL, Client: client, AppID: "Iv1.layerrail", PrivateKey: appKey, Now: func() time.Time { return now }},
		Client:              client,
		BaseURL:             baseURL,
		AllowedArchiveHosts: []string{baseURL.Hostname()},
		PrivateKey:          signingKey,
		SigningKeyID:        "source-finalizer-test-v1",
		Now:                 func() time.Time { return now },
	}

	firstGrant := conformanceGrant(now, firstSHA, "001")
	first, err := fetcher.Fetch(context.Background(), firstGrant)
	if err != nil {
		t.Fatal(err)
	}
	if err := sourceauth.VerifyFetchResult(publicKey, first); err != nil {
		t.Fatal(err)
	}
	if first.Result.ResolvedCommitSHA != firstSHA || first.Result.RequestedCommitSHA != firstSHA ||
		first.Result.Repository != "example/repository" || first.Result.TreeSHA == "" {
		t.Fatalf("unexpected exact-commit result: %#v", first.Result)
	}
	if provider.tokenCallCount() != 1 || provider.sawArchiveAuthorization() {
		t.Fatalf("token calls=%d archive authorization=%v", provider.tokenCallCount(), provider.sawArchiveAuthorization())
	}

	replay, err := fetcher.Fetch(context.Background(), firstGrant)
	if err != nil {
		t.Fatal(err)
	}
	if replay.Signature != first.Signature || provider.tokenCallCount() != 1 {
		t.Fatalf("replay changed result or minted a token: %#v calls=%d", replay, provider.tokenCallCount())
	}

	sameCommitGrant := conformanceGrant(now, firstSHA, "002")
	sameCommit, err := fetcher.Fetch(context.Background(), sameCommitGrant)
	if err != nil {
		t.Fatal(err)
	}
	if sameCommit.Result.SnapshotSHA256 != first.Result.SnapshotSHA256 {
		t.Fatalf("same tree changed source identity: %s != %s", sameCommit.Result.SnapshotSHA256, first.Result.SnapshotSHA256)
	}

	concurrentGrant := conformanceGrant(now, firstSHA, "004")
	beforeConcurrent := provider.tokenCallCount()
	start := make(chan struct{})
	type concurrentResult struct {
		signed sourceauth.SignedFetchResult
		err    error
	}
	results := make(chan concurrentResult, 8)
	for range 8 {
		go func() {
			<-start
			signed, fetchErr := fetcher.Fetch(context.Background(), concurrentGrant)
			results <- concurrentResult{signed: signed, err: fetchErr}
		}()
	}
	close(start)
	concurrentSignature := ""
	for range 8 {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		if concurrentSignature == "" {
			concurrentSignature = result.signed.Signature
		} else if result.signed.Signature != concurrentSignature {
			t.Fatal("concurrent replay returned different signed receipts")
		}
	}
	if provider.tokenCallCount() != beforeConcurrent+1 {
		t.Fatalf("concurrent replay minted %d tokens", provider.tokenCallCount()-beforeConcurrent)
	}

	forcePushGrant := conformanceGrant(now, secondSHA, "003")
	forcePush, err := fetcher.Fetch(context.Background(), forcePushGrant)
	if err != nil {
		t.Fatal(err)
	}
	if forcePush.Result.SnapshotSHA256 == first.Result.SnapshotSHA256 {
		t.Fatal("force-pushed tree reused the previous source identity")
	}
	if forcePush.Result.Warnings == nil || len(forcePush.Result.Warnings) != 0 {
		t.Fatalf("clean source warnings = %#v", forcePush.Result.Warnings)
	}
	for key, value := range store.bytes() {
		if bytes.Contains(value, []byte(provider.installationToken)) {
			t.Fatalf("provider credential persisted in object %s", key)
		}
	}
}

func TestGitHubProviderConformanceRejectsSubmodulesAndLFS(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 13, 2, 0, 0, 0, time.UTC)
	appKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, signingKey, _ := ed25519.GenerateKey(rand.Reader)
	submoduleSHA := strings.Repeat("c", 40)
	lfsSHA := strings.Repeat("d", 40)
	provider := newFakeGitHub(t, appKey.PublicKey, now, map[string]map[string]fixtureFile{
		submoduleSHA: {
			"vendor/module": {body: nil, mode: "160000", objectSHA: strings.Repeat("e", 40)},
		},
		lfsSHA: {
			"asset.bin": {body: []byte("version https://git-lfs.github.com/spec/v1\noid sha256:" + strings.Repeat("a", 64) + "\nsize 1024\n"), mode: "100644"},
		},
	})
	defer provider.server.Close()
	client := provider.server.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	baseURL, _ := url.Parse(provider.server.URL)
	fetcher := &Fetcher{
		Store:               newMemoryStore(),
		ScratchDir:          t.TempDir(),
		Policy:              sourcearchive.DefaultPolicy(),
		Tokens:              &GitHubAppTokenSource{BaseURL: baseURL, Client: client, AppID: "Iv1.layerrail", PrivateKey: appKey, Now: func() time.Time { return now }},
		Client:              client,
		BaseURL:             baseURL,
		AllowedArchiveHosts: []string{baseURL.Hostname()},
		PrivateKey:          signingKey,
		SigningKeyID:        "source-finalizer-test-v1",
		Now:                 func() time.Time { return now },
	}

	if _, err := fetcher.Fetch(context.Background(), conformanceGrant(now, submoduleSHA, "010")); !errors.Is(err, ErrSubmoduleUnsupported) {
		t.Fatalf("submodule error = %v", err)
	}
	if _, err := fetcher.Fetch(context.Background(), conformanceGrant(now, lfsSHA, "011")); !errors.Is(err, ErrLFSUnsupported) {
		t.Fatalf("LFS error = %v", err)
	}
}

func TestNormalizeArchiveRejectsMismatchedGitHubGlobalPAXCommit(t *testing.T) {
	t.Parallel()
	commit := strings.Repeat("a", 40)
	files := map[string]fixtureFile{"README.md": {body: []byte("safe\n"), mode: "100644"}}
	archive := makeProviderArchiveWithComment(t, commit, strings.Repeat("b", 40), files)
	tree := map[string]treeObject{
		"README.md": {Mode: "100644", SHA: gitBlobSHA(files["README.md"].body), Size: int64(len(files["README.md"].body))},
	}
	_, err := normalizeArchive(context.Background(), bytes.NewReader(archive), t.TempDir(), sourcearchive.DefaultPolicy(), tree, commit)
	if !errors.Is(err, ErrRepositoryPolicy) {
		t.Fatalf("global PAX commit error = %v", err)
	}
}

type fixtureFile struct {
	body      []byte
	mode      string
	objectSHA string
}

type fakeGitHub struct {
	server                   *httptest.Server
	appKey                   rsa.PublicKey
	now                      time.Time
	commits                  map[string]map[string]fixtureFile
	treeSHAs                 map[string]string
	installationToken        string
	tokenCalls               int
	archiveAuthorizationSeen bool
	mu                       sync.Mutex
	t                        *testing.T
}

func newFakeGitHub(
	t *testing.T,
	appKey rsa.PublicKey,
	now time.Time,
	commits map[string]map[string]fixtureFile,
) *fakeGitHub {
	t.Helper()
	provider := &fakeGitHub{
		appKey:            appKey,
		now:               now,
		commits:           commits,
		treeSHAs:          make(map[string]string),
		installationToken: "ghs_local_provider_token_value_1234567890",
		t:                 t,
	}
	for commit := range commits {
		digest := sha1.Sum([]byte("tree:" + commit))
		provider.treeSHAs[commit] = hex.EncodeToString(digest[:])
	}
	provider.server = httptest.NewServer(http.HandlerFunc(provider.handle))
	return provider
}

func (provider *fakeGitHub) handle(response http.ResponseWriter, request *http.Request) {
	provider.t.Helper()
	path := request.URL.Path
	switch {
	case request.Method == http.MethodPost && path == "/app/installations/123456/access_tokens":
		if err := verifyAppJWT(strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer "), &provider.appKey, "Iv1.layerrail", provider.now); err != nil {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		var body struct {
			Repositories []string          `json:"repositories"`
			Permissions  map[string]string `json:"permissions"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil || len(body.Repositories) != 1 ||
			body.Repositories[0] != "repository" || body.Permissions["contents"] != "read" {
			http.Error(response, "invalid token scope", http.StatusUnprocessableEntity)
			return
		}
		provider.mu.Lock()
		provider.tokenCalls++
		provider.mu.Unlock()
		writeTestJSON(response, http.StatusCreated, map[string]any{
			"token":        provider.installationToken,
			"expires_at":   provider.now.Add(time.Hour),
			"permissions":  map[string]string{"contents": "read"},
			"repositories": []map[string]string{{"full_name": "example/repository"}},
		})
	case strings.HasPrefix(path, "/repos/example/repository/commits/"):
		commit := strings.TrimPrefix(path, "/repos/example/repository/commits/")
		if !provider.authorized(request) || provider.commits[commit] == nil {
			http.NotFound(response, request)
			return
		}
		writeTestJSON(response, http.StatusOK, map[string]any{
			"sha": commit,
			"commit": map[string]any{
				"author": map[string]any{"name": "Example Author", "date": provider.now.Add(-time.Hour)},
				"tree":   map[string]any{"sha": provider.treeSHAs[commit]},
			},
		})
	case strings.HasPrefix(path, "/repos/example/repository/git/trees/"):
		if !provider.authorized(request) {
			http.Error(response, "forbidden", http.StatusForbidden)
			return
		}
		commit := provider.commitForTree(strings.TrimPrefix(path, "/repos/example/repository/git/trees/"))
		files := provider.commits[commit]
		if files == nil {
			http.NotFound(response, request)
			return
		}
		entries := make([]map[string]any, 0, len(files))
		paths := sortedFixturePaths(files)
		for _, name := range paths {
			file := files[name]
			objectType := "blob"
			objectSHA := file.objectSHA
			var size any = int64(len(file.body))
			if file.mode == "160000" {
				objectType = "commit"
				size = nil
			}
			if objectSHA == "" {
				objectSHA = gitBlobSHA(file.body)
			}
			entries = append(entries, map[string]any{
				"path": name, "mode": file.mode, "type": objectType, "sha": objectSHA, "size": size,
			})
		}
		writeTestJSON(response, http.StatusOK, map[string]any{
			"sha": provider.treeSHAs[commit], "truncated": false, "tree": entries,
		})
	case strings.HasPrefix(path, "/repos/example/repository/tarball/"):
		commit := strings.TrimPrefix(path, "/repos/example/repository/tarball/")
		if !provider.authorized(request) || provider.commits[commit] == nil {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Location", provider.server.URL+"/archives/"+commit)
		response.WriteHeader(http.StatusFound)
	case strings.HasPrefix(path, "/archives/"):
		commit := strings.TrimPrefix(path, "/archives/")
		if request.Header.Get("Authorization") != "" {
			provider.mu.Lock()
			provider.archiveAuthorizationSeen = true
			provider.mu.Unlock()
		}
		archive := makeProviderArchive(provider.t, commit, provider.commits[commit])
		response.Header().Set("Content-Type", "application/gzip")
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(archive)
	default:
		http.NotFound(response, request)
	}
}

func (provider *fakeGitHub) authorized(request *http.Request) bool {
	return request.Header.Get("Authorization") == "Bearer "+provider.installationToken &&
		request.Header.Get("X-GitHub-Api-Version") == githubAPIVersion
}

func (provider *fakeGitHub) commitForTree(treeSHA string) string {
	for commit, candidate := range provider.treeSHAs {
		if candidate == treeSHA {
			return commit
		}
	}
	return ""
}

func (provider *fakeGitHub) tokenCallCount() int {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.tokenCalls
}

func (provider *fakeGitHub) sawArchiveAuthorization() bool {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.archiveAuthorizationSeen
}

func verifyAppJWT(token string, key *rsa.PublicKey, issuer string, now time.Time) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("invalid JWT")
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || !bytes.Contains(header, []byte(`"alg":"RS256"`)) {
		return errors.New("invalid JWT header")
	}
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	var payload struct {
		IssuedAt  int64  `json:"iat"`
		ExpiresAt int64  `json:"exp"`
		Issuer    string `json:"iss"`
	}
	if err := json.Unmarshal(claims, &payload); err != nil || payload.Issuer != issuer ||
		payload.IssuedAt > now.Unix() || payload.ExpiresAt > now.Add(10*time.Minute).Unix() || payload.ExpiresAt <= now.Unix() {
		return errors.New("invalid JWT claims")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature)
}

func makeProviderArchive(t *testing.T, commit string, files map[string]fixtureFile) []byte {
	return makeProviderArchiveWithComment(t, commit, commit, files)
}

func makeProviderArchiveWithComment(t *testing.T, commit, comment string, files map[string]fixtureFile) []byte {
	t.Helper()
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	compressed.Header.ModTime = time.Unix(0, 0)
	compressed.Header.OS = 255
	writer := tar.NewWriter(compressed)
	if err := writer.WriteHeader(&tar.Header{
		Name: "pax_global_header", Typeflag: tar.TypeXGlobalHeader, PAXRecords: map[string]string{"comment": comment},
	}); err != nil {
		t.Fatal(err)
	}
	root := "example-repository-" + commit[:7]
	if err := writer.WriteHeader(&tar.Header{Name: root + "/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	for _, name := range sortedFixturePaths(files) {
		file := files[name]
		if file.mode == "160000" {
			continue
		}
		mode := int64(0o644)
		if file.mode == "100755" {
			mode = 0o755
		}
		if err := writer.WriteHeader(&tar.Header{Name: root + "/" + name, Typeflag: tar.TypeReg, Mode: mode, Size: int64(len(file.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(file.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func sortedFixturePaths(files map[string]fixtureFile) []string {
	paths := make([]string, 0, len(files))
	for name := range files {
		paths = append(paths, name)
	}
	sort.Strings(paths)
	return paths
}

func gitBlobSHA(body []byte) string {
	hash := sha1.New() // #nosec G401 -- test fixture reproduces Git object identity.
	_, _ = fmt.Fprintf(hash, "blob %d\x00", len(body))
	_, _ = hash.Write(body)
	return hex.EncodeToString(hash.Sum(nil))
}

func conformanceGrant(now time.Time, commitSHA string, suffix string) sourceauth.FetchGrant {
	return sourceauth.FetchGrant{
		Version:            1,
		Audience:           sourceauth.Audience,
		FetchID:            "fet_019b01da-7e31-7000-8000-000000000" + suffix,
		OrganizationID:     "org_019b01da-7e31-7000-8000-000000000101",
		ProjectID:          "prj_019b01da-7e31-7000-8000-000000000102",
		CreatorID:          "acct_019b01da-7e31-7000-8000-000000000103",
		SourceConnectionID: "src_019b01da-7e31-7000-8000-000000000104",
		Provider:           "github",
		InstallationID:     "123456",
		Repository:         "example/repository",
		CommitSHA:          commitSHA,
		RootDirectory:      "",
		ExpiresAt:          now.Add(15 * time.Minute),
	}
}

type storedObject struct {
	body   []byte
	digest string
}

type memoryStore struct {
	mu      sync.Mutex
	objects map[string]storedObject
}

func newMemoryStore() *memoryStore {
	return &memoryStore{objects: make(map[string]storedObject)}
}

func (*memoryStore) PresignPut(context.Context, string, time.Duration) (*url.URL, error) {
	return nil, errors.New("not implemented")
}

func (store *memoryStore) Open(_ context.Context, key string) (io.ReadCloser, objectstore.Info, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, found := store.objects[key]
	if !found {
		return nil, objectstore.Info{}, objectstore.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(value.body)), objectstore.Info{Size: int64(len(value.body)), SHA256: value.digest}, nil
}

func (store *memoryStore) PutImmutable(_ context.Context, key string, reader io.Reader, size int64, digest string, _ string) error {
	body, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	if int64(len(body)) != size {
		return errors.New("size mismatch")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if current, found := store.objects[key]; found {
		if !bytes.Equal(current.body, body) || current.digest != digest {
			return objectstore.ErrImmutableConflict
		}
		return nil
	}
	store.objects[key] = storedObject{body: append([]byte(nil), body...), digest: digest}
	return nil
}

func (*memoryStore) Delete(context.Context, []string) error { return nil }
func (*memoryStore) Ready(context.Context) error            { return nil }
func (*memoryStore) Ref(key string) string                  { return "s3://test-source/" + key }

func (store *memoryStore) bytes() map[string][]byte {
	store.mu.Lock()
	defer store.mu.Unlock()
	result := make(map[string][]byte, len(store.objects))
	for key, value := range store.objects {
		result[key] = append([]byte(nil), value.body...)
	}
	return result
}

func writeTestJSON(response http.ResponseWriter, status int, body any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(body)
}
