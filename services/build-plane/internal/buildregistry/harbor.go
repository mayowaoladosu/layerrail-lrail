package buildregistry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
)

type HarborClient struct {
	endpoint      *url.URL
	registry      string
	adminUsername string
	adminPassword []byte
	http          *http.Client
	clock         func() time.Time
	storageLimit  int64
}

type HarborConfig struct {
	Endpoint      string
	Registry      string
	AdminUsername string
	AdminPassword []byte
	HTTPClient    *http.Client
	Clock         func() time.Time
	StorageLimit  int64
}

type harborProject struct {
	ProjectID int64             `json:"project_id"`
	Name      string            `json:"name"`
	Registry  int64             `json:"registry_id"`
	Deleted   bool              `json:"deleted"`
	Metadata  map[string]string `json:"metadata"`
}

type harborProjectRequest struct {
	ProjectName string            `json:"project_name,omitempty"`
	Metadata    map[string]string `json:"metadata"`
	Storage     int64             `json:"storage_limit,omitempty"`
}

type harborQuota struct {
	ID   int64            `json:"id"`
	Hard map[string]int64 `json:"hard"`
}

type harborQuotaUpdate struct {
	Hard map[string]int64 `json:"hard"`
}

type immutableRule struct {
	ID             int64                          `json:"id,omitempty"`
	Priority       int                            `json:"priority,omitempty"`
	Disabled       bool                           `json:"disabled"`
	Action         string                         `json:"action"`
	Template       string                         `json:"template"`
	Params         map[string]any                 `json:"params"`
	TagSelectors   []immutableSelector            `json:"tag_selectors"`
	ScopeSelectors map[string][]immutableSelector `json:"scope_selectors"`
}

type immutableSelector struct {
	Kind       string `json:"kind"`
	Decoration string `json:"decoration"`
	Pattern    string `json:"pattern"`
	Extras     string `json:"extras,omitempty"`
}

type harborRobotCreate struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Level       string            `json:"level"`
	Disable     bool              `json:"disable"`
	Duration    int64             `json:"duration"`
	Permissions []robotPermission `json:"permissions"`
}

type robotPermission struct {
	Kind      string        `json:"kind"`
	Namespace string        `json:"namespace"`
	Access    []robotAccess `json:"access"`
}

type robotAccess struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Effect   string `json:"effect,omitempty"`
}

type harborRobotCreated struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Secret    string `json:"secret"`
	ExpiresAt int64  `json:"expires_at"`
}

type harborTokenResponse struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	IssuedAt    string `json:"issued_at"`
}

type registryTokenClaims struct {
	Audience string                `json:"aud"`
	Expires  int64                 `json:"exp"`
	IssuedAt int64                 `json:"iat"`
	Access   []registryTokenAccess `json:"access"`
}

type registryTokenAccess struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

func NewHarborClient(config HarborConfig) (*HarborClient, error) {
	endpointText, err := normalizeRegistryURL(config.Endpoint)
	if err != nil {
		return nil, err
	}
	registryText := config.Registry
	if registryText == "" {
		registryText = endpointText
	}
	registryText, err = normalizeRegistryURL(registryText)
	if err != nil {
		return nil, err
	}
	if config.AdminUsername == "" || len(config.AdminUsername) > 255 || len(config.AdminPassword) < 16 || len(config.AdminPassword) > 4096 ||
		config.HTTPClient == nil || config.StorageLimit < 1 {
		return nil, errors.New("Harbor client configuration is incomplete")
	}
	endpoint, _ := url.Parse(endpointText)
	client := *config.HTTPClient
	if client.Timeout == 0 {
		client.Timeout = DefaultHTTPTimeout
	}
	if client.Timeout < time.Second || client.Timeout > time.Minute {
		return nil, errors.New("Harbor HTTP timeout is outside bounds")
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &HarborClient{
		endpoint: endpoint, registry: registryText, adminUsername: config.AdminUsername,
		adminPassword: append([]byte(nil), config.AdminPassword...), http: &client, clock: config.Clock, storageLimit: config.StorageLimit,
	}, nil
}

func (client *HarborClient) Close() {
	for index := range client.adminPassword {
		client.adminPassword[index] = 0
	}
	client.adminPassword = nil
}

func (client *HarborClient) Registry() string { return client.registry }

func (client *HarborClient) EnsureProject(ctx context.Context, organizationID string) (string, error) {
	projectName, err := ProjectName(organizationID)
	if err != nil {
		return "", err
	}
	project, found, err := client.getProject(ctx, projectName)
	if err != nil {
		return "", err
	}
	if !found {
		request := harborProjectRequest{ProjectName: projectName, Metadata: expectedProjectMetadata(), Storage: client.storageLimit}
		status, err := client.doJSON(ctx, http.MethodPost, "/api/v2.0/projects", request, nil, nil)
		if err != nil || status != http.StatusCreated && status != http.StatusConflict {
			return "", fmt.Errorf("%w: create Harbor project", ErrRegistry)
		}
		project, found, err = client.getProject(ctx, projectName)
		if err != nil || !found {
			return "", fmt.Errorf("%w: Harbor project was not retrievable after creation", ErrRegistry)
		}
	}
	if project.Registry != 0 || project.Deleted || project.Name != projectName {
		return "", fmt.Errorf("%w: Harbor project identity is unsafe", ErrRegistry)
	}
	if !equalMetadata(project.Metadata, expectedProjectMetadata()) {
		status, err := client.doJSON(ctx, http.MethodPut, "/api/v2.0/projects/"+projectName, harborProjectRequest{Metadata: expectedProjectMetadata(), Storage: client.storageLimit}, nil, map[string]string{"X-Is-Resource-Name": "true"})
		if err != nil || status != http.StatusOK {
			return "", fmt.Errorf("%w: enforce private Harbor project metadata", ErrRegistry)
		}
		project, found, err = client.getProject(ctx, projectName)
		if err != nil || !found || !equalMetadata(project.Metadata, expectedProjectMetadata()) {
			return "", fmt.Errorf("%w: Harbor project metadata did not converge", ErrRegistry)
		}
	}
	if err := client.ensureStorageQuota(ctx, project); err != nil {
		return "", err
	}
	if err := client.ensureImmutability(ctx, projectName); err != nil {
		return "", err
	}
	return projectName, nil
}

func (client *HarborClient) ensureStorageQuota(ctx context.Context, project harborProject) error {
	quota, err := client.getProjectQuota(ctx, project.ProjectID)
	if err != nil {
		return err
	}
	if quota.Hard["storage"] == client.storageLimit {
		return nil
	}
	status, err := client.doJSON(ctx, http.MethodPut, "/api/v2.0/quotas/"+strconv.FormatInt(quota.ID, 10),
		harborQuotaUpdate{Hard: map[string]int64{"storage": client.storageLimit}}, nil, nil,
	)
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("%w: enforce Harbor project storage quota", ErrRegistry)
	}
	quota, err = client.getProjectQuota(ctx, project.ProjectID)
	if err != nil || quota.Hard["storage"] != client.storageLimit {
		return fmt.Errorf("%w: Harbor project storage quota did not converge", ErrRegistry)
	}
	return nil
}

func (client *HarborClient) getProjectQuota(ctx context.Context, projectID int64) (harborQuota, error) {
	if projectID <= 0 {
		return harborQuota{}, fmt.Errorf("%w: Harbor project quota identity is invalid", ErrRegistry)
	}
	query := url.Values{}
	query.Set("reference", "project")
	query.Set("reference_id", strconv.FormatInt(projectID, 10))
	query.Set("page", "1")
	query.Set("page_size", "100")
	var quotas []harborQuota
	status, err := client.doJSON(ctx, http.MethodGet, "/api/v2.0/quotas?"+query.Encode(), nil, &quotas, nil)
	if err != nil || status != http.StatusOK || len(quotas) != 1 || quotas[0].ID <= 0 || quotas[0].Hard == nil {
		return harborQuota{}, fmt.Errorf("%w: get Harbor project storage quota", ErrRegistry)
	}
	return quotas[0], nil
}

func (client *HarborClient) getProject(ctx context.Context, projectName string) (harborProject, bool, error) {
	var project harborProject
	status, err := client.doJSON(ctx, http.MethodGet, "/api/v2.0/projects/"+projectName, nil, &project, map[string]string{"X-Is-Resource-Name": "true"})
	if status == http.StatusNotFound && err == nil {
		return harborProject{}, false, nil
	}
	if err != nil || status != http.StatusOK {
		return harborProject{}, false, fmt.Errorf("%w: get Harbor project", ErrRegistry)
	}
	return project, true, nil
}

func expectedProjectMetadata() map[string]string {
	return map[string]string{
		"public": "false", "auto_scan": "false", "auto_sbom_generation": "false", "reuse_sys_cve_allowlist": "true",
	}
}

func equalMetadata(actual, expected map[string]string) bool {
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func (client *HarborClient) ensureImmutability(ctx context.Context, projectName string) error {
	var rules []immutableRule
	status, err := client.doJSON(ctx, http.MethodGet, "/api/v2.0/projects/"+projectName+"/immutabletagrules?page=1&page_size=100", nil, &rules, map[string]string{"X-Is-Resource-Name": "true"})
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("%w: list Harbor immutable rules", ErrRegistry)
	}
	expected := expectedImmutableRule()
	for _, rule := range rules {
		if sameImmutableRule(rule, expected) {
			if rule.Disabled {
				expected.ID = rule.ID
				status, err = client.doJSON(ctx, http.MethodPut, "/api/v2.0/projects/"+projectName+"/immutabletagrules/"+strconv.FormatInt(rule.ID, 10), expected, nil, map[string]string{"X-Is-Resource-Name": "true"})
				if err != nil || status != http.StatusOK {
					return fmt.Errorf("%w: enable Harbor immutable rule", ErrRegistry)
				}
			}
			return nil
		}
	}
	status, err = client.doJSON(ctx, http.MethodPost, "/api/v2.0/projects/"+projectName+"/immutabletagrules", expected, nil, map[string]string{"X-Is-Resource-Name": "true"})
	if err != nil || status != http.StatusCreated {
		return fmt.Errorf("%w: create Harbor immutable rule", ErrRegistry)
	}
	return nil
}

func expectedImmutableRule() immutableRule {
	return immutableRule{
		Disabled: false, Action: "immutable", Template: "immutable_template", Params: map[string]any{},
		TagSelectors:   []immutableSelector{{Kind: "doublestar", Decoration: "matches", Pattern: "**"}},
		ScopeSelectors: map[string][]immutableSelector{"repository": {{Kind: "doublestar", Decoration: "repoMatches", Pattern: "**"}}},
	}
}

func sameImmutableRule(actual, expected immutableRule) bool {
	return actual.Action == expected.Action && actual.Template == expected.Template && slices.Equal(actual.TagSelectors, expected.TagSelectors) &&
		slices.Equal(actual.ScopeSelectors["repository"], expected.ScopeSelectors["repository"])
}

func (client *HarborClient) CreatePushRobot(ctx context.Context, projectName, buildID string) (harborRobotCreated, error) {
	build, err := platformID(buildID, "bld")
	if err != nil || !harborNamePattern.MatchString(projectName) {
		return harborRobotCreated{}, errors.New("Harbor robot scope is invalid")
	}
	nameDigest := sha256Text(buildID)
	request := harborRobotCreate{
		Name: "publish-" + nameDigest[:24], Description: "Lrail ephemeral publisher for " + string(build),
		Level: "project", Disable: false, Duration: 1,
		Permissions: []robotPermission{{Kind: "project", Namespace: projectName, Access: []robotAccess{{Resource: "repository", Action: "pull"}, {Resource: "repository", Action: "push"}}}},
	}
	var created harborRobotCreated
	status, err := client.doJSON(ctx, http.MethodPost, "/api/v2.0/robots", request, &created, nil)
	if err != nil || status != http.StatusCreated || created.ID <= 0 || created.Name == "" || len(created.Name) > 255 || created.Secret == "" || len(created.Secret) > 4096 || created.ExpiresAt <= client.clock().UTC().Unix() {
		return harborRobotCreated{}, fmt.Errorf("%w: create Harbor robot", ErrRegistry)
	}
	return created, nil
}

func (client *HarborClient) DeleteRobot(ctx context.Context, robotID int64) error {
	if robotID <= 0 {
		return errors.New("Harbor robot identity is invalid")
	}
	status, err := client.doJSON(ctx, http.MethodDelete, "/api/v2.0/robots/"+strconv.FormatInt(robotID, 10), nil, nil, nil)
	if err != nil || status != http.StatusOK && status != http.StatusNotFound {
		return fmt.Errorf("%w: delete Harbor robot", ErrRegistry)
	}
	return nil
}

func (client *HarborClient) RepositoryToken(ctx context.Context, robot harborRobotCreated, projectName, repository string, requestedExpiry time.Time) (string, time.Time, error) {
	fullName, err := fullRepository(projectName, repository)
	if err != nil || robot.Name == "" || robot.Secret == "" {
		return "", time.Time{}, errors.New("Harbor repository token scope is invalid")
	}
	query := url.Values{}
	query.Set("service", "harbor-registry")
	query.Set("scope", "repository:"+fullName+":pull,push")
	var tokenResponse harborTokenResponse
	status, err := client.doJSONWithBasic(ctx, http.MethodGet, "/service/token?"+query.Encode(), nil, &tokenResponse, robot.Name, []byte(robot.Secret))
	if err != nil || status != http.StatusOK || tokenResponse.ExpiresIn <= 0 || tokenResponse.ExpiresIn > int64(MaxCapabilityTTL/time.Second) {
		return "", time.Time{}, fmt.Errorf("%w: issue Harbor repository token", ErrRegistry)
	}
	token := tokenResponse.Token
	if token == "" {
		token = tokenResponse.AccessToken
	}
	now := client.clock().UTC()
	expiresAt, err := validateRegistryToken(token, fullName, now)
	if err != nil {
		return "", time.Time{}, err
	}
	if requestedExpiry = requestedExpiry.UTC(); !expiresAt.After(now) || expiresAt.After(requestedExpiry) {
		return "", time.Time{}, fmt.Errorf("%w: Harbor repository token lifetime exceeds requested authority", ErrRegistry)
	}
	return token, expiresAt, nil
}

func validateRegistryToken(token, fullRepository string, now time.Time) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(token) > 64<<10 {
		return time.Time{}, fmt.Errorf("%w: Harbor token is not a bounded JWT", ErrRegistry)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payload) == 0 || len(payload) > 16<<10 {
		return time.Time{}, fmt.Errorf("%w: Harbor token claims are invalid", ErrRegistry)
	}
	var claims registryTokenClaims
	if err := decodeExternalJSON(payload, &claims); err != nil || claims.Audience != "harbor-registry" || claims.Expires <= now.Unix() || claims.Expires > now.Add(MaxCapabilityTTL).Unix() || len(claims.Access) != 1 {
		return time.Time{}, fmt.Errorf("%w: Harbor token claims exceed requested authority", ErrRegistry)
	}
	access := claims.Access[0]
	actions := append([]string(nil), access.Actions...)
	slices.Sort(actions)
	if access.Type != "repository" || access.Name != fullRepository || !slices.Equal(actions, []string{"pull", "push"}) {
		return time.Time{}, fmt.Errorf("%w: Harbor token repository scope differs", ErrRegistry)
	}
	return time.Unix(claims.Expires, 0).UTC(), nil
}

func (client *HarborClient) doJSON(ctx context.Context, method, requestPath string, body, destination any, headers map[string]string) (int, error) {
	return client.doJSONWithBasic(ctx, method, requestPath, body, destination, client.adminUsername, client.adminPassword, headers)
}

func (client *HarborClient) doJSONWithBasic(ctx context.Context, method, requestPath string, body, destination any, username string, password []byte, extraHeaders ...map[string]string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	requestURL, err := client.endpoint.Parse(requestPath)
	if err != nil || requestURL.Scheme != client.endpoint.Scheme || requestURL.Host != client.endpoint.Host {
		return 0, errors.New("Harbor request URL is invalid")
	}
	var payload io.Reader
	if body != nil {
		contents, err := json.Marshal(body)
		if err != nil || len(contents) > MaxHarborBodyBytes {
			return 0, errors.New("Harbor request body is invalid")
		}
		payload = bytes.NewReader(contents)
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), payload)
	if err != nil {
		return 0, errors.New("create Harbor request")
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	if username != "" {
		request.SetBasicAuth(username, string(password))
	}
	for _, headers := range extraHeaders {
		for name, value := range headers {
			request.Header.Set(name, value)
		}
	}
	response, err := client.http.Do(request)
	if err != nil {
		return 0, errors.New("send Harbor request")
	}
	defer response.Body.Close()
	contents, err := io.ReadAll(io.LimitReader(response.Body, MaxHarborBodyBytes+1))
	if err != nil || len(contents) > MaxHarborBodyBytes {
		return response.StatusCode, errors.New("read Harbor response")
	}
	if response.StatusCode >= 300 && response.StatusCode != http.StatusNotFound && response.StatusCode != http.StatusConflict {
		return response.StatusCode, errors.New("Harbor rejected request")
	}
	if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusConflict {
		return response.StatusCode, nil
	}
	if destination != nil {
		if len(contents) == 0 || decodeExternalJSON(contents, destination) != nil {
			return response.StatusCode, errors.New("decode Harbor response")
		}
	}
	return response.StatusCode, nil
}

func decodeExternalJSON(contents []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("JSON response contains trailing data")
	}
	return nil
}

func sha256Text(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func platformID(value, prefix string) (platformid.ID, error) {
	parsed, err := platformid.Parse(value)
	if err != nil || parsed.Prefix() != prefix {
		return "", errors.New("platform identity is invalid")
	}
	return parsed, nil
}
