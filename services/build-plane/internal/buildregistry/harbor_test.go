package buildregistry

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const registryOrgID = "org_019b01da-7e31-7000-8000-000000000001"
const registryProjectID = "prj_019b01da-7e31-7000-8000-000000000002"
const registryBuildID = "bld_019b01da-7e31-7000-8000-000000000003"

var registryNow = time.Date(2026, 7, 13, 11, 0, 0, 0, time.UTC)

type fakeHarbor struct {
	mu              sync.Mutex
	server          *httptest.Server
	project         *harborProject
	rule            *immutableRule
	robots          map[int64]harborRobotCreated
	nextRobot       int64
	projectCreates  int
	projectUpdates  int
	ruleCreates     int
	robotCreates    int
	robotDeletes    int
	tokenRequests   int
	wrongTokenScope bool
	adminUsername   string
	adminPassword   string
}

func newFakeHarbor(t *testing.T) *fakeHarbor {
	t.Helper()
	fake := &fakeHarbor{
		robots: make(map[int64]harborRobotCreated), nextRobot: 40,
		adminUsername: "admin", adminPassword: "test-admin-password",
	}
	fake.server = httptest.NewTLSServer(http.HandlerFunc(fake.handle))
	t.Cleanup(fake.server.Close)
	return fake
}

func (fake *fakeHarbor) client(t *testing.T) *HarborClient {
	t.Helper()
	client := fake.server.Client()
	client.Timeout = 5 * time.Second
	harbor, err := NewHarborClient(HarborConfig{
		Endpoint: fake.server.URL, Registry: fake.server.URL, AdminUsername: fake.adminUsername,
		AdminPassword: []byte(fake.adminPassword), HTTPClient: client, Clock: func() time.Time { return registryNow }, StorageLimit: 10 << 30,
	})
	if err != nil {
		t.Fatalf("NewHarborClient: %v", err)
	}
	t.Cleanup(harbor.Close)
	return harbor
}

func (fake *fakeHarbor) handle(response http.ResponseWriter, request *http.Request) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	response.Header().Set("Content-Type", "application/json")
	if request.URL.Path == "/service/token" {
		fake.handleToken(response, request)
		return
	}
	username, password, ok := request.BasicAuth()
	if !ok || username != fake.adminUsername || password != fake.adminPassword {
		response.WriteHeader(http.StatusUnauthorized)
		return
	}
	projectName, _ := ProjectName(registryOrgID)
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/api/v2.0/projects":
		var body harborProjectRequest
		if !decodeRequest(response, request, &body) || body.ProjectName != projectName || body.Metadata["public"] != "false" || body.Storage != 10<<30 {
			return
		}
		fake.projectCreates++
		if fake.project != nil {
			response.WriteHeader(http.StatusConflict)
			return
		}
		fake.project = &harborProject{ProjectID: 7, Name: projectName, Metadata: cloneMetadata(body.Metadata)}
		response.WriteHeader(http.StatusCreated)
	case request.Method == http.MethodGet && request.URL.Path == "/api/v2.0/projects/"+projectName:
		if request.Header.Get("X-Is-Resource-Name") != "true" || fake.project == nil {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		writeTestJSON(response, http.StatusOK, fake.project)
	case request.Method == http.MethodPut && request.URL.Path == "/api/v2.0/projects/"+projectName:
		var body harborProjectRequest
		if !decodeRequest(response, request, &body) || fake.project == nil {
			return
		}
		fake.project.Metadata = cloneMetadata(body.Metadata)
		fake.projectUpdates++
		response.WriteHeader(http.StatusOK)
	case request.Method == http.MethodGet && request.URL.Path == "/api/v2.0/projects/"+projectName+"/immutabletagrules":
		if fake.rule == nil {
			writeTestJSON(response, http.StatusOK, []immutableRule{})
			return
		}
		writeTestJSON(response, http.StatusOK, []immutableRule{*fake.rule})
	case request.Method == http.MethodPost && request.URL.Path == "/api/v2.0/projects/"+projectName+"/immutabletagrules":
		var rule immutableRule
		if !decodeRequest(response, request, &rule) || rule.Disabled || !sameImmutableRule(rule, expectedImmutableRule()) {
			return
		}
		rule.ID = 9
		fake.rule = &rule
		fake.ruleCreates++
		response.WriteHeader(http.StatusCreated)
	case request.Method == http.MethodPut && request.URL.Path == "/api/v2.0/projects/"+projectName+"/immutabletagrules/9":
		var rule immutableRule
		if !decodeRequest(response, request, &rule) || rule.Disabled {
			return
		}
		fake.rule = &rule
		response.WriteHeader(http.StatusOK)
	case request.Method == http.MethodPost && request.URL.Path == "/api/v2.0/robots":
		var body harborRobotCreate
		if !decodeRequest(response, request, &body) || body.Level != "project" || body.Duration != 1 || len(body.Permissions) != 1 || body.Permissions[0].Namespace != projectName ||
			len(body.Permissions[0].Access) != 2 || body.Permissions[0].Access[0].Action != "pull" || body.Permissions[0].Access[1].Action != "push" {
			return
		}
		fake.nextRobot++
		created := harborRobotCreated{ID: fake.nextRobot, Name: "robot$" + projectName + "+" + body.Name, Secret: "generated-robot-secret", ExpiresAt: registryNow.Add(24 * time.Hour).Unix()}
		fake.robots[created.ID] = created
		fake.robotCreates++
		writeTestJSON(response, http.StatusCreated, map[string]any{"id": created.ID, "name": created.Name, "secret": created.Secret, "expires_at": created.ExpiresAt, "creation_time": registryNow})
	case request.Method == http.MethodDelete && strings.HasPrefix(request.URL.Path, "/api/v2.0/robots/"):
		var robotID int64
		_, _ = fmt.Sscanf(strings.TrimPrefix(request.URL.Path, "/api/v2.0/robots/"), "%d", &robotID)
		if _, found := fake.robots[robotID]; !found {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		delete(fake.robots, robotID)
		fake.robotDeletes++
		response.WriteHeader(http.StatusOK)
	default:
		response.WriteHeader(http.StatusNotFound)
	}
}

func (fake *fakeHarbor) handleToken(response http.ResponseWriter, request *http.Request) {
	username, password, ok := request.BasicAuth()
	if !ok {
		response.WriteHeader(http.StatusUnauthorized)
		return
	}
	var robot harborRobotCreated
	found := false
	for _, candidate := range fake.robots {
		if candidate.Name == username && candidate.Secret == password {
			robot = candidate
			found = true
			break
		}
	}
	if !found || request.URL.Query().Get("service") != "harbor-registry" {
		response.WriteHeader(http.StatusUnauthorized)
		return
	}
	requested := request.URL.Query().Get("scope")
	if !strings.HasPrefix(requested, "repository:") || !strings.HasSuffix(requested, ":pull,push") {
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	fullRepository := strings.TrimSuffix(strings.TrimPrefix(requested, "repository:"), ":pull,push")
	if fake.wrongTokenScope {
		fullRepository += "-foreign"
	}
	claims := map[string]any{
		"iss": fake.server.URL, "sub": robot.Name, "aud": "harbor-registry", "iat": registryNow.Unix(), "exp": registryNow.Add(10 * time.Minute).Unix(),
		"access": []map[string]any{{"type": "repository", "name": fullRepository, "actions": []string{"push", "pull"}}},
	}
	fake.tokenRequests++
	writeTestJSON(response, http.StatusOK, map[string]any{"token": fakeJWT(claims), "expires_in": 600, "issued_at": registryNow.Format(time.RFC3339), "extra": "ignored"})
}

func fakeJWT(claims any) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func TestHarborClientEnsuresPrivateImmutableProjectAndScopedToken(t *testing.T) {
	t.Parallel()
	fake := newFakeHarbor(t)
	client := fake.client(t)
	projectName, err := client.EnsureProject(t.Context(), registryOrgID)
	if err != nil {
		t.Fatalf("EnsureProject: %v", err)
	}
	if _, err := client.EnsureProject(t.Context(), registryOrgID); err != nil {
		t.Fatalf("EnsureProject replay: %v", err)
	}
	if fake.projectCreates != 1 || fake.ruleCreates != 1 || fake.project.Metadata["public"] != "false" {
		t.Fatalf("project state: %#v", fake)
	}
	robot, err := client.CreatePushRobot(t.Context(), projectName, registryBuildID)
	if err != nil {
		t.Fatalf("CreatePushRobot: %v", err)
	}
	repository, _ := RepositoryName(registryProjectID, "api")
	token, expiresAt, err := client.RepositoryToken(t.Context(), robot, projectName, repository, registryNow.Add(12*time.Minute))
	if err != nil || token == "" || !expiresAt.Equal(registryNow.Add(10*time.Minute)) {
		t.Fatalf("token=%q expires=%s error=%v", token, expiresAt, err)
	}
	if err := client.DeleteRobot(t.Context(), robot.ID); err != nil {
		t.Fatalf("DeleteRobot: %v", err)
	}
	if fake.robotCreates != 1 || fake.robotDeletes != 1 || fake.tokenRequests != 1 || len(fake.robots) != 0 {
		t.Fatalf("robot state: %#v", fake)
	}
}

func TestHarborClientRejectsBroaderTokenScope(t *testing.T) {
	t.Parallel()
	fake := newFakeHarbor(t)
	fake.wrongTokenScope = true
	client := fake.client(t)
	projectName, _ := client.EnsureProject(t.Context(), registryOrgID)
	robot, _ := client.CreatePushRobot(t.Context(), projectName, registryBuildID)
	repository, _ := RepositoryName(registryProjectID, "api")
	if _, _, err := client.RepositoryToken(t.Context(), robot, projectName, repository, registryNow.Add(10*time.Minute)); err == nil {
		t.Fatal("expected broader repository token rejection")
	}
}

func TestProjectAndRepositoryNamesBindImmutableTenantScope(t *testing.T) {
	t.Parallel()
	projectName, err := ProjectName(registryOrgID)
	if err != nil || !strings.HasPrefix(projectName, "lrail-") || len(projectName) != len("lrail-")+sha256.Size*2 {
		t.Fatalf("projectName=%q error=%v", projectName, err)
	}
	other, _ := ProjectName("org_019b01da-7e31-7000-8000-000000000004")
	if projectName == other {
		t.Fatal("organization project names collided")
	}
	repository, err := RepositoryName(registryProjectID, "api")
	if err != nil || !repositoryPattern.MatchString(repository) || !strings.HasSuffix(repository, "/api") {
		t.Fatalf("repository=%q error=%v", repository, err)
	}
	if _, err := RepositoryName(registryProjectID, "../escape"); err == nil {
		t.Fatal("expected repository traversal rejection")
	}
	digest := sha256.Sum256([]byte(registryProjectID))
	if !strings.Contains(repository, hex.EncodeToString(digest[:16])) {
		t.Fatal("repository does not bind project identity")
	}
}

func decodeRequest(response http.ResponseWriter, request *http.Request, destination any) bool {
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		response.WriteHeader(http.StatusBadRequest)
		return false
	}
	return true
}

func writeTestJSON(response http.ResponseWriter, status int, value any) {
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func cloneMetadata(values map[string]string) map[string]string {
	clone := make(map[string]string, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func TestNormalizeRegistryURLRejectsCredentialsAndInsecureOrigins(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"http://harbor.invalid", "https://user:pass@harbor.invalid", "https://harbor.invalid/path", "https://harbor.invalid?query=1"} {
		if _, err := normalizeRegistryURL(value); err == nil {
			t.Fatalf("expected URL rejection for %q", value)
		}
	}
	if value, err := normalizeRegistryURL("https://harbor.invalid"); err != nil || value != "https://harbor.invalid" {
		t.Fatalf("normalized=%q error=%v", value, err)
	}
	parsed, _ := url.Parse("https://harbor.invalid")
	if parsed.Host != "harbor.invalid" {
		t.Fatal("URL test fixture is invalid")
	}
}
