package buildorchestrator

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const MaxBuildServiceRequestBytes int64 = 64 << 10

type HTTPHandler struct {
	broker   *Broker
	clock    func() time.Time
	capacity chan struct{}
}

type watchResponse struct {
	Events []Event   `json:"events"`
	Run    RunRecord `json:"run"`
}

type cancelRequest struct {
	Generation uint64 `json:"generation"`
	Reason     string `json:"reason"`
}

type errorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func NewHTTPHandler(broker *Broker, maxConcurrent int) (*HTTPHandler, error) {
	if broker == nil || maxConcurrent < 1 || maxConcurrent > 4096 {
		return nil, errors.New("build service HTTP configuration is invalid")
	}
	return &HTTPHandler{broker: broker, clock: time.Now, capacity: make(chan struct{}, maxConcurrent)}, nil
}

func (handler *HTTPHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	select {
	case handler.capacity <- struct{}{}:
		defer func() { <-handler.capacity }()
	default:
		handler.writeError(response, http.StatusServiceUnavailable, "build_service_busy", "Build service capacity is busy")
		return
	}
	switch {
	case request.URL.Path == "/live" && request.Method == http.MethodGet:
		handler.writeJSON(response, http.StatusOK, map[string]string{"status": "live"})
	case request.URL.Path == "/ready" && request.Method == http.MethodGet:
		handler.writeJSON(response, http.StatusOK, map[string]string{"status": "ready"})
	case request.URL.Path == "/v1/builds:submit" && request.Method == http.MethodPost:
		handler.submit(response, request)
	case strings.HasPrefix(request.URL.Path, "/v1/builds/"):
		handler.build(response, request)
	default:
		handler.writeError(response, http.StatusNotFound, "not_found", "Build service route was not found")
	}
}

func (handler *HTTPHandler) submit(response http.ResponseWriter, request *http.Request) {
	if len(request.URL.Query()) != 0 {
		handler.writeError(response, http.StatusBadRequest, "query_invalid", "Submit does not accept query parameters")
		return
	}
	if !jsonContentType(request.Header.Get("Content-Type")) {
		handler.writeError(response, http.StatusUnsupportedMediaType, "content_type_invalid", "Content-Type must be application/json")
		return
	}
	var build Request
	if err := decodeRequest(request, &build); err != nil || build.Validate(handler.clock().UTC()) != nil {
		handler.writeError(response, http.StatusBadRequest, "build_request_invalid", "Build request is invalid")
		return
	}
	record, err := handler.broker.Submit(request.Context(), build)
	if err != nil {
		handler.writeError(response, http.StatusConflict, "build_request_conflict", "Build generation conflicts with durable state")
		return
	}
	handler.writeJSON(response, http.StatusAccepted, record)
}

func (handler *HTTPHandler) build(response http.ResponseWriter, request *http.Request) {
	remainder := strings.TrimPrefix(request.URL.Path, "/v1/builds/")
	watch := strings.HasSuffix(remainder, "/events")
	cancel := strings.HasSuffix(remainder, ":cancel")
	buildID := strings.TrimSuffix(strings.TrimSuffix(remainder, "/events"), ":cancel")
	if strings.Contains(buildID, "/") || buildID == "" {
		handler.writeError(response, http.StatusNotFound, "not_found", "Build service route was not found")
		return
	}
	switch {
	case watch && request.Method == http.MethodGet:
		handler.watch(response, request, buildID)
	case cancel && request.Method == http.MethodPost:
		handler.cancel(response, request, buildID)
	case !watch && !cancel && request.Method == http.MethodGet:
		handler.get(response, request, buildID)
	default:
		response.Header().Set("Allow", allowedMethod(watch, cancel))
		handler.writeError(response, http.StatusMethodNotAllowed, "method_not_allowed", "HTTP method is not allowed")
	}
}

func (handler *HTTPHandler) get(response http.ResponseWriter, request *http.Request, buildID string) {
	if !onlyQueryKeys(request, "generation") {
		handler.writeError(response, http.StatusBadRequest, "query_invalid", "Build query contains an unknown parameter")
		return
	}
	generation, err := queryUint(request, "generation", false)
	if err != nil {
		handler.writeError(response, http.StatusBadRequest, "generation_invalid", "Build generation is invalid")
		return
	}
	record, found, err := handler.broker.Get(request.Context(), buildID, generation)
	if err != nil || !found {
		handler.writeError(response, http.StatusNotFound, "build_not_found", "Build generation was not found")
		return
	}
	handler.writeJSON(response, http.StatusOK, record)
}

func (handler *HTTPHandler) watch(response http.ResponseWriter, request *http.Request, buildID string) {
	if !onlyQueryKeys(request, "generation", "after", "limit", "wait_seconds") {
		handler.writeError(response, http.StatusBadRequest, "query_invalid", "Build event query contains an unknown parameter")
		return
	}
	generation, generationErr := queryUint(request, "generation", false)
	after, afterErr := queryUint(request, "after", true)
	limitValue, limitErr := queryUint(request, "limit", true)
	waitValue, waitErr := queryUint(request, "wait_seconds", true)
	if generationErr != nil || afterErr != nil || limitErr != nil || waitErr != nil || limitValue > 1000 || waitValue > uint64(MaxWatchDuration/time.Second) {
		handler.writeError(response, http.StatusBadRequest, "watch_cursor_invalid", "Build event cursor is invalid")
		return
	}
	limit := int(limitValue)
	events, record, err := handler.broker.Watch(request.Context(), buildID, generation, after, limit, time.Duration(waitValue)*time.Second)
	if err != nil {
		handler.writeError(response, http.StatusNotFound, "build_not_found", "Build generation was not found")
		return
	}
	if events == nil {
		events = []Event{}
	}
	handler.writeJSON(response, http.StatusOK, watchResponse{Events: events, Run: record})
}

func (handler *HTTPHandler) cancel(response http.ResponseWriter, request *http.Request, buildID string) {
	if len(request.URL.Query()) != 0 {
		handler.writeError(response, http.StatusBadRequest, "query_invalid", "Cancellation does not accept query parameters")
		return
	}
	if !jsonContentType(request.Header.Get("Content-Type")) {
		handler.writeError(response, http.StatusUnsupportedMediaType, "content_type_invalid", "Content-Type must be application/json")
		return
	}
	var input cancelRequest
	if err := decodeRequest(request, &input); err != nil || input.Generation == 0 || input.Reason == "" || len(input.Reason) > 512 {
		handler.writeError(response, http.StatusBadRequest, "cancel_request_invalid", "Build cancellation request is invalid")
		return
	}
	record, err := handler.broker.Cancel(request.Context(), buildID, input.Generation, input.Reason)
	if err != nil {
		handler.writeError(response, http.StatusNotFound, "build_not_found", "Build generation was not found")
		return
	}
	handler.writeJSON(response, http.StatusAccepted, record)
}

func decodeRequest(request *http.Request, destination any) error {
	defer request.Body.Close()
	reader := io.LimitReader(request.Body, MaxBuildServiceRequestBytes+1)
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request has trailing data")
	}
	return nil
}

func queryUint(request *http.Request, name string, optional bool) (uint64, error) {
	values, found := request.URL.Query()[name]
	if !found {
		if optional {
			return 0, nil
		}
		return 0, errors.New("query parameter is absent")
	}
	if len(values) != 1 || values[0] == "" {
		return 0, errors.New("query parameter is ambiguous")
	}
	value, err := strconv.ParseUint(values[0], 10, 64)
	if err != nil || (!optional && value == 0) {
		return 0, errors.New("query parameter is invalid")
	}
	return value, nil
}

func onlyQueryKeys(request *http.Request, allowed ...string) bool {
	accepted := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		accepted[key] = struct{}{}
	}
	for key := range request.URL.Query() {
		if _, found := accepted[key]; !found {
			return false
		}
	}
	return true
}

func (handler *HTTPHandler) writeJSON(response http.ResponseWriter, status int, value any) {
	contents, err := json.Marshal(value)
	if err != nil {
		handler.writeError(response, http.StatusInternalServerError, "response_invalid", "Build service response could not be encoded")
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_, _ = response.Write(append(contents, '\n'))
}

func (handler *HTTPHandler) writeError(response http.ResponseWriter, status int, code, message string) {
	value := errorResponse{}
	value.Error.Code = code
	value.Error.Message = message
	contents, _ := json.Marshal(value)
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(status)
	_, _ = response.Write(append(contents, '\n'))
}

func jsonContentType(value string) bool {
	value, _, _ = strings.Cut(strings.ToLower(strings.TrimSpace(value)), ";")
	return value == "application/json"
}

func allowedMethod(watch, cancel bool) string {
	if watch {
		return http.MethodGet
	}
	if cancel {
		return http.MethodPost
	}
	return http.MethodGet
}
