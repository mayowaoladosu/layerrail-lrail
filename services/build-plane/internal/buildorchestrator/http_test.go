package buildorchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPBuildServiceSubmitWatchGetAndCancel(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	runner := &fakeBrokerRunner{}
	runner.run = func(_ context.Context, request Request, emit Emit, _ int) (Result, error) {
		if err := emit(progressEvent(request, now, "detecting")); err != nil {
			return Result{}, err
		}
		result := failedBrokerResult(request, now, "detect_http_fixture")
		if err := emit(terminalBrokerEvent(request, now.Add(time.Second), result)); err != nil {
			return Result{}, err
		}
		return result, nil
	}
	broker, store := testBroker(t, runner, now, 2)
	defer closeTestBroker(t, broker, store)
	handler, err := NewHTTPHandler(broker, 32)
	if err != nil {
		t.Fatalf("NewHTTPHandler: %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	request := validRequest(now)

	response := buildServiceRequest(t, http.MethodPost, server.URL+"/v1/builds:submit", request)
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("submit status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	var accepted RunRecord
	decodeResponse(t, response, &accepted)
	if accepted.Request.BuildID != request.BuildID || accepted.RequestDigest == "" {
		t.Fatalf("accepted = %#v", accepted)
	}

	watchURL := server.URL + "/v1/builds/" + request.BuildID + "/events?generation=1&after=0&limit=100&wait_seconds=1"
	response = buildServiceRequest(t, http.MethodGet, watchURL, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("watch status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	var watched watchResponse
	decodeResponse(t, response, &watched)
	if len(watched.Events) == 0 || watched.Events[0].Sequence != 1 {
		t.Fatalf("watched = %#v", watched)
	}
	if !watched.Run.Terminal() {
		_, watched.Run = waitBrokerTerminal(t, broker, request, watched.Events[len(watched.Events)-1].Sequence)
	}

	response = buildServiceRequest(t, http.MethodGet, server.URL+"/v1/builds/"+request.BuildID+"?generation=1", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("get status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	var found RunRecord
	decodeResponse(t, response, &found)
	if !found.Terminal() || found.Result == nil {
		t.Fatalf("found = %#v", found)
	}

	response = buildServiceRequest(t, http.MethodPost, server.URL+"/v1/builds/"+request.BuildID+":cancel", cancelRequest{Generation: 1, Reason: "idempotent terminal cancellation"})
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("cancel status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	var canceled RunRecord
	decodeResponse(t, response, &canceled)
	if canceled.State != found.State {
		t.Fatalf("terminal cancellation changed state: %#v", canceled)
	}
}

func TestHTTPBuildServiceRejectsUnknownFieldsCredentialsAndForeignBuilds(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	runner := &fakeBrokerRunner{run: func(context.Context, Request, Emit, int) (Result, error) {
		return Result{}, nil
	}}
	broker, store := testBroker(t, runner, now, 1)
	defer closeTestBroker(t, broker, store)
	handler, _ := NewHTTPHandler(broker, 8)
	server := httptest.NewServer(handler)
	defer server.Close()

	unknown := map[string]any{"version": 1, "unexpected": true}
	response := buildServiceRequest(t, http.MethodPost, server.URL+"/v1/builds:submit", unknown)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown-field status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	request := validRequest(now)
	request.Source.ArchiveRef = "s3://access:secret@source/archive.tar.gz"
	response = buildServiceRequest(t, http.MethodPost, server.URL+"/v1/builds:submit", request)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("credential status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	response = buildServiceRequest(t, http.MethodGet, server.URL+"/v1/builds/bld_019b01da-7e31-7000-8000-000000000099?generation=1", nil)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("foreign status=%d body=%s", response.StatusCode, readResponse(t, response))
	}
	plain, err := http.Post(server.URL+"/v1/builds:submit", "text/plain", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatalf("plain submit: %v", err)
	}
	if plain.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("plain status=%d body=%s", plain.StatusCode, readResponse(t, plain))
	}
	_ = plain.Body.Close()
}

func buildServiceRequest(t *testing.T, method, target string, body any) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		contents, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		reader = bytes.NewReader(contents)
	}
	request, err := http.NewRequest(method, target, reader)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("HTTP request: %v", err)
	}
	return response
}

func decodeResponse(t *testing.T, response *http.Response, destination any) {
	t.Helper()
	defer response.Body.Close()
	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(destination); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

func readResponse(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	contents, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return string(contents)
}
