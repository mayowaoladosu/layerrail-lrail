package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServerHandlerRoutesAuthorityFormConnectAndHealth(t *testing.T) {
	t.Parallel()
	called := false
	proxy := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		called = request.Method == http.MethodConnect && request.Host == "api.github.com:443"
		response.WriteHeader(http.StatusNoContent)
	})
	handler := serverHandler(proxy)
	connect := httptest.NewRequest(http.MethodConnect, "http://api.github.com:443", nil)
	connect.Host = "api.github.com:443"
	connectResponse := httptest.NewRecorder()
	handler.ServeHTTP(connectResponse, connect)
	if !called || connectResponse.Code != http.StatusNoContent {
		t.Fatalf("called=%t status=%d", called, connectResponse.Code)
	}

	healthResponse := httptest.NewRecorder()
	handler.ServeHTTP(healthResponse, httptest.NewRequest(http.MethodGet, "http://proxy.invalid/ready", nil))
	if healthResponse.Code != http.StatusOK || healthResponse.Body.String() != "ok\n" {
		t.Fatalf("status=%d body=%q", healthResponse.Code, healthResponse.Body.String())
	}
}
