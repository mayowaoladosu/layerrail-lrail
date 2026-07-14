package provideregress

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type staticResolver []net.IP

func (resolver staticResolver) LookupNetIP(context.Context, string, string) ([]net.IP, error) {
	return append([]net.IP(nil), resolver...), nil
}

type pipeDialer struct {
	address string
	peer    net.Conn
}

func (dialer *pipeDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	dialer.address = address
	client, peer := net.Pipe()
	dialer.peer = peer
	return client, nil
}

func TestProxyRelaysOnlyAllowedPublicHTTPSAuthority(t *testing.T) {
	t.Parallel()
	dialer := new(pipeDialer)
	proxy, err := New(Config{
		AllowedHosts: []string{"api.github.com"}, Resolver: staticResolver{net.ParseIP("140.82.112.5")},
		Dialer: dialer, MaxConcurrent: 1, DialTimeout: time.Second, TunnelTimeout: time.Minute,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	server := httptest.NewServer(proxy.Handler())
	defer server.Close()
	connection, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := io.WriteString(connection, "CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("response=%#v error=%v", response, err)
	}
	defer response.Body.Close()
	go func() {
		defer dialer.peer.Close()
		buffer := make([]byte, 4)
		_, _ = io.ReadFull(dialer.peer, buffer)
		_, _ = dialer.peer.Write([]byte("pong"))
	}()
	if _, err := connection.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4)
	if _, err := io.ReadFull(connection, buffer); err != nil || string(buffer) != "pong" {
		t.Fatalf("body=%q error=%v", buffer, err)
	}
	if dialer.address != "140.82.112.5:443" {
		t.Fatalf("dialed %q", dialer.address)
	}
}

func TestProxyRejectsUnlistedAndPrivateDestinations(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name      string
		host      string
		addresses staticResolver
	}{
		{name: "unlisted", host: "evil.example:443", addresses: staticResolver{net.ParseIP("93.184.216.34")}},
		{name: "private resolution", host: "api.github.com:443", addresses: staticResolver{net.ParseIP("127.0.0.1")}},
		{name: "wrong port", host: "api.github.com:80", addresses: staticResolver{net.ParseIP("140.82.112.5")}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			proxy, err := New(Config{AllowedHosts: []string{"api.github.com"}, Resolver: testCase.addresses})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodConnect, "http://"+testCase.host, nil)
			request.Host = testCase.host
			response := httptest.NewRecorder()
			proxy.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusForbidden {
				t.Fatalf("status=%d", response.Code)
			}
		})
	}
}

func TestProxyRejectsMalformedConfigurationAndNonConnect(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{AllowedHosts: []string{"127.0.0.1"}, Resolver: staticResolver{net.ParseIP("93.184.216.34")}}); err == nil {
		t.Fatal("expected literal allowlist rejection")
	}
	proxy, err := New(Config{AllowedHosts: []string{"api.github.com"}, Resolver: staticResolver{net.ParseIP("140.82.112.5")}})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://api.github.com/", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", response.Code)
	}
}
