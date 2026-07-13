package buildegress

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestReadValidatedClientHelloAcceptsFragmentedHandshake(t *testing.T) {
	t.Parallel()
	original := makeClientHello(t, "packages.example.invalid")
	payload := original[5:]
	split := len(payload) / 2
	fragmented := appendTLSRecord(nil, payload[:split])
	fragmented = appendTLSRecord(fragmented, payload[split:])
	client, server := net.Pipe()
	go func() {
		_, _ = client.Write(fragmented)
		_ = client.Close()
	}()
	actual, err := readValidatedClientHello(server, "packages.example.invalid")
	_ = server.Close()
	if err != nil || string(actual) != string(fragmented) {
		t.Fatalf("fragmented ClientHello error=%v", err)
	}
}

func TestReadValidatedClientHelloRejectsMalformedInput(t *testing.T) {
	t.Parallel()
	valid := makeClientHello(t, "packages.example.invalid")
	oversized := append([]byte(nil), valid[:5]...)
	binary.BigEndian.PutUint16(oversized[3:5], uint16(19<<10))
	for name, input := range map[string][]byte{
		"plaintext": []byte("GET / HTTP/1.1\r\n\r\n"),
		"truncated": valid[:8],
		"oversized": oversized,
		"wrong SNI": makeClientHello(t, "fronted.example.invalid"),
	} {
		t.Run(name, func(t *testing.T) {
			client, server := net.Pipe()
			go func() {
				_, _ = client.Write(input)
				_ = client.Close()
			}()
			if _, err := readValidatedClientHello(server, "packages.example.invalid"); err == nil {
				t.Fatal("expected malformed ClientHello rejection")
			}
			_ = server.Close()
		})
	}
}

func FuzzClientHelloServerName(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{3, 3, 0, 1, 2, 3})
	f.Fuzz(func(t *testing.T, hello []byte) {
		if len(hello) > maxClientHelloBytes {
			t.Skip()
		}
		_, _ = clientHelloServerName(hello)
	})
}

func appendTLSRecord(destination, payload []byte) []byte {
	header := []byte{22, 3, 1, 0, 0}
	binary.BigEndian.PutUint16(header[3:5], uint16(len(payload)))
	destination = append(destination, header...)
	return append(destination, payload...)
}

func TestClientHelloReadDeadlineIsBounded(t *testing.T) {
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		_, err := readValidatedClientHello(server, "packages.example.invalid")
		done <- err
	}()
	_ = client.SetDeadline(time.Now().Add(10 * time.Millisecond))
	_, _ = io.WriteString(client, "\x16")
	_ = client.Close()
	if err := <-done; err == nil {
		t.Fatal("expected truncated ClientHello rejection")
	}
	_ = server.Close()
}
