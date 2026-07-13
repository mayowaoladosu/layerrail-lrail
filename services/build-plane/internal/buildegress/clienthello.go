package buildegress

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

const maxClientHelloBytes = 64 << 10
const clientHelloTimeout = 10 * time.Second

// readValidatedClientHello consumes only the initial TLS ClientHello, verifies
// exact SNI, and returns the original records for forwarding without TLS
// interception. Public HTTPS tunnels fail closed on plaintext, missing SNI,
// domain fronting, ECH-only names, malformed records, and oversized hellos.
func readValidatedClientHello(connection net.Conn, expectedDomain string) ([]byte, error) {
	if connection == nil || !validHostname(expectedDomain) {
		return nil, errors.New("TLS ClientHello validation input is invalid")
	}
	_ = connection.SetReadDeadline(time.Now().Add(clientHelloTimeout))
	defer connection.SetReadDeadline(time.Time{})
	var raw []byte
	var handshake []byte
	handshakeLength := -1
	for len(raw) < maxClientHelloBytes {
		header := make([]byte, 5)
		if _, err := io.ReadFull(connection, header); err != nil {
			return nil, errors.New("read TLS record header")
		}
		if header[0] != 22 || header[1] != 3 || header[2] > 4 {
			return nil, errors.New("tunnel did not begin with a TLS handshake")
		}
		recordLength := int(binary.BigEndian.Uint16(header[3:5]))
		if recordLength == 0 || recordLength > 18<<10 || len(raw)+5+recordLength > maxClientHelloBytes {
			return nil, errors.New("TLS ClientHello record size is invalid")
		}
		payload := make([]byte, recordLength)
		if _, err := io.ReadFull(connection, payload); err != nil {
			return nil, errors.New("read TLS record payload")
		}
		raw = append(raw, header...)
		raw = append(raw, payload...)
		handshake = append(handshake, payload...)
		if handshakeLength < 0 && len(handshake) >= 4 {
			if handshake[0] != 1 {
				return nil, errors.New("first TLS handshake message is not ClientHello")
			}
			handshakeLength = 4 + int(handshake[1])<<16 + int(handshake[2])<<8 + int(handshake[3])
			if handshakeLength < 4 || handshakeLength > maxClientHelloBytes {
				return nil, errors.New("TLS ClientHello handshake size is invalid")
			}
		}
		if handshakeLength >= 0 && len(handshake) >= handshakeLength {
			if len(handshake) != handshakeLength {
				return nil, errors.New("TLS record carries data after ClientHello")
			}
			serverName, err := clientHelloServerName(handshake[4:])
			if err != nil || serverName != expectedDomain {
				return nil, errors.New("TLS ClientHello SNI differs from CONNECT domain")
			}
			return raw, nil
		}
	}
	return nil, errors.New("TLS ClientHello exceeds limit")
}

func clientHelloServerName(hello []byte) (string, error) {
	cursor := 0
	take := func(length int) ([]byte, bool) {
		if length < 0 || cursor > len(hello)-length {
			return nil, false
		}
		value := hello[cursor : cursor+length]
		cursor += length
		return value, true
	}
	if _, ok := take(2 + 32); !ok {
		return "", errors.New("TLS ClientHello fixed fields are truncated")
	}
	sessionLength, ok := take(1)
	if !ok {
		return "", errors.New("TLS ClientHello session ID is truncated")
	}
	if _, ok := take(int(sessionLength[0])); !ok {
		return "", errors.New("TLS ClientHello session ID is truncated")
	}
	cipherLengthBytes, ok := take(2)
	if !ok {
		return "", errors.New("TLS ClientHello cipher suites are truncated")
	}
	cipherLength := int(binary.BigEndian.Uint16(cipherLengthBytes))
	if cipherLength == 0 || cipherLength%2 != 0 {
		return "", errors.New("TLS ClientHello cipher suites are invalid")
	}
	if _, ok := take(cipherLength); !ok {
		return "", errors.New("TLS ClientHello cipher suites are truncated")
	}
	compressionLength, ok := take(1)
	if !ok || compressionLength[0] == 0 {
		return "", errors.New("TLS ClientHello compression methods are invalid")
	}
	if _, ok := take(int(compressionLength[0])); !ok {
		return "", errors.New("TLS ClientHello compression methods are truncated")
	}
	extensionLengthBytes, ok := take(2)
	if !ok {
		return "", errors.New("TLS ClientHello extensions are absent")
	}
	extensionLength := int(binary.BigEndian.Uint16(extensionLengthBytes))
	extensions, ok := take(extensionLength)
	if !ok || cursor != len(hello) {
		return "", errors.New("TLS ClientHello extensions are truncated")
	}
	return serverNameExtension(extensions)
}

func serverNameExtension(extensions []byte) (string, error) {
	serverName := ""
	for len(extensions) > 0 {
		if len(extensions) < 4 {
			return "", errors.New("TLS extension header is truncated")
		}
		extensionType := binary.BigEndian.Uint16(extensions[:2])
		extensionLength := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if extensionLength > len(extensions) {
			return "", errors.New("TLS extension is truncated")
		}
		value := extensions[:extensionLength]
		extensions = extensions[extensionLength:]
		if extensionType != 0 {
			continue
		}
		if serverName != "" || len(value) < 2 || int(binary.BigEndian.Uint16(value[:2])) != len(value)-2 {
			return "", errors.New("TLS server-name extension is invalid")
		}
		names := value[2:]
		for len(names) > 0 {
			if len(names) < 3 {
				return "", errors.New("TLS server-name list is truncated")
			}
			nameType := names[0]
			nameLength := int(binary.BigEndian.Uint16(names[1:3]))
			names = names[3:]
			if nameLength == 0 || nameLength > len(names) {
				return "", errors.New("TLS server name is truncated")
			}
			name := string(names[:nameLength])
			names = names[nameLength:]
			if nameType == 0 {
				if serverName != "" || name != strings.ToLower(name) || !validHostname(name) {
					return "", errors.New("TLS server name is invalid")
				}
				serverName = name
			}
		}
	}
	if serverName == "" {
		return "", errors.New("TLS ClientHello lacks SNI")
	}
	return serverName, nil
}
