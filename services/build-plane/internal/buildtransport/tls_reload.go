package buildtransport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
)

const maxTLSFileBytes = 64 << 10

// NewReloadingServerTLSConfig reloads the leaf key pair and client roots for
// every new handshake. cert-manager can rotate projected Secret files without
// expiring a long-running controller or residue-agent process.
func NewReloadingServerTLSConfig(certificatePath, keyPath, clientCAPath string, allowedClientURIs []string) (*tls.Config, error) {
	load := func() (*tls.Config, error) {
		certificate, roots, err := loadTLSFiles(certificatePath, keyPath, clientCAPath)
		if err != nil {
			return nil, err
		}
		return NewServerTLSConfig(certificate, roots, allowedClientURIs)
	}
	initial, err := load()
	if err != nil {
		return nil, err
	}
	initial.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		configured, err := load()
		if err != nil {
			return nil, errors.New("reload mTLS server identity")
		}
		configured.Time = initial.Time
		return configured, nil
	}
	return initial, nil
}

// NewReloadingClientTLSConfig reloads the client leaf for every handshake.
// The server root is a long-lived cell trust anchor and is validated at start.
func NewReloadingClientTLSConfig(certificatePath, keyPath, serverCAPath, serverName string, allowedServerURIs []string) (*tls.Config, error) {
	certificate, roots, err := loadTLSFiles(certificatePath, keyPath, serverCAPath)
	if err != nil {
		return nil, err
	}
	configured, err := NewClientTLSConfig(certificate, roots, serverName, allowedServerURIs)
	if err != nil {
		return nil, err
	}
	configured.Certificates = nil
	configured.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		certificatePEM, err := readTLSFile(certificatePath)
		if err != nil {
			return nil, errors.New("reload mTLS client certificate")
		}
		keyPEM, err := readTLSFile(keyPath)
		if err != nil {
			return nil, errors.New("reload mTLS client key")
		}
		certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
		if err != nil {
			return nil, errors.New("parse reloaded mTLS client identity")
		}
		return &certificate, nil
	}
	return configured, nil
}

func loadTLSFiles(certificatePath, keyPath, caPath string) (tls.Certificate, *x509.CertPool, error) {
	certificatePEM, err := readTLSFile(certificatePath)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	keyPEM, err := readTLSFile(keyPath)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, errors.New("parse mTLS key pair")
	}
	caPEM, err := readTLSFile(caPath)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return tls.Certificate{}, nil, errors.New("parse mTLS trust roots")
	}
	return certificate, roots, nil
}

func readTLSFile(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("mTLS file path is empty")
	}
	contents, err := os.ReadFile(path)
	if err != nil || len(contents) == 0 || len(contents) > maxTLSFileBytes {
		return nil, errors.New("mTLS file is unavailable or oversized")
	}
	return contents, nil
}
