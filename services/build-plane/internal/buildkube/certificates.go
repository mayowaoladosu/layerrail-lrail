package buildkube

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildegress"
)

type CertificateRequest struct {
	WorkerName string
	DNSName    string
	ExpiresAt  time.Time
	Egress     buildegress.Policy
}

type IssuedCertificates struct {
	Material     TLSMaterial
	ClientConfig *tls.Config
}

type CertificateIssuer interface {
	Issue(ctx context.Context, request CertificateRequest) (IssuedCertificates, error)
}

type EphemeralCertificateIssuer struct {
	Clock func() time.Time
}

// PolicyCertificateIssuer combines the one-worker BuildKit CA with the
// cell-owned egress capability CA. The latter's private key stays in control.
type PolicyCertificateIssuer struct {
	Worker     CertificateIssuer
	Egress     *buildegress.CertificateAuthority
	LoadEgress func() (*buildegress.CertificateAuthority, error)
}

func (issuer PolicyCertificateIssuer) Issue(ctx context.Context, request CertificateRequest) (IssuedCertificates, error) {
	hasStaticIssuer := issuer.Egress != nil
	hasReloadingIssuer := issuer.LoadEgress != nil
	if issuer.Worker == nil || hasStaticIssuer == hasReloadingIssuer {
		return IssuedCertificates{}, errors.New("combined worker certificate issuer is incomplete")
	}
	egressIssuer := issuer.Egress
	if issuer.LoadEgress != nil {
		var err error
		egressIssuer, err = issuer.LoadEgress()
		if err != nil || egressIssuer == nil {
			return IssuedCertificates{}, errors.New("reload egress certificate issuer")
		}
	}
	issued, err := issuer.Worker.Issue(ctx, request)
	if err != nil {
		return IssuedCertificates{}, err
	}
	egress, err := egressIssuer.Issue(ctx, request.Egress)
	if err != nil {
		return IssuedCertificates{}, err
	}
	issued.Material.EgressClientCert = egress.Certificate
	issued.Material.EgressClientKey = egress.PrivateKey
	issued.Material.EgressServerCA = egress.ServerCA
	return issued, nil
}

func (issuer EphemeralCertificateIssuer) Issue(ctx context.Context, request CertificateRequest) (IssuedCertificates, error) {
	if err := ctx.Err(); err != nil {
		return IssuedCertificates{}, err
	}
	if issuer.Clock == nil {
		issuer.Clock = time.Now
	}
	now := issuer.Clock().UTC()
	if request.WorkerName == "" || request.DNSName == "" || !request.ExpiresAt.After(now) || request.ExpiresAt.Sub(now) > DefaultActiveDeadline {
		return IssuedCertificates{}, errors.New("worker certificate request is invalid")
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return IssuedCertificates{}, errors.New("generate worker CA key")
	}
	serial, err := randomSerial()
	if err != nil {
		return IssuedCertificates{}, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Lrail ephemeral build worker CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: request.ExpiresAt, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return IssuedCertificates{}, errors.New("issue worker CA certificate")
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		return IssuedCertificates{}, errors.New("parse worker CA certificate")
	}
	serverURI, _ := url.Parse("spiffe://lrail.internal/build-worker/" + request.WorkerName)
	clientURI, _ := url.Parse("spiffe://lrail.internal/build-controller/" + request.WorkerName)
	serverCertificate, serverPEM, serverKeyPEM, err := issueLeaf(caCertificate, caKey, now, request.ExpiresAt, request.WorkerName, []string{request.DNSName}, serverURI, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return IssuedCertificates{}, err
	}
	_ = serverCertificate
	clientCertificate, _, _, err := issueLeaf(caCertificate, caKey, now, request.ExpiresAt, "lrail-build-controller", nil, clientURI, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return IssuedCertificates{}, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	return IssuedCertificates{
		Material: TLSMaterial{CA: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), ServerCert: serverPEM, ServerKey: serverKeyPEM},
		ClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{clientCertificate}, RootCAs: roots,
			ServerName: request.DNSName, NextProtos: []string{"h2"},
		},
	}, nil
}

func issueLeaf(ca *x509.Certificate, caKey *ecdsa.PrivateKey, now, expiresAt time.Time, commonName string, dnsNames []string, identity *url.URL, usage x509.ExtKeyUsage) (tls.Certificate, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, nil, errors.New("generate worker leaf key")
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: commonName}, NotBefore: now.Add(-time.Minute), NotAfter: expiresAt,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, DNSNames: append([]string(nil), dnsNames...), URIs: []*url.URL{identity},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, nil, errors.New("issue worker leaf certificate")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, nil, nil, errors.New("marshal worker leaf key")
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, nil, errors.New("load worker leaf key pair")
	}
	return certificate, certificatePEM, keyPEM, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil || serial.Sign() == 0 {
		return nil, errors.New("generate worker certificate serial")
	}
	return serial, nil
}
