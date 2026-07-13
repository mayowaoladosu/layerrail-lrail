package buildregistry

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
)

const registryIntegrationImage = "registry:3@sha256:1be55279f18a2fe1a74edf2664cac61c1bea305b7b4642dab412e7affdcb3e33"
const registryIntegrationContainer = "lrail-wp039-registry-conformance"

func TestRealDistributionPublishesPullsAndDeduplicatesByDigest(t *testing.T) {
	if os.Getenv("LRAIL_REGISTRY_INTEGRATION") != "1" {
		t.Skip("set LRAIL_REGISTRY_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	certificateRoot := t.TempDir()
	roots := writeRegistryTLSIdentity(t, certificateRoot)
	removeRegistryContainer(context.Background())
	t.Cleanup(func() { removeRegistryContainer(context.Background()) })
	arguments := []string{
		"run", "-d", "--name", registryIntegrationContainer, "-p", "127.0.0.1::5000",
		"-v", certificateRoot + ":/certs:ro",
		"-e", "REGISTRY_HTTP_TLS_CERTIFICATE=/certs/tls.crt", "-e", "REGISTRY_HTTP_TLS_KEY=/certs/tls.key",
		registryIntegrationImage,
	}
	if output, err := exec.CommandContext(ctx, "docker", arguments...).CombinedOutput(); err != nil {
		t.Fatalf("docker run registry: %v: %s", err, output)
	}
	portOutput, err := exec.CommandContext(ctx, "docker", "port", registryIntegrationContainer, "5000/tcp").CombinedOutput()
	if err != nil {
		t.Fatalf("docker port: %v: %s", err, portOutput)
	}
	address := strings.TrimSpace(string(portOutput))
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("registry port %q: %v", address, err)
	}
	registryURL := "https://localhost:" + port
	httpClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}},
	}
	waitRegistryReady(t, ctx, httpClient, registryURL)
	artifact, expectedManifest := registryOCIFixture(t)
	artifact, evidence, signerPublicKey := registryEvidenceMaterials(t, artifact)
	repository, _ := RepositoryName(artifact.ProjectID, artifact.OutputName)
	broker := &publisherBroker{registry: registryURL, repository: repository, token: "ignored-by-authless-conformance-registry"}
	distribution, err := NewDistributionClient(httpClient)
	if err != nil {
		t.Fatalf("NewDistributionClient: %v", err)
	}
	publisher, err := NewPublisher(PublisherConfig{
		Broker: broker, Registry: distribution, RegistryOrigin: registryURL, Evidence: evidence, Clock: func() time.Time { return registryNow },
	})
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	first, err := publisher.Commit(t.Context(), artifact)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	second, err := publisher.Commit(t.Context(), artifact)
	if err != nil || first != second || first.ManifestDigest != expectedManifest || first.SupplyChain.PolicyState != "accepted" {
		t.Fatalf("first=%#v second=%#v error=%v", first, second, err)
	}
	projectName, _ := ProjectName(artifact.OrganizationID)
	identity, _ := buildworker.InspectOCIArtifact(artifact.Path)
	capability := PushCapability{Registry: registryURL, Repository: repository, Token: "ignored"}
	found, err := distribution.ManifestExists(t.Context(), capability, projectName, identity)
	if err != nil || !found {
		t.Fatalf("digest pull found=%v error=%v", found, err)
	}
	assertRegistryBlob(t, httpClient, registryURL, fullRepositoryPath(projectName, repository), identity.Config)
	for _, layer := range identity.Layers {
		assertRegistryBlob(t, httpClient, registryURL, fullRepositoryPath(projectName, repository), layer)
	}
	if cosignPath := os.Getenv("LRAIL_COSIGN_PATH"); cosignPath != "" {
		publicKeyPath := filepath.Join(certificateRoot, "cosign.pub")
		if err := os.WriteFile(publicKeyPath, signerPublicKey, 0o600); err != nil {
			t.Fatalf("write Cosign public key: %v", err)
		}
		command := exec.CommandContext(ctx, cosignPath, "verify", "--key", publicKeyPath, "--insecure-ignore-tlog", "--registry-cacert", filepath.Join(certificateRoot, "tls.crt"), first.Reference)
		command.Env = append(os.Environ(), "SSL_CERT_FILE="+filepath.Join(certificateRoot, "tls.crt"))
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("Cosign verify: %v: %s", err, output)
		}
	}
}

func fullRepositoryPath(projectName, repository string) string {
	fullName, _ := fullRepository(projectName, repository)
	return fullName
}

func assertRegistryBlob(t *testing.T, client *http.Client, registryURL, repository string, descriptor buildworker.OCIArtifactDescriptor) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, registryURL+"/v2/"+repository+"/blobs/"+descriptor.Digest, nil)
	if err != nil {
		t.Fatalf("create blob pull: %v", err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("pull blob %s: %v", descriptor.Digest, err)
	}
	contents, readErr := io.ReadAll(io.LimitReader(response.Body, descriptor.Size+1))
	closeErr := response.Body.Close()
	hash := sha256.Sum256(contents)
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || int64(len(contents)) != descriptor.Size ||
		"sha256:"+hex.EncodeToString(hash[:]) != descriptor.Digest || response.Header.Get("Docker-Content-Digest") != descriptor.Digest {
		t.Fatalf("pulled blob %s did not preserve its identity", descriptor.Digest)
	}
}

func writeRegistryTLSIdentity(t *testing.T, root string) *x509.CertPool {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey CA: %v", err)
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Lrail registry integration CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate CA: %v", err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate server: %v", err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(serverKey)
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	if err := os.WriteFile(filepath.Join(root, "tls.crt"), certificatePEM, 0o600); err != nil {
		t.Fatalf("Write cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("Write key: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool
}

func waitRegistryReady(t *testing.T, ctx context.Context, client *http.Client, endpoint string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v2/", nil)
		response, err := client.Do(request)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	logs, _ := exec.Command("docker", "logs", registryIntegrationContainer).CombinedOutput()
	t.Fatalf("registry did not become ready:\n%s", logs)
}

func removeRegistryContainer(ctx context.Context) {
	_, _ = exec.CommandContext(ctx, "docker", "rm", "-f", registryIntegrationContainer).CombinedOutput()
}
