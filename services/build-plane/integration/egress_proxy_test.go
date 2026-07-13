package integration

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
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildegress"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/solver/pb"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/net/dns/dnsmessage"
)

const egressIntegrationWorker = "lrail-wp038-egress-conformance"

func TestRealWorkerRoutesNetworkedSolveThroughPolicyProxy(t *testing.T) {
	if os.Getenv("LRAIL_BUILDKIT_PROXY_INTEGRATION") != "1" {
		t.Skip("set LRAIL_BUILDKIT_PROXY_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	hostAddress := dockerHostAddress(t)
	rootCertificate, rootKey, rootPEM, rootKeyPEM := integrationRootCA(t)

	targetCertificatePEM, targetKeyPEM := integrationLeaf(t, rootCertificate, rootKey, "packages.integration.test")
	targetTLS, err := tls.X509KeyPair(targetCertificatePEM, targetKeyPEM)
	if err != nil {
		t.Fatalf("target X509KeyPair: %v", err)
	}
	targetListener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	targetPort := targetListener.Addr().(*net.TCPAddr).Port
	targetServer := &http.Server{Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(response, "policy-egress-ok")
	})}
	go func() {
		_ = targetServer.Serve(tls.NewListener(targetListener, &tls.Config{
			MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{targetTLS},
		}))
	}()
	t.Cleanup(func() { _ = targetServer.Close() })

	dnsServer := startIntegrationDNS(t, hostAddress, "packages.integration.test")
	defer dnsServer.Close()
	proxyCertificatePEM, proxyKeyPEM := integrationLeaf(t, rootCertificate, rootKey, "proxy.integration.test")
	proxyTLS, err := buildegress.LoadServerTLSConfig(proxyCertificatePEM, proxyKeyPEM, rootPEM)
	if err != nil {
		t.Fatalf("LoadServerTLSConfig: %v", err)
	}
	resolver, err := buildegress.NewResolver(net.JoinHostPort(hostAddress.String(), strconv.Itoa(dnsServer.Port())))
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	audit := new(integrationAudit)
	proxy, err := buildegress.NewProxy(buildegress.ProxyOptions{
		Resolver: resolver, Dialer: &net.Dialer{Timeout: 5 * time.Second}, Audit: audit,
	})
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	proxyListener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	proxyPort := proxyListener.Addr().(*net.TCPAddr).Port
	proxyServer := buildegress.NewHTTPServer(proxy)
	go func() { _ = proxyServer.Serve(tls.NewListener(proxyListener, proxyTLS)) }()
	t.Cleanup(func() { _ = proxyServer.Close() })

	now := time.Now().UTC().Truncate(time.Second)
	certificateAuthority, err := buildegress.NewCertificateAuthority(rootPEM, rootKeyPEM, rootPEM, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewCertificateAuthority: %v", err)
	}
	lock := llbcompiler.DefinitionLock{Network: []llbcompiler.NetworkCapability{{NodeID: "n1", Profile: "private", Hosts: []string{}, GatewayID: "private-gateway"}}}
	policy, err := buildegress.NewPolicy(
		integrationBuildID, integrationOrgID, "build-egress-integration-a1", integrationPolicy, 1,
		now.Add(-time.Minute), now.Add(3*time.Minute), lock,
		map[string]buildegress.PrivateEndpoint{"private-gateway": {
			CIDRs: []string{hostAddress.String() + "/32"}, Ports: []int32{int32(targetPort)}, Hosts: []string{"packages.integration.test"},
		}},
	)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	clientMaterial, err := certificateAuthority.Issue(ctx, policy)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	credentialRoot := t.TempDir()
	writeIntegrationFile(t, credentialRoot, "client.pem", clientMaterial.Certificate)
	writeIntegrationFile(t, credentialRoot, "client-key.pem", clientMaterial.PrivateKey)
	writeIntegrationFile(t, credentialRoot, "ca.pem", clientMaterial.ServerCA)

	workerImage := os.Getenv("LRAIL_BUILD_WORKER_IMAGE")
	if workerImage == "" {
		workerImage = "lrail-buildkit-worker:wp038-final"
	}
	removeBuildKitContainer(context.Background(), egressIntegrationWorker)
	t.Cleanup(func() { removeBuildKitContainer(context.Background(), egressIntegrationWorker) })
	arguments := []string{
		"run", "-d", "--name", egressIntegrationWorker, "--privileged",
		"--security-opt", "seccomp=unconfined", "--security-opt", "apparmor=unconfined",
		"-p", "127.0.0.1:12348:1234",
		"--tmpfs", "/var/lib/lrail-worker:rw,size=1073741824,uid=1000,gid=1000",
		"--tmpfs", "/tmp:rw,size=67108864,uid=1000,gid=1000",
		"-v", credentialRoot + ":/run/lrail-egress:ro",
		"-e", "LRAIL_QUOTA_ROOT=/var/lib/lrail-worker",
		"-e", "LRAIL_SCRATCH_BYTES=1073741824", "-e", "LRAIL_SCRATCH_INODES=100000",
		"-e", "XDG_RUNTIME_DIR=/var/lib/lrail-worker/run", "-e", "TMPDIR=/var/lib/lrail-worker/tmp",
		"-e", "HTTP_PROXY=" + llbcompiler.BuildEgressProxyURL, "-e", "HTTPS_PROXY=" + llbcompiler.BuildEgressProxyURL,
		"-e", "NO_PROXY=127.0.0.1,localhost",
		"-e", "LRAIL_EGRESS_PROXY_ADDRESS=" + net.JoinHostPort(hostAddress.String(), strconv.Itoa(proxyPort)),
		"-e", "LRAIL_EGRESS_PROXY_SERVER_NAME=proxy.integration.test",
		"-e", "LRAIL_EGRESS_CLIENT_CERT=/run/lrail-egress/client.pem",
		"-e", "LRAIL_EGRESS_CLIENT_KEY=/run/lrail-egress/client-key.pem",
		"-e", "LRAIL_EGRESS_SERVER_CA=/run/lrail-egress/ca.pem",
		workerImage, "--addr", "tcp://0.0.0.0:1234", "--oci-worker-no-process-sandbox",
		"--root", "/var/lib/lrail-worker/buildkit",
	}
	if output, err := exec.CommandContext(ctx, "docker", arguments...).CombinedOutput(); err != nil {
		t.Fatalf("docker run worker: %v: %s", err, output)
	}
	buildkit := waitIntegrationBuildKit(t, ctx, "tcp://127.0.0.1:12348")
	defer buildkit.Close()

	probe := compileEgressProbe(t, targetPort)
	state := llb.Scratch().File(llb.Mkdir("/tmp", 0o1777)).File(llb.Mkfile("/probe", 0o755, probe)).File(llb.Mkfile("/target-ca.pem", 0o444, rootPEM))
	state = state.Run(
		llb.Args([]string{"/probe"}), llb.Network(pb.NetMode_UNSET),
		llb.User("10001:10001"),
		llb.WithProxy(llb.ProxyEnv{HTTPProxy: llbcompiler.BuildEgressProxyURL, HTTPSProxy: llbcompiler.BuildEgressProxyURL}),
	).Root()
	state = llb.Scratch().File(llb.Copy(state, "/tmp/proof.txt", "/proof.txt"))
	definition, err := state.Marshal(ctx, llb.Platform(ocispecs.Platform{OS: "linux", Architecture: "amd64"}))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	exportRoot := t.TempDir()
	statuses := make(chan *client.SolveStatus)
	statusDone := make(chan struct{})
	go func() {
		for range statuses {
		}
		close(statusDone)
	}()
	_, err = buildkit.Solve(ctx, definition, client.SolveOpt{
		Exports: []client.ExportEntry{{Type: client.ExporterLocal, OutputDir: exportRoot}},
	}, statuses)
	<-statusDone
	if err != nil {
		logs, _ := exec.Command("docker", "logs", egressIntegrationWorker).CombinedOutput()
		t.Fatalf("networked solve: %v\nworker logs:\n%s", err, logs)
	}
	proof, err := os.ReadFile(filepath.Join(exportRoot, "proof.txt"))
	if err != nil || string(proof) != "policy-egress-ok|metadata=blocked|undeclared=blocked" {
		t.Fatalf("proof=%q error=%v", proof, err)
	}
	events := audit.snapshot()
	if !containsAudit(events, "packages.integration.test", "allowed", "policy_match") ||
		!containsAudit(events, "", "denied", "ip_not_mapped") ||
		!containsAudit(events, "undeclared.integration.test", "denied", "domain_not_allowed") {
		t.Fatalf("egress audit=%#v", events)
	}
}

type integrationAudit struct {
	mu     sync.Mutex
	events []buildegress.AuditEvent
}

func (audit *integrationAudit) Record(_ context.Context, event buildegress.AuditEvent) error {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	audit.events = append(audit.events, event)
	return nil
}

func (audit *integrationAudit) snapshot() []buildegress.AuditEvent {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	return append([]buildegress.AuditEvent(nil), audit.events...)
}

func containsAudit(events []buildegress.AuditEvent, domain, action, reason string) bool {
	for _, event := range events {
		if event.Domain == domain && event.Action == action && event.Reason == reason {
			return true
		}
	}
	return false
}

func dockerHostAddress(t *testing.T) netip.Addr {
	t.Helper()
	addresses, err := net.LookupIP("host.docker.internal")
	if err != nil {
		t.Fatalf("resolve host.docker.internal: %v", err)
	}
	for _, address := range addresses {
		parsed, ok := netip.AddrFromSlice(address)
		if ok && parsed.Unmap().Is4() && parsed.Unmap().IsPrivate() {
			return parsed.Unmap()
		}
	}
	t.Fatalf("host.docker.internal has no private IPv4 address: %#v", addresses)
	return netip.Addr{}
}

func waitIntegrationBuildKit(t *testing.T, ctx context.Context, address string) *client.Client {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		buildkit, err := client.New(ctx, address)
		if err == nil {
			if _, err := buildkit.Info(ctx); err == nil {
				return buildkit
			}
			_ = buildkit.Close()
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
	logs, _ := exec.Command("docker", "logs", egressIntegrationWorker).CombinedOutput()
	t.Fatalf("worker did not become ready:\n%s", logs)
	return nil
}

func compileEgressProbe(t *testing.T, targetPort int) []byte {
	t.Helper()
	root := t.TempDir()
	source := fmt.Sprintf(`package main
import (
 "crypto/tls"
 "crypto/x509"
 "fmt"
 "io"
 "net/http"
 "os"
 "time"
)
func main() {
	if err := os.Mkdir("/tmp/go-build-private", 0700); err != nil { panic(err) }
	if err := os.WriteFile("/tmp/go-build-private/work", []byte("private"), 0600); err != nil { panic(err) }
	time.Sleep(1500*time.Millisecond)
 ca, err := os.ReadFile("/target-ca.pem"); if err != nil { panic(err) }
 roots := x509.NewCertPool(); if !roots.AppendCertsFromPEM(ca) { panic("bad CA") }
 transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}
 client := &http.Client{Transport: transport, Timeout: 10*time.Second}
 response, err := client.Get("https://packages.integration.test:%d/"); if err != nil { panic(err) }
 body, err := io.ReadAll(response.Body); response.Body.Close(); if err != nil || response.StatusCode != 200 { panic(fmt.Sprintf("target: %%v %%d", err, response.StatusCode)) }
 if response, err = client.Get("https://169.254.169.254/"); err == nil { response.Body.Close(); panic("metadata reachable") }
 if response, err = client.Get("https://undeclared.integration.test:%d/"); err == nil { response.Body.Close(); panic("undeclared reachable") }
 if err := os.WriteFile("/tmp/proof.txt", append(body, []byte("|metadata=blocked|undeclared=blocked")...), 0644); err != nil { panic(err) }
}
`, targetPort, targetPort)
	sourcePath := filepath.Join(root, "main.go")
	outputPath := filepath.Join(root, "probe")
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatalf("write probe: %v", err)
	}
	command := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", outputPath, sourcePath)
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile probe: %v: %s", err, output)
	}
	contents, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read probe: %v", err)
	}
	return contents
}

func writeIntegrationFile(t *testing.T, root, name string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), contents, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func integrationRootCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Lrail integration root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certificate, _ := x509.ParseCertificate(der)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return certificate, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func integrationLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, dnsName string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, _ := rand.Int(rand.Reader, serialLimit)
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: dnsName}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certificate = append(certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})...)
	return certificate, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

type integrationDNSServer struct {
	connection net.PacketConn
	domain     string
	answer     netip.Addr
}

func startIntegrationDNS(t *testing.T, answer netip.Addr, domain string) *integrationDNSServer {
	t.Helper()
	connection, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("DNS listen: %v", err)
	}
	server := &integrationDNSServer{connection: connection, domain: domain + ".", answer: answer}
	go server.serve()
	return server
}

func (server *integrationDNSServer) Port() int {
	return server.connection.LocalAddr().(*net.UDPAddr).Port
}

func (server *integrationDNSServer) Close() { _ = server.connection.Close() }

func (server *integrationDNSServer) serve() {
	buffer := make([]byte, 64<<10)
	for {
		count, peer, err := server.connection.ReadFrom(buffer)
		if err != nil {
			return
		}
		response, err := server.response(buffer[:count])
		if err == nil {
			_, _ = server.connection.WriteTo(response, peer)
		}
	}
}

func (server *integrationDNSServer) response(query []byte) ([]byte, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		return nil, err
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 {
		return nil, errors.New("invalid integration DNS question")
	}
	question := questions[0]
	message := dnsmessage.Message{Header: dnsmessage.Header{ID: header.ID, Response: true, RecursionAvailable: true}, Questions: questions}
	if strings.EqualFold(question.Name.String(), server.domain) && question.Type == dnsmessage.TypeA {
		message.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
			Body:   &dnsmessage.AResource{A: server.answer.As4()},
		}}
	} else if !strings.EqualFold(question.Name.String(), server.domain) {
		message.Header.RCode = dnsmessage.RCodeNameError
	}
	return message.Pack()
}

var _ buildegress.AuditSink = (*integrationAudit)(nil)
