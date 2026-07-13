package buildsigning

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"net"
	"strings"
	"testing"

	lrailv1 "github.com/mayowaoladosu/layerrail-lrail/gen/go/lrail/v1"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildsupply"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const signingOrgID = "org_019b01da-7e31-7000-8000-000000000001"
const signingProjectID = "prj_019b01da-7e31-7000-8000-000000000002"
const signingBuildID = "bld_019b01da-7e31-7000-8000-000000000003"
const signingSubject = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type memoryAuthority struct {
	private ed25519.PrivateKey
	public  []byte
	calls   int
}

func newMemoryAuthority(t *testing.T) *memoryAuthority {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	der, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	return &memoryAuthority{private: private, public: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})}
}

func (authority *memoryAuthority) Sign(_ context.Context, payload []byte) (Material, error) {
	authority.calls++
	return Material{KeyID: "lrail-build-evidence", KeyVersion: 2, Algorithm: buildsupply.SignatureAlgorithm, PublicKeyPEM: authority.public, Signature: ed25519.Sign(authority.private, payload)}, nil
}

func TestSigningGRPCRoundTripAndWrongSubjectDenial(t *testing.T) {
	t.Parallel()
	authority := newMemoryAuthority(t)
	client, cleanup := signingGRPCFixture(t, authority)
	defer cleanup()
	signer, err := NewGRPCSigner(client, 0)
	if err != nil {
		t.Fatal(err)
	}
	payload := validSimpleSigningPayload(signingSubject)
	signature, err := signer.Sign(t.Context(), buildsupply.SigningRequest{
		OrganizationID: signingOrgID, ProjectID: signingProjectID, BuildID: signingBuildID, Attempt: 1,
		OutputName: "api", Kind: buildsupply.KindSignature, SubjectDigest: signingSubject, Payload: payload,
	})
	if err != nil || signature.KeyVersion != 2 || authority.calls != 1 {
		t.Fatalf("signature=%#v calls=%d error=%v", signature, authority.calls, err)
	}
	if _, err := buildsupply.VerifySignature(signature.PublicKeyPEM, payload, signature.Value); err != nil {
		t.Fatal(err)
	}
	_, err = client.SignEvidence(t.Context(), &lrailv1.SignBuildEvidenceRequest{
		OrganizationId: signingOrgID, ProjectId: signingProjectID, BuildId: signingBuildID, Attempt: 1, OutputName: "api",
		Kind: buildsupply.KindSignature, SubjectDigest: "sha256:" + strings.Repeat("b", 64), Payload: payload, PayloadDigest: bytesDigest(payload),
	})
	if status.Code(err) != codes.InvalidArgument || authority.calls != 1 {
		t.Fatalf("wrong subject error=%v calls=%d", err, authority.calls)
	}
}

func TestSigningServerRejectsMutatedPayloadDigestAndUnknownKind(t *testing.T) {
	t.Parallel()
	authority := newMemoryAuthority(t)
	client, cleanup := signingGRPCFixture(t, authority)
	defer cleanup()
	payload := validSimpleSigningPayload(signingSubject)
	for name, mutate := range map[string]func(*lrailv1.SignBuildEvidenceRequest){
		"digest": func(request *lrailv1.SignBuildEvidenceRequest) {
			request.PayloadDigest = "sha256:" + strings.Repeat("f", 64)
		},
		"kind":    func(request *lrailv1.SignBuildEvidenceRequest) { request.Kind = "arbitrary" },
		"attempt": func(request *lrailv1.SignBuildEvidenceRequest) { request.Attempt = 6 },
	} {
		t.Run(name, func(t *testing.T) {
			request := &lrailv1.SignBuildEvidenceRequest{
				OrganizationId: signingOrgID, ProjectId: signingProjectID, BuildId: signingBuildID, Attempt: 1, OutputName: "api",
				Kind: buildsupply.KindSignature, SubjectDigest: signingSubject, Payload: payload, PayloadDigest: bytesDigest(payload),
			}
			mutate(request)
			if _, err := client.SignEvidence(t.Context(), request); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("error=%v", err)
			}
		})
	}
	if authority.calls != 0 {
		t.Fatalf("authority calls=%d", authority.calls)
	}
}

func validSimpleSigningPayload(subject string) []byte {
	return []byte(`{"critical":{"identity":{"docker-reference":"registry.example.invalid/lrail/api"},"image":{"Docker-manifest-digest":"` + subject + `"},"type":"cosign container image signature"},"optional":{}}`)
}

func signingGRPCFixture(t *testing.T, authority Authority) (lrailv1.BuildEvidenceSigningServiceClient, func()) {
	t.Helper()
	service, err := NewServer(authority, 2)
	if err != nil {
		t.Fatal(err)
	}
	listener := bufconn.Listen(buildsupply.MaxEvidenceBytes + 1<<20)
	server := grpc.NewServer(grpc.MaxRecvMsgSize(buildsupply.MaxEvidenceBytes+1<<20), grpc.MaxSendMsgSize(1<<20))
	lrailv1.RegisterBuildEvidenceSigningServiceServer(server, service)
	go func() { _ = server.Serve(listener) }()
	connection, err := grpc.NewClient("passthrough:///signing-test", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(buildsupply.MaxEvidenceBytes+1<<20)))
	if err != nil {
		t.Fatal(err)
	}
	return lrailv1.NewBuildEvidenceSigningServiceClient(connection), func() {
		_ = connection.Close()
		server.Stop()
		_ = listener.Close()
	}
}
