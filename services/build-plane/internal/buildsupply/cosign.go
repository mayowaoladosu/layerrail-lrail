package buildsupply

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
)

type simpleSigningPayload struct {
	Critical struct {
		Identity struct {
			DockerReference string `json:"docker-reference"`
		} `json:"identity"`
		Image struct {
			ManifestDigest string `json:"Docker-manifest-digest"`
		} `json:"image"`
		Type string `json:"type"`
	} `json:"critical"`
	Optional map[string]any `json:"optional"`
}

type dsseEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []dsseSignature `json:"signatures"`
}

type dsseSignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

func imageSignaturePayload(request GenerateRequest) ([]byte, error) {
	payload := simpleSigningPayload{Optional: map[string]any{
		"creator": "lrail-build-evidence/v1", "build_id": request.Artifact.BuildID,
		"attempt": request.Artifact.Attempt, "output": request.Artifact.OutputName,
		"policy_digest": request.Artifact.Provenance.PolicyDigest,
	}}
	payload.Critical.Identity.DockerReference = request.RepositoryReference
	payload.Critical.Image.ManifestDigest = request.Identity.ManifestDigest
	payload.Critical.Type = "cosign container image signature"
	return canonicaljson.Marshal(payload)
}

func signDSSE(ctx context.Context, signer Signer, request GenerateRequest, kind string, statement []byte) (SignedPayload, Signature, error) {
	pae := dssePAE(DSSEPayloadType, statement)
	if err := ValidateSigningPayload(kind, request.Identity.ManifestDigest, pae); err != nil {
		return SignedPayload{}, Signature{}, err
	}
	signature, err := signer.Sign(ctx, signingRequest(request, kind, pae))
	if err != nil {
		return SignedPayload{}, Signature{}, err
	}
	if err := validateSignature(signature, pae, request.Artifact.Provenance.SupplyChain); err != nil {
		return SignedPayload{}, Signature{}, err
	}
	envelope, err := canonicaljson.Marshal(dsseEnvelope{
		PayloadType: DSSEPayloadType, Payload: base64.StdEncoding.EncodeToString(statement),
		Signatures: []dsseSignature{{KeyID: signatureKeyID(signature), Sig: base64.StdEncoding.EncodeToString(signature.Value)}},
	})
	if err != nil || len(envelope) > MaxEvidenceBytes {
		return SignedPayload{}, Signature{}, errors.New("canonicalize signed DSSE evidence")
	}
	return SignedPayload{Kind: kind, PredicateType: predicateTypeForKind(kind), MediaType: DSSEMediaType, Payload: envelope, PayloadDigest: bytesDigest(envelope), Signature: append([]byte(nil), signature.Value...)}, signature, nil
}

func signImage(ctx context.Context, signer Signer, request GenerateRequest) (SignedPayload, Signature, error) {
	payload, err := imageSignaturePayload(request)
	if err != nil {
		return SignedPayload{}, Signature{}, err
	}
	if err := ValidateSigningPayload(KindSignature, request.Identity.ManifestDigest, payload); err != nil {
		return SignedPayload{}, Signature{}, err
	}
	signature, err := signer.Sign(ctx, signingRequest(request, KindSignature, payload))
	if err != nil {
		return SignedPayload{}, Signature{}, err
	}
	if err := validateSignature(signature, payload, request.Artifact.Provenance.SupplyChain); err != nil {
		return SignedPayload{}, Signature{}, err
	}
	return SignedPayload{Kind: KindSignature, MediaType: SimpleSigningType, Payload: payload, PayloadDigest: bytesDigest(payload), Signature: append([]byte(nil), signature.Value...)}, signature, nil
}

func signingRequest(request GenerateRequest, kind string, payload []byte) SigningRequest {
	return SigningRequest{
		OrganizationID: request.Artifact.OrganizationID, ProjectID: request.Artifact.ProjectID, BuildID: request.Artifact.BuildID,
		Attempt: request.Artifact.Attempt, OutputName: request.Artifact.OutputName, Kind: kind,
		SubjectDigest: request.Identity.ManifestDigest, Payload: payload,
	}
}

func validateSignature(signature Signature, payload []byte, policy llbcompiler.SupplyChainPolicy) error {
	if signature.KeyID != policy.SignerKeyID || signature.KeyVersion < 1 || signature.Algorithm != SignatureAlgorithm ||
		len(signature.Value) != ed25519.SignatureSize || len(signature.PublicKeyPEM) == 0 || len(signature.PublicKeyPEM) > 16<<10 {
		return errors.New("signing response identity differs from policy")
	}
	publicKey, digest, err := parsePublicKey(signature.PublicKeyPEM)
	if err != nil || !slices.Contains(policy.AllowedSignerPublicKeyDigests, digest) || !ed25519.Verify(publicKey, payload, signature.Value) {
		return errors.New("signing response failed trusted-key verification")
	}
	return nil
}

func parsePublicKey(contents []byte) (ed25519.PublicKey, string, error) {
	block, rest := pem.Decode(contents)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, "", errors.New("signer public key PEM is invalid")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	publicKey, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, "", errors.New("signer public key is not Ed25519")
	}
	digest := sha256.Sum256(block.Bytes)
	return append(ed25519.PublicKey(nil), publicKey...), "sha256:" + hex.EncodeToString(digest[:]), nil
}

func VerifySignature(publicKeyPEM, payload, signature []byte) (string, error) {
	publicKey, digest, err := parsePublicKey(publicKeyPEM)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, payload, signature) {
		return "", errors.New("Ed25519 signature verification failed")
	}
	return digest, nil
}

func ValidateSigningPayload(kind, subjectDigest string, payload []byte) error {
	if !digestPattern.MatchString(subjectDigest) || len(payload) == 0 || len(payload) > MaxEvidenceBytes {
		return errors.New("signing payload identity is invalid")
	}
	if kind == KindSignature {
		var simple simpleSigningPayload
		if err := decodeStrictJSON(payload, &simple); err != nil || simple.Critical.Type != "cosign container image signature" ||
			simple.Critical.Image.ManifestDigest != subjectDigest || simple.Critical.Identity.DockerReference == "" {
			return errors.New("Cosign signing payload subject is invalid")
		}
		return nil
	}
	payloadType, statementBytes, err := parseDSSEPAE(payload)
	if err != nil || payloadType != DSSEPayloadType || predicateTypeForKind(kind) == "" {
		return errors.New("DSSE signing payload is invalid")
	}
	var signed statement
	if err := decodeStrictJSON(statementBytes, &signed); err != nil || signed.Type != InTotoStatementType ||
		signed.PredicateType != predicateTypeForKind(kind) || len(signed.Subject) != 1 ||
		signed.Subject[0].Digest["sha256"] != strings.TrimPrefix(subjectDigest, "sha256:") {
		return errors.New("in-toto signing payload subject is invalid")
	}
	return nil
}

func parseDSSEPAE(contents []byte) (string, []byte, error) {
	const prefix = "DSSEv1 "
	if !bytes.HasPrefix(contents, []byte(prefix)) {
		return "", nil, errors.New("DSSE PAE prefix is invalid")
	}
	cursor := len(prefix)
	typeLength, next, err := parsePAELength(contents, cursor)
	if err != nil || typeLength < 1 || typeLength > 1024 || next+typeLength >= len(contents) {
		return "", nil, errors.New("DSSE PAE payload type length is invalid")
	}
	payloadType := string(contents[next : next+typeLength])
	cursor = next + typeLength
	if contents[cursor] != ' ' {
		return "", nil, errors.New("DSSE PAE payload separator is invalid")
	}
	payloadLength, next, err := parsePAELength(contents, cursor+1)
	if err != nil || payloadLength < 1 || payloadLength > MaxEvidenceBytes || next+payloadLength != len(contents) {
		return "", nil, errors.New("DSSE PAE payload length is invalid")
	}
	return payloadType, append([]byte(nil), contents[next:]...), nil
}

func parsePAELength(contents []byte, start int) (int, int, error) {
	end := bytes.IndexByte(contents[start:], ' ')
	if end <= 0 {
		return 0, 0, errors.New("DSSE PAE length is absent")
	}
	end += start
	value, err := strconv.Atoi(string(contents[start:end]))
	if err != nil || value < 0 || (contents[start] == '0' && end-start > 1) {
		return 0, 0, errors.New("DSSE PAE length is invalid")
	}
	return value, end + 1, nil
}

func validateSignedPayload(payload SignedPayload, subjectDigest string, signature Signature) error {
	if payload.Kind == KindSignature {
		if payload.MediaType != SimpleSigningType || payload.PredicateType != "" || bytesDigest(payload.Payload) != payload.PayloadDigest || !bytes.Equal(payload.Signature, signature.Value) {
			return errors.New("Cosign image signature payload identity is invalid")
		}
		var simple simpleSigningPayload
		if err := decodeStrictJSON(payload.Payload, &simple); err != nil || simple.Critical.Type != "cosign container image signature" ||
			simple.Critical.Image.ManifestDigest != subjectDigest || simple.Critical.Identity.DockerReference == "" ||
			!ed25519.Verify(mustPublicKey(signature.PublicKeyPEM), payload.Payload, payload.Signature) {
			return errors.New("Cosign image signature does not bind the immutable subject")
		}
		return nil
	}
	if payload.MediaType != DSSEMediaType || payload.PredicateType != predicateTypeForKind(payload.Kind) || bytesDigest(payload.Payload) != payload.PayloadDigest {
		return errors.New("signed attestation payload identity is invalid")
	}
	var envelope dsseEnvelope
	if err := decodeStrictJSON(payload.Payload, &envelope); err != nil || envelope.PayloadType != DSSEPayloadType || len(envelope.Signatures) != 1 ||
		envelope.Signatures[0].KeyID != signatureKeyID(signature) {
		return errors.New("DSSE envelope identity is invalid")
	}
	statementBytes, decodeErr := base64.StdEncoding.DecodeString(envelope.Payload)
	signatureBytes, signatureErr := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	if decodeErr != nil || signatureErr != nil || !bytes.Equal(signatureBytes, payload.Signature) ||
		!ed25519.Verify(mustPublicKey(signature.PublicKeyPEM), dssePAE(envelope.PayloadType, statementBytes), signatureBytes) {
		return errors.New("DSSE envelope signature is invalid")
	}
	var signed statement
	if err := decodeStrictJSON(statementBytes, &signed); err != nil || signed.Type != InTotoStatementType || signed.PredicateType != payload.PredicateType ||
		len(signed.Subject) != 1 || signed.Subject[0].Digest["sha256"] != strings.TrimPrefix(subjectDigest, "sha256:") {
		return errors.New("signed in-toto statement subject is invalid")
	}
	return nil
}

func dssePAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

func signatureKeyID(signature Signature) string {
	return fmt.Sprintf("%s:v%d", signature.KeyID, signature.KeyVersion)
}

func predicateTypeForKind(kind string) string {
	switch kind {
	case KindSBOM:
		return SPDXPredicateType
	case KindScan:
		return ScanPredicateType
	case KindProvenance:
		return SLSAPredicateType
	case KindPolicy:
		return PolicyPredicateType
	default:
		return ""
	}
}

func mustPublicKey(contents []byte) ed25519.PublicKey {
	key, _, _ := parsePublicKey(contents)
	return key
}

func decodeStrictJSON(contents []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing data")
	}
	return nil
}
