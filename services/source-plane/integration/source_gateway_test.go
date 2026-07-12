package integration

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourceauth"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourceupload"
)

const (
	defaultGateway = "http://127.0.0.1:58080"
	localGrantKey  = "__79_Pv6-fj39vX08_Lx8O_u7ezr6uno5-bl5OPi4eA"
	localPublicKey = "ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ"
	localAccessKey = "lrail_source_gateway"
	localSecretKey = "source-gateway-local-only-not-a-secret"
)

func TestScopedGatewayCredentialCannotListBuckets(t *testing.T) {
	if os.Getenv("LRAIL_SOURCE_INTEGRATION") != "1" {
		t.Skip("set LRAIL_SOURCE_INTEGRATION=1 to run the source gateway integration test")
	}
	client, err := minio.New("127.0.0.1:59000", &minio.Options{
		Creds:  credentials.NewStaticV4(localAccessKey, localSecretKey, ""),
		Secure: false,
		Region: "us-east-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	buckets, err := client.ListBuckets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(buckets) != 1 || buckets[0].Name != "lrail-source" {
		t.Fatalf("source gateway credentials saw unauthorized buckets: %#v", buckets)
	}
	exists, err := client.BucketExists(context.Background(), "lrail-source")
	if err != nil || !exists {
		t.Fatalf("scoped source bucket is inaccessible: exists=%v err=%v", exists, err)
	}
}

func TestSourceGatewayDirectUploadFinalizeAndReplay(t *testing.T) {
	if os.Getenv("LRAIL_SOURCE_INTEGRATION") != "1" {
		t.Skip("set LRAIL_SOURCE_INTEGRATION=1 to run the source gateway integration test")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	now := time.Now().UTC()
	sessionID, err := platformid.New("upl")
	if err != nil {
		t.Fatal(err)
	}
	archive := makeArchive(t, string(sessionID))
	archiveDigest := sha256.Sum256(archive)
	grant := sourceauth.UploadGrant{
		Version:               1,
		Audience:              sourceauth.Audience,
		SessionID:             string(sessionID),
		OrganizationID:        "org_019b01da-7e31-7000-8000-000000000002",
		ProjectID:             "prj_019b01da-7e31-7000-8000-000000000003",
		CreatorID:             "acct_019b01da-7e31-7000-8000-000000000004",
		ExpectedArchiveBytes:  int64(len(archive)),
		ExpectedArchiveSHA256: "sha256:" + hex.EncodeToString(archiveDigest[:]),
		ExpectedParts:         2,
		ExcludedCount:         1,
		ExpiresAt:             now.Add(10 * time.Minute),
	}
	key, err := base64.RawURLEncoding.DecodeString(localGrantKey)
	if err != nil {
		t.Fatal(err)
	}
	token, err := sourceauth.SignGrantAt(key, grant, now)
	if err != nil {
		t.Fatal(err)
	}

	var authorization struct {
		SessionID string                       `json:"session_id"`
		Parts     []sourceupload.PresignedPart `json:"parts"`
	}
	requestJSON(t, client, http.MethodPost, endpoint()+"/v1/sessions", token, map[string]any{}, &authorization, http.StatusCreated)
	if authorization.SessionID != string(sessionID) || len(authorization.Parts) != 2 {
		t.Fatalf("unexpected upload authorization: %#v", authorization)
	}

	midpoint := len(archive) / 2
	bodies := [][]byte{archive[:midpoint], archive[midpoint:]}
	parts := make([]sourceupload.Part, len(bodies))
	for index, body := range bodies {
		put, err := http.NewRequestWithContext(context.Background(), http.MethodPut, authorization.Parts[index].URL, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(put)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("part %d upload status = %d", index+1, response.StatusCode)
		}
		digest := sha256.Sum256(body)
		parts[index] = sourceupload.Part{
			Number: index + 1,
			Size:   int64(len(body)),
			SHA256: "sha256:" + hex.EncodeToString(digest[:]),
		}
	}

	finalizeBody := map[string]any{"parts": parts}
	var first sourceauth.SignedResult
	requestJSON(t, client, http.MethodPost, endpoint()+"/v1/finalizations", token, finalizeBody, &first, http.StatusOK)
	publicKey, err := base64.RawURLEncoding.DecodeString(localPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := sourceauth.VerifyResult(ed25519.PublicKey(publicKey), first); err != nil {
		t.Fatal(err)
	}
	if first.Result.SessionID != string(sessionID) || first.Result.ArchiveSHA256 != grant.ExpectedArchiveSHA256 {
		t.Fatalf("unexpected finalization result: %#v", first)
	}

	var replay sourceauth.SignedResult
	requestJSON(t, client, http.MethodPost, endpoint()+"/v1/finalizations", token, finalizeBody, &replay, http.StatusOK)
	if replay.Signature != first.Signature {
		t.Fatal("idempotent finalization returned a different signed receipt")
	}
}

func requestJSON(
	t *testing.T,
	client *http.Client,
	method string,
	location string,
	token string,
	input any,
	output any,
	wantStatus int,
) {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(context.Background(), method, location, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != wantStatus {
		raw, _ := io.ReadAll(io.LimitReader(response.Body, 8<<10))
		t.Fatalf("%s %s status = %d, body = %s", method, location, response.StatusCode, raw)
	}
	if err := json.NewDecoder(response.Body).Decode(output); err != nil {
		t.Fatal(err)
	}
}

func endpoint() string {
	if value := os.Getenv("LRAIL_SOURCE_GATEWAY_URL"); value != "" {
		return value
	}
	return defaultGateway
}

func makeArchive(t *testing.T, unique string) []byte {
	t.Helper()
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	compressed.Header.ModTime = time.Unix(0, 0)
	compressed.Header.OS = 255
	writer := tar.NewWriter(compressed)
	body := []byte("source integration " + unique + "\n")
	if err := writer.WriteHeader(&tar.Header{
		Name:     "README.md",
		Mode:     0o644,
		Size:     int64(len(body)),
		Typeflag: tar.TypeReg,
		ModTime:  time.Unix(0, 0),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
