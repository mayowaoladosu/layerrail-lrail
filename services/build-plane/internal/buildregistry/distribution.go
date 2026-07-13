package buildregistry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
)

const MaxRegistryResponseBytes int64 = 4 << 20

type DistributionClient struct {
	http *http.Client
}

func NewDistributionClient(httpClient *http.Client) (*DistributionClient, error) {
	if httpClient == nil {
		return nil, errors.New("OCI distribution HTTP client is absent")
	}
	client := *httpClient
	if client.Timeout == 0 {
		client.Timeout = 2 * time.Minute
	}
	if client.Timeout < time.Second || client.Timeout > 5*time.Minute {
		return nil, errors.New("OCI distribution timeout is outside bounds")
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &DistributionClient{http: &client}, nil
}

func (client *DistributionClient) ManifestExists(ctx context.Context, capability PushCapability, projectName string, identity buildworker.OCIArtifactIdentity) (bool, error) {
	response, contents, err := client.request(ctx, capability, projectName, http.MethodGet, "/manifests/"+identity.ManifestDigest, identity.ManifestMediaType, nil, 0)
	if err != nil {
		return false, err
	}
	if response.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if response.StatusCode != http.StatusOK {
		return false, fmt.Errorf("%w: registry manifest lookup was rejected", ErrRegistry)
	}
	if err := verifyManifestResponse(response, contents, identity); err != nil {
		return false, err
	}
	return true, nil
}

func (client *DistributionClient) EnsureBlob(ctx context.Context, capability PushCapability, projectName string, descriptor buildworker.OCIArtifactDescriptor, reader io.Reader) error {
	if !validDigest(descriptor.Digest) || descriptor.Size <= 0 || descriptor.MediaType == "" || reader == nil {
		return errors.New("OCI blob publication descriptor is invalid")
	}
	response, _, err := client.request(ctx, capability, projectName, http.MethodHead, "/blobs/"+descriptor.Digest, "", nil, 0)
	if err != nil {
		return err
	}
	if response.StatusCode == http.StatusOK {
		if err := verifyBlobHead(response, descriptor); err != nil {
			return err
		}
		if _, err := io.Copy(io.Discard, reader); err != nil {
			return errors.New("read existing local OCI blob")
		}
		return nil
	}
	if response.StatusCode != http.StatusNotFound {
		return fmt.Errorf("%w: registry blob lookup was rejected", ErrRegistry)
	}
	response, _, err = client.request(ctx, capability, projectName, http.MethodPost, "/blobs/uploads/", "", nil, 0)
	if err != nil || response.StatusCode != http.StatusAccepted {
		return fmt.Errorf("%w: registry blob upload could not start", ErrRegistry)
	}
	uploadURL, err := validateUploadLocation(capability.Registry, projectName, capability.Repository, response.Header.Get("Location"))
	if err != nil {
		return err
	}
	query := uploadURL.Query()
	query.Set("digest", descriptor.Digest)
	uploadURL.RawQuery = query.Encode()
	hash := sha256.New()
	counting := &registryCountingReader{reader: io.TeeReader(reader, hash)}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, uploadURL.String(), counting)
	if err != nil {
		return errors.New("create OCI blob upload request")
	}
	request.Header.Set("Authorization", "Bearer "+capability.Token)
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("Cache-Control", "no-store")
	request.ContentLength = descriptor.Size
	uploadResponse, err := client.http.Do(request)
	if err != nil {
		return errors.New("send OCI blob upload")
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(uploadResponse.Body, MaxRegistryResponseBytes))
	closeErr := uploadResponse.Body.Close()
	actualDigest := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if closeErr != nil || counting.count != descriptor.Size || actualDigest != descriptor.Digest || uploadResponse.StatusCode != http.StatusCreated || uploadResponse.Header.Get("Docker-Content-Digest") != descriptor.Digest {
		return fmt.Errorf("%w: registry blob upload identity differs", ErrRegistry)
	}
	response, _, err = client.request(ctx, capability, projectName, http.MethodHead, "/blobs/"+descriptor.Digest, "", nil, 0)
	if err != nil || response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: published registry blob is not retrievable", ErrRegistry)
	}
	return verifyBlobHead(response, descriptor)
}

func (client *DistributionClient) PutManifest(ctx context.Context, capability PushCapability, projectName string, identity buildworker.OCIArtifactIdentity) error {
	actual := sha256.Sum256(identity.Manifest)
	if !validDigest(identity.ManifestDigest) || "sha256:"+hex.EncodeToString(actual[:]) != identity.ManifestDigest || identity.ManifestMediaType == "" || len(identity.Manifest) == 0 || len(identity.Manifest) > int(MaxRegistryResponseBytes) {
		return errors.New("OCI manifest publication identity is invalid")
	}
	response, _, err := client.request(ctx, capability, projectName, http.MethodPut, "/manifests/"+identity.ManifestDigest, identity.ManifestMediaType, bytes.NewReader(identity.Manifest), int64(len(identity.Manifest)))
	if err != nil || response.StatusCode != http.StatusCreated || response.Header.Get("Docker-Content-Digest") != identity.ManifestDigest {
		return fmt.Errorf("%w: registry manifest publication failed", ErrRegistry)
	}
	found, err := client.ManifestExists(ctx, capability, projectName, identity)
	if err != nil || !found {
		return fmt.Errorf("%w: published manifest verification failed", ErrRegistry)
	}
	return nil
}

func (client *DistributionClient) request(ctx context.Context, capability PushCapability, projectName, method, suffix, contentType string, body io.Reader, length int64) (*http.Response, []byte, error) {
	requestURL, err := distributionURL(capability.Registry, projectName, capability.Repository, suffix)
	if err != nil || capability.Token == "" {
		return nil, nil, errors.New("OCI distribution request capability is invalid")
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL, body)
	if err != nil {
		return nil, nil, errors.New("create OCI distribution request")
	}
	request.Header.Set("Authorization", "Bearer "+capability.Token)
	request.Header.Set("Cache-Control", "no-store")
	if contentType != "" {
		if method == http.MethodGet || method == http.MethodHead {
			request.Header.Set("Accept", contentType)
		} else {
			request.Header.Set("Content-Type", contentType)
		}
	}
	if body != nil {
		request.ContentLength = length
	}
	response, err := client.http.Do(request)
	if err != nil {
		return nil, nil, errors.New("send OCI distribution request")
	}
	contents, readErr := io.ReadAll(io.LimitReader(response.Body, MaxRegistryResponseBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(contents) > int(MaxRegistryResponseBytes) {
		return nil, nil, errors.New("read OCI distribution response")
	}
	return response, contents, nil
}

func distributionURL(registry, projectName, repository, suffix string) (string, error) {
	origin, err := url.Parse(registry)
	fullName, scopeErr := fullRepository(projectName, repository)
	if err != nil || scopeErr != nil || origin.Scheme != "https" || origin.Host == "" || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || origin.User != nil || !strings.HasPrefix(suffix, "/") || strings.Contains(suffix, "..") {
		return "", errors.New("OCI distribution URL is invalid")
	}
	origin.Path = "/v2/" + fullName + suffix
	return origin.String(), nil
}

func validateUploadLocation(registry, projectName, repository, location string) (*url.URL, error) {
	origin, err := url.Parse(registry)
	if err != nil || location == "" || len(location) > 8192 {
		return nil, errors.New("registry upload location is invalid")
	}
	candidate, err := origin.Parse(location)
	fullName, scopeErr := fullRepository(projectName, repository)
	expectedPrefix := "/v2/" + fullName + "/blobs/uploads/"
	if err != nil || scopeErr != nil || candidate.Scheme != origin.Scheme || candidate.Host != origin.Host || candidate.User != nil || candidate.Fragment != "" || !strings.HasPrefix(candidate.Path, expectedPrefix) || strings.Contains(candidate.Path, "..") {
		return nil, errors.New("registry upload location escaped repository scope")
	}
	return candidate, nil
}

func verifyBlobHead(response *http.Response, descriptor buildworker.OCIArtifactDescriptor) error {
	if response.Header.Get("Docker-Content-Digest") != descriptor.Digest {
		return errors.New("registry blob digest header differs")
	}
	if length := response.Header.Get("Content-Length"); length != "" {
		parsed, err := strconv.ParseInt(length, 10, 64)
		if err != nil || parsed != descriptor.Size {
			return errors.New("registry blob size differs")
		}
	}
	return nil
}

func verifyManifestResponse(response *http.Response, contents []byte, identity buildworker.OCIArtifactIdentity) error {
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	actual := sha256.Sum256(contents)
	if err != nil || mediaType != identity.ManifestMediaType || response.Header.Get("Docker-Content-Digest") != identity.ManifestDigest ||
		"sha256:"+hex.EncodeToString(actual[:]) != identity.ManifestDigest || !bytes.Equal(contents, identity.Manifest) {
		return errors.New("registry manifest differs from local verified identity")
	}
	return nil
}

type registryCountingReader struct {
	reader io.Reader
	count  int64
}

func (reader *registryCountingReader) Read(destination []byte) (int, error) {
	count, err := reader.reader.Read(destination)
	reader.count += int64(count)
	return count, err
}
