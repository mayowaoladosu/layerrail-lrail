package buildregistry

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildsupply"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	CosignSignatureArtifactType   = "application/vnd.dev.cosign.artifact.sig.v1+json"
	CosignSBOMArtifactType        = "application/vnd.dev.cosign.artifact.sbom.v1+json"
	CosignAttestationArtifactType = "application/vnd.dev.cosign.artifact.att.v1+json"
)

type preparedEvidence struct {
	kind          string
	artifactType  string
	payloadDigest string
	identity      buildworker.OCIArtifactIdentity
	config        []byte
	payload       []byte
	annotations   map[string]string
}

func prepareEvidence(bundle buildsupply.Bundle, subject buildworker.OCIArtifactIdentity) ([]preparedEvidence, error) {
	if !validDigest(subject.ManifestDigest) || subject.ManifestMediaType != ocispecs.MediaTypeImageManifest || len(subject.Manifest) == 0 {
		return nil, errors.New("evidence subject identity is invalid")
	}
	payloads := make([]buildsupply.SignedPayload, 0, len(bundle.Attestations)+1)
	payloads = append(payloads, bundle.Attestations...)
	payloads = append(payloads, bundle.ImageSignature)
	if len(payloads) != 5 {
		return nil, errors.New("evidence payload set is incomplete")
	}
	config := []byte(`{}`)
	configDescriptor := buildworker.OCIArtifactDescriptor{Digest: digest.FromBytes(config).String(), Size: int64(len(config)), MediaType: ocispecs.MediaTypeImageConfig}
	subjectDescriptor := ocispecs.Descriptor{MediaType: subject.ManifestMediaType, Digest: digest.Digest(subject.ManifestDigest), Size: int64(len(subject.Manifest))}
	prepared := make([]preparedEvidence, 0, len(payloads))
	seen := make(map[string]struct{}, len(payloads))
	for _, payload := range payloads {
		artifactType := evidenceArtifactType(payload.Kind)
		if artifactType == "" || payload.MediaType == "" || len(payload.Payload) == 0 || len(payload.Payload) > buildsupply.MaxEvidenceBytes ||
			payload.PayloadDigest != digest.FromBytes(payload.Payload).String() {
			return nil, errors.New("evidence payload identity is invalid")
		}
		if _, duplicate := seen[payload.Kind]; duplicate {
			return nil, errors.New("evidence payload kind is duplicated")
		}
		seen[payload.Kind] = struct{}{}
		annotations := map[string]string{
			"dev.lrail.evidence.kind":            payload.Kind,
			"dev.lrail.evidence.payload-digest":  payload.PayloadDigest,
			"dev.lrail.signer.key-id":            bundle.SignerKeyID,
			"dev.lrail.signer.key-version":       strconv.Itoa(bundle.SignerKeyVersion),
			"dev.lrail.signer.public-key-digest": bundle.SignerPublicKeyDigest,
		}
		if payload.PredicateType != "" {
			annotations["dev.lrail.evidence.predicate-type"] = payload.PredicateType
		}
		if payload.Kind == buildsupply.KindSignature {
			annotations["dev.cosignproject.cosign/signature"] = base64.StdEncoding.EncodeToString(payload.Signature)
		}
		payloadDescriptor := buildworker.OCIArtifactDescriptor{Digest: payload.PayloadDigest, Size: int64(len(payload.Payload)), MediaType: payload.MediaType}
		manifest, err := canonicaljson.Marshal(ocispecs.Manifest{
			Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispecs.MediaTypeImageManifest,
			ArtifactType: artifactType,
			Config:       ocispecs.Descriptor{MediaType: configDescriptor.MediaType, Digest: digest.Digest(configDescriptor.Digest), Size: configDescriptor.Size},
			Layers:       []ocispecs.Descriptor{{MediaType: payloadDescriptor.MediaType, Digest: digest.Digest(payloadDescriptor.Digest), Size: payloadDescriptor.Size, Annotations: annotations}},
			Subject:      &subjectDescriptor,
			Annotations:  annotations,
		})
		if err != nil {
			return nil, errors.New("canonicalize OCI evidence manifest")
		}
		manifestDigest := digest.FromBytes(manifest).String()
		prepared = append(prepared, preparedEvidence{
			kind: payload.Kind, artifactType: artifactType, payloadDigest: payload.PayloadDigest,
			identity: buildworker.OCIArtifactIdentity{
				ManifestDigest: manifestDigest, ManifestMediaType: ocispecs.MediaTypeImageManifest, Manifest: manifest,
				Config: configDescriptor, Layers: []buildworker.OCIArtifactDescriptor{payloadDescriptor}, LayerDigests: []string{payloadDescriptor.Digest},
			},
			config: append([]byte(nil), config...), payload: append([]byte(nil), payload.Payload...), annotations: copyEvidenceAnnotations(annotations),
		})
	}
	return prepared, nil
}

func (publisher *Publisher) publishEvidence(ctx context.Context, capability PushCapability, projectName, repositoryReference string, subject buildworker.OCIArtifactIdentity, bundle buildsupply.Bundle) ([5]buildworker.EvidenceReference, error) {
	prepared, err := prepareEvidence(bundle, subject)
	if err != nil {
		return [5]buildworker.EvidenceReference{}, err
	}
	var references [5]buildworker.EvidenceReference
	for index, evidence := range prepared {
		if err := publisher.registry.EnsureBlob(ctx, capability, projectName, evidence.identity.Config, bytes.NewReader(evidence.config)); err != nil {
			return [5]buildworker.EvidenceReference{}, fmt.Errorf("%w: publish evidence config", ErrRegistry)
		}
		if err := publisher.registry.EnsureBlob(ctx, capability, projectName, evidence.identity.Layers[0], bytes.NewReader(evidence.payload)); err != nil {
			return [5]buildworker.EvidenceReference{}, fmt.Errorf("%w: publish evidence payload", ErrRegistry)
		}
		exists, err := publisher.registry.ManifestExists(ctx, capability, projectName, evidence.identity)
		if err != nil {
			return [5]buildworker.EvidenceReference{}, err
		}
		if !exists {
			if err := publisher.registry.PutManifest(ctx, capability, projectName, evidence.identity); err != nil {
				return [5]buildworker.EvidenceReference{}, err
			}
		}
		if evidence.kind == buildsupply.KindSignature {
			signatureTag := strings.ReplaceAll(subject.ManifestDigest, ":", "-") + ".sig"
			if err := publisher.registry.EnsureManifestReference(ctx, capability, projectName, evidence.identity, signatureTag); err != nil {
				return [5]buildworker.EvidenceReference{}, fmt.Errorf("%w: publish Cosign signature alias", ErrRegistry)
			}
		}
		references[index] = buildworker.EvidenceReference{
			Kind:           evidence.kind,
			Reference:      repositoryReference + "@" + evidence.identity.ManifestDigest,
			ManifestDigest: evidence.identity.ManifestDigest, PayloadDigest: evidence.payloadDigest,
		}
	}
	if err := publisher.registry.VerifyReferrers(ctx, capability, projectName, subject.ManifestDigest, prepared); err != nil {
		return [5]buildworker.EvidenceReference{}, err
	}
	return references, nil
}

func (client *DistributionClient) VerifyReferrers(ctx context.Context, capability PushCapability, projectName, subjectDigest string, expected []preparedEvidence) error {
	if !validDigest(subjectDigest) || len(expected) != 5 {
		return errors.New("OCI referrer verification request is invalid")
	}
	response, contents, err := client.request(ctx, capability, projectName, http.MethodGet, "/referrers/"+subjectDigest, ocispecs.MediaTypeImageIndex, nil, 0)
	if err != nil {
		return fmt.Errorf("%w: list OCI evidence referrers", ErrRegistry)
	}
	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusNotFound {
			return client.verifyReferrersFallback(ctx, capability, projectName, subjectDigest, expected)
		}
		return fmt.Errorf("%w: list OCI evidence referrers returned HTTP %d", ErrRegistry, response.StatusCode)
	}
	return verifyReferrerIndex(contents, expected)
}

func (client *DistributionClient) verifyReferrersFallback(ctx context.Context, capability PushCapability, projectName, subjectDigest string, expected []preparedEvidence) error {
	tag := strings.ReplaceAll(subjectDigest, ":", "-")
	response, contents, err := client.request(ctx, capability, projectName, http.MethodGet, "/manifests/"+tag, ocispecs.MediaTypeImageIndex, nil, 0)
	if err != nil {
		return fmt.Errorf("%w: read OCI referrers fallback", ErrRegistry)
	}
	index := ocispecs.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispecs.MediaTypeImageIndex, Manifests: []ocispecs.Descriptor{}}
	if response.StatusCode == http.StatusOK {
		if err := decodeExternalJSON(contents, &index); err != nil || index.SchemaVersion != 2 || index.MediaType != ocispecs.MediaTypeImageIndex || len(index.Manifests) > 10_000 {
			return fmt.Errorf("%w: OCI referrers fallback index is invalid", ErrRegistry)
		}
	} else if response.StatusCode != http.StatusNotFound {
		return fmt.Errorf("%w: read OCI referrers fallback returned HTTP %d", ErrRegistry, response.StatusCode)
	}
	descriptors := make(map[string]ocispecs.Descriptor, len(index.Manifests)+len(expected))
	for _, descriptor := range index.Manifests {
		identity := descriptor.Digest.String()
		if !validDigest(identity) || descriptor.MediaType != ocispecs.MediaTypeImageManifest || descriptor.Size <= 0 || descriptor.Size > MaxRegistryResponseBytes || descriptor.ArtifactType == "" {
			return fmt.Errorf("%w: OCI referrers fallback descriptor is invalid", ErrRegistry)
		}
		if _, duplicate := descriptors[identity]; duplicate {
			return fmt.Errorf("%w: OCI referrers fallback descriptor is duplicated", ErrRegistry)
		}
		descriptors[identity] = descriptor
	}
	for _, evidence := range expected {
		descriptors[evidence.identity.ManifestDigest] = ocispecs.Descriptor{
			MediaType: evidence.identity.ManifestMediaType, Digest: digest.Digest(evidence.identity.ManifestDigest),
			Size: int64(len(evidence.identity.Manifest)), ArtifactType: evidence.artifactType, Annotations: copyEvidenceAnnotations(evidence.annotations),
		}
	}
	index.Manifests = index.Manifests[:0]
	for _, descriptor := range descriptors {
		index.Manifests = append(index.Manifests, descriptor)
	}
	slices.SortFunc(index.Manifests, func(left, right ocispecs.Descriptor) int {
		return strings.Compare(left.Digest.String(), right.Digest.String())
	})
	updated, err := canonicaljson.Marshal(index)
	if err != nil || len(updated) > int(MaxRegistryResponseBytes) {
		return fmt.Errorf("%w: canonicalize OCI referrers fallback", ErrRegistry)
	}
	identity := buildworker.OCIArtifactIdentity{
		ManifestDigest: digest.FromBytes(updated).String(), ManifestMediaType: ocispecs.MediaTypeImageIndex, Manifest: updated,
	}
	if response.StatusCode != http.StatusOK || !bytes.Equal(contents, updated) {
		if err := client.PutManifestReference(ctx, capability, projectName, identity, tag); err != nil {
			return err
		}
	}
	response, contents, err = client.request(ctx, capability, projectName, http.MethodGet, "/manifests/"+tag, ocispecs.MediaTypeImageIndex, nil, 0)
	if err != nil || response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: OCI referrers fallback is not retrievable", ErrRegistry)
	}
	return verifyReferrerIndex(contents, expected)
}

func verifyReferrerIndex(contents []byte, expected []preparedEvidence) error {
	var index ocispecs.Index
	if err := decodeExternalJSON(contents, &index); err != nil || index.SchemaVersion != 2 || index.MediaType != ocispecs.MediaTypeImageIndex || len(index.Manifests) > 10_000 {
		return fmt.Errorf("%w: OCI evidence referrer index is invalid", ErrRegistry)
	}
	found := make(map[string]ocispecs.Descriptor, len(index.Manifests))
	for _, descriptor := range index.Manifests {
		if _, duplicate := found[descriptor.Digest.String()]; duplicate {
			return fmt.Errorf("%w: OCI evidence referrer is duplicated", ErrRegistry)
		}
		found[descriptor.Digest.String()] = descriptor
	}
	for _, evidence := range expected {
		descriptor, exists := found[evidence.identity.ManifestDigest]
		if !exists || descriptor.MediaType != evidence.identity.ManifestMediaType || descriptor.ArtifactType != evidence.artifactType || descriptor.Size != int64(len(evidence.identity.Manifest)) ||
			!containsEvidenceAnnotations(descriptor.Annotations, evidence.annotations) {
			return fmt.Errorf("%w: OCI evidence referrer is missing or differs", ErrRegistry)
		}
	}
	return nil
}

func copyEvidenceAnnotations(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func containsEvidenceAnnotations(actual, expected map[string]string) bool {
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func evidenceArtifactType(kind string) string {
	switch kind {
	case buildsupply.KindSignature:
		return CosignSignatureArtifactType
	case buildsupply.KindSBOM:
		return CosignSBOMArtifactType
	case buildsupply.KindScan, buildsupply.KindProvenance, buildsupply.KindPolicy:
		return CosignAttestationArtifactType
	default:
		return ""
	}
}
