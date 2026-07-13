# ADR-021: Signed supply-chain evidence and publication policy

- **Status:** Accepted
- **Date:** 2026-07-13
- **Complements:** ADR-006, ADR-019, and ADR-020

## Context

A BuildKit export and its OCI manifest digest prove byte identity, not admissibility. A release consumer also needs a bounded software bill of materials, vulnerability and configuration findings, build provenance, a trusted image signature, and the exact policy decision applied to those facts. Generating that evidence after granting registry authority would allow an image containing a seeded credential to become retrievable even when policy later rejects it. Running scanners against a registry would also give third-party tools customer registry credentials and make a mutable remote lookup part of the decision.

Scanner output is not inherently safe or reproducible. Syft emits a current time and random document namespace. Raw Trivy secret findings can contain matched credential text. Vulnerability databases move independently of source and build inputs. OCI registries may implement the Referrers API or only the OCI 1.1 fallback tag scheme. A signing process that can export its private key or shares the controller's broad authority does not establish a useful trust boundary.

## Decision

### Locked policy and local subject

The signed build definition lock contains the complete minimum supply-chain policy: exact Syft and Trivy versions, trusted signer key ID and public-key digests, denied vulnerability severities, denied configuration severities, denied license classifications, mandatory secret-free output, and mandatory image-configuration scanning. Assignment verification rejects an absent or weakened policy before execution.

The controller scans the already exported, locally owned OCI archive before requesting Harbor authority. Static directories first become deterministic OCI artifacts, then follow the identical scanner, policy, signer, and referrer path. The archive digest, manifest bytes, config, layers, sizes, media types, and subject manifest digest are revalidated before scanning, after evidence generation, and while publishing. Archive extraction rejects links, traversal, duplicate paths, unsupported entries, size expansion, and changed source bytes.

Syft 1.46.0 emits SPDX 2.3 JSON. Lrail replaces generated time and namespace values with subject-derived values and canonicalizes the document. Trivy 0.72.0 scans the verified local OCI layout offline for vulnerabilities, secrets, licenses, filesystem misconfiguration, and image-configuration secrets and misconfiguration. Its process receives no registry or application credentials. Lrail retains only normalized finding fields, sorts them, and omits raw secret matches. The signed report records the exact vulnerability database digest, metadata digest, and update time.

The version policy describes scanner behavior, while the component image digest identifies the executable build. When the official Syft 1.46.0 and Trivy 0.72.0 release binaries acquired fixed HIGH findings, Lrail retained those policy versions but checksum-pinned their release source commits and rebuilt with Go 1.26.5. The Trivy build overrides ORAS to security-fixed 2.6.2. Source archive checksums, release commits, compiler image, dependency version, and resulting production image are all explicit; a source or dependency change therefore requires a new component digest and security gate even when the scanner's API version remains unchanged.

The default platform policy denies any secret, any critical vulnerability, any high or critical configuration finding, and any license classified as forbidden. Lower-severity findings remain in signed evidence; mandatory scanning is distinct from the threshold that blocks publication. Policy denial occurs before signing and before Harbor capability issuance, so a denied subject and its potentially sensitive evidence are not published.

### Provenance and signatures

Lrail emits canonical in-toto Statement v1 envelopes. SLSA provenance v1 records the immutable source snapshot and archive, Build IR digest, definition digest, policy digest, builder SPIFFE identity, compiler version, target platform, base material digests and evidence identities, non-secret build arguments, declared network authority, logical secret names, assignment timing, invocation identity, and output manifest digest. It never records secret values.

A separate mTLS-only evidence-signing service signs one Cosign simple-signing image payload and four DSSE statements: SBOM, scan, provenance, and policy decision. The service accepts only the five defined signing kinds, exact subjects and payload digests, and at most five requests per bundle. It has no Harbor, build-worker, source, or control-database authority.

For every signing call, the service authenticates to OpenBao with an audience-bound projected Kubernetes token, receives a token with a maximum five-minute lifetime, reads the exact Transit key policy, signs with the latest explicit key version, verifies the returned Ed25519 signature locally, and revokes the token on every path. Revocation failure discards the result. The Transit key must be Ed25519, non-derived, non-exportable, non-backupable, non-deletable, and signing-capable. OpenBao 2.4 returns the versioned public key as canonical base64 raw Ed25519 bytes; Lrail converts those bytes to PKIX PEM and pins its SHA-256 digest. Private key material never leaves Transit.

The complete bundle must use one key ID, key version, algorithm, and public key. Lrail verifies every signature locally before publication. A key rotation during one bundle fails the build; any later workflow retry must use a fresh assignment attempt and regenerate the entire bundle rather than mixing key versions.

### OCI evidence publication

After policy acceptance, the registry broker grants one short-lived repository capability. The subject artifact is published by manifest digest, followed by five immutable evidence manifests in that same repository:

1. SPDX SBOM DSSE attestation;
2. normalized Trivy scan DSSE attestation;
3. SLSA provenance DSSE attestation;
4. Cosign simple-signing image signature; and
5. signed policy-decision DSSE attestation.

Each evidence manifest has an OCI `subject` descriptor for the exact artifact manifest and records evidence kind, predicate type, payload digest, signer key ID, key version, public-key digest, policy digest, and build identity. Lrail verifies local payload bytes, upload digest/length responses, manifest readback, and discovery descriptors including media type, artifact type, length, digest, annotations, and subject.

When the registry supports `/referrers/<digest>`, Lrail verifies discovery through that API. A 404 activates the OCI 1.1 `sha256-<digest>` referrers-index fallback, updated through canonical read/merge/write and mandatory post-write verification. The image signature also receives the conventional immutable `sha256-<digest>.sig` alias so official Cosign clients can discover and verify it on older registries. A conflicting alias, evidence payload, evidence manifest, or missing post-write descriptor fails closed. Repeating the same publication is idempotent.

### Database freshness and success semantics

A six-hour updater pulls the vulnerability database only from a site-owned, anonymous-read Harbor mirror. It writes a unique immutable generation, computes the database digest once, validates metadata and database presence, and atomically replaces a relative `current` symlink while retaining one previous generation. File locking serializes controller bootstrap and scheduled refresh. The controller mounts the RWX claim read-only, resolves one validated generation for a scan, and requires the database to be fresh. Thus a scan cannot combine database bytes from one generation with metadata from another.

No layer may turn partial evidence into success. The worker, controller, and durable build-result store independently require accepted policy, passed scan, the assignment policy digest, a trusted signer identity, exactly five unique evidence kinds, valid payload and manifest digests, and references in the subject repository. Missing, duplicated, foreign-repository, mutated, unsigned, stale, or untrusted evidence produces a failed build result.

## Evidence

Hermetic tests cover deterministic normalization; secret-value redaction; policy thresholds; missing evidence; subject, payload, signature, signer, and digest mutation; signing request constraints; token revocation failure; native and fallback referrer discovery; Cosign alias conflicts; duplicate publication; worker/controller/store success rejection; and cancellation-versus-completion races.

Pinned real-tool tests prove clean image and static OCI acceptance and seeded-layer-secret denial before registry authority. A TLS Distribution 3 test proves immutable subject and evidence publication, OCI fallback discovery, digest pull, duplicate idempotency, and official Cosign verification. A pinned OpenBao 2.4.1 test proves its actual Transit key response, non-exportable Ed25519 signing, local verification, and short-lived token revocation. A real updater test performs two database refreshes around an injected interrupted generation and proves locked atomic rotation, exact digest files, crash recovery, and bounded two-generation retention.

These tests do not claim production Harbor HA, production OpenBao Kubernetes-auth configuration, Rook-Ceph availability, regional replication, Rekor inclusion, RFC 3161 timestamps, or runtime admission. Those remain environment or successor-packet gates.

## Boundaries

WP-040 owns evidence generation, policy evaluation, signing, same-repository OCI attachment, and the rule that no successful build result exists without complete trusted evidence.

The control plane already has revision evidence fields and an organization-scoped attestations table. Persisting a BuildCell result into a product revision belongs to the end-to-end deployment workflow. Regional replication and runtime reconciliation must independently pull, re-hash, and verify these records before they may report availability or schedule a workload.

The policy signature proves what the configured automated policy decided. It is not a transparency-log timestamp, human approval, malware guarantee, license legal opinion, or proof that vulnerability data contains every future disclosure.

## Consequences

Build completion now includes bounded scanner, signing, registry, and readback latency. A publication failure may leave immutable unreferenced blobs or referrers, but never a successful result; retention owns later cleanup. Database storage requires an RWX class and enough capacity for two current-size generations plus refresh headroom. OpenBao and the evidence signer become hard dependencies for accepted builds.

In return, artifacts containing detected secrets never receive publication authority, scanners hold no registry credentials, private signing keys remain non-exportable, evidence survives as content-addressed OCI objects, older registries remain interoperable, and all downstream consumers receive one explicit trust contract.

## Supersession

A replacement must preserve pre-authority secret denial, exact local subject verification, deterministic non-secret evidence, pinned scanner and database identity, SLSA provenance completeness, non-exportable separate signing authority, same-subject immutable OCI evidence, native plus fallback discovery, official Cosign interoperability, and independent success rejection at worker, controller, and durable-store boundaries.
