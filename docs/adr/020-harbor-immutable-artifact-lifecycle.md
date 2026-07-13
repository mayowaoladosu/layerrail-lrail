# ADR-020: Harbor-backed immutable artifact lifecycle

- **Status:** Accepted
- **Date:** 2026-07-13
- **Complements:** ADR-006 and ADR-019

## Context

A successful BuildKit export is still local controller state. Runtime cells need an immutable OCI identity that survives worker and build-cell loss, while Harbor administrator credentials, reusable robot secrets, mutable tags, cross-organization repositories, and unguarded retention must not become build authority. Static bundles need the same digest and deletion semantics as runtime images without pretending that a local directory is a release.

## Decision

Lrail maps each immutable organization ID to a deterministic private Harbor project and each project/output pair to a deterministic repository. The adapter reconciles private project metadata, bounded storage quota, and an all-tag immutability rule before issuing publication authority. Human tags remain aliases; build and runtime records use manifest digests.

A separate mTLS registry capability broker is the only build-cell process that receives the Harbor administrator credential. For one signed build scope it creates a Harbor project robot internally, asks Harbor's token service for a JWT whose single access claim is `pull,push` on one deterministic repository, validates the returned claim and expiry, persists the robot lease in Bolt, and returns only the short-lived repository JWT. The build controller never receives the administrator or robot secret. Duplicate issuance revokes the older robot first; normal publication and every error path revoke the lease. A restart sweeper removes expired leases. Harbor token expiry above fifteen minutes fails closed.

The controller streams each already validated OCI config and layer to the Distribution API, verifies bytes, lengths, upload digest headers, and manifest identity, then reads the manifest back by digest. Duplicate publication first verifies the existing manifest and performs no blob or manifest rewrite. A mismatched digest, redirect, upload location, repository, token response, readback, or capability revocation fails the build.

Static bundles are packed deterministically as one OCI artifact with normalized paths, ownership, mode, timestamps, gzip metadata, file hashes, and an OCI image config. Lrail also writes a canonical immutable S3 publication manifest containing the source directory digest, OCI reference, manifest digest, and sorted file identities. Build results expose both references.

Retention input is an organization-scoped protected digest set covering active releases, rollback windows, retained deployments, legal holds, backups/restores, pinned revisions, and in-flight workflows. Deletion is denied for any protected digest and otherwise requires reference deletion, replication convergence, and registry-metadata backup. An immutable authorization record is stored before Harbor deletion and an immutable tombstone afterward. Missing audit storage prevents deletion. Journal identities exclude occurrence time, and Harbor treats an already-absent artifact as deleted, so retry after a post-delete tombstone failure converges without duplicating immutable journal objects.

The regional replication seam persists an idempotent `requested` operation for an exact digest and sorted target-cell set. This stub deliberately does not report regional availability. Later replication execution and independent regional verification must advance availability before runtime reconciliation.

## Evidence

Hermetic conformance covers private project reconciliation, immutability, exact robot permissions, JWT scope/TTL, durable lease restart and cleanup, cross-repository denial, OCI/static digest verification, duplicate publication, protected deletion, tombstones, and durable replication replay. A pinned Distribution 3 container over TLS proves real blob upload, manifest publication, digest pull, and duplicate idempotency. Production Harbor HA, object storage, scanner, replication, backup, and garbage-collection behavior remain environment conformance requirements rather than claims from the local Distribution test.

## Boundaries

WP-039 owns Harbor tenancy, publication capability brokering, immutable image/static publication, digest readback, protected deletion, tombstones, and the durable replication-request seam.

WP-040 owns Syft SBOMs, Trivy findings, provenance, Cosign signatures, referrers, and final supply-chain policy. A WP-039 artifact is retrievable and immutable but is not yet admissible or deployable until WP-040 evidence exists.

## Consequences

Publication has more explicit network calls and failure modes, but no build worker or controller holds broad registry authority. Registry and retention retries are content-idempotent, deletion leaves immutable audit evidence for later consumers, and replication requests cannot be confused with verified regional availability.

## Supersession

A replacement must preserve deterministic tenant/repository mapping, private projects, repository-only short-lived controller authority, no administrator or robot secret outside the broker, exact digest readback, duplicate idempotency, static OCI plus immutable publication manifests, protected-set deletion, pre-delete authorization, post-delete tombstones, and non-optimistic regional state.
