# ADR 004: Immutable hostile-source snapshots

- Status: accepted
- Date: 2026-07-12

## Context

Local directories and provider repositories are hostile inputs. Rails must authorize source acquisition but must not proxy source bytes, extract archives, hold reusable provider credentials, or decide that client-supplied metadata is trustworthy. Builds require one immutable identity independent of archive ordering and compression metadata.

## Decision

Rails creates an organization/project/account-scoped `SourceUploadSession` with exact compressed bytes, SHA-256, part count, root directory, exclusion count, and a fifteen-minute expiry. It signs this bounded grant with HMAC-SHA-256. The isolated Go source gateway validates the grant and returns presigned S3-compatible PUT URLs. Parts are at most 16 MiB; an upload has at most 256 parts and 1 GiB compressed bytes.

The Go finalizer streams parts in declared order, recomputes every part digest and total archive digest, and never extracts onto a filesystem. Its tar reader permits canonical regular files and directories only. It rejects traversal, absolute or Windows paths, Unicode/case collisions, control and reserved device names, links, devices, privileged modes, file/entry/expanded-byte limits, compression bombs, known credential paths, and private-key/token markers.

The canonical manifest is sorted by normalized path and records file type, normalized mode, size, and SHA-256. Snapshot identity is:

`SHA256(canonical_manifest || "\n" || canonical_metadata || "\n" || policy_version)`

The archive and manifest are written conditionally under the snapshot digest. A signed Ed25519 receipt is persisted immutably before temporary parts are deleted. Lost responses therefore replay the same receipt without requiring parts. Rails verifies the signature with an explicitly configured public-key set and verifies the session, organization, project, expected archive digest, and byte count before recording a project-scoped `SourceSnapshot`.

Provider fetches use a separate HMAC domain and an expiring grant bound to the fetch, organization, project, account, source connection, installation, repository, and exact commit. A dedicated provider-token broker is the only process that receives the reusable GitHub App RSA key. It exchanges the fetch grant for a one-hour installation token restricted to one repository and `contents:read`. The source gateway receives that token only in memory, resolves the requested commit and tree through the provider API, and downloads the exact-commit archive through an explicit HTTPS/redirect host allowlist and controlled egress proxy.

The fetcher does not ship or execute Git, so hooks, filters, external diff drivers, credential helpers, and arbitrary protocol helpers cannot run. It preflights the recursive provider tree, rejects truncated/oversized trees, links, unsupported object modes, and duplicate paths, then verifies every archive file against its Git blob identity. It strips the provider archive wrapper and repacks a deterministic archive before applying the same hostile-archive finalizer used by local uploads. Submodules and LFS pointers fail closed until their separately bounded recursive policies are enabled. The signed fetch receipt includes provider/repository, requested and resolved commit, tree identity, token expiry metadata, canonical snapshot and manifest identities, policy, warnings, and empty bounded submodule/LFS evidence.

The control plane treats a GitHub installation ID as globally unique and binds it to one organization and the member who connected it. A `ProjectSourceBinding` selects one authorized repository, branch policy, and canonical root for a project. Webhook ingress authenticates the exact raw body with HMAC-SHA-256, normalizes supported push, pull-request, installation, and repository-selection events, and never stores the provider payload or reusable credential. A security-definer function with a fixed input shape serializes delivery IDs, atomically writes normalized delivery/outbox/audit evidence, and returns only the tenant and actor routing IDs required to enqueue work.

Actionable deliveries begin in `received`. A Solid Queue job establishes an active member's organization context, claims the delivery through a narrow tenant-checked lease function, creates at most one `SourceFetch` per delivery/project binding, and releases the transaction before provider I/O. Completion verifies the signed exact-commit result in a new tenant transaction and persists author, authored time, policy, warnings, token expiry, and fail-closed submodule/LFS evidence. Failures retain only exception classes and retry the same fetch identity; successful replay observes the completed delivery and performs no work. A newer production force push advances the binding generation and links the previous production fetch through `superseded_by_source_fetch_id`; pull-request synchronization has a separate PR-number track and cannot replace production desired state. Immutable snapshots are never rewritten. Installation suspension/revocation and repository removal disable affected automatic bindings and close queued, unleased work.

## Boundaries

- Source bytes move from clients directly to object storage and from object storage to the isolated finalizer.
- The gateway has no PostgreSQL, Kubernetes, registry, or reusable provider-app credential. A repository-scoped read token exists only for one in-memory fetch and is never written to a snapshot, receipt, log, or error.
- The token broker has no source/object-storage, PostgreSQL, Kubernetes, registry, or build access. Remote provider access requires an explicit egress proxy; archive redirects are revalidated and never receive the installation token.
- The web role cannot insert, update, delete, or allocate IDs in the provider-delivery inbox. It can execute only authenticated ingress and tenant-checked claim/finish functions; the generic worker role has neither capability. Delivery, fetch, and project-binding tables use forced RLS.
- The container runs non-root, drops every capability, has a read-only root, and receives only bounded no-exec scratch space.
- Upload parts have a one-day object lifecycle; successful finalization removes them immediately. A worker-only, security-definer `SKIP LOCKED` function marks abandoned session rows expired in bounded batches.
- Production uses TLS endpoints and externally managed grant/signing keys. Development keys are deterministic, visibly local-only, and have no authority outside the Compose profile.
- Snapshot objects are immutable and versioned. Builds consume a digest, never a mutable branch or reusable upload grant.

## Consequences

Archive format and client behavior cannot bypass server recomputation. Reordered archives with the same safe tree and metadata produce one snapshot identity. Failed or abandoned uploads are bounded and expire. Provider redelivery reuses one immutable fetch receipt, the same exact commit produces the same project-scoped snapshot, and a force-pushed commit produces a different snapshot while retaining supersession evidence. Cross-language fixed fixtures prove Rails and Go generate the same HMAC grant and Rails verifies a deterministic Go Ed25519 receipt. Provider, database-role, retry, replay, and force-push conformance run in the acceptance gate.

## Supersession

A replacement must retain direct byte transfer, isolated streaming validation, deterministic manifests, bounded archive defenses, immutable writes, signed idempotent receipts, key rotation, tenant scoping, and real object-store acceptance evidence.
