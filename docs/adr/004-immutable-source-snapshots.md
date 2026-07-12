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

## Boundaries

- Source bytes move from clients directly to object storage and from object storage to the isolated finalizer.
- The gateway has no PostgreSQL, Kubernetes, registry, or provider credential.
- The container runs non-root, drops every capability, has a read-only root, and receives only bounded no-exec scratch space.
- Upload parts have a one-day object lifecycle; successful finalization removes them immediately. A worker-only, security-definer `SKIP LOCKED` function marks abandoned session rows expired in bounded batches.
- Production uses TLS endpoints and externally managed grant/signing keys. Development keys are deterministic, visibly local-only, and have no authority outside the Compose profile.
- Snapshot objects are immutable and versioned. Builds consume a digest, never a mutable branch or reusable upload grant.

## Consequences

Archive format and client behavior cannot bypass server recomputation. Reordered archives with the same safe tree and metadata produce one snapshot identity. Failed or abandoned uploads are bounded and expire. Cross-language grant and result contracts are exercised through Rails, Go, MinIO, PostgreSQL, and Ed25519 in the integration gate.

## Supersession

A replacement must retain direct byte transfer, isolated streaming validation, deterministic manifests, bounded archive defenses, immutable writes, signed idempotent receipts, key rotation, tenant scoping, and real object-store acceptance evidence.
