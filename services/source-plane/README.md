# Lrail source plane

The source plane turns direct-uploaded or fetched hostile bytes into an immutable, content-addressed snapshot. The currently implemented vertical slice covers local direct uploads. Git provider fetching is the next adapter over the same finalizer contract.

## Runtime

`cmd/source-gateway` exposes:

- `GET /live` — process liveness.
- `GET /ready` — source bucket reachability.
- `POST /v1/sessions` — validates a short-lived signed grant and returns bounded presigned part URLs.
- `POST /v1/finalizations` — validates part metadata, streams object parts through the archive finalizer, writes immutable snapshot objects, and returns a signed receipt.

The gateway requires explicit internal/public S3 endpoints, bucket, region, scoped S3 credentials, scratch directory, a 32-byte HMAC grant key, a 64-byte Ed25519 private key, and signing key ID. Key values are unpadded base64url. Production S3 endpoints default to TLS; disabling TLS is only for the local profile.

## Isolation and limits

The production image is distroless and runs as UID/GID 65532 with no capabilities. Compose makes its root filesystem read-only and mounts a 2.25 GiB no-exec scratch tmpfs. The finalizer never extracts source files. It parses tar entries as streams and rejects every non-regular payload type and unsafe portable path.

Default limits are 1 GiB compressed, 2 GiB expanded, 128 MiB per file, 50,000 entries, 512-byte paths, 100:1 compression, 256 parts, and 16 MiB per part. Every digest is SHA-256. Finalization receipts are Ed25519-signed and immutable. Temporary part cleanup happens only after the receipt is persisted; the object lifecycle and bounded database expiry worker clean abandoned sessions.

## Acceptance

The unit corpus covers traversal, absolute/Windows/control/device paths, links/devices, case collisions, secret paths/content, truncation, digest/size mismatches, entry/file/expanded/ratio limits, signature tampering, grant scope, immutable conflicts, and replay. `task test:integration` additionally performs a real Rails-issued grant, direct presigned uploads to MinIO, Go finalization, Ed25519 verification in Rails, PostgreSQL snapshot creation, part deletion, and idempotent replay.
