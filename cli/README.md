# Lrail CLI

The TypeScript CLI builds deterministic, non-executing source archives and uploads them directly to the source object store.

## Commands

- `lrail source:inspect [directory]` — applies VCS and Lrail ignore rules, scans bounded file content, and prints the archive digest plus canonical manifest without network access.
- `lrail source:upload --project <prj_...> [--directory .]` — requests a bounded upload session, PUTs archive parts to presigned object URLs, and finalizes the immutable snapshot.

`LRAIL_API_TOKEN` is required for upload and is sent only to the control-plane API. It is never sent to presigned object URLs, written to the archive, persisted to disk, or printed. `LRAIL_API_URL` defaults to the local Rails console, and `LRAIL_ORGANIZATION` can assert the organization already bound to the API key.

The archiver always excludes VCS metadata, dependency trees, non-example environment files, private-key file patterns, sockets/devices, symlinks, oversized files, and private-key/token markers. Tar paths, ordering, ownership metadata, timestamps, modes, gzip settings, manifest entries, and SHA-256 digests are deterministic. The Go finalizer still treats all CLI output as hostile and independently recomputes every bound and digest.
