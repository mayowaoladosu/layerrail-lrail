# Lrail CLI

The TypeScript CLI builds deterministic, non-executing source archives and uploads them directly to the source object store.

## Commands

- `lrail source:inspect [directory]` — applies VCS and Lrail ignore rules, scans bounded file content, and prints the archive digest plus canonical manifest without network access.
- `lrail source:upload --project <prj_...> [--directory .]` — requests a bounded upload session, PUTs archive parts to presigned object URLs, and finalizes the immutable snapshot.
- `lrail deploy [directory] --project <prj_...> --environment <env_...> --accept-detected` — archives and uploads local source, explicitly accepts an unambiguous detector proposal, creates the deployment, and follows retained build events through immutable signed artifact publication.
- `lrail deploy [directory] ... --build-file Lrailfile.star` — uses repository Starlark instead of accepting detector-generated configuration. Exactly one of `--accept-detected` and `--build-file` is required.
- `lrail deploy:git --project <prj_...> --environment <env_...> --connection <src_...> --repository owner/name --commit <exact-sha> --accept-detected` — fetches the exact commit through the authorized GitHub provider boundary, persists the signed immutable snapshot, creates the deployment, and follows the same retained artifact-build events. `--root` selects a canonical monorepo subdirectory.
- `lrail deploy:watch --operation <op_...> [--after <sequence>]` — resumes retained ordered events after a terminal disconnect without restarting the build.
- `lrail deploy:cancel --deployment <dep_...> --reason <text>` — requests idempotent cancellation; Temporal and BuildService reconcile the exact active generation and cleanup result.

Git-connected projects deploy through the same workflow after the provider webhook resolves and fetches an exact commit. Branch names remain routing metadata; the persisted source snapshot and artifact evidence are digest-bound. Force-pushes create new source/deployment generations, while replayed provider deliveries create no duplicate deployment.

`LRAIL_API_TOKEN` is required for upload and is sent only to the control-plane API. It is never sent to presigned object URLs, written to the archive, persisted to disk, or printed. `LRAIL_API_URL` defaults to the local Rails console, and `LRAIL_ORGANIZATION` can assert the organization already bound to the API key.

The archiver always excludes VCS metadata, dependency trees, non-example environment files, private-key file patterns, sockets/devices, symlinks, oversized files, and private-key/token markers. Tar paths, ordering, ownership metadata, timestamps, modes, gzip settings, manifest entries, and SHA-256 digests are deterministic. The Go finalizer still treats all CLI output as hostile and independently recomputes every bound and digest.
