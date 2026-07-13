# ADR-022: Deployment build orchestration seam

- **Status:** Accepted
- **Date:** 2026-07-13
- **Complements:** ADR-003, ADR-006, ADR-019, ADR-020, and ADR-021

## Context

Local uploads and provider fetches already produce immutable source snapshots. The detector, constrained Starlark evaluator, Build IR compiler, BuildKit cell, Harbor publisher, scanner, policy engine, and evidence signer also exist, but no owner connects those modules into one replay-safe deployment journey. Letting Rails perform builds would give customer source and build execution a route to the control database. Letting the build plane query Rails would invert desired-state ownership. Sending a detector proposal directly to BuildKit would turn advisory, customer-influenced metadata into executable authority without an owned translation and policy decision.

Temporal must remain the durable business orchestrator, but Temporal history cannot contain credentials, source bytes, log bodies, large detector output, LLB, or evidence payloads. BuildCell already streams the authoritative solve events and terminal result; adding another cell log protocol would create ordering and recovery disagreements.

## Decision

### Deep orchestration module

The Go `buildorchestrator` module owns the complete implementation behind one small interface: run a versioned immutable build request, emit ordered safe events, and return one terminal immutable result. Its external request contains only organization, project, deployment, operation, build generation, immutable source identities and object reference, explicit detector acceptance intent, target platform, and deadline. Cell placement, policy, base-image catalog, compiler versions, object layout, assignment signing, retries, and publication authority remain private implementation details.

The implementation performs these stages in order:

1. validate and stage the complete source object by digest;
2. safely materialize it into fresh bounded scratch;
3. run the deterministic Python detector without source execution or network authority;
4. select an explicitly enabled repository `Lrailfile.star` or translate an accepted, unblocked detector proposal into owned versioned Starlark;
5. evaluate constrained Starlark into canonical Build IR;
6. resolve every base image to a policy-approved digest and compile policy-locked BuildKit LLB;
7. write immutable IR, lock, LLB, config, detector, and generated-build objects beneath the selected cell prefix;
8. obtain a non-exportable OpenBao Transit signature over a short-lived generation-bound BuildCell assignment;
9. dispatch over TLS 1.3 mTLS and relay the existing BuildCell event stream; and
10. return success only when BuildCell reports clean cleanup and complete signed supply-chain evidence for every output.

The detector-to-Starlark translator is owned code with a version included in the generated object and definition digest. It consumes only the strict detector v2 contract, rejects blocked, ambiguous, unsupported, or unaccepted proposals, maps typed argv rather than shell strings, selects bases from the configured immutable catalog, and cannot broaden network, cache, secret, or output capabilities. Repository Starlark remains subject to the same evaluator, base catalog, policy lock, and LLB audit.

### Plane and authority separation

Rails remains authoritative for deployments, operations, builds, services, revisions, attestations, and tenant authorization. It prepares a generation-bound orchestration plan through an mTLS-only internal endpoint and accepts ordered event/result callbacks with compare-and-set generation checks. It never receives source bytes and never calls BuildKit.

The separate Ruby control-worker process consumes `deployment.created`, starts one Temporal workflow using `deployment/<id>/build/<generation>` as the business idempotency key, and invokes activities with plain versioned hashes. Activities fetch the plan, call the build module, heartbeat the last durable event sequence, and report results to Rails. Credentials come only from activity process configuration and never enter workflow input, return values, errors, search attributes, or memo.

The build broker has no route or credential for the control PostgreSQL database, source provider, Kubernetes API outside its build-cell client, Harbor administration, or evidence key. It may read the authorized immutable snapshot, write only its cell content prefix, request an assignment signature from its dedicated Transit policy, and call the selected BuildCell identity. BuildCell retains sole build execution, short-lived Harbor capability, evidence-signing, cleanup, and worker-allocation authority.

### Events, recovery, and cancellation

One broker sequence orders detector, compiler, assignment, and relayed BuildCell records. Events are append-only, bounded, UTF-8, secret-redacted records. Rails persists them under a unique `(operation, generation, sequence)` key before exposing them through cursor-based operation event retrieval. Live CLI following repeatedly resumes after the last sequence; it does not depend on one uninterrupted connection.

The broker persists request digest, stage, last event sequence, assignment identity, and terminal result. Repeating the same build and generation attaches to or replays the same run; a changed request under the same identity fails. A higher generation creates a new assignment nonce and object prefix. Temporal activity retry uses `Get` and `WatchEvents` before any resubmission. BuildCell replay and result recovery remain authoritative once assignment dispatch has begun.

Cancellation marks the Rails operation canceling, signals the Temporal workflow, and calls broker cancellation for the exact build generation. The broker cancels detection or compilation locally, or calls BuildCell `CancelAssignment` after dispatch. Completion and cancellation are reconciled before terminal classification. Forced cleanup still has to reach a terminal BuildCell cleanup result; a residue or quarantine condition cannot be reported as success.

### Product completion at M-B

The workflow persists one `Build` and one accepted detector/manifest record before dispatch. A complete output creates or resolves the project service by the accepted service name, creates an immutable `Revision`, and records all five evidence references as organization-scoped attestations. Build and revision rows bind source, Build IR, definition, artifact, manifest, SBOM, scan, provenance, signature, policy, logs, worker, and generation identities.

At M-B the deployment and operation finish in an explicit `artifact_ready` state. No release, target bundle, regional replication request, Kubernetes resource, route, or runtime process is created. Runtime begins only at the next milestone.

## Rejected alternatives

- Rails shelling out to the detector or BuildKit: violates plane isolation and gives the web tier source/build authority.
- Temporal calling each detector/compiler/storage/cell primitive separately: a shallow interface leaks implementation details into durable history and makes replay compatibility depend on every internal step.
- BuildCell reading Rails or cloning Git: violates source and database authority separation.
- Treating generated detector JSON as Build IR: skips explicit acceptance, owned translation, and Starlark policy.
- A second BuildCell log RPC: duplicates the existing ordered stream and creates irreconcilable retention semantics.
- Marking deployment `succeeded` after image export: ignores mandatory scan, policy, signature, evidence publication, readback, and cleanup.

## Consequences

The build broker becomes a durable internal control module and requires its own mTLS identity, object-prefix capability, Transit role, state volume, detector runtime, policy catalog, and BuildCell client. The Rails schema gains generation-bound operation events and immutable orchestration/evidence fields. The CLI gains explicit detected-configuration acceptance, resumable event following, and cancellation.

In return, callers learn one small interface while source handling, advisory detection, trusted translation, compilation, signing, execution, evidence, recovery, and cleanup remain local to one implementation. The same path serves local uploads and exact Git commits, retries cannot create a second artifact accidentally, logs survive disconnects, tenant checks remain in Rails, and M-B can prove a real immutable artifact without prematurely claiming runtime deployment.