# LayerRail Lrail

Lrail is an independently designed, owned platform-as-a-service control and data plane. It turns an authenticated organization, an immutable source snapshot, and a versioned project manifest into an isolated, signed build, a sandboxed regional workload, a verified edge route, correlated telemetry, and a reversible release.

This repository is intentionally independent. It does not import another LayerRail checkout or clone another PaaS product. The web console uses an original Rails implementation informed by established operational patterns from Dokploy and Coolify: organization context, project → environment → service hierarchy, direct deployment navigation, dense resource summaries, and responsive status views.

## Architectural laws

1. Customer code is hostile and never executes in a control-plane or privileged context.
2. Rails owns desired state and customer-visible truth; infrastructure controllers reconcile it.
3. Every side effect is idempotent, retryable, auditable, quota-aware, metered, and cleanable.
4. Revisions are immutable; promotion and rollback move verified release pointers.
5. Control, build, runtime, data, and edge planes have separate credentials and failure domains.
6. Public contracts are versioned and adapters are replaceable.
7. No production truth lives only in cache, memory, logs, metrics, one host, or a console action.

## Repository shape

- `apps/control-plane` — Rails HTML/API, authentication, domain commands, operator plane, and separately runnable worker entrypoints
- `services` — Go and Python source, build, regional, edge, DNS, data, telemetry, and tunnel services
- `cli` — TypeScript developer CLI
- `sdk` — Ruby, TypeScript, Go, and Python SDKs
- `contracts` — OpenAPI, Protobuf, event, JSON Schema, and CRD contracts
- `platform` — Kubernetes, Helm, Talos, edge, policy, and observability assets
- `bpf` — bounded CO-RE eBPF programs and tests
- `test` — fixtures, conformance, end-to-end, security, performance, and chaos suites
- `docs` — ADRs, threat models, runbooks, services, APIs, and operational evidence

## Security

No production credential belongs in this repository. Configuration examples contain references or unmistakably fake values only. See [SECURITY.md](SECURITY.md) for reporting and handling rules.

## Local acceptance

The lightweight profile starts PostgreSQL, Temporal, NATS JetStream, Valkey, MinIO, and Mailpit through `task lab:up`. `task db:prepare` applies authoritative migrations, while `task db:dump` generates a deterministic PostgreSQL SQL structure through the pinned container. `task db:verify` restores that artifact into a disposable database and checks functions, RLS policies, triggers, migration versions, and runtime-role denials.

The Rails app exposes independent process entrypoints for durable outbox, project-event, email, and Solid Queue source jobs. `bin/dev` starts the web process, CSS watcher, and job supervisor together. Production email uses Resend; development and tests use an in-memory adapter and never require a provider credential.

The official Temporal Ruby SDK does not support Windows, so `apps/control-workers` is intentionally built and tested as a separate non-root Linux image from an immutable Ruby base. Its real-service test proves business-key duplicate start, worker shutdown and replay on a new worker, explicit completion, bounded activity retry policy, and cancellation. `task check`, `task test`, and `task test:integration` are the required local gates.

Local source upload is also operational end to end. Rails authorizes an expiring bounded session, clients upload parts directly to the versioned MinIO bucket, and the non-root Go source gateway streams a hostile tar.gz through path/type/size/ratio/credential controls. It stores content-addressed archive and manifest objects, persists a signed replay receipt, deletes temporary parts, and returns an Ed25519 result that Rails verifies before creating the immutable snapshot. No source byte traverses Rails memory.

The provider acquisition plane is split at the credential seam. A dedicated non-root token broker alone holds the GitHub App key and can mint only one-repository, read-only installation tokens from signed fetch grants. The source gateway resolves and verifies an exact commit/tree, follows only approved archive redirects without forwarding the token, verifies Git blob identities, deterministically normalizes the archive, and emits an immutable Ed25519 fetch receipt. Its conformance suite proves exact-commit identity, replay without a second token, force-push divergence, credential absence from objects, and fail-closed submodule/LFS policy.

GitHub installation and repository routing are durable control-plane state. A globally unique installation belongs to one workspace and an auditable member; each project can bind one authorized repository, production branch, and canonical root. Webhook ingress verifies GitHub's raw-body HMAC before parsing, stores only normalized evidence, and applies each delivery identity once through a narrow security-definer function. Actionable push and pull-request deliveries enqueue an at-least-once source job. The job uses tenant-scoped lease functions, requests exactly the webhook commit, verifies the signed receipt, and records one immutable fetch effect per project binding. A replay has no second effect; a production force push supersedes only the previous production fetch, while a pull-request synchronize event supersedes only that PR's preview track. No snapshot is mutated. Installation suspension, revocation, or repository removal disables affected automatic acquisition.

The Python detector is a non-executing library/CLI with private typed Ruby, Node, Python, Go, static, and Docker plugins. Its bounded inventory exposes no shell, network, dynamic import, or arbitrary file capability. Detector v2 binds every proposal to exact snapshot/detector/ruleset/plugin versions and emits runtime/build/process detail, workspace ordering, structured diagnostics, add-on hints, exact files considered, and a content-addressed evidence graph with derived confidence. Only unblocked proposals include a strict `lrail.dev/v1` generated manifest. The published detector v1 schema remains intact; v2 has a separate contract and real/adversarial 90%-coverage corpus.

The Go build compiler evaluates only an in-memory constrained Starlark v1 request. Repository modules must carry exact digests beneath approved roots; compiler-owned standard modules use versioned `@lrail/v1` names. A deterministic one-evaluation cache rejects missing modules, traversal, cycles, initialization effects, and depth/count overflow. Shared source/AST/step/call/value/result/wall limits and context cancellation bound the whole load graph. Owned built-ins accept named arguments and return immutable source/state/cache/secret/output references; no host I/O, environment, network client, clock, randomness, process handle, BuildKit client, or secret value is exposed. Successful evaluation emits separately versioned, strictly validated Build IR v2 with module evidence and a replay-locked digest. Failures return stable safe file/line/column/rule/hint/call-stack diagnostics without raw source, host paths, or argument values.

## Status

Construction follows dependency-ordered, acceptance-gated vertical slices. A compile or attractive dashboard is not completion; executable positive, negative, recovery, and cleanup evidence is required for each supported capability.

## License

Original Lrail code is proprietary and publicly visible for evaluation. See [LICENSE.md](LICENSE.md).
