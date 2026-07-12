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

- `apps/control-plane` — Rails HTML/API, authentication, domain commands, and operator plane
- `apps/control-workers` — durable workflow, outbox, notification, and webhook workers
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

## Status

Construction follows dependency-ordered, acceptance-gated vertical slices. A compile or attractive dashboard is not completion; executable positive, negative, recovery, and cleanup evidence is required for each supported capability.

## License

Original Lrail code is proprietary and publicly visible for evaluation. See [LICENSE.md](LICENSE.md).
