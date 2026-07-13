# System architecture

## Product path

The first trustworthy vertical path is:

```text
authenticated organization
  → immutable source snapshot
  → explainable static detection
  → constrained Build IR
  → isolated BuildKit solve
  → signed and scanned OCI revision
  → signed regional TargetBundle
  → sandboxed workload and revision route
  → verified DNS/TLS edge generation
  → correlated telemetry
  → promotion, rollback, and cleanup
```

## Planes and authority

| Plane           | Authority                                                                       | Must not hold                                                                 |
| --------------- | ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Control         | Product desired state, identity, policy, lifecycle, customer-visible operations | Customer execution, cluster-admin credentials, private image push credentials |
| Source/build    | Immutable source materialization and build evidence                             | Control database access, reusable provider credentials, runtime authority     |
| Runtime         | Reconciliation of accepted signed regional generations                          | Product authorization, source-provider tokens, global mutation authority      |
| Data            | Add-on, backup, restore, credential, and storage reconciliation                 | Customer account sessions, control database access                            |
| Edge            | DNS/TLS/routing/cache/WAF delivery of accepted generations                      | Customer code, source, general secret authority, Kubernetes administration    |
| Telemetry/meter | Tenant-scoped signals and signed usage facts                                    | Product mutation authority, unscoped cross-tenant queries                     |

## Desired and observed state

Rails stores versioned desired specifications. Commands evaluate invariants and persist domain state, audit, and an outbox event atomically. Temporal coordinates finite multi-system processes after commit. Controllers reconcile signed desired generations continuously and report typed conditions. Controller observations never mutate product lifecycle directly; a command or workflow consumes the observation and performs the guarded transition.

## Deployment units

- `control-web`: Rails HTML and API
- `control-worker`: outbox, notifications, webhooks, and Temporal workflows
- `source-gateway`: isolated fetch/upload finalization
- `detector`: non-executing Python framework detector
- `build-control`: signed assignment verification, Starlark/Build IR/LLB, disposable Kata BuildKit workers, and residue quarantine
- `regional-control`: TargetBundle gateway, placement, capacity, and CRD controllers
- `edge-control`: EdgeGeneration compiler and delta xDS/SDS
- `dns-cert-control`: ownership, PowerDNS, ACME, and PKI
- `data-control`: volume and managed add-on lifecycle
- `telemetry-gateway` and `meter-service`: signal and usage isolation
- `tunnel-gateway/client`: expiring outbound QUIC tunnels
- `lrail-cli`: local developer interface over the public API

## Technology baseline

- Rails 8.1.3 and Ruby 3.4.10
- Go 1.26.5
- Python 3.14.6 with uv 0.11.28
- Node 24.16.0, TypeScript 5.9.3, pnpm 11.12.0
- OpenAPI 3.1, JSON Schema 2020-12, and Protobuf/Buf 1.71.0
- PostgreSQL, Temporal, NATS JetStream, Valkey, OpenBao, Harbor, and Ceph
- Kubernetes, Cilium, gVisor/Kata, Argo Rollouts, KEDA, Knative, and Kyverno
- Envoy delta ADS/SDS, PowerDNS, FRR, WireGuard, ATS, Coraza, and bounded eBPF
- OpenTelemetry, Loki, Mimir, Tempo, and ClickHouse

Exact platform component versions are selected through their conformance packets rather than guessed at repository bootstrap.

## Security invariants

- Organization ID is mandatory at every customer boundary and derives all infrastructure identity.
- Foreign-resource behavior does not disclose existence.
- Public POST operations support organization/principal/route-scoped idempotency.
- Secret values are written to the secret authority and are not persisted in product rows or returned twice.
- Revisions, artifacts, source snapshots, bundles, and edge generations are content-addressed and immutable.
- Long-running operations expose typed states, retry classification, cancellation, cleanup ownership, and audit correlation.
- No production fallback uses plaintext, unsigned artifacts, mutable tags, broad credentials, or human console edits.
