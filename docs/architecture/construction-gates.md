# Construction gates

A milestone passes only with executable evidence; elapsed time and merged code are not evidence.

| Gate | Capability      | Required proof                                                                                    |
| ---- | --------------- | ------------------------------------------------------------------------------------------------- |
| M-A  | Control core    | Two-tenant auth, roles, projects, commands, outbox, workflows, API/SDK, accessible console        |
| M-B  | Source/build    | Local and Git deploy produce immutable signed/scanned image, SBOM, provenance, and logs           |
| M-C  | Runtime cell    | Supported fixtures run in sandbox with signed TargetBundle, scaling, jobs, cancellation, rollback |
| M-D  | Production edge | Owned/custom domain verifies, receives TLS, routes through two edge instances, and rolls back     |
| M-E  | Telemetry/meter | Scoped logs/metrics/traces, alert/incident, signed usage facts, reconciled ledger                 |
| M-F  | Storage/data    | PostgreSQL, Valkey, volume, object space, credential rotation, backup, and PITR                   |
| M-G  | CDN/tunnel      | Cache policy, distributed purge, signed access, edge accounting, public/private QUIC tunnel       |
| M-H  | Multi-region    | Two independent cells/PoPs, recovery drills, threat falsification, measured RPO/RTO               |
| M-I  | GA evidence     | Golden journeys, load/soak, legal surfaces, on-call, penetration test, signed readiness packet    |

## Definition of done

Every supported feature includes:

- positive behavior and foreign-tenant/security negatives;
- public/internal contract, migrations, fixtures, and generated artifacts;
- authorization, tenancy, idempotency, limits, retry, cancellation, cleanup, telemetry, and audit;
- staged rollout and tested rollback or a proof that the change is compile-time/local only;
- dependency/license/security checks and no new secret or broad privilege;
- user, API, CLI, SDK, operator, and documentation paths where applicable.
