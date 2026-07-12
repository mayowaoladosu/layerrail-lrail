# Architecture decision records

ADRs are immutable decision history. Superseding decisions link to the prior record instead of rewriting its context.

| ADR | Decision                                                                            |
| --- | ----------------------------------------------------------------------------------- |
| 001 | Rails modular monolith owns product desired state and public API                    |
| 002 | Rodauth-Rails, isolated password hashes, and asynchronous Resend delivery           |
| 003 | Temporal for processes; NATS JetStream for distribution; transactional outbox/inbox |
| 004 | Immutable snapshots and a non-executing Python detector                             |
| 005 | Constrained Go Starlark compiler to typed Build IR and BuildKit LLB                 |
| 006 | Kata-isolated build plane and Harbor supply-chain evidence                          |
| 007 | Kubernetes regional cells, Cilium, gVisor/Kata, and signed TargetBundles            |
| 008 | Argo Rollouts, opt-in Knative serverless, and KEDA workers                          |
| 009 | OpenBao secret authority, External Secrets, and short-lived internal PKI            |
| 010 | Envoy delta ADS/SDS and make-before-break edge generations                          |
| 011 | PowerDNS, ACME, FRR anycast, and WireGuard backbone                                 |
| 012 | Apache Traffic Server and Ceph RGW for CDN/object delivery                          |
| 013 | Rook-Ceph and operator-wrapped managed data services                                |
| 014 | Loki/Mimir/Tempo and ClickHouse behind scoped query services                        |
| 015 | Append-only reconciled PostgreSQL usage ledger                                      |
| 016 | Small bounded C CO-RE eBPF programs controlled by Go                                |

Each record uses: status, context, decision, boundaries, consequences, and supersession.
