# ADR 003: Temporal for processes and JetStream for distribution

- Status: accepted
- Date: 2026-07-12

## Context

A platform command changes authoritative product state, may start a process lasting minutes or days, and distributes facts to independent consumers. Treating a broker as the workflow engine loses timers and cancellation semantics. Treating a workflow history as a broadcast log couples every observer to process internals. Publishing inside a database transaction also creates an unrecoverable dual-write gap.

## Decision

PostgreSQL remains the command boundary. Each accepted mutation writes product state, immutable audit evidence, an operation, and a versioned outbox event in one transaction. A restricted outbox worker claims rows through security-definer functions using `FOR UPDATE SKIP LOCKED`. It validates the event contract and no-secret policy, then publishes to a file-backed NATS JetStream stream. The public event ID is `Nats-Msg-Id`, making broker retries deduplicable. Publication is marked only after the broker acknowledgement.

Consumers use named durable pull subscriptions and explicit acknowledgements. Before an effect, a consumer inserts an organization-scoped inbox identity keyed by consumer and event. Handler effects run in a savepoint. Success and the inbox completion commit together; failure rolls back the effect while retaining attempt evidence. Bounded poison retries produce a durable dead-letter record and terminate broker redelivery.

Temporal is reserved for durable process state: workflow identity, timers, retries, cancellation, compensation, and versioned replay. NATS events may start or signal a Temporal workflow, but a consumer must never infer process completion from message delivery alone.

The official Temporal Ruby SDK is used from a separate immutable, non-root Linux image because its native core does not support MinGW Windows. Workflow IDs are command business keys. Duplicate starts resolve to the existing handle, incompatible worker generations use new task queues, and code changes use patch markers. Integration runs stop one worker while a workflow is waiting, resume it on a new worker, replay the completed history, and exercise cancellation against the real local Temporal service.

## Boundaries

- Event envelopes are contract-validated, self-contained, organization identified, and secret free.
- Event subjects are versioned and stream namespaces are explicit.
- The worker database role cannot read outbox or email tables directly.
- A consumer establishes organization context from an authenticated actor or service principal before RLS-scoped effects.
- Consumer effects must be idempotent independently of broker deduplication.
- PostgreSQL restores include functions, policies, triggers, migration versions, and least-privilege grants.

## Consequences

NATS loss can be repaired from unpublished PostgreSQL rows. Consumer restarts and duplicate delivery do not duplicate product effects. Invalid events become visible evidence instead of disappearing. Workflow implementation can evolve independently while preserving the stable domain-event contract.

## Supersession

A replacement must demonstrate atomic command evidence, broker-reset recovery, duplicate-effect prevention, bounded poison handling, cancellation, replay, and schema-restore privilege parity.
