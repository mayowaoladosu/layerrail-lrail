# Lrail control workers

This package hosts official Temporal Ruby SDK workflows in a separately deployable Linux process. The SDK does not support MinGW Windows, so development, linting, tests, and packaging run in the pinned container image rather than silently substituting another workflow engine.

## Process contract

- `LRAIL_TEMPORAL_ADDRESS` is required in production and identifies the Temporal frontend.
- `LRAIL_TEMPORAL_NAMESPACE` selects the namespace; local integration explicitly uses `default`.
- `LRAIL_TEMPORAL_TASK_QUEUE` is explicit and versioned when incompatible workers are introduced.
- `LRAIL_NATS_URL` and `LRAIL_NATS_STREAM` feed only validated `deployment.created` and `deployment.canceling` domain events into generation-bound Temporal starts/signals.
- `LRAIL_CONTROL_INTERNAL_*` configures the client certificate, key, CA, and HTTPS origin for Rails plan/event/result callbacks.
- `LRAIL_BUILD_SERVICE_*` configures the separate client identity and HTTPS origin for durable BuildService submit/watch/cancel calls.
- Workflow inputs are plain versioned hashes, never Active Record objects or credentials.
- Workflow IDs are business idempotency keys. Duplicate starts return a handle to the existing execution.
- Activities declare timeouts and bounded retry policy. Cancellation propagates through the workflow wait and reaches a terminal Temporal state.
- Workflow changes use patch markers and completed histories are replayed in integration tests before release.
- Deployment build activities heartbeat retained event cursors. Activity retry replays the same immutable plan, BuildService deduplicates the generation, and Rails deduplicates `(operation, generation, sequence)`.
- A cancellation signal runs a retrying exact-generation cancel activity while the main activity keeps watching; whichever terminal BuildService result wins is persisted before the workflow completes.

The runtime image uses an immutable Ruby base, installs only production dependencies, runs as UID/GID 10001, and contains neither tests nor development tooling. `task check` builds and lints the Linux package. `task test:integration` runs duplicate-start, restart/replay, completion, and cancellation against the real local Temporal service.
