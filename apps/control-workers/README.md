# Lrail control workers

This package hosts official Temporal Ruby SDK workflows in a separately deployable Linux process. The SDK does not support MinGW Windows, so development, linting, tests, and packaging run in the pinned container image rather than silently substituting another workflow engine.

## Process contract

- `LRAIL_TEMPORAL_ADDRESS` is required in production and identifies the Temporal frontend.
- `LRAIL_TEMPORAL_NAMESPACE` selects the namespace; local integration explicitly uses `default`.
- `LRAIL_TEMPORAL_TASK_QUEUE` is explicit and versioned when incompatible workers are introduced.
- Workflow inputs are plain versioned hashes, never Active Record objects or credentials.
- Workflow IDs are business idempotency keys. Duplicate starts return a handle to the existing execution.
- Activities declare timeouts and bounded retry policy. Cancellation propagates through the workflow wait and reaches a terminal Temporal state.
- Workflow changes use patch markers and completed histories are replayed in integration tests before release.

The runtime image uses an immutable Ruby base, installs only production dependencies, runs as UID/GID 10001, and contains neither tests nor development tooling. `task check` builds and lints the Linux package. `task test:integration` runs duplicate-start, restart/replay, completion, and cancellation against the real local Temporal service.
