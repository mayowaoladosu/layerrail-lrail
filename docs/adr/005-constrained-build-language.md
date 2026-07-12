# ADR-005: Constrained Starlark to typed Build IR

- **Status:** Accepted
- **Date:** 2026-07-12

## Context

Customer build definitions are hostile input. Shell-compatible configuration would expose ambient files, environment, network, time, randomness, and worker identity and would make policy review and deterministic caching unreliable.

## Decision

Lrail evaluates a bounded Starlark program with only owned built-ins: `source`, `image`, `run`, `copy`, `cache`, `secret`, `artifact`, and `static_site`. Module loading is denied in the initial contract. Execution has source-byte and step limits and honors cancellation.

Built-ins emit typed Build IR. They do not execute commands, open files, resolve images, use the network, inspect environment variables, or reveal secret values. Secret nodes carry logical IDs and `/run/secrets` targets only. The IR validator enforces earlier-node references, immutable base digests, safe paths, network ceilings, output state, and bounded cardinality.

The build-definition digest covers canonical IR, source snapshot, compiler version, resolved material digests, target platform, non-secret arguments, network profile, cache policy, outputs, and supply-chain policy. Secret values, worker identity, timestamps, queue position, and provider request IDs are excluded.

## Consequences

- Equivalent locked inputs produce the same typed graph and digest.
- New built-ins require a schema, validator, compiler, threat review, and golden tests.
- Dockerfiles remain supported as explicit source-controlled build input but run only in the isolated build plane.
- This compiler does not itself prove BuildKit worker isolation; that is a separate deployment and conformance gate.
