# ADR 005: Deterministic detector plugins and evidence graph

- Status: accepted
- Date: 2026-07-13

## Context

Framework detection inspects hostile customer snapshots before any build exists. A detector that runs package scripts, imports project modules, follows links, reads arbitrary files, reaches the network, or silently guesses conflicting process metadata would turn convenience logic into a code-execution or supply-chain boundary. A scalar confidence score without its exact contributions is not auditable product evidence.

## Decision

`Detector.detect(snapshot_path, source_snapshot_id, selected_root)` is the sole external interface. It inventories bounded immutable metadata, discovers package/workspace roots, invokes private typed plugin adapters, resolves overlays and conflicts, and returns one strict immutable proposal. Ruby, Node, Python, Go, static, and Docker are adapters at the internal plugin seam. Each adapter receives only `DetectionContext`; it cannot shell out, open arbitrary paths, import project code, or create network clients.

The inventory rejects root/selected-root links, parent traversal, noncanonical paths, case collisions, unsupported file types, excessive depth/count, oversized metadata, non-UTF-8 selected text, and aggregate read-budget overflow. It records executable mode and permits bounded source headers only for known language suffixes. VCS, dependency, virtual-environment, build, and coverage directories are excluded.

Plugins emit candidates, structured diagnostics, add-on hints, and content-addressed evidence facts. Confidence is derived, never assigned independently:

`confidence = clamp(0.5 + sum(evidence.confidence_delta), 0, 1)`

The resolver permits one service candidate per root. Explicit Docker intent overlays a framework candidate; close ecosystem conflicts, multiple Dockerfiles, confidence below the published threshold, missing locks/production commands/ports, and plugin ambiguity become blocking unresolved diagnostics. Node workspace dependencies are mapped to detected service names. Go modules may produce multiple process groups while retaining one module root. Production and worker processes remain distinct.

An unblocked result includes a generated manifest conforming to the existing `lrail.dev/v1` JSON Schema. It remains advisory until a user accepts a new project manifest revision. A blocked result never includes a generated manifest.

Detector v1 remains published and unchanged. WP-035 publishes `detector.lrail.dev/v2` at a separate contract ID with proposal, detector, ruleset, plugin, and source-snapshot identities; runtime/build/process detail; evidence graph; warnings/unresolved decisions; add-on hints; exact considered files; and generated manifest.

## Consequences

Detection is reproducible across operating systems and cannot become an implicit build. Every proposal is attributable to exact code/rules and exact snapshot evidence. New ecosystems require a private adapter satisfying the same small interface rather than edits across orchestration callers. Ambiguity increases product friction deliberately instead of becoming an unsafe default.

The conformance corpus contains real-shaped Rails/Sidekiq, Node workspace, FastAPI, Go multi-process, static, and Docker repositories plus conflicting lockfile, unsafe Procfile, malformed, oversized, unusual-encoding, symlink, traversal, build-tag, and conflicting-framework cases. Static typing, strict lint, JSON Schema fixtures, deterministic replay, and at least 90% coverage gate changes.

## Supersession

Any replacement must retain non-execution, no-network/no-shell plugin capabilities, bounded canonical inventory, exact snapshot/version identity, derived explainable confidence, explicit conflict blocking, immutable v1 compatibility, a separately versioned output contract, and generated-manifest validation.
