# ADR-007: Signed regional TargetBundles

- **Status:** Accepted
- **Date:** 2026-07-12

## Context

A runtime cell must continue serving its last verified state when global control is unavailable, but it must not query mutable Rails rows or accept forged, stale, cross-cell, or partial desired state.

## Decision

The control plane publishes a complete immutable `TargetBundle` for one organization, project, environment, cell, and monotonic generation. It includes services, process envelopes, routes, secret/version references, volume and add-on generations, schedules, artifacts, policy digest, validity, predecessor, and an Ed25519 signature.

The regional gateway performs bounded parsing, strict unknown-field rejection, signature and audience verification, validity checks, immutable identity checks, artifact/evidence closure, reference validation, and atomic compare-and-put generation acceptance before reconciling any CRD. Exact replay is idempotent; competing or stale generations fail.

Bundles never contain secret plaintext or long-lived provider credentials. Regional controllers report observed conditions but cannot directly perform product lifecycle transitions.

## Consequences

- A retained bundle plus durable data dependencies can reconstruct a cell without the control database.
- Signing-key rotation requires overlap and verifier rollout before old-key revocation.
- The in-memory store is a conformance implementation only; production uses a durable regional store with the same atomic contract.
