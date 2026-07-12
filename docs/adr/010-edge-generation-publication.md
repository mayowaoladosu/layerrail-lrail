# ADR-010: Canonical edge generations and make-before-break publication

- **Status:** Accepted
- **Date:** 2026-07-12

## Context

Customer route intent cannot be streamed directly to proxies. Host/path ambiguity, cross-tenant wildcard capture, unsafe normalization, missing releases, invalid weights, or dependency ordering could misroute traffic or expose another tenant.

## Decision

A separate Go compiler validates verified route intent and emits an immutable canonical `EdgeGeneration`. Hostnames use IDNA and lowercase canonicalization. Exact hosts precede wildcard hosts; exact paths precede prefixes; longer prefixes precede shorter prefixes; regex requires explicit priority. Encoded slash, backslash, dot, traversal, control characters, malformed hosts, non-100 traffic weights, and cross-organization exact/wildcard overlap are rejected.

The canonical digest is calculated after deterministic route and target ordering. Publication stages clusters/endpoints and secrets before routes, waits for ACK and health quorum, runs synthetic probes, activates only after success, and retains the previous signed generation for rollback.

## Consequences

- Route input order cannot change the generated digest.
- A NACK preserves last known good resources and blocks activation rather than deleting traffic.
- The compiler proves static intent safety; Envoy/xDS scale, ACK persistence, and PoP rollout remain separate conformance gates.
