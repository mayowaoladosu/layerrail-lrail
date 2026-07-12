# ADR 002: Isolated authentication and durable email delivery

- Status: accepted
- Date: 2026-07-12

## Context

Authentication owns password-equivalent material, recovery flows, active sessions, MFA enrollment, and security notices. The web process must authenticate users without obtaining reusable password hashes. Provider outages must not roll back an account transaction or cause duplicate verification and recovery messages.

## Decision

Rodauth-Rails owns browser authentication. PostgreSQL stores current and previous password hashes in dedicated tables. The web role can mutate those rows only through Rodauth's lifecycle and can verify passwords only through narrowly granted security-definer functions; it cannot select hash values.

Rodauth provider messages are converted after commit into versioned `EmailIntent` rows. An exact content fingerprint is the intent idempotency key. A restricted worker claims intents with `FOR UPDATE SKIP LOCKED` inside a security-definer function, then uses either the in-memory development adapter or Resend. Retry state, attempt count, provider identifier, and terminal delivery state remain in PostgreSQL.

Resend callbacks are verified over the raw request body with the official Svix verifier, its timestamp window, and all three signature headers. Provider delivery IDs are unique before state is applied. Unsupported, stale, tampered, or oversized requests do not mutate an intent.

## Boundaries

- Production requires explicit sender, Resend API key, and webhook signing secret.
- Provider secrets never enter an intent, event, log, fixture, or source file.
- The fake adapter is the default only outside production.
- Email templates are selected by name and version; workers reject unknown versions.
- The provider receipt table is reachable from the web role only through the signed-event function.

## Consequences

Account mutation and email transport are decoupled. A provider outage is observable and retryable without duplicate intent creation. Schema restores must preserve authentication functions and role grants, so the authoritative Rails dump is PostgreSQL SQL plus explicit runtime grants rather than a Ruby schema.

## Supersession

A replacement must retain unreadable password hashes, idempotent intents, raw-body signature verification, replay protection, and a tested provider-outage path.
