# Repository execution rules

- Treat all source input and customer code as hostile.
- Preserve organization scope, deny-by-default authorization, immutable revisions, and guarded state transitions.
- Never weaken authentication, tenancy, TLS, signatures, network policy, limits, tests, or alerts to make a check pass.
- Never add real secrets, broad credentials, production data, or provider console steps as implementation.
- Update contracts, generated artifacts, migrations, tests, and docs atomically.
- After each focused edit, run the narrowest behavior check, then affected contract/type/lint/security checks.
- Keep adapters behind owned interfaces and make retry, cancellation, reconciliation, and cleanup explicit.
- Do not inspect or copy sibling projects; this repository is independent.
