# Security Policy

## Reporting

Do not open public issues for suspected vulnerabilities. Report privately through GitHub Security Advisories for this repository.

Include the affected component, reproducible steps, impact, and any temporary mitigation. Do not include customer data, live credentials, or destructive proof.

## Credential handling

- Never commit passwords, tokens, private keys, certificates with private material, kubeconfigs, Terraform state, database dumps, or production-derived data.
- Use secret references in configuration. Runtime values are resolved from the configured secret authority.
- Examples must use unmistakably fake values that cannot authenticate anywhere.
- If a secret is exposed, revoke and rotate it before removing it from Git history.

## Supported branch

Security fixes target the default branch until a formal release-support matrix is published.
