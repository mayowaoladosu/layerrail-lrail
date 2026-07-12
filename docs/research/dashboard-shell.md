# Dashboard shell research

**Decision date:** 2026-07-12  
**Scope:** Information architecture and interaction patterns only. No third-party dashboard code, copy, trademarks, or assets are incorporated.

## Decision

Lrail's operational console uses an original Rails/Turbo/Stimulus implementation with:

- **Primary operational reference: Dokploy.** Its documented hierarchy—project → environment → service—matches Lrail's organization → project → environment → service model. Its official interface tour demonstrates project service grids, environment selection, deployment history, build logs, runtime logs, monitoring, domains, databases, backups, schedules, and organization settings.
- **Secondary responsive reference: Coolify.** Its first-party screenshots validate compact resource cards, clear status marks, dark operational surfaces, and layouts that collapse without replacing the resource hierarchy.
- **Product hierarchy reference: the Lrail blueprint.** The console remains team/organization first, then project, deployment, and settings. The first login leads to source selection and first-project creation rather than an empty generic dashboard.

The result must not look like a repurposed admin template. Navigation and screen density come from real PaaS operations; visual tokens, component markup, copy, workflows, and branding are Lrail-owned.

## License boundary

- Dokploy's root `LICENSE.MD` identifies the core repository as Apache-2.0. Its `LICENSE_PROPRIETARY.md` applies the Dokploy Source Available License only to code in a `/proprietary` folder. Lrail copies neither core nor proprietary implementation; enterprise screen ideas are not used as code sources.
- Coolify's `LICENSE` is Apache-2.0. Lrail still uses screenshots only as behavioral research and does not copy implementation or branded assets.
- Apache-2.0 does not grant trademark rights. Lrail uses no Dokploy or Coolify name, logo, product copy, or distinctive asset in the product interface.

## Shell specification

### Global frame

- A fixed desktop sidebar contains the Lrail mark, organization switcher, global routes, and account access.
- A compact top bar contains breadcrumbs, environment context, command/search trigger, alerts, and create action.
- At narrow widths, the sidebar becomes a modal navigation sheet; all functions remain keyboard reachable.
- `Ctrl+K` opens a command palette over an indexed list of organizations, projects, services, deployments, and settings.

### Navigation levels

1. **Global:** Home, projects, activity, platform status, invitations, security notices.
2. **Organization:** Overview, projects, members, access, usage, audit, settings.
3. **Project:** Overview, services, deployments, previews, data, domains, telemetry, settings.
4. **Service:** Deployments, releases, configuration, scaling, routes, metrics.
5. **Resource detail:** Summary, state timeline, events, logs, configuration, related resources, safe actions.

The left navigation changes context deliberately; it does not mix host administration with customer project navigation.

### Project and service surfaces

- Project index supports search, status filters, grid/list choice, and URL-persisted state.
- Project overview is environment-aware and shows a scan-friendly service grid.
- Service cards show kind, framework/runtime, current release, health, region, replica readiness, recent deployment, and one direct action row.
- Repeated resources may use cards; settings and narrative page sections remain unframed. Nested cards are prohibited.

### Deployment detail

The deployment route shows:

- immutable source identity and revision digest;
- stage tracker with accepted, running, waiting, retrying, succeeded, failed, canceling, and canceled states;
- stable-height structured/raw log viewer with follow, pause, search, wrap, time range, and download;
- timeline of state transitions and external conditions;
- evidence summary for SBOM, scan, provenance, signature, and policy;
- actions only when state and permission permit: cancel, retry, promote, pause, abort, or roll back.

### Settings

Settings are scoped visibly:

- organization: members, roles, API/OAuth clients, source providers, notifications, usage, audit, policy;
- project: source, environments, manifest, domains, webhooks, schedules, deletion;
- service: build, variables and secret references, health, scaling, routes, resources;
- account: identity, sessions, MFA, recovery, preferences.

### Accessibility and state

- WCAG 2.2 AA; status always has text and icon, never color alone.
- Useful server-rendered first paint; Turbo streams update bounded panels.
- Every async operation exposes stage, waiting reason, retry, terminal result, and remediation.
- No optimistic mutation for deployments, domains, access, data, or billing.
- Destructive actions name the resource and consequence; high-risk actions require recent authentication and typed confirmation.
- Tables provide sticky headers, keyboard navigation, responsive row detail, and textual graph alternatives.

## Rejected approaches

- **Fork Dokploy or Coolify UI:** conflicts with Rails-first architecture and introduces unnecessary license/upgrade coupling.
- **Generic React admin template:** does not encode PaaS resource hierarchy or operation state.
- **Pixel-copy Vercel:** creates trademark/trade-dress risk and omits Lrail-specific runtime, evidence, data, and operator surfaces.
- **Host-first Coolify navigation:** useful for self-host operators but wrong as the customer mental model for Lrail's organization-scoped cloud product.

## Primary sources

- Dokploy interface overview: https://docs.dokploy.com/docs/core/interface-overview
- Dokploy source and root license: https://github.com/Dokploy/dokploy
- Dokploy proprietary license boundary: https://github.com/Dokploy/dokploy/blob/canary/LICENSE_PROPRIETARY.md
- Coolify screenshots: https://coolify.io/docs/get-started/screenshots
- Coolify source and Apache-2.0 license: https://github.com/coollabsio/coolify
