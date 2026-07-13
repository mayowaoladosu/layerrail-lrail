# ADR-019: Build IR policy lock and deterministic BuildKit LLB

- **Status:** Accepted
- **Date:** 2026-07-13
- **Complements:** ADR-005 and ADR-018

## Context

Starlark evaluation produces typed Build IR, not an executable build. A separate seam must bind that graph to organization policy, verified base-image evidence, network and mount capabilities, and a concrete BuildKit Low-Level Build definition. Directly handing customer-controlled fields to a BuildKit client would leave cache tenancy, base provenance, egress, secret mounts, and output configuration implicit. Re-resolving mutable materials during compilation would also make equivalent accepted inputs produce different definitions.

## Decision

The WP-037 compiler is an in-memory deep module with one external interface: `Compile(context, Request) -> Result`. Its request contains organization/project IDs, Build IR v2 plus its expected digest, an immutable build-policy revision, exact base-material locks, and explicitly non-secret build arguments. It does not receive a BuildKit daemon, registry client, filesystem adapter, secret store, network client, clock, worker identity, queue metadata, or provider request ID. It emits official BuildKit v0.31.1 LLB protobuf definitions but never executes a solve.

The compiler validates and normalizes all policy before graph construction. Policy identity and revision are canonicalized into a policy digest. Registry, base-digest catalog, signature identity, SBOM/provenance requirements, allowed network profiles/hosts/gateways, cache scope/trust/sharing, allowed secret logical names, and allowed non-secret argument names are deny-by-default. Names resembling credentials, passwords, private keys, secrets, or tokens are forbidden as build arguments.

Every image node has exactly one material lock. Requested and resolved references must carry the same digest, target platform, allowed registry, approved signature identity, classification, and required SBOM/provenance evidence. A resolution digest is recomputed over those normalized facts. Compilation performs no registry lookup; BuildKit receives only the locked resolved digest reference with force-pull semantics so registry content is verified by digest at solve time.

Capabilities are explicit and immutable:

- Source nodes become `llb.Local` vertices with normalized include/exclude/follow paths, source-snapshot shared-key identity, and no session credential embedded in LLB.
- Image nodes become digest-pinned `llb.Image` vertices for the declared target platform.
- Run nodes use argv, sorted environment, non-root user, workdir, and explicit network mode. `none` maps to BuildKit no-network; `packages`, `allowlist`, and `private` use sandbox networking plus a locked gateway/host capability consumed by the WP-038 controller. The profile, hosts, and gateway remain in the definition lock; profile/hosts also bind the raw LLB vertex metadata.
- Cache nodes become persistent cache mounts. The cache ID is derived from scope ID, organization/project policy, trust domain, logical name, target, and policy digest. Shared caches are denied unless policy allows them. A run combining a secret mount with a shared cache is denied unless an explicit policy bit permits it.
- Secret nodes become BuildKit secret mounts by logical ID with mode `0400`, non-root ownership, required/optional behavior, and `/run/secrets` target. No secret value enters the request, policy lock, LLB, cache key, environment, arguments, output config, or diagnostic. Logical secret IDs are also denied as non-secret argv/env/argument values.
- Copy nodes become native BuildKit `FileOp` copies with exact source state, destination, ownership, mode, and destination creation. No shell command implements copying.
- OCI outputs carry canonical entrypoint/cmd/ports/labels config bytes; static outputs carry canonical header metadata. Each output has its own deterministic LLB protobuf bytes, graph summary, head digest, raw LLB digest, and output-config digest.

The build-definition lock covers compiler version, Build IR digest, policy digest, source snapshot, target platform, normalized non-secret arguments, complete base materials, network capabilities, cache capabilities, secret references (never values), and output LLB/config digests. Its canonical sha256 digest is the build-definition digest. Worker identity, timestamps, queue position, provider request IDs, secret values, and mutable resolution are excluded.

## Boundaries

WP-037 does not execute BuildKit, materialize local session bytes, configure the egress gateway, fetch secret values, publish cache records, export OCI artifacts, scan images, generate SBOM/provenance, or sign evidence. WP-038 owns assignment verification, isolated solve execution, JIT capability realization, progress, cancellation, and cleanup. WP-039 owns registry publication. WP-040 owns supply-chain evidence and policy decisions over final artifacts.

The BuildKit protobuf is an internal pinned implementation contract, not a public LayerRail API. Build IR v1 and v2 remain unchanged by this decision. A BuildKit upgrade requires golden LLB replay review because official protobuf and capability behavior may legitimately alter raw LLB digests.

## Consequences

Equivalent normalized requests produce the same build-definition digest and byte-identical LLB definitions. Policy or material changes alter the lock digest even when the source graph does not. Tenant cache scope, secret references, network intent, and base evidence become auditable inputs before any customer code executes. Raw LLB graphs can be inspected in tests without a daemon, while real execution and isolation remain a later independently gated concern.

## Supersession

A replacement must retain immutable material locks, deny-by-default policy, tenant/trust cache namespacing, reference-only secrets, explicit network capabilities, official deterministic LLB protobuf output, canonical definition locking, no ambient I/O, and clear separation from solve execution and supply-chain publication.
