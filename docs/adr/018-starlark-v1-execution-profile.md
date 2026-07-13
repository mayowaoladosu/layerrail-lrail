# ADR-018: Starlark v1 bounded module and execution profile

- **Status:** Accepted
- **Date:** 2026-07-13
- **Supersedes:** The initial no-module restriction in ADR-005

## Context

ADR-005 selected an owned Starlark interface that emits typed Build IR, but its initial contract disabled module loading and specified only source-byte and execution-step limits. WP-036 requires reusable repository and standard modules without turning the evaluator into a filesystem, network, process, environment, time, randomness, or secret-value capability. A finite step count alone does not bound parser work, call stacks, result size, one-operation collection amplification, or module initialization behavior.

## Decision

The external compiler interface accepts one immutable in-memory request: a canonical repository-relative entry filename, UTF-8 source bytes, and repository modules identified by canonical path, exact bytes, and a verified sha256 digest. The compiler never opens a path or asks a caller-supplied I/O adapter to resolve a load.

Repository loads use `//approved/root/module.star` names and are accepted only beneath roots fixed in compiler policy. Owned standard loads use versioned names such as `@lrail/v1/helpers.star`; their source ships with the compiler. Relative names, URLs, absolute paths, drive paths, backslashes, traversal, missing modules, digest substitution, duplicate module paths, cycles, excessive depth, and excessive total module count fail closed. A per-request deterministic cache evaluates each module once. Module globals are frozen, and module initialization may define helpers but may not emit Build IR; helper invocations from the entry file may call owned built-ins.

Evaluation uses an immutable compiler and isolated per-request state. The entry file and every loaded module share one Starlark thread, execution-step counter, call-depth monitor, cancellation state, and aggregate source/AST budgets. Context cancellation covers user cancellation, request deadlines, worker drain, and platform wall timeout. The thread is checked at every abstract instruction. Source bytes, AST nodes, execution steps, call depth, result nodes, outputs, module count/depth, string bytes, collection items, and wall duration all have hard ceilings that callers may lower but never raise.

The v1 syntax profile permits bounded literals, immutable bindings, named helper functions, conditionals, indexing, comparisons, and boolean logic. It rejects loops, comprehensions, lambdas, mutable method/attribute access, slices, augmented/index assignment, byte literals, variadic expansion, collection constructors, printing, and potentially amplifying arithmetic or collection operators. Recursion and global reassignment remain disabled by Starlark file options. This deliberately narrow profile makes string/list limits enforceable without exposing an allocator hook that Starlark does not provide.

Owned built-ins accept named arguments only and return immutable typed references:

- `source(path, include, exclude)` selects bounded snapshot paths.
- `image(ref)` requires a digest-pinned lowercase OCI reference.
- `run(base, argv, env, mounts, network, user, workdir)` emits an argv-based step.
- `shell(command)` is the only explicit shell interpretation wrapper.
- `copy(base, src, dest, owner, mode)` emits a validated copy step.
- `cache(name, target, sharing)` and `secret(name, target, required)` declare capabilities; no secret value enters Starlark or Build IR.
- `artifact(name, state, entrypoint, cmd, ports, labels)` and `static_site(name, source_dir, headers)` declare sorted unique outputs.

Build IR v1 remains published unchanged. The compiler emits separately versioned Build IR v2 with `ir_version`, `dsl_api_version`, compiler version, immutable source snapshot, target/network assignment, sorted loaded-module name/kind/digest evidence, sequential typed nodes, and sorted outputs. Every operation has an exact attribute shape and legal reference kinds. The canonical definition digest covers all v2 fields, including DSL/compiler/module identity, but never secret values, host identity, time, queue state, or provider request IDs.

Failures return one structured diagnostic with a stable code, severity, repository-relative file, one-based line/column, rule name, safe hint, and bounded call stack. Exported messages intentionally omit raw source text, host paths, and argument values.

## Boundaries

This decision does not resolve mutable image tags, apply organization build policy, or compile Build IR to BuildKit LLB. Those are WP-037 concerns. It does not materialize snapshots; the source plane supplies already verified bytes and digests. It does not make a hard in-process memory quota claim; instead the syntax profile removes known single-operation amplification and combines bounded source/AST/value/result sizes with disposable build-plane process isolation.

## Consequences

Equivalent locked inputs produce byte-equivalent canonical Build IR and a replay-locked digest. Repository helpers are reusable without ambient I/O, while standard helpers evolve only under an explicit versioned name. Some general Starlark constructs are intentionally unavailable; widening the profile requires an allocator/termination analysis, threat review, contract version decision, adversarial corpus, and deterministic golden replay.

## Supersession

A replacement must preserve in-memory-only module resolution, exact module identity, cycle and traversal rejection, shared cancellation and limits, non-amplifying syntax, immutable typed built-ins, no secret values, separately versioned IR, deterministic golden replay, and safe structured diagnostics.
