# Lrail detector

The detector is a deterministic Python library and machine-readable command. Its deep interface accepts one validated immutable snapshot directory, one `snp_` identity, and one optional repository-relative root; it returns one complete advisory proposal. It never imports, builds, executes, or shells into customer code and has no network capability.

## Plugin seam

Ruby, Node/TypeScript, Python, Go, static, and Docker detection are private adapters behind `DetectorPlugin`. Plugins receive only `DetectionContext`: a bounded `SnapshotInventory` and immutable `WorkspaceIndex`. They never receive a raw filesystem root. The built-in modules are statically checked to reject process, network, dynamic-import, and direct-file capabilities.

Inventory records canonical paths, sizes, executable bits, and selected UTF-8 source headers. It skips dependency/build/VCS directories and symlinks, rejects case collisions and traversal, and enforces file, depth, per-file, header, and aggregate read limits. All metadata reads are cached and reported exactly.

## Versioned v2 contract

Every result records:

- proposal, detector, ruleset, and plugin versions;
- the immutable source snapshot ID and selected root;
- service kind, root, language/framework, runtime version, build strategy, frozen install/build argv, output/cache/required paths, process argv/port/protocol/health, and workspace dependencies;
- a content-addressed evidence graph where confidence is exactly `clamp(0.5 + Σ confidence_delta)`;
- structured warnings and blocking unresolved decisions;
- unsupported features, evidence-backed add-on hints, and every file considered;
- a nullable-free generated `lrail.dev/v1` manifest only when the proposal is unblocked.

The published v1 schema remains immutable. New output uses `detector.lrail.dev/v2` and the separately versioned v2 schema.

Explicit Dockerfiles overlay framework detection at the same root. Close framework conflicts, conflicting lockfiles, missing production commands/ports, unsafe Procfiles, unknown adapters, build tags, and low confidence block one-click deployment. Multiple independent roots are ordered deterministically; workspace package dependencies become service dependencies when both roots produce services.

## Development

Run `uv sync --frozen`, then `uv run pytest`, `uv run ruff check .`, and `uv run mypy src`. The fixture corpus covers real Ruby, Node monorepo, Python ASGI, Go multi-process, static, Docker, and adversarial repositories. Coverage must remain at least 90%.
