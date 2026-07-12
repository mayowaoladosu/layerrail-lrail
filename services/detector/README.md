# Lrail detector

The detector reads a validated, immutable source snapshot and emits an explainable service proposal. It never imports, builds, executes, or shells into customer code and has no network client.

## Contract

Input:

- an immutable snapshot directory;
- an optional repository-relative root;
- fixed inventory and metadata byte limits.

Output:

- service roots, language and framework candidates;
- build method, install/build/start suggestions, ports, and health paths;
- evidence with exact files and bounded details;
- every file considered, unsupported features, warnings, and an ambiguity block.

A high confidence score is not permission to deploy. Ambiguous start commands, overlapping service roots, malformed manifests, or conflicting ecosystems require explicit user confirmation.

## Development

Run `uv sync --frozen`, then `uv run pytest`, `uv run ruff check .`, and `uv run mypy src`.
