"""Plain and configured static publication detector plugin."""

from __future__ import annotations

from lrail_detector.models import BuildProposal, PluginVersion, ProcessProposal, RuntimeProposal
from lrail_detector.plugins.base import (
    Candidate,
    DetectionContext,
    PluginResult,
    diagnostic,
    evidence,
)
from lrail_detector.plugins.helpers import join, root_name

_STRONG_MANIFESTS = ("Gemfile", "go.mod", "package.json", "pyproject.toml", "requirements.txt")


class StaticPlugin:
    """Detect immutable static roots with no stronger runtime manifest."""

    descriptor = PluginVersion(plugin="static", version="1.0.0")

    def detect(self, context: DetectionContext) -> PluginResult:
        """Return static publication roots without reading page content."""
        candidates = []
        for record in context.inventory.records_named("index.html"):
            root = record.parent
            if any(context.inventory.contains(join(root, name)) for name in _STRONG_MANIFESTS):
                continue
            evidence_nodes = [
                evidence(
                    "static",
                    "static.html-entrypoint",
                    record.path,
                    "index.html identifies an immutable static publication root",
                    0.38,
                )
            ]
            files = {record.path}
            required = {record.path}
            unresolved = []
            for name in ("netlify.toml", "vercel.json"):
                path = join(root, name)
                if not context.inventory.contains(path):
                    continue
                try:
                    context.inventory.read_text(path)
                except ValueError as error:
                    unresolved.append(
                        diagnostic(
                            "static.unreadable-publication-config",
                            str(error),
                            blocking=True,
                            path=path,
                            root=root,
                            detector="static",
                        )
                    )
                else:
                    files.add(path)
                    required.add(path)
                    evidence_nodes.append(
                        evidence(
                            "static",
                            "static.publication-config",
                            path,
                            f"{name} declares generated static publication intent",
                            0.02,
                        )
                    )
            candidates.append(
                Candidate(
                    name=root_name(root),
                    root=root,
                    kind="static",
                    language="static",
                    framework="Static HTML",
                    runtime=RuntimeProposal(name="static"),
                    build=BuildProposal(
                        strategy="auto",
                        install_command=(),
                        build_command=(),
                        output_path=root,
                        cache_paths=(),
                        required_files=tuple(sorted(required)),
                    ),
                    processes=(
                        ProcessProposal(
                            name="web",
                            kind="static",
                            command=(),
                            protocol="none",
                        ),
                    ),
                    evidence=tuple(evidence_nodes),
                    unsupported_features=(),
                    files_considered=tuple(sorted(files)),
                    unresolved=tuple(unresolved),
                    ambiguous=bool(unresolved),
                )
            )
        return PluginResult(candidates=tuple(candidates))
