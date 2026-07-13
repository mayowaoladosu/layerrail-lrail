"""Detector orchestration, plugin isolation, and deterministic proposal resolution."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import cast

from lrail_detector.inventory import InventoryError, SnapshotInventory
from lrail_detector.models import (
    AddonEngine,
    AddonHint,
    DetectionResult,
    Diagnostic,
    DiagnosticSeverity,
    Evidence,
    EvidenceEdge,
    EvidenceGraph,
    EvidenceRelation,
    GeneratedManifest,
    ManifestAddon,
    ManifestBuild,
    ManifestProcess,
    ManifestProject,
    ManifestService,
    ServiceProposal,
)
from lrail_detector.plugins import DEFAULT_PLUGINS, DetectorPlugin
from lrail_detector.plugins.base import Candidate, DetectionContext, diagnostic
from lrail_detector.workspaces import WorkspaceIndex

MAX_SERVICE_PROPOSALS = 64
MAX_PLUGIN_CANDIDATES = 128
MAX_PLUGINS = 32
CONFIDENCE_MARGIN = 0.15
MIN_AUTO_CONFIDENCE = 0.75


class Detector:
    """Deep detector module: one immutable snapshot request to one complete proposal."""

    def __init__(
        self,
        *,
        plugins: tuple[DetectorPlugin, ...] = DEFAULT_PLUGINS,
        max_services: int = MAX_SERVICE_PROPOSALS,
    ) -> None:
        """Create a detector with a bounded private plugin set."""
        if not 1 <= max_services <= MAX_SERVICE_PROPOSALS:
            msg = "max_services must be between 1 and 64"
            raise ValueError(msg)
        if not plugins or len(plugins) > MAX_PLUGINS:
            msg = "detector requires between 1 and 32 plugins"
            raise ValueError(msg)
        descriptors = tuple(plugin.descriptor for plugin in plugins)
        names = tuple(item.plugin for item in descriptors)
        if len(set(names)) != len(names):
            msg = "detector plugin IDs must be unique"
            raise ValueError(msg)
        allowed_plugin_types = {type(plugin) for plugin in DEFAULT_PLUGINS}
        if any(type(plugin) not in allowed_plugin_types for plugin in plugins):
            msg = "detector plugins must be registered private lrail_detector adapters"
            raise ValueError(msg)
        self.max_services = max_services
        self.plugins = tuple(sorted(plugins, key=lambda plugin: plugin.descriptor.plugin))

    def detect(
        self,
        snapshot_root: Path,
        source_snapshot_id: str,
        selected_root: str = ".",
    ) -> DetectionResult:
        """Inspect bounded metadata and return a stable advisory proposal."""
        versions = tuple(plugin.descriptor for plugin in self.plugins)
        try:
            inventory = SnapshotInventory.build(snapshot_root, selected_root)
        except (InventoryError, OSError) as error:
            message = (
                str(error) if isinstance(error, InventoryError) else "snapshot inventory failed"
            )
            inventory_unresolved = (
                diagnostic(
                    "inventory.rejected",
                    message,
                    blocking=True,
                    root=_safe_root(selected_root),
                    detector="inventory",
                ),
            )
            return DetectionResult(
                source_snapshot_id=source_snapshot_id,
                snapshot_root=_safe_root(selected_root),
                plugins=versions,
                services=(),
                evidence_graph=EvidenceGraph(nodes=(), edges=()),
                warnings=(),
                unresolved=inventory_unresolved,
                unsupported_features=(),
                suggested_addons=(),
                files_considered=(),
                generated_manifest=None,
                blocked=True,
            )

        workspaces, workspace_warnings = WorkspaceIndex.discover(inventory)
        context = DetectionContext(inventory=inventory, workspaces=workspaces)
        all_candidates: list[Candidate] = []
        warnings: list[Diagnostic] = list(workspace_warnings)
        unresolved_diagnostics: list[Diagnostic] = []
        repository_configuration = tuple(
            record.path
            for record in inventory.records_named(
                "lrail.yaml",
                "lrail.yml",
                "Lrailfile.star",
            )
        )
        warnings.extend(
            (
                diagnostic(
                    "detector.repository-config-present",
                    "Repository configuration has higher precedence; detector output "
                    "fills only unaccepted initialization fields",
                    blocking=False,
                    path=path,
                    root=inventory.selected_root,
                    detector="resolver",
                )
            )
            for path in repository_configuration
        )
        for plugin in self.plugins:
            try:
                result = plugin.detect(context)
            except (InventoryError, OSError, RecursionError, TypeError, ValueError) as error:
                unresolved_diagnostics.append(
                    diagnostic(
                        "plugin.failed",
                        f"Plugin {plugin.descriptor.plugin} rejected bounded metadata "
                        f"({error.__class__.__name__})",
                        blocking=True,
                        root=inventory.selected_root,
                        detector=plugin.descriptor.plugin,
                    )
                )
                continue
            if len(result.candidates) > MAX_PLUGIN_CANDIDATES:
                unresolved_diagnostics.append(
                    diagnostic(
                        "plugin.candidate-limit",
                        f"Plugin {plugin.descriptor.plugin} exceeded "
                        f"{MAX_PLUGIN_CANDIDATES} candidates",
                        blocking=True,
                        root=inventory.selected_root,
                        detector=plugin.descriptor.plugin,
                    )
                )
                all_candidates.extend(result.candidates[:MAX_PLUGIN_CANDIDATES])
            else:
                all_candidates.extend(result.candidates)
            warnings.extend(result.warnings)
            unresolved_diagnostics.extend(result.unresolved)

        candidates = self._apply_overlays(
            all_candidates,
            warnings,
            unresolved_diagnostics,
        )
        selected, rejected = self._resolve_conflicts(
            candidates,
            warnings,
            unresolved_diagnostics,
        )
        if len(selected) > self.max_services:
            unresolved_diagnostics.append(
                diagnostic(
                    "detector.service-limit",
                    f"Detected {len(selected)} services; narrow the root below {self.max_services}",
                    blocking=True,
                    root=inventory.selected_root,
                    detector="resolver",
                )
            )
            selected = selected[: self.max_services]
        if len(selected) > 1:
            warnings.append(
                diagnostic(
                    "detector.monorepo",
                    f"Monorepo proposal contains {len(selected)} service roots",
                    blocking=False,
                    root=inventory.selected_root,
                    detector="resolver",
                )
            )

        services, root_to_name = self._to_services(selected, unresolved_diagnostics)
        services = self._order_services(services, unresolved_diagnostics)
        for candidate in selected:
            warnings.extend(candidate.warnings)
            unresolved_diagnostics.extend(candidate.unresolved)
        if not services:
            unresolved_diagnostics.append(
                diagnostic(
                    "detector.no-service",
                    "No supported service could be detected from bounded metadata",
                    blocking=True,
                    root=inventory.selected_root,
                    detector="resolver",
                )
            )

        evidence_graph = self._evidence_graph(
            all_candidates=all_candidates,
            selected=selected,
            rejected=rejected,
            root_to_name=root_to_name,
        )
        warnings = _dedupe_diagnostics(warnings, severity="warning")
        unresolved_values = _dedupe_diagnostics(
            unresolved_diagnostics,
            severity="blocking",
        )
        unsupported = tuple(
            sorted({feature for service in services for feature in service.unsupported_features})
        )
        addons = self._addon_hints(selected, root_to_name)
        files_considered = tuple(
            sorted(
                {
                    *inventory.files_read,
                    *repository_configuration,
                    *(path for candidate in all_candidates for path in candidate.files_considered),
                }
            )
        )
        blocked = bool(
            unresolved_values
            or not services
            or unsupported
            or any(service.ambiguous for service in services)
        )
        manifest = None if blocked else self._generated_manifest(services, selected, addons)
        return DetectionResult(
            source_snapshot_id=source_snapshot_id,
            snapshot_root=inventory.selected_root,
            plugins=versions,
            services=services,
            evidence_graph=evidence_graph,
            warnings=tuple(warnings),
            unresolved=tuple(unresolved_values),
            unsupported_features=unsupported,
            suggested_addons=addons,
            files_considered=files_considered,
            generated_manifest=manifest,
            blocked=blocked,
        )

    @staticmethod
    def _apply_overlays(
        candidates: list[Candidate],
        warnings: list[Diagnostic],
        unresolved: list[Diagnostic],
    ) -> list[Candidate]:
        overlays: dict[str, list[Candidate]] = {}
        normal: list[Candidate] = []
        for candidate in candidates:
            if candidate.overlay:
                overlays.setdefault(candidate.root, []).append(candidate)
            else:
                normal.append(candidate)
        result: list[Candidate] = []
        claimed: set[str] = set()
        for candidate in normal:
            roots = overlays.get(candidate.root, [])
            if not roots:
                result.append(candidate)
                continue
            if len(roots) > 1:
                unresolved.append(
                    diagnostic(
                        "docker.multiple-overlays",
                        f"Multiple Dockerfiles compete at service root {candidate.root}",
                        blocking=True,
                        root=candidate.root,
                        detector="resolver",
                    )
                )
                result.append(replace(candidate, ambiguous=True))
                continue
            docker = roots[0]
            claimed.add(candidate.root)
            warnings.extend(docker.warnings)
            unresolved.extend(docker.unresolved)
            result.append(
                replace(
                    candidate,
                    build=docker.build,
                    processes=docker.processes if not docker.ambiguous else candidate.processes,
                    evidence=(*candidate.evidence, *docker.evidence),
                    unsupported_features=tuple(
                        sorted({*candidate.unsupported_features, *docker.unsupported_features})
                    ),
                    files_considered=tuple(
                        sorted({*candidate.files_considered, *docker.files_considered})
                    ),
                    warnings=(*candidate.warnings, *docker.warnings),
                    unresolved=(*candidate.unresolved, *docker.unresolved),
                    ambiguous=candidate.ambiguous or docker.ambiguous,
                )
            )
        for root, root_overlays in overlays.items():
            if root not in claimed:
                result.extend(root_overlays)
        return result

    @staticmethod
    def _resolve_conflicts(
        candidates: list[Candidate],
        warnings: list[Diagnostic],
        unresolved: list[Diagnostic],
    ) -> tuple[list[Candidate], dict[str, tuple[Candidate, ...]]]:
        by_root: dict[str, list[Candidate]] = {}
        for candidate in candidates:
            by_root.setdefault(candidate.root, []).append(candidate)
        selected: list[Candidate] = []
        rejected: dict[str, tuple[Candidate, ...]] = {}
        for root in sorted(by_root):
            group = sorted(
                by_root[root],
                key=lambda item: (-item.confidence, item.framework, item.language),
            )
            if len(group) == 1:
                selected.append(group[0])
                continue
            primary, secondary = group[:2]
            rails_asset_node = primary.framework == "Rails" and secondary.framework in {
                "Astro",
                "Node.js",
                "Vite",
            }
            if rails_asset_node or primary.confidence - secondary.confidence >= CONFIDENCE_MARGIN:
                selected.append(
                    replace(
                        primary,
                        files_considered=tuple(
                            sorted({path for item in group for path in item.files_considered})
                        ),
                    )
                )
                rejected[root] = tuple(group[1:])
                warnings.append(
                    diagnostic(
                        "resolver.lower-confidence-candidate",
                        f"Selected {primary.framework} over "
                        + ", ".join(item.framework for item in group[1:]),
                        blocking=False,
                        root=root,
                        detector="resolver",
                    )
                )
                continue
            selected.append(replace(primary, ambiguous=True))
            rejected[root] = tuple(group[1:])
            unresolved.append(
                diagnostic(
                    "resolver.framework-conflict",
                    "Conflicting service candidates require confirmation: "
                    + ", ".join(item.framework for item in group),
                    blocking=True,
                    root=root,
                    detector="resolver",
                )
            )
        return selected, rejected

    @staticmethod
    def _to_services(
        candidates: list[Candidate],
        unresolved: list[Diagnostic],
    ) -> tuple[tuple[ServiceProposal, ...], dict[str, str]]:
        used_names: set[str] = set()
        named: list[tuple[Candidate, str]] = []
        for candidate in sorted(candidates, key=lambda item: (item.root, item.name)):
            name = candidate.name
            if name in used_names:
                suffix = candidate.root.replace("/", "-").replace(".", "root").strip("-")
                base = f"{name}-{suffix}"[:63].rstrip("-")
                name = base
                counter = 2
                while name in used_names:
                    tail = f"-{counter}"
                    name = f"{base[: 63 - len(tail)]}{tail}"
                    counter += 1
            used_names.add(name)
            named.append((candidate, name))
        root_to_name = {candidate.root: name for candidate, name in named}
        services: list[ServiceProposal] = []
        for candidate, name in named:
            ambiguous = candidate.ambiguous
            if candidate.confidence < MIN_AUTO_CONFIDENCE:
                ambiguous = True
                unresolved.append(
                    diagnostic(
                        "resolver.low-confidence",
                        f"{candidate.framework} confidence {candidate.confidence:.3f} is below "
                        f"the {MIN_AUTO_CONFIDENCE:.2f} automatic threshold",
                        blocking=True,
                        root=candidate.root,
                        detector="resolver",
                    )
                )
            dependencies = tuple(
                sorted(
                    root_to_name[root]
                    for root in candidate.dependency_roots
                    if root in root_to_name and root_to_name[root] != name
                )
            )
            services.append(
                ServiceProposal(
                    name=name,
                    root=candidate.root,
                    kind=candidate.kind,
                    language=candidate.language,
                    framework=candidate.framework,
                    runtime=candidate.runtime,
                    build=candidate.build,
                    processes=candidate.processes,
                    depends_on=dependencies,
                    confidence=candidate.confidence,
                    evidence_ids=tuple(sorted({item.id for item in candidate.evidence})),
                    unsupported_features=tuple(sorted(set(candidate.unsupported_features))),
                    files_considered=tuple(sorted(set(candidate.files_considered))),
                    ambiguous=ambiguous,
                )
            )
        return tuple(services), root_to_name

    @staticmethod
    def _evidence_graph(
        *,
        all_candidates: list[Candidate],
        selected: list[Candidate],
        rejected: dict[str, tuple[Candidate, ...]],
        root_to_name: dict[str, str],
    ) -> EvidenceGraph:
        nodes: dict[str, Evidence] = {}
        for candidate in all_candidates:
            for item in candidate.evidence:
                nodes[item.id] = item
        selected_by_root = {candidate.root: candidate for candidate in selected}
        edges: set[tuple[str, str, str]] = set()
        for root, candidate in selected_by_root.items():
            name = root_to_name.get(root)
            if not name:
                continue
            relation = "requires_confirmation" if candidate.ambiguous else "supports"
            edges.update((item.id, f"service:{name}", relation) for item in candidate.evidence)
            for rejected_candidate in rejected.get(root, ()):
                edges.update(
                    (item.id, f"service:{name}", "conflicts")
                    for item in rejected_candidate.evidence
                )
        return EvidenceGraph(
            nodes=tuple(nodes[key] for key in sorted(nodes)),
            edges=tuple(
                EvidenceEdge(
                    source=source,
                    target=target,
                    relation=cast("EvidenceRelation", relation),
                )
                for source, target, relation in sorted(
                    edges,
                    key=lambda item: (item[1], item[0], item[2]),
                )
            ),
        )

    @staticmethod
    def _order_services(
        services: tuple[ServiceProposal, ...],
        unresolved: list[Diagnostic],
    ) -> tuple[ServiceProposal, ...]:
        by_name = {service.name: service for service in services}
        remaining = {service.name: set(service.depends_on) for service in services}
        ordered: list[ServiceProposal] = []
        while remaining:
            ready = sorted(name for name, dependencies in remaining.items() if not dependencies)
            if not ready:
                cycle = ", ".join(sorted(remaining))
                unresolved.append(
                    diagnostic(
                        "workspace.dependency-cycle",
                        f"Detected service dependency cycle: {cycle}",
                        blocking=True,
                        root=".",
                        detector="resolver",
                    )
                )
                ordered.extend(by_name[name] for name in sorted(remaining))
                break
            for name in ready:
                ordered.append(by_name[name])
                del remaining[name]
            for dependencies in remaining.values():
                dependencies.difference_update(ready)
        return tuple(ordered)

    @staticmethod
    def _addon_hints(
        candidates: list[Candidate],
        root_to_name: dict[str, str],
    ) -> tuple[AddonHint, ...]:
        grouped: dict[AddonEngine, _AddonAccumulator] = {}
        for candidate in candidates:
            service = root_to_name.get(candidate.root)
            if not service:
                continue
            for addon in candidate.addons:
                value = grouped.setdefault(addon.engine, _AddonAccumulator())
                value.services.add(service)
                value.evidence.update(addon.evidence_ids)
                value.reasons.add(addon.reason)
                value.required = value.required or addon.required
        names = {"postgresql": "postgres", "rabbitmq": "rabbitmq"}
        return tuple(
            AddonHint(
                name=names.get(engine, engine),
                engine=engine,
                services=tuple(sorted(value.services)),
                required=value.required,
                reason="; ".join(sorted(value.reasons)),
                evidence_ids=tuple(sorted(value.evidence)),
            )
            for engine, value in sorted(grouped.items())
        )

    @staticmethod
    def _generated_manifest(
        services: tuple[ServiceProposal, ...],
        candidates: list[Candidate],
        addons: tuple[AddonHint, ...],
    ) -> GeneratedManifest:
        candidates_by_root = {candidate.root: candidate for candidate in candidates}
        manifest_services = []
        for service in services:
            candidate = candidates_by_root[service.root]
            dockerfile = next(
                (
                    path
                    for path in candidate.build.required_files
                    if PurePosixPath(path).name.casefold().startswith("dockerfile")
                ),
                None,
            )
            processes = tuple(
                ManifestProcess(
                    name=process.name,
                    kind=process.kind,
                    command=process.command or ("lrail-static",),
                    port=process.port,
                    health_path=process.health_path,
                )
                for process in service.processes
            )
            manifest_services.append(
                ManifestService(
                    name=service.name,
                    root=service.root,
                    build=ManifestBuild(
                        method=service.build.strategy,
                        network=(
                            "packages"
                            if service.build.install_command or service.build.build_command
                            else "none"
                        ),
                        dockerfile=dockerfile if service.build.strategy == "dockerfile" else None,
                    ),
                    processes=processes,
                )
            )
        project_name = services[0].name if len(services) == 1 else "project"
        return GeneratedManifest(
            project=ManifestProject(name=project_name),
            services=tuple(manifest_services),
            addons=tuple(ManifestAddon(name=addon.name, engine=addon.engine) for addon in addons),
        )


def detect(
    snapshot_root: Path,
    source_snapshot_id: str,
    selected_root: str = ".",
) -> DetectionResult:
    """Run one detector with default plugins and safety limits."""
    return Detector().detect(snapshot_root, source_snapshot_id, selected_root)


def _safe_root(value: str) -> str:
    if not value or value.startswith("/") or "\\" in value or ".." in PurePosixPath(value).parts:
        return "."
    normalized = str(PurePosixPath(value))
    return normalized if normalized and normalized != "/" else "."


def _diagnostic_key(value: Diagnostic) -> tuple[str, str, str, str, str]:
    return (
        value.code,
        value.service_root or "",
        value.path or "",
        value.detector or "",
        value.message,
    )


def _dedupe_diagnostics(
    values: list[Diagnostic],
    *,
    severity: DiagnosticSeverity,
) -> list[Diagnostic]:
    unique = {_diagnostic_key(value): value for value in values if value.severity == severity}
    return [unique[key] for key in sorted(unique)]


@dataclass(slots=True)
class _AddonAccumulator:
    services: set[str] = field(default_factory=set)
    evidence: set[str] = field(default_factory=set)
    reasons: set[str] = field(default_factory=set)
    required: bool = False
