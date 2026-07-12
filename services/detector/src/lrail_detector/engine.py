"""Detector orchestration and deterministic conflict resolution."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from lrail_detector.inventory import InventoryError, SnapshotInventory
from lrail_detector.models import DetectionResult, ServiceProposal
from lrail_detector.rules import (
    Candidate,
    apply_docker_overrides,
    detect_docker,
    detect_go,
    detect_node,
    detect_python,
    detect_ruby,
    detect_static,
)

if TYPE_CHECKING:
    from pathlib import Path

MAX_SERVICE_PROPOSALS = 64
CONFIDENCE_MARGIN = 0.15


class Detector:
    """Run static rules over one immutable snapshot."""

    def __init__(self, *, max_services: int = MAX_SERVICE_PROPOSALS) -> None:
        """Create a detector with a bounded result cardinality."""
        if not 1 <= max_services <= MAX_SERVICE_PROPOSALS:
            msg = "max_services must be between 1 and 64"
            raise ValueError(msg)
        self.max_services = max_services

    def detect(self, snapshot_root: Path, selected_root: str = ".") -> DetectionResult:
        """Return a stable proposal without executing or importing source."""
        try:
            inventory = SnapshotInventory.build(snapshot_root, selected_root)
        except (InventoryError, OSError) as error:
            return DetectionResult(
                snapshot_root=selected_root,
                services=(),
                warnings=(str(error),),
                blocked=True,
            )

        warnings: list[str] = []
        candidates = [
            *detect_ruby(inventory, warnings),
            *detect_node(inventory, warnings),
            *detect_python(inventory, warnings),
            *detect_go(inventory, warnings),
            *detect_static(inventory),
            *detect_docker(inventory, warnings),
        ]
        candidates = apply_docker_overrides(candidates)
        selected, conflict = self._resolve_conflicts(candidates, warnings)
        if len(selected) > self.max_services:
            warnings.append(
                f"detected {len(selected)} services; maximum is {self.max_services}; "
                "narrow the root"
            )
            selected = selected[: self.max_services]
            conflict = True
        if len(selected) > 1:
            warnings.append(f"monorepo proposal contains {len(selected)} service roots")

        services = self._to_proposals(selected)
        blocked = conflict or not services or any(service.ambiguous for service in services)
        if not services:
            warnings.append("no supported service could be detected from bounded metadata")
        return DetectionResult(
            snapshot_root=inventory.selected_root,
            services=services,
            warnings=tuple(dict.fromkeys(warnings)),
            blocked=blocked,
        )

    @staticmethod
    def _resolve_conflicts(
        candidates: list[Candidate], warnings: list[str]
    ) -> tuple[list[Candidate], bool]:
        by_root: dict[str, list[Candidate]] = {}
        for candidate in candidates:
            by_root.setdefault(candidate.root, []).append(candidate)
        selected: list[Candidate] = []
        conflict = False
        for root in sorted(by_root):
            group = sorted(by_root[root], key=lambda item: (-item.confidence, item.framework))
            if len(group) == 1:
                selected.append(group[0])
                continue
            primary = group[0]
            secondary = group[1]
            rails_with_asset_node = primary.framework == "Rails" and secondary.framework in {
                "Node.js",
                "Vite",
            }
            if (
                rails_with_asset_node
                or primary.confidence - secondary.confidence >= CONFIDENCE_MARGIN
            ):
                merged_files = tuple(
                    sorted({path for candidate in group for path in candidate.files_considered})
                )
                selected.append(replace(primary, files_considered=merged_files))
                warnings.append(
                    f"selected {primary.framework} at {root} over lower-confidence "
                    f"{', '.join(item.framework for item in group[1:])}"
                )
                continue
            conflict = True
            frameworks = ", ".join(item.framework for item in group)
            warnings.append(f"conflicting service candidates at {root}: {frameworks}")
            merged_evidence = tuple(item for candidate in group for item in candidate.evidence)
            merged_files = tuple(
                sorted({path for candidate in group for path in candidate.files_considered})
            )
            selected.append(
                replace(
                    primary,
                    evidence=merged_evidence,
                    files_considered=merged_files,
                    ambiguous=True,
                )
            )
        return selected, conflict

    @staticmethod
    def _to_proposals(candidates: list[Candidate]) -> tuple[ServiceProposal, ...]:
        proposals: list[ServiceProposal] = []
        used_names: set[str] = set()
        for candidate in sorted(candidates, key=lambda item: (item.root, item.name)):
            name = candidate.name
            if name in used_names:
                suffix = str(candidate.root).replace("/", "-").replace(".", "root").strip("-")
                base = f"{name}-{suffix}"[:63].rstrip("-")
                name = base
                counter = 2
                while name in used_names:
                    tail = f"-{counter}"
                    name = f"{base[: 63 - len(tail)]}{tail}"
                    counter += 1
            used_names.add(name)
            proposals.append(
                ServiceProposal(
                    name=name,
                    root=candidate.root,
                    language=candidate.language,
                    framework=candidate.framework,
                    build_method=candidate.build_method,
                    install_command=candidate.install_command,
                    build_command=candidate.build_command,
                    processes=candidate.processes,
                    confidence=candidate.confidence,
                    evidence=candidate.evidence,
                    unsupported_features=candidate.unsupported_features,
                    files_considered=candidate.files_considered,
                    ambiguous=candidate.ambiguous,
                )
            )
        return tuple(proposals)


def detect(snapshot_root: Path, selected_root: str = ".") -> DetectionResult:
    """Run one detector with default safety limits."""
    return Detector().detect(snapshot_root, selected_root)
