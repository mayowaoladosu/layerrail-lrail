"""Strict internal detector plugin seam and immutable candidate records."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from lrail_detector.models import (
    AddonEngine,
    BuildProposal,
    Diagnostic,
    Evidence,
    Language,
    PluginVersion,
    ProcessProposal,
    RuntimeProposal,
    ServiceKind,
)

if TYPE_CHECKING:
    from lrail_detector.inventory import SnapshotInventory
    from lrail_detector.workspaces import WorkspaceIndex


@dataclass(frozen=True, slots=True)
class DetectionContext:
    """Only capabilities available to private detector plugins."""

    inventory: SnapshotInventory
    workspaces: WorkspaceIndex


@dataclass(frozen=True, slots=True)
class AddonRequest:
    """Internal evidence-backed managed data suggestion."""

    engine: AddonEngine
    reason: str
    evidence_ids: tuple[str, ...]
    required: bool = False


@dataclass(frozen=True, slots=True)
class Candidate:
    """One plugin proposal before global conflict and name resolution."""

    name: str
    root: str
    kind: ServiceKind
    language: Language
    framework: str
    runtime: RuntimeProposal
    build: BuildProposal
    processes: tuple[ProcessProposal, ...]
    evidence: tuple[Evidence, ...]
    unsupported_features: tuple[str, ...]
    files_considered: tuple[str, ...]
    dependency_roots: tuple[str, ...] = ()
    addons: tuple[AddonRequest, ...] = ()
    warnings: tuple[Diagnostic, ...] = ()
    unresolved: tuple[Diagnostic, ...] = ()
    ambiguous: bool = False
    overlay: bool = False

    @property
    def confidence(self) -> float:
        """Derive confidence only from declared evidence contributions."""
        value = 0.5 + sum(item.confidence_delta for item in self.evidence)
        return round(max(0.0, min(1.0, value)), 3)


@dataclass(frozen=True, slots=True)
class PluginResult:
    """Bounded immutable output from one detector plugin."""

    candidates: tuple[Candidate, ...] = ()
    warnings: tuple[Diagnostic, ...] = ()
    unresolved: tuple[Diagnostic, ...] = ()


class DetectorPlugin(Protocol):
    """Private typed plugin interface; implementations receive no filesystem path."""

    descriptor: PluginVersion

    def detect(self, context: DetectionContext) -> PluginResult:
        """Return facts and candidates using only bounded context capabilities."""
        ...


def evidence(
    detector: str,
    fact: str,
    path: str,
    detail: str,
    confidence_delta: float,
) -> Evidence:
    """Create a content-addressed stable evidence node."""
    canonical = "\x00".join((detector, fact, path, detail, f"{confidence_delta:.6f}")).encode()
    identifier = f"ev_{hashlib.sha256(canonical).hexdigest()[:20]}"
    return Evidence(
        id=identifier,
        detector=detector,
        fact=fact,
        path=path,
        detail=detail,
        confidence_delta=confidence_delta,
    )


def diagnostic(
    code: str,
    message: str,
    *,
    blocking: bool,
    path: str | None = None,
    root: str | None = None,
    detector: str | None = None,
) -> Diagnostic:
    """Create one stable warning or unresolved decision."""
    return Diagnostic(
        code=code,
        severity="blocking" if blocking else "warning",
        message=message,
        path=path,
        service_root=root,
        detector=detector,
    )
