"""Strict versioned detector proposal and evidence contracts."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_serializer,
    model_validator,
)

SCHEMA_VERSION: Literal["detector.lrail.dev/v2"] = "detector.lrail.dev/v2"
PROPOSAL_VERSION: Literal[1] = 1
DETECTOR_VERSION: Literal["0.2.0"] = "0.2.0"
RULESET_VERSION: Literal["2026-07-13.1"] = "2026-07-13.1"
MAX_ARGUMENT_BYTES = 4096
ASCII_CONTROL_LIMIT = 32
ASCII_DELETE = 127

Language = Literal["ruby", "node", "python", "go", "static", "docker"]
BuildMethod = Literal["auto", "dockerfile", "starlark"]
ServiceKind = Literal["web", "worker", "private_service", "static"]
ProcessKind = Literal["web", "worker", "private_service", "release", "job", "static"]
Protocol = Literal["http", "tcp", "none"]
DiagnosticSeverity = Literal["warning", "blocking"]
EvidenceRelation = Literal["supports", "conflicts", "requires_confirmation"]
AddonEngine = Literal[
    "postgresql",
    "mysql",
    "mariadb",
    "valkey",
    "mongodb",
    "opensearch",
    "clickhouse",
    "rabbitmq",
]

Name = Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,62}$")]
ResourceID = Annotated[
    str,
    Field(
        pattern=(
            r"^[a-z]{2,5}_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        )
    ),
]
EvidenceID = Annotated[str, Field(pattern=r"^ev_[0-9a-f]{20}$")]


def canonical_relative_path(value: str, *, allow_dot: bool = True) -> str:
    """Validate one canonical repository-relative POSIX path."""
    if not value or "\x00" in value or "\\" in value:
        msg = "path must be a non-empty repository-relative POSIX path"
        raise ValueError(msg)
    if value == "." and allow_dot:
        return value
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        msg = "path must be canonical and cannot traverse parents"
        raise ValueError(msg)
    if str(candidate) != value:
        msg = "path must be canonical"
        raise ValueError(msg)
    return value


def sorted_unique(values: tuple[str, ...], field: str) -> tuple[str, ...]:
    """Require stable deduplicated string tuples at contract edges."""
    if tuple(sorted(set(values))) != values:
        msg = f"{field} must be sorted and unique"
        raise ValueError(msg)
    return values


class FrozenModel(BaseModel):
    """Strict immutable contract base."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class PluginVersion(FrozenModel):
    """Exact private detector plugin and ruleset identity."""

    plugin: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,63}$")
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$", max_length=32)


class Evidence(FrozenModel):
    """One immutable confidence contribution in the evidence graph."""

    id: EvidenceID
    detector: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,63}$")
    fact: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,127}$")
    path: str = Field(max_length=1024)
    detail: str = Field(min_length=1, max_length=512)
    confidence_delta: float = Field(ge=-0.5, le=0.5)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        """Keep evidence attached to one canonical snapshot path."""
        return canonical_relative_path(value)


class EvidenceEdge(FrozenModel):
    """A typed relation from evidence to a proposed service."""

    source: EvidenceID
    target: str = Field(pattern=r"^service:[a-z][a-z0-9-]{0,62}$")
    relation: EvidenceRelation


class EvidenceGraph(FrozenModel):
    """Deterministic graph explaining every service confidence score."""

    nodes: tuple[Evidence, ...] = Field(max_length=1024)
    edges: tuple[EvidenceEdge, ...] = Field(max_length=4096)

    @model_validator(mode="after")
    def validate_graph(self) -> EvidenceGraph:
        """Reject dangling, duplicate, or non-canonical graph records."""
        node_ids = tuple(node.id for node in self.nodes)
        if tuple(sorted(node_ids)) != node_ids or len(set(node_ids)) != len(node_ids):
            msg = "evidence graph nodes must be sorted and unique"
            raise ValueError(msg)
        expected_edges = tuple(
            sorted(self.edges, key=lambda item: (item.target, item.source, item.relation))
        )
        if expected_edges != self.edges:
            msg = "evidence graph edges must be sorted"
            raise ValueError(msg)
        known = set(node_ids)
        if any(edge.source not in known for edge in self.edges):
            msg = "evidence graph contains a dangling source"
            raise ValueError(msg)
        return self


class Diagnostic(FrozenModel):
    """Stable warning or unresolved decision requiring confirmation."""

    code: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,127}$")
    severity: DiagnosticSeverity
    message: str = Field(min_length=1, max_length=512)
    path: str | None = Field(default=None, max_length=1024)
    service_root: str | None = Field(default=None, max_length=1024)
    detector: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_.-]{1,63}$")

    @field_validator("path", "service_root")
    @classmethod
    def validate_optional_path(cls, value: str | None) -> str | None:
        """Validate diagnostic paths when present."""
        return canonical_relative_path(value) if value is not None else value


class RuntimeProposal(FrozenModel):
    """Language runtime inferred from declared repository metadata."""

    name: Language
    version: str | None = Field(default=None, min_length=1, max_length=64)
    version_source: str | None = Field(default=None, max_length=1024)

    @field_validator("version_source")
    @classmethod
    def validate_version_source(cls, value: str | None) -> str | None:
        """Attach runtime versions to a canonical metadata path."""
        return canonical_relative_path(value) if value is not None else value


class BuildProposal(FrozenModel):
    """Non-executed build recommendation and its required inputs."""

    strategy: BuildMethod
    install_command: tuple[str, ...] = Field(max_length=64)
    build_command: tuple[str, ...] = Field(max_length=64)
    output_path: str | None = Field(default=None, max_length=1024)
    cache_paths: tuple[str, ...] = Field(max_length=64)
    required_files: tuple[str, ...] = Field(min_length=1, max_length=256)

    @field_validator("output_path")
    @classmethod
    def validate_output_path(cls, value: str | None) -> str | None:
        """Keep build output inside the service root."""
        return canonical_relative_path(value) if value is not None else value

    @field_validator("cache_paths", "required_files")
    @classmethod
    def validate_paths(cls, value: tuple[str, ...], info: object) -> tuple[str, ...]:
        """Require canonical sorted build path lists."""
        field = getattr(info, "field_name", "paths")
        checked = tuple(canonical_relative_path(item) for item in value)
        return sorted_unique(checked, field)

    @field_validator("install_command", "build_command")
    @classmethod
    def validate_commands(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Bound suggested argv without interpreting it as a shell string."""
        if any(
            not item or len(item) > MAX_ARGUMENT_BYTES or _contains_control_character(item)
            for item in value
        ):
            msg = "command arguments must be non-empty and bounded"
            raise ValueError(msg)
        return value


class ProcessProposal(FrozenModel):
    """One process group inferred without executing source."""

    name: Name
    kind: ProcessKind
    command: tuple[str, ...] = Field(max_length=64)
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: Protocol = "none"
    health_path: str | None = Field(default=None, pattern=r"^/", max_length=512)

    @field_validator("command")
    @classmethod
    def validate_command(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Reject control characters and unbounded argv entries."""
        if any(
            not item or len(item) > MAX_ARGUMENT_BYTES or _contains_control_character(item)
            for item in value
        ):
            msg = "process command arguments must be non-empty and bounded"
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def validate_process(self) -> ProcessProposal:
        """Require explicit network metadata and executable commands when relevant."""
        if self.kind in {"web", "private_service"} and self.port is None:
            msg = f"{self.kind} process requires a port"
            raise ValueError(msg)
        if self.port is not None and self.protocol == "none":
            msg = "a network port requires an explicit protocol"
            raise ValueError(msg)
        if self.kind != "static" and not self.command:
            msg = f"{self.kind} process requires a command"
            raise ValueError(msg)
        return self


class ServiceProposal(FrozenModel):
    """Explainable build and runtime proposal for one service root."""

    name: Name
    root: str = Field(max_length=1024)
    kind: ServiceKind
    language: Language
    framework: str = Field(min_length=1, max_length=64)
    runtime: RuntimeProposal
    build: BuildProposal
    processes: tuple[ProcessProposal, ...] = Field(min_length=1, max_length=32)
    depends_on: tuple[Name, ...] = Field(max_length=64)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: tuple[EvidenceID, ...] = Field(min_length=1, max_length=128)
    unsupported_features: tuple[str, ...] = Field(max_length=64)
    files_considered: tuple[str, ...] = Field(min_length=1, max_length=512)
    ambiguous: bool

    @field_validator("root")
    @classmethod
    def validate_root(cls, value: str) -> str:
        """Require a canonical service root."""
        return canonical_relative_path(value)

    @field_validator("depends_on", "evidence_ids", "unsupported_features")
    @classmethod
    def validate_sorted_values(cls, value: tuple[str, ...], info: object) -> tuple[str, ...]:
        """Require stable unique references."""
        return sorted_unique(value, getattr(info, "field_name", "values"))

    @field_validator("files_considered")
    @classmethod
    def validate_files(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Require exact canonical sorted metadata paths."""
        checked = tuple(canonical_relative_path(item) for item in value)
        return sorted_unique(checked, "files_considered")


class AddonHint(FrozenModel):
    """Evidence-backed managed data suggestion, never an automatic provision."""

    name: Name
    engine: AddonEngine
    services: tuple[Name, ...] = Field(min_length=1, max_length=64)
    required: bool = False
    reason: str = Field(min_length=1, max_length=512)
    evidence_ids: tuple[EvidenceID, ...] = Field(min_length=1, max_length=128)

    @field_validator("services", "evidence_ids")
    @classmethod
    def validate_refs(cls, value: tuple[str, ...], info: object) -> tuple[str, ...]:
        """Keep add-on references deterministic."""
        return sorted_unique(value, getattr(info, "field_name", "references"))


class ManifestResources(FrozenModel):
    """Conservative initialization resource profile."""

    profile: Literal["nano", "small", "medium", "large", "xlarge"] = "nano"


class ManifestProcess(FrozenModel):
    """Process subset compatible with the lrail.yaml v1 schema."""

    name: Name
    kind: ProcessKind
    command: tuple[str, ...] = Field(min_length=1, max_length=64)
    resources: ManifestResources = ManifestResources()
    port: int | None = Field(default=None, ge=1, le=65535)
    health_path: str | None = Field(default=None, pattern=r"^/", max_length=512)
    runtime_class: Literal["sandbox", "microvm", "native"] = "sandbox"


class ManifestBuild(FrozenModel):
    """Build subset compatible with the lrail.yaml v1 schema."""

    method: BuildMethod
    network: Literal["none", "packages", "allowlist", "private"] = "packages"
    dockerfile: str | None = None
    starlark: str | None = None

    @field_validator("dockerfile", "starlark")
    @classmethod
    def validate_build_file(cls, value: str | None) -> str | None:
        """Keep explicit build files inside the snapshot."""
        return canonical_relative_path(value) if value is not None else value


class ManifestService(FrozenModel):
    """Generated service initialization proposal."""

    name: Name
    root: str
    build: ManifestBuild
    processes: tuple[ManifestProcess, ...] = Field(min_length=1, max_length=32)

    @field_validator("root")
    @classmethod
    def validate_root(cls, value: str) -> str:
        """Require a canonical generated service root."""
        return canonical_relative_path(value)


class ManifestProject(FrozenModel):
    """Generated project identity proposal."""

    name: Name


class ManifestAddon(FrozenModel):
    """Generated add-on proposal compatible with lrail.yaml v1."""

    name: Name
    engine: AddonEngine
    plan: Name = "nano"
    deletion_protection: bool = True


class GeneratedManifest(FrozenModel):
    """Strict deploy-blocked-until-accepted lrail.yaml proposal."""

    api_version: Literal["lrail.dev/v1"] = "lrail.dev/v1"
    project: ManifestProject
    services: tuple[ManifestService, ...] = Field(min_length=1, max_length=64)
    addons: tuple[ManifestAddon, ...] = Field(max_length=64)
    schedules: tuple[object, ...] = Field(default=(), max_length=0)

    @model_serializer
    def serialize_manifest(self) -> dict[str, object]:
        """Emit exactly the nullable-free lrail.yaml v1 subset."""
        return {
            "api_version": self.api_version,
            "project": self.project.model_dump(mode="json", exclude_none=True),
            "services": [
                service.model_dump(mode="json", exclude_none=True) for service in self.services
            ],
            "addons": [addon.model_dump(mode="json", exclude_none=True) for addon in self.addons],
            "schedules": [],
        }


class DetectionResult(FrozenModel):
    """Top-level stable detector v2 response."""

    schema_version: Literal["detector.lrail.dev/v2"] = SCHEMA_VERSION
    proposal_version: Literal[1] = PROPOSAL_VERSION
    detector_version: Literal["0.2.0"] = DETECTOR_VERSION
    ruleset_version: Literal["2026-07-13.1"] = RULESET_VERSION
    source_snapshot_id: ResourceID
    snapshot_root: str = Field(max_length=1024)
    plugins: tuple[PluginVersion, ...] = Field(min_length=1, max_length=32)
    services: tuple[ServiceProposal, ...] = Field(max_length=64)
    evidence_graph: EvidenceGraph
    warnings: tuple[Diagnostic, ...] = Field(max_length=256)
    unresolved: tuple[Diagnostic, ...] = Field(max_length=256)
    unsupported_features: tuple[str, ...] = Field(max_length=256)
    suggested_addons: tuple[AddonHint, ...] = Field(max_length=64)
    files_considered: tuple[str, ...] = Field(max_length=4096)
    generated_manifest: GeneratedManifest | None
    blocked: bool

    @field_validator("source_snapshot_id")
    @classmethod
    def validate_snapshot_id(cls, value: str) -> str:
        """Bind every proposal to one immutable source snapshot."""
        if not value.startswith("snp_"):
            msg = "source_snapshot_id must use the snp prefix"
            raise ValueError(msg)
        return value

    @field_validator("snapshot_root")
    @classmethod
    def validate_snapshot_root(cls, value: str) -> str:
        """Record only the selected repository-relative root."""
        return canonical_relative_path(value)

    @field_validator("unsupported_features")
    @classmethod
    def validate_unsupported(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Require a deterministic unsupported-feature set."""
        return sorted_unique(value, "unsupported_features")

    @field_validator("files_considered")
    @classmethod
    def validate_files(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Require the exact canonical sorted global read set."""
        checked = tuple(canonical_relative_path(item) for item in value)
        return sorted_unique(checked, "files_considered")

    @model_validator(mode="after")
    def validate_decision(self) -> DetectionResult:
        """Make deploy blocking and generated-manifest availability impossible to misstate."""
        _validate_plugin_and_diagnostic_order(self)
        service_names, evidence = _validate_service_evidence(self)
        _validate_addons_and_unsupported(self, service_names, evidence)
        _validate_blocked_manifest_state(self, service_names)
        return self


def _contains_control_character(value: str) -> bool:
    return any(
        ord(character) < ASCII_CONTROL_LIMIT or ord(character) == ASCII_DELETE
        for character in value
    )


def _validate_plugin_and_diagnostic_order(result: DetectionResult) -> None:
    plugin_names = tuple(item.plugin for item in result.plugins)
    if plugin_names != tuple(sorted(set(plugin_names))):
        msg = "plugins must be sorted and unique"
        raise ValueError(msg)
    warning_keys = tuple(_diagnostic_key(item) for item in result.warnings)
    unresolved_keys = tuple(_diagnostic_key(item) for item in result.unresolved)
    if warning_keys != tuple(sorted(set(warning_keys))) or any(
        item.severity != "warning" for item in result.warnings
    ):
        msg = "warnings must contain sorted unique warning diagnostics"
        raise ValueError(msg)
    if unresolved_keys != tuple(sorted(set(unresolved_keys))) or any(
        item.severity != "blocking" for item in result.unresolved
    ):
        msg = "unresolved must contain sorted unique blocking diagnostics"
        raise ValueError(msg)


def _validate_service_evidence(
    result: DetectionResult,
) -> tuple[tuple[str, ...], dict[str, Evidence]]:
    service_names = tuple(service.name for service in result.services)
    service_roots = tuple(service.root for service in result.services)
    if len(set(service_names)) != len(service_names) or len(set(service_roots)) != len(
        service_roots
    ):
        msg = "service names and roots must be unique"
        raise ValueError(msg)
    seen_services: set[str] = set()
    evidence = {node.id: node for node in result.evidence_graph.nodes}
    cycle_reported = any(item.code == "workspace.dependency-cycle" for item in result.unresolved)
    for service in result.services:
        if not set(service.depends_on) <= seen_services and not cycle_reported:
            msg = "services must be topologically ordered by depends_on"
            raise ValueError(msg)
        seen_services.add(service.name)
        if not set(service.evidence_ids) <= set(evidence):
            msg = "service references unknown evidence"
            raise ValueError(msg)
        expected = round(
            max(
                0.0,
                min(
                    1.0,
                    0.5 + sum(evidence[item].confidence_delta for item in service.evidence_ids),
                ),
            ),
            3,
        )
        if service.confidence != expected:
            msg = "service confidence does not equal its evidence contributions"
            raise ValueError(msg)
        if not set(service.files_considered) <= set(result.files_considered):
            msg = "service files must be present in global files_considered"
            raise ValueError(msg)
    expected_targets = {f"service:{name}" for name in service_names}
    if not {edge.target for edge in result.evidence_graph.edges} <= expected_targets:
        msg = "evidence graph targets an unknown service"
        raise ValueError(msg)
    if not {node.path for node in evidence.values()} <= set(result.files_considered):
        msg = "evidence paths must be present in global files_considered"
        raise ValueError(msg)
    return service_names, evidence


def _validate_addons_and_unsupported(
    result: DetectionResult,
    service_names: tuple[str, ...],
    evidence: dict[str, Evidence],
) -> None:
    for addon in result.suggested_addons:
        if not set(addon.services) <= set(service_names):
            msg = "add-on hint references an unknown service"
            raise ValueError(msg)
        if not set(addon.evidence_ids) <= set(evidence):
            msg = "add-on hint references unknown evidence"
            raise ValueError(msg)
    expected = tuple(
        sorted({feature for service in result.services for feature in service.unsupported_features})
    )
    if result.unsupported_features != expected:
        msg = "unsupported_features must aggregate all service values"
        raise ValueError(msg)


def _validate_blocked_manifest_state(
    result: DetectionResult,
    service_names: tuple[str, ...],
) -> None:
    expected_blocked = bool(
        result.unresolved
        or not result.services
        or result.unsupported_features
        or any(service.ambiguous for service in result.services)
    )
    if result.blocked != expected_blocked:
        msg = "blocked must reflect unresolved, unsupported, or ambiguous detector state"
        raise ValueError(msg)
    if result.blocked == (result.generated_manifest is not None):
        msg = "generated_manifest is available only for unblocked proposals"
        raise ValueError(msg)
    if result.generated_manifest is not None:
        manifest_names = tuple(service.name for service in result.generated_manifest.services)
        if manifest_names != service_names:
            msg = "generated manifest services must match the proposal order"
            raise ValueError(msg)


def _diagnostic_key(value: Diagnostic) -> tuple[str, str, str, str, str]:
    return (
        value.code,
        value.service_root or "",
        value.path or "",
        value.detector or "",
        value.message,
    )
