"""Versioned detector output models."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Language = Literal["ruby", "node", "python", "go", "static", "docker"]
BuildMethod = Literal["auto", "dockerfile", "starlark"]


class FrozenModel(BaseModel):
    """Strict immutable contract base."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class Evidence(FrozenModel):
    """One bounded fact supporting a proposal."""

    kind: Literal["manifest", "dependency", "script", "file", "docker", "workspace"]
    path: str = Field(max_length=1024)
    detail: str = Field(max_length=512)
    weight: float = Field(ge=0.0, le=1.0)


class ProcessProposal(FrozenModel):
    """One process group inferred without executing source."""

    name: str = Field(pattern=r"^[a-z][a-z0-9-]{0,62}$")
    kind: Literal["web", "worker", "private_service", "release", "job", "static"]
    command: tuple[str, ...] = Field(max_length=64)
    port: int | None = Field(default=None, ge=1, le=65535)
    health_path: str | None = Field(default=None, pattern=r"^/", max_length=512)

    @model_validator(mode="after")
    def require_network_port(self) -> ProcessProposal:
        """Require a port for network-serving process groups."""
        if self.kind in {"web", "private_service"} and self.port is None:
            msg = f"{self.kind} process requires a port"
            raise ValueError(msg)
        return self


class ServiceProposal(FrozenModel):
    """Explainable build and runtime proposal for one service root."""

    name: str = Field(pattern=r"^[a-z][a-z0-9-]{0,62}$")
    root: str = Field(max_length=1024)
    language: Language
    framework: str = Field(max_length=64)
    build_method: BuildMethod
    install_command: tuple[str, ...] = Field(max_length=64)
    build_command: tuple[str, ...] = Field(max_length=64)
    processes: tuple[ProcessProposal, ...] = Field(min_length=1, max_length=32)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: tuple[Evidence, ...] = Field(min_length=1, max_length=128)
    unsupported_features: tuple[str, ...] = Field(max_length=64)
    files_considered: tuple[str, ...] = Field(min_length=1, max_length=512)
    ambiguous: bool


class DetectionResult(FrozenModel):
    """Top-level stable detector response."""

    schema_version: Literal["detector.lrail.dev/v1"] = "detector.lrail.dev/v1"
    snapshot_root: str
    services: tuple[ServiceProposal, ...] = Field(max_length=64)
    warnings: tuple[str, ...] = Field(max_length=128)
    blocked: bool
