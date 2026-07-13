"""Explicit Dockerfile and bounded Compose-hint detector plugin."""

from __future__ import annotations

import json
import re

from lrail_detector.models import (
    BuildProposal,
    PluginVersion,
    ProcessProposal,
    RuntimeProposal,
)
from lrail_detector.plugins.base import (
    Candidate,
    DetectionContext,
    PluginResult,
    diagnostic,
    evidence,
)
from lrail_detector.plugins.helpers import join, root_name

_EXPOSE = re.compile(r"(?im)^\s*EXPOSE\s+(?P<ports>[^\r\n#]+)")
_JSON_DIRECTIVE = re.compile(r"(?im)^\s*(?P<kind>CMD|ENTRYPOINT)\s+(?P<value>\[[^\n]+\])\s*$")
_SHELL_DIRECTIVE = re.compile(r"(?im)^\s*(?:CMD|ENTRYPOINT)\s+(?!\[)(?P<value>[^\r\n]+)$")
_FROM = re.compile(r"(?im)^\s*FROM\s+\S+(?:\s+AS\s+(?P<name>[A-Za-z0-9_.-]+))?")
_HEALTHCHECK = re.compile(r"(?im)^\s*HEALTHCHECK\b")
_COMPOSE_PORT = re.compile(r"['\"]?(?:127\.0\.0\.1:)?[0-9]+:(?P<port>[1-9][0-9]{1,4})['\"]?")
_COMPOSE_FILES = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")
MAX_PORT = 65_535


class DockerPlugin:
    """Detect explicit container builds without evaluating Docker instructions."""

    descriptor = PluginVersion(plugin="docker", version="1.0.0")

    def detect(self, context: DetectionContext) -> PluginResult:
        """Return overlay candidates for every bounded Dockerfile."""
        candidates = []
        warnings = []
        dockerfiles = [
            record
            for record in context.inventory.files
            if record.name.casefold() == "dockerfile"
            or record.name.casefold().startswith("dockerfile.")
        ]
        for record in dockerfiles:
            try:
                raw = context.inventory.read_text(record.path)
            except ValueError as error:
                warnings.append(
                    diagnostic(
                        "docker.unreadable-dockerfile",
                        str(error),
                        blocking=False,
                        path=record.path,
                        root=record.parent,
                        detector="docker",
                    )
                )
                continue
            candidates.append(self._candidate(context, record.path, record.parent, raw))
        return PluginResult(candidates=tuple(candidates), warnings=tuple(warnings))

    def _candidate(
        self,
        context: DetectionContext,
        dockerfile: str,
        root: str,
        raw: str,
    ) -> Candidate:
        evidence_nodes = [
            evidence(
                "docker",
                "docker.explicit-build",
                dockerfile,
                "Dockerfile explicitly controls the image build",
                0.49,
            )
        ]
        unresolved = []
        warnings = []
        unsupported = []
        files = {dockerfile}
        required = {dockerfile}

        ports = _ports(raw)
        compose_port: int | None = None
        for name in _COMPOSE_FILES:
            path = join(root, name)
            if not context.inventory.contains(path):
                continue
            try:
                compose = context.inventory.read_text(path)
            except ValueError as error:
                warnings.append(
                    diagnostic(
                        "docker.unreadable-compose",
                        str(error),
                        blocking=False,
                        path=path,
                        root=root,
                        detector="docker",
                    )
                )
                continue
            files.add(path)
            required.add(path)
            evidence_nodes.append(
                evidence(
                    "docker",
                    "docker.compose-hint",
                    path,
                    "Compose metadata supplies advisory runtime hints",
                    0.0,
                )
            )
            match = _COMPOSE_PORT.search(compose)
            if match and int(match.group("port")) <= MAX_PORT:
                compose_port = int(match.group("port"))
            if re.search(r"(?im)^\s*privileged\s*:\s*true\s*$", compose):
                unsupported.append("privileged_container")
            if re.search(r"(?im)^\s*network_mode\s*:\s*host\s*$", compose):
                unsupported.append("host_network")

        if len(ports) > 1:
            unresolved.append(
                diagnostic(
                    "docker.multiple-exposed-ports",
                    "Multiple Dockerfile ports require an explicit runtime process selection",
                    blocking=True,
                    path=dockerfile,
                    root=root,
                    detector="docker",
                )
            )
        port = ports[0] if len(ports) == 1 else compose_port or 8080
        if not ports and compose_port is None:
            unresolved.append(
                diagnostic(
                    "docker.port-unresolved",
                    "Docker runtime port must be confirmed from EXPOSE or one Compose mapping",
                    blocking=True,
                    path=dockerfile,
                    root=root,
                    detector="docker",
                )
            )

        entrypoint: tuple[str, ...] = ()
        command: tuple[str, ...] = ()
        for match in _JSON_DIRECTIVE.finditer(raw):
            try:
                values = json.loads(match.group("value"))
            except json.JSONDecodeError:
                unresolved.append(
                    diagnostic(
                        "docker.invalid-json-command",
                        f"{match.group('kind')} is not a valid JSON argv array",
                        blocking=True,
                        path=dockerfile,
                        root=root,
                        detector="docker",
                    )
                )
                continue
            if (
                not isinstance(values, list)
                or not values
                or not all(isinstance(item, str) and item for item in values)
            ):
                unresolved.append(
                    diagnostic(
                        "docker.invalid-json-command",
                        f"{match.group('kind')} must be a non-empty string argv array",
                        blocking=True,
                        path=dockerfile,
                        root=root,
                        detector="docker",
                    )
                )
                continue
            parsed = tuple(values[:64])
            if match.group("kind").upper() == "ENTRYPOINT":
                entrypoint = parsed
            else:
                command = parsed
        runtime_command = (*entrypoint, *command)
        if _SHELL_DIRECTIVE.search(raw):
            unresolved.append(
                diagnostic(
                    "docker.shell-command",
                    "Shell-form CMD or ENTRYPOINT requires explicit argv confirmation",
                    blocking=True,
                    path=dockerfile,
                    root=root,
                    detector="docker",
                )
            )
        if not runtime_command:
            runtime_command = ("docker-image-default",)
            unresolved.append(
                diagnostic(
                    "docker.command-unresolved",
                    "Docker image runtime command must be confirmed",
                    blocking=True,
                    path=dockerfile,
                    root=root,
                    detector="docker",
                )
            )

        stages = tuple(_FROM.finditer(raw))
        target = stages[-1].group("name") if stages else None
        build_command = ["docker", "build", "--file", dockerfile]
        if target:
            build_command.extend(("--target", target))
        build_command.append(root)
        return Candidate(
            name=root_name(root),
            root=root,
            kind="web",
            language="docker",
            framework="Dockerfile",
            runtime=RuntimeProposal(name="docker"),
            build=BuildProposal(
                strategy="dockerfile",
                install_command=(),
                build_command=tuple(build_command),
                output_path=None,
                cache_paths=(),
                required_files=tuple(sorted(required)),
            ),
            processes=(
                ProcessProposal(
                    name="web",
                    kind="web",
                    command=runtime_command,
                    port=port,
                    protocol="http",
                    health_path=None if _HEALTHCHECK.search(raw) else "/",
                ),
            ),
            evidence=tuple(evidence_nodes),
            unsupported_features=tuple(sorted(set(unsupported))),
            files_considered=tuple(sorted(files)),
            warnings=tuple(warnings),
            unresolved=tuple(unresolved),
            ambiguous=bool(unresolved),
            overlay=True,
        )


def _ports(raw: str) -> tuple[int, ...]:
    values: set[int] = set()
    for match in _EXPOSE.finditer(raw):
        for token in match.group("ports").split():
            candidate = token.split("/", 1)[0]
            if candidate.isdigit() and 1 <= int(candidate) <= MAX_PORT:
                values.add(int(candidate))
    return tuple(sorted(values))
