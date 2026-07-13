"""Go module, package-main, build-tag, and process detector plugin."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from lrail_detector.models import (
    AddonEngine,
    BuildProposal,
    Diagnostic,
    PluginVersion,
    ProcessKind,
    ProcessProposal,
    Protocol,
    RuntimeProposal,
)
from lrail_detector.plugins.base import (
    AddonRequest,
    Candidate,
    DetectionContext,
    PluginResult,
    diagnostic,
    evidence,
)
from lrail_detector.plugins.helpers import join, read_header, root_name, workspace_files

_MODULE = re.compile(r"(?m)^\s*module\s+(?P<name>\S+)")
_GO_VERSION = re.compile(r"(?m)^\s*go\s+(?P<version>[0-9]+(?:\.[0-9]+){1,2})")
_PACKAGE_MAIN = re.compile(r"(?m)^\s*package\s+main\s*$")
_BUILD_TAG = re.compile(r"(?m)^\s*//(?:go:build|\s*\+build)\s+(?P<tag>[^\r\n]+)")
_PORT = re.compile(r"(?<![0-9]):(?P<port>[1-9][0-9]{1,4})(?![0-9])")
_NETWORK_MARKERS = ("ListenAndServe", "http.Server", "gin.", "echo.", "fiber.", "chi.")
MAX_PORT = 65_535
COMMAND_PATH_PARTS = 3
_FRAMEWORKS = (
    ("Gin", "github.com/gin-gonic/gin"),
    ("Echo", "github.com/labstack/echo"),
    ("Fiber", "github.com/gofiber/fiber"),
    ("Chi", "github.com/go-chi/chi"),
)
_ADDONS: tuple[tuple[frozenset[str], AddonEngine, str], ...] = (
    (frozenset({"github.com/jackc/pgx", "github.com/lib/pq"}), "postgresql", "database driver"),
    (frozenset({"github.com/go-sql-driver/mysql"}), "mysql", "database driver"),
    (frozenset({"github.com/redis/go-redis"}), "valkey", "cache client"),
    (frozenset({"go.mongodb.org/mongo-driver"}), "mongodb", "document database driver"),
    (frozenset({"github.com/rabbitmq/amqp091-go"}), "rabbitmq", "message queue driver"),
    (frozenset({"github.com/clickhouse/clickhouse-go"}), "clickhouse", "analytics driver"),
)


class GoPlugin:
    """Detect Go command processes from bounded module and source headers."""

    descriptor = PluginVersion(plugin="go", version="1.0.0")

    def detect(self, context: DetectionContext) -> PluginResult:
        """Return one service per module with one or more explicit process groups."""
        candidates: list[Candidate] = []
        warnings = []
        for record in context.inventory.records_named("go.mod"):
            try:
                raw = context.inventory.read_text(record.path)
            except ValueError as error:
                warnings.append(
                    diagnostic(
                        "go.unreadable-module",
                        str(error),
                        blocking=False,
                        path=record.path,
                        root=record.parent,
                        detector="go",
                    )
                )
                continue
            candidate, candidate_warnings = self._candidate(
                context,
                record.path,
                record.parent,
                raw,
            )
            warnings.extend(candidate_warnings)
            if candidate:
                candidates.append(candidate)
        return PluginResult(candidates=tuple(candidates), warnings=tuple(warnings))

    def _candidate(
        self,
        context: DetectionContext,
        manifest: str,
        root: str,
        raw: str,
    ) -> tuple[Candidate | None, tuple[Diagnostic, ...]]:
        command_files = [
            record
            for record in context.inventory.records_under(root)
            if record.name == "main.go" and _is_command_path(root, record.path)
        ]
        headers: dict[str, str] = {}
        diagnostics: list[Diagnostic] = []
        for record in command_files:
            header, warning = read_header(context, record.path, detector="go", root=root)
            if warning:
                diagnostics.append(warning)
                continue
            if header is None:
                continue
            if _PACKAGE_MAIN.search(header):
                headers[record.path] = header
        if not headers:
            return (
                None,
                (
                    diagnostic(
                        "go.no-main-package",
                        f"Go module at {root} has no bounded package main entrypoint",
                        blocking=False,
                        path=manifest,
                        root=root,
                        detector="go",
                    ),
                ),
            )

        module_match = _MODULE.search(raw)
        module = module_match.group("name") if module_match else root_name(root)
        version_match = _GO_VERSION.search(raw)
        runtime_version = version_match.group("version") if version_match else None
        framework = next((name for name, package in _FRAMEWORKS if package in raw), "Go net/http")
        evidence_nodes = [
            evidence(
                "go",
                "go.module",
                manifest,
                f"Go module {module} declares a reproducible build root",
                0.25,
            )
        ]
        unresolved = []
        processes: list[ProcessProposal] = []
        files = {manifest, *headers}
        required = {manifest, *headers}
        go_sum = join(root, "go.sum")
        if context.inventory.contains(go_sum):
            files.add(go_sum)
            required.add(go_sum)
            evidence_nodes.append(
                evidence(
                    "go",
                    "go.module-checksums",
                    go_sum,
                    "go.sum pins module content checksums",
                    0.03,
                )
            )
        else:
            unresolved.append(
                diagnostic(
                    "go.missing-checksums",
                    "A deployable Go module requires go.sum",
                    blocking=True,
                    path=manifest,
                    root=root,
                    detector="go",
                )
            )
        for declaration in workspace_files(context, root):
            files.add(declaration)
            required.add(declaration)
            evidence_nodes.append(
                evidence(
                    "go",
                    "go.workspace-membership",
                    declaration,
                    f"go.work declares module root {root}",
                    0.02,
                )
            )

        for path, header in sorted(headers.items()):
            command_name = _command_name(root, path)
            tags = tuple(match.group("tag").strip() for match in _BUILD_TAG.finditer(header))
            network = any(marker in header for marker in _NETWORK_MARKERS) or command_name in {
                "api",
                "server",
            }
            process_name = "web" if network and command_name == "app" else command_name
            if network:
                port_match = _PORT.search(header)
                port = int(port_match.group("port")) if port_match else 8080
                if port > MAX_PORT:
                    port = 8080
                    port_match = None
                if not port_match:
                    unresolved.append(
                        diagnostic(
                            "go.listen-port-unresolved",
                            f"Network command {process_name} has no literal bounded listen port",
                            blocking=True,
                            path=path,
                            root=root,
                            detector="go",
                        )
                    )
                kind: ProcessKind = "web"
                protocol: Protocol = "http"
                health = "/healthz"
            else:
                port = None
                kind = "job" if command_name in {"migrate", "migration"} else "worker"
                protocol = "none"
                health = None
            processes.append(
                ProcessProposal(
                    name=process_name,
                    kind=kind,
                    command=(f"/app/out/{process_name}",),
                    port=port,
                    protocol=protocol,
                    health_path=health,
                )
            )
            evidence_nodes.append(
                evidence(
                    "go",
                    "go.package-main",
                    path,
                    f"Static header declares package main for process {process_name}",
                    0.12,
                )
            )
            if tags:
                unresolved.append(
                    diagnostic(
                        "go.build-tags-require-review",
                        f"Process {command_name} uses build constraints: {', '.join(tags)}",
                        blocking=True,
                        path=path,
                        root=root,
                        detector="go",
                    )
                )

        addons = []
        modules = {
            line.split()[0]
            for line in raw.splitlines()
            if line.strip().startswith("github.com/") or line.strip().startswith("go.mongodb.org/")
        }
        for names, engine, reason in _ADDONS:
            matched = sorted(
                name for name in names if any(module.startswith(name) for module in modules)
            )
            if not matched:
                continue
            node = evidence(
                "go",
                f"go.addon-{engine}",
                manifest,
                f"Modules {', '.join(matched)} suggest {engine}",
                0.0,
            )
            evidence_nodes.append(node)
            addons.append(
                AddonRequest(
                    engine=engine,
                    reason=reason,
                    evidence_ids=(node.id,),
                )
            )

        command_patterns = tuple(
            "./" + str(PurePosixPath(path).parent.relative_to(PurePosixPath(root)))
            if root != "."
            else "./" + str(PurePosixPath(path).parent)
            for path in sorted(headers)
        )
        output_target = f"out/{processes[0].name}" if len(processes) == 1 else "out/"
        return (
            Candidate(
                name=root_name(root),
                root=root,
                kind="web" if any(process.kind == "web" for process in processes) else "worker",
                language="go",
                framework=framework,
                runtime=RuntimeProposal(
                    name="go",
                    version=runtime_version,
                    version_source=manifest if runtime_version else None,
                ),
                build=BuildProposal(
                    strategy="auto",
                    install_command=("go", "mod", "download"),
                    build_command=(
                        "go",
                        "build",
                        "-trimpath",
                        "-o",
                        output_target,
                        *command_patterns,
                    ),
                    output_path=join(root, "out"),
                    cache_paths=(join(root, ".cache/go-build"),),
                    required_files=tuple(sorted(required)),
                ),
                processes=tuple(processes),
                evidence=tuple(evidence_nodes),
                unsupported_features=(),
                files_considered=tuple(sorted(files)),
                addons=tuple(addons),
                unresolved=tuple(unresolved),
                ambiguous=bool(unresolved),
            ),
            tuple(diagnostics),
        )


def _command_name(root: str, path: str) -> str:
    parent = PurePosixPath(path).parent
    if path == join(root, "main.go"):
        return "app"
    return parent.name.casefold().replace("_", "-")[:63] or "app"


def _is_command_path(root: str, path: str) -> bool:
    if path == join(root, "main.go"):
        return True
    relative = path if root == "." else path.removeprefix(f"{root}/")
    parts = PurePosixPath(relative).parts
    return len(parts) == COMMAND_PATH_PARTS and parts[0] == "cmd" and parts[-1] == "main.go"
