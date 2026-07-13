"""Python ASGI, WSGI, Django, and worker detector plugin."""

from __future__ import annotations

import re
import tomllib
from pathlib import PurePosixPath
from typing import Any

from lrail_detector.models import (
    AddonEngine,
    BuildProposal,
    Diagnostic,
    PluginVersion,
    ProcessKind,
    ProcessProposal,
    RuntimeProposal,
    ServiceKind,
)
from lrail_detector.plugins.base import (
    AddonRequest,
    Candidate,
    DetectionContext,
    PluginResult,
    diagnostic,
    evidence,
)
from lrail_detector.plugins.helpers import (
    join,
    parse_procfile,
    read_header,
    root_name,
    runtime_file,
)

_REQUIREMENT = re.compile(r"(?im)^\s*(?P<name>[a-z0-9_.-]+)(?P<constraint>[^;\s#]*)")
_DJANGO_SETTINGS = re.compile(r"DJANGO_SETTINGS_MODULE\s*['\"],\s*['\"](?P<module>[A-Za-z0-9_.]+)")
_APP_ASSIGNMENT = re.compile(
    r"(?m)^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:FastAPI|Flask)\s*\("
)
_ADDONS: tuple[tuple[frozenset[str], AddonEngine, str], ...] = (
    (frozenset({"psycopg", "psycopg2", "asyncpg"}), "postgresql", "database adapter"),
    (frozenset({"mysqlclient", "pymysql"}), "mysql", "database adapter"),
    (frozenset({"redis", "celery", "rq"}), "valkey", "cache or queue adapter"),
    (frozenset({"pymongo", "motor", "mongoengine"}), "mongodb", "document database adapter"),
    (frozenset({"pika", "kombu"}), "rabbitmq", "message queue adapter"),
    (
        frozenset({"clickhouse-connect", "clickhouse-driver"}),
        "clickhouse",
        "analytics database adapter",
    ),
)


class PythonPlugin:
    """Detect production Python processes from dependency and entrypoint metadata."""

    descriptor = PluginVersion(plugin="python", version="1.0.0")

    def detect(self, context: DetectionContext) -> PluginResult:
        """Return Python candidates without importing project modules."""
        roots = {
            record.parent
            for record in context.inventory.records_named(
                "pyproject.toml",
                "requirements.txt",
                "Pipfile",
            )
        }
        candidates: list[Candidate] = []
        for root in sorted(roots):
            candidate = self._candidate(context, root)
            if candidate:
                candidates.append(candidate)
        return PluginResult(candidates=tuple(candidates))

    def _candidate(self, context: DetectionContext, root: str) -> Candidate | None:
        dependencies: set[str] = set()
        files: set[str] = set()
        required: set[str] = set()
        unresolved = []
        warnings: list[Diagnostic] = []
        runtime_version: str | None = None
        runtime_source: str | None = None
        manifest: str | None = None

        pyproject = join(root, "pyproject.toml")
        if context.inventory.contains(pyproject):
            manifest = pyproject
            files.add(pyproject)
            required.add(pyproject)
            try:
                raw = context.inventory.read_text(pyproject)
                document = tomllib.loads(raw)
                dependencies.update(_toml_dependencies(document))
                requires_python = document.get("project", {}).get("requires-python")
                if isinstance(requires_python, str) and requires_python:
                    runtime_version = requires_python[:64]
                    runtime_source = pyproject
            except (ValueError, tomllib.TOMLDecodeError) as error:
                unresolved.append(
                    diagnostic(
                        "python.invalid-pyproject",
                        f"Cannot parse pyproject.toml: {error}",
                        blocking=True,
                        path=pyproject,
                        root=root,
                        detector="python",
                    )
                )

        requirements = join(root, "requirements.txt")
        requirements_raw = ""
        if context.inventory.contains(requirements):
            manifest = manifest or requirements
            files.add(requirements)
            required.add(requirements)
            try:
                requirements_raw = context.inventory.read_text(requirements)
                dependencies.update(
                    match.group("name").casefold().replace("_", "-")
                    for match in _REQUIREMENT.finditer(requirements_raw)
                )
                directives = [
                    line.strip()
                    for line in requirements_raw.splitlines()
                    if line.lstrip().startswith("-")
                ]
                if directives:
                    unresolved.append(
                        diagnostic(
                            "python.requirements-directive-unresolved",
                            "Nested, editable, URL, or option requirements require review",
                            blocking=True,
                            path=requirements,
                            root=root,
                            detector="python",
                        )
                    )
            except ValueError as error:
                unresolved.append(
                    diagnostic(
                        "python.unreadable-requirements",
                        str(error),
                        blocking=True,
                        path=requirements,
                        root=root,
                        detector="python",
                    )
                )

        pipfile = join(root, "Pipfile")
        if context.inventory.contains(pipfile):
            manifest = manifest or pipfile
            files.add(pipfile)
            required.add(pipfile)
            try:
                raw = context.inventory.read_text(pipfile)
                dependencies.update(
                    match.group("name").casefold() for match in _REQUIREMENT.finditer(raw)
                )
            except ValueError as error:
                unresolved.append(
                    diagnostic(
                        "python.unreadable-pipfile",
                        str(error),
                        blocking=True,
                        path=pipfile,
                        root=root,
                        detector="python",
                    )
                )

        if manifest is None:
            return None
        frameworks = [
            name
            for name, packages in (
                ("Django", {"django"}),
                ("FastAPI", {"fastapi"}),
                ("Flask", {"flask"}),
            )
            if dependencies & packages
        ]
        worker_only = not frameworks and bool(dependencies & {"celery", "rq"})
        if not frameworks and not worker_only:
            return None
        framework = frameworks[0] if frameworks else "Python Worker"
        if len(frameworks) > 1:
            unresolved.append(
                diagnostic(
                    "python.multiple-frameworks",
                    "Multiple Python web frameworks share one package root: "
                    + ", ".join(frameworks),
                    blocking=True,
                    path=manifest,
                    root=root,
                    detector="python",
                )
            )
        if framework == "FastAPI" and "uvicorn" not in dependencies:
            unresolved.append(
                diagnostic(
                    "python.missing-asgi-server",
                    "FastAPI requires a declared production ASGI server",
                    blocking=True,
                    path=manifest,
                    root=root,
                    detector="python",
                )
            )
        if framework in {"Django", "Flask"} and "gunicorn" not in dependencies:
            unresolved.append(
                diagnostic(
                    "python.missing-wsgi-server",
                    f"{framework} requires a declared production WSGI server",
                    blocking=True,
                    path=manifest,
                    root=root,
                    detector="python",
                )
            )

        evidence_nodes = [
            evidence(
                "python",
                "python.framework-dependency",
                manifest,
                f"Declared Python dependencies identify {framework}",
                0.47 if framework == "Django" else 0.45 if framework == "FastAPI" else 0.42,
            )
        ]
        locks = context.workspaces.nearest_lockfiles(root, "python")
        install_command: tuple[str, ...]
        if len(locks) == 1:
            lock = locks[0]
            filename = PurePosixPath(lock).name
            install_command = (
                ("uv", "sync", "--frozen")
                if filename == "uv.lock"
                else ("poetry", "install", "--no-interaction", "--no-root", "--sync")
                if filename == "poetry.lock"
                else ("pipenv", "sync", "--deploy")
            )
            files.add(lock)
            required.add(lock)
            evidence_nodes.append(
                evidence(
                    "python",
                    "python.lockfile",
                    lock,
                    f"{filename} supplies a reproducible environment",
                    0.01,
                )
            )
        elif len(locks) > 1:
            install_command = ("python", "-m", "pip", "install", "-r", "requirements.txt")
            unresolved.append(
                diagnostic(
                    "python.conflicting-lockfiles",
                    "Multiple Python lockfiles exist at the same precedence: " + ", ".join(locks),
                    blocking=True,
                    path=manifest,
                    root=root,
                    detector="python",
                )
            )
        elif requirements_raw and _requirements_are_pinned(requirements_raw):
            install_command = ("python", "-m", "pip", "install", "-r", "requirements.txt")
            evidence_nodes.append(
                evidence(
                    "python",
                    "python.pinned-requirements",
                    requirements,
                    "Every direct requirements entry is exactly pinned",
                    0.01,
                )
            )
        else:
            install_command = ("python", "-m", "pip", "install", "-r", "requirements.txt")
            unresolved.append(
                diagnostic(
                    "python.dependencies-not-locked",
                    "Python dependencies require uv.lock, poetry.lock, Pipfile.lock, or exact pins",
                    blocking=True,
                    path=manifest,
                    root=root,
                    detector="python",
                )
            )

        if runtime_version is None:
            runtime_version, runtime_source, runtime_diagnostics = runtime_file(
                context,
                root,
                (".python-version",),
                detector="python",
            )
            warnings.extend(runtime_diagnostics)
        if runtime_source:
            files.add(runtime_source)
            required.add(runtime_source)

        processes, entry_files, process_diagnostics = _processes(
            context,
            root,
            framework,
            dependencies,
        )
        files.update(entry_files)
        required.update(entry_files)
        unresolved.extend(process_diagnostics)

        procfile = join(root, "Procfile")
        if context.inventory.contains(procfile):
            files.add(procfile)
            required.add(procfile)
            try:
                raw = context.inventory.read_text(procfile)
            except ValueError as error:
                unresolved.append(
                    diagnostic(
                        "python.unreadable-procfile",
                        str(error),
                        blocking=True,
                        path=procfile,
                        root=root,
                        detector="python",
                    )
                )
            else:
                declared, procfile_diagnostics = parse_procfile(
                    raw,
                    path=procfile,
                    root=root,
                    detector="python",
                )
                unresolved.extend(procfile_diagnostics)
                if declared:
                    processes = tuple(
                        ProcessProposal(
                            name=name,
                            kind=_procfile_kind(name),
                            command=command,
                            port=8000 if name == "web" else None,
                            protocol="http" if name == "web" else "none",
                            health_path="/" if name == "web" else None,
                        )
                        for name, command in sorted(declared.items())
                    )

        addons: list[AddonRequest] = []
        for names, engine, reason in _ADDONS:
            matched = sorted(names & dependencies)
            if not matched:
                continue
            node = evidence(
                "python",
                f"python.addon-{engine}",
                manifest,
                f"Dependencies {', '.join(matched)} suggest {engine}",
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

        kind: ServiceKind = (
            "worker"
            if all(process.kind in {"worker", "job", "release"} for process in processes)
            else "web"
        )
        return Candidate(
            name=root_name(root),
            root=root,
            kind=kind,
            language="python",
            framework=framework,
            runtime=RuntimeProposal(
                name="python",
                version=runtime_version,
                version_source=runtime_source,
            ),
            build=BuildProposal(
                strategy="auto",
                install_command=install_command,
                build_command=(),
                output_path=None,
                cache_paths=(join(root, ".venv"),),
                required_files=tuple(sorted(required)),
            ),
            processes=processes,
            evidence=tuple(evidence_nodes),
            unsupported_features=(),
            files_considered=tuple(sorted(files)),
            addons=tuple(addons),
            warnings=tuple(warnings),
            unresolved=tuple(unresolved),
            ambiguous=bool(unresolved),
        )


def _toml_dependencies(document: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    project = document.get("project", {})
    if isinstance(project, dict):
        for dependency in project.get("dependencies", ()):
            if isinstance(dependency, str):
                match = _REQUIREMENT.match(dependency)
                if match:
                    values.add(match.group("name").casefold().replace("_", "-"))
    poetry = document.get("tool", {}).get("poetry", {}).get("dependencies", {})
    if isinstance(poetry, dict):
        values.update(str(name).casefold().replace("_", "-") for name in poetry if name != "python")
    return values


def _requirements_are_pinned(raw: str) -> bool:
    entries = [
        line.strip()
        for line in raw.splitlines()
        if line.strip() and not line.lstrip().startswith(("#", "-"))
    ]
    return bool(entries) and all("==" in line and not line.endswith("==") for line in entries)


def _processes(
    context: DetectionContext,
    root: str,
    framework: str,
    dependencies: set[str],
) -> tuple[tuple[ProcessProposal, ...], set[str], tuple[Diagnostic, ...]]:
    files: set[str] = set()
    unresolved = []
    if framework == "Python Worker":
        if "celery" in dependencies:
            return (
                (
                    ProcessProposal(
                        name="worker",
                        kind="worker",
                        command=("celery", "-A", "app", "worker"),
                    ),
                ),
                files,
                (
                    diagnostic(
                        "python.worker-module-unresolved",
                        "Celery application module must be confirmed",
                        blocking=True,
                        root=root,
                        detector="python",
                    ),
                ),
            )
        return (
            (ProcessProposal(name="worker", kind="worker", command=("rq", "worker")),),
            files,
            (),
        )

    candidates = [
        record.path
        for record in context.inventory.records_under(root)
        if record.name in {"app.py", "asgi.py", "main.py", "manage.py", "wsgi.py"}
    ]
    headers: dict[str, str] = {}
    for path in sorted(candidates):
        header, warning = read_header(context, path, detector="python", root=root)
        if warning:
            unresolved.append(warning)
            continue
        if header is None:
            continue
        headers[path] = header
        files.add(path)

    if framework == "Django":
        wsgi = next((path for path in headers if path.endswith("wsgi.py")), None)
        if wsgi:
            module = _module_for(root, wsgi)
        else:
            manage = next((path for path in headers if path.endswith("manage.py")), None)
            settings = _DJANGO_SETTINGS.search(headers.get(manage, "")) if manage else None
            module = (
                f"{settings.group('module').rsplit('.', 1)[0]}.wsgi" if settings else "project.wsgi"
            )
            unresolved.append(
                diagnostic(
                    "python.django-wsgi-unresolved",
                    "Django WSGI module must be confirmed",
                    blocking=True,
                    path=manage,
                    root=root,
                    detector="python",
                )
            )
        processes = [
            ProcessProposal(
                name="web",
                kind="web",
                command=("gunicorn", f"{module}:application", "--bind", "0.0.0.0:8000"),
                port=8000,
                protocol="http",
                health_path="/",
            )
        ]
        _append_python_workers(processes, dependencies, unresolved, root=root)
        return tuple(processes), files, tuple(unresolved)

    preferred = "main.py" if framework == "FastAPI" else "app.py"
    entry = next((path for path in headers if PurePosixPath(path).name == preferred), None)
    entry = entry or next((path for path in headers if path.endswith(("main.py", "app.py"))), None)
    if entry:
        assignment = _APP_ASSIGNMENT.search(headers[entry])
        variable = assignment.group("name") if assignment else "app"
        module = _module_for(root, entry)
        if assignment is None:
            unresolved.append(
                diagnostic(
                    "python.app-symbol-unresolved",
                    f"{framework} application symbol must be confirmed",
                    blocking=True,
                    path=entry,
                    root=root,
                    detector="python",
                )
            )
    else:
        variable = "app"
        module = "main" if framework == "FastAPI" else "app"
        unresolved.append(
            diagnostic(
                "python.entrypoint-unresolved",
                f"{framework} ASGI/WSGI module must be confirmed",
                blocking=True,
                root=root,
                detector="python",
            )
        )
    command = (
        ("uvicorn", f"{module}:{variable}", "--host", "0.0.0.0", "--port", "8000")
        if framework == "FastAPI"
        else ("gunicorn", "--bind", "0.0.0.0:8000", f"{module}:{variable}")
    )
    processes = [
        ProcessProposal(
            name="web",
            kind="web",
            command=command,
            port=8000,
            protocol="http",
            health_path="/docs" if framework == "FastAPI" else "/",
        )
    ]
    _append_python_workers(processes, dependencies, unresolved, root=root)
    return tuple(processes), files, tuple(unresolved)


def _module_for(root: str, path: str) -> str:
    relative = path if root == "." else path.removeprefix(f"{root}/")
    return str(PurePosixPath(relative).with_suffix("")).replace("/", ".")


def _procfile_kind(name: str) -> ProcessKind:
    if name == "web":
        return "web"
    return "release" if name == "release" else "worker"


def _append_python_workers(
    processes: list[ProcessProposal],
    dependencies: set[str],
    unresolved: list[Diagnostic],
    *,
    root: str,
) -> None:
    if "celery" in dependencies:
        processes.append(
            ProcessProposal(
                name="worker",
                kind="worker",
                command=("celery", "-A", "app", "worker"),
            )
        )
        unresolved.append(
            diagnostic(
                "python.worker-module-unresolved",
                "Celery application module must be confirmed",
                blocking=True,
                root=root,
                detector="python",
            )
        )
    elif "rq" in dependencies:
        processes.append(
            ProcessProposal(
                name="worker",
                kind="worker",
                command=("rq", "worker"),
            )
        )
