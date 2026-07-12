"""Pure static detector rules over a bounded snapshot inventory."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from pathlib import PurePosixPath
from typing import Any

from lrail_detector.inventory import InventoryError, SnapshotInventory
from lrail_detector.models import BuildMethod, Evidence, Language, ProcessProposal

_DIGEST_SAFE_NAME = re.compile(r"[^a-z0-9-]+")
_RUBY_GEM = re.compile(r"\bgem\s*[\( ]?\s*['\"](?P<name>[a-zA-Z0-9_-]+)")
_DOCKER_EXPOSE = re.compile(r"(?im)^\s*EXPOSE\s+(?P<port>[0-9]{1,5})(?:/tcp)?(?:\s|$)")
_DOCKER_HEALTH = re.compile(r"(?im)^\s*HEALTHCHECK\b")
_DOCKER_JSON_COMMAND = re.compile(r"(?im)^\s*(?:CMD|ENTRYPOINT)\s+(?P<value>\[[^\n]+\])\s*$")
MAX_PORT = 65_535


@dataclass(frozen=True, slots=True)
class Candidate:
    """Internal rule result before conflict resolution."""

    name: str
    root: str
    language: Language
    framework: str
    build_method: BuildMethod
    install_command: tuple[str, ...]
    build_command: tuple[str, ...]
    processes: tuple[ProcessProposal, ...]
    confidence: float
    evidence: tuple[Evidence, ...]
    unsupported_features: tuple[str, ...]
    files_considered: tuple[str, ...]
    ambiguous: bool = False


def _slug(value: str, fallback: str) -> str:
    value = value.casefold().replace("_", "-").replace("/", "-")
    value = _DIGEST_SAFE_NAME.sub("-", value).strip("-")
    value = re.sub(r"-{2,}", "-", value)
    if not value or not value[0].isalpha():
        value = f"app-{value}" if value else fallback
    return value[:63].rstrip("-") or fallback


def _root_name(root: str) -> str:
    return "app" if root == "." else _slug(PurePosixPath(root).name, "app")


def _join(root: str, name: str) -> str:
    return name if root == "." else f"{root}/{name}"


def _read(inventory: SnapshotInventory, path: str, warnings: list[str]) -> str | None:
    try:
        return inventory.read_text(path)
    except InventoryError as error:
        warnings.append(str(error))
        return None


def _package_manager(
    inventory: SnapshotInventory,
    root: str,
) -> tuple[str, tuple[str, ...], str | None]:
    choices = (
        ("pnpm-lock.yaml", "pnpm", ("pnpm", "install", "--frozen-lockfile")),
        ("bun.lockb", "bun", ("bun", "install", "--frozen-lockfile")),
        ("bun.lock", "bun", ("bun", "install", "--frozen-lockfile")),
        ("yarn.lock", "yarn", ("yarn", "install", "--immutable")),
        ("package-lock.json", "npm", ("npm", "ci")),
        ("npm-shrinkwrap.json", "npm", ("npm", "ci")),
    )
    for filename, manager, command in choices:
        path = _join(root, filename)
        if inventory.contains(path):
            return manager, command, path
    return "npm", ("npm", "install"), None


def _script_command(manager: str, script: str) -> tuple[str, ...]:
    return (manager, "run", script)


def detect_node(inventory: SnapshotInventory, warnings: list[str]) -> list[Candidate]:
    """Detect Node and TypeScript services from package metadata only."""
    candidates: list[Candidate] = []
    for record in inventory.records_named("package.json"):
        raw = _read(inventory, record.path, warnings)
        if raw is None:
            continue
        try:
            package = json.loads(raw)
        except json.JSONDecodeError, RecursionError:
            warnings.append(f"invalid package.json: {record.path}")
            continue
        if not isinstance(package, dict):
            warnings.append(f"package.json root must be an object: {record.path}")
            continue
        root = record.parent
        dependencies: dict[str, Any] = {}
        for key in ("dependencies", "devDependencies", "peerDependencies"):
            value = package.get(key, {})
            if isinstance(value, dict):
                dependencies.update(value)
        names = {str(name).casefold() for name in dependencies}
        scripts = package.get("scripts", {})
        if not isinstance(scripts, dict):
            scripts = {}

        framework_matches = [
            ("Next.js", "next", 0.98, 3000, "web"),
            ("Nuxt", "nuxt", 0.98, 3000, "web"),
            ("SvelteKit", "@sveltejs/kit", 0.97, 3000, "web"),
            ("Remix", "@remix-run/node", 0.96, 3000, "web"),
            ("NestJS", "@nestjs/core", 0.96, 3000, "web"),
            ("Fastify", "fastify", 0.91, 3000, "web"),
            ("Express", "express", 0.9, 3000, "web"),
            ("Vite", "vite", 0.86, None, "static"),
        ]
        matches = [item for item in framework_matches if item[1] in names]
        has_runnable_script = any(name in scripts for name in ("start", "serve", "dev", "build"))
        if not matches and not has_runnable_script:
            continue

        framework, dependency, confidence, port, kind = (
            matches[0]
            if matches
            else (
                "Node.js",
                "scripts",
                0.72,
                3000,
                "web",
            )
        )
        manager, install, lockfile = _package_manager(inventory, root)
        build = _script_command(manager, "build") if "build" in scripts else ()
        start_script = "start" if "start" in scripts else "serve" if "serve" in scripts else None
        if kind == "static":
            process = ProcessProposal(name="web", kind="static", command=())
        else:
            command = (
                _script_command(manager, start_script)
                if start_script
                else (manager, "exec", dependency, "start")
            )
            process = ProcessProposal(
                name="web",
                kind="web",
                command=command,
                port=port,
                health_path="/",
            )

        evidence = [
            Evidence(
                kind="manifest",
                path=record.path,
                detail="package metadata declares a runnable service",
                weight=0.65,
            )
        ]
        if matches:
            evidence.append(
                Evidence(
                    kind="dependency",
                    path=record.path,
                    detail=f"dependency {dependency} identifies {framework}",
                    weight=confidence,
                )
            )
        if start_script:
            evidence.append(
                Evidence(
                    kind="script",
                    path=record.path,
                    detail=f"script {start_script} supplies the runtime entry point",
                    weight=0.8,
                )
            )
        considered = [record.path]
        if lockfile:
            considered.append(lockfile)
            evidence.append(
                Evidence(
                    kind="file",
                    path=lockfile,
                    detail=f"lockfile selects {manager}",
                    weight=0.7,
                )
            )
        unsupported = []
        if "electron" in names:
            unsupported.append("desktop_runtime")
        if any(name in names for name in ("node-gyp", "@mapbox/node-pre-gyp")):
            unsupported.append("native_addon_requires_build_validation")
        package_name = package.get("name")
        name = _slug(str(package_name), _root_name(root)) if package_name else _root_name(root)
        candidates.append(
            Candidate(
                name=name,
                root=root,
                language="node",
                framework=framework,
                build_method="auto",
                install_command=install,
                build_command=build,
                processes=(process,),
                confidence=confidence,
                evidence=tuple(evidence),
                unsupported_features=tuple(sorted(unsupported)),
                files_considered=tuple(sorted(considered)),
                ambiguous=len(matches) > 1 or (kind != "static" and start_script is None),
            )
        )
    return candidates


def detect_ruby(inventory: SnapshotInventory, warnings: list[str]) -> list[Candidate]:
    """Detect Rails and Rack services from Gemfiles and conventional files."""
    candidates: list[Candidate] = []
    for record in inventory.records_named("Gemfile"):
        raw = _read(inventory, record.path, warnings)
        if raw is None:
            continue
        gems = {match.group("name").casefold() for match in _RUBY_GEM.finditer(raw)}
        root = record.parent
        rails = "rails" in gems or inventory.contains(_join(root, "config/application.rb"))
        rack = "rack" in gems or inventory.contains(_join(root, "config.ru"))
        if not rails and not rack:
            continue
        framework = "Rails" if rails else "Rack"
        command = (
            ("bundle", "exec", "rails", "server", "-b", "0.0.0.0", "-p", "3000")
            if rails
            else ("bundle", "exec", "rackup", "-o", "0.0.0.0", "-p", "3000")
        )
        considered = [record.path]
        lockfile = _join(root, "Gemfile.lock")
        if inventory.contains(lockfile):
            considered.append(lockfile)
        evidence = (
            Evidence(
                kind="dependency",
                path=record.path,
                detail=f"Gemfile declares {framework}",
                weight=0.98 if rails else 0.9,
            ),
        )
        candidates.append(
            Candidate(
                name=_root_name(root),
                root=root,
                language="ruby",
                framework=framework,
                build_method="auto",
                install_command=("bundle", "install", "--deployment"),
                build_command=("bin/rails", "assets:precompile") if rails else (),
                processes=(
                    ProcessProposal(
                        name="web",
                        kind="web",
                        command=command,
                        port=3000,
                        health_path="/up" if rails else "/",
                    ),
                ),
                confidence=0.98 if rails else 0.9,
                evidence=evidence,
                unsupported_features=(),
                files_considered=tuple(sorted(considered)),
            )
        )
    return candidates


def _python_metadata(
    inventory: SnapshotInventory, root: str, warnings: list[str]
) -> tuple[str, list[str]]:
    texts: list[str] = []
    considered: list[str] = []
    for name in ("pyproject.toml", "requirements.txt", "Pipfile"):
        path = _join(root, name)
        if inventory.contains(path):
            raw = _read(inventory, path, warnings)
            if raw is not None:
                texts.append(raw.casefold())
                considered.append(path)
    return "\n".join(texts), considered


def detect_python(inventory: SnapshotInventory, warnings: list[str]) -> list[Candidate]:
    """Detect Python web services from package metadata and conventional entry files."""
    roots = {
        record.parent
        for record in inventory.records_named("pyproject.toml", "requirements.txt", "Pipfile")
    }
    candidates: list[Candidate] = []
    for root in sorted(roots):
        metadata, considered = _python_metadata(inventory, root, warnings)
        manage = _join(root, "manage.py")
        main = _join(root, "main.py")
        app = _join(root, "app.py")
        command: tuple[str, ...]
        if "django" in metadata or inventory.contains(manage):
            framework, confidence = "Django", 0.97
            command = ("python", "manage.py", "runserver", "0.0.0.0:8000")
            health = "/"
            if inventory.contains(manage):
                considered.append(manage)
        elif "fastapi" in metadata:
            framework, confidence = "FastAPI", 0.95
            module = "main:app" if inventory.contains(main) else "app:app"
            command = ("uvicorn", module, "--host", "0.0.0.0", "--port", "8000")
            health = "/docs"
            for path in (main, app):
                if inventory.contains(path):
                    considered.append(path)
        elif "flask" in metadata:
            framework, confidence = "Flask", 0.92
            module = "app:app" if inventory.contains(app) else "main:app"
            command = ("gunicorn", "--bind", "0.0.0.0:8000", module)
            health = "/"
            for path in (main, app):
                if inventory.contains(path):
                    considered.append(path)
        else:
            continue
        manifest = considered[0]
        candidates.append(
            Candidate(
                name=_root_name(root),
                root=root,
                language="python",
                framework=framework,
                build_method="auto",
                install_command=("uv", "sync", "--frozen"),
                build_command=(),
                processes=(
                    ProcessProposal(
                        name="web",
                        kind="web",
                        command=command,
                        port=8000,
                        health_path=health,
                    ),
                ),
                confidence=confidence,
                evidence=(
                    Evidence(
                        kind="dependency",
                        path=manifest,
                        detail=f"Python metadata identifies {framework}",
                        weight=confidence,
                    ),
                ),
                unsupported_features=(),
                files_considered=tuple(sorted(set(considered))),
                ambiguous=framework in {"FastAPI", "Flask"}
                and not any(inventory.contains(path) for path in (main, app)),
            )
        )
    return candidates


def detect_go(inventory: SnapshotInventory, warnings: list[str]) -> list[Candidate]:
    """Detect Go services from modules and conventional command roots."""
    candidates: list[Candidate] = []
    for record in inventory.records_named("go.mod"):
        raw = _read(inventory, record.path, warnings)
        if raw is None:
            continue
        root = record.parent
        module_match = re.search(r"(?m)^\s*module\s+(\S+)", raw)
        module = module_match.group(1) if module_match else _root_name(root)
        main_files = [
            item.path
            for item in inventory.records_under(root)
            if item.name == "main.go" and "/cmd/" in f"/{item.path}"
        ]
        command_name = PurePosixPath(main_files[0]).parent.name if len(main_files) == 1 else "app"
        candidates.append(
            Candidate(
                name=_root_name(root),
                root=root,
                language="go",
                framework="Go",
                build_method="auto",
                install_command=("go", "mod", "download"),
                build_command=("go", "build", "-trimpath", "-o", f"/out/{command_name}", "./..."),
                processes=(
                    ProcessProposal(
                        name="web",
                        kind="web",
                        command=(f"/app/{command_name}",),
                        port=8080,
                        health_path="/healthz",
                    ),
                ),
                confidence=0.91 if len(main_files) == 1 else 0.78,
                evidence=(
                    Evidence(
                        kind="manifest",
                        path=record.path,
                        detail=f"Go module {module} declares a build root",
                        weight=0.9,
                    ),
                ),
                unsupported_features=(),
                files_considered=(record.path, *sorted(main_files)),
                ambiguous=len(main_files) != 1,
            )
        )
    return candidates


def detect_static(inventory: SnapshotInventory) -> list[Candidate]:
    """Detect plain static sites that have no stronger manifest at the same root."""
    manifest_roots = {
        record.parent
        for record in inventory.records_named(
            "package.json", "Gemfile", "pyproject.toml", "requirements.txt", "go.mod"
        )
    }
    candidates: list[Candidate] = []
    for record in inventory.records_named("index.html"):
        if record.parent in manifest_roots:
            continue
        candidates.append(
            Candidate(
                name=_root_name(record.parent),
                root=record.parent,
                language="static",
                framework="Static HTML",
                build_method="auto",
                install_command=(),
                build_command=(),
                processes=(ProcessProposal(name="web", kind="static", command=()),),
                confidence=0.88,
                evidence=(
                    Evidence(
                        kind="file",
                        path=record.path,
                        detail="index.html identifies a static publication root",
                        weight=0.88,
                    ),
                ),
                unsupported_features=(),
                files_considered=(record.path,),
            )
        )
    return candidates


def detect_docker(inventory: SnapshotInventory, warnings: list[str]) -> list[Candidate]:
    """Detect explicit Dockerfile builds and bounded runtime hints."""
    candidates: list[Candidate] = []
    dockerfiles = [
        record
        for record in inventory.files
        if record.name.casefold() == "dockerfile"
        or record.name.casefold().startswith("dockerfile.")
    ]
    for record in dockerfiles:
        raw = _read(inventory, record.path, warnings)
        if raw is None:
            continue
        expose = _DOCKER_EXPOSE.search(raw)
        port = int(expose.group("port")) if expose else 8080
        if port > MAX_PORT:
            warnings.append(f"Dockerfile exposes an invalid port: {record.path}")
            port = 8080
            expose = None
        command: tuple[str, ...] = ()
        command_match = _DOCKER_JSON_COMMAND.search(raw)
        if command_match:
            try:
                parsed = json.loads(command_match.group("value"))
                if isinstance(parsed, list) and all(isinstance(item, str) for item in parsed):
                    command = tuple(parsed[:64])
            except json.JSONDecodeError:
                warnings.append(f"Dockerfile command is not valid JSON array form: {record.path}")
        root = record.parent
        candidates.append(
            Candidate(
                name=_root_name(root),
                root=root,
                language="docker",
                framework="Dockerfile",
                build_method="dockerfile",
                install_command=(),
                build_command=("dockerfile", record.name),
                processes=(
                    ProcessProposal(
                        name="web",
                        kind="web",
                        command=command,
                        port=port,
                        health_path="/" if not _DOCKER_HEALTH.search(raw) else None,
                    ),
                ),
                confidence=0.99,
                evidence=(
                    Evidence(
                        kind="docker",
                        path=record.path,
                        detail="explicit Dockerfile controls the build",
                        weight=0.99,
                    ),
                ),
                unsupported_features=(),
                files_considered=(record.path,),
                ambiguous=not expose or not command,
            )
        )
    return candidates


def apply_docker_overrides(candidates: list[Candidate]) -> list[Candidate]:
    """Apply explicit Docker build intent to a detected framework at the same root."""
    docker_by_root = {
        candidate.root: candidate for candidate in candidates if candidate.language == "docker"
    }
    non_docker = [candidate for candidate in candidates if candidate.language != "docker"]
    result: list[Candidate] = []
    claimed: set[str] = set()
    for candidate in non_docker:
        docker = docker_by_root.get(candidate.root)
        if docker is None:
            result.append(candidate)
            continue
        claimed.add(candidate.root)
        result.append(
            replace(
                candidate,
                build_method="dockerfile",
                processes=docker.processes if not docker.ambiguous else candidate.processes,
                confidence=max(candidate.confidence, docker.confidence),
                evidence=(*candidate.evidence, *docker.evidence),
                files_considered=tuple(
                    sorted({*candidate.files_considered, *docker.files_considered})
                ),
                ambiguous=candidate.ambiguous or docker.ambiguous,
            )
        )
    result.extend(docker for root, docker in docker_by_root.items() if root not in claimed)
    return result
