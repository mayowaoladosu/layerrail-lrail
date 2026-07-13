"""Node.js and TypeScript detector plugin."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from typing import Any

from lrail_detector.inventory import InventoryError
from lrail_detector.models import (
    BuildProposal,
    Diagnostic,
    PluginVersion,
    ProcessProposal,
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
from lrail_detector.plugins.helpers import join, root_name, runtime_file, slug, workspace_files


@dataclass(frozen=True, slots=True)
class Framework:
    """One declarative Node framework signature and default runtime shape."""

    name: str
    dependency: str
    delta: float
    kind: str
    port: int | None
    output: str | None
    health: str | None
    start_scripts: tuple[str, ...]


_FRAMEWORKS = (
    Framework("Next.js", "next", 0.36, "web", 3000, ".next", "/", ("start",)),
    Framework("Nuxt", "nuxt", 0.36, "web", 3000, ".output", "/", ("start", "preview")),
    Framework(
        "SvelteKit",
        "@sveltejs/kit",
        0.35,
        "web",
        3000,
        ".svelte-kit",
        "/",
        ("start", "preview"),
    ),
    Framework("Remix", "@remix-run/node", 0.34, "web", 3000, "build", "/", ("start",)),
    Framework("NestJS", "@nestjs/core", 0.34, "web", 3000, "dist", "/", ("start:prod", "start")),
    Framework("Fastify", "fastify", 0.29, "web", 3000, None, "/", ("start",)),
    Framework("Express", "express", 0.28, "web", 3000, None, "/", ("start",)),
    Framework("Hono", "hono", 0.27, "web", 3000, "dist", "/", ("start",)),
    Framework("Astro", "astro", 0.34, "static", None, "dist", None, ()),
    Framework("Gatsby", "gatsby", 0.33, "static", None, "public", None, ()),
    Framework("Vite", "vite", 0.30, "static", None, "dist", None, ()),
)
_LOCKS: dict[str, tuple[str, tuple[str, ...]]] = {
    "pnpm-lock.yaml": ("pnpm", ("pnpm", "install", "--frozen-lockfile")),
    "bun.lock": ("bun", ("bun", "install", "--frozen-lockfile")),
    "bun.lockb": ("bun", ("bun", "install", "--frozen-lockfile")),
    "yarn.lock": ("yarn", ("yarn", "install", "--immutable")),
    "package-lock.json": ("npm", ("npm", "ci")),
    "npm-shrinkwrap.json": ("npm", ("npm", "ci")),
}
_ADDONS: tuple[tuple[frozenset[str], str, str], ...] = (
    (frozenset({"pg", "postgres"}), "postgresql", "database dependency"),
    (frozenset({"mysql2"}), "mysql", "database dependency"),
    (frozenset({"ioredis", "redis", "bullmq"}), "valkey", "cache or queue dependency"),
    (frozenset({"mongodb", "mongoose"}), "mongodb", "document database dependency"),
    (frozenset({"amqplib"}), "rabbitmq", "message queue dependency"),
    (frozenset({"@clickhouse/client"}), "clickhouse", "analytics database dependency"),
)


class NodePlugin:
    """Detect Node services from package, lockfile, script, and workspace facts."""

    descriptor = PluginVersion(plugin="node", version="1.0.0")

    def detect(self, context: DetectionContext) -> PluginResult:
        """Return deterministic Node candidates without reading application modules."""
        candidates: list[Candidate] = []
        warnings = []
        for record in context.inventory.records_named("package.json"):
            try:
                raw = context.inventory.read_text(record.path)
                package = json.loads(raw)
            except (InventoryError, json.JSONDecodeError, RecursionError) as error:
                warnings.append(
                    diagnostic(
                        "node.invalid-package-json",
                        f"Cannot parse package metadata: {error}",
                        blocking=False,
                        path=record.path,
                        root=record.parent,
                        detector=self.descriptor.plugin,
                    )
                )
                continue
            if not isinstance(package, dict):
                warnings.append(
                    diagnostic(
                        "node.package-root-not-object",
                        "package.json root must be an object",
                        blocking=False,
                        path=record.path,
                        root=record.parent,
                        detector=self.descriptor.plugin,
                    )
                )
                continue
            candidate = self._candidate(context, record.path, record.parent, package)
            if candidate is not None:
                candidates.append(candidate)
        return PluginResult(
            candidates=tuple(candidates),
            warnings=tuple(warnings),
        )

    def _candidate(
        self,
        context: DetectionContext,
        manifest: str,
        root: str,
        package: dict[str, Any],
    ) -> Candidate | None:
        dependencies = _dependencies(package)
        scripts = _scripts(package)
        matches = [framework for framework in _FRAMEWORKS if framework.dependency in dependencies]
        runnable_scripts = ("build", "jobs", "queue", "start", "serve", "worker")
        if not matches and not any(name in scripts for name in runnable_scripts):
            return None

        evidence_nodes = [
            evidence(
                "node",
                "node.package-manifest",
                manifest,
                "package.json declares a runnable package root",
                0.12,
            )
        ]
        unresolved = []
        candidate_warnings: list[Diagnostic] = []
        worker_only = not matches and any(name in scripts for name in ("jobs", "queue", "worker"))
        framework = (
            matches[0]
            if matches
            else Framework(
                "Node.js",
                "scripts",
                0.10,
                "worker" if worker_only else "web",
                None if worker_only else 3000,
                None,
                None if worker_only else "/",
                ("jobs", "queue", "worker") if worker_only else ("start", "serve"),
            )
        )
        if framework.name == "SvelteKit":
            if "@sveltejs/adapter-static" in dependencies:
                framework = replace(
                    framework,
                    kind="static",
                    port=None,
                    output="build",
                    health=None,
                )
            elif "@sveltejs/adapter-node" not in dependencies:
                unresolved.append(
                    diagnostic(
                        "node.svelte-adapter-unresolved",
                        "SvelteKit requires an explicit node or static adapter",
                        blocking=True,
                        path=manifest,
                        root=root,
                        detector="node",
                    )
                )
        if matches:
            evidence_nodes.append(
                evidence(
                    "node",
                    "node.framework-dependency",
                    manifest,
                    f"Dependency {framework.dependency} identifies {framework.name}",
                    framework.delta,
                )
            )
        else:
            evidence_nodes.append(
                evidence(
                    "node",
                    "node.runnable-script",
                    manifest,
                    "Package scripts declare a production process",
                    framework.delta,
                )
            )
        if len(matches) > 1:
            unresolved.append(
                diagnostic(
                    "node.multiple-frameworks",
                    "Multiple server or static frameworks share one package root: "
                    + ", ".join(item.name for item in matches),
                    blocking=True,
                    path=manifest,
                    root=root,
                    detector="node",
                )
            )

        locks = context.workspaces.nearest_lockfiles(root, "node")
        manager = "npm"
        install: tuple[str, ...] = ("npm", "install")
        if len(locks) == 1:
            manager, install = _LOCKS[locks[0].rsplit("/", 1)[-1]]
            evidence_nodes.append(
                evidence(
                    "node",
                    "node.lockfile",
                    locks[0],
                    f"Lockfile selects reproducible {manager} installation",
                    0.04,
                )
            )
        elif len(locks) > 1:
            unresolved.append(
                diagnostic(
                    "node.conflicting-lockfiles",
                    "Multiple package-manager lockfiles exist at the same precedence: "
                    + ", ".join(locks),
                    blocking=True,
                    path=manifest,
                    root=root,
                    detector="node",
                )
            )
        else:
            unresolved.append(
                diagnostic(
                    "node.missing-lockfile",
                    "A frozen Node install requires exactly one supported lockfile",
                    blocking=True,
                    path=manifest,
                    root=root,
                    detector="node",
                )
            )

        workspace_declarations = workspace_files(context, root)
        if workspace_declarations:
            evidence_nodes.extend(
                (
                    evidence(
                        "node",
                        "node.workspace-membership",
                        path,
                        f"Workspace configuration declares package root {root}",
                        0.02,
                    )
                )
                for path in workspace_declarations
            )

        runtime_version, runtime_source, runtime_warnings = _node_runtime(context, root, package)
        candidate_warnings.extend(runtime_warnings)
        build_command = (manager, "run", "build") if "build" in scripts else ()
        output = join(root, framework.output) if framework.output else None
        processes: list[ProcessProposal] = []
        if framework.kind == "static":
            processes.append(
                ProcessProposal(
                    name="web",
                    kind="static",
                    command=(),
                    protocol="none",
                )
            )
            if "build" not in scripts:
                unresolved.append(
                    diagnostic(
                        "node.missing-static-build",
                        f"{framework.name} requires an explicit production build script",
                        blocking=True,
                        path=manifest,
                        root=root,
                        detector="node",
                    )
                )
        elif framework.kind == "worker":
            worker_script = next(name for name in framework.start_scripts if name in scripts)
            processes.append(
                ProcessProposal(
                    name=worker_script,
                    kind="worker",
                    command=(manager, "run", worker_script),
                )
            )
        else:
            start_script = next((name for name in framework.start_scripts if name in scripts), None)
            if start_script:
                command = (manager, "run", start_script)
                evidence_nodes.append(
                    evidence(
                        "node",
                        "node.start-script",
                        manifest,
                        f"Script {start_script} supplies the production entry point",
                        0.03,
                    )
                )
            else:
                command = (manager, "run", framework.start_scripts[0])
                unresolved.append(
                    diagnostic(
                        "node.missing-start-script",
                        f"{framework.name} has no explicit supported production start script",
                        blocking=True,
                        path=manifest,
                        root=root,
                        detector="node",
                    )
                )
            processes.append(
                ProcessProposal(
                    name="web",
                    kind="web",
                    command=command,
                    port=framework.port,
                    protocol="http",
                    health_path=framework.health,
                )
            )

        for script_name in () if framework.kind == "worker" else ("jobs", "queue", "worker"):
            if script_name in scripts:
                processes.append(
                    ProcessProposal(
                        name=script_name,
                        kind="worker",
                        command=(manager, "run", script_name),
                    )
                )
                evidence_nodes.append(
                    evidence(
                        "node",
                        "node.worker-script",
                        manifest,
                        f"Script {script_name} declares a background process",
                        0.01,
                    )
                )

        addons: list[AddonRequest] = []
        for names, engine, reason in _ADDONS:
            matched = sorted(names & dependencies)
            if not matched:
                continue
            node = evidence(
                "node",
                f"node.addon-{engine}",
                manifest,
                f"Dependencies {', '.join(matched)} suggest {engine}",
                0.0,
            )
            evidence_nodes.append(node)
            addons.append(
                AddonRequest(
                    engine=engine,  # type: ignore[arg-type]
                    reason=reason,
                    evidence_ids=(node.id,),
                )
            )

        unsupported = []
        if "electron" in dependencies:
            unsupported.append("desktop_runtime")
        if dependencies & {"node-gyp", "@mapbox/node-pre-gyp"}:
            unsupported.append("native_addon_requires_build_validation")
        if "@prisma/client" in dependencies and not dependencies & {"pg", "postgres", "mysql2"}:
            unsupported.append("database_provider_requires_confirmation")

        required = {manifest, *locks, *workspace_declarations}
        files = set(required)
        if runtime_source:
            required.add(runtime_source)
            files.add(runtime_source)
        package_name = package.get("name")
        name = slug(str(package_name), root_name(root)) if package_name else root_name(root)
        return Candidate(
            name=name,
            root=root,
            kind=(
                "static"
                if framework.kind == "static"
                else "worker"
                if framework.kind == "worker"
                else "web"
            ),
            language="node",
            framework=framework.name,
            runtime=RuntimeProposal(
                name="node",
                version=runtime_version,
                version_source=runtime_source,
            ),
            build=BuildProposal(
                strategy="auto",
                install_command=install,
                build_command=build_command,
                output_path=output,
                cache_paths=(join(root, "node_modules/.cache"),),
                required_files=tuple(sorted(required)),
            ),
            processes=tuple(processes),
            evidence=tuple(evidence_nodes),
            unsupported_features=tuple(sorted(unsupported)),
            files_considered=tuple(sorted(files)),
            dependency_roots=context.workspaces.dependency_roots(root),
            addons=tuple(addons),
            warnings=tuple(candidate_warnings),
            unresolved=tuple(unresolved),
            ambiguous=bool(unresolved),
        )


def _dependencies(package: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        declared = package.get(key, {})
        if isinstance(declared, dict):
            values.update(str(name) for name in declared)
    return values


def _scripts(package: dict[str, Any]) -> dict[str, str]:
    declared = package.get("scripts", {})
    if not isinstance(declared, dict):
        return {}
    return {str(name): value for name, value in declared.items() if isinstance(value, str)}


def _node_runtime(
    context: DetectionContext,
    root: str,
    package: dict[str, Any],
) -> tuple[str | None, str | None, tuple[Any, ...]]:
    engines = package.get("engines", {})
    if isinstance(engines, dict) and isinstance(engines.get("node"), str):
        return str(engines["node"])[:64], join(root, "package.json"), ()
    value, source, warnings = runtime_file(
        context,
        root,
        (".node-version", ".nvmrc"),
        detector="node",
    )
    if value or root == ".":
        return value, source, warnings
    inherited, inherited_source, inherited_warnings = runtime_file(
        context,
        ".",
        (".node-version", ".nvmrc"),
        detector="node",
    )
    return inherited, inherited_source, (*warnings, *inherited_warnings)
