"""Ruby, Rails, Rack, Sinatra, Roda, and worker detector plugin."""

from __future__ import annotations

import re

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
from lrail_detector.plugins.helpers import join, parse_procfile, root_name, runtime_file

_GEM = re.compile(r"\bgem\s*[\( ]?\s*['\"](?P<name>[a-zA-Z0-9_-]+)")
_RUBY_LOCK_VERSION = re.compile(r"(?ms)^RUBY VERSION\s+\n\s+ruby\s+(?P<version>[^\s]+)")
_ADDONS: tuple[tuple[frozenset[str], AddonEngine, str], ...] = (
    (frozenset({"pg"}), "postgresql", "database adapter"),
    (frozenset({"mysql2"}), "mysql", "database adapter"),
    (frozenset({"redis", "redis-client", "sidekiq"}), "valkey", "cache or queue adapter"),
    (frozenset({"mongoid"}), "mongodb", "document database adapter"),
    (frozenset({"bunny"}), "rabbitmq", "message queue adapter"),
)


class RubyPlugin:
    """Detect Ruby web and worker processes from declared bundle metadata."""

    descriptor = PluginVersion(plugin="ruby", version="1.0.0")

    def detect(self, context: DetectionContext) -> PluginResult:
        """Return Ruby candidates without evaluating Gemfiles or requiring project code."""
        candidates: list[Candidate] = []
        warnings: list[Diagnostic] = []
        for record in context.inventory.records_named("Gemfile"):
            try:
                raw = context.inventory.read_text(record.path)
            except ValueError as error:
                warnings.append(
                    diagnostic(
                        "ruby.unreadable-gemfile",
                        str(error),
                        blocking=False,
                        path=record.path,
                        root=record.parent,
                        detector="ruby",
                    )
                )
                continue
            candidate = self._candidate(context, record.path, record.parent, raw)
            if candidate:
                candidates.append(candidate)
        return PluginResult(candidates=tuple(candidates), warnings=tuple(warnings))

    def _candidate(
        self,
        context: DetectionContext,
        manifest: str,
        root: str,
        raw: str,
    ) -> Candidate | None:
        gems = {match.group("name").casefold() for match in _GEM.finditer(raw)}
        rails = "rails" in gems or context.inventory.contains(join(root, "config/application.rb"))
        sinatra = "sinatra" in gems
        roda = "roda" in gems
        rack = "rack" in gems or context.inventory.contains(join(root, "config.ru"))
        worker_only = "sidekiq" in gems and not any((rails, sinatra, roda, rack))
        if not any((rails, sinatra, roda, rack, worker_only)):
            return None

        framework = (
            "Rails"
            if rails
            else "Sinatra"
            if sinatra
            else "Roda"
            if roda
            else "Rack"
            if rack
            else "Sidekiq"
        )
        delta = {
            "Rails": 0.48,
            "Sinatra": 0.42,
            "Roda": 0.42,
            "Rack": 0.38,
            "Sidekiq": 0.36,
        }[framework]
        evidence_nodes = [
            evidence(
                "ruby",
                "ruby.framework-gem",
                manifest,
                f"Gemfile declarations identify {framework}",
                delta,
            )
        ]
        unresolved = []
        warnings: list[Diagnostic] = []
        if sum((rails, sinatra, roda)) > 1:
            unresolved.append(
                diagnostic(
                    "ruby.multiple-frameworks",
                    "Multiple Ruby frameworks share one service root",
                    blocking=True,
                    path=manifest,
                    root=root,
                    detector="ruby",
                )
            )

        lockfile = join(root, "Gemfile.lock")
        files = {manifest}
        required = {manifest}
        if context.inventory.contains(lockfile):
            files.add(lockfile)
            required.add(lockfile)
            evidence_nodes.append(
                evidence(
                    "ruby",
                    "ruby.bundle-lock",
                    lockfile,
                    "Gemfile.lock supplies a reproducible bundle",
                    0.01,
                )
            )
        else:
            unresolved.append(
                diagnostic(
                    "ruby.missing-lockfile",
                    "A deployable Ruby proposal requires Gemfile.lock",
                    blocking=True,
                    path=manifest,
                    root=root,
                    detector="ruby",
                )
            )

        runtime_version, runtime_source, runtime_warnings = runtime_file(
            context,
            root,
            (".ruby-version",),
            detector="ruby",
        )
        warnings.extend(runtime_warnings)
        if runtime_version is None and context.inventory.contains(lockfile):
            try:
                lock = context.inventory.read_text(lockfile)
            except ValueError:
                lock = ""
            match = _RUBY_LOCK_VERSION.search(lock)
            if match:
                runtime_version = match.group("version")[:64]
                runtime_source = lockfile
        if runtime_source:
            files.add(runtime_source)
            required.add(runtime_source)

        processes: list[ProcessProposal] = []
        procfile = join(root, "Procfile")
        if context.inventory.contains(procfile):
            files.add(procfile)
            required.add(procfile)
            try:
                procfile_raw = context.inventory.read_text(procfile)
            except ValueError as error:
                unresolved.append(
                    diagnostic(
                        "ruby.unreadable-procfile",
                        str(error),
                        blocking=True,
                        path=procfile,
                        root=root,
                        detector="ruby",
                    )
                )
                procfile_raw = ""
            commands, procfile_warnings = parse_procfile(
                procfile_raw,
                path=procfile,
                root=root,
                detector="ruby",
            )
            unresolved.extend(procfile_warnings)
            for name, command in sorted(commands.items()):
                kind = _process_kind(name)
                processes.append(
                    ProcessProposal(
                        name=name,
                        kind=kind,
                        command=command,
                        port=3000 if kind == "web" else None,
                        protocol="http" if kind == "web" else "none",
                        health_path=(
                            "/up" if kind == "web" and rails else "/" if kind == "web" else None
                        ),
                    )
                )
                evidence_nodes.append(
                    evidence(
                        "ruby",
                        "ruby.procfile-process",
                        procfile,
                        f"Procfile declares {name} as {kind}",
                        0.0,
                    )
                )

        if not processes:
            if worker_only:
                processes.append(
                    ProcessProposal(
                        name="worker",
                        kind="worker",
                        command=("bundle", "exec", "sidekiq"),
                    )
                )
            else:
                processes.append(
                    ProcessProposal(
                        name="web",
                        kind="web",
                        command=_web_command(framework),
                        port=3000,
                        protocol="http",
                        health_path="/up" if rails else "/",
                    )
                )
                if "sidekiq" in gems:
                    processes.append(
                        ProcessProposal(
                            name="worker",
                            kind="worker",
                            command=("bundle", "exec", "sidekiq"),
                        )
                    )
                if rails and gems & {"pg", "mysql2"}:
                    processes.append(
                        ProcessProposal(
                            name="release",
                            kind="release",
                            command=("bundle", "exec", "rails", "db:prepare"),
                        )
                    )

        addons: list[AddonRequest] = []
        for names, engine, reason in _ADDONS:
            matched = sorted(names & gems)
            if not matched:
                continue
            node = evidence(
                "ruby",
                f"ruby.addon-{engine}",
                manifest,
                f"Gems {', '.join(matched)} suggest {engine}",
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

        service_kind: ServiceKind = (
            "worker"
            if all(process.kind in {"worker", "job", "release"} for process in processes)
            else "web"
        )
        return Candidate(
            name=root_name(root),
            root=root,
            kind=service_kind,
            language="ruby",
            framework=framework,
            runtime=RuntimeProposal(
                name="ruby",
                version=runtime_version,
                version_source=runtime_source,
            ),
            build=BuildProposal(
                strategy="auto",
                install_command=("bundle", "install", "--deployment"),
                build_command=("bin/rails", "assets:precompile") if rails else (),
                output_path=join(root, "public/assets") if rails else None,
                cache_paths=(join(root, "vendor/bundle"),),
                required_files=tuple(sorted(required)),
            ),
            processes=tuple(processes),
            evidence=tuple(evidence_nodes),
            unsupported_features=(),
            files_considered=tuple(sorted(files)),
            addons=tuple(addons),
            warnings=tuple(warnings),
            unresolved=tuple(unresolved),
            ambiguous=bool(unresolved),
        )


def _web_command(framework: str) -> tuple[str, ...]:
    if framework == "Rails":
        return ("bundle", "exec", "rails", "server", "-b", "0.0.0.0", "-p", "3000")
    return ("bundle", "exec", "rackup", "-o", "0.0.0.0", "-p", "3000")


def _process_kind(name: str) -> ProcessKind:
    if name == "web":
        return "web"
    if name == "release":
        return "release"
    if name in {"job", "scheduler"}:
        return "job"
    return "worker"
