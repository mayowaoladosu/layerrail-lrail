"""Deterministic workspace, package-root, lockfile, and dependency discovery."""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from lrail_detector.inventory import InventoryError, SnapshotInventory
from lrail_detector.models import Diagnostic, canonical_relative_path
from lrail_detector.plugins.base import diagnostic

_NODE_LOCKFILES = (
    "bun.lock",
    "bun.lockb",
    "npm-shrinkwrap.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
)
_PYTHON_LOCKFILES = ("Pipfile.lock", "poetry.lock", "uv.lock")
_GO_USE_LINE = re.compile(r"(?m)^\s*(?:use\s+)?(?P<path>\.?\.?/[A-Za-z0-9_./-]+)\s*$")
_PNPM_PACKAGE = re.compile(r"(?m)^\s*-\s*['\"]?(?P<pattern>[^'\"#\s]+)['\"]?\s*$")


@dataclass(frozen=True, slots=True)
class WorkspaceIndex:
    """Immutable repository workspace graph shared by all plugins."""

    package_roots: tuple[str, ...]
    files: tuple[str, ...]
    declared_roots: tuple[str, ...]
    declarations: tuple[tuple[str, tuple[str, ...]], ...]
    node_names: tuple[tuple[str, str], ...]
    dependencies: tuple[tuple[str, tuple[str, ...]], ...]

    @classmethod
    def discover(
        cls,
        inventory: SnapshotInventory,
    ) -> tuple[WorkspaceIndex, tuple[Diagnostic, ...]]:
        """Discover workspaces without globbing outside the bounded inventory."""
        warnings: list[Diagnostic] = []
        package_roots = {
            record.parent
            for record in inventory.records_named(
                "package.json",
                "Gemfile",
                "pyproject.toml",
                "requirements.txt",
                "Pipfile",
                "go.mod",
                "Dockerfile",
                "index.html",
            )
        }
        node_packages: dict[str, dict[str, object]] = {}
        node_name_to_root: dict[str, str] = {}
        declarations: dict[str, set[str]] = {}
        workspace_patterns: list[tuple[str, str, str]] = []

        for record in inventory.records_named("package.json"):
            try:
                raw = inventory.read_text(record.path)
                value = json.loads(raw)
            except (InventoryError, json.JSONDecodeError, RecursionError) as error:
                warnings.append(
                    diagnostic(
                        "workspace.invalid-package-json",
                        f"Cannot use package workspace metadata: {error}",
                        blocking=False,
                        path=record.path,
                        root=record.parent,
                        detector="workspace",
                    )
                )
                continue
            if not isinstance(value, dict):
                warnings.append(
                    diagnostic(
                        "workspace.package-root-not-object",
                        "package.json root must be an object",
                        blocking=False,
                        path=record.path,
                        root=record.parent,
                        detector="workspace",
                    )
                )
                continue
            node_packages[record.parent] = value
            name = value.get("name")
            if isinstance(name, str) and name:
                node_name_to_root[name] = record.parent
            patterns = value.get("workspaces", ())
            if isinstance(patterns, dict):
                patterns = patterns.get("packages", ())
            if isinstance(patterns, list):
                workspace_patterns.extend(
                    (record.parent, pattern, record.path)
                    for pattern in patterns
                    if isinstance(pattern, str)
                )

        for record in inventory.records_named("pnpm-workspace.yaml"):
            try:
                raw = inventory.read_text(record.path)
            except InventoryError as error:
                warnings.append(
                    diagnostic(
                        "workspace.unreadable-pnpm-workspace",
                        str(error),
                        blocking=False,
                        path=record.path,
                        root=record.parent,
                        detector="workspace",
                    )
                )
                continue
            workspace_patterns.extend(
                (record.parent, match.group("pattern"), record.path)
                for match in _PNPM_PACKAGE.finditer(raw)
            )

        declared: set[str] = set()
        node_roots = set(node_packages)
        for parent, pattern, declaration in sorted(workspace_patterns):
            normalized = _workspace_pattern(parent, pattern)
            if normalized is None:
                warnings.append(
                    diagnostic(
                        "workspace.unsafe-pattern",
                        f"Workspace pattern is unsupported or unsafe: {pattern}",
                        blocking=False,
                        path=declaration,
                        root=parent,
                        detector="workspace",
                    )
                )
                continue
            for root in sorted(node_roots):
                if root != parent and fnmatch.fnmatchcase(root, normalized):
                    declared.add(root)
                    declarations.setdefault(root, set()).add(declaration)

        for record in inventory.records_named("go.work"):
            try:
                raw = inventory.read_text(record.path)
            except InventoryError as error:
                warnings.append(
                    diagnostic(
                        "workspace.unreadable-go-work",
                        str(error),
                        blocking=False,
                        path=record.path,
                        root=record.parent,
                        detector="workspace",
                    )
                )
                continue
            for match in _GO_USE_LINE.finditer(raw):
                candidate = _resolve_declared_path(record.parent, match.group("path"))
                if candidate is None:
                    warnings.append(
                        diagnostic(
                            "workspace.unsafe-go-use",
                            f"go.work use path escapes the snapshot: {match.group('path')}",
                            blocking=False,
                            path=record.path,
                            root=record.parent,
                            detector="workspace",
                        )
                    )
                    continue
                if candidate in package_roots:
                    declared.add(candidate)
                    declarations.setdefault(candidate, set()).add(record.path)

        dependencies: dict[str, set[str]] = {}
        for root, package in node_packages.items():
            for key in ("dependencies", "devDependencies", "optionalDependencies"):
                values = package.get(key, {})
                if not isinstance(values, dict):
                    continue
                for dependency in values:
                    target = node_name_to_root.get(str(dependency))
                    if target and target != root:
                        dependencies.setdefault(root, set()).add(target)

        return (
            cls(
                package_roots=tuple(sorted(package_roots)),
                files=tuple(record.path for record in inventory.files),
                declared_roots=tuple(sorted(declared)),
                declarations=tuple(
                    (root, tuple(sorted(paths))) for root, paths in sorted(declarations.items())
                ),
                node_names=tuple(sorted((root, name) for name, root in node_name_to_root.items())),
                dependencies=tuple(
                    (root, tuple(sorted(values))) for root, values in sorted(dependencies.items())
                ),
            ),
            tuple(sorted(warnings, key=_diagnostic_key)),
        )

    def declaration_paths(self, root: str) -> tuple[str, ...]:
        """Return files that explicitly declare one package as a workspace member."""
        return dict(self.declarations).get(root, ())

    def dependency_roots(self, root: str) -> tuple[str, ...]:
        """Return internal package roots required by one package root."""
        return dict(self.dependencies).get(root, ())

    def node_package_name(self, root: str) -> str | None:
        """Return the declared package name for a Node root."""
        return dict(self.node_names).get(root)

    def nearest_lockfiles(self, root: str, ecosystem: str) -> tuple[str, ...]:
        """Find lockfiles at the service root or its nearest repository ancestor."""
        names = _NODE_LOCKFILES if ecosystem == "node" else _PYTHON_LOCKFILES
        current = root
        while True:
            found = tuple(
                sorted(
                    path
                    for name in names
                    if self._contains_at(current, name)
                    for path in (_join(current, name),)
                )
            )
            if found:
                return found
            if current == ".":
                return ()
            parent = str(PurePosixPath(current).parent)
            current = "." if parent == "." else parent

    def _contains_at(self, root: str, name: str) -> bool:
        return _join(root, name) in self._all_paths

    @property
    def _all_paths(self) -> frozenset[str]:
        """Return package/declaration paths used only for ancestry helpers."""
        return frozenset(self.files)


def _workspace_pattern(parent: str, pattern: str) -> str | None:
    if (
        not pattern
        or "\\" in pattern
        or pattern.startswith("/")
        or ".." in PurePosixPath(pattern).parts
    ):
        return None
    combined = pattern if parent == "." else f"{parent}/{pattern}"
    if any(character in combined for character in "?[]{}") or "**" in combined:
        return None
    return combined.rstrip("/")


def _resolve_declared_path(parent: str, value: str) -> str | None:
    combined = PurePosixPath(parent, value)
    parts: list[str] = []
    for part in combined.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
            continue
        parts.append(part)
    candidate = "/".join(parts) or "."
    return canonical_relative_path(candidate)


def _join(root: str, name: str) -> str:
    return name if root == "." else f"{root}/{name}"


def _diagnostic_key(value: Diagnostic) -> tuple[str, str, str, str]:
    return (value.code, value.service_root or "", value.path or "", value.message)
