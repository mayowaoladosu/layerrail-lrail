"""Shared pure helpers for private detector plugin adapters."""

from __future__ import annotations

import re
import shlex
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from lrail_detector.inventory import InventoryError
from lrail_detector.plugins.base import DetectionContext, diagnostic

if TYPE_CHECKING:
    from lrail_detector.models import Diagnostic

_SLUG_UNSAFE = re.compile(r"[^a-z0-9-]+")
_SHELL_CONTROL = re.compile(r"(?:&&|\|\||[&|;<>`$])")
MAX_COMMAND_ARGS = 64
MAX_ARGUMENT_BYTES = 4096


def slug(value: str, fallback: str = "app") -> str:
    """Create a stable manifest-safe name from declared metadata."""
    normalized = value.casefold().replace("_", "-").replace("/", "-")
    normalized = _SLUG_UNSAFE.sub("-", normalized).strip("-")
    normalized = re.sub(r"-{2,}", "-", normalized)
    if not normalized or not normalized[0].isalpha():
        normalized = f"app-{normalized}" if normalized else fallback
    return normalized[:63].rstrip("-") or fallback


def root_name(root: str) -> str:
    """Return a stable service name for one repository root."""
    return "app" if root == "." else slug(PurePosixPath(root).name)


def join(root: str, name: str) -> str:
    """Join a service root and one known relative metadata filename."""
    return name if root == "." else f"{root}/{name}"


def read_text(
    context: DetectionContext,
    path: str,
    *,
    detector: str,
    root: str,
) -> tuple[str | None, Diagnostic | None]:
    """Read bounded allowlisted metadata and normalize failures to diagnostics."""
    try:
        return context.inventory.read_text(path), None
    except InventoryError as error:
        return None, diagnostic(
            "metadata.unreadable",
            str(error),
            blocking=True,
            path=path,
            root=root,
            detector=detector,
        )


def read_header(
    context: DetectionContext,
    path: str,
    *,
    detector: str,
    root: str,
) -> tuple[str | None, Diagnostic | None]:
    """Read one selected source header and normalize failures."""
    try:
        return context.inventory.read_header(path), None
    except InventoryError as error:
        return None, diagnostic(
            "metadata.unreadable-header",
            str(error),
            blocking=True,
            path=path,
            root=root,
            detector=detector,
        )


def runtime_file(
    context: DetectionContext,
    root: str,
    names: tuple[str, ...],
    *,
    detector: str,
) -> tuple[str | None, str | None, tuple[Diagnostic, ...]]:
    """Read the first explicit runtime-version file at one root."""
    warnings: list[Diagnostic] = []
    for name in names:
        path = join(root, name)
        if not context.inventory.contains(path):
            continue
        raw, warning = read_text(context, path, detector=detector, root=root)
        if warning:
            warnings.append(warning)
            continue
        if raw is None:
            continue
        value = raw.strip().splitlines()[0].strip() if raw.strip() else ""
        if value:
            return value[:64], path, tuple(warnings)
        warnings.append(
            diagnostic(
                "runtime.empty-version",
                f"Runtime version file is empty: {path}",
                blocking=False,
                path=path,
                root=root,
                detector=detector,
            )
        )
    return None, None, tuple(warnings)


def parse_procfile(
    raw: str,
    *,
    path: str,
    root: str,
    detector: str,
) -> tuple[dict[str, tuple[str, ...]], tuple[Diagnostic, ...]]:
    """Parse bounded Procfile argv only when no shell operators are present."""
    commands: dict[str, tuple[str, ...]] = {}
    warnings: list[Diagnostic] = []
    for line_number, line in enumerate(raw.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        name, separator, command = stripped.partition(":")
        if not separator or not re.fullmatch(r"[a-z][a-z0-9_-]{0,62}", name):
            warnings.append(
                diagnostic(
                    "procfile.invalid-entry",
                    f"Procfile entry {line_number} has no valid process name",
                    blocking=True,
                    path=path,
                    root=root,
                    detector=detector,
                )
            )
            continue
        if _SHELL_CONTROL.search(command):
            warnings.append(
                diagnostic(
                    "procfile.shell-command",
                    f"Procfile entry {name} requires explicit review because "
                    "it uses shell operators",
                    blocking=True,
                    path=path,
                    root=root,
                    detector=detector,
                )
            )
            continue
        try:
            arguments = tuple(shlex.split(command, posix=True))
        except ValueError:
            arguments = ()
        if (
            not arguments
            or len(arguments) > MAX_COMMAND_ARGS
            or any(len(item) > MAX_ARGUMENT_BYTES for item in arguments)
        ):
            warnings.append(
                diagnostic(
                    "procfile.invalid-command",
                    f"Procfile entry {name} does not contain bounded argv",
                    blocking=True,
                    path=path,
                    root=root,
                    detector=detector,
                )
            )
            continue
        commands[name.replace("_", "-")] = arguments
    return commands, tuple(warnings)


def workspace_files(context: DetectionContext, root: str) -> tuple[str, ...]:
    """Return exact declarations proving one package is a workspace member."""
    return context.workspaces.declaration_paths(root)
