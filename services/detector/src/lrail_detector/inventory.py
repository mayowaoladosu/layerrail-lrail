"""Bounded filesystem inventory with no symlink traversal or code execution."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

MAX_FILES = 50_000
MAX_DEPTH = 32
MAX_METADATA_BYTES = 2 * 1024 * 1024
SKIPPED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "__pycache__",
        "node_modules",
        "vendor",
        "target",
        "dist",
        "build",
        "coverage",
    }
)
READABLE_METADATA = frozenset(
    {
        "package.json",
        "gemfile",
        "gemfile.lock",
        "config.ru",
        "pyproject.toml",
        "requirements.txt",
        "requirements-dev.txt",
        "pipfile",
        "poetry.lock",
        "uv.lock",
        "go.mod",
        "go.work",
        "dockerfile",
        "procfile",
        "index.html",
        "manage.py",
        "main.py",
        "app.py",
        "wsgi.py",
        "asgi.py",
        "lrail.yaml",
        "lrail.yml",
        "lrailfile.star",
    }
)


class InventoryError(ValueError):
    """Snapshot cannot be inventoried under detector safety limits."""


@dataclass(frozen=True, slots=True)
class FileRecord:
    """Safe file metadata relative to the immutable snapshot root."""

    path: str
    size: int

    @property
    def name(self) -> str:
        """Return the final path component."""
        return PurePosixPath(self.path).name

    @property
    def parent(self) -> str:
        """Return a normalized repository-relative parent directory."""
        parent = str(PurePosixPath(self.path).parent)
        return "." if parent == "." else parent


class SnapshotInventory:
    """Read-only bounded view of an immutable source snapshot."""

    def __init__(
        self,
        snapshot_root: Path,
        selected_root: str,
        files: tuple[FileRecord, ...],
    ) -> None:
        """Store a prevalidated immutable file index."""
        self.snapshot_root = snapshot_root
        self.selected_root = selected_root
        self.files = files
        self._paths = frozenset(record.path for record in files)

    @classmethod
    def build(cls, snapshot_root: Path, selected_root: str = ".") -> SnapshotInventory:
        """Create a deterministic inventory without following any symlink."""
        if snapshot_root.is_symlink():
            msg = "snapshot root cannot be a symlink"
            raise InventoryError(msg)
        root = snapshot_root.resolve(strict=True)
        if not root.is_dir():
            msg = "snapshot root must be a directory"
            raise InventoryError(msg)
        normalized = cls._normalize_selected_root(selected_root)
        start = root if normalized == "." else root.joinpath(*PurePosixPath(normalized).parts)
        if start.is_symlink():
            msg = "selected root cannot be a symlink"
            raise InventoryError(msg)
        try:
            resolved_start = start.resolve(strict=True)
        except FileNotFoundError as error:
            msg = f"selected root does not exist: {normalized}"
            raise InventoryError(msg) from error
        if resolved_start != root and root not in resolved_start.parents:
            msg = "selected root escapes the snapshot"
            raise InventoryError(msg)
        if not resolved_start.is_dir() or resolved_start.is_symlink():
            msg = "selected root must be a real directory"
            raise InventoryError(msg)

        files: list[FileRecord] = []
        stack: list[tuple[Path, int]] = [(resolved_start, 0)]
        while stack:
            directory, depth = stack.pop()
            if depth > MAX_DEPTH:
                msg = f"snapshot directory depth exceeds {MAX_DEPTH}"
                raise InventoryError(msg)
            try:
                entries = sorted(os.scandir(directory), key=lambda entry: entry.name.casefold())
            except OSError as error:
                msg = f"cannot inventory {directory.relative_to(root).as_posix()}"
                raise InventoryError(msg) from error
            for entry in entries:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name.casefold() not in SKIPPED_DIRECTORIES:
                        stack.append((Path(entry.path), depth + 1))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                relative = Path(entry.path).relative_to(root).as_posix()
                size = entry.stat(follow_symlinks=False).st_size
                files.append(FileRecord(path=relative, size=size))
                if len(files) > MAX_FILES:
                    msg = f"snapshot file count exceeds {MAX_FILES}"
                    raise InventoryError(msg)

        files.sort(key=lambda record: record.path.casefold())
        return cls(root, normalized, tuple(files))

    @staticmethod
    def _normalize_selected_root(selected_root: str) -> str:
        if not selected_root or selected_root == ".":
            return "."
        if "\x00" in selected_root or "\\" in selected_root:
            msg = "selected root must be a repository-relative POSIX path"
            raise InventoryError(msg)
        candidate = PurePosixPath(selected_root)
        if candidate.is_absolute() or ".." in candidate.parts:
            msg = "selected root cannot be absolute or contain parent traversal"
            raise InventoryError(msg)
        normalized = str(candidate)
        if normalized in {"", "."}:
            return "."
        return normalized

    def contains(self, relative_path: str) -> bool:
        """Return whether an inventoried regular file exists."""
        return relative_path in self._paths

    def records_named(self, *names: str) -> tuple[FileRecord, ...]:
        """Return records whose basename case-insensitively matches a name."""
        expected = {name.casefold() for name in names}
        return tuple(record for record in self.files if record.name.casefold() in expected)

    def records_under(self, root: str) -> tuple[FileRecord, ...]:
        """Return files at or below one normalized service root."""
        if root == ".":
            return self.files
        prefix = f"{root.rstrip('/')}/"
        return tuple(record for record in self.files if record.path.startswith(prefix))

    def read_text(self, relative_path: str) -> str:
        """Read one allowlisted metadata file under the byte limit."""
        if relative_path not in self._paths:
            msg = f"metadata file was not inventoried: {relative_path}"
            raise InventoryError(msg)
        name = PurePosixPath(relative_path).name.casefold()
        if name not in READABLE_METADATA and not name.startswith("dockerfile."):
            msg = f"file is not detector-readable metadata: {relative_path}"
            raise InventoryError(msg)
        target = self.snapshot_root.joinpath(*PurePosixPath(relative_path).parts)
        if target.is_symlink():
            msg = f"metadata symlink rejected: {relative_path}"
            raise InventoryError(msg)
        size = target.stat().st_size
        if size > MAX_METADATA_BYTES:
            msg = f"metadata file exceeds {MAX_METADATA_BYTES} bytes: {relative_path}"
            raise InventoryError(msg)
        resolved = target.resolve(strict=True)
        if self.snapshot_root not in resolved.parents:
            msg = f"metadata path escapes snapshot: {relative_path}"
            raise InventoryError(msg)
        try:
            return target.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            msg = f"metadata is not UTF-8: {relative_path}"
            raise InventoryError(msg) from error
