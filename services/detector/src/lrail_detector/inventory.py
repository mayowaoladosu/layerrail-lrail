"""Bounded filesystem inventory with no symlink traversal or code execution."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

MAX_FILES = 50_000
MAX_DEPTH = 32
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_HEADER_BYTES = 64 * 1024
MAX_TOTAL_READ_BYTES = 16 * 1024 * 1024
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
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "pnpm-workspace.yaml",
        "yarn.lock",
        "bun.lock",
        "bun.lockb",
        "turbo.json",
        "nx.json",
        "gemfile",
        "gemfile.lock",
        ".ruby-version",
        "config.ru",
        "pyproject.toml",
        "requirements.txt",
        "requirements-dev.txt",
        "pipfile",
        "pipfile.lock",
        "poetry.lock",
        "uv.lock",
        ".python-version",
        "go.mod",
        "go.sum",
        "go.work",
        ".node-version",
        ".nvmrc",
        "dockerfile",
        "compose.yaml",
        "compose.yml",
        "docker-compose.yaml",
        "docker-compose.yml",
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
        "netlify.toml",
        "vercel.json",
    }
)


class InventoryError(ValueError):
    """Snapshot cannot be inventoried under detector safety limits."""


@dataclass(frozen=True, slots=True)
class FileRecord:
    """Safe file metadata relative to the immutable snapshot root."""

    path: str
    size: int
    mode: int

    @property
    def executable(self) -> bool:
        """Return whether any executable mode bit is set."""
        return bool(self.mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))

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
        self._snapshot_root = snapshot_root
        self.selected_root = selected_root
        self.files = files
        self._paths = frozenset(record.path for record in files)
        self._text_cache: dict[str, str] = {}
        self._header_cache: dict[str, str] = {}
        self._read_sizes: dict[str, int] = {}

    @classmethod
    def build(cls, snapshot_root: Path, selected_root: str = ".") -> SnapshotInventory:
        """Create a deterministic inventory without following any symlink."""
        if snapshot_root.is_symlink():
            msg = "snapshot root cannot be a symlink"
            raise InventoryError(msg)
        try:
            root = snapshot_root.resolve(strict=True)
        except FileNotFoundError as error:
            msg = "snapshot root does not exist"
            raise InventoryError(msg) from error
        except OSError as error:
            msg = "snapshot root cannot be resolved"
            raise InventoryError(msg) from error
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
        folded_paths: dict[str, str] = {}
        stack: list[tuple[Path, int]] = [(resolved_start, 0)]
        while stack:
            directory, depth = stack.pop()
            if depth > MAX_DEPTH:
                msg = f"snapshot directory depth exceeds {MAX_DEPTH}"
                raise InventoryError(msg)
            try:
                entries = sorted(
                    os.scandir(directory),
                    key=lambda entry: (entry.name.casefold(), entry.name),
                )
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
                metadata = entry.stat(follow_symlinks=False)
                folded = relative.casefold()
                if folded in folded_paths and folded_paths[folded] != relative:
                    msg = f"snapshot contains a case-colliding path: {relative}"
                    raise InventoryError(msg)
                folded_paths[folded] = relative
                files.append(
                    FileRecord(
                        path=relative,
                        size=metadata.st_size,
                        mode=stat.S_IMODE(metadata.st_mode),
                    )
                )
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
        if normalized != selected_root:
            msg = "selected root must use canonical POSIX spelling"
            raise InventoryError(msg)
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
        cached = self._text_cache.get(relative_path)
        if cached is not None:
            return cached
        if relative_path not in self._paths:
            msg = f"metadata file was not inventoried: {relative_path}"
            raise InventoryError(msg)
        name = PurePosixPath(relative_path).name.casefold()
        if name not in READABLE_METADATA and not name.startswith("dockerfile."):
            msg = f"file is not detector-readable metadata: {relative_path}"
            raise InventoryError(msg)
        target = self._snapshot_root.joinpath(*PurePosixPath(relative_path).parts)
        if target.is_symlink():
            msg = f"metadata symlink rejected: {relative_path}"
            raise InventoryError(msg)
        size = target.stat().st_size
        if size > MAX_METADATA_BYTES:
            msg = f"metadata file exceeds {MAX_METADATA_BYTES} bytes: {relative_path}"
            raise InventoryError(msg)
        resolved = target.resolve(strict=True)
        if self._snapshot_root not in resolved.parents:
            msg = f"metadata path escapes snapshot: {relative_path}"
            raise InventoryError(msg)
        self._reserve_read(relative_path, size)
        try:
            value = target.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            msg = f"metadata is not UTF-8: {relative_path}"
            raise InventoryError(msg) from error
        self._text_cache[relative_path] = value
        return value

    def read_header(self, relative_path: str) -> str:
        """Read only a bounded UTF-8 source header selected for static evidence."""
        cached_text = self._text_cache.get(relative_path)
        if cached_text is not None:
            return cached_text[:MAX_HEADER_BYTES]
        cached = self._header_cache.get(relative_path)
        if cached is not None:
            return cached
        if relative_path not in self._paths:
            msg = f"header file was not inventoried: {relative_path}"
            raise InventoryError(msg)
        suffix = PurePosixPath(relative_path).suffix.casefold()
        if suffix not in {".go", ".js", ".mjs", ".cjs", ".ts", ".py", ".rb", ".sh"}:
            msg = f"file is not detector-readable source metadata: {relative_path}"
            raise InventoryError(msg)
        target = self._snapshot_root.joinpath(*PurePosixPath(relative_path).parts)
        if target.is_symlink():
            msg = f"source header symlink rejected: {relative_path}"
            raise InventoryError(msg)
        resolved = target.resolve(strict=True)
        if self._snapshot_root not in resolved.parents:
            msg = f"source header escapes snapshot: {relative_path}"
            raise InventoryError(msg)
        with target.open("rb") as handle:
            raw = handle.read(MAX_HEADER_BYTES)
        self._reserve_read(relative_path, len(raw))
        try:
            value = raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        except UnicodeDecodeError as error:
            msg = f"source header is not UTF-8: {relative_path}"
            raise InventoryError(msg) from error
        self._header_cache[relative_path] = value
        return value

    @property
    def files_read(self) -> tuple[str, ...]:
        """Return every metadata path actually read, in canonical order."""
        return tuple(sorted(self._read_sizes))

    def _reserve_read(self, relative_path: str, size: int) -> None:
        previous = self._read_sizes.get(relative_path, 0)
        projected = sum(self._read_sizes.values()) - previous + max(previous, size)
        if projected > MAX_TOTAL_READ_BYTES:
            msg = f"detector metadata read budget exceeds {MAX_TOTAL_READ_BYTES} bytes"
            raise InventoryError(msg)
        self._read_sizes[relative_path] = max(previous, size)
