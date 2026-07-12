#!/usr/bin/env python3
"""Create a deterministic Rails PostgreSQL structure dump through local Compose."""

from __future__ import annotations

import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTROL_PLANE = ROOT / "apps" / "control-plane"
OUTPUT = CONTROL_PLANE / "db" / "structure.sql"
GRANTS = CONTROL_PLANE / "db" / "runtime_grants.sql"
DATABASE = "lrail_control_development"
DATABASE_USER = "lrail_local"
MARKER = "-- LRAIL_RUNTIME_GRANTS_BEGIN"


def run(*command: str, input_text: str | None = None) -> str:
    result = subprocess.run(
        command,
        cwd=ROOT,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise SystemExit(result.stderr or result.stdout)
    return result.stdout


def sanitize_dump(raw: str) -> str:
    lines = raw.replace("\r\n", "\n").splitlines()
    lines = [line for line in lines if not re.match(r"^\\(?:un)?restrict\b", line)]
    while lines and (not lines[0].strip() or lines[0].startswith("--")):
        lines.pop(0)
    return "\n".join(lines).rstrip()


def migration_versions() -> list[str]:
    return sorted(path.name.split("_", 1)[0] for path in (CONTROL_PLANE / "db" / "migrate").glob("*.rb"))


def schema_version_sql() -> str:
    values = ",\n".join(f"('{version}')" for version in migration_versions())
    return f'INSERT INTO "schema_migrations" (version) VALUES\n{values}\nON CONFLICT DO NOTHING;'


def main() -> None:
    container = run("docker", "compose", "ps", "-q", "postgres").strip()
    if not container:
        raise SystemExit("Compose PostgreSQL is not running")

    raw = run(
        "docker",
        "exec",
        container,
        "pg_dump",
        "--schema-only",
        "--no-privileges",
        "--no-owner",
        "--username",
        DATABASE_USER,
        DATABASE,
    )
    content = "\n\n".join(
        [
            sanitize_dump(raw),
            'SET search_path TO "$user", public;',
            schema_version_sql(),
            MARKER,
            GRANTS.read_text(encoding="utf-8").rstrip(),
        ]
    )
    OUTPUT.write_text(f"{content}\n", encoding="utf-8", newline="\n")
    print(f"Wrote {OUTPUT.relative_to(ROOT)} with {len(migration_versions())} migration versions")


if __name__ == "__main__":
    main()
