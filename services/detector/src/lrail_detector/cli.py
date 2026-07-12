"""Machine-readable detector command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from lrail_detector.engine import Detector

if TYPE_CHECKING:
    from collections.abc import Sequence


def parser() -> argparse.ArgumentParser:
    """Build the bounded detector CLI parser."""
    value = argparse.ArgumentParser(
        prog="lrail-detector",
        description="Inspect immutable source metadata without executing customer code.",
    )
    value.add_argument("snapshot", type=Path, help="validated immutable snapshot directory")
    value.add_argument("--root", default=".", help="repository-relative service or monorepo root")
    value.add_argument("--pretty", action="store_true", help="indent JSON output")
    value.add_argument(
        "--fail-on-block",
        action="store_true",
        help="exit with status 2 when user confirmation is required",
    )
    return value


def main(argv: Sequence[str] | None = None) -> int:
    """Detect and write exactly one JSON response to standard output."""
    arguments = parser().parse_args(argv)
    result = Detector().detect(arguments.snapshot, arguments.root)
    payload = result.model_dump_json(indent=2 if arguments.pretty else None)
    sys.stdout.write(f"{payload}\n")
    return 2 if arguments.fail_on_block and result.blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
