from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    tracked = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", "*.go"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    files = [value.decode() for value in tracked.split(b"\0") if value]
    result = subprocess.run(
        ["gofmt", "-l", *files],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        return result.returncode
    if result.stdout:
        sys.stderr.write("Go files require gofmt:\n")
        sys.stderr.write(result.stdout)
        return 1
    print(f"Validated gofmt for {len(files)} repository Go files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
