from __future__ import annotations

import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GO_IMAGE = (
    "golang:1.26.5-bookworm@"
    "sha256:18aedc16aa19b3fd7ded7245fc14b109e054d65d22ed53c355c899582bbb2113"
)


def main() -> int:
    packages = sys.argv[1:] or ["./..."]
    if platform.system() == "Windows":
        command = [
            "docker",
            "run",
            "--rm",
            "--mount",
            f"type=bind,source={ROOT},target=/workspace",
            "--mount",
            "type=volume,source=lrail-go-mod,target=/go/pkg/mod",
            "-w",
            "/workspace",
            GO_IMAGE,
            "go",
            "test",
            "-race",
            *packages,
        ]
    else:
        command = ["go", "test", "-race", *packages]
    result = subprocess.run(command, cwd=ROOT, check=False)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
