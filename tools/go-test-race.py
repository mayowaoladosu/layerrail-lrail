from __future__ import annotations

import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GO_IMAGE = (
    "golang:1.26.4-bookworm@"
    "sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b"
)


def main() -> int:
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
            "./...",
        ]
    else:
        command = ["go", "test", "-race", "./..."]
    result = subprocess.run(command, cwd=ROOT, check=False)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
