from __future__ import annotations

import json
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Tool:
    name: str
    command: tuple[str, ...]
    expected: str
    required: bool = True


TOOLS = (
    Tool("git", ("git", "--version"), "2."),
    Tool("docker", ("docker", "--version"), "29."),
    Tool("ruby", ("ruby", "--version"), "3.4.", required=False),
    Tool("go", ("go", "version"), "go1.26."),
    Tool("python", ("python", "--version"), "3.14."),
    Tool("node", ("node", "--version"), "v24."),
    Tool("corepack", ("corepack", "--version"), "0."),
    Tool("mise", ("mise", "--version"), "2026."),
)


def run(command: tuple[str, ...]) -> tuple[bool, str]:
    executable = shutil.which(command[0])
    if executable is None:
        return False, "not found"
    windows = platform.system() == "Windows"
    invocation: str | tuple[str, ...] = (
        subprocess.list2cmdline(command) if windows else command
    )
    result = subprocess.run(
        invocation,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        shell=windows,
        timeout=15,
    )
    output = " ".join((result.stdout + result.stderr).split())
    return result.returncode == 0, output


def virtualization_check() -> tuple[bool, str]:
    ok, output = run(("docker", "info", "--format", "{{json .ServerVersion}}"))
    if not ok:
        return False, output
    try:
        version = json.loads(output)
    except json.JSONDecodeError:
        return False, f"unexpected Docker response: {output}"
    return True, f"Docker engine {version}"


def main() -> int:
    failures: list[str] = []
    warnings: list[str] = []
    print(f"Lrail doctor — {platform.system()} {platform.release()}")
    print(f"workspace: {ROOT}")

    for tool in TOOLS:
        ok, output = run(tool.command)
        if not ok:
            message = f"{tool.name}: {output}"
            (failures if tool.required else warnings).append(message)
            print(f"✗ {message}")
            continue

        version_ok = tool.expected in output
        marker = "✓" if version_ok else "!"
        print(f"{marker} {tool.name}: {output}")
        if not version_ok:
            message = f"{tool.name}: expected family {tool.expected}, got {output}"
            (failures if tool.required else warnings).append(message)

    docker_ok, docker_output = virtualization_check()
    print(f"{'✓' if docker_ok else '✗'} virtualization: {docker_output}")
    if not docker_ok:
        failures.append(f"virtualization: {docker_output}")

    ignored, ignored_output = run(
        ("git", "check-ignore", "Lrail_Owned_PaaS_Master_Engineering_Blueprint.docx")
    )
    if not ignored or not re.search(r"Blueprint\.docx$", ignored_output):
        failures.append("local blueprint is not protected by .gitignore")
        print("✗ source blueprint ignore guard")
    else:
        print("✓ source blueprint ignore guard")

    if warnings:
        print("\nWarnings (mise can supply the exact optional local runtime):")
        for warning in warnings:
            print(f"- {warning}")

    if failures:
        print("\nDoctor failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("\nEnvironment is ready.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
