from __future__ import annotations

import json
import subprocess
import sys

UPSTREAM = (
    "docker.io/library/golang:1.26.5-alpine@"
    "sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2"
)
PROBE_FILES = (
    "/usr/local/go/bin/go",
    "/bin/busybox",
    "/etc/alpine-release",
)


def command(*arguments: str) -> str:
    return subprocess.run(
        arguments,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    ).stdout


def inspect(reference: str) -> dict[str, object]:
    images = json.loads(command("docker", "image", "inspect", reference))
    if len(images) != 1:
        raise ValueError("image inspection did not return exactly one image")
    return images[0]


def checksums(reference: str) -> str:
    return command(
        "docker",
        "run",
        "--rm",
        "--entrypoint",
        "/bin/sh",
        reference,
        "-c",
        "sha256sum " + " ".join(PROBE_FILES),
    )


def main() -> int:
    if len(sys.argv) != 2:
        sys.stderr.write("usage: verify-go-base.py IMAGE\n")
        return 2
    candidate = inspect(sys.argv[1])
    upstream = inspect(UPSTREAM)
    layers = candidate.get("RootFS", {}).get("Layers", [])
    if len(layers) != 1:
        raise ValueError(f"flattened base has {len(layers)} filesystem layers")
    for field in ("Env", "Cmd", "Entrypoint", "WorkingDir", "User"):
        expected = upstream.get("Config", {}).get(field)
        actual = candidate.get("Config", {}).get(field)
        if actual != expected:
            raise ValueError(
                f"flattened base config {field} differs: expected {expected!r}, got {actual!r}"
            )
    for field in ("Architecture", "Os"):
        if candidate.get(field) != upstream.get(field):
            raise ValueError(f"flattened base {field} differs from upstream")
    if checksums(sys.argv[1]) != checksums(UPSTREAM):
        raise ValueError("flattened base toolchain bytes differ from upstream")
    print("Flattened Go base preserves one layer, upstream config, and toolchain bytes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())