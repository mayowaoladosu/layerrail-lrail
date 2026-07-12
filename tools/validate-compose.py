from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "compose.yml"


def main() -> int:
    text = COMPOSE.read_text(encoding="utf-8")
    failures: list[str] = []

    images = re.findall(r"^\s+image:\s+([^\s]+)\s*$", text, flags=re.MULTILINE)
    if not images:
        failures.append("no images found")
    for image in images:
        if ":latest" in image or "@sha256:" not in image:
            failures.append(f"image is not immutable: {image}")

    forbidden = {
        "privileged: true": "privileged container",
        "/var/run/docker.sock": "Docker socket mount",
        "network_mode: host": "host network",
        "0.0.0.0:": "non-loopback published port",
    }
    for needle, label in forbidden.items():
        if needle in text:
            failures.append(f"forbidden {label}")

    published = re.findall(r'^\s+-\s+"([^\"]+:[0-9]+)"\s*$', text, flags=re.MULTILINE)
    for port in published:
        if not port.startswith("127.0.0.1:"):
            failures.append(f"port does not bind loopback: {port}")

    if "local-only-not-a-secret" not in text:
        failures.append("development credentials are not unmistakably fake")

    if failures:
        print("Compose policy failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print(f"Validated {len(images)} immutable local images and {len(published)} loopback ports.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
