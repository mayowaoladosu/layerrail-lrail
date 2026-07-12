from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "compose.yml"
LOCAL_BUILDS = {
    "lrail-source-gateway:local": ROOT / "services" / "source-plane" / "Dockerfile",
}


def main() -> int:
    text = COMPOSE.read_text(encoding="utf-8")
    failures: list[str] = []

    images = re.findall(r"^\s+image:\s+([^\s]+)\s*$", text, flags=re.MULTILINE)
    if not images:
        failures.append("no images found")
    local_images = 0
    for image in images:
        if image in LOCAL_BUILDS:
            local_images += 1
            dockerfile = LOCAL_BUILDS[image]
            base_images = re.findall(
                r"^FROM\s+([^\s]+)",
                dockerfile.read_text(encoding="utf-8"),
                flags=re.MULTILINE | re.IGNORECASE,
            )
            if not base_images or any("@sha256:" not in base for base in base_images):
                failures.append(f"local image has mutable Dockerfile base: {image}")
        elif ":latest" in image or "@sha256:" not in image:
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

    print(
        f"Validated {len(images) - local_images} immutable images, "
        f"{local_images} reproducible local build, and {len(published)} loopback ports."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
