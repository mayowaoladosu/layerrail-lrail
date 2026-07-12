from __future__ import annotations

import json
import socket
import subprocess
import sys
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]


def run(*command: str, capture: bool = False) -> str:
    result = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        capture_output=capture,
        text=True,
        timeout=600,
    )
    if result.returncode != 0:
        if capture:
            print(result.stdout, end="")
            print(result.stderr, end="", file=sys.stderr)
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}")
    return result.stdout if capture else ""


def probe_socket(host: str, port: int) -> None:
    with socket.create_connection((host, port), timeout=3):
        return


def probe_http(url: str) -> None:
    with urlopen(url, timeout=3) as response:  # noqa: S310 - fixed loopback URLs only
        if response.status != 200:
            raise RuntimeError(f"{url} returned HTTP {response.status}")


def main() -> int:
    try:
        run(sys.executable, "tools/validate-compose.py")
        run("docker", "compose", "config", "--quiet")
        run(
            "docker",
            "compose",
            "run",
            "--rm",
            "--no-deps",
            "nats",
            "-t",
            "-c",
            "/etc/nats/nats.conf",
        )
        run("docker", "compose", "up", "-d", "--wait")

        container_ids = run("docker", "compose", "ps", "-q", capture=True).split()
        if len(container_ids) != 6:
            raise RuntimeError(f"expected 6 local dependency containers, found {len(container_ids)}")
        for container_id in container_ids:
            inspection = json.loads(run("docker", "inspect", container_id, capture=True))[0]
            name = inspection["Name"].lstrip("/")
            state = inspection["State"]
            health = state.get("Health", {}).get("Status")
            if state["Status"] != "running" or health != "healthy":
                raise RuntimeError(f"{name} is {state['Status']}/{health}")
            print(f"✓ {name}: healthy")

        for port in (55432, 57233, 54222, 56379, 59000, 51025):
            probe_socket("127.0.0.1", port)
        for url in (
            "http://127.0.0.1:58222/healthz",
            "http://127.0.0.1:59000/minio/health/live",
            "http://127.0.0.1:58025/livez",
        ):
            probe_http(url)
        print("Local dependency cold-start and protocol probes passed.")
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Local stack verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
