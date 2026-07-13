from __future__ import annotations

import hashlib
import os
import platform
import stat
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "v3.1.1"
MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024
ASSETS = {
    ("darwin", "amd64"): (
        "cosign-darwin-amd64",
        "14d2678dfbfde18798151e86fbd91ebdadbb7424b18412a42a155dd8a2df4c7a",
    ),
    ("darwin", "arm64"): (
        "cosign-darwin-arm64",
        "94b42a9e697be95675f6160ab031a9a5f1ec1e646d6f648d7b2f5cd59ececbc5",
    ),
    ("linux", "amd64"): (
        "cosign-linux-amd64",
        "ae1ecd212663f3693ad9edf8b1a183900c9a52d3155ba6e354237f9a0f6463fc",
    ),
    ("linux", "arm64"): (
        "cosign-linux-arm64",
        "2ec865872e331c32fd12b08dae15332d3f92c0aa029219589684a4903ca85d11",
    ),
    ("windows", "amd64"): (
        "cosign-windows-amd64.exe",
        "9d2c026e667bfd979fa7ba1cab8c4b24d2e73f336ec2d57f7fc72c7e73e5b4b6",
    ),
}


def normalized_platform() -> tuple[str, str]:
    operating_system = platform.system().lower()
    machine = platform.machine().lower()
    architectures = {
        "amd64": "amd64",
        "x86_64": "amd64",
        "arm64": "arm64",
        "aarch64": "arm64",
    }
    architecture = architectures.get(machine, machine)
    return operating_system, architecture


def digest(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def acquire(asset: str, expected_digest: str) -> Path:
    destination = ROOT / ".work" / "cosign-v3.1.1" / asset
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file() and digest(destination) == expected_digest:
        destination.chmod(destination.stat().st_mode | stat.S_IXUSR)
        return destination
    temporary = destination.with_suffix(destination.suffix + ".download")
    temporary.unlink(missing_ok=True)
    request = urllib.request.Request(
        f"https://github.com/sigstore/cosign/releases/download/{VERSION}/{asset}",
        headers={"User-Agent": "lrail-cosign-conformance/1"},
    )
    checksum = hashlib.sha256()
    size = 0
    try:
        with (
            urllib.request.urlopen(request, timeout=60) as response,
            temporary.open("xb") as output,
        ):
            if not response.geturl().startswith("https://"):
                raise RuntimeError("Cosign release redirect was not HTTPS")
            while block := response.read(1024 * 1024):
                size += len(block)
                if size > MAX_DOWNLOAD_BYTES:
                    raise RuntimeError("Cosign release asset exceeded size policy")
                checksum.update(block)
                output.write(block)
        if size == 0 or checksum.hexdigest() != expected_digest:
            raise RuntimeError("Cosign release checksum mismatch")
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    destination.chmod(destination.stat().st_mode | stat.S_IXUSR)
    return destination


def main() -> int:
    identity = normalized_platform()
    selected = ASSETS.get(identity)
    if selected is None:
        sys.stderr.write(f"No pinned Cosign verifier for {identity[0]}/{identity[1]}\n")
        return 2
    try:
        executable = acquire(*selected)
    except (OSError, RuntimeError) as error:
        sys.stderr.write(f"Cosign verifier acquisition failed: {error}\n")
        return 1
    version = subprocess.run(
        [str(executable), "version"], cwd=ROOT, check=False, text=True
    )
    if version.returncode != 0:
        return version.returncode
    environment = os.environ.copy()
    environment["LRAIL_REGISTRY_INTEGRATION"] = "1"
    environment["LRAIL_COSIGN_PATH"] = str(executable.resolve())
    result = subprocess.run(
        [
            "go",
            "test",
            "./services/build-plane/internal/buildregistry",
            "-run",
            "TestRealDistributionPublishesPullsAndDeduplicatesByDigest",
            "-count=1",
            "-v",
        ],
        cwd=ROOT,
        env=environment,
        check=False,
    )
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
