from __future__ import annotations

import copy
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

UPSTREAM = (
    "docker.io/library/golang:1.26.5-alpine@"
    "sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2"
)
LABELS = {
    "dev.lrail.upstream.reference": UPSTREAM,
    "org.opencontainers.image.licenses": "BSD-3-Clause AND MIT AND Apache-2.0",
    "org.opencontainers.image.source": (
        "https://github.com/mayowaoladosu/layerrail-lrail"
    ),
    "org.opencontainers.image.title": (
        "LayerRail flattened Go 1.26.5 Alpine build base"
    ),
}


def command(*arguments: str) -> str:
    return subprocess.run(
        arguments,
        check=True,
        capture_output=True,
        text=True,
        timeout=300,
    ).stdout


def image_archive(reference: str, destination: Path) -> None:
    command("docker", "image", "save", "--output", str(destination), reference)


def archive_config(
    archive: tarfile.TarFile, *, require_one_layer: bool = False
) -> tuple[dict[str, object], dict[str, object]]:
    manifest_file = archive.extractfile("manifest.json")
    if manifest_file is None:
        raise ValueError("image archive manifest is absent")
    manifests = json.load(manifest_file)
    if len(manifests) != 1:
        raise ValueError("image archive must contain exactly one image")
    if require_one_layer and len(manifests[0].get("Layers", [])) != 1:
        raise ValueError("rootfs image archive must contain exactly one layer")
    config_file = archive.extractfile(manifests[0]["Config"])
    if config_file is None:
        raise ValueError("image archive config is absent")
    return manifests[0], json.load(config_file)


def tar_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def add_bytes(archive: tarfile.TarFile, name: str, contents: bytes) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(contents)
    member.mode = 0o644
    member.mtime = 0
    archive.addfile(member, io.BytesIO(contents))


def main() -> int:
    if len(sys.argv) != 3:
        sys.stderr.write("usage: rewrite-go-base.py ROOTFS_IMAGE TARGET_IMAGE\n")
        return 2
    source_reference, target_reference = sys.argv[1:]
    with tempfile.TemporaryDirectory(prefix="lrail-go-base-") as temporary:
        root = Path(temporary)
        source_path = root / "source.tar"
        upstream_path = root / "upstream.tar"
        output_path = root / "rewritten.tar"
        image_archive(source_reference, source_path)
        image_archive(UPSTREAM, upstream_path)
        with tarfile.open(source_path, "r") as source, tarfile.open(
            upstream_path, "r"
        ) as upstream:
            source_manifest, source_config = archive_config(
                source, require_one_layer=True
            )
            _, upstream_config = archive_config(upstream)
            runtime = copy.deepcopy(upstream_config["config"])
            runtime["Labels"] = LABELS
            rewritten = {
                "architecture": upstream_config["architecture"],
                "config": runtime,
                "created": upstream_config["created"],
                "history": [
                    {
                        "created": upstream_config["created"],
                        "created_by": (
                            "LayerRail: flatten exact pinned upstream rootfs"
                        ),
                    }
                ],
                "os": upstream_config["os"],
                "rootfs": source_config["rootfs"],
            }
            config_bytes = tar_bytes(rewritten)
            config_name = hashlib.sha256(config_bytes).hexdigest() + ".json"
            manifest = [
                {
                    "Config": config_name,
                    "Layers": source_manifest["Layers"],
                    "RepoTags": [target_reference],
                }
            ]
            with tarfile.open(output_path, "w") as output:
                for layer_name in source_manifest["Layers"]:
                    member = source.getmember(layer_name)
                    contents = source.extractfile(member)
                    if contents is None:
                        raise ValueError("rootfs layer archive is unavailable")
                    output.addfile(member, contents)
                add_bytes(output, config_name, config_bytes)
                add_bytes(output, "manifest.json", tar_bytes(manifest))
        loaded = command("docker", "image", "load", "--input", str(output_path))
        if target_reference not in loaded:
            raise ValueError(
                f"rewritten image was not tagged as {target_reference}: {loaded.strip()}"
            )
    print("Rewrote upstream image config without adding a filesystem layer.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())