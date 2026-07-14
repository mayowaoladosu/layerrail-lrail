from __future__ import annotations

import base64
import json
import re
import sys
import time

import mb_lab as lab

NAMESPACE = "lrail-build"
NAME = "lrail-runc-single-id-conformance"
INNER = """#!/bin/sh
set -eu
cd /work/bundle
exec /usr/bin/buildkit-runc --root /work/runc-state run lrail-probe
"""
CONFIG = {
    "ociVersion": "1.0.2",
    "process": {
        "terminal": False,
        "user": {"uid": 10001, "gid": 10001},
        "args": [
            "/bin/sh",
            "-ec",
            "printf 'probe uid=%s gid=%s\\n' \"$(id -u)\" \"$(id -g)\"; "
            "cat /proc/self/uid_map; cat /proc/self/gid_map; "
            "awk '/^(CapEff|NoNewPrivs):/{print}' /proc/self/status",
        ],
        "env": ["PATH=/bin", "LRAIL_ROOTLESSKIT_SINGLE_ID=true"],
        "cwd": "/",
        "capabilities": {
            "bounding": [],
            "effective": [],
            "inheritable": [],
            "permitted": [],
            "ambient": [],
        },
        "noNewPrivileges": True,
    },
    "root": {"path": "rootfs", "readonly": False},
    "hostname": "lrail-runc-probe",
    "mounts": [
        {
            "destination": "/proc",
            "type": "bind",
            "source": "/proc",
            "options": ["rbind"],
        },
        {
            "destination": "/dev",
            "type": "tmpfs",
            "source": "tmpfs",
            "options": ["nosuid", "strictatime", "mode=755", "size=65536k"],
        },
        {
            "destination": "/dev/pts",
            "type": "devpts",
            "source": "devpts",
            "options": [
                "nosuid",
                "noexec",
                "newinstance",
                "ptmxmode=0666",
                "mode=0620",
                "gid=10001",
            ],
        },
        {
            "destination": "/dev/shm",
            "type": "tmpfs",
            "source": "shm",
            "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"],
        },
    ],
    "linux": {
        "uidMappings": [{"containerID": 10001, "hostID": 0, "size": 1}],
        "gidMappings": [{"containerID": 10001, "hostID": 0, "size": 1}],
        "namespaces": [
            {"type": "network"},
            {"type": "ipc"},
            {"type": "uts"},
            {"type": "mount"},
            {"type": "user"},
        ],
        "maskedPaths": [],
        "readonlyPaths": [],
    },
}


def cleanup() -> None:
    for kind, name in (
        ("job", NAME),
        ("secret", f"{NAME}-tls"),
        ("serviceaccount", NAME),
    ):
        lab.command(
            "kubectl",
            "delete",
            kind,
            name,
            "-n",
            NAMESPACE,
            "--ignore-not-found=true",
            "--wait=true",
            check=False,
        )


def resource(worker: str) -> dict[str, object]:
    labels = {
        "app.kubernetes.io/name": "lrail-build-worker",
        "lrail.dev/assignment": NAME,
        "dev.lrail/lab": "runc-single-id-conformance",
    }
    profile = {"type": "RuntimeDefault"}
    apparmor = {"type": "RuntimeDefault"}
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": NAME, "namespace": NAMESPACE, "labels": labels},
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": 300,
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "serviceAccountName": NAME,
                    "restartPolicy": "Never",
                    "automountServiceAccountToken": False,
                    "enableServiceLinks": False,
                    "hostNetwork": False,
                    "hostPID": False,
                    "hostIPC": False,
                    "shareProcessNamespace": False,
                    "runtimeClassName": "kata-qemu",
                    "nodeSelector": {
                        "kubernetes.io/hostname": lab.EXPECTED_KATA_NODE,
                        "lrail.dev/kata": "true",
                        "lrail.dev/pool": "build",
                    },
                    "tolerations": [
                        {
                            "key": "lrail.dev/build",
                            "operator": "Equal",
                            "value": "true",
                            "effect": "NoSchedule",
                        }
                    ],
                    "imagePullSecrets": [{"name": "lrail-build-images"}],
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 1000,
                        "runAsGroup": 1000,
                        "fsGroup": 1000,
                        "fsGroupChangePolicy": "OnRootMismatch",
                        "seccompProfile": profile,
                        "appArmorProfile": apparmor,
                    },
                    "containers": [
                        {
                            "name": "buildkit",
                            "image": worker,
                            "imagePullPolicy": "IfNotPresent",
                            "command": ["/bin/sh", "-ec"],
                            "args": [
                                "mkdir -p /work/bundle/rootfs/bin /work/bundle/rootfs/lib "
                                "/work/bundle/rootfs/proc /work/bundle/rootfs/dev/pts "
                                "/work/bundle/rootfs/dev/shm /work/rootlesskit /work/tmp /work/run; "
                                "cp /bin/busybox /work/bundle/rootfs/bin/busybox; "
                                "for name in sh id cat awk; do ln -s busybox "
                                '"/work/bundle/rootfs/bin/$name"; done; '
                                "cp /lib/ld-musl-x86_64.so.1 "
                                "/work/bundle/rootfs/lib/ld-musl-x86_64.so.1; "
                                "cp /probe/config.json /work/bundle/config.json; "
                                "exec /usr/bin/rootlesskit --pidns --state-dir=/work/rootlesskit "
                                "/probe/inner.sh"
                            ],
                            "env": [
                                {"name": "LRAIL_ROOTLESSKIT_SINGLE_ID", "value": "true"},
                                {"name": "XDG_RUNTIME_DIR", "value": "/work/run"},
                                {"name": "TMPDIR", "value": "/work/tmp"},
                            ],
                            "securityContext": {
                                "runAsNonRoot": True,
                                "runAsUser": 1000,
                                "runAsGroup": 1000,
                                "privileged": False,
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                                "seccompProfile": profile,
                                "appArmorProfile": apparmor,
                            },
                            "resources": {
                                "requests": {
                                    "cpu": "100m",
                                    "memory": "128Mi",
                                    "ephemeral-storage": "64Mi",
                                },
                                "limits": {
                                    "cpu": "1",
                                    "memory": "512Mi",
                                    "ephemeral-storage": "256Mi",
                                },
                            },
                            "volumeMounts": [
                                {"name": "state", "mountPath": "/work"},
                                {"name": "tmp", "mountPath": "/tmp"},
                                {"name": "tls", "mountPath": "/probe", "readOnly": True},
                            ],
                        }
                    ],
                    "volumes": [
                        {"name": "state", "emptyDir": {"sizeLimit": "256Mi"}},
                        {
                            "name": "tmp",
                            "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"},
                        },
                        {
                            "name": "tls",
                            "secret": {
                                "secretName": f"{NAME}-tls",
                                "defaultMode": 0o555,
                            },
                        },
                    ],
                },
            },
        },
    }


def main() -> int:
    lab.require_context()
    versions = json.loads(lab.VERSIONS.read_text(encoding="utf-8"))
    worker = versions.get("lrail_images", {}).get("buildkit_worker", "")
    if not re.fullmatch(r"ghcr\.io/.+@sha256:[0-9a-f]{64}", worker):
        raise lab.LabFailure("lab worker image is not digest pinned")
    cleanup()
    try:
        lab.apply_resource(
            {
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {"name": NAME, "namespace": NAMESPACE},
                "automountServiceAccountToken": False,
            }
        )
        data = {
            "config.json": base64.b64encode(
                json.dumps(CONFIG, separators=(",", ":")).encode()
            ).decode(),
            "inner.sh": base64.b64encode(INNER.encode()).decode(),
        }
        lab.apply_resource(
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": f"{NAME}-tls", "namespace": NAMESPACE},
                "type": "Opaque",
                "data": data,
            }
        )
        lab.apply_resource(resource(worker))
        deadline = time.monotonic() + 300
        status: dict[str, object] = {}
        while time.monotonic() < deadline:
            status = json.loads(
                lab.command(
                    "kubectl", "get", "job", NAME, "-n", NAMESPACE, "-o", "json"
                ).stdout
            ).get("status", {})
            if status.get("succeeded") == 1 or int(status.get("failed", 0)) >= 1:
                break
            time.sleep(0.5)
        logs = lab.command(
            "kubectl", "logs", f"job/{NAME}", "-n", NAMESPACE, check=False
        ).stdout
        map_lines = re.findall(r"(?m)^\s*10001\s+0\s+1\s*$", logs)
        if (
            status.get("succeeded") != 1
            or "probe uid=10001 gid=10001" not in logs
            or len(map_lines) != 2
            or not re.search(r"(?m)^CapEff:\s+0000000000000000$", logs)
            or not re.search(r"(?m)^NoNewPrivs:\s+1$", logs)
        ):
            raise lab.LabFailure(f"strict runc conformance failed: {logs[-1000:]}")
        print(
            json.dumps(
                {
                    "runtime": "kata-qemu",
                    "worker": worker,
                    "rootlesskit_pid_namespace": True,
                    "oci_pid_namespace": False,
                    "uid_gid": "10001:10001",
                    "uid_gid_maps": 2,
                    "cap_eff": "0",
                    "no_new_privileges": 1,
                    "api_token": False,
                    "pod_capabilities": [],
                },
                separators=(",", ":"),
            )
        )
        return 0
    finally:
        cleanup()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, json.JSONDecodeError, lab.LabFailure) as error:
        sys.stderr.write(f"M-B runc probe failed closed: {error}\n")
        raise SystemExit(1)
