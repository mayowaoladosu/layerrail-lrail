from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = ROOT / "platform/kubernetes/build-cell/lab/versions.json"
EXPECTED_CONTEXT = "lrail-alpha"
KATA_PROBE = """apiVersion: v1
kind: Pod
metadata:
  name: lrail-mb-kata-probe
  namespace: default
  labels:
    dev.lrail/lab: mb
spec:
  runtimeClassName: kata-qemu
  restartPolicy: Never
  automountServiceAccountToken: false
  enableServiceLinks: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: proof
      image: alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
      command:
        - /bin/sh
        - -c
        - >-
          set -eu;
          test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token;
          test ! -S /var/run/docker.sock;
          test ! -S /run/containerd/containerd.sock;
          grep -q kata /proc/version || test -d /run/kata-containers;
          echo kata-qemu-ok;
          sleep 2
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      resources:
        requests:
          cpu: 10m
          memory: 16Mi
        limits:
          cpu: 100m
          memory: 64Mi
"""


class LabFailure(RuntimeError):
    pass


def command(
    *arguments: str, input_text: str | None = None, check: bool = True
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        list(arguments),
        cwd=ROOT,
        input=input_text,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    if check and result.returncode != 0:
        message = (result.stderr or result.stdout).strip()
        raise LabFailure(f"{arguments[0]} failed: {message[:2000]}")
    return result


def require_context() -> None:
    configured = json.loads(VERSIONS.read_text(encoding="utf-8"))
    if configured.get("cluster_context") != EXPECTED_CONTEXT:
        raise LabFailure("lab version record targets an unexpected cluster context")
    current = command("kubectl", "config", "current-context").stdout.strip()
    if current != EXPECTED_CONTEXT:
        raise LabFailure(
            f"refusing to mutate Kubernetes context {current!r}; expected {EXPECTED_CONTEXT!r}"
        )
    node = command(
        "kubectl", "get", "node", EXPECTED_CONTEXT, "-o", "name"
    ).stdout.strip()
    if node != f"node/{EXPECTED_CONTEXT}":
        raise LabFailure("expected minikube lab node is unavailable")


def delete_probe() -> None:
    command(
        "kubectl",
        "delete",
        "pod",
        "lrail-mb-kata-probe",
        "--ignore-not-found=true",
        "--wait=true",
        check=False,
    )


def kata_probe() -> None:
    require_context()
    runtime = command("kubectl", "get", "runtimeclass", "kata-qemu", "-o", "json")
    runtime_data = json.loads(runtime.stdout)
    if runtime_data.get("handler") != "kata-qemu":
        raise LabFailure("kata-qemu RuntimeClass handler is absent or changed")
    node_labels = json.loads(
        command("kubectl", "get", "node", EXPECTED_CONTEXT, "-o", "json").stdout
    )["metadata"]["labels"]
    if node_labels.get("katacontainers.io/kata-runtime") != "true":
        raise LabFailure("lab node is not marked ready by the Kata installer")

    delete_probe()
    command("kubectl", "apply", "-f", "-", input_text=KATA_PROBE)
    deadline = time.monotonic() + 180
    phase = ""
    message = ""
    try:
        while time.monotonic() < deadline:
            pod = json.loads(
                command(
                    "kubectl", "get", "pod", "lrail-mb-kata-probe", "-o", "json"
                ).stdout
            )
            phase = pod.get("status", {}).get("phase", "")
            statuses = pod.get("status", {}).get("containerStatuses", [])
            if phase == "Succeeded":
                logs = command("kubectl", "logs", "lrail-mb-kata-probe").stdout
                if logs.strip() != "kata-qemu-ok":
                    raise LabFailure(
                        "Kata probe completed without the expected guest proof"
                    )
                print(
                    "Kata qemu guest started without API token or host runtime sockets."
                )
                return
            if phase == "Failed":
                message = (
                    statuses[0]
                    .get("state", {})
                    .get("terminated", {})
                    .get("message", "")
                    if statuses
                    else ""
                )
                break
            events = command(
                "kubectl",
                "get",
                "events",
                "--field-selector=involvedObject.name=lrail-mb-kata-probe",
                "-o",
                "json",
                check=False,
            )
            if events.returncode == 0:
                items = json.loads(events.stdout).get("items", [])
                warnings = [item for item in items if item.get("type") == "Warning"]
                failures = [item.get("message", "") for item in warnings]
                if failures:
                    message = failures[-1]
                    if (
                        warnings[-1].get("reason") == "FailedCreatePodSandBox"
                        or "timed out connecting to vsock" in message
                    ):
                        break
            time.sleep(2)
        if "timed out connecting to vsock" in message:
            raise LabFailure(
                "Kata qemu launched but its guest agent did not boot over vsock; "
                "this Docker Desktop/WSL2 host does not currently satisfy nested-KVM M-B execution. "
                "Do not substitute gVisor or runc."
            )
        raise LabFailure(
            f"Kata probe did not succeed (phase={phase!r}, message={message[:512]!r})"
        )
    finally:
        delete_probe()


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] != "kata":
        sys.stderr.write("usage: mb_lab.py kata\n")
        return 2
    try:
        kata_probe()
    except (OSError, json.JSONDecodeError, LabFailure) as error:
        sys.stderr.write(f"M-B lab failed closed: {error}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
