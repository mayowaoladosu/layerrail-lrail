from __future__ import annotations

import base64
import hashlib
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


def dependency_probe() -> None:
    require_context()
    configured = json.loads(VERSIONS.read_text(encoding="utf-8"))
    releases = {
        item["name"]: item
        for item in json.loads(command("helm", "list", "-A", "-o", "json").stdout)
    }
    expected_releases = {
        "cert-manager": (
            "cert-manager",
            "cert-manager-" + configured["dependencies"]["cert_manager"]["version"],
            configured["dependencies"]["cert_manager"]["version"],
        ),
        "kyverno": (
            "kyverno",
            "kyverno-" + configured["dependencies"]["kyverno"]["version"],
            "v" + configured["dependencies"]["kyverno"]["application_version"],
        ),
        "openbao": (
            "lrail-security",
            "openbao-" + configured["dependencies"]["openbao"]["version"],
            "v" + configured["dependencies"]["openbao"]["application_version"],
        ),
        "harbor": (
            "lrail-registry",
            "harbor-" + configured["dependencies"]["harbor"]["version"],
            configured["dependencies"]["harbor"]["application_version"],
        ),
        "kata-deploy": (
            "kata-system",
            "kata-deploy-" + configured["dependencies"]["kata"]["chart_version"],
            configured["dependencies"]["kata"]["chart_version"],
        ),
    }
    for name, (namespace, chart, application) in expected_releases.items():
        release = releases.get(name)
        if (
            not release
            or release.get("status") != "deployed"
            or release.get("namespace") != namespace
            or release.get("chart") != chart
            or release.get("app_version") != application
        ):
            raise LabFailure(f"Helm release {name!r} differs from the dependency lock")

    pods = json.loads(command("kubectl", "get", "pods", "-A", "-o", "json").stdout)[
        "items"
    ]
    observed_images: set[str] = set()
    for pod in pods:
        for status in pod.get("status", {}).get("containerStatuses", []):
            image_id = status.get("imageID", "").removeprefix("docker-pullable://")
            if image_id:
                observed_images.add(image_id)
    for name, image in configured["dependency_images"].items():
        if image not in observed_images:
            raise LabFailure(
                f"dependency image {name!r} does not match its runtime digest"
            )

    status = command(
        "kubectl",
        "exec",
        "-n",
        "lrail-security",
        "openbao-0",
        "--",
        "env",
        "BAO_ADDR=https://localhost:8200",
        "BAO_CACERT=/openbao/tls/ca.crt",
        "bao",
        "status",
        "-format=json",
    )
    openbao = json.loads(status.stdout)
    if not openbao.get("initialized") or openbao.get("sealed"):
        raise LabFailure("OpenBao is not initialized and unsealed")

    expected_jobs = {
        ("lrail-storage", "lrail-minio-init"): "",
        ("lrail-storage", "lrail-minio-conformance"): "object-capabilities-ok",
        ("lrail-registry", "harbor-conformance"): "harbor-tls-auth-challenge-ok",
    }
    for (namespace, name), expected_log in expected_jobs.items():
        job = json.loads(
            command("kubectl", "get", "job", name, "-n", namespace, "-o", "json").stdout
        )
        if job.get("status", {}).get("succeeded") != 1:
            raise LabFailure(
                f"dependency conformance job {namespace}/{name} is not complete"
            )
        if expected_log:
            logs = command("kubectl", "logs", f"job/{name}", "-n", namespace).stdout
            if expected_log not in logs:
                raise LabFailure(
                    f"dependency conformance job {namespace}/{name} lacks proof"
                )
    print(
        "Pinned PKI, policy, OpenBao, Harbor, and object-store dependencies verified."
    )


def secret_value(namespace: str, name: str, key: str) -> bytes:
    secret = json.loads(
        command("kubectl", "get", "secret", name, "-n", namespace, "-o", "json").stdout
    )
    encoded = secret.get("data", {}).get(key)
    if not encoded:
        raise LabFailure(f"runtime secret {namespace}/{name} lacks {key}")
    try:
        return base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise LabFailure(
            f"runtime secret {namespace}/{name} contains invalid data"
        ) from error


def apply_resource(resource: dict[str, object]) -> None:
    command("kubectl", "apply", "-f", "-", input_text=json.dumps(resource))


def config_map(namespace: str, name: str, data: dict[str, str]) -> None:
    apply_resource(
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "labels": {"dev.lrail/lab": "mb-functional-gvisor"},
            },
            "data": data,
        }
    )


def opaque_secret(namespace: str, name: str, data: dict[str, bytes]) -> None:
    apply_resource(
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "labels": {"dev.lrail/lab": "mb-functional-gvisor"},
            },
            "type": "Opaque",
            "data": {
                key: base64.b64encode(value).decode("ascii")
                for key, value in data.items()
            },
        }
    )


def image_pull_secret(namespace: str, username: str, token: str) -> None:
    authorization = base64.b64encode(f"{username}:{token}".encode()).decode("ascii")
    docker_config = json.dumps(
        {
            "auths": {
                "ghcr.io": {
                    "username": username,
                    "password": token,
                    "auth": authorization,
                }
            }
        },
        separators=(",", ":"),
    ).encode()
    apply_resource(
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": "lrail-build-images",
                "namespace": namespace,
                "labels": {"dev.lrail/lab": "mb-functional-gvisor"},
            },
            "type": "kubernetes.io/dockerconfigjson",
            "data": {
                ".dockerconfigjson": base64.b64encode(docker_config).decode("ascii")
            },
        }
    )


def openbao_public_key(name: str, root_token: str) -> tuple[str, str]:
    response = command(
        "kubectl",
        "exec",
        "-n",
        "lrail-security",
        "openbao-0",
        "--",
        "env",
        "BAO_ADDR=https://localhost:8200",
        "BAO_CACERT=/openbao/tls/ca.crt",
        f"BAO_TOKEN={root_token}",
        "bao",
        "read",
        f"transit/keys/{name}",
        "-format=json",
    )
    key = json.loads(response.stdout)["data"]
    if (
        key.get("type") != "ed25519"
        or key.get("derived")
        or key.get("exportable")
        or key.get("allow_plaintext_backup")
        or key.get("deletion_allowed")
        or not key.get("supports_signing")
    ):
        raise LabFailure(f"OpenBao key {name!r} is unsafe")
    version = str(key["latest_version"])
    raw = base64.b64decode(key["keys"][version]["public_key"], validate=True)
    if len(raw) != 32:
        raise LabFailure(f"OpenBao key {name!r} is not canonical Ed25519")
    encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    subject_public_key_info = bytes.fromhex("302a300506032b6570032100") + raw
    digest = "sha256:" + hashlib.sha256(subject_public_key_info).hexdigest()
    return encoded, digest


def functional_cell() -> None:
    dependency_probe()
    command(
        "kubectl",
        "apply",
        "-f",
        str(ROOT / "platform/kubernetes/build-cell/base/namespaces.yaml"),
    )
    command(
        "kubectl",
        "label",
        "node",
        EXPECTED_CONTEXT,
        "lrail.dev/pool=build",
        "lrail.dev/gvisor=true",
        "--overwrite",
    )

    root_token = secret_value(
        "lrail-security", "lrail-openbao-bootstrap", "root-token"
    ).decode("utf-8")
    assignment_key, assignment_digest = openbao_public_key(
        "build-assignment", root_token
    )
    _, evidence_digest = openbao_public_key("build-evidence", root_token)
    root_ca = secret_value("lrail-storage", "minio-server-tls", "ca.crt").decode(
        "utf-8"
    )
    minio = {
        key: secret_value("lrail-storage", "lrail-minio-bootstrap", key)
        for key in (
            "cell-access-key",
            "cell-secret-key",
            "reader-access-key",
            "reader-secret-key",
        )
    }
    harbor_password = secret_value(
        "lrail-registry", "lrail-harbor-bootstrap", "HARBOR_ADMIN_PASSWORD"
    )
    dns_address = command(
        "kubectl",
        "get",
        "service",
        "kube-dns",
        "-n",
        "kube-system",
        "-o",
        "jsonpath={.spec.clusterIP}",
    ).stdout.strip()
    if not dns_address:
        raise LabFailure("cluster DNS address is unavailable")

    build_policy = json.loads(
        (ROOT / "services/build-plane/config/build-policy.v1.example.json").read_text(
            encoding="utf-8"
        )
    )
    build_policy["supply_chain"]["allowed_signer_public_key_digests"] = [
        evidence_digest
    ]
    base_catalog = (
        ROOT / "services/build-plane/config/base-catalog.v1.json"
    ).read_text(encoding="utf-8")

    config_map(
        "lrail-build-control",
        "lrail-build-cell-site",
        {
            "cell-id": "cell_019b01da-7e31-7000-8000-000000000001",
            "object-prefix": "s3://lrail-build/cell-lab/",
            "s3-endpoint": "minio.lrail-storage.svc.cluster.local:9000",
            "s3-region": "us-east-1",
            "openbao-address": "https://openbao.lrail-security.svc.cluster.local:8200",
            "openbao-role": "build-cell",
            "openbao-signing-role": "build-evidence-signer",
            "harbor-api-endpoint": "https://harbor.lrail-registry.svc.cluster.local",
            "harbor-registry": "https://harbor.lrail-registry.svc.cluster.local",
            "harbor-project-storage-limit": "10737418240",
            "trivy-db-repository": "ghcr.io/aquasecurity/trivy-db:2",
            "trivy-max-db-age": "48h",
            "cluster-dns-cidr": f"{dns_address}/32",
            "cluster-dns-address": f"{dns_address}:53",
            "residue-server-name": "lrail-residue-agent.lrail-build-system.svc.cluster.local",
            "residue-server-uris": "spiffe://lrail.internal/residue-agent",
            "allowed-broker-uris": "spiffe://lrail.internal/build-broker",
        },
    )
    config_map(
        "lrail-build-control",
        "lrail-build-assignment-keys",
        {"keys.json": json.dumps({"lrail-build-assignment": assignment_key})},
    )
    for namespace in ("lrail-build-control", "lrail-control"):
        config_map(namespace, "lrail-openbao-ca", {"ca.pem": root_ca})
        config_map(namespace, "lrail-s3-ca", {"ca.pem": root_ca})
    config_map("lrail-build-control", "lrail-harbor-ca", {"ca.pem": root_ca})
    config_map(
        "lrail-build-system",
        "lrail-residue-agent-site",
        {"allowed-client-uris": "spiffe://lrail.internal/build-controller"},
    )
    config_map(
        "lrail-control",
        "lrail-build-broker-site",
        {
            "cell-id": "cell_019b01da-7e31-7000-8000-000000000001",
            "source-object-prefix": "s3://lrail-source/snapshots",
            "cell-object-prefix": "s3://lrail-build/cell-lab",
            "source-s3-endpoint": "minio.lrail-storage.svc.cluster.local:9000",
            "source-s3-region": "us-east-1",
            "source-s3-secure": "true",
            "cell-s3-endpoint": "minio.lrail-storage.svc.cluster.local:9000",
            "cell-s3-region": "us-east-1",
            "cell-s3-secure": "true",
            "dsl-compiler-version": "0.3.0",
            "llb-compiler-version": "0.2.0",
            "assignment-openbao-address": "https://openbao.lrail-security.svc.cluster.local:8200",
            "assignment-openbao-role": "build-assignment-signer",
            "assignment-openbao-auth-mount": "kubernetes",
            "assignment-openbao-transit-mount": "transit",
            "assignment-openbao-key-name": "build-assignment",
            "assignment-key-id": "lrail-build-assignment",
            "assignment-public-key-digest": assignment_digest,
            "buildcell-address": "dns:///lrail-build-cell.lrail-build-control.svc.cluster.local:9443",
            "buildcell-server-name": "lrail-build-cell.lrail-build-control.svc.cluster.local",
            "buildcell-server-uris": "spiffe://lrail.internal/build-cell",
            "build-policy.json": json.dumps(build_policy, sort_keys=True),
            "base-catalog.json": base_catalog,
        },
    )
    opaque_secret(
        "lrail-build-control",
        "lrail-build-s3",
        {
            "access-key": minio["cell-access-key"],
            "secret-key": minio["cell-secret-key"],
        },
    )
    opaque_secret(
        "lrail-control",
        "lrail-build-broker-source-s3",
        {
            "access-key": minio["reader-access-key"],
            "secret-key": minio["reader-secret-key"],
        },
    )
    opaque_secret(
        "lrail-control",
        "lrail-build-broker-cell-s3",
        {
            "access-key": minio["cell-access-key"],
            "secret-key": minio["cell-secret-key"],
        },
    )
    opaque_secret(
        "lrail-build-control",
        "lrail-harbor-admin",
        {"username": b"admin", "password": harbor_password},
    )

    username = command("gh", "api", "user", "--jq", ".login").stdout.strip()
    token = command("gh", "auth", "token").stdout.strip()
    if not username or not token:
        raise LabFailure("GitHub package identity is unavailable")
    for namespace in (
        "lrail-control",
        "lrail-build-control",
        "lrail-build",
        "lrail-build-system",
    ):
        image_pull_secret(namespace, username, token)

    command(
        "kubectl",
        "apply",
        "-k",
        str(ROOT / "platform/kubernetes/build-cell/lab"),
    )
    for namespace in ("lrail-control", "lrail-build-control", "lrail-build-system"):
        command(
            "kubectl",
            "wait",
            "--for=condition=Ready",
            "certificate",
            "--all",
            "-n",
            namespace,
            "--timeout=300s",
        )
    command(
        "kubectl",
        "rollout",
        "restart",
        "deployment/lrail-build-broker",
        "-n",
        "lrail-control",
    )
    rollouts = (
        ("deployment", "lrail-build-egress", "lrail-build-control"),
        ("deployment", "lrail-build-registry-broker", "lrail-build-control"),
        ("deployment", "lrail-build-evidence-signer", "lrail-build-control"),
        ("daemonset", "lrail-residue-agent", "lrail-build-system"),
        ("deployment", "lrail-build-control", "lrail-build-control"),
        ("deployment", "lrail-build-broker", "lrail-control"),
    )
    for kind, name, namespace in rollouts:
        command(
            "kubectl",
            "rollout",
            "status",
            f"{kind}/{name}",
            "-n",
            namespace,
            "--timeout=1200s",
        )
    print(
        "Functional gVisor BuildCell and durable broker are ready. "
        "This does not satisfy the separate Kata M-B gate."
    )


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {
        "dependencies",
        "functional-cell",
        "kata",
    }:
        sys.stderr.write("usage: mb_lab.py dependencies|functional-cell|kata\n")
        return 2
    try:
        if sys.argv[1] == "dependencies":
            dependency_probe()
        elif sys.argv[1] == "functional-cell":
            functional_cell()
        else:
            kata_probe()
    except (OSError, json.JSONDecodeError, LabFailure) as error:
        sys.stderr.write(f"M-B lab failed closed: {error}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
