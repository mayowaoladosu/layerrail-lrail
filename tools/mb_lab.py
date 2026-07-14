from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = ROOT / "platform/kubernetes/build-cell/lab/versions.json"
EXPECTED_CONTEXT = "lrail-kata"
EXPECTED_KATA_NODE = "lrail-kata-worker"
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
          awk '$2 == "/" && $3 == "virtiofs" { found=1 } END { exit !found }' /proc/mounts;
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
""".replace(
    "  runtimeClassName: kata-qemu\n",
    "  runtimeClassName: kata-qemu\n  nodeSelector:\n    kubernetes.io/hostname: lrail-kata-worker\n",
)


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
    if (
        configured.get("cluster_context") != EXPECTED_CONTEXT
        or configured.get("kata_node") != EXPECTED_KATA_NODE
    ):
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
        raise LabFailure("expected lab control node is unavailable")
    worker = command(
        "kubectl", "get", "node", EXPECTED_KATA_NODE, "-o", "name"
    ).stdout.strip()
    if worker != f"node/{EXPECTED_KATA_NODE}":
        raise LabFailure("expected nested-KVM Kata worker is unavailable")


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
        command("kubectl", "get", "node", EXPECTED_KATA_NODE, "-o", "json").stdout
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


def write_lab_file(name: str, contents: str, mode: int) -> None:
    root = ROOT / ".work" / "mb-lab"
    root.mkdir(parents=True, exist_ok=True)
    path = root / name
    temporary = root / f".{name}.{secrets.token_hex(8)}.tmp"
    try:
        temporary.write_text(contents, encoding="utf-8")
        os.chmod(temporary, mode)
        temporary.replace(path)
        os.chmod(path, mode)
    finally:
        temporary.unlink(missing_ok=True)


def source_signing_material() -> tuple[bytes, bytes, bytes]:
    generated = command(
        "node",
        "--input-type=module",
        "--eval",
        """
import crypto from "node:crypto";
const {privateKey} = crypto.generateKeyPairSync("ed25519");
const jwk = privateKey.export({format: "jwk"});
console.log(JSON.stringify({seed: jwk.d, publicKey: jwk.x}));
""",
    )
    values = json.loads(generated.stdout)
    try:
        seed = base64.urlsafe_b64decode(values["seed"] + "==")
        public_key = base64.urlsafe_b64decode(values["publicKey"] + "==")
    except (KeyError, ValueError, TypeError) as error:
        raise LabFailure("generated source signing key is invalid") from error
    if len(seed) != 32 or len(public_key) != 32:
        raise LabFailure("generated source signing key has an unexpected size")
    private_key = base64.urlsafe_b64encode(seed + public_key).rstrip(b"=")
    encoded_public = base64.urlsafe_b64encode(public_key).decode("ascii").rstrip("=")
    key_id = f"source-finalizer-mb-{hashlib.sha256(public_key).hexdigest()[:16]}"
    grant_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=")
    write_lab_file("source-grant-key", grant_key.decode("ascii"), 0o600)
    write_lab_file(
        "source-signing-public-keys.json",
        json.dumps({key_id: encoded_public}, separators=(",", ":")),
        0o600,
    )
    return grant_key, private_key, key_id.encode("ascii")


def github_app_credentials() -> dict[str, bytes] | None:
    path = ROOT / ".work" / "mb-lab" / "github-app.json"
    try:
        stat = path.lstat()
    except FileNotFoundError:
        return None
    if (
        not stat.is_file()
        or path.is_symlink()
        or stat.st_size < 1
        or stat.st_size > 32 << 10
    ):
        raise LabFailure("GitHub App runtime credential file is unsafe")
    try:
        values = json.loads(path.read_text(encoding="utf-8"))
        app_id = str(int(values["app_id"]))
        slug = values["slug"]
        private_key = values["private_key"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise LabFailure("GitHub App runtime credential file is invalid") from error
    valid_slug = (
        isinstance(slug, str)
        and 1 <= len(slug) <= 100
        and all(
            character.islower() or character.isdigit() or character == "-"
            for character in slug
        )
    )
    pem_label = "RSA " + "PRIVATE KEY"
    valid_key = (
        isinstance(private_key, str)
        and 1 <= len(private_key) <= 16 << 10
        and private_key.startswith(f"-----BEGIN {pem_label}-----\n")
        and private_key.endswith(f"-----END {pem_label}-----\n")
    )
    if int(app_id) < 1 or not valid_slug or not valid_key:
        raise LabFailure("GitHub App runtime credential identity is invalid")
    return {
        "app-id": app_id.encode("ascii"),
        "private-key.pem": private_key.encode("ascii"),
    }


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
    runtime = json.loads(
        command("kubectl", "get", "runtimeclass", "gvisor", "-o", "json").stdout
    )
    if runtime.get("handler") != "runsc":
        raise LabFailure("functional gVisor RuntimeClass is unavailable or unexpected")
    command(
        "kubectl",
        "apply",
        "-f",
        str(ROOT / "platform/kubernetes/build-cell/base/namespaces.yaml"),
    )
    apply_resource(
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "lrail-source",
                "labels": {
                    "pod-security.kubernetes.io/enforce": "restricted",
                    "pod-security.kubernetes.io/audit": "restricted",
                    "pod-security.kubernetes.io/warn": "restricted",
                    "dev.lrail/lab": "mb-functional-gvisor",
                },
            },
        }
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
            "source-access-key",
            "source-secret-key",
        )
    }
    harbor_password = secret_value(
        "lrail-registry", "lrail-harbor-bootstrap", "HARBOR_ADMIN_PASSWORD"
    )
    source_grant_key, source_private_key, source_key_id = source_signing_material()
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
    config_map("lrail-source", "lrail-s3-ca", {"ca.pem": root_ca})
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
        "lrail-source",
        "lrail-source-gateway-s3",
        {
            "access-key": minio["source-access-key"],
            "secret-key": minio["source-secret-key"],
        },
    )
    opaque_secret(
        "lrail-source",
        "lrail-source-gateway-signing",
        {
            "grant-key": source_grant_key,
            "private-key": source_private_key,
            "key-id": source_key_id,
        },
    )
    app_credentials = github_app_credentials()
    if app_credentials:
        opaque_secret("lrail-source", "lrail-github-app", app_credentials)
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
        "lrail-source",
    ):
        image_pull_secret(namespace, username, token)

    command(
        "kubectl",
        "apply",
        "-k",
        str(ROOT / "platform/kubernetes/build-cell/lab"),
    )
    if app_credentials:
        command(
            "kubectl",
            "scale",
            "deployment/lrail-provider-broker",
            "--replicas=1",
            "-n",
            "lrail-source",
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
    rollouts = [
        ("deployment", "lrail-source-gateway", "lrail-source"),
        ("deployment", "lrail-provider-egress", "lrail-source"),
        ("deployment", "lrail-build-egress", "lrail-build-control"),
        ("deployment", "lrail-build-registry-broker", "lrail-build-control"),
        ("deployment", "lrail-build-evidence-signer", "lrail-build-control"),
        ("daemonset", "lrail-residue-agent", "lrail-build-system"),
        ("deployment", "lrail-build-control", "lrail-build-control"),
        ("deployment", "lrail-build-broker", "lrail-control"),
    ]
    if app_credentials:
        rollouts.append(("deployment", "lrail-provider-broker", "lrail-source"))
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
    for kind in ("deployment", "service", "networkpolicy"):
        command(
            "kubectl",
            "delete",
            kind,
            "lrail-source-gateway" if kind != "networkpolicy" else "source-gateway",
            "-n",
            "lrail-control",
            "--ignore-not-found=true",
            check=False,
        )
    command(
        "kubectl",
        "delete",
        "ciliumnetworkpolicy",
        "source-gateway",
        "-n",
        "lrail-control",
        "--ignore-not-found=true",
        check=False,
    )
    print(
        "Functional gVisor BuildCell and durable broker are ready. "
        "This does not satisfy the separate Kata M-B gate."
    )


def git_provider() -> None:
    require_context()
    credentials = github_app_credentials()
    if not credentials:
        raise LabFailure("ignored GitHub App runtime credential is unavailable")
    source_gateway = json.loads(
        command(
            "kubectl",
            "get",
            "deployment/lrail-source-gateway",
            "-n",
            "lrail-source",
            "-o",
            "json",
        ).stdout
    )
    if source_gateway.get("status", {}).get("readyReplicas") != 1:
        raise LabFailure("source gateway is not ready for exact-Git acquisition")
    opaque_secret("lrail-source", "lrail-github-app", credentials)
    command(
        "kubectl",
        "apply",
        "-f",
        str(ROOT / "platform/kubernetes/build-cell/lab/provider-git.yaml"),
    )
    command(
        "kubectl",
        "scale",
        "deployment/lrail-provider-broker",
        "--replicas=1",
        "-n",
        "lrail-source",
    )
    for name in ("lrail-provider-egress", "lrail-provider-broker"):
        command(
            "kubectl",
            "rollout",
            "status",
            f"deployment/{name}",
            "-n",
            "lrail-source",
            "--timeout=600s",
        )
    print(
        "Exact-Git provider broker and policy egress are ready without changing "
        "the strict BuildCell runtime."
    )


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {
        "dependencies",
        "functional-cell",
        "git-provider",
        "kata",
    }:
        sys.stderr.write(
            "usage: mb_lab.py dependencies|functional-cell|git-provider|kata\n"
        )
        return 2
    try:
        if sys.argv[1] == "dependencies":
            dependency_probe()
        elif sys.argv[1] == "functional-cell":
            functional_cell()
        elif sys.argv[1] == "git-provider":
            git_provider()
        else:
            kata_probe()
    except (OSError, json.JSONDecodeError, LabFailure) as error:
        sys.stderr.write(f"M-B lab failed closed: {error}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
