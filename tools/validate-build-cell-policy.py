from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KYVERNO_IMAGE = (
    "ghcr.io/kyverno/kyverno-cli@"
    "sha256:82d2359550442f96a11292e410fb7a5c929a12265b98b819c5858f88dcf29cf7"
)
POLICY = "/workspace/platform/kubernetes/build-cell/base/admission-policy.yaml"
FIXTURES = "/workspace/platform/kubernetes/build-cell/testdata"
RENDERED_BASE = ROOT / ".work" / "wp040-build-cell-rendered.yaml"
RENDERED_EXAMPLE = ROOT / ".work" / "wp040-build-cell-example-rendered.yaml"


def validate_rendered_manifests() -> None:
    def rendered_text(path: Path) -> str:
        contents = path.read_bytes()
        if contents.startswith((b"\xff\xfe", b"\xfe\xff")):
            return contents.decode("utf-16")
        return contents.decode("utf-8")

    base = rendered_text(RENDERED_BASE)
    example = rendered_text(RENDERED_EXAMPLE)
    required_base = [
        "name: lrail-build-broker",
        "app.kubernetes.io/component: durable-build-service",
        "image: ghcr.io/mayowaoladosu/layerrail-lrail/build-broker@sha256:5deb720604c52d6ea7b16d13e65d2851664f1ffd273d8c652fe1e6ccab7ada9d",
        "name: lrail-build-broker-state",
        "secretName: lrail-build-broker-source-s3",
        "secretName: lrail-build-broker-cell-s3",
        "secretName: lrail-build-broker-cell-client-tls",
        "secretName: lrail-control-worker-build-client-tls",
        "spiffe://lrail.internal/build-service",
        "spiffe://lrail.internal/build-broker",
        "spiffe://lrail.internal/control-worker",
        "name: LRAIL_ASSIGNMENT_OPENBAO_JWT_FILE",
        "name: LRAIL_ALLOWED_CLIENT_URIS",
        "name: lrail-build-egress",
        "app.kubernetes.io/component: policy-proxy",
        "image: ghcr.io/mayowaoladosu/layerrail-lrail/build-egress-proxy@sha256:",
        "name: lrail-build-egress-client-ca",
        "name: lrail-build-egress-client-ca",
        "name: LRAIL_EGRESS_CLIENT_CA_KEY",
        "name: LRAIL_EGRESS_SERVER_CA",
        "name: LRAIL_DNS_SERVER",
        "name: lrail-build-registry-broker",
        "app.kubernetes.io/component: credential-broker",
        "image: ghcr.io/mayowaoladosu/layerrail-lrail/registry-broker@sha256:",
        "name: LRAIL_REGISTRY_BROKER_ADDRESS",
        "name: LRAIL_HARBOR_CA_FILE",
        "name: lrail-build-registry-client",
        "name: lrail-build-evidence-signer",
        "app.kubernetes.io/component: signing-service",
        "image: ghcr.io/mayowaoladosu/layerrail-lrail/evidence-signer@sha256:",
        "name: lrail-trivy-db-updater",
        "image: ghcr.io/mayowaoladosu/layerrail-lrail/trivy-db-updater@sha256:",
        "update.sh: |",
        'mv -fT "${current_link}" "${root}/current"',
        "- ReadWriteMany",
        "name: LRAIL_SIGNING_ADDRESS",
        "name: LRAIL_SYFT_PATH",
        "name: LRAIL_TRIVY_DB_METADATA",
        "value: /var/lib/lrail-trivy/current/db/metadata.json",
        "name: lrail-build-evidence-client",
        "port: 8443",
        "port: 9445",
        "port: 9446",
        "169.254.0.0/16",
        "fe80::/10",
    ]
    for value in required_base:
        if value not in base:
            raise ValueError(f"rendered base lacks {value!r}")
    if base.count('port: "9445"') < 2:
        raise ValueError(
            "rendered base lacks both registry-broker ingress and controller egress"
        )
    if base.count('port: "9446"') < 2:
        raise ValueError(
            "rendered base lacks both evidence-signer ingress and controller egress"
        )
    for forbidden in ["name: lrail-build-artifacts", "name: LRAIL_ARTIFACT_ROOT"]:
        if forbidden in base:
            raise ValueError(
                f"rendered base retains obsolete local artifact authority {forbidden!r}"
            )
    for image, image_digest in re.findall(
        r"image: (ghcr\.io/mayowaoladosu/layerrail-lrail/[^@\s]+)@sha256:([0-9a-f]{64})",
        base,
    ):
        if len(set(image_digest)) == 1:
            raise ValueError(f"rendered base retains placeholder digest for {image}")

    dynamic_policy = (
        ROOT / "services/build-plane/internal/buildkube/resources.go"
    ).read_text(encoding="utf-8")
    for value in [
        "ProxyServerName",
        "ProxyPort",
        '"rules": map[string]any{"dns"',
        '"egressDeny"',
    ]:
        if value not in dynamic_policy:
            raise ValueError(f"dynamic worker policy lacks {value!r}")
    for forbidden in ['"toFQDNs"', '"toCIDR"']:
        if forbidden in dynamic_policy:
            raise ValueError(
                f"worker policy still grants direct destinations via {forbidden}"
            )

    for value in [
        '"hosts":["packages.internal.example"]',
        "name: build-egress-private-example",
        "cidr: 10.20.30.40/32",
        'port: "443"',
        "harbor-api-endpoint: https://harbor.example.invalid",
        "matchName: harbor.example.invalid",
        "name: lrail-harbor-admin",
        "openbao-signing-role: build-evidence-signer",
        "name: lrail-build-broker-site",
        "assignment-openbao-role: build-assignment-signer",
        "assignment-key-id: lrail-build-assignment",
        "source-object-prefix: s3://lrail-source/snapshots",
        "name: lrail-build-broker-source-s3",
        "name: lrail-build-broker-cell-s3",
        "trivy-db-repository: harbor.example.invalid/lrail-security-public/trivy-db:2",
        "storageClassName: rook-cephfs",
        "storageClassName: rook-ceph-block",
    ]:
        if value not in example:
            raise ValueError(f"example private proxy mapping lacks {value!r}")
    if example.count("matchName: harbor.example.invalid") != 3:
        raise ValueError(
            "example must grant exact Harbor HTTPS egress to controller, registry broker, and Trivy updater"
        )
    if example.count('port: "9445"') < 2:
        raise ValueError(
            "example overlay dropped the controller-to-registry-broker route"
        )
    if example.count('port: "9446"') < 2:
        raise ValueError(
            "example overlay dropped the controller-to-evidence-signer route"
        )
    if example.count("matchName: openbao.example.invalid") < 2:
        raise ValueError(
            "example must grant exact OpenBao HTTPS egress to controller and evidence signer"
        )

    broker = (ROOT / "platform/kubernetes/build-cell/base/build-broker.yaml").read_text(
        encoding="utf-8"
    )
    for value in [
        "replicas: 1",
        "type: Recreate",
        "accessModes: [ReadWriteOnce]",
        "automountServiceAccountToken: false",
        "audience: openbao.lrail.internal",
        "readOnlyRootFilesystem: true",
        'drop: ["ALL"]',
        "LRAIL_SOURCE_S3_ACCESS_KEY_FILE",
        "LRAIL_CELL_S3_ACCESS_KEY_FILE",
    ]:
        if value not in broker:
            raise ValueError(f"build broker lacks {value!r}")
    for forbidden in [
        "LRAIL_DATABASE",
        "LRAIL_GITHUB",
        "LRAIL_HARBOR_ADMIN",
        "KUBERNETES_SERVICE_HOST",
        "/var/run/secrets/kubernetes.io/serviceaccount",
        "automountServiceAccountToken: true",
    ]:
        if forbidden in broker:
            raise ValueError(f"build broker gained forbidden authority {forbidden!r}")

    broker_network = base.split("name: build-broker", 1)[1].split(
        "name: default-deny", 1
    )[0]
    for forbidden in ['port: "5432"', "toEntities: [kube-apiserver]"]:
        if forbidden in broker_network:
            raise ValueError(f"build broker network gained {forbidden!r}")

    policies = ROOT / "platform/kubernetes/build-cell/base/policies"
    source_policy = json.loads(
        (policies / "build-broker-source-read.json").read_text(encoding="utf-8")
    )
    cell_policy = json.loads(
        (policies / "build-broker-cell-content.json").read_text(encoding="utf-8")
    )
    source_statement = source_policy["Statement"]
    cell_statement = cell_policy["Statement"]
    if len(source_statement) != 1 or source_statement[0]["Action"] != ["s3:GetObject"]:
        raise ValueError("broker source policy is not read-only")
    if source_statement[0]["Resource"] != ["arn:aws:s3:::lrail-source/snapshots/*"]:
        raise ValueError("broker source policy escaped finalized snapshots")
    if len(cell_statement) != 1 or cell_statement[0]["Action"] != [
        "s3:GetObject",
        "s3:PutObject",
    ]:
        raise ValueError("broker cell policy has excess object authority")
    if cell_statement[0]["Resource"] != ["arn:aws:s3:::lrail-build/cell-example/*"]:
        raise ValueError("broker cell policy escaped its selected prefix")

    site = (
        ROOT / "platform/kubernetes/build-cell/overlays/example/site-broker-config.yaml"
    ).read_text(encoding="utf-8")
    catalog = json.loads(config_map_literal(site, "base-catalog.json"))
    canonical_catalog = json.loads(
        (ROOT / "services/build-plane/config/base-catalog.v1.json").read_text(
            encoding="utf-8"
        )
    )
    if catalog != canonical_catalog:
        raise ValueError("broker base catalog drifted from the owned catalog")
    build_policy = json.loads(config_map_literal(site, "build-policy.json"))
    signer_digests = build_policy["supply_chain"]["allowed_signer_public_key_digests"]
    if (
        build_policy["supply_chain"]["syft_version"] != "1.46.0"
        or build_policy["supply_chain"]["trivy_version"] != "0.72.0"
        or len(signer_digests) != 1
        or signer_digests[0] == "sha256:" + ("0" * 64)
    ):
        raise ValueError("broker supply-chain policy is not pinned")

    key_config = (
        ROOT / "platform/kubernetes/build-cell/overlays/example/site-config.yaml"
    ).read_text(encoding="utf-8")
    key_match = re.search(
        r'\{"lrail-build-assignment":"([A-Za-z0-9_-]+)"\}', key_config
    )
    digest_match = re.search(
        r"assignment-public-key-digest: (sha256:[0-9a-f]{64})", site
    )
    if not key_match or not digest_match:
        raise ValueError("example assignment identity is incomplete")
    encoded = key_match.group(1)
    public_key = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    subject_public_key_info = bytes.fromhex("302a300506032b6570032100") + public_key
    actual_digest = "sha256:" + hashlib.sha256(subject_public_key_info).hexdigest()
    if len(public_key) != 32 or actual_digest != digest_match.group(1):
        raise ValueError("example assignment key and broker digest differ")

    openbao_policy = (
        ROOT / "platform/openbao/policies/build-assignment-signer.hcl"
    ).read_text(encoding="utf-8")
    for value in [
        'path "transit/keys/build-assignment"',
        'path "transit/sign/build-assignment"',
        'path "auth/token/revoke-self"',
    ]:
        if value not in openbao_policy:
            raise ValueError(f"assignment signer policy lacks {value!r}")
    if "*" in openbao_policy or "sudo" in openbao_policy:
        raise ValueError("assignment signer policy is overprivileged")


def config_map_literal(contents: str, key: str) -> str:
    lines = contents.splitlines()
    marker = f"  {key}: |"
    try:
        cursor = lines.index(marker) + 1
    except ValueError as error:
        raise ValueError(f"broker ConfigMap lacks {key}") from error
    value: list[str] = []
    while cursor < len(lines) and lines[cursor].startswith("    "):
        value.append(lines[cursor][4:])
        cursor += 1
    if not value:
        raise ValueError(f"broker ConfigMap {key} is empty")
    return "\n".join(value)


def apply(fixture: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--mount",
            f"type=bind,source={ROOT},target=/workspace,readonly",
            KYVERNO_IMAGE,
            "apply",
            POLICY,
            "--resource",
            f"{FIXTURES}/{fixture}",
            "--remove-color",
        ],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )


def main() -> int:
    try:
        validate_rendered_manifests()
    except (OSError, ValueError) as error:
        sys.stderr.write(f"Build-cell manifest validation failed: {error}\n")
        return 1

    admitted = apply("worker-pod.yaml")
    if admitted.returncode != 0:
        sys.stderr.write(admitted.stdout + admitted.stderr)
        return 1

    rejected = apply("worker-sidecar-pod.yaml")
    if rejected.returncode == 0:
        sys.stderr.write("Kyverno admitted the forbidden sidecar fixture.\n")
        return 1

    print("Kyverno admitted the isolated worker and rejected the sidecar fixture.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
