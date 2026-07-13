from __future__ import annotations

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
        "trivy-db-repository: harbor.example.invalid/lrail-security-public/trivy-db:2",
        "storageClassName: rook-cephfs",
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
