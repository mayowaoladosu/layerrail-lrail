from __future__ import annotations

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
RENDERED_BASE = ROOT / ".work" / "wp038-build-cell-rendered.yaml"
RENDERED_EXAMPLE = ROOT / ".work" / "wp038-build-cell-example-rendered.yaml"


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
        "port: 8443",
        "169.254.0.0/16",
        "fe80::/10",
    ]
    for value in required_base:
        if value not in base:
            raise ValueError(f"rendered base lacks {value!r}")

    dynamic_policy = (ROOT / "services/build-plane/internal/buildkube/resources.go").read_text(
        encoding="utf-8"
    )
    for value in [
        'ProxyServerName',
        'ProxyPort',
        '"rules": map[string]any{"dns"',
        '"egressDeny"',
    ]:
        if value not in dynamic_policy:
            raise ValueError(f"dynamic worker policy lacks {value!r}")
    for forbidden in ['"toFQDNs"', '"toCIDR"']:
        if forbidden in dynamic_policy:
            raise ValueError(f"worker policy still grants direct destinations via {forbidden}")

    for value in [
        '"hosts":["packages.internal.example"]',
        "name: build-egress-private-example",
        "cidr: 10.20.30.40/32",
        'port: "443"',
    ]:
        if value not in example:
            raise ValueError(f"example private proxy mapping lacks {value!r}")


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
