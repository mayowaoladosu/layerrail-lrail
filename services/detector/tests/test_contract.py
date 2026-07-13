from __future__ import annotations

import ast
import copy
import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from lrail_detector.engine import Detector, detect
from lrail_detector.inventory import SnapshotInventory
from lrail_detector.models import (
    DETECTOR_VERSION,
    RULESET_VERSION,
    DetectionResult,
)
from lrail_detector.plugins.node import NodePlugin

if TYPE_CHECKING:
    from lrail_detector.plugins.base import PluginResult

SNAPSHOT_ID = "snp_019b01da-7e31-7000-8000-000000000037"
FIXTURES = Path(__file__).with_name("fixtures")
ROOT = Path(__file__).resolve().parents[3]


def test_v2_contract_is_versioned_explainable_and_manifest_ready() -> None:
    result = detect(FIXTURES / "rails-worker", SNAPSHOT_ID)

    assert result.schema_version == "detector.lrail.dev/v2"
    assert result.proposal_version == 1
    assert result.detector_version == DETECTOR_VERSION
    assert result.ruleset_version == RULESET_VERSION
    assert result.source_snapshot_id == SNAPSHOT_ID
    assert [plugin.plugin for plugin in result.plugins] == [
        "docker",
        "go",
        "node",
        "python",
        "ruby",
        "static",
    ]
    assert result.files_considered == tuple(sorted(result.files_considered))
    assert result.evidence_graph.nodes
    assert result.evidence_graph.edges
    assert result.generated_manifest is not None
    assert result.generated_manifest.api_version == "lrail.dev/v1"
    assert {addon.engine for addon in result.suggested_addons} == {"postgresql", "valkey"}


def test_monorepo_dependency_order_and_addon_hints_are_evidence_backed() -> None:
    result = detect(FIXTURES / "node-monorepo", SNAPSHOT_ID)
    services = {service.name: service for service in result.services}

    assert result.blocked is False
    assert [service.name for service in result.services].index("fixture-worker") < [
        service.name for service in result.services
    ].index("fixture-api")
    assert services["fixture-api"].depends_on == ("fixture-worker",)
    assert services["fixture-web"].build.output_path == "apps/web/dist"
    assert services["fixture-worker"].kind == "worker"
    assert {addon.engine for addon in result.suggested_addons} == {"postgresql", "valkey"}
    node_ids = {node.id for node in result.evidence_graph.nodes}
    assert all(set(addon.evidence_ids) <= node_ids for addon in result.suggested_addons)


def test_inventory_records_executable_mode_and_bounded_source_headers(tmp_path: Path) -> None:
    script = tmp_path / "worker.sh"
    script.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    try:
        script.chmod(0o755)
    except OSError:
        pytest.skip("executable mode changes are unavailable")
    inventory = SnapshotInventory.build(tmp_path)
    record = inventory.records_named("worker.sh")[0]

    assert record.executable is bool(record.mode & 0o111)
    assert inventory.read_header("worker.sh") == "#!/bin/sh\nexit 99\n"
    assert inventory.files_read == ("worker.sh",)


def test_plugins_have_no_process_network_dynamic_import_or_direct_file_capability() -> None:
    plugin_root = ROOT / "services/detector/src/lrail_detector/plugins"
    forbidden_imports = {"http", "importlib", "requests", "runpy", "socket", "subprocess", "urllib"}
    forbidden_calls = {"__import__", "compile", "eval", "exec", "open"}
    allowed_imports = {
        "__future__",
        "dataclasses",
        "hashlib",
        "json",
        "lrail_detector",
        "pathlib",
        "re",
        "shlex",
        "tomllib",
        "typing",
    }

    for path in sorted(plugin_root.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".", 1)[0])
        called = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert imported.isdisjoint(forbidden_imports), path
        assert imported <= allowed_imports, path
        assert called.isdisjoint(forbidden_calls), path


def test_external_plugins_and_invalid_snapshot_identity_fail_closed(tmp_path: Path) -> None:
    class ExternalPlugin:
        descriptor = type("Descriptor", (), {"plugin": "external", "version": "1.0.0"})()

        def detect(self, context: object) -> object:
            return context

    with pytest.raises(ValueError, match="registered private lrail_detector adapters"):
        Detector(plugins=(ExternalPlugin(),))  # type: ignore[arg-type]

    (tmp_path / "index.html").write_text("ok", encoding="utf-8")
    with pytest.raises(ValidationError, match="source_snapshot_id"):
        detect(tmp_path, "not-a-snapshot")


def test_private_plugin_failure_becomes_stable_blocking_diagnostic(tmp_path: Path) -> None:
    plugin = NodePlugin()

    def fail(context: object) -> PluginResult:
        del context
        msg = "inert plugin failure"
        raise ValueError(msg)

    plugin.detect = fail  # type: ignore[method-assign]
    (tmp_path / "index.html").write_text("ok", encoding="utf-8")

    result = Detector(plugins=(plugin,)).detect(tmp_path, SNAPSHOT_ID)

    assert result.blocked is True
    assert [item.code for item in result.unresolved] == ["detector.no-service", "plugin.failed"]


def test_repository_configuration_is_reported_without_execution(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text("ok", encoding="utf-8")
    (tmp_path / "lrail.yaml").write_text("services: []\n", encoding="utf-8")
    (tmp_path / "Lrailfile.star").write_text('fail("must not execute")\n', encoding="utf-8")

    result = detect(tmp_path, SNAPSHOT_ID)

    assert result.blocked is False
    assert {"Lrailfile.star", "lrail.yaml"} <= set(result.files_considered)
    assert sum(item.code == "detector.repository-config-present" for item in result.warnings) == 2


def test_v1_schema_remains_immutable_beside_versioned_v2() -> None:
    v1 = json.loads(
        ROOT.joinpath("contracts/jsonschema/detector/detection-result.schema.json").read_text(
            encoding="utf-8"
        )
    )
    v2 = json.loads(
        ROOT.joinpath("contracts/jsonschema/detector/detection-result-v2.schema.json").read_text(
            encoding="utf-8"
        )
    )

    assert v1["$id"] == "https://contracts.lrail.dev/detector/detection-result.schema.json"
    assert v1["properties"]["schema_version"]["const"] == "detector.lrail.dev/v1"
    assert v2["$id"] == "https://contracts.lrail.dev/detector/v2/detection-result.schema.json"
    assert v2["properties"]["schema_version"]["const"] == "detector.lrail.dev/v2"


def test_public_v2_fixture_is_exact_detector_output_and_invalid_fixture_is_rejected() -> None:
    contracts = ROOT / "contracts/fixtures"
    expected = DetectionResult.model_validate_json(
        contracts.joinpath("detector-v2.valid.json").read_text(encoding="utf-8")
    )

    actual = detect(FIXTURES / "static-site", expected.source_snapshot_id)

    assert actual == expected
    with pytest.raises(ValidationError):
        DetectionResult.model_validate_json(
            contracts.joinpath("detector-v2.invalid.json").read_text(encoding="utf-8")
        )


def test_v2_cross_field_invariants_reject_inconsistent_proposals() -> None:
    valid = json.loads(
        ROOT.joinpath("contracts/fixtures/detector-v2.valid.json").read_text(encoding="utf-8")
    )

    def mutate(path: tuple[object, ...], value: object) -> dict[str, object]:
        changed = copy.deepcopy(valid)
        target: object = changed
        for key in path[:-1]:
            target = target[key]  # type: ignore[index]
        target[path[-1]] = value  # type: ignore[index]
        return changed

    evidence_id = valid["services"][0]["evidence_ids"][0]
    mutations = [
        mutate(("plugins",), [valid["plugins"][0], valid["plugins"][0]]),
        mutate(
            ("warnings",),
            [{"code": "test.warning", "severity": "blocking", "message": "wrong"}],
        ),
        mutate(
            ("unresolved",),
            [{"code": "test.unresolved", "severity": "warning", "message": "wrong"}],
        ),
        mutate(("services", 0, "depends_on"), ["unknown"]),
        mutate(("services", 0, "evidence_ids"), ["ev_00000000000000000000"]),
        mutate(("services", 0, "confidence"), 0.1),
        mutate(("services", 0, "files_considered"), ["index.html", "missing.txt"]),
        mutate(("evidence_graph", "edges", 0, "target"), "service:unknown"),
        mutate(("evidence_graph", "nodes", 0, "path"), "missing.txt"),
        mutate(
            ("suggested_addons",),
            [
                {
                    "name": "cache",
                    "engine": "valkey",
                    "services": ["unknown"],
                    "required": False,
                    "reason": "test",
                    "evidence_ids": [evidence_id],
                }
            ],
        ),
        mutate(("unsupported_features",), ["desktop_runtime"]),
        mutate(("blocked",), not valid["blocked"]),
        mutate(("generated_manifest", "services", 0, "name"), "other"),
    ]

    for value in mutations:
        with pytest.raises(ValidationError):
            DetectionResult.model_validate(value)
