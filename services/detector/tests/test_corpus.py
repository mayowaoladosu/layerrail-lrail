from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from lrail_detector.engine import detect

SNAPSHOT_ID = "snp_019b01da-7e31-7000-8000-000000000036"
FIXTURES = Path(__file__).with_name("fixtures")
CASES = json.loads(FIXTURES.joinpath("cases.json").read_text(encoding="utf-8"))
MANIFEST_SCHEMA = json.loads(
    Path(__file__)
    .resolve()
    .parents[3]
    .joinpath("contracts/jsonschema/manifest/lrail.schema.json")
    .read_text(encoding="utf-8")
)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["fixture"])
def test_real_and_adversarial_fixture_corpus(case: dict[str, object]) -> None:
    root = FIXTURES / str(case["fixture"])

    first = detect(root, SNAPSHOT_ID)
    second = detect(root, SNAPSHOT_ID)

    assert first == second
    assert first.blocked is case["blocked"]
    if "frameworks" in case:
        assert sorted(service.framework for service in first.services) == sorted(case["frameworks"])
    if "service_count" in case:
        assert len(first.services) == case["service_count"]
    if "processes" in case:
        assert sorted(
            process.name for service in first.services for process in service.processes
        ) == sorted(case["processes"])
    if "unresolved" in case:
        assert str(case["unresolved"]) in {item.code for item in first.unresolved}

    node_by_id = {node.id: node for node in first.evidence_graph.nodes}
    for service in first.services:
        expected = round(
            min(
                1.0,
                max(
                    0.0,
                    0.5 + sum(node_by_id[item].confidence_delta for item in service.evidence_ids),
                ),
            ),
            3,
        )
        assert service.confidence == expected
        assert set(service.evidence_ids) <= set(node_by_id)

    if first.blocked:
        assert first.generated_manifest is None
    else:
        assert first.generated_manifest is not None
        Draft202012Validator(MANIFEST_SCHEMA).validate(
            first.generated_manifest.model_dump(mode="json")
        )
