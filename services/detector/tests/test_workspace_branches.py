from __future__ import annotations

import json
from pathlib import Path

from lrail_detector.engine import detect

SNAPSHOT_ID = "snp_019b01da-7e31-7000-8000-000000000040"


def write_tree(root: Path, files: dict[str, str]) -> None:
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def test_pnpm_workspace_declaration_and_internal_dependency_order(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "pnpm-workspace.yaml": "packages:\n  - 'services/*'\n",
            "pnpm-lock.yaml": "lockfileVersion: '9'\n",
            "services/api/package.json": json.dumps(
                {
                    "name": "api",
                    "scripts": {"start": "node api.js"},
                    "dependencies": {"express": "5", "worker": "workspace:*"},
                }
            ),
            "services/worker/package.json": json.dumps(
                {"name": "worker", "scripts": {"worker": "node worker.js"}}
            ),
        },
    )

    result = detect(tmp_path, SNAPSHOT_ID)
    services = {service.name: service for service in result.services}

    assert result.blocked is False
    assert services["api"].depends_on == ("worker",)
    assert "pnpm-workspace.yaml" in services["api"].files_considered


def test_unsafe_workspace_pattern_is_warned_without_path_escape(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "package.json": json.dumps({"workspaces": ["../outside", "apps/**"]}),
            "apps/web/package.json": json.dumps(
                {
                    "name": "web",
                    "scripts": {"start": "node server.js"},
                    "dependencies": {"express": "5"},
                }
            ),
            "pnpm-lock.yaml": "lockfileVersion: '9'\n",
        },
    )

    result = detect(tmp_path, SNAPSHOT_ID)

    assert sum(item.code == "workspace.unsafe-pattern" for item in result.warnings) == 2
    assert all("outside" not in path for path in result.files_considered)


def test_go_work_declares_nested_module_membership(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "go.work": "go 1.26\nuse (\n  ./services/api\n)\n",
            "services/api/go.mod": "module example.invalid/api\n\ngo 1.26\n",
            "services/api/go.sum": "example.invalid/x v1.0.0 h1:fixture\n",
            "services/api/main.go": 'package main\n// http.ListenAndServe(":8081", nil)\n',
        },
    )

    result = detect(tmp_path, SNAPSHOT_ID)
    service = result.services[0]

    assert result.blocked is False
    assert "go.work" in service.files_considered
    assert any(node.fact == "go.workspace-membership" for node in result.evidence_graph.nodes)


def test_invalid_and_non_object_workspace_package_metadata_is_bounded(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "bad/package.json": "{bad",
            "array/package.json": "[]",
            "site/index.html": "<h1>site</h1>",
        },
    )

    result = detect(tmp_path, SNAPSHOT_ID)
    codes = {item.code for item in result.warnings}

    assert "workspace.invalid-package-json" in codes
    assert "workspace.package-root-not-object" in codes
    assert [service.framework for service in result.services] == ["Static HTML"]


def test_go_work_parent_escape_is_ignored_and_warned(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "go.work": "go 1.26\nuse ../../outside\n",
            "site/index.html": "<h1>safe</h1>",
        },
    )

    result = detect(tmp_path, SNAPSHOT_ID)

    assert "workspace.unsafe-go-use" in {item.code for item in result.warnings}
    assert [service.framework for service in result.services] == ["Static HTML"]


def test_workspace_dependency_cycle_blocks_proposal(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "package.json": json.dumps({"workspaces": ["apps/*"]}),
            "package-lock.json": '{"lockfileVersion":3}\n',
            "apps/a/package.json": json.dumps(
                {
                    "name": "a",
                    "scripts": {"worker": "node a.js"},
                    "dependencies": {"b": "workspace:*"},
                }
            ),
            "apps/b/package.json": json.dumps(
                {
                    "name": "b",
                    "scripts": {"worker": "node b.js"},
                    "dependencies": {"a": "workspace:*"},
                }
            ),
        },
    )

    result = detect(tmp_path, SNAPSHOT_ID)

    assert result.blocked is True
    assert "workspace.dependency-cycle" in {item.code for item in result.unresolved}
