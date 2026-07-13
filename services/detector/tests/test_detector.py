from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from lrail_detector.cli import main
from lrail_detector.engine import Detector
from lrail_detector.engine import detect as detect_snapshot
from lrail_detector.inventory import MAX_METADATA_BYTES, InventoryError, SnapshotInventory
from lrail_detector.models import ProcessProposal

SNAPSHOT_ID = "snp_019b01da-7e31-7000-8000-000000000035"


def detect(snapshot: Path, selected_root: str = "."):
    return detect_snapshot(snapshot, SNAPSHOT_ID, selected_root)


def write_tree(root: Path, files: dict[str, str]) -> Path:
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return root


def test_detects_rails_service(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "Gemfile": 'source "https://rubygems.org"\ngem "rails", "~> 8.1"\n',
            "Gemfile.lock": "GEM\n",
            "config/application.rb": "class App < Rails::Application; end\n",
        },
    )

    result = detect(tmp_path)

    assert result.blocked is False
    service = result.services[0]
    assert service.language == "ruby"
    assert service.framework == "Rails"
    assert service.processes[0].command[:3] == ("bundle", "exec", "rails")
    assert service.processes[0].health_path == "/up"
    assert service.files_considered == ("Gemfile", "Gemfile.lock")


def test_detects_next_with_locked_pnpm_commands(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "package.json": json.dumps(
                {
                    "name": "storefront",
                    "scripts": {"build": "next build", "start": "next start"},
                    "dependencies": {"next": "16.0.0", "react": "19.0.0"},
                }
            ),
            "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
        },
    )

    service = detect(tmp_path).services[0]

    assert service.framework == "Next.js"
    assert service.build.install_command == ("pnpm", "install", "--frozen-lockfile")
    assert service.build.build_command == ("pnpm", "run", "build")
    assert service.processes[0].command == ("pnpm", "run", "start")


def test_detects_fastapi_without_reading_arbitrary_source(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "pyproject.toml": '[project]\nname="api"\ndependencies=["fastapi", "uvicorn"]\n',
            "uv.lock": "version = 1\n",
            "main.py": (
                "from fastapi import FastAPI\n"
                "app = FastAPI()\n"
                "raise RuntimeError('must never execute')\n"
            ),
            "private.py": "API_TOKEN = 'this file is not detector metadata'\n",
        },
    )

    result = detect(tmp_path)

    assert result.blocked is False
    service = result.services[0]
    assert service.framework == "FastAPI"
    assert service.processes[0].command[:2] == ("uvicorn", "main:app")
    assert "private.py" not in service.files_considered


def test_detects_go_web_and_worker_processes_in_one_module(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "go.mod": "module example.invalid/platform\n\ngo 1.26\n",
            "go.sum": "example.invalid/dependency v1.0.0 h1:fixture\n",
            "cmd/api/main.go": 'package main\n// http.ListenAndServe(":8080", nil)\n',
        },
    )
    single = detect(tmp_path)
    assert single.blocked is False
    assert single.services[0].processes[0].command == ("/app/out/api",)

    write_tree(tmp_path, {"cmd/worker/main.go": "package main\n"})
    multiple = detect(tmp_path)
    assert multiple.blocked is False
    assert {process.name for process in multiple.services[0].processes} == {"api", "worker"}


def test_dockerfile_overrides_build_method_but_keeps_framework(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "Gemfile": 'gem "rails"\n',
            "Gemfile.lock": "GEM\n",
            "Dockerfile": 'FROM ruby:3.4\nEXPOSE 8080\nCMD ["bin/rails", "server"]\n',
        },
    )

    service = detect(tmp_path).services[0]

    assert service.framework == "Rails"
    assert service.build.strategy == "dockerfile"
    assert service.processes[0].port == 8080
    assert service.processes[0].command == ("bin/rails", "server")
    detector_ids = {
        result.detector
        for result in detect(tmp_path).evidence_graph.nodes
        if result.id in service.evidence_ids
    }
    assert detector_ids == {"docker", "ruby"}


def test_dockerfile_without_runtime_hints_requires_confirmation(tmp_path: Path) -> None:
    write_tree(tmp_path, {"Dockerfile": "FROM scratch\nCOPY . /app\n"})

    result = detect(tmp_path)

    assert result.blocked is True
    assert result.services[0].framework == "Dockerfile"
    assert result.services[0].ambiguous is True


def test_detects_plain_static_site(tmp_path: Path) -> None:
    write_tree(tmp_path, {"index.html": "<!doctype html><title>Static</title>"})

    result = detect(tmp_path)

    assert result.blocked is False
    assert result.services[0].language == "static"
    assert result.services[0].processes[0].kind == "static"


def test_detects_multi_service_workspace_deterministically(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "package.json": json.dumps({"name": "root", "workspaces": ["apps/*"]}),
            "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
            "apps/web/package.json": json.dumps(
                {
                    "name": "web",
                    "scripts": {"build": "vite build"},
                    "devDependencies": {"vite": "8.0.0"},
                }
            ),
            "apps/api/package.json": json.dumps(
                {
                    "name": "api",
                    "scripts": {"start": "node server.js"},
                    "dependencies": {"express": "5.0.0"},
                }
            ),
        },
    )

    first = detect(tmp_path)
    second = detect(tmp_path)

    assert first == second
    assert [service.root for service in first.services] == ["apps/api", "apps/web"]
    assert any("Monorepo proposal" in warning.message for warning in first.warnings)


def test_conflicting_frameworks_at_one_root_block_deployment(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "Gemfile": 'gem "rails"\n',
            "package.json": json.dumps(
                {
                    "scripts": {"build": "next build", "start": "next start"},
                    "dependencies": {"next": "16.0.0"},
                }
            ),
        },
    )

    result = detect(tmp_path)

    assert result.blocked is True
    assert result.services[0].ambiguous is True
    assert any(item.code == "resolver.framework-conflict" for item in result.unresolved)


def test_malformed_metadata_is_safe_and_explainable(tmp_path: Path) -> None:
    write_tree(tmp_path, {"package.json": "{not-json", "README.md": "next express"})

    result = detect(tmp_path)

    assert result.blocked is True
    assert result.services == ()
    assert any(item.code == "node.invalid-package-json" for item in result.warnings)
    assert any(item.code == "detector.no-service" for item in result.unresolved)


def test_selected_root_limits_monorepo_detection(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "apps/api/package.json": json.dumps(
                {"scripts": {"start": "node server.js"}, "dependencies": {"express": "5"}}
            ),
            "apps/web/index.html": "<h1>web</h1>",
        },
    )

    result = detect(tmp_path, "apps/api")

    assert [service.root for service in result.services] == ["apps/api"]
    assert result.snapshot_root == "apps/api"


@pytest.mark.parametrize("selected", ["../other", "/absolute", "apps\\api", "a/../../b"])
def test_rejects_selected_root_escape(tmp_path: Path, selected: str) -> None:
    tmp_path.joinpath("app").mkdir()

    result = detect(tmp_path, selected)

    assert result.blocked is True
    assert result.services == ()
    assert "selected root" in result.unresolved[0].message


def test_skips_symlinks_even_when_they_look_like_manifests(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside.json"
    outside.write_text(json.dumps({"scripts": {"start": "bad"}}), encoding="utf-8")
    try:
        (tmp_path / "package.json").symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable on this host")

    result = detect(tmp_path)

    assert result.services == ()
    assert result.blocked is True


def test_rejects_oversized_metadata(tmp_path: Path) -> None:
    package = tmp_path / "package.json"
    with package.open("wb") as handle:
        handle.seek(MAX_METADATA_BYTES)
        handle.write(b"x")

    result = detect(tmp_path)

    assert result.blocked is True
    assert any(
        "metadata file exceeds" in item.message for item in result.warnings + result.unresolved
    )


def test_depth_limit_prevents_adversarial_tree(tmp_path: Path) -> None:
    current = tmp_path
    for index in range(35):
        current /= f"d{index}"
        current.mkdir()
    (current / "index.html").write_text("x", encoding="utf-8")

    result = detect(tmp_path)

    assert result.blocked is True
    assert any("depth exceeds" in item.message for item in result.unresolved)


def test_cli_emits_one_contract_and_block_exit(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    write_tree(tmp_path, {"index.html": "<h1>ok</h1>"})
    assert main([str(tmp_path), "--snapshot-id", SNAPSHOT_ID, "--pretty", "--fail-on-block"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == "detector.lrail.dev/v2"

    empty = tmp_path / "empty"
    empty.mkdir()
    assert main([str(empty), "--snapshot-id", SNAPSHOT_ID, "--fail-on-block"]) == 2
    blocked = json.loads(capsys.readouterr().out)
    assert blocked["blocked"] is True


def test_service_limit_blocks_unbounded_monorepo(tmp_path: Path) -> None:
    for index in range(3):
        write_tree(tmp_path, {f"apps/app-{index}/index.html": "<h1>app</h1>"})

    result = Detector(max_services=2).detect(tmp_path, SNAPSHOT_ID)

    assert result.blocked is True
    assert len(result.services) == 2
    assert any(item.code == "detector.service-limit" for item in result.unresolved)


def test_inventory_rejects_non_directory(tmp_path: Path) -> None:
    target = tmp_path / "snapshot.tar"
    target.write_text("not a directory", encoding="utf-8")

    with pytest.raises(InventoryError, match="must be a directory"):
        SnapshotInventory.build(target)


def test_detector_rejects_invalid_service_limit() -> None:
    with pytest.raises(ValueError, match="between 1 and 64"):
        Detector(max_services=0)


def test_network_process_requires_port() -> None:
    with pytest.raises(ValidationError, match="requires a port"):
        ProcessProposal(name="web", kind="web", command=("run",))


def test_rails_with_vite_assets_selects_rails(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "Gemfile": 'gem "rails"\n',
            "Gemfile.lock": "GEM\n",
            "package.json": json.dumps(
                {"scripts": {"build": "vite build"}, "devDependencies": {"vite": "8"}}
            ),
            "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
        },
    )

    result = detect(tmp_path)

    assert result.blocked is False
    assert result.services[0].framework == "Rails"
    assert set(result.services[0].files_considered) == {
        "Gemfile",
        "Gemfile.lock",
        "package.json",
        "pnpm-lock.yaml",
    }
    assert any(item.code == "resolver.lower-confidence-candidate" for item in result.warnings)


@pytest.mark.parametrize(
    ("metadata", "entry", "framework", "expected"),
    [
        ("django==6.0", "manage.py", "Django", ("gunicorn", "project.wsgi:application")),
        ("flask==4.0", "app.py", "Flask", ("gunicorn", "--bind")),
    ],
)
def test_detects_additional_python_frameworks(
    tmp_path: Path,
    metadata: str,
    entry: str,
    framework: str,
    expected: tuple[str, ...],
) -> None:
    write_tree(tmp_path, {"requirements.txt": metadata, entry: "# metadata entry\n"})

    service = detect(tmp_path).services[0]

    assert service.framework == framework
    assert service.processes[0].command[:2] == expected


def test_node_reports_unsupported_native_desktop_dependencies(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "package.json": json.dumps(
                {
                    "name": "@demo/desktop",
                    "scripts": {"start": "electron ."},
                    "dependencies": {"electron": "40", "node-gyp": "12"},
                }
            )
        },
    )

    service = detect(tmp_path).services[0]

    assert service.name == "demo-desktop"
    assert detect(tmp_path).blocked is True
    assert service.unsupported_features == (
        "desktop_runtime",
        "native_addon_requires_build_validation",
    )


def test_non_object_scripts_do_not_crash(tmp_path: Path) -> None:
    write_tree(tmp_path, {"package.json": json.dumps({"scripts": [], "dependencies": {}})})
    assert detect(tmp_path).services == ()


def test_invalid_docker_hints_are_bounded(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {"Dockerfile": 'FROM scratch\nEXPOSE 99999\nCMD ["unterminated"\n'},
    )

    result = detect(tmp_path)

    assert result.services[0].processes[0].port == 8080
    assert any("port" in item.code for item in result.unresolved)


def test_duplicate_service_names_get_stable_path_suffix(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "apps/site/index.html": "<h1>one</h1>",
            "services/site/index.html": "<h1>two</h1>",
        },
    )

    names = [service.name for service in detect(tmp_path).services]

    assert names == ["site", "site-services-site"]


def test_selected_root_symlink_is_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (real / "index.html").write_text("ok", encoding="utf-8")
    link = tmp_path / "linked"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable on this host")

    result = detect(tmp_path, "linked")

    assert result.blocked is True
    assert "symlink" in result.unresolved[0].message


def test_non_utf8_metadata_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_bytes(b"\xff\xfe\x00")
    result = detect(tmp_path)
    assert result.blocked is True
    assert any("not UTF-8" in item.message for item in result.warnings + result.unresolved)


@given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-", min_size=1, max_size=30))
def test_arbitrary_safe_missing_root_never_escapes(selected: str) -> None:
    with TemporaryDirectory() as directory:
        result = detect(Path(directory), selected)
        assert result.blocked is True
        assert result.services == ()
