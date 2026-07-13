from __future__ import annotations

import json
from pathlib import Path

from lrail_detector.engine import detect

SNAPSHOT_ID = "snp_019b01da-7e31-7000-8000-000000000039"


def write_tree(root: Path, files: dict[str, str | bytes]) -> None:
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")


def test_docker_compose_security_and_runtime_ambiguities(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "Dockerfile": "FROM alpine\nEXPOSE 8080 9090\nCMD app --serve\n",
            "compose.yaml": (
                "services:\n  app:\n    ports: ['3000:3000']\n"
                "    privileged: true\n    network_mode: host\n"
            ),
        },
    )

    result = detect(tmp_path, SNAPSHOT_ID)

    assert result.blocked is True
    assert {item.code for item in result.unresolved} >= {
        "docker.multiple-exposed-ports",
        "docker.shell-command",
        "docker.command-unresolved",
    }
    assert set(result.unsupported_features) == {"host_network", "privileged_container"}
    assert "compose.yaml" in result.files_considered


def test_docker_invalid_json_command_and_unreadable_metadata(tmp_path: Path) -> None:
    write_tree(tmp_path, {"Dockerfile": 'FROM scratch\nEXPOSE 8080\nCMD [1, "bad"]\n'})
    result = detect(tmp_path, SNAPSHOT_ID)
    assert "docker.invalid-json-command" in {item.code for item in result.unresolved}

    (tmp_path / "Dockerfile").write_bytes(b"\xff\xfe")
    unreadable = detect(tmp_path, SNAPSHOT_ID)
    assert unreadable.services == ()
    assert "docker.unreadable-dockerfile" in {item.code for item in unreadable.warnings}


def test_python_django_wsgi_and_procfile_processes(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "requirements.txt": "django==6.0\ngunicorn==23.0.0\npsycopg==3.2.10\n",
            "project/wsgi.py": "application = object()\n",
            "Procfile": (
                "web: gunicorn project.wsgi:application --bind 0.0.0.0:8000\n"
                "worker: python worker.py\n"
            ),
        },
    )

    result = detect(tmp_path, SNAPSHOT_ID)
    service = result.services[0]

    assert result.blocked is False
    assert {process.name for process in service.processes} == {"web", "worker"}
    assert service.processes[0].command[0] == "gunicorn"
    assert {addon.engine for addon in result.suggested_addons} == {"postgresql"}


def test_python_worker_and_framework_conflict_paths(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "pyproject.toml": ('[project]\nname="worker"\ndependencies=["celery", "redis"]\n'),
            "uv.lock": "version = 1\n",
        },
    )
    worker = detect(tmp_path, SNAPSHOT_ID)
    assert worker.services[0].kind == "worker"
    assert "python.worker-module-unresolved" in {item.code for item in worker.unresolved}

    write_tree(
        tmp_path,
        {
            "pyproject.toml": (
                '[project]\nname="conflict"\ndependencies=["fastapi", "flask", "uvicorn"]\n'
            ),
            "main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
        },
    )
    conflict = detect(tmp_path, SNAPSHOT_ID)
    assert "python.multiple-frameworks" in {item.code for item in conflict.unresolved}


def test_python_requirements_directives_and_missing_server_block(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "requirements.txt": "-r private.txt\nfastapi==0.116.1\n",
            "main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
        },
    )

    result = detect(tmp_path, SNAPSHOT_ID)
    codes = {item.code for item in result.unresolved}

    assert "python.requirements-directive-unresolved" in codes
    assert "python.missing-asgi-server" in codes


def test_python_pipenv_flask_and_rq_worker_are_reproducible(tmp_path: Path) -> None:
    flask = tmp_path / "flask"
    worker = tmp_path / "worker"
    write_tree(
        flask,
        {
            "Pipfile": '[packages]\nflask = "==4.0"\ngunicorn = "==23.0.0"\n',
            "Pipfile.lock": "{}\n",
            "app.py": "from flask import Flask\napp = Flask(__name__)\n",
        },
    )
    write_tree(
        worker,
        {
            "pyproject.toml": '[project]\ndependencies=["rq"]\n',
            "uv.lock": "version = 1\n",
        },
    )

    flask_result = detect(flask, SNAPSHOT_ID)
    worker_result = detect(worker, SNAPSHOT_ID)

    assert flask_result.blocked is False
    assert flask_result.services[0].build.install_command == ("pipenv", "sync", "--deploy")
    assert worker_result.blocked is False
    assert worker_result.services[0].processes[0].command == ("rq", "worker")


def test_ruby_rack_worker_conflict_and_missing_lock_paths(tmp_path: Path) -> None:
    rack = tmp_path / "rack"
    conflict = tmp_path / "conflict"
    worker = tmp_path / "worker"
    write_tree(
        rack,
        {
            "Gemfile": 'gem "sinatra"\ngem "rack"\n',
            "Gemfile.lock": "GEM\n",
            "config.ru": "run Sinatra::Application\n",
        },
    )
    write_tree(
        conflict,
        {
            "Gemfile": 'gem "sinatra"\ngem "roda"\n',
            "Gemfile.lock": "GEM\n",
        },
    )
    write_tree(worker, {"Gemfile": 'gem "sidekiq"\n', "Gemfile.lock": "GEM\n"})

    assert detect(rack, SNAPSHOT_ID).services[0].framework == "Sinatra"
    assert "ruby.multiple-frameworks" in {
        item.code for item in detect(conflict, SNAPSHOT_ID).unresolved
    }
    worker_result = detect(worker, SNAPSHOT_ID)
    assert worker_result.blocked is False
    assert worker_result.services[0].kind == "worker"
    assert {addon.engine for addon in worker_result.suggested_addons} == {"valkey"}

    (rack / "Gemfile.lock").unlink()
    assert "ruby.missing-lockfile" in {item.code for item in detect(rack, SNAPSHOT_ID).unresolved}


def test_go_missing_main_checksum_build_tag_and_port_paths(tmp_path: Path) -> None:
    write_tree(tmp_path, {"go.mod": "module example.invalid/lib\n\ngo 1.26\n"})
    library = detect(tmp_path, SNAPSHOT_ID)
    assert library.services == ()
    assert "go.no-main-package" in {item.code for item in library.warnings}

    write_tree(
        tmp_path,
        {
            "cmd/api/main.go": (
                '//go:build linux\npackage main\n// http.ListenAndServe(":70000", nil)\n'
            )
        },
    )
    command = detect(tmp_path, SNAPSHOT_ID)
    codes = {item.code for item in command.unresolved}
    assert {
        "go.build-tags-require-review",
        "go.listen-port-unresolved",
        "go.missing-checksums",
    } <= codes


def test_root_go_main_without_network_markers_is_a_worker(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "go.mod": "module example.invalid/worker\n\ngo 1.26\n",
            "go.sum": "example.invalid/x v1.0.0 h1:fixture\n",
            "main.go": "package main\nfunc main() {}\n",
        },
    )

    result = detect(tmp_path, SNAPSHOT_ID)

    assert result.blocked is False
    process = result.services[0].processes[0]
    assert (process.name, process.kind, process.port) == ("app", "worker", None)
    assert result.services[0].build.build_command[-2:] == ("out/app", "./.")


def test_node_svelte_adapter_runtime_and_framework_conflicts(tmp_path: Path) -> None:
    package = {
        "name": "svelte-app",
        "engines": {"node": ">=24"},
        "scripts": {"build": "vite build", "start": "node build"},
        "dependencies": {"@sveltejs/kit": "2"},
    }
    write_tree(
        tmp_path,
        {"package.json": json.dumps(package), "pnpm-lock.yaml": "lockfileVersion: '9'\n"},
    )
    unresolved = detect(tmp_path, SNAPSHOT_ID)
    assert unresolved.services[0].runtime.version == ">=24"
    assert "node.svelte-adapter-unresolved" in {item.code for item in unresolved.unresolved}

    package["dependencies"]["@sveltejs/adapter-static"] = "3"
    write_tree(tmp_path, {"package.json": json.dumps(package)})
    static = detect(tmp_path, SNAPSHOT_ID)
    assert static.blocked is False
    assert static.services[0].kind == "static"
    assert static.services[0].build.output_path == "build"

    package["dependencies"]["next"] = "16"
    write_tree(tmp_path, {"package.json": json.dumps(package)})
    conflict = detect(tmp_path, SNAPSHOT_ID)
    assert "node.multiple-frameworks" in {item.code for item in conflict.unresolved}


def test_empty_runtime_version_warns_without_blocking_locked_node_service(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "package.json": json.dumps(
                {
                    "scripts": {"start": "node server.js"},
                    "dependencies": {"express": "5"},
                }
            ),
            "package-lock.json": '{"lockfileVersion":3}\n',
            ".node-version": "\n",
        },
    )

    result = detect(tmp_path, SNAPSHOT_ID)

    assert result.blocked is False
    assert "runtime.empty-version" in {item.code for item in result.warnings}
