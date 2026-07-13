from __future__ import annotations

from pathlib import Path

import pytest

import lrail_detector.inventory as inventory_module
from lrail_detector.inventory import InventoryError, SnapshotInventory


def test_inventory_read_capabilities_reject_unlisted_and_unreadable_paths(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("text", encoding="utf-8")
    (tmp_path / "image.bin").write_bytes(b"binary")
    inventory = SnapshotInventory.build(tmp_path)

    with pytest.raises(InventoryError, match="not inventoried"):
        inventory.read_text("missing.json")
    with pytest.raises(InventoryError, match="not detector-readable metadata"):
        inventory.read_text("README.md")
    with pytest.raises(InventoryError, match="not detector-readable source"):
        inventory.read_header("image.bin")
    with pytest.raises(InventoryError, match="not inventoried"):
        inventory.read_header("missing.py")


def test_inventory_caches_text_and_headers_and_enforces_total_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "package.json").write_text('{"name":"fixture"}', encoding="utf-8")
    (tmp_path / "main.py").write_text("app = object()\n", encoding="utf-8")
    (tmp_path / "worker.py").write_text("run = object()\n", encoding="utf-8")
    inventory = SnapshotInventory.build(tmp_path)

    assert inventory.read_text("package.json") is inventory.read_text("package.json")
    assert inventory.read_header("package.json") == '{"name":"fixture"}'
    assert inventory.read_header("main.py") is inventory.read_header("main.py")
    monkeypatch.setattr(inventory_module, "MAX_TOTAL_READ_BYTES", 4)
    with pytest.raises(InventoryError, match="read budget"):
        inventory.read_header("worker.py")


def test_inventory_rejects_non_utf8_header_and_oversized_direct_metadata(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_bytes(b"\xff\xfe")
    package = tmp_path / "package.json"
    with package.open("wb") as handle:
        handle.seek(inventory_module.MAX_METADATA_BYTES)
        handle.write(b"x")
    inventory = SnapshotInventory.build(tmp_path)

    with pytest.raises(InventoryError, match="source header is not UTF-8"):
        inventory.read_header("main.py")
    with pytest.raises(InventoryError, match="metadata file exceeds"):
        inventory.read_text("package.json")


def test_inventory_rejects_missing_file_and_selected_file_roots(tmp_path: Path) -> None:
    (tmp_path / "file").write_text("x", encoding="utf-8")
    with pytest.raises(InventoryError, match="does not exist"):
        SnapshotInventory.build(tmp_path, "missing")
    with pytest.raises(InventoryError, match="real directory"):
        SnapshotInventory.build(tmp_path, "file")
    with pytest.raises(InventoryError, match="canonical POSIX"):
        SnapshotInventory.build(tmp_path, "a/./b")
    with pytest.raises(InventoryError, match="snapshot root does not exist"):
        SnapshotInventory.build(tmp_path / "missing-root")


def test_inventory_file_limit_and_skipped_directories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "one.txt").write_text("1", encoding="utf-8")
    (tmp_path / "two.txt").write_text("2", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(inventory_module, "MAX_FILES", 1)

    with pytest.raises(InventoryError, match="file count exceeds"):
        SnapshotInventory.build(tmp_path)


def test_inventory_rejects_root_symlink_and_post_inventory_metadata_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    package = real / "package.json"
    package.write_text("{}", encoding="utf-8")
    root_link = tmp_path / "root-link"
    try:
        root_link.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(InventoryError, match="root cannot be a symlink"):
        SnapshotInventory.build(root_link)

    inventory = SnapshotInventory.build(real)
    package.unlink()
    package.symlink_to(tmp_path / "outside.json")
    with pytest.raises(InventoryError, match="metadata symlink rejected"):
        inventory.read_text("package.json")
