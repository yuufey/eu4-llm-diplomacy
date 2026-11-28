from __future__ import annotations

import json
import threading

from PIL import Image

from bridge.map_archive import SCHEMA, publish_map_bundle


class FakeMapService:
    def __init__(self):
        self.calls = 0

    def render_bundle(self, **kwargs):
        self.calls += 1
        snapshot_id = f"snapshot-{self.calls}"
        images = {
            scale: Image.new("RGB", (8, 6), color=(self.calls, 20, 30))
            for scale in ("overview", "region", "local")
        }
        views = {
            scale: {"size": [8, 6], "date": "1495.2.3", "snapshot_id": snapshot_id,
                    "cells": "encoded"}
            for scale in images
        }
        return {
            "images": images,
            "views": views,
            "snapshot": {"date": "1495.2.3", "owners": {1: "TUR"},
                          "identity": {"pid": 1}},
            "observer": "TUR",
            "snapshot_id": snapshot_id,
            "metrics": {"capture_seconds": 0.1},
        }


def test_publish_writes_three_images_data_and_atomic_pointer(tmp_path):
    service = FakeMapService()
    result = publish_map_bundle(service, tmp_path)

    assert service.calls == 1
    assert result["schema"] == SCHEMA
    assert result["latest"] is True
    bundle = tmp_path / "bundles" / result["bundle_id"]
    assert (bundle / "manifest.json").is_file()
    assert (bundle / "snapshot.json").is_file()
    assert {path.name for path in bundle.glob("*.png")} == {"overview.png", "region.png", "local.png"}
    assert json.loads((tmp_path / "latest.json").read_text(encoding="utf-8"))["bundle_id"] == result["bundle_id"]


def test_cleanup_keeps_two_own_bundles_and_unrelated_directory(tmp_path):
    service = FakeMapService()
    for _ in range(4):
        publish_map_bundle(service, tmp_path)
    unrelated = tmp_path / "bundles" / "keep-me"
    unrelated.mkdir()
    (unrelated / "note.txt").write_text("preserve", encoding="utf-8")

    own = [path for path in (tmp_path / "bundles").iterdir()
           if path.is_dir() and (path / "manifest.json").is_file()]
    assert len(own) == 2
    assert unrelated.is_dir()
    assert (tmp_path / "latest.json").is_file()


def test_cleanup_does_not_delete_user_file_inside_old_bundle(tmp_path):
    service = FakeMapService()
    first = publish_map_bundle(service, tmp_path)
    publish_map_bundle(service, tmp_path)
    user_file = tmp_path / "bundles" / first["bundle_id"] / "user-notes.txt"
    user_file.write_text("keep this", encoding="utf-8")

    publish_map_bundle(service, tmp_path)

    assert user_file.read_text(encoding="utf-8") == "keep this"
    assert user_file.parent.is_dir()


def test_existing_non_map_latest_is_not_overwritten(tmp_path):
    latest = tmp_path / "latest.json"
    latest.write_text("user-owned", encoding="utf-8")
    service = FakeMapService()

    import pytest
    with pytest.raises(ValueError, match="MAP_BUNDLE_LATEST_CONFLICT"):
        publish_map_bundle(service, tmp_path)

    assert latest.read_text(encoding="utf-8") == "user-owned"
    assert service.calls == 0


def test_bundles_file_cannot_redirect_archive_outside_root(tmp_path):
    bundles = tmp_path / "bundles"
    bundles.write_text("user-owned", encoding="utf-8")
    service = FakeMapService()

    import pytest
    with pytest.raises(ValueError, match="MAP_BUNDLE_BUNDLES_EXTERNAL"):
        publish_map_bundle(service, tmp_path)

    assert bundles.read_text(encoding="utf-8") == "user-owned"
    assert service.calls == 0


def test_publishers_serialize_same_directory(tmp_path):
    service = FakeMapService()
    results = []
    errors = []

    def publish():
        try:
            results.append(publish_map_bundle(service, tmp_path))
        except BaseException as error:  # pragma: no cover - failure is asserted below
            errors.append(error)

    threads = [threading.Thread(target=publish) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(results) == 2
    assert (tmp_path / "latest.json").is_file()
