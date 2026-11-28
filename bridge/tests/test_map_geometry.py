"""Tests for the static province identity raster used by map rendering."""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
from PIL import Image

from bridge.map_geometry import load_map_geometry


def _fixture(root: Path) -> None:
    map_dir = root / "map"
    map_dir.mkdir(parents=True)
    (root / "launcher-settings.json").write_text(json.dumps({"rawVersion": "v1.37.4.0"}), encoding="utf-8")
    (map_dir / "default.map").write_text(
        'width = 4\nheight = 2\n'
        'definitions = "definition.csv"\nprovinces = "provinces.bmp"\n'
        'adjacencies = "adjacencies.csv"\nclimate = "climate.txt"\n'
        'sea_starts = { 2 }\nlakes = { 3 }\n',
        encoding="utf-8",
    )
    (map_dir / "definition.csv").write_text(
        "province;red;green;blue;name\n"
        "0;0;0;0;sentinel\n"
        "1;128;34;64;A\n"
        "2;0;36;128;B\n"
        "3;128;38;192;C\n",
        encoding="utf-8",
    )
    (map_dir / "climate.txt").write_text(
        "temperate = {\n 1\n # Wasteland\n 1\n}\nimpassable = { 3 }\n", encoding="utf-8"
    )
    (map_dir / "adjacencies.csv").write_text(
        "From;To;Type;Through;start_x;start_y;stop_x;stop_y;Comment\n",
        encoding="utf-8",
    )
    pixels = np.array(
        [
            [[128, 34, 64], [0, 36, 128], [128, 38, 192], [0, 0, 0]],
            [[128, 34, 64], [0, 36, 128], [128, 38, 192], [128, 34, 64]],
        ], dtype=np.uint8,
    )
    Image.fromarray(pixels, mode="RGB").save(map_dir / "provinces.bmp")


def test_loads_identity_raster_and_static_classes(tmp_path):
    _fixture(tmp_path)
    geometry = load_map_geometry(game_root=tmp_path, user_data=tmp_path / "user", enabled_mods=[])
    assert geometry.shape == (2, 4)
    assert geometry.province_ids.tolist() == [[1, 2, 3, 0], [1, 2, 3, 1]]
    assert geometry.province_at(0, 0) == 1
    assert geometry.province_at(3, 0) is None
    assert geometry.province_at(-1, 0) is None
    assert geometry.kind_for_province(2) == "sea"
    assert geometry.kind_for_province(3) == "lake"
    assert geometry.kind_for_province(1) == "land"
    assert geometry.wasteland_province_ids == frozenset({3})
