"""Tests for effective static country colours used by political maps."""
from __future__ import annotations

import json
from pathlib import Path

from bridge.map_colors import load_country_colors


def _fixture(root: Path) -> None:
    (root / "map").mkdir(parents=True)
    (root / "common" / "country_tags").mkdir(parents=True)
    (root / "common" / "countries").mkdir(parents=True)
    (root / "launcher-settings.json").write_text(json.dumps({"rawVersion": "v1.37.4.0"}), encoding="utf-8")
    (root / "map" / "default.map").write_text(
        'definitions = "definition.csv"\nadjacencies = "adjacencies.csv"\n', encoding="utf-8"
    )
    (root / "map" / "definition.csv").write_text(
        "province;red;green;blue;name\n1;128;34;64;A\n", encoding="utf-8"
    )
    (root / "map" / "adjacencies.csv").write_text(
        "From;To;Type;Through;start_x;start_y;stop_x;stop_y;Comment\n", encoding="utf-8"
    )
    (root / "common" / "country_tags" / "00_countries.txt").write_text(
        'FRA = "countries/France.txt"\nTUR = "countries/Ottomans.txt"\n', encoding="utf-8"
    )
    (root / "common" / "countries" / "France.txt").write_text(
        "color = { 20 50 210 }\n", encoding="utf-8"
    )
    (root / "common" / "countries" / "Ottomans.txt").write_text(
        "color = { 126 203 120 }\n", encoding="utf-8"
    )


def test_resolves_tags_to_country_definition_colors_and_accepts_save_override(tmp_path):
    _fixture(tmp_path)
    colors = load_country_colors(
        game_root=tmp_path, user_data=tmp_path / "user", enabled_mods=[], save_colors={"TUR": (1, 2, 3)}
    )
    assert colors.colors["FRA"] == (20, 50, 210)
    assert colors.lookup("TUR").rgb == (1, 2, 3)
    assert colors.lookup("TUR").source == "save_map_color"
    assert colors.context()["status"] == "ready"


def test_only_tags_limits_definition_reads(tmp_path):
    _fixture(tmp_path)
    colors = load_country_colors(game_root=tmp_path, user_data=tmp_path / "user", enabled_mods=[], only_tags=["FRA"])
    assert set(colors.colors) == {"FRA"}
