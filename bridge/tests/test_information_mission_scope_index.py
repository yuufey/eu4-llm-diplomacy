"""Offline tests for bounded effective static mission-scope membership."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from bridge.information.mission_definitions import _parse_mission_script
from bridge.information.mission_scope_index import StaticMissionScopeIndex


_DEFINITION_HEADER = "province;red;green;blue;name"
_ADJACENCY_HEADER = "From;To;Type;Through;start_x;start_y;stop_x;stop_y;Comment"


class _FixtureParser:
    def context(self):
        return {"status": "ready", "complete": True, "name": "fixture", "version": "test"}

    def parse_files(self, paths):
        result = {}
        for path in paths:
            path = Path(path).resolve()
            text = path.read_text(encoding="utf-8")
            result[str(path)] = {"nodes": _parse_mission_script(text), "text": text}
        return result


def _csv_definitions(ids=range(1, 9)) -> str:
    rows = [_DEFINITION_HEADER, "0;0;0;0;sentinel"]
    rows.extend(f"{value};{value};0;0;province_{value}" for value in ids)
    return "\n".join(rows) + "\n"


def _write_game(root: Path, *, areas: str | None = None, regions: str | None = None,
                superregions: str | None = None, continents: str | None = None,
                province_groups: str | None = None, country_tags: str | None = None,
                adjacency_row: str | None = None, definitions: str | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "launcher-settings.json").write_text(
        json.dumps({"rawVersion": "v1.37.4.0"}), encoding="utf-8"
    )
    map_dir = root / "map"
    map_dir.mkdir(parents=True, exist_ok=True)
    (map_dir / "default.map").write_text(
        'definitions = "definition.csv"\nadjacencies = "adjacencies.csv"\n', encoding="utf-8"
    )
    (map_dir / "definition.csv").write_text(
        _csv_definitions() if definitions is None else definitions, encoding="utf-8"
    )
    rows = [_ADJACENCY_HEADER]
    if adjacency_row is not None:
        rows.append(adjacency_row)
    (map_dir / "adjacencies.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    (map_dir / "area.txt").write_text(areas or "alpha_area = { 1 2 }\nbeta_area = { 3 4 }\n", encoding="utf-8")
    (map_dir / "region.txt").write_text(
        regions or "west_region = { areas = { alpha_area beta_area } }\n", encoding="utf-8"
    )
    (map_dir / "superregion.txt").write_text(
        superregions or "west_superregion = { west_region }\n", encoding="utf-8"
    )
    (map_dir / "continent.txt").write_text(
        continents or "europe = { 1 2 3 4 }\n", encoding="utf-8"
    )
    (map_dir / "provincegroup.txt").write_text(
        province_groups or "west_group = { 1 2 }\n", encoding="utf-8"
    )
    tag_dir = root / "common" / "country_tags"
    tag_dir.mkdir(parents=True, exist_ok=True)
    (tag_dir / "00_countries.txt").write_text(
        country_tags or 'FRA = "countries/FRA.txt"\nENG = "countries/ENG.txt"\n',
        encoding="utf-8",
    )
    return root


def _index(game: Path, user: Path, mods=None) -> StaticMissionScopeIndex:
    return StaticMissionScopeIndex(
        game, user, enabled_mods=[] if mods is None else mods, script_parser=_FixtureParser()
    )


def test_resolves_transitive_geography_country_tags_and_csv_provinces(tmp_path):
    game = _write_game(
        tmp_path / "game",
        areas=("alpha_area = { 1 2 color = { 10 20 30 } }\n"
               "beta_area = { 3 4 }\nFRA = { 5 }\nbad_area = { 99 }\nempty_area = { }\n"),
        regions=("west_region = { areas = { alpha_area beta_area } monsoon = { start = 4 end = 9 } }\n"
                 "bad_region = { areas = { missing_area } }\nrandom_new_world_region = { }\n"),
        superregions=("west_superregion = { west_region restrict_charter }\n"
                      "bad_superregion = { missing_region }\n"),
        continents="europe = { 1 2 3 4 }\n",
        province_groups="west_group = { 1 2 }\n",
    )
    index = _index(game, tmp_path / "user")
    context = index.context()
    assert context["status"] == "ready"
    assert context["game_root"] == str(game.resolve())
    assert context["user_data"] == str((tmp_path / "user").resolve())
    assert context["script_parser"]["name"] == "fixture"
    assert context["component_statuses"]["country_tags"]["status"] == "ready"

    rows = index.lookup_scopes([
        "alpha_area", "west_region", "west_superregion", "europe", "west_group",
        "ENG", "1", "8", "bad_area", "empty_area", "bad_region", "random_new_world_region",
        "bad_superregion", "FRA",
    ])
    assert rows["alpha_area"]["status"] == "known"
    assert rows["alpha_area"]["kind"] == "areas"
    assert rows["alpha_area"]["members"] == [1, 2]
    assert rows["west_region"]["members"] == [1, 2, 3, 4]
    assert rows["west_superregion"]["members"] == [1, 2, 3, 4]
    assert rows["europe"]["members"] == [1, 2, 3, 4]
    assert rows["west_group"]["members"] == [1, 2]
    assert rows["ENG"] == {
        "status": "known", "kind": "country_tag", "name": "ENG", "value": "ENG",
        "source": rows["ENG"]["source"],
    }
    assert rows["ENG"]["source"]["files"][0]["relative"] == "common/country_tags/00_countries.txt"
    assert rows["1"]["kind"] == "province_id" and rows["1"]["value"] == 1
    assert rows["8"]["status"] == "known"
    assert rows["bad_area"]["status"] == "unknown"
    assert rows["empty_area"]["status"] == "unknown"
    assert rows["bad_region"]["status"] == "unknown"
    assert rows["random_new_world_region"]["status"] == "unknown"
    assert rows["bad_superregion"]["status"] == "unknown"
    assert rows["FRA"] == {"status": "unknown", "name": "FRA", "reason": "SCOPE_KIND_COLLISION"}
    assert rows["8"]["status"] == "known"
    assert index.lookup_scope("99")["status"] == "unknown"


def test_map_area_replace_path_overrides_only_the_selected_area_file(tmp_path):
    game = _write_game(tmp_path / "game")
    user = tmp_path / "user"
    mod_root = user / "mod" / "area_override"
    (mod_root / "map").mkdir(parents=True)
    (mod_root / "map" / "area.txt").write_text("alpha_area = { 7 }\n", encoding="utf-8")
    descriptor = user / "mod" / "area_override.mod"
    descriptor.parent.mkdir(parents=True, exist_ok=True)
    descriptor.write_text(
        f'name="area override"\npath="{str(mod_root).replace(chr(92), "/")}"\n'
        'replace_path="map/area.txt"\n', encoding="utf-8"
    )
    index = _index(game, user, ["mod/area_override.mod"])
    context = index.context()
    assert context["status"] == "ready"
    assert context["enabled_mods"][0]["replace_paths"] == ["map/area.txt"]
    area = index.lookup_scope("alpha_area")
    assert area["status"] == "known" and area["members"] == [7]
    area_file = next(row for row in area["source"]["files"] if row["relative"] == "map/area.txt")
    assert area_file["source_kind"] == "enabled_mod"
    assert index.lookup_scope("beta_area")["status"] == "unknown"


def test_malformed_adjacencies_do_not_withdraw_independent_scope_components(tmp_path):
    game = _write_game(
        tmp_path / "game", adjacency_row="not;a;valid;row",
    )
    index = _index(game, tmp_path / "user")
    context = index.context()
    assert context["status"] == "ready"
    assert index.lookup_scope("alpha_area")["members"] == [1, 2]
    assert index.lookup_scope("ENG")["status"] == "known"


def test_invalid_country_tag_file_withdraws_only_country_kind(tmp_path):
    game = _write_game(
        tmp_path / "game", country_tags='fra = "countries/fra.txt"\n'
    )
    index = _index(game, tmp_path / "user")
    context = index.context()
    assert context["component_statuses"]["country_tags"]["status"] == "unavailable"
    assert index.lookup_scope("alpha_area")["status"] == "known"
    assert index.lookup_scope("fra")["status"] == "unknown"


def test_selected_area_bytes_are_rechecked_and_dependent_region_is_retracted(tmp_path):
    game = _write_game(tmp_path / "game")
    index = _index(game, tmp_path / "user")
    assert index.lookup_scope("west_region")["status"] == "known"
    (game / "map" / "area.txt").write_text("alpha_area = { 7 }\nbeta_area = { 8 }\n", encoding="utf-8")
    context = index.context()
    assert context["component_statuses"]["areas"]["status"] == "unavailable"
    assert context["component_statuses"]["regions"]["status"] == "unavailable"
    assert index.lookup_scope("alpha_area")["status"] == "unknown"
    assert index.lookup_scope("west_region")["status"] == "unknown"


def test_scope_name_is_not_guessed_across_loaded_kinds_and_unknown_ids_stay_unknown(tmp_path):
    game = _write_game(tmp_path / "game", areas="europe = { 1 }\n")
    index = _index(game, tmp_path / "user")
    assert index.lookup_scope("europe")["reason"] == "SCOPE_KIND_COLLISION"
    assert index.lookup_scope("0001")["status"] == "unknown"


def test_duplicate_region_and_superregion_names_fail_closed(tmp_path):
    game = _write_game(
        tmp_path / "game",
        regions=("duplicate_region = { areas = { alpha_area } }\n"
                 "duplicate_region = { areas = { beta_area } }\n"
                 "east_region = { areas = { alpha_area } }\n"),
        superregions=("duplicate_superregion = { east_region }\n"
                      "duplicate_superregion = { duplicate_region }\n"),
    )
    index = _index(game, tmp_path / "user")
    assert index.lookup_scope("duplicate_region") == {
        "status": "unknown", "name": "duplicate_region", "reason": "SCOPE_NAME_DUPLICATE",
        "kind": "regions",
    }
    assert index.lookup_scope("duplicate_superregion") == {
        "status": "unknown", "name": "duplicate_superregion", "reason": "SCOPE_NAME_DUPLICATE",
        "kind": "superregions",
    }

