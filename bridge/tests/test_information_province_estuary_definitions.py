"""Offline tests for strict static estuary-rule binding."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from bridge.information.mission_definitions import _parse_mission_script
from bridge.information.model import canonical
from bridge.information.province_estuary_definitions import BoundEstuaryDefinition


_DEFINITION_CSV = "province;red;green;blue;name\n0;0;0;0;sentinel\n1;1;1;1;one\n"
_ADJACENCY_CSV = "From;To;Type;Through;start_x;start_y;stop_x;stop_y;Comment\n"


class _FixtureParser:
    def context(self):
        return {"status": "ready", "complete": True, "name": "fixture", "version": "1"}

    def parse_files(self, paths):
        result = {}
        for path in paths:
            path = Path(path).resolve()
            text = path.read_text(encoding="utf-8")
            result[str(path)] = {"nodes": _parse_mission_script(text), "text": text}
        return result


def _write_game(root: Path) -> Path:
    (root / "launcher-settings.json").parent.mkdir(parents=True, exist_ok=True)
    (root / "launcher-settings.json").write_text(
        json.dumps({"rawVersion": "v1.37.4.0"}), encoding="utf-8"
    )
    map_dir = root / "map"
    map_dir.mkdir(parents=True, exist_ok=True)
    (map_dir / "default.map").write_text(
        'definitions = "definition.csv"\nadjacencies = "adjacencies.csv"\n', encoding="utf-8"
    )
    (map_dir / "definition.csv").write_text(_DEFINITION_CSV, encoding="utf-8")
    (map_dir / "adjacencies.csv").write_text(_ADJACENCY_CSV, encoding="utf-8")
    return root


def _write_trigger(root: Path, text: str, relative: str = "00_estuary.txt") -> Path:
    path = root / "common" / "scripted_triggers" / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _rule(keys: list[str], *, wrapper: bool = False) -> str:
    leaves = "\n".join(f"has_province_modifier = {key}" for key in keys)
    expression = f"OR = {{\n{leaves}\n}}"
    if wrapper:
        expression = f"custom_trigger_tooltip = {{ tooltip = estuary_tt\n{expression}\n}}"
    return f"has_river_estuary_trigger = {{\n{expression}\n}}\n"


def _bind(game: Path, user: Path, mods=None, *, parser=None, **kwargs) -> BoundEstuaryDefinition:
    return BoundEstuaryDefinition(
        game_root=game,
        user_data=user,
        enabled_mods=[] if mods is None else mods,
        script_parser=parser or _FixtureParser(),
        **kwargs,
    )


def test_extracts_complete_custom_tooltip_or_ast_and_ordered_literal_keys(tmp_path):
    game = _write_game(tmp_path / "game")
    path = _write_trigger(game, '''
has_river_estuary_trigger = {
    custom_trigger_tooltip = {
        tooltip = estuary_tooltip
        OR = {
            has_province_modifier = river_estuary_modifier
            custom_trigger_tooltip = {
                tooltip = named_estuary_tooltip
                has_province_modifier = tagus_estuary_modifier
            }
            has_province_modifier = mng_bogue_modifier
            has_province_modifier = river_estuary_modifier
        }
    }
}
''')
    result = _bind(game, tmp_path / "user").context()
    assert result["status"] == "known"
    assert result["complete"] is True
    assert result["game_fact"] is False
    assert result["known_modifier_keys"] == [
        "river_estuary_modifier", "tagus_estuary_modifier", "mng_bogue_modifier"
    ]
    assert result["definition_file"]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert result["scriptedtrigger_ast"]["key"] == "has_river_estuary_trigger"
    assert result["scriptedtrigger_ast_sha256"] == hashlib.sha256(
        canonical(result["scriptedtrigger_ast"]).encode("utf-8")
    ).hexdigest()
    assert result["identity"]["stable_before_after"] is True
    assert result["identity"]["before_sha256"] == result["identity"]["after_sha256"]


def test_direct_or_is_accepted_and_same_relative_path_mod_file_wins(tmp_path):
    game = _write_game(tmp_path / "game")
    _write_trigger(game, _rule(["river_estuary_modifier"]))
    mod = tmp_path / "mod"
    _write_trigger(mod, _rule(["tagus_estuary_modifier"]), "00_estuary.txt")
    descriptor = tmp_path / "mod.mod"
    descriptor.write_text(f'name="overlay"\npath="{mod.as_posix()}"\n', encoding="utf-8")
    result = _bind(game, tmp_path / "user", [{"descriptor": descriptor, "root": mod}]).context()
    assert result["status"] == "known"
    assert result["known_modifier_keys"] == ["tagus_estuary_modifier"]
    assert result["definition_file"]["source_kind"] == "enabled_mod"


def test_replace_path_removes_base_trigger_without_fallback(tmp_path):
    game = _write_game(tmp_path / "game")
    _write_trigger(game, _rule(["river_estuary_modifier"]), "00_base.txt")
    user = tmp_path / "user"
    mod = user / "mod" / "replacement"
    _write_trigger(mod, _rule(["tagus_estuary_modifier"]), "10_override.txt")
    descriptor = user / "mod" / "replacement.mod"
    descriptor.parent.mkdir(parents=True, exist_ok=True)
    descriptor.write_text(
        f'name="replacement"\npath="{mod.as_posix()}"\n'
        'replace_path="common/scripted_triggers"\n', encoding="utf-8"
    )
    result = _bind(game, user, ["mod/replacement.mod"]).context()
    assert result["status"] == "known"
    assert result["known_modifier_keys"] == ["tagus_estuary_modifier"]
    assert [row["relative"] for row in result["definition_files"]] == [
        "common/scripted_triggers/10_override.txt"
    ]


def test_extra_condition_is_unknown_and_never_silently_ignored(tmp_path):
    game = _write_game(tmp_path / "game")
    _write_trigger(game, '''
has_river_estuary_trigger = {
    OR = { has_province_modifier = river_estuary_modifier }
    has_country_flag = some_flag
}
''')
    result = _bind(game, tmp_path / "user").context()
    assert result["status"] == "unknown"
    assert result["known_modifier_keys"] == []
    assert "UNSUPPORTED_TRIGGER_SHAPE" in {row["code"] for row in result["reasons"]}


def test_duplicate_effective_definitions_are_unknown(tmp_path):
    game = _write_game(tmp_path / "game")
    _write_trigger(game, _rule(["river_estuary_modifier"]), "00_estuary.txt")
    _write_trigger(game, _rule(["tagus_estuary_modifier"]), "01_estuary.txt")
    result = _bind(game, tmp_path / "user").context()
    assert result["status"] == "unknown"
    assert "ESTUARY_TRIGGER_DUPLICATE_DEFINITION" in {row["code"] for row in result["reasons"]}


def test_input_hash_drift_makes_bound_result_unknown(tmp_path):
    game = _write_game(tmp_path / "game")
    path = _write_trigger(game, _rule(["river_estuary_modifier"]))
    bound = _bind(game, tmp_path / "user")
    assert bound.context()["status"] == "known"
    path.write_text(_rule(["tagus_estuary_modifier"]), encoding="utf-8")
    result = bound.context()
    assert result["status"] == "unknown"
    assert result["known_modifier_keys"] == []
    assert "INPUT_IDENTITY_CHANGED" in {row["code"] for row in result["reasons"]}


def test_file_size_limit_is_checked_before_parse(tmp_path):
    game = _write_game(tmp_path / "game")
    _write_trigger(game, _rule(["river_estuary_modifier"]) + ("#" + "x" * 600))
    result = _bind(game, tmp_path / "user", max_file_bytes=512).context()
    assert result["status"] == "unknown"
    assert "STATIC_INPUT_SIZE_OUT_OF_RANGE" in {row["code"] for row in result["reasons"]}


def test_configuration_sha_drift_between_stack_load_and_binding_is_unknown(tmp_path, monkeypatch):
    from bridge.information import province_estuary_definitions as module

    game = _write_game(tmp_path / "game")
    _write_trigger(game, _rule(["river_estuary_modifier"]))
    original_loader = module.StraitDefinitionIndex

    class _MutatingLoader(original_loader):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            (game / "launcher-settings.json").write_text(
                json.dumps({"rawVersion": "v1.37.4.0", "changed_after_load": True}), encoding="utf-8"
            )

    monkeypatch.setattr(module, "StraitDefinitionIndex", _MutatingLoader)
    result = _bind(game, tmp_path / "user").context()
    assert result["status"] == "unknown"
    assert "CONFIGURATION_IDENTITY_CHANGED" in {row["code"] for row in result["reasons"]}


def test_scripted_trigger_directory_member_limit_stops_resolution(tmp_path, monkeypatch):
    from bridge.information import province_estuary_definitions as module

    monkeypatch.setattr(module, "MAX_DIRECTORY_MEMBERS", 1)
    game = _write_game(tmp_path / "game")
    _write_trigger(game, _rule(["river_estuary_modifier"]), "00.txt")
    _write_trigger(game, "other_trigger = { always = yes }\n", "01.txt")
    result = _bind(game, tmp_path / "user").context()
    assert result["status"] == "unknown"
    assert "SCRIPTED_TRIGGER_DIRECTORY_MEMBER_LIMIT" in {row["code"] for row in result["reasons"]}


def test_replace_path_traversal_is_rejected_by_existing_stack_loader(tmp_path):
    game = _write_game(tmp_path / "game")
    _write_trigger(game, _rule(["river_estuary_modifier"]))
    user = tmp_path / "user"
    mod = user / "mod" / "bad"
    _write_trigger(mod, _rule(["tagus_estuary_modifier"]))
    descriptor = user / "mod" / "bad.mod"
    descriptor.parent.mkdir(parents=True, exist_ok=True)
    descriptor.write_text(
        f'name="bad"\npath="{mod.as_posix()}"\nreplace_path="../common"\n', encoding="utf-8"
    )
    result = _bind(game, user, ["mod/bad.mod"]).context()
    assert result["status"] == "unknown"
    assert "ENABLED_MOD_UNSUPPORTED" in {row["code"] for row in result["reasons"]}


@pytest.mark.parametrize(
    ("keys", "expected_reason"),
    [
        (["x" * 256], "INVALID_MODIFIER_KEY"),
        ([f"key_{index}" for index in range(65)], "ESTUARY_KEY_COUNT_LIMIT"),
        (["estuary_水"], "INVALID_MODIFIER_KEY"),
        (["invalid.key"], "INVALID_MODIFIER_KEY"),
    ],
)
def test_modifier_key_ascii_length_and_count_boundaries(tmp_path, keys, expected_reason):
    game = _write_game(tmp_path / "game")
    _write_trigger(game, _rule(keys))
    result = _bind(game, tmp_path / "user").context()
    assert result["status"] == "unknown"
    assert result["known_modifier_keys"] == []
    assert expected_reason in {row["code"] for row in result["reasons"]}


def test_scripted_trigger_relative_path_length_is_bounded(tmp_path, monkeypatch):
    from bridge.information import province_estuary_definitions as module

    monkeypatch.setattr(module, "MAX_RELATIVE_PATH_BYTES", 40)
    game = _write_game(tmp_path / "game")
    _write_trigger(game, _rule(["river_estuary_modifier"]), "nested/branch/00.txt")
    result = _bind(game, tmp_path / "user").context()
    assert result["status"] == "unknown"
    assert "SCRIPTED_TRIGGER_PATH_LENGTH_LIMIT" in {row["code"] for row in result["reasons"]}
