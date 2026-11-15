"""Bounded static mission-definition index tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bridge.information.mission_definitions import (
    MissionDefinitionError,
    MissionDefinitionIndex,
)


def _fixture(tmp_path: Path, files: dict[str, str], *, version: str | None = "v1.37.4.0") -> tuple[Path, Path]:
    game = tmp_path / "game"
    user = tmp_path / "user"
    mission_dir = game / "missions"
    mission_dir.mkdir(parents=True)
    if version is not None:
        (game / "launcher-settings.json").write_text(
            json.dumps({"rawVersion": version}), encoding="utf-8"
        )
    for name, text in files.items():
        path = mission_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return game, user


def _root(root_id: str, task: str = "task_one", *, extra: str = "") -> str:
    return f"""
    {root_id} = {{
        slot = 1
        generic = no
        potential = {{ tag = FRA has_dlc = \"Domination\" {extra} }}
        {task} = {{
            required_missions = {{ prerequisite_a prerequisite_b }}
            position = 1
            provinces_to_highlight = {{ area = france_area }}
            trigger = {{ always = no }}
            effect = {{ add_mil_power = 50 }}
        }}
    }}
    """


def _reason_codes(context: dict) -> set[str]:
    return {
        item["code"] for item in context.get("reasons", []) if isinstance(item, dict) and "code" in item
    }


def test_preserves_rule_trees_repeated_keys_and_does_not_evaluate_conditions(tmp_path):
    game, user = _fixture(tmp_path, {
        "00_fixture.txt": _root(
            "root_a",
            extra='has_dlc = "Emperor"',
        ).replace(
            "required_missions = { prerequisite_a prerequisite_b }",
            "required_missions = { prerequisite_a prerequisite_b }\n            required_missions = { prerequisite_c }",
        ),
    })
    index = MissionDefinitionIndex(game, user, enabled_mods=[])

    context = index.context()
    assert context["status"] == "ready"
    json.dumps(context, ensure_ascii=False)
    root = index.root("root_a")
    task = root["tasks"][0]
    assert root["slot"] == 1
    assert root["generic"] is False
    assert isinstance(root["potential"], dict)
    assert len(root["potential"]["children"]) == 3
    assert [item["key"] for item in root["potential"]["children"]].count("has_dlc") == 2
    assert len(task["required_missions"]) == 2
    assert task["trigger"]["children"][0]["key"] == "always"
    assert task["trigger"]["children"][0]["value"] == "no"
    assert "name" not in root
    assert task["source"]["line"] > 0
    assert "raw_script" in task["trigger"]
    assert task["trigger"]["ast_semantics"] == "structural"
    assert all(item.lines is None for item in index._state.definition_files)


def test_raw_script_slices_split_each_definition_text_once(tmp_path):
    from bridge.information.mission_definitions import _DefinitionFile, _ScriptNode, _raw_script

    class CountingText(str):
        splits = 0

        def splitlines(self, keepends=False):
            self.splits += 1
            return super().splitlines(keepends=keepends)

    text = CountingText('root = {\r\n  trigger = {\r\n    always = yes\r\n  }\r\n}\r\n')
    source = _DefinitionFile('missions/test.txt', tmp_path / 'test.txt',
                             'basegame', 'basegame', '0' * 64, len(text), text=text)
    assert _raw_script(source, _ScriptNode('trigger', 2, end_line=4)) == (
        '  trigger = {\r\n    always = yes\r\n  }\r\n')
    assert _raw_script(source, _ScriptNode('root', 1, end_line=5)) == text
    assert text.splits == 1


def test_comparison_operator_and_bare_effect_block_are_retained(tmp_path):
    game, user = _fixture(tmp_path, {
        "00_operator.txt": r"""
        root_a = {
            slot = 1
            generic = no
            potential = { development >= 10 NOT = { stability < 0 } "quoted key" = "\"escaped\"" bare_token empty_block = {} }
            task_a = {
                position = 1
                trigger = { manpower != 5 }
                effect = { create_general_with_pips { tradition = 25 } explicit_block = {} bare_block {} }
            }
        }
        """,
    })
    index = MissionDefinitionIndex(game, user, enabled_mods=[])

    assert index.context()["status"] == "ready"
    root = index.root("root_a")
    potential = root["potential"]
    assert potential["children"][0]["operator"] == ">="
    assert potential["children"][1]["children"][0]["operator"] == "<"
    quoted = next(item for item in potential["children"] if item["key"] == "quoted key")
    assert quoted["kind"] == "scalar" and quoted["assignment"] == "="
    assert quoted["raw_key"] == '"quoted key"'
    assert quoted["raw_value"] == '"\\"escaped\\""'
    bare = next(item for item in potential["children"] if item["key"] == "bare_token")
    empty = next(item for item in potential["children"] if item["key"] == "empty_block")
    assert bare["kind"] == "bare" and bare["assignment"] is None
    assert empty["kind"] == "block" and empty["assignment"] == "="
    task = root["tasks"][0]
    assert task["trigger"]["children"][0]["operator"] == "!="
    assert task["effect"]["children"][0]["key"] == "create_general_with_pips"
    assert task["effect"]["children"][0]["kind"] == "block"
    assert task["effect"]["children"][0]["assignment"] is None
    assert task["effect"]["children"][1]["kind"] == "block"
    assert task["effect"]["children"][1]["assignment"] == "="
    assert task["effect"]["children"][2]["kind"] == "block"
    assert task["effect"]["children"][2]["assignment"] is None
    assert ">=" in potential["raw_script"] and "<" in potential["raw_script"]


def test_same_path_mod_overlay_is_effective_and_provenance_is_kept(tmp_path):
    game, user = _fixture(tmp_path, {"00_overlay.txt": _root("root_a", "base_task")})
    mod = user / "mod" / "overlay"
    (mod / "missions").mkdir(parents=True)
    (mod / "missions" / "00_overlay.txt").write_text(
        _root("root_a", "mod_task"), encoding="utf-8"
    )
    descriptor = user / "mod" / "overlay.mod"
    descriptor.parent.mkdir(parents=True, exist_ok=True)
    descriptor.write_text(
        'name="Overlay"\npath="' + str(mod).replace("\\", "/") + '"\n', encoding="utf-8"
    )
    index = MissionDefinitionIndex(game, user, enabled_mods=["mod/overlay.mod"])

    assert index.context()["status"] == "ready"
    root = index.root("root_a")
    assert root["tasks"][0]["task_id"] == "mod_task"
    assert root["source"]["source_kind"] == "enabled_mod"
    assert root["source"]["path"] == "missions/00_overlay.txt"
    effective = [item for item in index.context()["definition_files"] if item["relative"] == "missions/00_overlay.txt"]
    assert len(effective) == 1 and effective[0]["source_kind"] == "enabled_mod"


def test_replace_path_removes_base_without_silent_fallback(tmp_path):
    game, user = _fixture(tmp_path, {"00_base.txt": _root("base_root")})
    mod = user / "mod" / "replacement"
    (mod / "missions").mkdir(parents=True)
    (mod / "missions" / "01_replacement.txt").write_text(_root("replacement_root"), encoding="utf-8")
    descriptor = user / "mod" / "replacement.mod"
    descriptor.parent.mkdir(parents=True, exist_ok=True)
    descriptor.write_text(
        'name="Replacement"\npath="' + str(mod).replace("\\", "/") + '"\nreplace_path="missions"\n',
        encoding="utf-8",
    )
    index = MissionDefinitionIndex(game, user, enabled_mods=["mod/replacement.mod"])

    assert index.context()["status"] == "ready"
    assert [item["root_id"] for item in index.roots()] == ["replacement_root"]
    assert index.context()["enabled_mods"][0]["replace_paths"] == ["missions"]


def test_duplicate_root_in_one_file_fails_closed(tmp_path):
    game, user = _fixture(tmp_path, {"00_duplicate.txt": _root("duplicate_root") + _root("duplicate_root")})
    index = MissionDefinitionIndex(game, user, enabled_mods=[])

    context = index.context()
    assert context["status"] == "unready"
    assert "DUPLICATE_MISSION_ROOT" in _reason_codes(context)
    with pytest.raises(MissionDefinitionError) as exc_info:
        index.roots()
    assert exc_info.value.code == "DUPLICATE_MISSION_ROOT"


def test_missing_version_and_unknown_archive_are_unavailable(tmp_path):
    game, user = _fixture(tmp_path, {"00_fixture.txt": _root("root_a")}, version=None)
    missing_version = MissionDefinitionIndex(game, user, enabled_mods=[])
    assert "GAME_VERSION_UNAVAILABLE" in _reason_codes(missing_version.context())

    game2, user2 = _fixture(tmp_path / "archive", {"00_fixture.txt": _root("root_a")})
    mod = user2 / "mod" / "archived"
    mod.mkdir(parents=True)
    descriptor = user2 / "mod" / "archived.mod"
    descriptor.parent.mkdir(parents=True, exist_ok=True)
    descriptor.write_text('archive="archived.zip"\n', encoding="utf-8")
    archived = MissionDefinitionIndex(game2, user2, enabled_mods=["mod/archived.mod"])
    assert "MOD_ARCHIVE_UNSUPPORTED" in _reason_codes(archived.context())
    assert archived.context()["status"] == "unready"


def test_directory_member_change_invalidates_old_index(tmp_path):
    game, user = _fixture(tmp_path, {"00_fixture.txt": _root("root_a")})
    index = MissionDefinitionIndex(game, user, enabled_mods=[])
    assert index.context()["status"] == "ready"
    (game / "missions" / "01_added.txt").write_text(_root("new_root"), encoding="utf-8")
    changed = index.context()
    assert changed["status"] == "unready"
    assert "MISSION_DIRECTORY_CHANGED" in _reason_codes(changed)
    with pytest.raises(MissionDefinitionError):
        index.roots()


def test_version_input_change_invalidates_old_index(tmp_path):
    game, user = _fixture(tmp_path, {"00_fixture.txt": _root("root_a")})
    index = MissionDefinitionIndex(game, user, enabled_mods=[])
    assert index.context()["status"] == "ready"
    (game / "launcher-settings.json").write_text(
        json.dumps({"rawVersion": "v1.37.4.0", "changed": True}), encoding="utf-8"
    )
    changed = index.context()
    assert changed["status"] == "unready"
    assert "MISSION_INPUT_CHANGED" in _reason_codes(changed)


def test_utf8_fallback_is_marked_structural_and_does_not_invent_names(tmp_path):
    game, user = _fixture(tmp_path, {})
    raw = b'root_a={slot=1 generic=no icon="\xc9" task_a={position=1}}'
    (game / "missions" / "00_latin1.txt").write_bytes(raw)
    index = MissionDefinitionIndex(game, user, enabled_mods=[])

    assert index.context()["status"] == "ready"
    definition = index.context()["definition_files"][0]
    assert definition["encoding"]["name"] == "latin-1"
    assert definition["encoding"]["structural_only"] is True
    assert "name" not in index.root("root_a")


def test_limits_are_bounded(tmp_path):
    game, user = _fixture(tmp_path, {"00_large.txt": _root("root_a")})
    index = MissionDefinitionIndex(game, user, enabled_mods=[], max_file_bytes=32)
    assert index.context()["status"] == "unready"
    assert "MISSION_FILE_UNAVAILABLE" in _reason_codes(index.context())


def test_unknown_root_is_explicit(tmp_path):
    game, user = _fixture(tmp_path, {"00_fixture.txt": _root("root_a")})
    index = MissionDefinitionIndex(game, user, enabled_mods=[])
    with pytest.raises(MissionDefinitionError) as exc_info:
        index.root("does_not_exist")
    assert exc_info.value.code == "UNKNOWN_ROOT_ID"


def test_real_1374_mission_index_is_read_only_and_uses_enabled_overlay():
    game = Path(r"D:\Downloads\Europa Universalis IV（1.37.4）\Europa Universalis IV")
    user = Path(r"C:\Users\wangyufei\Documents\Paradox Interactive\Europa Universalis IV")
    if not (game / "missions").is_dir() or not (user / "dlc_load.json").is_file():
        pytest.skip("local EU4 1.37.4 installation is not configured")
    index = MissionDefinitionIndex(game, user)
    context = index.context()
    assert context["status"] == "ready"
    french = index.root("french_missions_1")
    assert french["source"]["source_kind"] == "enabled_mod"
    assert french["source"]["path"] == "missions/DOM_French_Missions.txt"
    assert french["tasks"]
    assert all("name" not in item for item in index.roots(["french_missions_1"]))
