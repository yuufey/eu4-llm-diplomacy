"""Offline contract tests for effective static imperial reform declarations."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge.information.imperial_reform_definitions import ImperialReformDefinitionIndex
from bridge.information.mission_definitions import _ScriptNode


class FixtureParser:
    def __init__(self, files: dict[str, list[_ScriptNode]], *, fail: bool = False):
        self.files = files
        self.fail = fail
        self.changed = False
        self.calls: list[list[str]] = []
        self._context = {
            "status": "ready", "complete": True, "name": "fixture-cwtools",
            "version": "0.6.0-alpha", "manifest_sha256": "a" * 64,
            "semantics": "syntax_only", "conditions_evaluated": False,
            "effects_executed": False, "reasons": [],
        }

    def context(self):
        return deepcopy(self._context) if not self.changed else {
            **deepcopy(self._context), "manifest_sha256": "b" * 64
        }

    def assert_current(self):
        if self.changed:
            raise ValueError("fixture parser changed")

    def parse_files(self, paths):
        self.calls.append([str(Path(path).resolve()) for path in paths])
        if self.fail:
            raise ValueError("fixture parse failure")
        return {
            str(Path(path).resolve()): {
                "nodes": deepcopy(self.files[Path(path).name]),
                "parser": self.context(),
            }
            for path in paths
        }


def _node(key: str, *, value: str | None = None, kind: str = "scalar",
          assignment: str | None = "=", children: list[_ScriptNode] | None = None,
          line: int = 1) -> _ScriptNode:
    node = _ScriptNode(key=key, line=line, end_line=line + (len(children or []) > 0),
                       value=value, children=list(children or []), kind=kind,
                       assignment=assignment)
    node.source_column = 0
    node.end_column = len(key)
    return node


def _reform(reform_id: str, empire: str | None, *, line: int = 1,
            extra: list[_ScriptNode] | None = None,
            empire_nodes: list[_ScriptNode] | None = None) -> _ScriptNode:
    declarations = list(empire_nodes) if empire_nodes is not None else (
        [_node("empire", value=empire, line=line + 1)] if empire is not None else []
    )
    declarations.extend(extra or [])
    return _node(reform_id, kind="block", assignment="=", children=declarations, line=line)


def _fixture(tmp_path: Path, trees: dict[str, list[_ScriptNode]], *,
             enabled_mods=(), parser: FixtureParser | None = None):
    game = tmp_path / "game"
    user = tmp_path / "user"
    game.mkdir(parents=True)
    (game / "launcher-settings.json").write_text(
        json.dumps({"rawVersion": "v1.37.4.0"}), encoding="utf-8"
    )
    reform_dir = game / "common" / "imperial_reforms"
    reform_dir.mkdir(parents=True)
    for name in trees:
        (reform_dir / name).write_text("fixture syntax input\n", encoding="utf-8")
    return game, user, parser or FixtureParser(trees)


def test_effective_hre_and_china_declarations_use_explicit_empire_and_preserve_ast(tmp_path):
    nested = _node("on_effect", kind="block", children=[
        _node("add_dip_power", value="10", line=7),
        _node("add_dip_power", value="20", line=8),
    ], line=6)
    trees = {
        "00_hre.txt": [_reform("reichsreform", "hre", line=1, extra=[nested])],
        "01_china.txt": [_reform("celestial_reform", "celestial_empire", line=20)],
    }
    game, user, parser = _fixture(tmp_path, trees)
    index = ImperialReformDefinitionIndex(game, user, enabled_mods=[], parser=parser)

    context = index.context()
    assert context["status"] == "ready"
    assert context["complete"] is False
    assert context["script_parser"]["semantics"] == "syntax_only"
    assert [item["reform_id"] for item in index.definitions()] == ["reichsreform"]
    assert [item["reform_id"] for item in index.definitions("celestial_empire")] == ["celestial_reform"]
    declarations = index.definitions()[0]["declarations"]
    effect = next(item for item in declarations if item["key"] == "on_effect")
    assert [item["value"] for item in effect["children"]] == ["10", "20"]
    assert effect["line"] == 6 and effect["source_column"] == 0
    assert len(parser.calls) == 1 and len(parser.calls[0]) == 2
    clean = index.definitions()
    clean[0]["declarations"].clear()
    assert len(index.definitions()[0]["declarations"]) == 2
    json.dumps(context, ensure_ascii=False)


def test_replace_path_masks_base_files_and_directory_addition_retracts_index(tmp_path):
    trees = {"00_base.txt": [_reform("base_only", "hre")]}
    game, user, parser = _fixture(tmp_path, trees)
    mod_root = user / "mod" / "overlay"
    mod_dir = mod_root / "common" / "imperial_reforms"
    mod_dir.mkdir(parents=True)
    (mod_dir / "10_overlay.txt").write_text("fixture overlay\n", encoding="utf-8")
    descriptor = user / "mod" / "overlay.mod"
    descriptor.parent.mkdir(parents=True, exist_ok=True)
    descriptor.write_text(
        f'name = "overlay"\npath = "{mod_root.as_posix()}"\n'
        'replace_path = "common/imperial_reforms"\n', encoding="utf-8"
    )
    parser.files["10_overlay.txt"] = [_reform("overlay_only", "hre", line=5)]
    index = ImperialReformDefinitionIndex(
        game, user, enabled_mods=[descriptor], parser=parser
    )
    assert index.context()["status"] == "ready"
    assert [item["reform_id"] for item in index.definitions()] == ["overlay_only"]
    (mod_dir / "20_added.txt").write_text("late file\n", encoding="utf-8")
    changed = index.context()
    assert changed["status"] == "unready"
    assert any(item["code"] == "INPUT_CHANGED" for item in changed["reasons"])
    with pytest.raises(ValueError, match="IMPERIAL_REFORM_INDEX_CHANGED"):
        index.definitions()


@pytest.mark.parametrize("case", ("duplicate", "invalid_id"))
def test_duplicate_or_invalid_root_ids_fail_closed(tmp_path, case):
    if case == "duplicate":
        trees = {
            "00_one.txt": [_reform("same_id", "hre")],
            "01_two.txt": [_reform("same_id", "celestial_empire", line=10)],
        }
    else:
        trees = {"00_bad.txt": [_reform("../escape", "hre")]}
    game, user, parser = _fixture(tmp_path, trees)
    index = ImperialReformDefinitionIndex(game, user, enabled_mods=[], parser=parser)
    context = index.context()
    assert context["status"] == "unready"
    expected = "REFORM_ID_DUPLICATE" if case == "duplicate" else "REFORM_ID_INVALID"
    assert expected in {item["code"] for item in context["reasons"]}
    with pytest.raises(ValueError, match="IMPERIAL_REFORM_INDEX_UNREADY"):
        index.definitions()


def test_unknown_or_ambiguous_empire_is_a_gap_and_never_enters_hre_results(tmp_path):
    trees = {"00_mixed.txt": [
        _reform("explicit_hre", "hre"),
        _reform("unknown_empire", "roman_empire", line=10),
        _reform("ambiguous_empire", None, line=20, empire_nodes=[
            _node("empire", value="hre", line=21),
            _node("empire", value="celestial_empire", line=22),
        ]),
    ]}
    game, user, parser = _fixture(tmp_path, trees)
    index = ImperialReformDefinitionIndex(game, user, enabled_mods=[], parser=parser)
    context = index.context()
    assert context["status"] == "ready" and context["complete"] is False
    assert [item["reform_id"] for item in index.definitions("hre")] == ["explicit_hre"]
    assert context["unknown_empire_count"] == 2
    assert {item["reason"] for item in context["unknown_empire_definitions"]} == {
        "EMPIRE_VALUE_UNKNOWN", "EMPIRE_DECLARATION_AMBIGUOUS"
    }


def test_selected_file_configuration_parser_and_member_drift_invalidate_index(tmp_path):
    trees = {"00_hre.txt": [_reform("reform_a", "hre")]}
    game, user, parser = _fixture(tmp_path, trees)
    user.mkdir(parents=True)
    load_path = user / "dlc_load.json"
    load_path.write_text(json.dumps({"enabled_mods": []}), encoding="utf-8")
    index = ImperialReformDefinitionIndex(game, user, enabled_mods=None, parser=parser)
    assert index.context()["status"] == "ready"
    load_path.write_text(json.dumps({"enabled_mods": ["new.mod"]}), encoding="utf-8")
    assert index.context()["status"] == "unready"
    assert any(item["code"] == "INPUT_CHANGED" for item in index.context()["reasons"])

    game2, user2, parser2 = _fixture(tmp_path / "second", trees)
    index2 = ImperialReformDefinitionIndex(game2, user2, enabled_mods=[], parser=parser2)
    source_file = game2 / "common" / "imperial_reforms" / "00_hre.txt"
    source_file.write_text("changed contents\n", encoding="utf-8")
    assert index2.context()["status"] == "unready"
    with pytest.raises(ValueError, match="IMPERIAL_REFORM_INDEX_CHANGED"):
        index2.assert_current()

    game3, user3, parser3 = _fixture(tmp_path / "third", trees)
    index3 = ImperialReformDefinitionIndex(game3, user3, enabled_mods=[], parser=parser3)
    (game3 / "common" / "imperial_reforms" / "notes.txt").write_text("new member\n", encoding="utf-8")
    assert index3.context()["status"] == "unready"


def test_parser_failure_and_parser_pin_drift_do_not_publish_records(tmp_path):
    trees = {"00_hre.txt": [_reform("reform_a", "hre")]}
    game, user, parser = _fixture(tmp_path, trees, parser=FixtureParser(trees, fail=True))
    failed = ImperialReformDefinitionIndex(game, user, enabled_mods=[], parser=parser)
    assert failed.context()["status"] == "unready"
    assert any(item["code"] == "CWTOOLS_PARSE_FAILED" for item in failed.context()["reasons"])

    game2, user2, parser2 = _fixture(tmp_path / "second", trees)
    index = ImperialReformDefinitionIndex(game2, user2, enabled_mods=[], parser=parser2)
    assert [item["reform_id"] for item in index.definitions()] == ["reform_a"]
    parser2.changed = True
    assert index.context()["status"] == "unready"
