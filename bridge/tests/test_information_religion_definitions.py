"""Offline tests for the effective EU4 religion identity index."""
from __future__ import annotations

import json
from pathlib import Path

import bridge.information.religion_definitions as religion_definitions
from bridge.information.religion_definitions import ReligionDefinitionIndex
from bridge.tests.test_information_imperial_reform_definitions import FixtureParser, _node


def _religion(key: str, *, line: int = 1):
    return _node(key, kind="block", assignment="=", children=[], line=line)


def _group(key: str, *religions, line: int = 1):
    return _node(key, kind="block", assignment="=", children=list(religions), line=line)


def _fixture(tmp_path: Path, trees: dict[str, list], *, parser=None):
    game = tmp_path / "game"
    user = tmp_path / "user"
    game.mkdir(parents=True)
    (game / "launcher-settings.json").write_text(
        json.dumps({"rawVersion": "v1.37.4.0"}), encoding="utf-8"
    )
    religion_dir = game / "common" / "religions"
    religion_dir.mkdir(parents=True)
    for name in trees:
        (religion_dir / name).write_text("fixture syntax input\n", encoding="utf-8")
    return game, user, parser or FixtureParser(trees)


def _index(game, user, parser, enabled_mods=()):
    return ReligionDefinitionIndex(game, user, enabled_mods=enabled_mods, parser=parser)


def test_lookup_uses_direct_religion_children_and_exposes_definition_pins(tmp_path):
    trees = {"00_religions.txt": [
        _group("christian", _religion("catholic", line=4), _religion("orthodox", line=8),
               _node("religious_schools", kind="block", children=[_religion("not_a_religion")], line=10),
               _node("flag_emblem_index_range", kind="block", children=[_node("1", value="2")], line=14),
               line=2)
    ]}
    game, user, parser = _fixture(tmp_path, trees)
    index = _index(game, user, parser)

    assert index.context()["status"] == "ready"
    assert index.context()["complete"] is False
    result = index.lookup("catholic")
    assert result["status"] == "known"
    assert result["religion_key"] == "catholic"
    assert result["religion_group_key"] == "christian"
    assert result["definition"]["relative_file"] == "common/religions/00_religions.txt"
    assert result["definition"]["line"] == 4
    assert result["definition"]["file_sha256"]
    assert result["source_pins"]["configuration_sha256"]
    assert result["source_pins"]["definitions_sha256"]
    assert result["source_pins"]["parser_manifest_sha256"] == "a" * 64
    assert result["source_pins"]["cwt_commit"] == "a85622d368bbb7afca938ed70fdd5eda44aec769"
    assert result["source_pins"]["cwt_sha256"] == (
        "bc7e80059f6b71acd12b8af9d8bf2d98850b891073326d845a1d62aa8760f1af")
    group = index.lookup_group("christian")
    assert group["status"] == "known"
    assert group["religion_group_key"] == "christian"
    assert group["definition"]["line"] == 2
    assert group["source"] == result["source_pins"]
    assert group["source_pins"] == result["source_pins"]
    assert index.lookup_group("missing_group")["reason"] == "RELIGION_GROUP_NOT_FOUND"
    assert index.lookup("not_a_religion")["reason"] == "RELIGION_DEFINITION_NOT_FOUND"
    assert index.lookup("unknown_religion")["reason"] == "RELIGION_DEFINITION_NOT_FOUND"
    assert len(parser.calls) == 1 and len(parser.calls[0]) == 1


def test_repeated_religion_group_does_not_merge_across_files(tmp_path):
    trees = {
        "00_one.txt": [_group("christian", _religion("catholic", line=3), line=1)],
        "10_two.txt": [_group("christian", _religion("protestant", line=8), line=6)],
    }
    game, user, parser = _fixture(tmp_path, trees)
    index = _index(game, user, parser)

    context = index.context()
    assert context["status"] == "ready"
    assert context["duplicate_group_keys"] == ["christian"]
    assert index.lookup_group("christian")["reason"] == "RELIGION_GROUP_AMBIGUOUS"
    for key in ("catholic", "protestant"):
        result = index.lookup(key)
        assert result["status"] == "unknown"
        assert result["reason"] == "RELIGION_DEFINITION_AMBIGUOUS"
        assert len(result["definitions"]) == 1


def test_duplicate_religion_key_is_unknown_even_under_different_groups(tmp_path):
    trees = {
        "00_one.txt": [_group("christian", _religion("shared_key", line=3), line=1)],
        "10_two.txt": [_group("muslim", _religion("shared_key", line=8), line=6)],
    }
    game, user, parser = _fixture(tmp_path, trees)
    index = _index(game, user, parser)

    result = index.lookup("shared_key")
    assert result["status"] == "unknown"
    assert result["reason"] == "RELIGION_DEFINITION_AMBIGUOUS"
    assert {row["relative_file"] for row in result["definitions"]} == {
        "common/religions/00_one.txt", "common/religions/10_two.txt"}


def test_same_relative_file_overlay_wins_without_duplicate_identity(tmp_path):
    trees = {"00_religions.txt": [_group("christian", _religion("base_only", line=3), line=1)]}
    game, user, parser = _fixture(tmp_path, trees)
    mod_root = user / "mod" / "overlay"
    mod_dir = mod_root / "common" / "religions"
    mod_dir.mkdir(parents=True)
    (mod_dir / "00_religions.txt").write_text("overlay syntax input\n", encoding="utf-8")
    descriptor = user / "mod" / "overlay.mod"
    descriptor.parent.mkdir(parents=True, exist_ok=True)
    descriptor.write_text(
        f'name = "overlay"\npath = "{mod_root.as_posix()}"\n', encoding="utf-8"
    )
    parser.files["00_religions.txt"] = [
        _group("christian", _religion("overlay_only", line=13), line=11)
    ]
    index = _index(game, user, parser, [descriptor])

    assert index.context()["status"] == "ready"
    assert index.lookup("overlay_only")["status"] == "known"
    assert index.lookup("base_only")["reason"] == "RELIGION_DEFINITION_NOT_FOUND"
    assert index.context()["definition_files"][0]["source_kind"] == "enabled_mod"
    assert len(parser.calls[0]) == 1


def test_replace_path_removes_base_definitions_and_keeps_mod_group(tmp_path):
    trees = {"00_base.txt": [_group("christian", _religion("base_only", line=3), line=1)]}
    game, user, parser = _fixture(tmp_path, trees)
    mod_root = user / "mod" / "replace"
    mod_dir = mod_root / "common" / "religions"
    mod_dir.mkdir(parents=True)
    (mod_dir / "20_custom.txt").write_text("replacement syntax input\n", encoding="utf-8")
    descriptor = user / "mod" / "replace.mod"
    descriptor.parent.mkdir(parents=True, exist_ok=True)
    descriptor.write_text(
        f'name = "replace"\npath = "{mod_root.as_posix()}"\n'
        'replace_path = "common/religions"\n', encoding="utf-8"
    )
    parser.files["20_custom.txt"] = [
        _group("custom_group", _religion("custom_only", line=4), line=2)
    ]
    index = _index(game, user, parser, [descriptor])

    assert index.context()["status"] == "ready"
    assert index.lookup("custom_only")["religion_group_key"] == "custom_group"
    assert index.lookup("base_only")["reason"] == "RELIGION_DEFINITION_NOT_FOUND"
    assert [item["relative"] for item in index.context()["definition_files"]] == [
        "common/religions/20_custom.txt"]


def test_changed_files_invalidate_old_index_and_new_index_rebuilds(tmp_path):
    trees = {"00_base.txt": [_group("christian", _religion("base_only", line=3), line=1)]}
    game, user, parser = _fixture(tmp_path, trees)
    index = _index(game, user, parser)
    assert index.lookup("base_only")["status"] == "known"

    religion_dir = game / "common" / "religions"
    (religion_dir / "00_base.txt").write_text("changed\n", encoding="utf-8")
    (religion_dir / "10_new.txt").write_text("new syntax input\n", encoding="utf-8")
    parser.files["10_new.txt"] = [_group("reformed", _religion("new_key", line=9), line=7)]
    assert index.context()["status"] == "unready"
    assert index.lookup("base_only")["reason"] == "RELIGION_DEFINITION_INDEX_UNAVAILABLE"
    assert index.lookup_group("christian")["reason"] == "RELIGION_DEFINITION_INDEX_UNAVAILABLE"

    rebuilt = _index(game, user, parser)
    assert rebuilt.context()["status"] == "ready"
    assert rebuilt.lookup("new_key")["religion_group_key"] == "reformed"


def test_empty_directory_is_ready_but_parser_failure_is_unready(tmp_path):
    game, user, empty_parser = _fixture(tmp_path / "empty", {})
    empty = _index(game, user, empty_parser)
    assert empty.context()["status"] == "ready"
    assert empty.context()["religion_definition_count"] == 0
    assert empty_parser.calls == []
    assert empty.lookup("absent")["reason"] == "RELIGION_DEFINITION_NOT_FOUND"

    trees = {"00_bad.txt": [_group("christian", _religion("catholic"))]}
    game2, user2, _ = _fixture(tmp_path / "parse-failure", trees)
    failing_parser = FixtureParser(trees, fail=True)
    failed = _index(game2, user2, failing_parser)
    assert failed.context()["status"] == "unready"
    assert any(reason["code"] == "CWTOOLS_PARSE_FAILED" for reason in failed.context()["reasons"])
    assert failed.lookup("catholic")["reason"] == "RELIGION_DEFINITION_INDEX_UNAVAILABLE"


def test_declaration_methods_return_static_syntax_and_isolated_copies(tmp_path):
    nested = _node("trigger", kind="block", children=[
        _node("has_country_flag", value="example", line=6),
    ], line=5)
    school = _node("religious_schools", kind="block", children=[
        _node("school_of_salamanca", kind="block", children=[], line=11),
    ], line=10)
    flags = _node("flag_emblem_index_range", kind="block", children=[
        _node("1", value="4", line=13),
    ], line=12)
    trees = {"00_religions.txt": [
        _group("christian", _religion("catholic", line=4), school, flags, line=2)
    ]}
    # Include a nested declaration in the religion itself, which remains syntax only.
    trees["00_religions.txt"][0].children[0].children.append(nested)
    game, user, parser = _fixture(tmp_path, trees)
    index = _index(game, user, parser)

    result = index.definition("catholic")
    assert result["status"] == "known"
    assert result["religion_key"] == "catholic"
    assert result["religion_group_key"] == "christian"
    assert result["definition"]["relative_file"] == "common/religions/00_religions.txt"
    assert result["source_pins"]["definitions_sha256"]
    assert result["conditions_evaluated"] is False
    assert result["effects_executed"] is False
    assert result["runtime_state_observed"] is False
    assert result["syntax"]["key"] == "catholic"
    assert result["syntax"]["children"][0]["key"] == "trigger"
    assert result["syntax"]["children"][0]["children"][0]["value"] == "example"
    result["syntax"]["children"][0]["children"][0]["value"] = "mutated"
    assert index.definition("catholic")["syntax"]["children"][0]["children"][0]["value"] == "example"

    group = index.group_definition("christian")
    assert group["status"] == "known"
    assert group["religion_group_key"] == "christian"
    assert group["conditions_evaluated"] is False
    assert group["effects_executed"] is False
    assert group["runtime_state_observed"] is False
    assert [item["key"] for item in group["syntax"]["children"]] == [
        "religious_schools", "flag_emblem_index_range"]
    group["syntax"]["children"].clear()
    assert len(index.group_definition("christian")["syntax"]["children"]) == 2
    assert len(parser.calls[-1]) == 1


def test_declaration_methods_reject_ambiguity_and_changed_inputs(tmp_path):
    trees = {
        "00_one.txt": [_group("christian", _religion("shared_key", line=3), line=1)],
        "10_two.txt": [_group("muslim", _religion("shared_key", line=8), line=6)],
    }
    game, user, parser = _fixture(tmp_path, trees)
    index = _index(game, user, parser)
    ambiguous = index.definition("shared_key")
    assert ambiguous["status"] == "unknown"
    assert ambiguous["reason"] == "RELIGION_DEFINITION_AMBIGUOUS"
    assert "syntax" not in ambiguous

    trees2 = {"00_base.txt": [_group("christian", _religion("catholic", line=3), line=1)]}
    game2, user2, parser2 = _fixture(tmp_path / "changed", trees2)
    changed = _index(game2, user2, parser2)
    assert changed.definition("catholic")["status"] == "known"
    (game2 / "common" / "religions" / "00_base.txt").write_text("changed\n", encoding="utf-8")
    stale = changed.definition("catholic")
    assert stale["status"] == "unknown"
    assert stale["reason"] == "RELIGION_DEFINITION_INDEX_UNAVAILABLE"
    assert "syntax" not in stale


def test_group_declaration_rejects_bad_children_and_ast_budget(tmp_path, monkeypatch):
    duplicate_children = [
        _node("icon", value="first", line=3),
        _node("icon", value="second", line=4),
    ]
    trees = {"00_religions.txt": [_group("christian", *duplicate_children, line=1)]}
    game, user, parser = _fixture(tmp_path, trees)
    index = _index(game, user, parser)
    duplicate = index.group_definition("christian")
    assert duplicate["status"] == "unknown"
    assert duplicate["reason"] == "RELIGION_GROUP_AST_DUPLICATE_CHILD"

    nested = _node("outer", kind="block", children=[
        _node("inner", kind="block", children=[_node("value", value="1", line=7)], line=6)
    ], line=5)
    trees2 = {"00_religions.txt": [
        _group("christian", _node("catholic", kind="block", children=[nested], line=3), line=1)
    ]}
    game2, user2, parser2 = _fixture(tmp_path / "budget", trees2)
    index2 = _index(game2, user2, parser2)
    monkeypatch.setattr(religion_definitions, "MAX_DECLARATION_AST_NODES", 2)
    over_budget = index2.definition("catholic")
    assert over_budget["status"] == "unknown"
    assert over_budget["reason"] == "RELIGION_DECLARATION_AST_NODE_LIMIT"
    assert "syntax" not in over_budget

    monkeypatch.setattr(religion_definitions, "MAX_DECLARATION_AST_NODES", 32768)
    monkeypatch.setattr(religion_definitions, "MAX_DECLARATION_AST_DEPTH", 1)
    too_deep = index2.definition("catholic")
    assert too_deep["status"] == "unknown"
    assert too_deep["reason"] == "RELIGION_DECLARATION_AST_DEPTH_LIMIT"
    monkeypatch.setattr(religion_definitions, "MAX_DECLARATION_AST_DEPTH", 64)
    monkeypatch.setattr(religion_definitions, "MAX_DECLARATION_JSON_BYTES", 128)
    too_large = index2.definition("catholic")
    assert too_large["status"] == "unknown"
    assert too_large["reason"] == "RELIGION_DECLARATION_AST_JSON_LIMIT"


def test_definition_declaration_rejects_invalid_nested_assignment(tmp_path):
    invalid = _node("unexpected_assignment", value="x", assignment="not-an-operator", line=5)
    religion = _node("catholic", kind="block", children=[invalid], line=3)
    game, user, parser = _fixture(tmp_path, {"00_religions.txt": [
        _group("christian", religion, line=1)
    ]})
    result = _index(game, user, parser).definition("catholic")
    assert result["status"] == "unknown"
    assert result["reason"] == "RELIGION_DECLARATION_AST_NODE_INVALID"
    assert "syntax" not in result
