from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

from bridge.information.mission_definitions import _ScriptNode
from bridge.information.opinion_definitions import (
    DIRECTORY, FIELDS, OpinionModifierDefinitionIndex,
)


class FixtureParser:
    def __init__(self, trees):
        self.trees = trees
        self.calls = []
        self._metadata = {
            "status": "ready", "complete": True, "name": "fixture-cwtools",
            "manifest_sha256": "a" * 64, "semantics": "syntax_only",
            "conditions_evaluated": False, "effects_executed": False,
        }

    def context(self):
        return deepcopy(self._metadata)

    def assert_current(self):
        return None

    def parse_files(self, paths):
        resolved = [str(Path(path).resolve()) for path in paths]
        self.calls.append(resolved)
        return {
            path: {"nodes": deepcopy(self.trees[Path(path).name]), "parser": self.context()}
            for path in resolved
        }


def _node(key, *, value=None, kind="scalar", assignment="=", children=None, line=1):
    children = list(children or [])
    return _ScriptNode(key=key, line=line, end_line=line + bool(children), value=value,
                       children=children, kind=kind, assignment=assignment,
                       raw_key=key, raw_value=value)


def _definition(key, *fields, line=1):
    return _node(key, kind="block", children=list(fields), line=line)


def _fixture(tmp_path, definitions, *, mods=(), directory=DIRECTORY):
    game = tmp_path / "game"
    user = tmp_path / "user"
    base = game.joinpath(*Path(directory).parts)
    base.mkdir(parents=True)
    user.mkdir(parents=True)
    (game / "launcher-settings.json").write_text(
        json.dumps({"rawVersion": "v1.37.4.0"}), encoding="utf-8",
    )
    trees = {}
    for filename, (text, nodes) in definitions.items():
        target = base / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        trees[filename] = nodes
    parser = FixtureParser(trees)
    return game, user, parser


def _index(game, user, parser, mods=(), *, directory=DIRECTORY, fields=FIELDS):
    return OpinionModifierDefinitionIndex(
        game, user, enabled_mods=mods, parser=parser,
        directory=directory, fields=fields,
    )


def _mod(tmp_path, *, name="overlay", replace_path=None):
    user = tmp_path / "user"
    user.mkdir(exist_ok=True)
    mod_root = user / "mod" / name
    descriptor = user / "mod" / f"{name}.mod"
    descriptor.parent.mkdir(parents=True, exist_ok=True)
    lines = [f'name = "{name}"', f'path = "{mod_root.as_posix()}"']
    if replace_path:
        lines.append(f'replace_path = "{replace_path}"')
    descriptor.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return mod_root, descriptor


def test_lookup_keeps_missing_zero_and_nonliteral_declarations_distinct(tmp_path):
    tree = _definition(
        "llm_bridge_goodwill",
        _node("opinion", value="0", line=2),
        _node("max", value="10", line=3),
        _node("yearly_decay", value="scale_decay", line=4),
        _node("years", kind="block", children=[_node("value", value="2")], line=5),
    )
    game, user, parser = _fixture(tmp_path, {"00_opinion.txt": ("llm_bridge_goodwill = {}\n", [tree])})
    index = _index(game, user, parser)

    result = index.lookup("llm_bridge_goodwill")
    assert result["status"] == "known"
    declarations = result["declarations"]
    assert declarations["opinion"] == {"status": "declared", "value": "0"}
    assert declarations["min"] == {"status": "not_declared"}
    assert declarations["max"] == {"status": "declared", "value": "10"}
    assert declarations["yearly_decay"] == {
        "status": "unknown", "reason": "NON_LITERAL_DECLARATION",
    }
    assert declarations["years"] == {
        "status": "unknown", "reason": "NON_LITERAL_DECLARATION",
    }
    assert declarations["months"] == {"status": "not_declared"}
    assert result["source_basis"] == "disk_configuration"
    assert result["loaded_membership_verified"] is False
    assert result["conditions_evaluated"] is False
    assert result["current_decay_evaluated"] is False
    assert index.context()["status"] == "ready"
    assert parser.calls and len(parser.calls[0]) == 1


def test_same_relative_mod_file_overrides_base_definition(tmp_path):
    base_tree = _definition("base_only", _node("opinion", value="1"))
    game, user, _ = _fixture(
        tmp_path, {"00_shared.txt": ("base syntax\n", [base_tree])},
    )
    mod_root, descriptor = _mod(tmp_path)
    mod_file = mod_root / "common" / "opinion_modifiers" / "00_shared.txt"
    mod_file.parent.mkdir(parents=True)
    mod_file.write_text("mod syntax\n", encoding="utf-8")
    parser = FixtureParser({"00_shared.txt": [
        _definition("overlay_only", _node("opinion", value="2")),
    ]})

    index = _index(game, user, parser, [descriptor])
    assert index.context()["status"] == "ready"
    assert index.lookup("overlay_only")["status"] == "known"
    assert index.lookup("base_only")["reason"] == "OPINION_DEFINITION_NOT_FOUND"
    assert index.context()["definition_files"][0]["source_kind"] == "enabled_mod"
    assert len(parser.calls[0]) == 1


def test_custom_event_modifier_directory_fields_and_mod_override(tmp_path):
    directory = "common/event_modifiers"
    game, user, _ = _fixture(
        tmp_path,
        {"00_shared.txt": ("base syntax\n", [_definition("base_only")])},
        directory=directory,
    )
    mod_root, descriptor = _mod(tmp_path, name="event-overlay")
    mod_file = mod_root / "common" / "event_modifiers" / "00_shared.txt"
    mod_file.parent.mkdir(parents=True)
    mod_file.write_text("mod syntax\n", encoding="utf-8")
    parser = FixtureParser({"00_shared.txt": [
        _definition(
            "event_overlay",
            _node("diplomatic_upkeep", value="1"),
            _node("nobles_loyalty_modifier", value="0.1"),
        ),
    ]})

    fields = ("diplomatic_upkeep", "nobles_loyalty_modifier")
    index = _index(
        game, user, parser, [descriptor], directory=directory, fields=fields,
    )
    result = index.lookup("event_overlay")

    assert result["status"] == "known"
    assert result["declarations"] == {
        "diplomatic_upkeep": {"status": "declared", "value": "1"},
        "nobles_loyalty_modifier": {"status": "declared", "value": "0.1"},
    }
    assert index.lookup("base_only")["reason"] == "OPINION_DEFINITION_NOT_FOUND"
    context = index.context()
    assert context["definition_scope"] == directory
    assert context["declaration_fields"] == list(fields)
    assert context["definition_files"][0]["relative"] == (
        "common/event_modifiers/00_shared.txt"
    )
    assert context["definition_files"][0]["source_kind"] == "enabled_mod"


def test_fields_none_reads_all_direct_child_declarations(tmp_path):
    directory = "common/event_modifiers"
    tree = _definition(
        "dynamic_fields",
        _node("global_tax_modifier", value="0.15"),
        _node("build_cost", value="-0.1"),
        _node("scripted_value", value="scale_value"),
        _node("nested_effect", kind="block", children=[_node("value", value="2")]),
        _node("Duplicate", value="1"),
        _node("duplicate", value="2"),
    )
    game, user, parser = _fixture(
        tmp_path,
        {"00_dynamic.txt": ("dynamic syntax\n", [tree])},
        directory=directory,
    )
    index = _index(game, user, parser, directory=directory, fields=None)

    result = index.lookup("dynamic_fields")
    assert result["status"] == "known"
    assert result["declarations"] == {
        "build_cost": {"status": "declared", "value": "-0.1"},
        "Duplicate": {"status": "unknown", "reason": "DUPLICATE_FIELD_DECLARATION"},
        "global_tax_modifier": {"status": "declared", "value": "0.15"},
        "nested_effect": {"status": "unknown", "reason": "NON_LITERAL_DECLARATION"},
        "scripted_value": {"status": "unknown", "reason": "NON_LITERAL_DECLARATION"},
    }
    assert index.context()["declaration_fields"] is None


def test_replace_path_removes_base_directory_and_uses_replacement_file(tmp_path):
    base_tree = _definition("base_only", _node("opinion", value="1"))
    game, user, _ = _fixture(
        tmp_path, {"00_base.txt": ("base syntax\n", [base_tree])},
    )
    mod_root, descriptor = _mod(
        tmp_path, name="replace", replace_path="common/opinion_modifiers",
    )
    mod_file = mod_root / "common" / "opinion_modifiers" / "20_replacement.txt"
    mod_file.parent.mkdir(parents=True)
    mod_file.write_text("replacement syntax\n", encoding="utf-8")
    parser = FixtureParser({"20_replacement.txt": [
        _definition("replacement_only", _node("opinion", value="3")),
    ]})

    index = _index(game, user, parser, [descriptor])
    assert index.lookup("replacement_only")["status"] == "known"
    assert index.lookup("base_only")["reason"] == "OPINION_DEFINITION_NOT_FOUND"
    assert [item["relative"] for item in index.context()["definition_files"]] == [
        "common/opinion_modifiers/20_replacement.txt",
    ]


def test_duplicate_effective_keys_are_ambiguous_not_merged(tmp_path):
    first = _definition("shared_key", _node("opinion", value="1"), line=1)
    second = _definition("SHARED_KEY", _node("opinion", value="2"), line=4)
    game, user, parser = _fixture(tmp_path, {
        "00_first.txt": ("first\n", [first]),
        "10_second.txt": ("second\n", [second]),
    })
    result = _index(game, user, parser).lookup("shared_key")
    assert result["status"] == "unknown"
    assert result["reason"] == "OPINION_DEFINITION_AMBIGUOUS"
    assert {row["relative_file"] for row in result["definitions"]} == {
        "common/opinion_modifiers/00_first.txt",
        "common/opinion_modifiers/10_second.txt",
    }


def test_changed_directory_or_selected_file_withdraws_old_index(tmp_path):
    tree = _definition("one_key", _node("opinion", value="1"))
    game, user, parser = _fixture(tmp_path, {"00_base.txt": ("base\n", [tree])})
    index = _index(game, user, parser)
    assert index.lookup("one_key")["status"] == "known"

    (game / "common" / "opinion_modifiers" / "10_late.txt").write_text(
        "new file\n", encoding="utf-8",
    )
    result = index.lookup("one_key")
    assert result["status"] == "unknown"
    assert result["reason"] == "OPINION_DEFINITION_INDEX_UNAVAILABLE"

    game2, user2, parser2 = _fixture(
        tmp_path / "second", {"00_base.txt": ("base\n", [tree])},
    )
    index2 = _index(game2, user2, parser2)
    (game2 / "common" / "opinion_modifiers" / "00_base.txt").write_text(
        "changed bytes\n", encoding="utf-8",
    )
    assert index2.lookup("one_key")["reason"] == "OPINION_DEFINITION_INDEX_UNAVAILABLE"


def test_definition_budget_counts_duplicates_and_rejects_above_8192(tmp_path):
    repeated = [_definition("same_key", _node("opinion", value="0"))
                for _ in range(8193)]
    game, user, parser = _fixture(
        tmp_path, {"00_many.txt": ("bounded syntax\n", repeated)},
    )
    index = _index(game, user, parser)
    context = index.context()
    assert context["status"] == "unready"
    assert context["reasons"][0]["code"] == "DEFINITION_LIMIT"
    assert index.lookup("same_key")["reason"] == "OPINION_DEFINITION_INDEX_UNAVAILABLE"
