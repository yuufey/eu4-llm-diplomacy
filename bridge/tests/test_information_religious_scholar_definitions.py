"""Offline tests for the static school-to-scholar-modifier index."""
from __future__ import annotations

from copy import deepcopy
import hashlib

import pytest

import bridge.information.religious_scholar_definitions as scholar_definitions
from bridge.information.religious_scholar_definitions import ReligiousScholarDefinitionIndex
from bridge.tests.test_information_imperial_reform_definitions import (
    FixtureParser,
    _node,
)
from bridge.tests.test_information_religion_definitions import _fixture, _group


PINS = {
    "configuration_sha256": "1" * 64,
    "definitions_sha256": "2" * 64,
    "parser_manifest_sha256": "3" * 64,
    "cwt_sha256": "4" * 64,
    "cwt_commit": "a" * 40,
}
CONTEXT = {
    "status": "ready",
    "configuration_sha256": PINS["configuration_sha256"],
    "definitions_sha256": PINS["definitions_sha256"],
    "script_parser": {"manifest_sha256": PINS["parser_manifest_sha256"]},
    "cwt_contract": {
        "commit": PINS["cwt_commit"],
        "schema_file": {"sha256": PINS["cwt_sha256"]},
    },
}
FILE_SHA = hashlib.sha256(b"fixture definition").hexdigest()


def _ast(
    key,
    *,
    kind="scalar",
    value=None,
    children=None,
    assignment="=",
    line=1,
    end_line=None,
):
    children = list(children or [])
    return {
        "key": key,
        "assignment": assignment,
        "kind": kind,
        "value": value,
        "children": children,
        "line": line,
        "end_line": line if end_line is None else end_line,
        "source_column": 0,
        "end_column": len(key),
    }


def _add_modifier(name, *, line=10, extra=()):
    children = [_ast("name", value=name, line=line)]
    children.extend(extra)
    return _ast("add_country_modifier", kind="block", children=children, line=line)


def _school(school_key="hanafi_school", modifier_key="hanafi_scholar_modifier", *,
            cooldown=True, extra_children=(), line=5):
    invite_children = [_add_modifier(modifier_key, line=line + 1)]
    if cooldown:
        invite_children.append(_add_modifier(
            "has_invited_scholar_recently", line=line + 2,
            extra=(_ast("hidden", value="yes", line=line + 2),),
        ))
    children = [
        _ast("potential_invite_scholar", kind="block", children=[], line=line),
        _ast("on_invite_scholar", kind="block", children=invite_children,
             line=line + 1, end_line=line + 4),
        _ast("invite_scholar_modifier_display", value=modifier_key, line=line + 5),
    ]
    children.extend(extra_children)
    return _ast(school_key, kind="block", children=children, line=line, end_line=line + 6)


def _group_result(group_key="muslim", schools=(), *, extra_group_children=(),
                  definition=None, pins=None):
    school_block = _ast(
        "religious_schools", kind="block", children=list(schools), line=3,
        end_line=40,
    )
    syntax = _ast(
        group_key, kind="block", children=[school_block, *extra_group_children],
        line=1, end_line=50,
    )
    pins = deepcopy(PINS if pins is None else pins)
    definition = deepcopy(definition or {
        "relative_file": "common/religions/00_fixture.txt",
        "line": 1,
        "file_sha256": FILE_SHA,
        "source_kind": "basegame",
    })
    return {
        "status": "known",
        "religion_group_key": group_key,
        "definition": definition,
        "source": deepcopy(pins),
        "source_pins": deepcopy(pins),
        "syntax": syntax,
        "conditions_evaluated": False,
        "effects_executed": False,
        "runtime_state_observed": False,
    }


class _Index:
    def __init__(self, groups, *, keys=None, contexts=None, stale=False):
        self.groups = groups
        self.keys = list(groups) if keys is None else list(keys)
        self.contexts = contexts or [deepcopy(CONTEXT)]
        self.context_calls = 0
        self.stale = stale
        self.group_calls = []

    def assert_current(self):
        if self.stale:
            raise ValueError("stale fixture")

    def context(self):
        current = self.contexts[min(self.context_calls, len(self.contexts) - 1)]
        self.context_calls += 1
        return deepcopy(current)

    def group_keys(self):
        return list(self.keys)

    def group_definition(self, key):
        self.group_calls.append(key)
        return deepcopy(self.groups[key])


def _wrapper_for(*schools, group_key="muslim", **kwargs):
    return ReligiousScholarDefinitionIndex(
        index=_Index({group_key: _group_result(group_key, schools)}, **kwargs)
    )


def test_mapping_extracts_displayed_modifier_and_excludes_cooldown():
    result = _wrapper_for(_school()).mapping()

    assert result["status"] == "known"
    assert result["conditions_evaluated"] is False
    assert result["effects_executed"] is False
    assert result["runtime_state_observed"] is False
    assert result["source_pins"] == PINS
    assert len(result["mappings"]) == 1
    row = result["mappings"][0]
    assert set(row) == {
        "religion_group_key", "school_key", "modifier_key", "definition",
        "source_pins", "conditions_evaluated", "effects_executed",
        "runtime_state_observed",
    }
    assert row["religion_group_key"] == "muslim"
    assert row["school_key"] == "hanafi_school"
    assert row["modifier_key"] == "hanafi_scholar_modifier"
    assert row["modifier_key"] != "has_invited_scholar_recently"
    assert row["definition"]["relative_file"] == "common/religions/00_fixture.txt"
    assert row["definition"]["line"] == 5
    assert row["source_pins"] == PINS
    assert all(row[key] is False for key in (
        "conditions_evaluated", "effects_executed", "runtime_state_observed"
    ))


def test_default_index_enumerates_existing_parsed_groups(tmp_path):
    school = _node("hanafi_school", kind="block", children=[
        _node("on_invite_scholar", kind="block", children=[
            _node("add_country_modifier", kind="block", children=[
                _node("name", value="hanafi_scholar_modifier", line=4),
            ], line=3),
            _node("add_country_modifier", kind="block", children=[
                _node("name", value="has_invited_scholar_recently", line=6),
                _node("hidden", value="yes", line=6),
            ], line=5),
        ], line=2),
        _node("invite_scholar_modifier_display", value="hanafi_scholar_modifier", line=7),
    ], line=1)
    religious_schools = _node(
        "religious_schools", kind="block", children=[school], line=10
    )
    game, user, parser = _fixture(
        tmp_path,
        {"00_religions.txt": [_group("muslim", religious_schools, line=1)]},
    )
    index = ReligiousScholarDefinitionIndex(
        game_root=game, user_data=user, enabled_mods=(), parser=parser
    )

    result = index.mapping()

    assert result["status"] == "known"
    assert [(row["religion_group_key"], row["school_key"], row["modifier_key"])
            for row in result["mappings"]] == [
        ("muslim", "hanafi_school", "hanafi_scholar_modifier")
    ]
    assert result["mappings"][0]["definition"]["line"] == 1
    assert result["source_pins"]["configuration_sha256"]
    assert result["source_pins"]["definitions_sha256"]
    assert result["source_pins"]["parser_manifest_sha256"] == "a" * 64
    assert parser.calls


def test_ready_empty_index_returns_known_empty_mapping(tmp_path):
    game, user, parser = _fixture(tmp_path, {"00_empty.txt": []})
    result = ReligiousScholarDefinitionIndex(
        game_root=game, user_data=user, enabled_mods=(), parser=parser
    ).mapping()

    assert result["status"] == "known"
    assert result["mappings"] == []
    assert result["source_pins"]["definitions_sha256"]


def test_group_duplicate_and_casefold_collision_fail_closed():
    index = _Index(
        {"muslim": _group_result("muslim", [_school()])},
        keys=["muslim", "MUSLIM"],
    )
    result = ReligiousScholarDefinitionIndex(index=index).mapping()
    assert result == {
        "status": "unknown",
        "reason": "RELIGIOUS_SCHOLAR_MAPPING_UNAVAILABLE",
    }
    assert index.group_calls == []


@pytest.mark.parametrize("school_keys", [
    ("hanafi_school", "hanafi_school"),
    ("hanafi_school", "Hanafi_school"),
])
def test_duplicate_or_casefold_school_keys_fail_closed(school_keys):
    schools = [_school(key, f"{key}_scholar_modifier") for key in school_keys]
    result = _wrapper_for(*schools).mapping()
    assert result["status"] == "unknown"
    assert "mappings" not in result


def test_duplicate_religious_schools_blocks_fail_closed():
    base = _group_result("muslim", [_school()])
    base["syntax"]["children"].append(deepcopy(base["syntax"]["children"][0]))
    result = ReligiousScholarDefinitionIndex(index=_Index({"muslim": base})).mapping()
    assert result["status"] == "unknown"


@pytest.mark.parametrize("display_nodes", [
    [],
    [_ast("invite_scholar_modifier_display", value="hanafi_scholar_modifier", line=50),
     _ast("invite_scholar_modifier_display", value="hanafi_scholar_modifier", line=51)],
    [_ast("invite_scholar_modifier_display", kind="block", children=[], line=50)],
])
def test_missing_duplicate_or_malformed_display_fails_closed(display_nodes):
    school = _school()
    school["children"] = [
        node for node in school["children"]
        if node["key"] != "invite_scholar_modifier_display"
    ] + display_nodes
    result = _wrapper_for(school).mapping()
    assert result["status"] == "unknown"


def test_cooldown_modifier_alone_does_not_satisfy_display_mapping():
    school = _school(cooldown=False)
    handler = next(n for n in school["children"] if n["key"] == "on_invite_scholar")
    handler["children"][0]["children"][0]["value"] = "has_invited_scholar_recently"
    result = _wrapper_for(school).mapping()
    assert result["status"] == "unknown"


def test_duplicate_matching_add_country_modifier_fails_closed():
    school = _school()
    handler = next(n for n in school["children"] if n["key"] == "on_invite_scholar")
    handler["children"].append(_add_modifier("hanafi_scholar_modifier", line=30))
    result = _wrapper_for(school).mapping()
    assert result["status"] == "unknown"


@pytest.mark.parametrize("mapped_keys", [
    ("shared_scholar_modifier", "shared_scholar_modifier"),
    ("shared_scholar_modifier", "SHARED_SCHOLAR_MODIFIER"),
])
def test_modifier_mapping_to_multiple_schools_fails_closed(mapped_keys):
    result = _wrapper_for(
        _school("school_one", mapped_keys[0]),
        _school("school_two", mapped_keys[1], line=40),
    ).mapping()
    assert result["status"] == "unknown"


def test_group_definition_wrong_pins_or_extra_keys_fail_closed():
    result = _group_result("muslim", [_school()])
    result["source_pins"]["definitions_sha256"] = "f" * 64
    assert ReligiousScholarDefinitionIndex(
        index=_Index({"muslim": result})
    ).mapping()["status"] == "unknown"

    result = _group_result("muslim", [_school()])
    result["private_pointer"] = "0x1234"
    assert ReligiousScholarDefinitionIndex(
        index=_Index({"muslim": result})
    ).mapping()["status"] == "unknown"


@pytest.mark.parametrize("bad_mutation", [
    lambda syntax: syntax["children"][0]["children"][0].update(private="x"),
    lambda syntax: syntax["children"][0]["children"][0].update(line=True),
    lambda syntax: syntax["children"][0]["children"][0].update(assignment="bad"),
])
def test_malformed_ast_fails_closed(bad_mutation):
    result = _group_result("muslim", [_school()])
    bad_mutation(result["syntax"])
    projected = ReligiousScholarDefinitionIndex(
        index=_Index({"muslim": result})
    ).mapping()
    assert projected["status"] == "unknown"


def test_ast_total_budget_and_group_count_budget_fail_closed(monkeypatch):
    monkeypatch.setattr(scholar_definitions, "MAX_TOTAL_AST_NODES", 2)
    result = _wrapper_for(_school()).mapping()
    assert result["status"] == "unknown"

    monkeypatch.setattr(scholar_definitions, "MAX_TOTAL_AST_NODES", 131072)
    index = _Index({"muslim": _group_result("muslim"), "christian": _group_result("christian")})
    monkeypatch.setattr(scholar_definitions, "MAX_GROUPS", 1)
    result = ReligiousScholarDefinitionIndex(index=index).mapping()
    assert result["status"] == "unknown"


def test_context_change_and_stale_index_fail_closed():
    changed = deepcopy(CONTEXT)
    changed["definitions_sha256"] = "f" * 64
    index = _Index(
        {"muslim": _group_result("muslim", [_school()])},
        contexts=[deepcopy(CONTEXT), changed],
    )
    assert ReligiousScholarDefinitionIndex(index=index).mapping()["status"] == "unknown"

    stale = _Index({"muslim": _group_result("muslim", [_school()])}, stale=True)
    assert ReligiousScholarDefinitionIndex(index=stale).mapping()["status"] == "unknown"


def test_missing_group_keys_protocol_fails_closed():
    class NoEnumeration:
        def assert_current(self):
            pass

        def context(self):
            return deepcopy(CONTEXT)

    result = ReligiousScholarDefinitionIndex(index=NoEnumeration()).mapping()
    assert result["status"] == "unknown"


def test_output_isolated_from_the_index_result():
    index = _Index({"muslim": _group_result("muslim", [_school()])})
    source = ReligiousScholarDefinitionIndex(index=index)
    first = source.mapping()
    first["mappings"][0]["source_pins"]["configuration_sha256"] = "0" * 64
    second = source.mapping()
    assert second["mappings"][0]["source_pins"] == PINS
