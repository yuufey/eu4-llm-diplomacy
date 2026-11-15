"""Mocked-index tests for bounded religious-school AST selection."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information.religious_school_definitions import ReligiousSchoolDefinitionIndex


def _node(key, *, assignment="=", kind="block", value=None, children=None, line=1):
    return {
        "key": key,
        "assignment": assignment,
        "kind": kind,
        "value": value,
        "children": deepcopy(children or []),
        "line": line,
        "end_line": line,
        "source_column": 1,
        "end_column": 20,
    }


def _group_result(group_key="christian", school_key="school_of_salamanca"):
    trigger = _node("potential_invite_scholar", children=[
        _node("has_country_flag", kind="scalar", value="example", children=[], line=12),
    ], line=11)
    school = _node(school_key, children=[trigger], line=10)
    schools = _node("religious_schools", children=[school], line=9)
    root = _node(group_key, children=[
        schools,
        _node("flag_emblem_index_range", children=[
            _node("1", assignment=None, kind="bare", children=[], line=15),
        ], line=14),
    ], line=1)
    pins = {
        "configuration_sha256": "1" * 64,
        "definitions_sha256": "2" * 64,
        "parser_manifest_sha256": "3" * 64,
        "cwt_sha256": "4" * 64,
        "cwt_commit": "a" * 40,
    }
    return {
        "status": "known",
        "religion_group_key": group_key,
        "definition": {
            "relative_file": "common/religions/00_religion.txt",
            "line": 1,
            "file_sha256": "5" * 64,
            "source_kind": "basegame",
        },
        "source": deepcopy(pins),
        "source_pins": deepcopy(pins),
        "syntax": root,
        "conditions_evaluated": False,
        "effects_executed": False,
        "runtime_state_observed": False,
    }


class FakeIndex:
    def __init__(self, result=None, *, context=None, context_after=None,
                 group_error=None, fail_assert_at=None):
        self.result = deepcopy(result if result is not None else _group_result())
        self.current_context = deepcopy(context if context is not None else {"status": "ready", "revision": 1})
        self.context_after = deepcopy(context_after)
        self.group_error = group_error
        self.fail_assert_at = fail_assert_at
        self.calls = []
        self.context_calls = 0
        self.assert_calls = 0

    def context(self):
        self.context_calls += 1
        return deepcopy(self.current_context)

    def assert_current(self):
        self.assert_calls += 1
        if self.fail_assert_at == self.assert_calls:
            raise ValueError("INDEX_CHANGED")

    def group_definition(self, group_key):
        self.calls.append(group_key)
        if self.context_after is not None:
            self.current_context = deepcopy(self.context_after)
        if self.group_error is not None:
            raise self.group_error
        return deepcopy(self.result)


def _unknown():
    return {
        "status": "unknown",
        "reason": "RELIGIOUS_SCHOOL_DEFINITION_UNAVAILABLE",
    }


def test_selects_exact_school_ast_and_reuses_group_provenance_once():
    index = FakeIndex()
    wrapped = ReligiousSchoolDefinitionIndex(index)

    result = wrapped.definition("christian", "school_of_salamanca")

    assert result == {
        "status": "known",
        "religion_group_key": "christian",
        "school_key": "school_of_salamanca",
        "source": index.result["source"],
        "source_pins": index.result["source_pins"],
        "syntax": index.result["syntax"]["children"][0]["children"][0],
        "conditions_evaluated": False,
        "effects_executed": False,
        "active_effects_proven": False,
    }
    assert set(result) == {
        "status", "religion_group_key", "school_key", "source", "source_pins",
        "syntax", "conditions_evaluated", "effects_executed", "active_effects_proven",
    }
    assert index.calls == ["christian"]
    assert index.assert_calls == 2
    assert index.context_calls == 2


def test_context_and_assert_current_forward_to_wrapped_index():
    index = FakeIndex()
    wrapped = ReligiousSchoolDefinitionIndex(index)

    context = wrapped.context()
    context["revision"] = 99
    wrapped.assert_current()

    assert index.current_context == {"status": "ready", "revision": 1}
    assert index.context_calls == 1
    assert index.assert_calls == 1


@pytest.mark.parametrize(("group_key", "school_key"), [
    ("Christian", "school_of_salamanca"),
    ("christian", "School_Of_Salamanca"),
])
def test_requires_exact_canonical_group_and_school_keys(group_key, school_key):
    wrapped = ReligiousSchoolDefinitionIndex(FakeIndex())

    assert wrapped.definition(group_key, school_key) == _unknown()


@pytest.mark.parametrize(("group_key", "school_key"), [
    (None, "school_of_salamanca"),
    (True, "school_of_salamanca"),
    ("christian", None),
    ("christian", "bad key"),
    ("../group", "school_of_salamanca"),
])
def test_invalid_key_types_or_syntax_return_exact_unknown_without_reading_index(group_key, school_key):
    index = FakeIndex()
    wrapped = ReligiousSchoolDefinitionIndex(index)

    assert wrapped.definition(group_key, school_key) == _unknown()
    assert index.calls == []
    assert index.assert_calls == 0
    assert index.context_calls == 0


def test_group_definition_failure_or_budget_error_is_unknown_without_retry():
    index = FakeIndex(group_error=ValueError("RELIGION_DECLARATION_AST_NODE_LIMIT"))
    wrapped = ReligiousSchoolDefinitionIndex(index)

    assert wrapped.definition("christian", "school_of_salamanca") == _unknown()
    assert index.calls == ["christian"]
    assert index.assert_calls == 2
    assert index.context_calls == 2


def test_unknown_group_definition_is_projected_to_fixed_unknown_dto():
    group = {"status": "unknown", "reason": "RELIGION_GROUP_NOT_FOUND", "private_path": "C:/secret"}
    index = FakeIndex(group)
    wrapped = ReligiousSchoolDefinitionIndex(index)

    assert wrapped.definition("christian", "school_of_salamanca") == _unknown()
    assert index.calls == ["christian"]


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "casefold_duplicate", "not_block", "wrong_assignment", "has_value"])
def test_religious_schools_container_must_be_unique_and_block_shaped(mutation):
    group = _group_result()
    children = group["syntax"]["children"]
    schools = children[0]
    if mutation == "missing":
        children.pop(0)
    elif mutation == "duplicate":
        children.append(deepcopy(schools))
    elif mutation == "casefold_duplicate":
        duplicate = deepcopy(schools)
        duplicate["key"] = "Religious_Schools"
        children.append(duplicate)
    elif mutation == "not_block":
        schools["kind"] = "scalar"
        schools["children"] = []
    elif mutation == "wrong_assignment":
        schools["assignment"] = ">"
    elif mutation == "has_value":
        schools["value"] = "yes"
    wrapped = ReligiousSchoolDefinitionIndex(FakeIndex(group))

    assert wrapped.definition("christian", "school_of_salamanca") == _unknown()


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "casefold_collision"])
def test_school_child_must_match_exactly_once_without_casefold_collision(mutation):
    group = _group_result()
    school_children = group["syntax"]["children"][0]["children"]
    if mutation == "missing":
        school_children.clear()
    elif mutation == "duplicate":
        school_children.append(deepcopy(school_children[0]))
    else:
        collision = deepcopy(school_children[0])
        collision["key"] = "School_Of_Salamanca"
        school_children.append(collision)
    wrapped = ReligiousSchoolDefinitionIndex(FakeIndex(group))

    assert wrapped.definition("christian", "school_of_salamanca") == _unknown()


@pytest.mark.parametrize(("field", "bad_value"), [
    ("assignment", ">"),
    ("kind", "scalar"),
    ("value", "yes"),
])
def test_selected_school_must_be_an_equals_block_with_null_value(field, bad_value):
    group = _group_result()
    school = group["syntax"]["children"][0]["children"][0]
    school[field] = bad_value
    if field == "kind":
        school["children"] = []
    wrapped = ReligiousSchoolDefinitionIndex(FakeIndex(group))

    assert wrapped.definition("christian", "school_of_salamanca") == _unknown()


@pytest.mark.parametrize("mutation", ["group_key", "syntax_key", "static_flag", "pin_mismatch", "bad_pin", "private_extra"])
def test_group_identity_static_flags_and_source_pins_are_required(mutation):
    group = _group_result()
    if mutation == "group_key":
        group["religion_group_key"] = "muslim"
    elif mutation == "syntax_key":
        group["syntax"]["key"] = "muslim"
    elif mutation == "static_flag":
        group["effects_executed"] = True
    elif mutation == "pin_mismatch":
        group["source"]["definitions_sha256"] = "9" * 64
    elif mutation == "bad_pin":
        group["source_pins"]["cwt_commit"] = "short"
        group["source"]["cwt_commit"] = "short"
    elif mutation == "private_extra":
        group["private_path"] = "C:/secret"
    wrapped = ReligiousSchoolDefinitionIndex(FakeIndex(group))

    assert wrapped.definition("christian", "school_of_salamanca") == _unknown()


@pytest.mark.parametrize("mode", ["context", "assert_current"])
def test_input_drift_or_index_staleness_retracts_selected_school(mode):
    if mode == "context":
        index = FakeIndex(context_after={"status": "ready", "revision": 2})
    else:
        index = FakeIndex(fail_assert_at=2)
    wrapped = ReligiousSchoolDefinitionIndex(index)

    assert wrapped.definition("christian", "school_of_salamanca") == _unknown()
    assert index.calls == ["christian"]


def test_school_ast_and_pins_are_deep_copied_from_group_result():
    index = FakeIndex()
    wrapped = ReligiousSchoolDefinitionIndex(index)

    first = wrapped.definition("christian", "school_of_salamanca")
    first["syntax"]["children"][0]["children"][0]["value"] = "changed"
    first["source_pins"]["definitions_sha256"] = "f" * 64

    second = wrapped.definition("christian", "school_of_salamanca")
    assert second["syntax"]["children"][0]["children"][0]["value"] == "example"
    assert second["source_pins"]["definitions_sha256"] == "2" * 64

