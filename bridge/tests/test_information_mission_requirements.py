"""Decision-relevant mission prerequisites and missing-input boundaries."""
from copy import deepcopy

import pytest

from bridge.information.mission_requirements import evaluate_prerequisites


def block(*ids):
    return {"key": "required_missions", "kind": "block", "assignment": "=", "value": None,
            "children": [{"key": task, "kind": "bare", "assignment": None, "value": None, "children": []}
                         for task in ids]}


def evaluate(rules, completed):
    return evaluate_prerequisites(rules, completed, game_version="1.37.4")


def test_all_required_ids_must_be_completed_and_missing_ids_are_explicit():
    rules = block("first", "second")
    incomplete = evaluate(rules, {"status": "known", "task_ids": ["first", "unrelated"]})
    assert incomplete["status"] == "known" and incomplete["satisfied"] is False
    assert incomplete["missing_task_ids"] == ["second"]
    complete = evaluate(rules, {"status": "known", "task_ids": ["second", "first"]})
    assert complete["satisfied"] is True and complete["missing_task_ids"] == []
    assert complete["semantics"]["scope"] == "required_missions_only"


def test_no_prerequisites_is_distinct_from_unknown_completion_history():
    assert evaluate([], {"status": "unknown"})["satisfied"] is True
    assert evaluate(block(), {"status": "unknown"})["satisfied"] is True
    unknown = evaluate(block("first"), {"status": "unknown"})
    assert unknown["satisfied"] is None and unknown["missing_task_ids"] is None
    assert unknown["required_task_ids"] == ["first"]


def test_repeated_blocks_append_without_replacing_earlier_requirements():
    result = evaluate([block("a"), block("b", "a")], {"status": "known", "task_ids": ["b"]})
    assert result["required_task_ids"] == ["a", "b", "a"]
    assert result["satisfied"] is False and result["missing_task_ids"] == ["a", "a"]


@pytest.mark.parametrize("rules", [None, ["first"], {"key": "required_missions"},
    dict(block("first"), assignment=None), dict(block("first"), kind="scalar"),
    block("@script_variable"), dict(block(), children=[dict(block(), key="first")])])
def test_unsupported_expressions_do_not_become_empty_or_false_requirements(rules):
    result = evaluate(rules, {"status": "known", "task_ids": []})
    assert result["status"] == "unknown" and result["satisfied"] is None


@pytest.mark.parametrize("values", [None, "first", [None], ["bad task"], ["a"]*4097])
def test_bad_completion_input_cannot_prove_absence(values):
    result = evaluate(block("first"), {"status": "known", "task_ids": values})
    assert result["status"] == "unknown" and result["missing_task_ids"] is None


def test_limits_versions_and_input_preservation():
    rules, completed = block("a"), {"status": "known", "task_ids": ["a"]}
    before = deepcopy((rules, completed))
    assert evaluate(rules, completed)["satisfied"] is True
    assert (rules, completed) == before
    assert evaluate(block(*(["a"]*513)), completed)["status"] == "unknown"
    assert evaluate_prerequisites(rules, completed, game_version="1.37.5")["status"] == "unknown"


def test_mission_adapter_attaches_derivation_but_keeps_trigger_and_reward_unevaluated(tmp_path):
    from bridge.tests.test_information_missions import service, query
    api, state, definitions = service(tmp_path)
    definitions.values["loaded"]["tasks"][1]["required_missions"] = block("first")
    try:
        result = api.query("prerequisite-derivation", queries=[query("M02", ["prerequisites", "unlock_conditions"], task_id="second")])
        fields = result["items"][0]["fields"]
        entry = fields["prerequisites"]["value"][0]
        assert entry["evaluated"] is True and entry["evaluation"]["satisfied"] is True
        assert fields["unlock_conditions"]["value"]["evaluated"] is False
        state.sample["completed_missions"] = {"status": "unknown"}
        other = api.query("unknown-completions", queries=[query("M02", ["prerequisites"], task_id="second")])
        entry = other["items"][0]["fields"]["prerequisites"]["value"][0]
        assert entry["evaluated"] is False and entry["evaluation"]["satisfied"] is None
    finally:
        api.close()
