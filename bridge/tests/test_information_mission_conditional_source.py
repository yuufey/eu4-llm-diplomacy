"""Validation and public projection tests for conditional mission triggers."""

import pytest

from bridge.information.mission_condition_source import project_eligibility
from bridge.information.mission_trigger_memory import IF_EVALUATE_RVA
from bridge.information.mission_trigger_source import (
    MAX_PUBLIC_JSON_BYTES,
    normalize_triggers,
    project_progress,
)
from bridge.tests.test_information_mission_trigger_source import (
    _address,
    _group,
    _leaf,
    _normalized_state,
    _prerequisites,
    _report,
    _task,
)


def _if_node(limit, then, else_branch, *, selected_branch=None, evaluation=None,
             token=0x2F4D, method=IF_EVALUATE_RVA):
    limit_value = limit["evaluation"]["satisfied"]
    then_value = then["evaluation"]["satisfied"]
    else_value = else_branch["evaluation"]["satisfied"]
    if selected_branch is None:
        selected_branch = "then" if limit_value is True else "else" if limit_value is False else "unknown"
    if evaluation is None:
        if limit_value is True:
            computed = then_value
        elif limit_value is False:
            computed = else_value
        else:
            computed = then_value if then_value is not None and then_value == else_value else None
        evaluation = {
            "status": "unknown" if computed is None else "known",
            "satisfied": computed,
        }
    return {
        "kind": "if",
        "token": token,
        "method_rva": method,
        "native_pointer": _address(),
        "limit": limit,
        "then": then,
        "else": else_branch,
        "selected_branch": selected_branch,
        "evaluation": evaluation,
    }


def _branch(kind, value, *, metric=None):
    child = (_leaf(None, kind="unsupported", method=0x123456)
             if value is None else _leaf(value, metric=metric))
    return _group(kind, [child])


def _unknown_limit():
    return _group("and", [_leaf(None, kind="unsupported", method=0x123456)])


def _normalized_if(if_tree, *, task_id="task_a"):
    return normalize_triggers(
        _report([_task(task_id, _group("and", [if_tree]))]),
        _prerequisites(task_id),
    )


def test_reader_output_normalizes_and_projects_without_branch_shape_translation():
    """Exercise the actual producer/consumer boundary, not two hand-built trees."""
    from bridge.information import mission_trigger_memory as memory
    from bridge.tests.test_information_mission_conditional_triggers import _install_single_if
    from bridge.tests.test_information_mission_trigger_memory import _fixture, _write_leaf

    reader, module, country, loaded, guards, _definitions, pointers = _fixture()
    limit, body = 0xA30000, 0xA31000
    _write_leaf(reader, module, limit, "sailors", memory.SAILORS_TOKEN, 500)
    _write_leaf(reader, module, body, "sailors", memory.SAILORS_TOKEN, 800)
    reader.dword_put(country + memory.SAILORS_CURRENT_OFFSET, 9, signed=True)
    reader.dword_put(country + memory.SAILORS_MAX_OFFSET, 10, signed=True)
    _install_single_if(reader, module, pointers['task_a'], 0xA20000,
        limit_children=[limit], then_children=[body], else_children=[], token=0x27C3)
    captured = memory.capture_triggers(reader, module, country, loaded, code_guards=guards)
    assert captured['status'] == 'observed'
    entries = [{key: row[key] for key in ('root_id', 'task_id')} for row in captured['tasks']]
    normalized = normalize_triggers(_report(captured['tasks']), {'status': 'known', 'tasks': entries})
    assert normalized['status'] == 'known'
    public = project_progress({'mission_triggers': normalized}, entries, '1.37.4')
    assert public['status'] == 'known'
    branch = public['value']['tasks'][0]['trigger']['children'][0]
    assert branch['selected_branch'] == 'then'
    assert branch['evaluation'] == {'status': 'known', 'satisfied': True}
    assert set(('limit', 'then', 'else')).issubset(branch)
    assert 'branches' not in branch and 'native_pointer' not in branch


@pytest.mark.parametrize(
    ("limit", "then_value", "else_value", "selection", "expected"),
    [
        (True, False, True, "then", False),
        (False, True, False, "else", False),
        (None, True, True, "unknown", True),
        (None, True, False, "unknown", None),
        (None, None, None, "unknown", None),
    ],
)
def test_normalizer_recomputes_if_selection_and_three_state_result(
        limit, then_value, else_value, selection, expected):
    limit_node = _unknown_limit() if limit is None else _branch("and", limit)
    conditional = _if_node(
        limit_node,
        _branch("and", then_value),
        _branch("and", else_value),
    )

    normalized = _normalized_if(conditional)

    assert normalized["status"] == "known"
    result = normalized["tasks"][0]["tree"]["children"][0]
    assert result["kind"] == "if"
    assert result["selected_branch"] == selection
    assert result["evaluation"] == {
        "status": "unknown" if expected is None else "known",
        "satisfied": expected,
    }
    assert set(("limit", "then", "else")).issubset(result)
    assert "children" not in result


def test_normalizer_accepts_nested_else_if_chain():
    inner = _if_node(
        _branch("and", True),
        _branch("and", True),
        _branch("and", False),
    )
    outer = _if_node(
        _branch("and", False),
        _branch("and", False),
        inner,
    )

    normalized = _normalized_if(outer)

    assert normalized["status"] == "known"
    public_source = normalized["tasks"][0]["tree"]["children"][0]
    assert public_source["selected_branch"] == "else"
    assert public_source["else"]["kind"] == "if"
    assert public_source["else"]["selected_branch"] == "then"
    assert public_source["evaluation"] == {"status": "known", "satisfied": True}


@pytest.mark.parametrize("corruption", [
    "bad_token",
    "bad_method_type",
    "bad_evaluation_type",
    "bad_selection",
    "forged_result",
    "wrong_method",
    "bad_limit_kind",
    "bad_then_kind",
    "bad_else_kind",
    "missing_branch",
    "children_alias",
])
def test_normalizer_rejects_malformed_or_forged_if_nodes(corruption):
    conditional = _if_node(
        _branch("and", True),
        _branch("and", True),
        _branch("and", False),
    )
    if corruption == "bad_token":
        conditional["token"] = "0x2F4D"
    elif corruption == "bad_method_type":
        conditional["method_rva"] = True
    elif corruption == "bad_evaluation_type":
        conditional["evaluation"] = {"status": "known", "satisfied": 1}
    elif corruption == "bad_selection":
        conditional["selected_branch"] = "else"
    elif corruption == "forged_result":
        conditional["evaluation"] = {"status": "known", "satisfied": False}
    elif corruption == "wrong_method":
        conditional["method_rva"] = 0xB98070
    elif corruption == "bad_limit_kind":
        conditional["limit"] = _branch("or", True)
    elif corruption == "bad_then_kind":
        conditional["then"] = _leaf(True)
    elif corruption == "bad_else_kind":
        conditional["else"] = _leaf(False)
    elif corruption == "missing_branch":
        del conditional["else"]
    else:
        conditional["children"] = []

    normalized = _normalized_if(conditional)

    assert normalized == {
        "status": "unknown", "reason": "MISSION_TRIGGER_TREE_INVALID",
    }


def test_project_preserves_if_branches_strips_native_details_and_counts_every_branch_leaf():
    limit = _branch("and", True)
    then = _group("and", [
        _leaf(True, metric={
            "label": "safe then metadata",
            "method_rva": 0xC154B0,
            "native_pointer": _address("0x0000000141002000"),
            "rawreads": [{"address": "0xA00000"}],
        }),
        _leaf(False),
    ])
    else_branch = _group("and", [
        _leaf(False),
        _leaf(True, extra={"rawreads": [{"address": "0xA00008"}]}),
    ])
    conditional = _if_node(limit, then, else_branch)
    state = _normalized_state([_task(tree=_group("and", [conditional]))])

    result = project_progress(
        state, [{"root_id": "loaded", "task_id": "task_a"}], "1.37.4",
    )

    assert result["status"] == "known"
    value = result["value"]
    public_if = value["tasks"][0]["trigger"]["children"][0]
    assert public_if["kind"] == "if"
    assert public_if["selected_branch"] == "then"
    assert all(key in public_if for key in ("limit", "then", "else"))
    assert "children" not in public_if
    assert value["evaluated_leaf_count"] == 5
    assert value["satisfied_leaf_count"] == 3
    assert value["unsatisfied_leaf_count"] == 2
    assert value["unknown_leaf_count"] == 0
    assert "percentage" not in value
    public_text = str(value)
    for private_name in ("native_pointer", "method_rva", "rawreads", "_compare"):
        assert private_name not in public_text
    assert public_if["then"]["children"][0]["metric"]["label"] == "safe then metadata"


def test_public_budget_applies_to_inactive_if_branches():
    conditional = _if_node(
        _branch("and", True),
        _branch("and", True),
        _group("and", [_leaf(False, metric={"text": "x" * MAX_PUBLIC_JSON_BYTES})]),
    )
    state = _normalized_state([_task(tree=_group("and", [conditional]))])

    result = project_progress(
        state, [{"root_id": "loaded", "task_id": "task_a"}], "1.37.4",
    )

    assert result == {
        "status": "unknown", "reason": "MISSION_TRIGGER_PUBLIC_BUDGET_EXCEEDED",
    }


def test_progress_keeps_selected_task_order_for_conditional_trees():
    rows = [
        _task("first", _group("and", [
            _if_node(_branch("and", True), _branch("and", True), _branch("and", False)),
        ])),
        _task("second", _group("and", [
            _if_node(_branch("and", False), _branch("and", True), _branch("and", False)),
        ])),
    ]
    state = _normalized_state(rows)

    result = project_progress(state, [
        {"root_id": "loaded", "task_id": "second"},
        {"root_id": "loaded", "task_id": "first"},
    ], "1.37.4")

    assert result["status"] == "known"
    assert [row["task_id"] for row in result["value"]["tasks"]] == ["second", "first"]


def test_unknown_nonconvergent_if_cannot_make_mission_eligibility_true():
    conditional = _if_node(
        _unknown_limit(),
        _branch("and", True),
        _branch("and", False),
    )
    state = _normalized_state(
        [_task(tree=_group("and", [conditional]))],
        condition_rows=[{
            "root_id": "loaded",
            "task_id": "task_a",
            "task_completed": False,
            "prerequisites_satisfied": True,
        }],
        condition_status="known",
    )

    result = project_eligibility(
        state, [{"root_id": "loaded", "task_id": "task_a"}], "1.37.4",
    )

    assert result["status"] == "known"
    row = result["value"]["tasks"][0]
    assert row["status"] == "unknown"
    assert row["currently_completable"] is None
    assert row["reason"] == "TASK_TRIGGER_NOT_EVALUATED"
    assert row["checks"]["task_trigger"] == {"status": "unknown", "satisfied": None}
    assert result["value"]["known_true_count"] == 0
