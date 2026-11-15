"""Validation and public projection tests for loaded mission trigger trees."""

from copy import deepcopy

import pytest

from bridge.information.mission_trigger_memory import (
    AND_EVALUATE_RVA,
    EXPLORER_EVALUATE_RVA,
    NOR_EVALUATE_RVA,
    OR_EVALUATE_RVA,
    SAILORS_EVALUATE_RVA,
)
from bridge.information.mission_trigger_profile import PROFILE_SHA256
from bridge.information.mission_trigger_source import (
    MAX_PUBLIC_JSON_BYTES,
    MAX_TOTAL_NODES,
    normalize_triggers,
    project_progress,
    trigger_results,
)


def _address(address="0x0000000141001000"):
    return {"va": address, "rva": "0x1000", "rva_identity": "module_relative_candidate"}


def _leaf(value, *, kind="leaf", token=0x33F0, method=SAILORS_EVALUATE_RVA,
          metric=None, extra=None):
    node = {
        "kind": kind,
        "token": token,
        "method_rva": method,
        "native_pointer": _address(),
        "evaluation": {
            "status": "unknown" if value is None else "known",
            "satisfied": value,
        },
    }
    if metric is not None:
        node["metric"] = metric
    if extra:
        node.update(extra)
    if kind == "unsupported":
        node["evaluation"] = {"status": "unknown", "satisfied": None, "reason": "unsupported_method"}
    return node


def _group(kind, children, *, token=0x2F4D, method=None):
    methods = {"and": AND_EVALUATE_RVA, "or": OR_EVALUATE_RVA, "nor": NOR_EVALUATE_RVA}
    if method is None:
        method = methods[kind]
    values = [child["evaluation"]["satisfied"] for child in children]
    if kind == "and":
        value = False if False in values else True if all(item is True for item in values) else None
    elif kind == "or":
        value = True if True in values else False if all(item is False for item in values) else None
    else:
        value = False if True in values else True if all(item is False for item in values) else None
    return {
        "kind": kind,
        "token": token,
        "method_rva": method,
        "native_pointer": _address(),
        "children": children,
        "evaluation": {"status": "unknown" if value is None else "known", "satisfied": value},
    }


def _task(task_id="task_a", tree=None, root_id="loaded"):
    return {"root_id": root_id, "task_id": task_id,
            "tree": _group("and", []) if tree is None else tree}


def _report(rows, *, include=True, consistent=True, profile=PROFILE_SHA256,
            closed=True, complete=True, status="observed"):
    return {
        "request": {"include_triggers": include},
        "doublepass": {"trigger_consistent": consistent},
        "trigger_profile_sha256": profile,
        "cleanup": {"handle_close": {"closed": closed}},
        "mission_triggers": {"status": status, "complete": complete, "tasks": rows},
    }


def _prerequisites(*task_ids):
    return {"status": "known", "tasks": [
        {"root_id": "loaded", "task_id": task_id} for task_id in task_ids
    ]}


def _normalized_state(rows, *, condition_rows=None, condition_status="unknown"):
    conditions = {"status": condition_status, "reason": "CONDITIONS_NOT_CAPTURED"}
    if condition_status == "known":
        conditions = {
            "status": "known",
            "canonical_pointer_keys_verified": True,
            "tasks": condition_rows or [],
        }
    return {
        "mission_triggers": {
            "status": "known",
            "tasks": deepcopy(rows),
            "profile_sha256": PROFILE_SHA256,
            "loaded_trigger_binding_verified": True,
        },
        "mission_conditions": conditions,
    }


@pytest.mark.parametrize("corruption", [
    "request", "doublepass", "profile", "cleanup", "status", "complete", "prerequisites",
])
def test_normalizer_requires_capture_profile_doublepass_cleanup_and_loaded_binding(corruption):
    report = _report([_task()])
    prerequisites = _prerequisites("task_a")
    if corruption == "request":
        report["request"]["include_triggers"] = False
    elif corruption == "doublepass":
        report["doublepass"]["trigger_consistent"] = False
    elif corruption == "profile":
        report["trigger_profile_sha256"] = "0" * 64
    elif corruption == "cleanup":
        report["cleanup"]["handle_close"]["closed"] = False
    elif corruption == "status":
        report["mission_triggers"]["status"] = "unknown"
    elif corruption == "complete":
        report["mission_triggers"]["complete"] = False
    else:
        prerequisites["status"] = "unknown"

    assert normalize_triggers(report, prerequisites) == {
        "status": "unknown", "reason": "MISSION_TRIGGERS_NOT_VERIFIED",
    }


@pytest.mark.parametrize("bad_rows", [
    [],
    [_task("task_b")],
    [_task("task_a"), _task("task_a")],
])
def test_normalizer_rejects_missing_reordered_or_extra_tasks(bad_rows):
    prerequisites = _prerequisites("task_a")
    assert normalize_triggers(_report(bad_rows), prerequisites)["status"] == "unknown"


def test_normalizer_rejects_task_order_that_differs_from_loaded_prerequisites():
    report = _report([_task("task_b"), _task("task_a")])
    prerequisites = _prerequisites("task_a", "task_b")
    assert normalize_triggers(report, prerequisites)["status"] == "unknown"


def test_normalizer_accepts_loaded_task_order_and_recomputes_three_state_logic():
    unknown = _leaf(None, kind="unsupported", method=0x123456)
    false_leaf = _leaf(False)
    true_leaf = _leaf(True)
    nor_true = _group("nor", [_group("or", [false_leaf, unknown])])
    # A NOR group is none-of its children.  A false child and an unknown child
    # leave its result unknown, and the root AND is unknown even though one
    # sibling is true.
    root = _group("and", [nor_true, true_leaf])
    report = _report([_task("task_a", root)])

    normalized = normalize_triggers(report, _prerequisites("task_a"))

    assert normalized["status"] == "known"
    assert normalized["profile_sha256"] == PROFILE_SHA256
    assert normalized["loaded_trigger_binding_verified"] is True
    assert normalized["tasks"][0]["tree"]["evaluation"] == {"status": "unknown", "satisfied": None}
    assert normalized["tasks"][0]["tree"]["children"][0]["kind"] == "nor"


@pytest.mark.parametrize(("kind", "children", "expected"), [
    ("nor", [], True),
    ("nor", [_leaf(False)], True),
    ("nor", [_leaf(True)], False),
    ("nor", [_leaf(None, kind="unsupported", method=0x123456)], None),
])
def test_normalizer_uses_none_of_nor_and_its_three_state_empty_identity(kind, children, expected):
    report = _report([_task(tree=_group("and", [_group(kind, children)]))])

    normalized = normalize_triggers(report, _prerequisites("task_a"))

    assert normalized["status"] == "known"
    assert normalized["tasks"][0]["tree"]["children"][0]["evaluation"] == {
        "status": "unknown" if expected is None else "known",
        "satisfied": expected,
    }


def test_empty_and_and_or_have_native_logical_identities():
    and_root = normalize_triggers(_report([_task(tree=_group("and", []))]),
                                  _prerequisites("task_a"))
    or_child = _group("or", [])
    nor_child = _group("nor", [])
    nested = normalize_triggers(_report([_task(tree=_group("and", [or_child, nor_child]))]),
                               _prerequisites("task_a"))

    assert and_root["tasks"][0]["tree"]["evaluation"] == {"status": "known", "satisfied": True}
    assert nested["tasks"][0]["tree"]["children"][0]["evaluation"] == {
        "status": "known", "satisfied": False,
    }
    assert nested["tasks"][0]["tree"]["children"][1]["evaluation"] == {
        "status": "known", "satisfied": True,
    }


@pytest.mark.parametrize("corruption", [
    "known_int", "unknown_bool", "unsupported_known", "wrong_logic_value",
    "root_not_and", "method_mismatch", "bad_pointer", "leaf_children",
])
def test_normalizer_rejects_malformed_tree_shapes_and_declared_results(corruption):
    tree = _group("and", [_leaf(True)])
    if corruption == "known_int":
        tree["children"][0]["evaluation"] = {"status": "known", "satisfied": 1}
    elif corruption == "unknown_bool":
        tree["children"][0]["evaluation"] = {"status": "unknown", "satisfied": False}
    elif corruption == "unsupported_known":
        tree["children"][0] = _leaf(True, kind="unsupported", method=0x123456)
    elif corruption == "wrong_logic_value":
        tree["evaluation"] = {"status": "known", "satisfied": False}
    elif corruption == "root_not_and":
        tree = _group("or", [_leaf(False)])
    elif corruption == "method_mismatch":
        tree["children"][0]["method_rva"] = OR_EVALUATE_RVA
    elif corruption == "bad_pointer":
        tree["children"][0]["native_pointer"] = {"va": "not-an-address"}
    else:
        tree["children"][0]["children"] = []

    result = normalize_triggers(_report([_task(tree=tree)]), _prerequisites("task_a"))
    assert result["status"] == "unknown"


def _nested_and(depth):
    node = _leaf(True)
    for _ in range(depth):
        node = _group("and", [node])
    return node


def test_normalizer_enforces_tree_depth_and_total_node_budgets():
    at_limit = normalize_triggers(
        _report([_task(tree=_nested_and(32))]), _prerequisites("task_a"),
    )
    too_deep = normalize_triggers(
        _report([_task(tree=_nested_and(33))]), _prerequisites("task_a"),
    )
    flat_over_limit = _group("and", [_leaf(True) for _ in range(MAX_TOTAL_NODES)])
    too_many = normalize_triggers(
        _report([_task(tree=flat_over_limit)]), _prerequisites("task_a"),
    )

    assert at_limit["status"] == "known"
    assert too_deep["status"] == "unknown"
    assert too_many["status"] == "unknown"


def test_project_selects_only_loaded_entries_and_keeps_condition_checks_separate():
    rows = [_task("first", _group("and", [_leaf(True)])),
            _task("second", _group("and", [_leaf(False)]))]
    conditions = [
        {"root_id": "loaded", "task_id": "first", "task_completed": True,
         "prerequisites_satisfied": False},
        {"root_id": "loaded", "task_id": "second", "task_completed": False,
         "prerequisites_satisfied": True},
    ]
    state = _normalized_state(rows, condition_rows=conditions, condition_status="known")

    result = project_progress(
        state, [{"root_id": "loaded", "task_id": "second"}], "1.37.4",
    )

    assert result["status"] == "known"
    assert result["complete"] is False
    assert result["value_origin"] == "loaded_native_trigger_tree_partial"
    assert result["task_trigger_complete"] is False
    assert result["value"]["task_count"] == 1
    assert result["value"]["tasks"][0]["checks"] == {
        "already_completed": False, "prerequisites_satisfied": True,
    }
    assert result["value"]["tasks"][0]["task_id"] == "second"
    assert "percentage" not in result["value"]
    assert "native_pointer" not in str(result["value"]["tasks"][0]["trigger"])
    assert "method_rva" not in str(result["value"]["tasks"][0]["trigger"])


def test_project_leaves_checks_unknown_without_condition_capture_and_counts_only_leaf_nodes():
    tree = _group("and", [
        _leaf(True, metric={"threshold": 1000, "unit": "ratio_milli"},
              extra={"condition_name": "sailor_percentage", "labeltoken": 0x33F0}),
        _leaf(False, token=0x2B60, method=EXPLORER_EVALUATE_RVA),
        _leaf(None, kind="unsupported", token=None, method=0x123456),
        _group("or", [], token=0x296C),
    ])
    state = _normalized_state([_task(tree=tree)])

    result = project_progress(
        state, [{"root_id": "loaded", "task_id": "task_a"}], "1.37.4",
    )

    value = result["value"]
    assert value["tasks"][0]["checks"] == {
        "already_completed": None, "prerequisites_satisfied": None,
    }
    assert value["evaluated_leaf_count"] == 2
    assert value["satisfied_leaf_count"] == 1
    assert value["unsatisfied_leaf_count"] == 1
    assert value["unknown_leaf_count"] == 1
    public_tree = value["tasks"][0]["trigger"]
    assert public_tree["children"][0]["condition_name"] == "sailor_percentage"
    assert public_tree["children"][0]["labeltoken"] == 0x33F0
    assert public_tree["children"][0]["metric"]["unit"] == "ratio_milli"
    assert "native_pointer" not in str(public_tree)
    assert "method_rva" not in str(public_tree)


@pytest.mark.parametrize("state", [
    {},
    {"mission_triggers": {"status": "unknown", "reason": "NO_CAPTURE"}},
    {"mission_triggers": {"status": "known", "loaded_trigger_binding_verified": False}},
])
def test_project_refuses_absent_unknown_or_unbound_trigger_capture_without_static_fallback(state):
    result = project_progress(
        state,
        [{"root_id": "loaded", "task_id": "task_a", "declared_trigger": _group("and", [_leaf(True)])}],
        "1.37.4",
    )
    assert result["status"] == "unknown"
    assert "value" not in result


def test_project_rejects_unselected_outside_capture_and_output_over_budget():
    state = _normalized_state([_task()])
    outside = project_progress(state, [{"root_id": "disk", "task_id": "task_a"}], "1.37.4")
    huge_tree = _group("and", [_leaf(True, metric={"text": "x" * MAX_PUBLIC_JSON_BYTES})])
    over_budget = project_progress(
        _normalized_state([_task(tree=huge_tree)]),
        [{"root_id": "loaded", "task_id": "task_a"}],
        "1.37.4",
    )

    assert outside["status"] == "unknown"
    assert over_budget == {
        "status": "unknown", "reason": "MISSION_TRIGGER_PUBLIC_BUDGET_EXCEEDED",
    }


def test_project_is_limited_to_live_1374():
    result = project_progress(_normalized_state([_task()]), [], "1.36.2")
    assert result == {"status": "unknown", "reason": "MISSION_TRIGGER_VERSION_UNSUPPORTED"}


def test_trigger_results_requires_verified_binding_and_rejects_duplicate_or_bad_trees():
    good_tree = _group("and", [_leaf(True)])
    state = _normalized_state([_task(tree=good_tree)])
    assert trigger_results(state) == {
        ("loaded", "task_a"): {"status": "known", "satisfied": True},
    }

    state["mission_triggers"]["loaded_trigger_binding_verified"] = False
    assert trigger_results(state) == {}
    state["mission_triggers"]["loaded_trigger_binding_verified"] = True
    state["mission_triggers"]["tasks"].append(_task(tree=good_tree))
    assert trigger_results(state) == {}

