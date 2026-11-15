"""Candidate costs reuse selected, read-only diplomatic action previews."""
from copy import deepcopy

import pytest

from bridge.diplomacy import ObserverSession
from bridge.information.mission_candidate_costs import (
    MAX_ACTIONS,
    MAX_INPUT_BYTES,
    MAX_PLANS,
    MissionCandidateCostReader,
    normalize_plans,
    project_inspection,
)
import bridge.peace_execution as peace_execution


DATE_RAW = 56501040
SELECTOR = {"root_id": "root_main", "task_id": "task_core"}
WAR_PARAMETERS = {
    "casus_belli": "no_casus_belli",
    "war_goal": {"province_id": -1, "beneficiary": "FRA"},
    "call_allies": [],
}
PEACE_PARAMETERS = {
    "peace_context": {
        "war_id": "war_0123456789abcdef_01234567",
        "direction": "demand",
        "terms": [{
            "action_id": "cede_province",
            "province_ids": [183],
            "beneficiary": "FRA",
        }],
    },
}


def _war_action(action_id="war-action", recipient="ENG", parameters=None):
    return {
        "id": action_id,
        "action_id": "declare_war",
        "recipient": recipient,
        "parameters": deepcopy(WAR_PARAMETERS if parameters is None else parameters),
    }


def _peace_action(action_id="peace-action", recipient="ENG", parameters=None):
    return {
        "id": action_id,
        "action_id": "cede_province",
        "recipient": recipient,
        "parameters": deepcopy(PEACE_PARAMETERS if parameters is None else parameters),
    }


def _plan(plan_id="plan-one", *actions):
    return {"id": plan_id, "actions": list(actions) or [_war_action()]}


def _context():
    return {"session_id": "candidate-session", "game_date": DATE_RAW}


def _normalized_war_action():
    return normalize_plans([_plan("plan-one", _war_action())], "FRA")[0]["actions"][0]


def _normalized_peace_action():
    return normalize_plans([_plan("plan-one", _peace_action())], "FRA")[0]["actions"][0]


def _public_cost_item(resource, raw, **changes):
    item = {
        "resource": resource,
        "amount_raw": raw,
        "native_raw": raw,
        "amount": raw / 1000,
        "scale": 1000,
        "unit": resource,
        "unit_verified": True,
        "scale_verified": True,
        "source": "native_rule",
        "complete": True,
    }
    item.update(changes)
    return item


def _public_war_inspection(action, *, actor="FRA", date_raw=DATE_RAW, items=None):
    """Minimal public QUERY3 shape used by the declare-war tool tests."""
    params = deepcopy(action["parameters"])
    return {
        "family": "declare_war",
        "action_id": "declare_war",
        "actor": actor,
        "recipient": action["recipient"],
        "phase": "initiate",
        "submitted": False,
        "session": {"status": "ready", "date_raw": date_raw},
        "selection_requested": True,
        "selection_matched": True,
        "selection_match_count": 1,
        "requested_casus_belli": params["casus_belli"],
        "requested_province_id": params["war_goal"]["province_id"],
        "requested_beneficiary": params["war_goal"]["beneficiary"],
        "parameters": {"requested": deepcopy(params), "actual": params, "complete": True},
        "costs": {
            "status": "partial",
            "complete": False,
            "context": "selected_parameters",
            "items": deepcopy(items if items is not None else [
                _public_cost_item("stability_loss", 0),
                _public_cost_item("war_exhaustion", 1500),
            ]),
        },
    }


def _public_peace_inspection(action, *, peace_context=None, date_raw=DATE_RAW):
    """Minimal public cede-province inspection; absent previews stay absent."""
    return {
        "action_id": "cede_province",
        "actor": "FRA",
        "recipient": action["recipient"],
        "phase": "initiate",
        "submitted": False,
        "session": {"status": "ready", "date_raw": date_raw},
        "peace_context": deepcopy(
            action["parameters"]["peace_context"] if peace_context is None else peace_context
        ),
    }


def test_declare_war_uses_pure_observer_normalizer_and_requires_explicit_selection(monkeypatch):
    original = ObserverSession._normalize_declare_war_parameters
    calls = []

    def spy(parameters, *, actor, recipient):
        calls.append((deepcopy(parameters), actor, recipient))
        return original(parameters, actor=actor, recipient=recipient)

    monkeypatch.setattr(ObserverSession, "_normalize_declare_war_parameters", spy)
    normalized = normalize_plans([_plan("p", _war_action())], "FRA")

    assert calls == [(WAR_PARAMETERS, "FRA", "ENG")]
    assert normalized[0]["actions"][0]["parameters"] == WAR_PARAMETERS

    with pytest.raises(Exception) as error:
        normalize_plans([_plan("empty", _war_action(parameters={}))], "FRA")
    assert getattr(error.value, "code", None) == "invalid_parameters"
    assert calls[-1] == ({}, "FRA", "ENG")


def test_cede_province_uses_exact_peace_execution_normalizer(monkeypatch):
    original = peace_execution.normalize_peace_execution_parameters
    calls = []

    def spy(action_id, actor, recipient, phase, parameters):
        calls.append((action_id, actor, recipient, phase, deepcopy(parameters)))
        return original(action_id, actor, recipient, phase, parameters)

    monkeypatch.setattr(peace_execution, "normalize_peace_execution_parameters", spy)
    normalized = normalize_plans([_plan("p", _peace_action())], "FRA")

    assert calls == [("cede_province", "FRA", "ENG", "initiate", PEACE_PARAMETERS)]
    assert normalized[0]["actions"][0]["parameters"] == original(
        "cede_province", "FRA", "ENG", "initiate", PEACE_PARAMETERS,
    )
    assert normalized[0]["actions"][0]["parameters"]["peace_context"]["terms"][0]["action_id"] == "cede_province"


def test_plan_action_limits_admit_eight_plans_and_sixteen_actions():
    plans = [
        _plan(f"plan-{index}", _war_action("war-a"), _war_action("war-b"))
        for index in range(MAX_PLANS)
    ]

    normalized = normalize_plans(plans, "FRA")

    assert len(normalized) == MAX_PLANS
    assert sum(len(plan["actions"]) for plan in normalized) == MAX_ACTIONS


def test_plan_size_limits_and_bad_ids_or_targets_fail_before_action_normalization(monkeypatch):
    calls = []
    original = ObserverSession._normalize_declare_war_parameters

    def spy(parameters, *, actor, recipient):
        calls.append((deepcopy(parameters), actor, recipient))
        return original(parameters, actor=actor, recipient=recipient)

    monkeypatch.setattr(ObserverSession, "_normalize_declare_war_parameters", spy)

    with pytest.raises(Exception):
        normalize_plans([_plan(f"plan-{index}") for index in range(MAX_PLANS + 1)], "FRA")
    assert calls == []

    over_action_limit = _plan("many", *[
        _war_action(f"action-{index}") for index in range(MAX_ACTIONS + 1)
    ])
    with pytest.raises(Exception):
        normalize_plans([over_action_limit], "FRA")
    assert calls == []

    oversized = _plan("large", _war_action(parameters={"blob": "x" * MAX_INPUT_BYTES}))
    with pytest.raises(Exception):
        normalize_plans([oversized], "FRA")
    assert calls == []

    duplicate_plan_ids = [_plan("duplicate"), _plan("duplicate", _war_action("next"))]
    with pytest.raises(Exception):
        normalize_plans(duplicate_plan_ids, "FRA")

    duplicate_action_ids = [_plan("p", _war_action("same"), _war_action("same"))]
    with pytest.raises(Exception):
        normalize_plans(duplicate_action_ids, "FRA")

    before_foreign_target = len(calls)
    with pytest.raises(Exception):
        normalize_plans([_plan("foreign", _war_action("self", recipient="FRA"))], "FRA")
    assert len(calls) == before_foreign_target


def test_public_inspections_preserve_cost_units_zero_and_do_not_sum_future_costs():
    war = _normalized_war_action()
    peace = _normalized_peace_action()
    plan = {"id": "plan", "actions": [war, peace]}
    calls = []

    def inspector(action_id, actor, recipient, phase, parameters):
        calls.append((action_id, actor, recipient, phase, deepcopy(parameters)))
        selected = next(action for action in (war, peace)
                        if action["action_id"] == action_id and action["recipient"] == recipient)
        if action_id == "declare_war":
            return _public_war_inspection(selected, actor=actor)
        return _public_peace_inspection(selected)

    result = MissionCandidateCostReader(inspector).read([plan], "FRA", _context(), SELECTOR)

    assert len(calls) == 2
    assert calls == [
        ("declare_war", "FRA", "ENG", "initiate", war["parameters"]),
        ("cede_province", "FRA", "ENG", "initiate", peace["parameters"]),
    ]
    value = result["value"]
    assert value["selector"] == SELECTOR
    assert value["sequencing"] == "independent_previews_at_current_state"
    war_result = value["plans"][0]["actions"][0]["costs"]
    assert war_result["status"] == "known"
    assert war_result["submitted"] is False
    assert [(item["resource"], item["amount_raw"], item["scale"], item["unit"],
             item["amount"], item["amount_decimal"]) for item in war_result["items"]] == [
        ("stability_loss", 0, 1000, "stability_loss", 0.0, "0.000"),
        ("war_exhaustion", 1500, 1000, "war_exhaustion", 1.5, "1.500"),
    ]
    plan_result = value["plans"][0]
    assert plan_result["total_cost"] == {
        "status": "unknown", "reason": "CROSS_ACTION_TOTAL_NOT_EVALUATED", "complete": False,
    }
    peace_result = plan_result["actions"][1]["costs"]
    assert peace_result["status"] == "known" and peace_result["submitted"] is False
    assert peace_result["items"] == []
    assert peace_result["preview_fields"]["P02"]["war_score_cost"]["status"] == "unknown"
    assert peace_result["preview_fields"]["P02"]["war_score_cost"]["reason"] == "FIELD_NOT_PRESENT_IN_SOURCE"
    assert all(field["status"] == "unknown"
               for field in peace_result["preview_fields"]["P05"].values())


@pytest.mark.parametrize(("path", "value"), [
    (("action_id",), "insult"),
    (("actor",), "ENG"),
    (("recipient",), "BUR"),
    (("phase",), "query"),
    (("submitted",), True),
    (("session", "status"), "unavailable"),
    (("session", "date_raw"), DATE_RAW + 1),
])
def test_mismatched_public_identity_or_nonquery_session_withholds_cost(path, value):
    action = _normalized_war_action()
    inspected = _public_war_inspection(action)
    target = inspected
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value

    projected = project_inspection(action, "FRA", _context(), inspected)

    assert projected["status"] == "unknown"
    assert projected["reason"] == "CANDIDATE_INSPECTION_IDENTITY_MISMATCH"
    assert "items" not in projected


@pytest.mark.parametrize(("path", "value"), [
    (("selection_requested",), False),
    (("selection_matched",), False),
    (("selection_match_count",), 0),
    (("selection_match_count",), True),
    (("requested_casus_belli",), "other_cb"),
    (("requested_province_id",), 10),
    (("requested_beneficiary",), "ENG"),
    (("parameters", "complete"), False),
    (("parameters", "actual", "casus_belli"), "other_cb"),
    (("parameters", "actual", "war_goal", "province_id"), 10),
])
def test_requested_selection_and_actual_echo_must_all_match(path, value):
    action = _normalized_war_action()
    inspected = _public_war_inspection(action)
    target = inspected
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value

    projected = project_inspection(action, "FRA", _context(), inspected)

    assert projected["status"] == "unknown"
    assert projected["reason"] == "CANDIDATE_DECLARE_WAR_SELECTION_UNVERIFIED"
    assert "items" not in projected


@pytest.mark.parametrize("changes", [
    {"amount_raw": True},
    {"amount_raw": 1 << 31, "native_raw": 1 << 31},
    {"native_raw": True},
    {"unit": "unknown", "unit_verified": False},
    {"unit_verified": False},
    {"scale": 100, "scale_verified": False},
    {"amount": 9.0},
])
def test_invalid_raw_or_unverified_cost_metadata_never_becomes_a_known_amount(changes):
    action = _normalized_war_action()
    inspected = _public_war_inspection(
        action, items=[_public_cost_item("stability_loss", 1000, **changes)],
    )

    projected = project_inspection(action, "FRA", _context(), inspected)

    assert projected["status"] == "unknown"
    assert projected["reason"] == "CANDIDATE_DECLARE_WAR_NO_VERIFIED_COST_ITEMS"


def test_conflicting_duplicate_resource_is_withheld_and_missing_resource_stays_unknown():
    action = _normalized_war_action()
    duplicate = _public_war_inspection(action, items=[
        _public_cost_item("stability_loss", 1000),
        _public_cost_item("stability_loss", 2000),
    ])
    result = project_inspection(action, "FRA", _context(), duplicate)
    assert result["status"] == "unknown"
    assert result["reason"] == "CANDIDATE_DECLARE_WAR_DUPLICATE_COST_RESOURCE"

    one_metric = _public_war_inspection(action, items=[_public_cost_item("stability_loss", 0)])
    partial = project_inspection(action, "FRA", _context(), one_metric)
    assert partial["status"] == "known"
    assert [item["resource"] for item in partial["items"]] == ["stability_loss"]
    assert "war_exhaustion_unverified_or_missing" in partial["unknown_dimensions"]


@pytest.mark.parametrize("changed", [
    {"war_id": "war_fedcba9876543210_76543210"},
    {"direction": "offer"},
])
def test_peace_preview_requires_exact_war_context_identity(changed):
    action = _normalized_peace_action()
    inspected_context = deepcopy(action["parameters"]["peace_context"])
    inspected_context.update(changed)

    projected = project_inspection(
        action, "FRA", _context(), _public_peace_inspection(action, peace_context=inspected_context),
    )

    assert projected["status"] == "unknown"
    assert projected["reason"] == "CANDIDATE_PEACE_SELECTION_UNVERIFIED"


def test_inspector_failure_is_not_retried_or_executed():
    action = _normalized_war_action()
    calls = []

    def failing_inspector(*args):
        calls.append(args)
        raise RuntimeError("read-only inspection failed")

    result = MissionCandidateCostReader(failing_inspector).read(
        [{"id": "plan", "actions": [action]}], "FRA", _context(), SELECTOR,
    )

    assert len(calls) == 1
    projected = result["value"]["plans"][0]["actions"][0]["costs"]
    assert projected == {
        "status": "unknown", "reason": "CANDIDATE_INSPECTION_FAILED", "complete": False,
    }
    assert result["value"]["plans"][0]["actions"][0]["phase"] == "initiate"

