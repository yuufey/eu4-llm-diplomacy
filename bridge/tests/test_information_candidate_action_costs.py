"""Purpose-neutral action inspection core compatibility checks."""
from copy import deepcopy
import re

import pytest

from bridge.information.candidate_action_costs import inspect_plans, normalize_plans
from bridge.information.model import InformationError


WAR_PARAMETERS = {
    "casus_belli": "no_casus_belli",
    "war_goal": {"province_id": -1, "beneficiary": "FRA"},
    "call_allies": [],
}


def _plan(plan_id):
    return {
        "id": plan_id,
        "actions": [{
            "id": "action-one",
            "action_id": "declare_war",
            "recipient": "ENG",
            "parameters": deepcopy(WAR_PARAMETERS),
        }],
    }


def test_extended_plan_id_pattern_and_shared_inspection_are_caller_neutral():
    long_id = "s" + "x" * 127
    source = [_plan(long_id), _plan("scenario-two")]

    with pytest.raises(InformationError):
        normalize_plans([source[0]], "FRA")

    normalized = normalize_plans(
        source,
        "FRA",
        plan_id_pattern=re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}"),
    )
    calls = []

    def inspector(action_id, actor, recipient, phase, parameters):
        calls.append((action_id, actor, recipient, phase, deepcopy(parameters)))
        return None

    result = inspect_plans(
        inspector,
        normalized,
        "FRA",
        {"game_date": 56501040},
    )

    assert [plan["id"] for plan in result["plans"]] == [long_id, "scenario-two"]
    assert result["inspector_calls"] == 1
    assert result["shared_result_hits"] == 1
    assert len(calls) == 1
    assert [plan["actions"][0]["costs"]["reason"] for plan in result["plans"]] == [
        "CANDIDATE_INSPECTION_UNAVAILABLE",
        "CANDIDATE_INSPECTION_UNAVAILABLE",
    ]
    assert "selector" not in result and "task_association" not in result
