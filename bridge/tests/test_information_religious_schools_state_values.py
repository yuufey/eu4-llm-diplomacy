from copy import deepcopy

import pytest

from bridge.information import religious_schools_state_values as values
from bridge.information import religious_schools_values as parent_values


def _unknown(reason):
    return {"status": "unknown", "reason": reason}


def _payload():
    return {
        "has_school": True,
        "religion_key": "catholic",
        "religion_group_key": "christian",
        "current_school": {"status": "known", "key": "shafi"},
        "uses_schools": _unknown("RELIGIOUS_SCHOOLS_THREAD_GATE_UNRESOLVED"),
        "invited_scholars": _unknown("INVITED_SCHOLARS_NOT_READ"),
        "relations": _unknown("SCHOOL_RELATIONS_NOT_READ"),
    }


@pytest.mark.parametrize("known", [True, False])
def test_public_value_accepts_exact_native_activation_boolean(known):
    source = _payload()
    source["uses_schools"] = {"status": "known", "value": known}

    result = values.public_value(source, "POR")

    assert result == source
    assert result["uses_schools"] == {"status": "known", "value": known}
    assert result["invited_scholars"] == _unknown("INVITED_SCHOLARS_NOT_READ")
    assert result["relations"] == _unknown("SCHOOL_RELATIONS_NOT_READ")


@pytest.mark.parametrize("reason", sorted(values.UNKNOWN_REASONS))
def test_public_value_accepts_only_declared_activation_unknown_reasons(reason):
    source = _payload()
    source["uses_schools"] = _unknown(reason)

    assert values.public_value(source, "POR")["uses_schools"] == _unknown(reason)


@pytest.mark.parametrize(
    "activation",
    [
        {"status": "known", "value": 1},
        {"status": "known", "value": True, "address": "0x12345678"},
        {"status": "unknown", "reason": "UNRECOGNIZED_REASON"},
        {"status": "unknown", "reason": "RELIGIOUS_SCHOOLS_ACTIVATION_CHANGED",
         "pointer": "0x12345678"},
        {"status": "unknown", "reason": "RELIGIOUS_SCHOOLS_ACTIVATION_UNAVAILABLE",
         "value": False},
        {"status": "none", "reason": "NATIVE_SCHOOL_SENTINEL"},
        None,
    ],
)
def test_public_value_rejects_forged_or_inexact_activation_projection(activation):
    source = _payload()
    source["uses_schools"] = deepcopy(activation)

    with pytest.raises(ValueError, match=(
            "SCHOOL_ACTIVATION_SHAPE|SCHOOL_ACTIVATION_BOOLEAN|SCHOOL_ACTIVATION_UNKNOWN")):
        values.public_value(source, "POR")


def test_public_value_keeps_parent_scholar_and_relation_rules():
    source = _payload()
    source["invited_scholars"] = {"status": "known", "value": []}

    with pytest.raises(ValueError, match="SCHOOL_UNPROVEN_STATE"):
        values.public_value(source, "POR")


def test_public_value_returns_a_deep_copy_of_activation_and_parent_identity():
    source = _payload()
    source["uses_schools"] = {"status": "known", "value": True}

    result = values.public_value(source, "POR")
    result["uses_schools"]["value"] = False
    result["current_school"]["key"] = "mutated"

    assert source["uses_schools"]["value"] is True
    assert source["current_school"]["key"] == "shafi"

