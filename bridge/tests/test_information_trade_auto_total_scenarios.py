from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import trade_province_power_scenarios as scenarios


I32_MIN = -(1 << 31)
I32_MAX = (1 << 31) - 1
POWER_MODEL = "province_source_fixed_other_inputs"
TOTAL_MODEL = "fixed_other_country_power"


def _i32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _baseline(*, total_power: int = 1000) -> dict:
    return {
        "fields": {
            "country_power": {
                "status": "known", "raw": 100, "value": 100,
                "unit": "trade_power", "scale": 1000,
            },
            "total_power": {
                "status": "known", "raw": total_power, "value": total_power,
                "unit": "trade_power", "scale": 1000,
            },
        },
        "native_power_components": {
            "status": "known",
            "value": {
                "multiplier_raw": 1000, "cap_raw": 100, "base_raw": 100,
                "subtract_raw": 0, "add_raw": 0,
            },
            "basis": "native_trade_node_power_caches", "scale": 1000,
            "period": "current", "complete": False,
        },
        "native_power_sum_membership": {
            "status": "known",
            "basis": "native_global_country_power_sum_membership",
            "period": "current",
            "complete": False,
            "value": {
                "observer": "FRA", "country_slot": 20, "member_count": 256,
                "observer_occurrences": 1, "fullref_occurrences": 1,
                "slot_occurrences": 1, "observer_nonplayer_verified": True,
                "canonical_observer_verified": True, "stable": True,
            },
        },
    }


def _auto(scenario_id: str, province_delta: int, **extra) -> dict:
    return {
        "id": scenario_id,
        "power_input_model": POWER_MODEL,
        "province_power_delta_raw": province_delta,
        "total_power_input_model": TOTAL_MODEL,
        **extra,
    }


def _explicit(scenario_id: str, province_delta: int, total_delta: int) -> dict:
    return {
        "id": scenario_id,
        "power_input_model": POWER_MODEL,
        "province_power_delta_raw": province_delta,
        "total_power_delta_raw": total_delta,
    }


def test_manual_and_existing_explicit_total_forms_keep_their_shapes():
    baseline = _baseline()
    manual = {"id": "manual", "country_power_delta_raw": -3,
              "total_power_delta_raw": 7, "description": "kept"}
    explicit = _explicit("explicit", 10, -9)
    result = scenarios.derive_power_scenarios(baseline, [manual, explicit])
    assert result["resolved_scenarios"] == [
        manual,
        {"id": "explicit", "total_power_delta_raw": -9,
         "country_power_delta_raw": 10},
    ]
    assert set(result["transitions"]) == {"explicit"}
    value = result["transitions"]["explicit"]["value"]
    assert value["total_power_delta_raw"] == -9
    assert "total_power_input_model" not in value
    assert "total_power_before_raw" not in value


def test_auto_total_derives_delta_and_does_not_mutate_inputs():
    baseline = _baseline(total_power=1000)
    scenario = _auto("auto", 50, description="keep", actions=[{"kind": "preview"}])
    original_baseline, original_scenario = deepcopy(baseline), deepcopy(scenario)

    result = scenarios.derive_power_scenarios(baseline, [scenario])

    assert result["resolved_scenarios"] == [{
        "id": "auto", "description": "keep", "actions": [{"kind": "preview"}],
        "country_power_delta_raw": 50, "total_power_delta_raw": 50,
    }]
    value = result["transitions"]["auto"]["value"]
    assert value["country_power_delta_raw"] == 50
    assert value["total_power_input_model"] == TOTAL_MODEL
    assert value["total_power_before_raw"] == 1000
    assert value["total_power_after_raw"] == 1050
    assert value["total_power_delta_raw"] == 50
    assert "power_input_model" not in result["resolved_scenarios"][0]
    assert "total_power_input_model" not in result["resolved_scenarios"][0]
    assert "province_power_delta_raw" not in result["resolved_scenarios"][0]
    assert baseline == original_baseline and scenario == original_scenario


@pytest.mark.parametrize(
    ("province_delta", "total_before", "expected_delta", "expected_after"),
    [(0, 77, 0, 77), (-5, 77, -5, 72)],
)
def test_auto_total_supports_zero_and_negative_deltas(
        province_delta, total_before, expected_delta, expected_after):
    result = scenarios.derive_power_scenarios(
        _baseline(total_power=total_before), [_auto("auto", province_delta)]
    )
    transition = result["transitions"]["auto"]
    assert transition["status"] == "known"
    value = transition["value"]
    assert value["total_power_before_raw"] == total_before
    assert value["total_power_after_raw"] == expected_after
    assert value["total_power_delta_raw"] == expected_delta
    assert result["resolved_scenarios"][0]["total_power_delta_raw"] == expected_delta


def test_auto_total_wrap_is_unknown_when_mathematical_delta_leaves_i32():
    result = scenarios.derive_power_scenarios(
        _baseline(total_power=I32_MAX), [_auto("wrap", 1)]
    )
    assert result["resolved_scenarios"] == []
    transition = result["transitions"]["wrap"]
    assert transition["status"] == "unknown"
    assert transition["reason"] == "DERIVED_TOTAL_POWER_DELTA_OUTSIDE_DOMAIN"
    assert transition["game_fact"] is False and transition["complete"] is False


def test_missing_membership_blocks_auto_only():
    baseline = _baseline()
    baseline.pop("native_power_sum_membership")
    result = scenarios.derive_power_scenarios(
        baseline, [_auto("auto", 1), _explicit("explicit", 1, 3)]
    )
    assert result["transitions"]["auto"]["reason"] == "BASELINE_POWER_SUM_MEMBERSHIP_UNKNOWN"
    assert result["transitions"]["explicit"]["status"] == "known"
    assert [item["id"] for item in result["resolved_scenarios"]] == ["explicit"]


@pytest.mark.parametrize(
    "key", ["observer_nonplayer_verified", "canonical_observer_verified"]
)
def test_observer_verification_false_blocks_auto(key):
    baseline = _baseline()
    baseline["native_power_sum_membership"]["value"][key] = False
    result = scenarios.derive_power_scenarios(baseline, [_auto("auto", 1)])
    assert result["transitions"]["auto"]["reason"] == "BASELINE_POWER_SUM_MEMBERSHIP_UNKNOWN"


@pytest.mark.parametrize(
    ("key", "bad_value"),
    [
        ("observer_occurrences", 0), ("observer_occurrences", 2),
        ("fullref_occurrences", 2), ("slot_occurrences", 2),
        ("observer_occurrences", True),
    ],
)
def test_membership_requires_single_typed_occurrences(key, bad_value):
    baseline = _baseline()
    baseline["native_power_sum_membership"]["value"][key] = bad_value
    result = scenarios.derive_power_scenarios(baseline, [_auto("auto", 1)])
    assert result["transitions"]["auto"]["reason"] == "BASELINE_POWER_SUM_MEMBERSHIP_UNKNOWN"


@pytest.mark.parametrize(
    ("key", "bad_value"),
    [
        ("country_slot", -1), ("country_slot", 4096), ("country_slot", True),
        ("member_count", 0), ("member_count", 4097), ("member_count", False),
    ],
)
def test_membership_slot_and_count_require_bounded_nonbool_integers(key, bad_value):
    baseline = _baseline()
    baseline["native_power_sum_membership"]["value"][key] = bad_value
    result = scenarios.derive_power_scenarios(baseline, [_auto("auto", 1)])
    assert result["transitions"]["auto"]["reason"] == "BASELINE_POWER_SUM_MEMBERSHIP_UNKNOWN"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda gate: gate.update(extra=True),
        lambda gate: gate["value"].update(extra=True),
        lambda gate: gate["value"].pop("stable"),
        lambda gate: gate.update(basis="other"),
        lambda gate: gate.update(complete=0),
        lambda gate: gate["value"].update(observer="ENG"),
        lambda gate: gate["value"].update(canonical_observer_verified=1),
    ],
)
def test_membership_rejects_shape_and_typed_flag_drift(mutation):
    baseline = _baseline()
    mutation(baseline["native_power_sum_membership"])
    result = scenarios.derive_power_scenarios(baseline, [_auto("auto", 1)])
    assert result["transitions"]["auto"]["reason"] == "BASELINE_POWER_SUM_MEMBERSHIP_UNKNOWN"


@pytest.mark.parametrize(
    "field", [
        {"status": "unknown", "raw": 10, "value": 10, "unit": "trade_power", "scale": 1000},
        {"status": "known", "raw": 10, "value": 11, "unit": "trade_power", "scale": 1000},
        {"status": "known", "raw": True, "value": True, "unit": "trade_power", "scale": 1000},
        {"status": "known", "raw": 10, "value": 10, "unit": "ducats", "scale": 1000},
        {"status": "known", "raw": 10, "value": 10, "unit": "trade_power", "scale": 1},
    ],
)
def test_invalid_total_baseline_field_blocks_auto(field):
    baseline = _baseline()
    baseline["fields"]["total_power"] = field
    result = scenarios.derive_power_scenarios(baseline, [_auto("auto", 1)])
    assert result["transitions"]["auto"]["reason"] == "BASELINE_TOTAL_POWER_UNKNOWN"


def test_total_auto_model_is_rejected_on_manual_or_unknown_or_mixed_forms():
    baseline = _baseline()
    with pytest.raises(ValueError, match="manual_total_power_input_model_invalid"):
        scenarios.derive_power_scenarios(baseline, [{
            "id": "manual", "country_power_delta_raw": 1,
            "total_power_delta_raw": 1, "total_power_input_model": TOTAL_MODEL,
        }])
    unknown = _auto("unknown", 1)
    unknown["total_power_input_model"] = "other"
    with pytest.raises(ValueError, match="scenario_total_power_input_model_invalid"):
        scenarios.derive_power_scenarios(baseline, [unknown])
    mixed = _auto("mixed", 1, total_power_delta_raw=1)
    with pytest.raises(ValueError, match="scenario_total_power_form_mixed"):
        scenarios.derive_power_scenarios(baseline, [mixed])


def test_manual_explicit_and_auto_siblings_resolve_without_mutation():
    baseline = _baseline()
    siblings = [
        {"id": "manual", "country_power_delta_raw": 1, "total_power_delta_raw": -2},
        _explicit("explicit", 2, 3),
        _auto("auto", 4),
    ]
    original_baseline, original_siblings = deepcopy(baseline), deepcopy(siblings)
    result = scenarios.derive_power_scenarios(baseline, siblings)
    assert [item["id"] for item in result["resolved_scenarios"]] == [
        "manual", "explicit", "auto",
    ]
    assert result["resolved_scenarios"][0] == siblings[0]
    assert result["resolved_scenarios"][1]["total_power_delta_raw"] == 3
    assert result["resolved_scenarios"][2]["total_power_delta_raw"] == 4
    assert set(result["transitions"]) == {"explicit", "auto"}
    assert baseline == original_baseline and siblings == original_siblings

