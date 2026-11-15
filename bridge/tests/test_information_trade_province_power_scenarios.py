from __future__ import annotations

import random

import pytest

from bridge.information import trade_province_power_scenarios as scenarios


I32_MIN = -(1 << 31)
I32_MAX = (1 << 31) - 1
MAGIC_DIV_1000 = 0x20C49BA5E353F7CF
MODEL = "province_source_fixed_other_inputs"


def _i32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _trunc0_div1000_magic(value: int) -> int:
    """Independent signed-high multiply, arithmetic shift and sign correction."""
    high_signed = (value * MAGIC_DIV_1000) >> 64
    floor_quotient = high_signed >> 7
    if value < 0:
        floor_quotient += 1
    return floor_quotient


def _oracle_power(components: dict[str, int]) -> int:
    product = components["0x44"] * components["0x4c"]
    quotient32 = _i32(_trunc0_div1000_magic(product))
    positive32 = quotient32 if quotient32 > 0 else 0
    cap = components["0x48"]
    capped = cap if cap < positive32 else positive32
    delta = _i32(components["0x54"] - components["0x50"])
    return _i32(capped + delta)


def _oracle_refresh(components: dict[str, int]):
    positive = _oracle_power({
        **components,
        "0x48": I32_MAX,
        "0x50": 0,
        "0x54": 0,
    })
    old_power = _oracle_power(components)
    refreshed = old_power <= positive
    cap = positive if refreshed else components["0x48"]
    after_components = {**components, "0x48": cap}
    return after_components, _oracle_power(after_components), refreshed


def _components(multiplier: int, base: int, subtract: int = 0,
                add: int = 0, cap: int | None = None) -> dict[str, int]:
    partial = {"0x44": multiplier, "0x48": I32_MAX, "0x4c": base,
               "0x50": 0, "0x54": 0}
    if cap is None:
        cap = _oracle_power(partial)
    return {"0x44": multiplier, "0x48": cap, "0x4c": base,
            "0x50": subtract, "0x54": add}


def _baseline(components: dict[str, int]) -> dict[str, object]:
    power = _oracle_power(components)
    values = {
        "multiplier_raw": components["0x44"],
        "cap_raw": components["0x48"],
        "base_raw": components["0x4c"],
        "subtract_raw": components["0x50"],
        "add_raw": components["0x54"],
    }
    return {
        "fields": {
            "country_power": {
                "status": "known", "raw": power, "value": power,
                "unit": "trade_power", "scale": 1000,
            }
        },
        "native_power_components": {
            "status": "known", "value": values,
            "basis": "native_trade_node_power_caches", "scale": 1000,
            "period": "current", "complete": False,
        },
    }


def _scenario(scenario_id: str, province_delta: int, total_delta: int = 0, **extra):
    return {
        "id": scenario_id,
        "power_input_model": MODEL,
        "province_power_delta_raw": province_delta,
        "total_power_delta_raw": total_delta,
        **extra,
    }


def test_magic_signed_high_oracle_matches_truncation_boundaries_and_fixed_random_products():
    values = [
        0, 1, -1, 999, -999, 1000, -1000, 1001, -1001,
        I32_MAX * I32_MAX, I32_MIN * I32_MIN,
        I32_MIN * I32_MAX, -I32_MAX * I32_MAX,
    ]
    rng = random.Random(206)
    values.extend(rng.randint(-(1 << 62), (1 << 62) - 1) for _ in range(512))
    for value in values:
        expected = abs(value) // 1000
        if value < 0:
            expected = -expected
        assert _trunc0_div1000_magic(value) == expected


def test_manual_scenarios_are_copied_and_do_not_get_transitions():
    manual = {
        "id": "manual", "country_power_delta_raw": -8,
        "total_power_delta_raw": 4, "description": "keep this",
        "actions": [{"kind": "observe"}],
    }
    baseline = _baseline(_components(1000, 100))
    result = scenarios.derive_power_scenarios(baseline, [manual])
    assert result == {"resolved_scenarios": [manual], "transitions": {}}
    assert result["resolved_scenarios"][0] is not manual


def test_positive_province_delta_refreshes_cap_and_preserves_total_delta():
    baseline = _baseline(_components(1000, 100))
    derived = _scenario("raise-base", 50, 17, description="caller supplied total")
    result = scenarios.derive_power_scenarios(baseline, [derived])
    resolved = result["resolved_scenarios"][0]
    transition = result["transitions"]["raise-base"]
    assert resolved == {
        "id": "raise-base", "total_power_delta_raw": 17,
        "description": "caller supplied total", "country_power_delta_raw": 50,
    }
    assert transition["status"] == "known"
    assert transition["basis"] == "native_country_power_province_source_scenario"
    assert transition["game_fact"] is False and transition["complete"] is False
    value = transition["value"]
    assert value["province_power_delta_raw"] == 50
    assert value["country_power_before_raw"] == 100
    assert value["country_power_after_raw"] == 150
    assert value["country_power_delta_raw"] == 50
    assert value["total_power_delta_raw"] == 17
    assert value["base_before_raw"] == 100 and value["base_after_raw"] == 150
    assert value["cap_before_raw"] == 100 and value["cap_after_raw"] == 150
    assert value["cap_refreshed"] is True
    assert value["power_input_model"] == MODEL


def test_negative_delta_can_keep_existing_cap():
    baseline = _baseline(_components(1000, 100, add=60))
    result = scenarios.derive_power_scenarios(baseline, [_scenario("keep-cap", 0)])
    transition = result["transitions"]["keep-cap"]
    assert transition["status"] == "known"
    assert transition["value"]["country_power_before_raw"] == 160
    assert transition["value"]["country_power_after_raw"] == 160
    assert transition["value"]["cap_before_raw"] == transition["value"]["cap_after_raw"] == 100
    assert transition["value"]["cap_refreshed"] is False


def test_signed_i32_base_addition_wraps_before_recalculation():
    baseline = _baseline(_components(1000, I32_MAX - 1))
    delta = 10
    result = scenarios.derive_power_scenarios(baseline, [_scenario("wrap-base", delta)])
    transition = result["transitions"]["wrap-base"]
    assert transition["status"] == "known"
    assert transition["value"]["base_after_raw"] == _i32((I32_MAX - 1) + delta)
    expected = _oracle_power({
        "0x44": 1000,
        "0x48": transition["value"]["cap_after_raw"],
        "0x4c": _i32((I32_MAX - 1) + delta),
        "0x50": 0,
        "0x54": 0,
    })
    assert transition["value"]["country_power_after_raw"] == expected


@pytest.mark.parametrize(
    ("baseline_factory", "expected_reason"),
    [
        (lambda: None, "BASELINE_COUNTRY_POWER_UNKNOWN"),
        (lambda: _baseline(_components(9, 100)), "BASELINE_MULTIPLIER_BELOW_NATIVE_MIN"),
        (lambda: _baseline(_components(1000, 100, cap=50)), "NATIVE_POWER_BASELINE_NOT_REFRESHED"),
    ],
)
def test_bad_or_unsettled_baseline_only_blocks_new_mode(baseline_factory, expected_reason):
    baseline = baseline_factory()
    if baseline is not None and expected_reason == "BASELINE_COUNTRY_POWER_UNKNOWN":
        baseline["fields"]["country_power"]["raw"] += 1
        baseline["fields"]["country_power"]["value"] += 1
    manual = {"id": "manual", "country_power_delta_raw": 3, "total_power_delta_raw": 4}
    derived = _scenario("new", 2, 5)
    result = scenarios.derive_power_scenarios(baseline, [manual, derived])
    assert result["resolved_scenarios"] == [manual]
    assert result["transitions"]["new"]["status"] == "unknown"
    assert result["transitions"]["new"]["reason"] == expected_reason
    assert result["transitions"]["new"]["game_fact"] is False
    assert result["transitions"]["new"]["complete"] is False


def test_country_delta_outside_signed_i32_is_unknown_and_not_resolved():
    components = _components(1000, I32_MAX, add=100)
    baseline = _baseline(components)
    result = scenarios.derive_power_scenarios(
        baseline, [_scenario("overflow-delta", -1000, 12)]
    )
    assert result["resolved_scenarios"] == []
    transition = result["transitions"]["overflow-delta"]
    assert transition["status"] == "unknown"
    assert transition["reason"] == "DERIVED_POWER_DELTA_OUTSIDE_DOMAIN"


def test_baseline_power_mismatch_is_unknown():
    baseline = _baseline(_components(1000, 100))
    baseline["fields"]["country_power"]["raw"] += 1
    baseline["fields"]["country_power"]["value"] += 1
    result = scenarios.derive_power_scenarios(baseline, [_scenario("mismatch", 1)])
    assert result["resolved_scenarios"] == []
    assert result["transitions"]["mismatch"]["reason"] == "NATIVE_POWER_BASELINE_MISMATCH"


def test_fixed_random_components_and_deltas_match_independent_oracle():
    rng = random.Random(6206)
    baseline_components = []
    derived_scenarios = []
    expected = {}
    for index in range(512):
        multiplier = rng.randint(10, I32_MAX)
        base = rng.randint(I32_MIN, I32_MAX)
        subtract = rng.randint(I32_MIN, I32_MAX)
        add = rng.randint(I32_MIN, I32_MAX)
        components = _components(multiplier, base, subtract, add)
        baseline_components.append(components)
        delta = rng.randint(-100_000, 100_000)
        total_delta = rng.randint(I32_MIN, I32_MAX)
        scenario_id = f"random-{index}"
        derived_scenarios.append(_scenario(scenario_id, delta, total_delta))
        before = _oracle_power(components)
        base_after = _i32(base + delta)
        after_components = {**components, "0x4c": base_after}
        after_components, after, refreshed = _oracle_refresh(after_components)
        power_delta = after - before
        expected[scenario_id] = (before, after, power_delta, base_after,
                                 after_components["0x48"], refreshed, total_delta)

    for components, scenario in zip(baseline_components, derived_scenarios):
        baseline = _baseline(components)
        result = scenarios.derive_power_scenarios(baseline, [scenario])
        transition = result["transitions"][scenario["id"]]
        before, after, delta, base_after, cap_after, refreshed, total = expected[scenario["id"]]
        if not I32_MIN <= delta <= I32_MAX:
            assert transition["status"] == "unknown"
            assert transition["reason"] == "DERIVED_POWER_DELTA_OUTSIDE_DOMAIN"
            assert result["resolved_scenarios"] == []
            continue
        assert transition["status"] == "known"
        value = transition["value"]
        assert value["country_power_before_raw"] == before
        assert value["country_power_after_raw"] == after
        assert value["country_power_delta_raw"] == delta
        assert value["base_after_raw"] == base_after
        assert value["cap_after_raw"] == cap_after
        assert value["cap_refreshed"] is refreshed
        assert value["total_power_delta_raw"] == total


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("province_power_delta_raw", True),
        ("province_power_delta_raw", 1.0),
        ("province_power_delta_raw", I32_MAX + 1),
        ("total_power_delta_raw", False),
        ("total_power_delta_raw", -1.5),
        ("total_power_delta_raw", I32_MIN - 1),
    ],
)
def test_new_scenario_rejects_bool_float_and_out_of_i32(field, bad_value):
    baseline = _baseline(_components(1000, 100))
    item = _scenario("invalid", 1, 2)
    item[field] = bad_value
    with pytest.raises(ValueError):
        scenarios.derive_power_scenarios(baseline, [item])


def test_duplicate_or_unknown_scenario_model_is_programmer_error():
    baseline = _baseline(_components(1000, 100))
    with pytest.raises(ValueError):
        scenarios.derive_power_scenarios(
            baseline, [_scenario("same", 1), _scenario("same", 2)]
        )
    wrong_model = _scenario("wrong", 1)
    wrong_model["power_input_model"] = "other"
    with pytest.raises(ValueError):
        scenarios.derive_power_scenarios(baseline, [wrong_model])
