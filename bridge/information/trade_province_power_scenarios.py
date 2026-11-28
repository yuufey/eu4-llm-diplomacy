"""Derive country-power changes for fixed-other-input province scenarios.

This pure projection reuses the existing country-power calculator. An optional
total-power model derives the node-total delta only when the baseline proves
the observer's unique membership in the native sum list; neither mode claims a
game outcome.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import re
from typing import Any

from . import trade_power_memory as _trade_power


POWER_INPUT_MODEL = "province_source_fixed_other_inputs"
TOTAL_POWER_INPUT_MODEL = "fixed_other_country_power"
TRANSITION_BASIS = "native_country_power_province_source_scenario"
COMPONENTS_BASIS = "native_trade_node_power_caches"
SCALE = 1000
UNIT = "trade_power"
INT32_MIN = -(1 << 31)
INT32_MAX = (1 << 31) - 1

_VALUE_TO_COMPONENT = {
    "multiplier_raw": "0x44",
    "cap_raw": "0x48",
    "base_raw": "0x4c",
    "subtract_raw": "0x50",
    "add_raw": "0x54",
}
_KNOWN_BASELINE_REASONS = {
    "BASELINE_COUNTRY_POWER_UNKNOWN",
    "BASELINE_POWER_COMPONENTS_UNKNOWN",
    "BASELINE_MULTIPLIER_BELOW_NATIVE_MIN",
    "NATIVE_POWER_BASELINE_MISMATCH",
    "NATIVE_POWER_BASELINE_NOT_REFRESHED",
    "BASELINE_POWER_SUM_MEMBERSHIP_UNKNOWN",
    "BASELINE_TOTAL_POWER_UNKNOWN",
}


def _is_i32(value: Any) -> bool:
    return type(value) is int and INT32_MIN <= value <= INT32_MAX


def _wrap_i32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _unknown(reason: str) -> dict[str, Any]:
    if reason not in _KNOWN_BASELINE_REASONS | {
        "DERIVED_POWER_DELTA_OUTSIDE_DOMAIN",
        "DERIVED_TOTAL_POWER_DELTA_OUTSIDE_DOMAIN",
    }:
        reason = "BASELINE_POWER_COMPONENTS_UNKNOWN"
    return {
        "status": "unknown",
        "basis": TRANSITION_BASIS,
        "game_fact": False,
        "complete": False,
        "reason": reason,
    }


def _validate_scenario(scenario: Any) -> tuple[str, dict[str, Any]]:
    if not isinstance(scenario, Mapping):
        raise ValueError("scenario_invalid")
    scenario_id = scenario.get("id")
    if type(scenario_id) is not str or not scenario_id:
        raise ValueError("scenario_id_invalid")
    model = scenario.get("power_input_model")
    if model is None and "power_input_model" not in scenario:
        if "total_power_input_model" in scenario:
            raise ValueError("manual_total_power_input_model_invalid")
        country_delta = scenario.get("country_power_delta_raw")
        if not _is_i32(country_delta):
            raise ValueError("manual_country_power_delta_invalid")
        if not _is_i32(scenario.get("total_power_delta_raw")):
            raise ValueError("scenario_total_power_delta_invalid")
        return "manual", deepcopy(dict(scenario))
    if model != POWER_INPUT_MODEL:
        raise ValueError("scenario_power_input_model_invalid")

    has_total_delta = "total_power_delta_raw" in scenario
    has_total_model = "total_power_input_model" in scenario
    if has_total_delta and has_total_model:
        raise ValueError("scenario_total_power_form_mixed")
    if has_total_model:
        if (type(scenario.get("total_power_input_model")) is not str
                or scenario.get("total_power_input_model") != TOTAL_POWER_INPUT_MODEL):
            raise ValueError("scenario_total_power_input_model_invalid")
        kind = "automatic_total"
    else:
        if not _is_i32(scenario.get("total_power_delta_raw")):
            raise ValueError("scenario_total_power_delta_invalid")
        kind = "derived"
    allowed = {
        "id", "power_input_model", "province_power_delta_raw",
        "total_power_delta_raw", "total_power_input_model", "description", "actions",
    }
    if set(scenario) - allowed:
        raise ValueError("derived_scenario_fields_invalid")
    province_delta = scenario.get("province_power_delta_raw")
    if not _is_i32(province_delta):
        raise ValueError("scenario_province_power_delta_invalid")
    return kind, deepcopy(dict(scenario))


def _parse_country_power(baseline: Any) -> int | None:
    if not isinstance(baseline, Mapping):
        return None
    fields = baseline.get("fields")
    component = fields.get("country_power") if isinstance(fields, Mapping) else None
    if not isinstance(component, Mapping) or component.get("status") != "known":
        return None
    raw = component.get("raw")
    value = component.get("value")
    if (not _is_i32(raw) or not _is_i32(value) or raw != value
            or component.get("unit") != UNIT or component.get("scale") != SCALE):
        return None
    return raw


def _parse_power_sum_membership(baseline: Any) -> bool:
    if not isinstance(baseline, Mapping):
        return False
    gate = baseline.get("native_power_sum_membership")
    gate_keys = {"status", "basis", "period", "complete", "value"}
    if not isinstance(gate, Mapping) or set(gate) != gate_keys:
        return False
    if (gate.get("status") != "known"
            or gate.get("basis") != "native_global_country_power_sum_membership"
            or gate.get("period") != "current"
            or gate.get("complete") is not False):
        return False
    value = gate.get("value")
    value_keys = {
        "observer", "country_slot", "member_count", "observer_occurrences",
        "fullref_occurrences", "slot_occurrences", "observer_nonplayer_verified",
        "canonical_observer_verified", "stable",
    }
    if not isinstance(value, Mapping) or set(value) != value_keys:
        return False
    observer = value.get("observer")
    source = baseline.get("source")
    if (not isinstance(observer, str) or re.fullmatch(r"[A-Z0-9]{3}", observer) is None
            or not isinstance(source, Mapping) or source.get("observer") != observer):
        return False
    country_slot = value.get("country_slot")
    member_count = value.get("member_count")
    if type(country_slot) is not int or not 0 <= country_slot <= 4095:
        return False
    if type(member_count) is not int or not 1 <= member_count <= 4096:
        return False
    for key in ("observer_occurrences", "fullref_occurrences", "slot_occurrences"):
        if type(value.get(key)) is not int or value.get(key) != 1:
            return False
    if type(value.get("observer_nonplayer_verified")) is not bool:
        return False
    for key in ("canonical_observer_verified", "stable"):
        if type(value.get(key)) is not bool or value.get(key) is not True:
            return False
    return True


def _parse_total_power(baseline: Any) -> int | None:
    if not isinstance(baseline, Mapping):
        return None
    fields = baseline.get("fields")
    field = fields.get("total_power") if isinstance(fields, Mapping) else None
    if not isinstance(field, Mapping) or field.get("status") != "known":
        return None
    raw = field.get("raw")
    value = field.get("value")
    if (not _is_i32(raw) or not _is_i32(value) or raw != value
            or field.get("unit") != UNIT or type(field.get("scale")) is not int
            or field.get("scale") != SCALE):
        return None
    return raw


def _parse_power_components(baseline: Any) -> tuple[dict[str, int] | None, str | None]:
    if not isinstance(baseline, Mapping):
        return None, "BASELINE_POWER_COMPONENTS_UNKNOWN"
    raw = baseline.get("native_power_components")
    if not isinstance(raw, Mapping) or raw.get("status") != "known":
        return None, "BASELINE_POWER_COMPONENTS_UNKNOWN"
    values = raw.get("value")
    if (not isinstance(values, Mapping) or set(values) != set(_VALUE_TO_COMPONENT)
            or raw.get("basis") != COMPONENTS_BASIS or raw.get("scale") != SCALE
            or raw.get("period") != "current" or raw.get("complete") is not False):
        return None, "BASELINE_POWER_COMPONENTS_UNKNOWN"
    components: dict[str, int] = {}
    for value_key, component_key in _VALUE_TO_COMPONENT.items():
        value = values.get(value_key)
        if not _is_i32(value):
            return None, "BASELINE_POWER_COMPONENTS_UNKNOWN"
        components[component_key] = value
    if components["0x44"] < 10:
        return None, "BASELINE_MULTIPLIER_BELOW_NATIVE_MIN"
    return components, None


def _refresh(components: Mapping[str, int]) -> tuple[dict[str, int], int, bool]:
    current = dict(components)
    positive = _trade_power._country_power({
        **current,
        "0x48": INT32_MAX,
        "0x50": 0,
        "0x54": 0,
    })
    old_power = _trade_power._country_power(current)
    cap_refreshed = old_power <= positive
    new_cap = positive if cap_refreshed else current["0x48"]
    refreshed = {**current, "0x48": new_cap}
    return refreshed, _trade_power._country_power(refreshed), cap_refreshed


def _baseline_components(baseline: Any) -> tuple[dict[str, int] | None, int | None, str | None]:
    expected_power = _parse_country_power(baseline)
    if expected_power is None:
        return None, None, "BASELINE_COUNTRY_POWER_UNKNOWN"
    components, reason = _parse_power_components(baseline)
    if components is None:
        return None, None, reason or "BASELINE_POWER_COMPONENTS_UNKNOWN"
    current_power = _trade_power._country_power(components)
    if current_power != expected_power:
        return None, None, "NATIVE_POWER_BASELINE_MISMATCH"
    _refreshed, after_refresh, _cap_refreshed = _refresh(components)
    if after_refresh != current_power:
        return None, None, "NATIVE_POWER_BASELINE_NOT_REFRESHED"
    return components, current_power, None


def derive_power_scenarios(baseline: Any, scenarios: Any) -> dict[str, Any]:
    """Resolve manual and province-source scenarios.

    Invalid scenario input is a caller/programmer error and raises
    ``ValueError``. Missing or inconsistent baseline evidence only makes the
    modeled transition unknown; manual scenarios remain usable. Automatic
    total deltas require a current strict membership gate and total-power value.
    """
    if not isinstance(scenarios, (list, tuple)):
        raise ValueError("scenarios_invalid")
    parsed: list[tuple[str, dict[str, Any]]] = []
    ids: set[str] = set()
    for scenario in scenarios:
        kind, normalized = _validate_scenario(scenario)
        scenario_id = normalized["id"]
        if scenario_id in ids:
            raise ValueError("scenario_id_duplicate")
        ids.add(scenario_id)
        parsed.append((kind, normalized))

    resolved: list[dict[str, Any]] = []
    transitions: dict[str, dict[str, Any]] = {}
    baseline_components, baseline_power, baseline_reason = _baseline_components(baseline)
    has_automatic_total = any(kind == "automatic_total" for kind, _ in parsed)
    baseline_membership_known = (
        _parse_power_sum_membership(baseline) if has_automatic_total else False
    )
    baseline_total_power = _parse_total_power(baseline) if has_automatic_total else None

    for kind, scenario in parsed:
        if kind == "manual":
            resolved.append(deepcopy(scenario))
            continue

        scenario_id = scenario["id"]
        if baseline_reason is not None or baseline_components is None or baseline_power is None:
            transitions[scenario_id] = _unknown(baseline_reason or "BASELINE_POWER_COMPONENTS_UNKNOWN")
            continue
        if kind == "automatic_total" and not baseline_membership_known:
            transitions[scenario_id] = _unknown("BASELINE_POWER_SUM_MEMBERSHIP_UNKNOWN")
            continue
        if kind == "automatic_total" and baseline_total_power is None:
            transitions[scenario_id] = _unknown("BASELINE_TOTAL_POWER_UNKNOWN")
            continue

        before = dict(baseline_components)
        base_before = before["0x4c"]
        cap_before = before["0x48"]
        base_after = _wrap_i32(base_before + scenario["province_power_delta_raw"])
        after_components = {**before, "0x4c": base_after}
        after_components, country_after, cap_refreshed = _refresh(after_components)
        country_delta = country_after - baseline_power
        if not INT32_MIN <= country_delta <= INT32_MAX:
            transitions[scenario_id] = _unknown("DERIVED_POWER_DELTA_OUTSIDE_DOMAIN")
            continue

        country_delta = int(country_delta)

        total_after: int | None = None
        if kind == "automatic_total":
            assert baseline_total_power is not None
            total_after = _wrap_i32(baseline_total_power + country_delta)
            total_delta = total_after - baseline_total_power
            if not _is_i32(total_delta):
                transitions[scenario_id] = _unknown("DERIVED_TOTAL_POWER_DELTA_OUTSIDE_DOMAIN")
                continue
        else:
            total_delta = scenario["total_power_delta_raw"]

        resolved_scenario = deepcopy(scenario)
        resolved_scenario.pop("power_input_model", None)
        resolved_scenario.pop("province_power_delta_raw", None)
        if kind == "automatic_total":
            resolved_scenario.pop("total_power_input_model", None)
            resolved_scenario["total_power_delta_raw"] = total_delta
        resolved_scenario["country_power_delta_raw"] = country_delta
        resolved.append(resolved_scenario)
        value = {
            "province_power_delta_raw": scenario["province_power_delta_raw"],
            "country_power_before_raw": baseline_power,
            "country_power_after_raw": country_after,
            "country_power_delta_raw": country_delta,
            "total_power_delta_raw": total_delta,
            "base_before_raw": base_before,
            "base_after_raw": base_after,
            "cap_before_raw": cap_before,
            "cap_after_raw": after_components["0x48"],
            "cap_refreshed": cap_refreshed,
            "power_input_model": POWER_INPUT_MODEL,
        }
        if kind == "automatic_total":
            value.update({
                "total_power_input_model": TOTAL_POWER_INPUT_MODEL,
                "total_power_before_raw": baseline_total_power,
                "total_power_after_raw": total_after,
            })
        transitions[scenario_id] = {
            "status": "known",
            "basis": TRANSITION_BASIS,
            "game_fact": False,
            "complete": False,
            "value": value,
        }

    return {"resolved_scenarios": resolved, "transitions": transitions}


__all__ = ["derive_power_scenarios"]
