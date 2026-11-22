"""Bounded read-only governing-capacity cache projection."""
from __future__ import annotations

from copy import deepcopy

from . import country_scale_development_memory as _binding
from . import foreign_quality_memory as _quality
from . import relations_capacity_memory as _shared_cache
from . import governance_capacity_values as _values


SCHEMA = "information.governance_capacity_memory.v1"
FIELD = "N06.governance_capacity"
FIELDS = (FIELD,)
UNIT = "governing_capacity_summary"
SCALE = 1
BASIS = "native_governing_capacity_cache_and_limit_arithmetic"
VALUE_ORIGIN = "derived_from_copied_native_governing_capacity_inputs"

GOVERNANCE_CAPACITY_USED_OFFSET = 0xE2C
GOVERNANCE_CAPACITY_BASE_POINTER_OFFSET = 0x2440
GOVERNANCE_CAPACITY_BASE_VALUE_OFFSET = 0x1C
MODIFIER_ADD_ID = 409
MODIFIER_RATIO_ID = 410
MODIFIER_ADD_UNIT = "governing_capacity"
MODIFIER_RATIO_UNIT = "ratio_modifier"

_SAFE_RAW_FAILURE = "GOVERNANCE_CAPACITY_INPUT_UNAVAILABLE"


def _unknown(reason: str) -> dict:
    return {"status": "unknown", "reason": reason}


def _known_number(name: str, value: int) -> dict:
    spec = _values.NUMBER_SPECS[name]
    width = spec["width"]
    return {
        "status": "known", "value": value, "raw": value,
        "raw_hex": value.to_bytes(width, "little", signed=True).hex(),
        "unit": spec["unit"], "scale": spec["scale"], "period": "current",
        "partial": True, "complete": False, "basis": spec["basis"],
        "value_origin": spec["value_origin"],
    }


def _component_raw(component: object) -> int | None:
    if not isinstance(component, dict) or component.get("status") != "known":
        return None
    value = component.get("raw")
    return value if type(value) is int and -(1 << 31) <= value < (1 << 31) else None


def _set_derived(used_field: dict, limit_field: dict) -> tuple[dict, dict]:
    if used_field.get("status") != "known":
        return (_unknown("GOVERNANCE_CAPACITY_USED_UNAVAILABLE"),
                _unknown("GOVERNANCE_CAPACITY_USED_UNAVAILABLE"))
    if limit_field.get("status") != "known":
        return (_unknown("GOVERNANCE_CAPACITY_LIMIT_UNAVAILABLE"),
                _unknown("GOVERNANCE_CAPACITY_LIMIT_UNAVAILABLE"))
    used = used_field["raw"]
    limit = limit_field["raw"]
    ratio = _values.used_ratio(used, limit)
    fraction_field = ({"status": "not_applicable",
                       "reason": "GOVERNANCE_CAPACITY_LIMIT_ZERO"} if ratio is None
                      else _known_number("used_fraction", ratio))
    return fraction_field, _known_number("headroom", _values.headroom_signed(used, limit))


def read_fields(reader, base, target_binding, fields=FIELDS, *, observer='FRA', **_unused):
    result = {}
    if not isinstance(fields, (tuple, list)) or len(fields) > 16:
        return {FIELD: {"status": "unknown", "reason": "FIELD_REQUEST_INVALID"}}
    for name in fields:
        if not isinstance(name, str):
            return {FIELD: {"status": "unknown", "reason": "FIELD_REQUEST_INVALID"}}
        if name != FIELD:
            result[name] = {"status": "unknown", "reason": "FIELD_NOT_SUPPORTED"}
    if FIELD not in fields:
        return result

    trace = _quality._TraceReader(reader)
    raw = {
        "schema": SCHEMA,
        "module_base": hex(base) if type(base) is int else None,
        "target_binding": None,
        "target_binding_revalidation": None,
        "cache_state": None,
        "used": {},
        "native_limit_base": {},
        "modifier_processor_manager": None,
        "modifier_409": None,
        "modifier_410": None,
        "reads": [],
        "budget": trace.budget(),
    }
    used_field = _unknown("GOVERNANCE_CAPACITY_USED_UNAVAILABLE")
    limit_field = _unknown("GOVERNANCE_CAPACITY_LIMIT_UNAVAILABLE")
    target_error = None

    try:
        module, country, retained = _binding._parse_target(base, target_binding)
        if retained.get("tag") != observer:
            raise ValueError("TARGET_COUNTRY_SCOPE")
        limiter = _binding._shared._BoundedReader(trace)
        raw["target_binding_revalidation"] = _binding._validate_target_binding(
            limiter, module, country, retained)
        raw["target_binding"] = deepcopy(retained)
    except Exception as error:
        failure = str(getattr(error, "reason", None) or error)[:160]
        raw["failure"] = failure
        reason = ("TARGET_COUNTRY_SCOPE" if failure == "TARGET_COUNTRY_SCOPE"
                  else "TARGET_BINDING_UNVERIFIED")
        raw.update(reads=deepcopy(trace.reads), budget=trace.budget())
        if trace.budget_failed:
            reason = "GOVERNANCE_CAPACITY_READ_BUDGET_EXCEEDED"
        return {FIELD: {"status": "unknown", "reason": reason, "raw_inputs": raw}}

    try:
        used_address = _quality._add(country, GOVERNANCE_CAPACITY_USED_OFFSET, 4)
        raw["used"]["address"] = hex(used_address)
        used = trace.i32(used_address, "governance_capacity.used_i32")
        raw["used"].update(status="known", raw=used, raw_hex=trace.reads[-1]["raw_hex"])
        used_field = _known_number("used", used)
    except Exception as error:
        raw["used"].update(status="unknown", error=str(getattr(error, "reason", None)
                                                            or error)[:128])
        used_field = _unknown("GOVERNANCE_CAPACITY_USED_READ_FAILED")

    try:
        state = trace.i32(_quality._add(country, _quality.COUNTRY_CACHE_STATE_OFFSET, 4),
                          "governance_capacity.cache_state_i32")
        raw["cache_state"] = state
    except Exception as error:
        state = None
        raw["cache_state_error"] = str(getattr(error, "reason", None) or error)[:128]
        limit_field = _unknown("GOVERNANCE_CAPACITY_CACHE_STATE_UNAVAILABLE")

    manager = None
    if state == 1:
        limit_field = _unknown("MILITARY_CACHE_CALCULATING")
    elif state is not None:
        manager, manager_inputs, manager_error = _shared_cache._manager_record(trace, module)
        raw["modifier_processor_manager"] = manager_inputs
        if manager_error or manager is None:
            limit_field = _unknown("GOVERNANCE_CAPACITY_MANAGER_UNAVAILABLE")
        else:
            base_record = {}
            raw["native_limit_base"] = base_record
            try:
                base_pointer_address = _quality._add(
                    country, GOVERNANCE_CAPACITY_BASE_POINTER_OFFSET, 8)
                base_record["pointer_cell"] = hex(base_pointer_address)
                pointer_raw = trace.u64(base_pointer_address,
                                        "governance_capacity.limit_base_pointer")
                pointer = _quality._valid_pointer(pointer_raw, "GOVERNANCE_CAPACITY_BASE")
                base_record["pointer"] = hex(pointer)
                if pointer in (country, manager):
                    raise ValueError("governance_capacity_base_alias")
                base_value_address = _quality._add(pointer,
                    GOVERNANCE_CAPACITY_BASE_VALUE_OFFSET, 4)
                base_value = trace.i32(base_value_address,
                    "governance_capacity.limit_base_i32")
                base_record.update(value_address=hex(base_value_address), raw=base_value,
                                   raw_hex=trace.reads[-1]["raw_hex"], status="known")
            except Exception as error:
                base_record.update(status="unknown",
                    error=str(getattr(error, "reason", None) or error)[:128])
                base_value = None

            if base_value is None:
                limit_field = _unknown("GOVERNANCE_CAPACITY_BASE_UNAVAILABLE")
            else:
                add_component = _quality._read_modifier(
                    trace, country, manager, state, "governance_capacity_modifier_409",
                    MODIFIER_ADD_ID, MODIFIER_ADD_UNIT)
                ratio_component = _quality._read_modifier(
                    trace, country, manager, state, "governance_capacity_modifier_410",
                    MODIFIER_RATIO_ID, MODIFIER_RATIO_UNIT)
                raw["modifier_409"] = add_component
                raw["modifier_410"] = ratio_component
                additive = _component_raw(add_component)
                ratio_modifier = _component_raw(ratio_component)
                if additive is None:
                    limit_field = _unknown("GOVERNANCE_CAPACITY_MODIFIER_409_UNAVAILABLE")
                elif ratio_modifier is None:
                    limit_field = _unknown("GOVERNANCE_CAPACITY_MODIFIER_410_UNAVAILABLE")
                else:
                    try:
                        limit = _values.capacity_limit(base_value, additive, ratio_modifier)
                        limit_field = _known_number("limit", limit)
                    except (ValueError, OverflowError):
                        limit_field = _unknown("GOVERNANCE_CAPACITY_LIMIT_ARITHMETIC_FAILED")

    fraction_field, headroom_field = _set_derived(used_field, limit_field)
    numbers = {"used": used_field, "limit": limit_field,
               "used_fraction": fraction_field, "headroom": headroom_field}
    if trace.budget_failed:
        reason = "GOVERNANCE_CAPACITY_READ_BUDGET_EXCEEDED"
        numbers = {key: _unknown(reason) for key in _values.NUMBER_SPECS}

    raw.update(reads=deepcopy(trace.reads), budget=trace.budget())
    if any(item.get("status") == "known" for item in numbers.values()):
        field = {"status": "known", "value": numbers, "unit": UNIT, "scale": SCALE,
                 "period": "current", "partial": True, "complete": False,
                 "basis": BASIS, "value_origin": VALUE_ORIGIN, "raw_inputs": raw}
    else:
        reason = ("GOVERNANCE_CAPACITY_READ_BUDGET_EXCEEDED" if trace.budget_failed
                  else "GOVERNANCE_CAPACITY_UNAVAILABLE")
        field = {"status": "unknown", "reason": reason, "raw_inputs": raw}
    result[FIELD] = field
    return result
