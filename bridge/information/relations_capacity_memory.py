"""Bounded native diplomatic-relation capacity arithmetic for country FRA.

The parent capture owns process identity, ROM guards, NPC role, country-view
admission and the two-pass contract.  This leaf only revalidates the canonical
country binding and copies the two target-local cache values plus modifier 159;
it does not enumerate relation records or call native code.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from . import country_scale_development_memory as _country_binding
from . import foreign_quality_memory as _quality


SCHEMA = "information.relations_capacity_memory.v1"
FIELD_COUNT = "N05.relations_count"
FIELD_LIMIT = "N05.relations_limit"
FIELDS = (FIELD_COUNT, FIELD_LIMIT)
OBSERVER = "FRA"

BASE_CACHE_OFFSET = 0x98C4
FREE_SLOTS_OFFSET = 0x98C8
MODIFIER_ID = 159
MODIFIER_NAME = "relations_capacity"
MODIFIER_UNIT = "native_fixed_point"
MODIFIER_SCALE = 1000
RELATION_UNIT = "diplomatic_relation"
RELATION_SCALE = 1
BASIS = "native_diplomatic_relation_trigger_arithmetic"
VALUE_ORIGIN = "derived_from_copied_native_modifier_and_relation_caches"

MAX_TOTAL_READ_BYTES = _quality.MAX_TOTAL_READ_BYTES
MAX_READ_CALLS = _quality.MAX_READ_CALLS
MAX_SINGLE_READ_BYTES = _quality.MAX_SINGLE_READ_BYTES
MAX_FIELDS = 16


def _unknown(reason: str, raw_inputs: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "reason": reason}
    if raw_inputs is not None:
        result["raw_inputs"] = deepcopy(dict(raw_inputs))
    return result


def _known(value: int, raw_inputs: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": "known",
        "value": value,
        "raw": value,
        "raw_hex": int(value).to_bytes(4, "little", signed=True).hex(),
        "unit": RELATION_UNIT,
        "scale": RELATION_SCALE,
        "period": "current",
        "partial": True,
        "complete": False,
        "basis": BASIS,
        "value_origin": VALUE_ORIGIN,
        "raw_inputs": deepcopy(dict(raw_inputs)),
    }


def _wrap_i32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value & 0x80000000 else value


def _read_i32(trace: Any, address: int, label: str,
              failure_reason: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read one signed cache cell and retain its exact bytes and trace slice."""
    start = len(trace.reads)
    inputs: dict[str, Any] = {"address": hex(address)}
    try:
        raw = trace.exact(address, 4, label)
        value = int.from_bytes(raw, "little", signed=True)
        inputs.update({"raw_hex": raw.hex(), "value": value})
        return {"status": "known", "value": value, "raw": value}, inputs
    except Exception as exc:
        inputs["error"] = str(getattr(exc, "reason", None) or exc)
        return _unknown(failure_reason), inputs
    finally:
        inputs["reads"] = deepcopy(trace.reads[start:])


def _manager_record(trace: Any, base: int) -> tuple[int | None, dict[str, Any], str | None]:
    start = len(trace.reads)
    address = None
    inputs: dict[str, Any] = {}
    try:
        address = _quality._add(base, _quality.MODIFIER_PROCESSOR_GLOBAL_RVA, 8)
        inputs["cell"] = hex(address)
        manager = _quality._valid_pointer(
            trace.u64(address, "relations_capacity.modifier_processor_manager"),
            "MODIFIER_PROCESSOR_MANAGER")
        inputs["pointer"] = hex(manager)
        return manager, inputs, None
    except Exception as exc:
        inputs["error"] = str(getattr(exc, "reason", None) or exc)
        return None, inputs, "RELATIONS_MODIFIER_PROCESSOR_MANAGER_UNAVAILABLE"
    finally:
        inputs["reads"] = deepcopy(trace.reads[start:])


def _common_raw(base: int, retained: Mapping[str, Any] | None,
                target_evidence: Mapping[str, Any] | None,
                trace: Any) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "module_base": hex(base) if type(base) is int else None,
        "target_binding": deepcopy(dict(retained)) if isinstance(retained, Mapping) else None,
        "target_binding_revalidation": deepcopy(dict(target_evidence))
        if isinstance(target_evidence, Mapping) else None,
        "reads": deepcopy(trace.reads),
        "budget": trace.budget(),
    }


def _unknown_fields(reason: str, raw: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {field: _unknown(reason, raw) for field in FIELDS}


def _field_request(fields: Any) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Normalize a bounded request without reading memory for unsupported-only calls."""
    if not isinstance(fields, (tuple, list)) or len(fields) > MAX_FIELDS:
        return {}, []
    if any(not isinstance(field, str) for field in fields):
        return {}, []
    result: dict[str, dict[str, Any]] = {}
    seen: set[str] = set()
    supported: list[str] = []
    for field in fields:
        if field in seen:
            result[field] = _unknown("duplicate_field_requested")
            continue
        seen.add(field)
        if field not in FIELDS:
            result[field] = _unknown("unsupported_field")
        else:
            supported.append(field)
    return result, supported


def read_fields(reader: Any, base: int, target_binding: Any,
                fields: tuple[str, ...] | list[str]) -> dict[str, dict[str, Any]]:
    """Read the requested FRA relation count/limit from bounded native caches.

    Modifier 159 is copied with the exact dense/sparse and processor checks used
    by the existing quality leaf.  The native arithmetic is:
    ``limit = trunc_zero(modifier159 / 1000)`` and
    ``count = i32(limit + i32(base_cache - free_slots))``.  The additional
    cache term belongs to the native current-count expression, not ALLOW.
    """
    result, supported = _field_request(fields)
    if not supported:
        return result

    trace = _quality._TraceReader(reader)
    retained: dict[str, Any] | None = None
    target_evidence: dict[str, Any] | None = None
    try:
        module_base, country_pointer, retained = _country_binding._parse_target(base, target_binding)
    except Exception as exc:
        reason = "TARGET_BINDING_INVALID"
        raw = _common_raw(base, None, None, trace)
        raw["target_binding_input"] = deepcopy(target_binding)
        raw["error"] = str(exc)[:160]
        for field in supported:
            if field not in result:
                result[field] = _unknown(reason, raw)
        return result

    if retained.get("tag") != OBSERVER:
        raw = _common_raw(base, retained, None, trace)
        raw["error"] = "TARGET_COUNTRY_SCOPE"
        for field in supported:
            if field not in result:
                result[field] = _unknown("TARGET_COUNTRY_SCOPE", raw)
        return result

    try:
        # The shared bounded reader performs the same canonical database
        # resolution as the country-scale leaf while the quality trace retains
        # the ordered underlying reads for later audit/replay.
        limiter = _country_binding._shared._BoundedReader(trace)
        target_evidence = _country_binding._validate_target_binding(
            limiter, module_base, country_pointer, retained)
    except Exception as exc:
        reason = "TARGET_BINDING_UNVERIFIED"
        raw = _common_raw(base, retained, None, trace)
        raw["error"] = str(exc)[:180]
        for field in supported:
            if field not in result:
                result[field] = _unknown(reason, raw)
        return result

    raw = _common_raw(base, retained, target_evidence, trace)
    raw["formula"] = {
        "relations_limit": "trunc_zero(modifier159 / 1000)",
        "relations_count": "i32(relations_limit + i32(base_cache - free_slots))",
        "modifier_scale": MODIFIER_SCALE,
    }

    # The two relation-cache cells are independent reads.  Preserve each raw
    # byte record even if the other cache or modifier later proves unknown.
    try:
        base_address = _quality._add(country_pointer, BASE_CACHE_OFFSET, 4)
        free_address = _quality._add(country_pointer, FREE_SLOTS_OFFSET, 4)
        cache_state_address = _quality._add(
            country_pointer, _quality.COUNTRY_CACHE_STATE_OFFSET, 4)
    except Exception as exc:
        raw["error"] = str(exc)[:160]
        for field in supported:
            if field not in result:
                result[field] = _unknown("RELATIONS_CACHE_ADDRESS_INVALID", raw)
        return result
    base_record, base_inputs = _read_i32(
        trace, base_address, "relations_capacity.base_cache_i32",
        "RELATIONS_BASE_CACHE_READ_FAILED")
    free_record, free_inputs = _read_i32(
        trace, free_address, "relations_capacity.free_slots_i32",
        "RELATIONS_FREE_SLOTS_READ_FAILED")
    raw["base_cache"] = deepcopy(base_inputs)
    raw["free_slots_cache"] = deepcopy(free_inputs)

    cache_state_record, cache_state_inputs = _read_i32(
        trace, cache_state_address, "relations_capacity.cache_state_i32",
        "RELATIONS_CACHE_STATE_READ_FAILED")
    raw["cache_state"] = deepcopy(cache_state_inputs)

    modifier: dict[str, Any]
    manager_inputs: dict[str, Any] = {}
    if cache_state_record.get("status") != "known":
        modifier = _unknown(str(cache_state_record.get("reason")
                               or "RELATIONS_CACHE_STATE_READ_FAILED"))
    elif cache_state_record.get("value") == 1:
        modifier = _unknown("MILITARY_CACHE_CALCULATING")
    else:
        manager, manager_inputs, manager_error = _manager_record(trace, module_base)
        if manager_error is not None or manager is None:
            modifier = _unknown(manager_error or "RELATIONS_MODIFIER_PROCESSOR_MANAGER_UNAVAILABLE")
        else:
            modifier = _quality._read_modifier(
                trace, country_pointer, manager, cache_state_record["value"],
                MODIFIER_NAME, MODIFIER_ID, MODIFIER_UNIT)
    raw["modifier_processor_manager"] = deepcopy(manager_inputs)
    raw["modifier_component"] = deepcopy(modifier)
    raw["reads"] = deepcopy(trace.reads)
    raw["budget"] = trace.budget()

    modifier_known = (
        not trace.budget_failed
        and modifier.get("status") == "known"
        and type(modifier.get("raw")) is int)
    if modifier_known:
        modifier_raw = modifier["raw"]
        delta = _quality._trunc_zero(modifier_raw, MODIFIER_SCALE)
        limit = delta
        raw["arithmetic"] = {
            "modifier_raw": modifier_raw,
            "modifier_trunc_zero": delta,
            "limit": limit,
        }
        limit_field = _known(limit, raw)
        if (base_record.get("status") == "known" and free_record.get("status") == "known"
                and type(base_record.get("value")) is int and type(free_record.get("value")) is int):
            count = _wrap_i32(limit + _wrap_i32(base_record["value"] - free_record["value"]))
            raw["arithmetic"]["base_cache"] = base_record["value"]
            raw["arithmetic"]["free_slots"] = free_record["value"]
            raw["arithmetic"]["count"] = count
            count_field = _known(count, raw)
        elif trace.budget_failed:
            count_field = _unknown("RELATIONS_CAPACITY_READ_BUDGET_EXCEEDED", raw)
            limit_field = _unknown("RELATIONS_CAPACITY_READ_BUDGET_EXCEEDED", raw)
        else:
            failed_cache = base_record if base_record.get("status") != "known" else free_record
            count_field = _unknown(str(failed_cache.get("reason")
                                       or "RELATIONS_COUNT_CACHE_READ_FAILED"), raw)
    else:
        if modifier.get("status") != "known":
            modifier_reason = modifier.get("reason")
            if modifier_reason == "MODIFIER_PROCESSOR_PRESENT":
                failure_reason = modifier_reason
            elif modifier_reason == "MILITARY_CACHE_CALCULATING":
                failure_reason = modifier_reason
            else:
                failure_reason = "RELATIONS_MODIFIER_UNKNOWN"
        elif trace.budget_failed:
            failure_reason = "RELATIONS_CAPACITY_READ_BUDGET_EXCEEDED"
        else:
            failure_reason = "RELATIONS_CAPACITY_ARITHMETIC_INVALID"
        limit_field = _unknown(failure_reason, raw)
        count_field = _unknown(failure_reason, raw)

    if FIELD_LIMIT in supported and FIELD_LIMIT not in result:
        result[FIELD_LIMIT] = limit_field
    if FIELD_COUNT in supported and FIELD_COUNT not in result:
        result[FIELD_COUNT] = count_field
    return result


__all__ = [
    "SCHEMA", "FIELD_COUNT", "FIELD_LIMIT", "FIELDS", "OBSERVER",
    "BASE_CACHE_OFFSET", "FREE_SLOTS_OFFSET", "MODIFIER_ID", "MODIFIER_NAME",
    "MAX_TOTAL_READ_BYTES", "MAX_READ_CALLS", "MAX_SINGLE_READ_BYTES", "read_fields",
]
