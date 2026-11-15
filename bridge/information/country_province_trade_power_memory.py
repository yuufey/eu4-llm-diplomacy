"""Bounded passive reader for the country's global-province trade modifier.

This leaf validates a compact canonical country binding and reads raw modifier
17 only when its descriptor name matches and the descriptor processor is null.
The caller owns permission checks, profile/session admission and two-pass
stability. No native function is invoked here.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from . import country_scale_development_memory as _country_binding
from . import foreign_quality_memory as _quality
from . import province_trade_power_inputs_memory as _province_inputs
from .modifier_storage import read_raw_modifier


FIELD_COUNTRY_GLOBAL_PROVINCE_TRADE_POWER_MODIFIER = (
    "G02.country_global_province_trade_power_modifier"
)
SUPPORTED_FIELDS = (FIELD_COUNTRY_GLOBAL_PROVINCE_TRADE_POWER_MODIFIER,)

MODIFIER_KEY = "global_prov_trade_power_modifier"
MODIFIER_ID = 17
MODIFIER_UNIT = "ratio"
MODIFIER_SCALE = 1000
CACHE_STATE_OFFSET = 0x28C8
MODIFIER_PROCESSOR_GLOBAL_RVA = 0x2358060
MODIFIER_PROCESSOR_STRIDE = 0x60
MODIFIER_PROCESSOR_OFFSET = 0x40
MODIFIER_DESCRIPTOR_SIZE = 0x60
MODIFIER_OBJECT_OFFSET = 0x28D0
MODIFIER_OBJECT_SIZE = 0x68
SUPPORTED_CACHE_STATES = (0, 2)

_BASIS = "native_country_province_trade_power_modifier_processor_absent"


def _unknown(reason: str, raw_inputs: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": "unknown",
        "reason": reason,
        "complete": False,
        "basis": _BASIS,
        "period": "current",
        "raw_inputs": deepcopy(dict(raw_inputs)),
    }


def _known(tag: str, raw_value: int, raw_inputs: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": "known",
        "value": {
            "country": tag,
            "raw": raw_value,
            "scale": MODIFIER_SCALE,
            "unit": MODIFIER_UNIT,
        },
        "complete": False,
        "basis": _BASIS,
        "period": "current",
        "raw_inputs": deepcopy(dict(raw_inputs)),
    }


def _safe_binding_input(binding: Any) -> Any:
    if not isinstance(binding, Mapping):
        return f"<{type(binding).__name__}>"
    keys = ("tag", "country_pointer", "fullref", "fullref_raw_hex")
    result: dict[str, Any] = {}
    for key in keys:
        value = binding.get(key)
        if value is None or type(value) in (str, int, bool):
            result[key] = value
        else:
            result[key] = f"<{type(value).__name__}>"
    return result


def _new_trace(reader: Any) -> _quality._TraceReader:
    return _quality._TraceReader(reader)


def _finish_unknown(reason: str, raw_inputs: dict[str, Any],
                    trace: _quality._TraceReader) -> dict[str, Any]:
    raw_inputs["reads"] = deepcopy(trace.reads)
    raw_inputs["read_budget"] = trace.budget()
    return _unknown(reason, raw_inputs)


def _finish_known(tag: str, raw_value: int, raw_inputs: dict[str, Any],
                  trace: _quality._TraceReader) -> dict[str, Any]:
    raw_inputs["reads"] = deepcopy(trace.reads)
    raw_inputs["read_budget"] = trace.budget()
    return _known(tag, raw_value, raw_inputs)


def _read_field(reader: Any, module_base: Any,
                country_binding: Any) -> dict[str, Any]:
    trace = _new_trace(reader)
    raw: dict[str, Any] = {
        "field": FIELD_COUNTRY_GLOBAL_PROVINCE_TRADE_POWER_MODIFIER,
        "module_base_input": module_base if type(module_base) in (int, str) else None,
        "country_binding_input": _safe_binding_input(country_binding),
        "modifier_id": MODIFIER_ID,
        "modifier_key_expected": MODIFIER_KEY,
        "cache_state_allowed_by_this_leaf": list(SUPPORTED_CACHE_STATES),
    }

    try:
        base, country, retained = _country_binding._parse_target(
            module_base, country_binding
        )
    except Exception:
        return _finish_unknown("COUNTRY_BINDING_INVALID", raw, trace)
    raw.update({
        "module_base": hex(base),
        "country_pointer": hex(country),
        "country_tag": retained.get("tag"),
        "country_fullref": retained.get("fullref"),
    })

    try:
        limiter = _country_binding._shared._BoundedReader(trace)
        binding_evidence = _country_binding._validate_target_binding(
            limiter, base, country, retained
        )
        if not isinstance(binding_evidence, Mapping):
            raise ValueError("binding_evidence_invalid")
        raw["canonical_binding_revalidation"] = deepcopy(dict(binding_evidence))
    except Exception:
        return _finish_unknown("COUNTRY_BINDING_UNVERIFIED", raw, trace)

    try:
        cache_state_address = _quality._add(country, CACHE_STATE_OFFSET, 4)
        cache_state_before = trace.i32(
            cache_state_address, "country_province_trade_power.cache_state_before_i32"
        )
    except Exception:
        return _finish_unknown("COUNTRY_CACHE_STATE_UNAVAILABLE", raw, trace)
    raw.update({
        "cache_state_address": hex(cache_state_address),
        "cache_state_before": cache_state_before,
    })
    if cache_state_before == 1:
        return _finish_unknown("COUNTRY_CACHE_STATE_CALCULATING", raw, trace)
    if cache_state_before not in SUPPORTED_CACHE_STATES:
        return _finish_unknown("COUNTRY_CACHE_STATE_UNSUPPORTED", raw, trace)

    try:
        manager_cell = _quality._add(base, MODIFIER_PROCESSOR_GLOBAL_RVA, 8)
        manager_raw = trace.exact(
            manager_cell, 8, "country_province_trade_power.processor_manager_global"
        )
        manager = _quality._valid_pointer(
            int.from_bytes(manager_raw, "little", signed=False),
            "MODIFIER_PROCESSOR_MANAGER",
        )
        descriptor_address = _quality._add(
            manager, MODIFIER_ID * MODIFIER_PROCESSOR_STRIDE,
            MODIFIER_DESCRIPTOR_SIZE,
        )
        descriptor_raw = trace.exact(
            descriptor_address, MODIFIER_DESCRIPTOR_SIZE,
            "country_province_trade_power.index_17.descriptor_96",
        )
        processor_cell = descriptor_address + MODIFIER_PROCESSOR_OFFSET
        processor_raw = descriptor_raw[
            MODIFIER_PROCESSOR_OFFSET:MODIFIER_PROCESSOR_OFFSET + 8
        ]
        if len(processor_raw) != 8:
            raise _quality._Failure("DESCRIPTOR_PROCESSOR_POINTER_SHORT")
        processor_pointer = int.from_bytes(processor_raw, "little", signed=False)
        descriptor_forbidden = (
            country, manager_cell, manager, descriptor_address, processor_cell,
        )
        key_before = _province_inputs._parse_descriptor_name(
            trace, descriptor_address, descriptor_raw, MODIFIER_KEY,
            descriptor_forbidden, "country_index_17",
        )
    except Exception as exc:
        raw["descriptor_error_class"] = type(exc).__name__
        reason = "COUNTRY_MODIFIER_KEY_MISMATCH" if (
            isinstance(exc, _quality._Failure)
            and exc.reason == "DESCRIPTOR_NAME_MISMATCH"
        ) else "COUNTRY_MODIFIER_DESCRIPTOR_UNVERIFIED"
        return _finish_unknown(reason, raw, trace)

    raw.update({
        "processor_manager_global_rva": hex(MODIFIER_PROCESSOR_GLOBAL_RVA),
        "processor_manager_global_cell": hex(manager_cell),
        "processor_manager_global_raw_hex": manager_raw.hex(),
        "processor_manager": hex(manager),
        "modifier_index": MODIFIER_ID,
        "modifier_descriptor_address": hex(descriptor_address),
        "modifier_descriptor_raw_hex": descriptor_raw.hex(),
        "modifier_descriptor_key_header_raw_hex": descriptor_raw[:0x20].hex(),
        "modifier_key_before": deepcopy(key_before),
        "processor_pointer_cell": hex(processor_cell),
        "processor_pointer_before": hex(processor_pointer),
        "processor_pointer_raw_hex": processor_raw.hex(),
    })
    if key_before.get("key") != MODIFIER_KEY:
        return _finish_unknown("COUNTRY_MODIFIER_KEY_MISMATCH", raw, trace)
    if processor_pointer != 0:
        return _finish_unknown("COUNTRY_MODIFIER_PROCESSOR_PRESENT", raw, trace)

    try:
        modifier_object = _quality._add(country, MODIFIER_OBJECT_OFFSET,
                                        MODIFIER_OBJECT_SIZE)
        storage_component = read_raw_modifier(
            trace, country, MODIFIER_ID, MODIFIER_UNIT,
            name=MODIFIER_KEY,
            forbidden_pointers=(country, modifier_object, manager_cell, manager,
                                descriptor_address, processor_cell),
        )
        if not isinstance(storage_component, Mapping):
            raise ValueError("modifier_storage_result_invalid")
        storage_component = dict(storage_component)
        raw["modifier_object_address"] = hex(modifier_object)
        raw["modifier_storage_component"] = deepcopy(storage_component)
    except Exception as exc:
        raw["storage_error_class"] = type(exc).__name__
        return _finish_unknown("COUNTRY_MODIFIER_STORAGE_UNAVAILABLE", raw, trace)

    stability_errors: list[str] = []
    try:
        manager_recheck = trace.exact(
            manager_cell, 8,
            "country_province_trade_power.processor_manager_global_recheck",
        )
        raw["processor_manager_global_recheck_raw_hex"] = manager_recheck.hex()
        if manager_recheck != manager_raw:
            stability_errors.append("COUNTRY_MODIFIER_MANAGER_CHANGED")
    except Exception:
        manager_recheck = None
        stability_errors.append("COUNTRY_MODIFIER_STABILITY_UNAVAILABLE")

    try:
        key_header_recheck = trace.exact(
            descriptor_address, 0x20,
            "country_province_trade_power.index_17.key_header_recheck",
        )
        processor_recheck = trace.exact(
            processor_cell, 8,
            "country_province_trade_power.index_17.processor_recheck",
        )
        raw["modifier_descriptor_key_header_recheck_raw_hex"] = key_header_recheck.hex()
        raw["processor_pointer_recheck_raw_hex"] = processor_recheck.hex()
        header_changed = key_header_recheck != descriptor_raw[:0x20]
        processor_changed = processor_recheck != processor_raw
        if header_changed:
            stability_errors.append("COUNTRY_MODIFIER_DESCRIPTOR_CHANGED")
        if processor_changed:
            stability_errors.append("COUNTRY_MODIFIER_PROCESSOR_CHANGED")
        if not header_changed and not processor_changed:
            try:
                key_after = _province_inputs._parse_descriptor_name(
                    trace, descriptor_address, key_header_recheck, MODIFIER_KEY,
                    descriptor_forbidden, "country_index_17_recheck",
                )
            except Exception:
                stability_errors.append("COUNTRY_MODIFIER_KEY_CHANGED")
            else:
                raw["modifier_key_after"] = deepcopy(key_after)
                if key_after != key_before:
                    stability_errors.append("COUNTRY_MODIFIER_KEY_CHANGED")
    except Exception:
        stability_errors.append("COUNTRY_MODIFIER_STABILITY_UNAVAILABLE")

    try:
        cache_state_after = trace.i32(
            cache_state_address,
            "country_province_trade_power.cache_state_after_i32",
        )
        raw["cache_state_after"] = cache_state_after
        if cache_state_after != cache_state_before:
            stability_errors.append("COUNTRY_CACHE_STATE_CHANGED")
        elif cache_state_after not in SUPPORTED_CACHE_STATES:
            stability_errors.append("COUNTRY_CACHE_STATE_UNSUPPORTED")
    except Exception:
        stability_errors.append("COUNTRY_CACHE_STATE_RECHECK_UNAVAILABLE")

    raw["stability_errors"] = list(dict.fromkeys(stability_errors))
    if stability_errors:
        return _finish_unknown(stability_errors[0], raw, trace)
    if storage_component.get("status") != "known":
        return _finish_unknown("COUNTRY_MODIFIER_STORAGE_UNAVAILABLE", raw, trace)
    raw_value = storage_component.get("raw")
    if (type(raw_value) is not int or not -(1 << 31) <= raw_value < (1 << 31)
            or storage_component.get("unit") != MODIFIER_UNIT
            or storage_component.get("scale") != MODIFIER_SCALE):
        return _finish_unknown("COUNTRY_MODIFIER_STORAGE_RESULT_INVALID", raw, trace)
    tag = retained.get("tag")
    if not isinstance(tag, str) or not tag:
        return _finish_unknown("COUNTRY_BINDING_INVALID", raw, trace)
    return _finish_known(tag, raw_value, raw, trace)


def read_fields(reader: Any, module_base: Any, country_binding: Any,
                fields: tuple[str, ...] | list[str]) -> dict[str, dict[str, Any]]:
    """Read the single allowlisted passive country modifier field."""
    if not isinstance(fields, (tuple, list)) or len(fields) > 16:
        return {}
    if any(not isinstance(field, str) for field in fields):
        return {}
    requested = tuple(fields)
    unique_fields = tuple(dict.fromkeys(requested))
    if len(unique_fields) != len(requested):
        return {field: _unknown("DUPLICATE_FIELD_REQUESTED", {})
                for field in unique_fields}
    result: dict[str, dict[str, Any]] = {}
    for field in unique_fields:
        if field != FIELD_COUNTRY_GLOBAL_PROVINCE_TRADE_POWER_MODIFIER:
            result[field] = _unknown("UNSUPPORTED_FIELD", {})
    if FIELD_COUNTRY_GLOBAL_PROVINCE_TRADE_POWER_MODIFIER in unique_fields:
        result[FIELD_COUNTRY_GLOBAL_PROVINCE_TRADE_POWER_MODIFIER] = _read_field(
            reader, module_base, country_binding
        )
    return {field: result[field] for field in unique_fields}


__all__ = [
    "FIELD_COUNTRY_GLOBAL_PROVINCE_TRADE_POWER_MODIFIER",
    "MODIFIER_ID",
    "MODIFIER_KEY",
    "SUPPORTED_FIELDS",
    "read_fields",
]
