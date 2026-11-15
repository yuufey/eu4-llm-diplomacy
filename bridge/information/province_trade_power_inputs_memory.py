"""Internal reader for province-scoped trade-power modifier inputs.

The caller owns observer admission, canonical discovery and two-pass stability.
This leaf only reads the index-15/index-16 modifier descriptors and their raw
modifier storage when the native processor pointer is null. It never executes
a native processor or predicts an acquisition delta.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from . import foreign_quality_memory as _foreign
from . import modifier_storage as _modifier_storage
from . import province_identity_memory as _identity
from . import province_trade_power_memory as _trade_power


FIELD_PROVINCE_TRADE_POWER = _trade_power.FIELD_PROVINCE_TRADE_POWER
FIELD_PROVINCE_TRADE_POWER_VALUE = "G02.province_trade_power_value"
FIELD_PROVINCE_TRADE_POWER_MODIFIER = "G02.province_trade_power_modifier"
FIELD_PROVINCE_TRADE_POWER_FURTHER_MODIFIER = "G02.province_trade_power_further_modifier"

SUPPORTED_FIELDS = (
    FIELD_PROVINCE_TRADE_POWER,
    FIELD_PROVINCE_TRADE_POWER_VALUE,
    FIELD_PROVINCE_TRADE_POWER_MODIFIER,
    FIELD_PROVINCE_TRADE_POWER_FURTHER_MODIFIER,
)
NEW_FIELDS = SUPPORTED_FIELDS[1:]

MODIFIER_PROCESSOR_GLOBAL_RVA = 0x2358060
MODIFIER_PROCESSOR_STRIDE = 0x60
MODIFIER_PROCESSOR_OFFSET = 0x40
MODIFIER_DESCRIPTOR_SIZE = 0x60
STRING32_SIZE = 0x20
STRING32_LENGTH_OFFSET = 0x10
STRING32_CAPACITY_OFFSET = 0x18
MAX_STRING_CAPACITY = 1 << 20
MAX_PROVINCE_ID = 0xFFFF
MODIFIER_OBJECT_SIZE = 0x68

_DESCRIPTORS = {
    15: {
        "key": "province_trade_power_value",
        "fields": (FIELD_PROVINCE_TRADE_POWER_VALUE,),
    },
    16: {
        "key": "province_trade_power_modifier",
        "fields": (FIELD_PROVINCE_TRADE_POWER_MODIFIER,
                   FIELD_PROVINCE_TRADE_POWER_FURTHER_MODIFIER),
    },
}
_FIELD_SPECS = {
    FIELD_PROVINCE_TRADE_POWER_VALUE: (15, 0x998, "trade_power"),
    FIELD_PROVINCE_TRADE_POWER_MODIFIER: (16, 0x998, "ratio"),
    FIELD_PROVINCE_TRADE_POWER_FURTHER_MODIFIER: (16, 0x2438, "ratio"),
}

_BASIS = "native_province_numeric_modifier_processor_absent"
_GAPS = [
    "PROVINCE_VIEW_ADMISSION_AND_DISCOVERY_ARE_PARENT_OWNED",
    "PARENT_TWO_PASS_CONTEXT_AND_FIELD_STABILITY_ARE_PARENT_OWNED",
    "SESSION_PROFILE_AND_CODE_GUARDS_ARE_PARENT_OWNED",
    "NON_NULL_NATIVE_MODIFIER_PROCESSORS_ARE_NOT_EVALUATED",
    "CACHE_REFRESH_TIMING_AND_UI_RENDERING_ARE_NOT_PROVEN",
    "ACQUISITION_CAUSAL_DELTA_IS_NOT_PROVEN",
]


def _unknown(reason: str, raw_inputs: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "status": "unknown",
        "complete": False,
        "reason": reason,
        "raw_inputs": raw_inputs if raw_inputs is not None else {},
        "basis": _BASIS,
        "period": "current",
        "gaps": list(_GAPS),
    }


def _known(raw_value: int, unit: str, raw_inputs: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "known",
        "complete": False,
        "value": {"raw": raw_value, "scale": 1000, "unit": unit},
        "raw_inputs": raw_inputs,
        "basis": _BASIS,
        "period": "current",
        "gaps": list(_GAPS),
    }


def _raw_binding(module_base: Any, province_binding: Any) -> dict[str, Any]:
    keys = ("province_id", "record_id", "record_pointer", "id_address", "id_raw_hex")
    return {
        "module_base": _identity._raw_scalar(module_base),
        "province_binding": {
            key: _identity._raw_scalar(province_binding.get(key))
            for key in keys
        } if isinstance(province_binding, Mapping)
        else _identity._raw_scalar(province_binding),
    }


def _failure_reason(exc: BaseException) -> str:
    if isinstance(exc, _foreign._Failure):
        return exc.reason
    return f"READ_FAILED:{type(exc).__name__}"


def _parse_descriptor_name(
    trace: _foreign._TraceReader,
    descriptor_address: int,
    descriptor_raw: bytes,
    expected_key: str,
    forbidden: tuple[int, ...],
    label: str,
) -> dict[str, Any]:
    header = descriptor_raw[:STRING32_SIZE]
    if len(header) != STRING32_SIZE:
        raise _foreign._Failure("DESCRIPTOR_STRING32_SHORT")
    length = int.from_bytes(
        header[STRING32_LENGTH_OFFSET:STRING32_LENGTH_OFFSET + 8], "little"
    )
    capacity = int.from_bytes(
        header[STRING32_CAPACITY_OFFSET:STRING32_CAPACITY_OFFSET + 8], "little"
    )
    if length > 255:
        raise _foreign._Failure("DESCRIPTOR_NAME_LENGTH_OUT_OF_RANGE")
    if capacity < length or capacity > MAX_STRING_CAPACITY:
        raise _foreign._Failure("DESCRIPTOR_NAME_CAPACITY_INVALID")

    if capacity < 16:
        if length > 15:
            raise _foreign._Failure("DESCRIPTOR_INLINE_NAME_LENGTH_INVALID")
        payload = header[:length + 1]
        name_address = descriptor_address
        storage = "inline"
        pointer = None
    else:
        pointer = int.from_bytes(header[:8], "little", signed=False)
        pointer = _foreign._valid_pointer(pointer, "DESCRIPTOR_NAME", alignment=1)
        if pointer in forbidden:
            raise _foreign._Failure("DESCRIPTOR_NAME_POINTER_ALIAS")
        name_address = _foreign._add(pointer, 0, length + 1)
        payload = trace.exact(name_address, length + 1,
                              f"province_trade_power_inputs.{label}.key_bytes")
        storage = "heap"

    if len(payload) != length + 1 or payload[-1:] != b"\0" or b"\0" in payload[:-1]:
        raise _foreign._Failure("DESCRIPTOR_NAME_TERMINATOR_INVALID")
    try:
        decoded = payload[:-1].decode("ascii")
    except UnicodeDecodeError as exc:
        raise _foreign._Failure("DESCRIPTOR_NAME_NOT_ASCII") from exc
    if decoded != expected_key:
        raise _foreign._Failure("DESCRIPTOR_NAME_MISMATCH")
    return {
        "key": decoded,
        "expected_key": expected_key,
        "storage": storage,
        "length": length,
        "capacity": capacity,
        "header_raw_hex": header.hex(),
        "payload_address": hex(name_address),
        "payload_raw_hex": payload.hex(),
        "pointer": hex(pointer) if pointer is not None else None,
    }


def _storage_component(
    trace: _foreign._TraceReader,
    record: int,
    manager: int,
    global_address: int,
    descriptor_address: int,
    processor_cell: int,
    descriptor: dict[str, Any],
    field: str,
) -> tuple[dict[str, Any], int]:
    modifier_id, container_offset, unit = _FIELD_SPECS[field]
    object_address = _foreign._add(record, container_offset, MODIFIER_OBJECT_SIZE)
    forbidden = (
        record,
        object_address,
        manager,
        global_address,
        descriptor_address,
        processor_cell,
    )
    start = len(trace.reads)
    component = _modifier_storage.read_raw_modifier_object(
        trace,
        object_address,
        modifier_id,
        unit,
        name=field,
        forbidden_pointers=forbidden,
    )
    if not isinstance(component, Mapping):
        raise _foreign._Failure("MODIFIER_STORAGE_RESULT_INVALID")
    return dict(component), start


def _read_new_fields(
    reader: Any,
    module_base: Any,
    province_binding: Any,
    fields: tuple[str, ...],
) -> dict[str, dict[str, Any]]:
    trace = _foreign._TraceReader(reader)
    raw_base = {
        **_raw_binding(module_base, province_binding),
        "field_group": list(fields),
        "validation_errors": [],
    }
    results: dict[str, dict[str, Any]] = {}
    descriptor_states: dict[int, dict[str, Any]] = {}
    component_states: dict[str, dict[str, Any]] = {}
    global_address: int | None = None
    manager: int | None = None
    manager_raw: bytes | None = None

    try:
        base, record, binding = _identity._validate_binding(module_base, province_binding)
        province_id = binding["province_id"]
        if not 1 <= province_id <= MAX_PROVINCE_ID:
            raise _foreign._Failure("PROVINCE_ID_OUT_OF_RANGE")
        global_address = _foreign._add(base, MODIFIER_PROCESSOR_GLOBAL_RVA, 8)
        manager_raw = trace.exact(
            global_address, 8, "province_trade_power_inputs.manager_global"
        )
        manager = _foreign._valid_pointer(
            int.from_bytes(manager_raw, "little", signed=False),
            "MODIFIER_PROCESSOR_MANAGER",
        )
        raw_base.update({
            "module_base": hex(base),
            "province_id": province_id,
            "canonical_record_address": hex(record),
            "canonical_binding_echo": dict(binding),
            "modifier_processor_global_rva": hex(MODIFIER_PROCESSOR_GLOBAL_RVA),
            "modifier_processor_global_address": hex(global_address),
            "modifier_processor_global_raw_hex": manager_raw.hex(),
            "modifier_processor_manager": hex(manager),
        })
    except Exception as exc:
        reason = _failure_reason(exc)
        raw_base["validation_errors"].append({"error": reason})
        for field in fields:
            results[field] = _unknown(reason, deepcopy(raw_base))
        _attach_trace(results, trace)
        return results

    assert global_address is not None and manager is not None and manager_raw is not None
    indexes = tuple(dict.fromkeys(_FIELD_SPECS[field][0] for field in fields))
    for index in indexes:
        spec = _DESCRIPTORS[index]
        label = f"index_{index}"
        state: dict[str, Any] = {
            "index": index,
            "expected_key": spec["key"],
            "descriptor_address": None,
            "descriptor_raw_hex": None,
            "key": None,
            "processor_pointer": None,
            "fields": list(field for field in fields if _FIELD_SPECS[field][0] == index),
            "error": None,
        }
        try:
            descriptor_address = _foreign._add(
                manager, index * MODIFIER_PROCESSOR_STRIDE, MODIFIER_DESCRIPTOR_SIZE
            )
            descriptor_raw = trace.exact(
                descriptor_address, MODIFIER_DESCRIPTOR_SIZE,
                f"province_trade_power_inputs.{label}.descriptor_96",
            )
            processor_cell = descriptor_address + MODIFIER_PROCESSOR_OFFSET
            processor_raw = descriptor_raw[MODIFIER_PROCESSOR_OFFSET:
                                           MODIFIER_PROCESSOR_OFFSET + 8]
            if len(processor_raw) != 8:
                raise _foreign._Failure("DESCRIPTOR_PROCESSOR_POINTER_SHORT")
            processor_pointer = int.from_bytes(processor_raw, "little", signed=False)
            state.update({
                "descriptor_address": descriptor_address,
                "descriptor_raw": descriptor_raw,
                "descriptor_raw_hex": descriptor_raw.hex(),
                "descriptor_key_header_raw": descriptor_raw[:STRING32_SIZE],
                "processor_cell": processor_cell,
                "processor_raw": processor_raw,
                "processor_pointer": processor_pointer,
            })
            name_forbidden = (record, manager, global_address, descriptor_address,
                              processor_cell)
            key = _parse_descriptor_name(
                trace, descriptor_address, descriptor_raw, spec["key"],
                name_forbidden, label,
            )
            state["key"] = key
            if processor_pointer != 0:
                state["error"] = "MODIFIER_PROCESSOR_NON_NULL"
        except Exception as exc:
            state["error"] = _failure_reason(exc)
        descriptor_states[index] = state

        for field in state["fields"]:
            component_start = len(trace.reads)
            if state["error"] is not None:
                component_states[field] = {
                    "component": None,
                    "start": component_start,
                    "error": state["error"],
                    "descriptor_index": index,
                }
                continue
            try:
                component, storage_start = _storage_component(
                    trace, record, manager, global_address,
                    state["descriptor_address"], state["processor_cell"],
                    state, field,
                )
                component_states[field] = {
                    "component": component,
                    "start": storage_start,
                    "error": None,
                    "descriptor_index": index,
                }
            except Exception as exc:
                component_states[field] = {
                    "component": None,
                    "start": component_start,
                    "error": _failure_reason(exc),
                    "descriptor_index": index,
                }
            if trace.budget_failed:
                for remaining in state["fields"][state["fields"].index(field) + 1:]:
                    component_states[remaining] = {
                        "component": None,
                        "start": len(trace.reads),
                        "error": "SHARED_READ_BUDGET_EXCEEDED",
                        "descriptor_index": index,
                    }
                break

    global_recheck: bytes | None = None
    if not trace.budget_failed:
        try:
            global_recheck = trace.exact(
                global_address, 8,
                "province_trade_power_inputs.manager_global_recheck",
            )
            if global_recheck != manager_raw:
                for field in fields:
                    component_states[field] = {
                        **component_states.get(field, {}),
                        "error": "MODIFIER_PROCESSOR_MANAGER_CHANGED",
                    }
        except Exception as exc:
            reason = _failure_reason(exc)
            for field in fields:
                component_states[field] = {
                    **component_states.get(field, {}), "error": reason,
                }

    if not trace.budget_failed:
        for index, state in descriptor_states.items():
            if state.get("descriptor_address") is None:
                continue
            try:
                header_recheck = trace.exact(
                    state["descriptor_address"], STRING32_SIZE,
                    f"province_trade_power_inputs.index_{index}.key_header_recheck",
                )
                processor_recheck = trace.exact(
                    state["processor_cell"], 8,
                    f"province_trade_power_inputs.index_{index}.processor_recheck",
                )
                if header_recheck != state["descriptor_key_header_raw"]:
                    raise _foreign._Failure("MODIFIER_DESCRIPTOR_KEY_CHANGED")
                if processor_recheck != state["processor_raw"]:
                    raise _foreign._Failure("MODIFIER_PROCESSOR_CHANGED")
            except Exception as exc:
                reason = _failure_reason(exc)
                for field in state["fields"]:
                    component_states[field] = {
                        **component_states.get(field, {}), "error": reason,
                    }
                state["recheck_error"] = reason
                continue
            state["key_header_recheck_raw_hex"] = header_recheck.hex()
            state["processor_recheck_raw_hex"] = processor_recheck.hex()

    for field in fields:
        state = component_states.get(field, {})
        index = state.get("descriptor_index", _FIELD_SPECS[field][0])
        descriptor = descriptor_states.get(index, {})
        raw_inputs = deepcopy(raw_base)
        raw_inputs.update({
            "field": field,
            "modifier_id": index,
            "container_offset": hex(_FIELD_SPECS[field][1]),
            "unit": _FIELD_SPECS[field][2],
            "descriptor": {
                key: deepcopy(value)
                for key, value in descriptor.items()
                if key not in ("descriptor_raw", "descriptor_key_header_raw", "processor_raw")
            },
            "descriptor_raw_hex": descriptor.get("descriptor_raw_hex"),
            "descriptor_key_header_raw_hex": (
                descriptor.get("descriptor_key_header_raw", b"").hex()
                if isinstance(descriptor.get("descriptor_key_header_raw"), bytes) else None
            ),
            "processor_pointer": (hex(descriptor["processor_pointer"])
                                  if type(descriptor.get("processor_pointer")) is int else None),
            "manager_global_recheck_raw_hex": global_recheck.hex()
            if global_recheck is not None else None,
            "storage_component": deepcopy(state.get("component")),
            "reads": deepcopy(trace.reads),
            "read_budget": trace.budget(),
        })
        error = state.get("error")
        component = state.get("component")
        if error is not None:
            results[field] = _unknown(str(error), raw_inputs)
            continue
        if not isinstance(component, Mapping) or component.get("status") != "known":
            reason = (component.get("reason") if isinstance(component, Mapping)
                      else None) or "MODIFIER_STORAGE_UNKNOWN"
            results[field] = _unknown(str(reason), raw_inputs)
            continue
        raw_value = component.get("raw")
        unit = _FIELD_SPECS[field][2]
        if (type(raw_value) is not int or not -(1 << 31) <= raw_value < (1 << 31)
                or component.get("unit") != unit or component.get("scale") != 1000):
            results[field] = _unknown("MODIFIER_STORAGE_RESULT_INVALID", raw_inputs)
            continue
        results[field] = _known(raw_value, unit, raw_inputs)

    _attach_trace(results, trace)
    return results


def _attach_trace(results: dict[str, dict[str, Any]], trace: _foreign._TraceReader) -> None:
    for field in results.values():
        raw_inputs = field.get("raw_inputs")
        if isinstance(raw_inputs, dict):
            raw_inputs.setdefault("reads", deepcopy(trace.reads))
            raw_inputs.setdefault("read_budget", trace.budget())


def read_fields(
    reader: Any,
    module_base: Any,
    province_binding: Any,
    fields: tuple[str, ...] | list[str],
) -> dict[str, dict[str, Any]]:
    """Read the requested current province trade-power modifier inputs."""
    if not isinstance(fields, (tuple, list)) or len(fields) > _identity.MAX_FIELDS:
        return {}
    if any(not isinstance(field, str) for field in fields):
        return {}
    requested = tuple(fields)
    unique_fields = tuple(dict.fromkeys(requested))
    if len(unique_fields) != len(requested):
        return {field: _unknown("duplicate_field_requested") for field in unique_fields}
    if not unique_fields:
        return {}

    result_by_field: dict[str, dict[str, Any]] = {
        field: _unknown("unsupported_field")
        for field in unique_fields if field not in SUPPORTED_FIELDS
    }
    new_fields = tuple(field for field in unique_fields if field in NEW_FIELDS)
    if new_fields:
        result_by_field.update(_read_new_fields(
            reader, module_base, province_binding, new_fields
        ))
    if FIELD_PROVINCE_TRADE_POWER in unique_fields:
        result_by_field[FIELD_PROVINCE_TRADE_POWER] = _trade_power.read_fields(
            reader,
            module_base,
            province_binding,
            (FIELD_PROVINCE_TRADE_POWER,),
        )[FIELD_PROVINCE_TRADE_POWER]
    return {field: result_by_field[field] for field in unique_fields}


__all__ = [
    "FIELD_PROVINCE_TRADE_POWER",
    "FIELD_PROVINCE_TRADE_POWER_FURTHER_MODIFIER",
    "FIELD_PROVINCE_TRADE_POWER_MODIFIER",
    "FIELD_PROVINCE_TRADE_POWER_VALUE",
    "SUPPORTED_FIELDS",
    "read_fields",
]
