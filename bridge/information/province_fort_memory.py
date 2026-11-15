"""Bounded leaf reader for the native fort-level scope-trigger input.

Ordinary B23 evidence maps native ``fort_level`` token 0x2963 through the
constructor at RVA 0xba1140. The bounded evaluation window loads a signed dword from
``[province + 0x2de0]`` and compares it with the selector value. This leaf
returns that one signed integer through an already resolved canonical province
binding; it does not evaluate the trigger or establish complete fort state.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from . import province_identity_memory as _identity


FIELD_FORT_LEVEL = "G02.fort_level"
SUPPORTED_FIELDS = (FIELD_FORT_LEVEL,)

PROVINCE_FORT_LEVEL_OFFSET = 0x2DE0
FORT_LEVEL_SIZE = 4
MIN_PROVINCE_ID = 1
MAX_PROVINCE_ID = 0xFFFF
READ_LABEL = "province_fort.fort_level"

_BASIS = "native_fort_level_scope_trigger_input"
_GAPS = [
    "PROVINCE_VIEW_ADMISSION_AND_DISCOVERY_ARE_PARENT_OWNED",
    "PARENT_TWO_PASS_CONTEXT_GUARD_NOT_PERFORMED_BY_LEAF",
    "SESSION_PROFILE_AND_CODE_GUARDS_ARE_PARENT_OWNED",
    "CURRENT_SCOPE_TRIGGER_INPUT_ONLY_NOT_COMPLETE_FORT_STATE",
    "GARRISON_AND_MAINTENANCE_SEMANTICS_NOT_CLOSED",
    "CAPITAL_FORT_SEMANTICS_NOT_CLOSED",
]


def _unknown(reason: str, raw_inputs: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "status": "unknown",
        "complete": False,
        "reason": reason,
        "raw_inputs": raw_inputs if raw_inputs is not None else {},
        "basis": _BASIS,
        "gaps": list(_GAPS),
    }


def _known(value: int, raw_inputs: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "known",
        "complete": False,
        "value": value,
        "raw_inputs": raw_inputs,
        "basis": _BASIS,
        "gaps": list(_GAPS),
    }


def _raw_binding(module_base: Any, province_binding: Any) -> dict[str, Any]:
    return {
        "module_base": _identity._raw_scalar(module_base),
        "province_binding": {
            key: _identity._raw_scalar(province_binding.get(key))
            for key in (
                "province_id",
                "record_id",
                "record_pointer",
                "id_address",
                "id_raw_hex",
            )
        } if isinstance(province_binding, Mapping) else _identity._raw_scalar(province_binding),
    }


def _raw_base(module_base: int, binding: dict[str, Any]) -> dict[str, Any]:
    return {
        "module_base": hex(module_base),
        "province_binding": dict(binding),
        "field": FIELD_FORT_LEVEL,
        "read_failures": [],
    }


def _validate_province_identity(
    module_base: Any,
    province_binding: Any,
) -> tuple[int, int, dict[str, Any]]:
    base, record, binding = _identity._validate_binding(module_base, province_binding)
    province_id = binding["province_id"]
    if not MIN_PROVINCE_ID <= province_id <= MAX_PROVINCE_ID:
        raise ValueError("province_id_out_of_supported_range")
    return base, record, binding


def _read_fort_level(
    reader: Any,
    module_base: int,
    record: int,
    binding: dict[str, Any],
) -> dict[str, Any]:
    raw_inputs = _raw_base(module_base, binding)
    address = record + PROVINCE_FORT_LEVEL_OFFSET
    raw_inputs.update({
        "fort_level_offset": hex(PROVINCE_FORT_LEVEL_OFFSET),
        "fort_level_address": hex(address),
        "fort_level_size": FORT_LEVEL_SIZE,
    })
    try:
        _identity._checked_user_range(
            address,
            FORT_LEVEL_SIZE,
            "province_fort_level",
        )
        raw = _identity._read_exact(
            reader,
            address,
            FORT_LEVEL_SIZE,
            READ_LABEL,
        )
        value = int.from_bytes(raw, "little", signed=True)
        raw_inputs.update({
            "fort_level_raw_hex": raw.hex(),
            "fort_level_raw_signed_i32": value,
        })
        return _known(value, raw_inputs)
    except Exception as exc:
        raw_inputs["read_failures"].append({
            "label": READ_LABEL,
            "address": hex(address),
            "size": FORT_LEVEL_SIZE,
            "error": f"{type(exc).__name__}:{str(exc)[:160]}",
        })
        return _unknown(
            f"FORT_LEVEL_READ_FAILED:{type(exc).__name__}:{str(exc)[:160]}",
            raw_inputs,
        )


def read_fields(
    reader: Any,
    module_base: Any,
    province_binding: Any,
    fields: tuple[str, ...] | list[str],
) -> dict[str, dict[str, Any]]:
    """Read requested fort-level inputs through a canonical ID binding.

    Unsupported fields and malformed bounded field lists cause no memory
    read. Admission, discovery, and context stability remain parent-owned.
    """
    if not isinstance(fields, (tuple, list)) or len(fields) > _identity.MAX_FIELDS:
        return {}
    if any(not isinstance(field, str) for field in fields):
        return {}
    unique_fields = tuple(dict.fromkeys(fields))
    if len(unique_fields) != len(fields):
        return {field: _unknown("duplicate_field_requested") for field in unique_fields}
    if not unique_fields:
        return {}

    unsupported = {
        field: _unknown("unsupported_field")
        for field in unique_fields if field not in SUPPORTED_FIELDS
    }
    supported = tuple(field for field in unique_fields if field in SUPPORTED_FIELDS)
    if not supported:
        return unsupported

    try:
        base, record, binding = _validate_province_identity(module_base, province_binding)
    except Exception as exc:
        reason = str(exc) or type(exc).__name__
        raw_inputs = _raw_binding(module_base, province_binding)
        return {
            **unsupported,
            **{field: _unknown(reason, raw_inputs) for field in supported},
        }

    result = dict(unsupported)
    for field in supported:
        result[field] = _read_fort_level(reader, base, record, binding)
    return result


__all__ = [
    "FIELD_FORT_LEVEL",
    "FORT_LEVEL_SIZE",
    "MAX_PROVINCE_ID",
    "PROVINCE_FORT_LEVEL_OFFSET",
    "READ_LABEL",
    "SUPPORTED_FIELDS",
    "read_fields",
]
