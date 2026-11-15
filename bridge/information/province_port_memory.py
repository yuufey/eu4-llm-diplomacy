"""Bounded leaf reader for the province native has-port scope predicate.

The parent supplies an already resolved canonical province binding and owns
admission, discovery, session/profile checks, and two-pass context guards. This
leaf copies one qword from the province record and applies its native nonzero
predicate. It does not dereference the qword or infer facilities, eligibility,
estuary state, or rendered UI.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from . import province_identity_memory as _identity


FIELD_HAS_PORT = "G02.has_port"
SUPPORTED_FIELDS = (FIELD_HAS_PORT,)

PROVINCE_HAS_PORT_PREDICATE_OFFSET = 0x550
PREDICATE_SIZE = 8
MIN_PROVINCE_ID = 1
MAX_PROVINCE_ID = 0xFFFF
READ_LABEL = "province_port.has_port_scope_predicate"

_BASIS = "native_has_port_scope_predicate"
_GAPS = [
    "PROVINCE_VIEW_ADMISSION_AND_DISCOVERY_ARE_PARENT_OWNED",
    "PARENT_TWO_PASS_CONTEXT_GUARD_NOT_PERFORMED_BY_LEAF",
    "SESSION_PROFILE_AND_CODE_GUARDS_ARE_PARENT_OWNED",
    "PORT_FACILITIES_AND_ACCESS_ELIGIBILITY_NOT_READ",
    "ESTUARY_STATE_NOT_READ",
    "RENDERING_NOT_OBSERVED",
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


def _known(value: bool, raw_inputs: dict[str, Any]) -> dict[str, Any]:
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
        "field": FIELD_HAS_PORT,
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


def _read_has_port(
    reader: Any,
    module_base: int,
    record: int,
    binding: dict[str, Any],
) -> dict[str, Any]:
    raw_inputs = _raw_base(module_base, binding)
    address = record + PROVINCE_HAS_PORT_PREDICATE_OFFSET
    raw_inputs.update({
        "predicate_offset": hex(PROVINCE_HAS_PORT_PREDICATE_OFFSET),
        "predicate_address": hex(address),
        "predicate_size": PREDICATE_SIZE,
    })
    try:
        _identity._checked_user_range(
            address,
            PREDICATE_SIZE,
            "province_has_port_scope_predicate",
        )
        raw = _identity._read_exact(
            reader,
            address,
            PREDICATE_SIZE,
            READ_LABEL,
        )
        raw_value = int.from_bytes(raw, "little", signed=False)
        has_port = raw_value != 0
        raw_inputs.update({
            "predicate_raw_hex": raw.hex(),
            "predicate_raw_value": raw_value,
            "predicate_nonzero": has_port,
        })
        return _known(has_port, raw_inputs)
    except Exception as exc:
        raw_inputs["read_failures"].append({
            "label": READ_LABEL,
            "address": hex(address),
            "size": PREDICATE_SIZE,
            "error": f"{type(exc).__name__}:{str(exc)[:160]}",
        })
        return _unknown(
            f"HAS_PORT_PREDICATE_READ_FAILED:{type(exc).__name__}:{str(exc)[:160]}",
            raw_inputs,
        )


def read_fields(
    reader: Any,
    module_base: Any,
    province_binding: Any,
    fields: tuple[str, ...] | list[str],
) -> dict[str, dict[str, Any]]:
    """Read requested port-predicate fields through a canonical ID binding.

    Unsupported fields and malformed bounded field lists cause no memory read.
    This leaf does not decide observer admission or context stability.
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
        result[field] = _read_has_port(reader, base, record, binding)
    return result


__all__ = [
    "FIELD_HAS_PORT",
    "MAX_PROVINCE_ID",
    "PROVINCE_HAS_PORT_PREDICATE_OFFSET",
    "READ_LABEL",
    "SUPPORTED_FIELDS",
    "read_fields",
]
