"""Bounded leaf reader for a province's center-of-trade display inputs.

The caller supplies an already resolved canonical province binding and owns
country-role, discovery, budget, and two-pass checks. This leaf only copies the
center-of-trade pointer, its definition inputs, and a sprite request key. It
does not call game code or claim that a sprite was rendered.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .province_identity_memory import (
    MAX_FIELDS,
    PROVINCE_RECORD_STRIDE,
    _checked_user_range,
    _raw_scalar,
    _read_exact,
    _user_pointer,
    _validate_binding,
)


FIELD_CENTER_OF_TRADE = "G02.center_of_trade"
SUPPORTED_FIELDS = (FIELD_CENTER_OF_TRADE,)

PROVINCE_CENTER_OF_TRADE_POINTER_OFFSET = 0x960
CENTER_OF_TRADE_DEFINITION_POINTER_OFFSET = 0x8
DEFINITION_KIND_OFFSET = 0x10
DEFINITION_LEVEL_OFFSET = 0x14
CENTER_OF_TRADE_OBJECT_READ_END = 0x10
DEFINITION_READ_END = 0x18
MIN_PROVINCE_ID = 1
MAX_PROVINCE_ID = 0xFFFF
MAX_SIGNED_I32 = 0x7FFFFFFF

_BASIS = "province_center_of_trade_definition_type_and_level_sprite_request_only"
_GAPS = [
    "PROVINCE_VIEW_ADMISSION_AND_DISCOVERY_ARE_PARENT_OWNED",
    "OWNER_CONTROLLER_AND_DISPLAY_COLOR_NOT_READ",
    "SPRITE_KEY_IS_A_REQUEST_INPUT_NOT_PROOF_OF_RENDERING",
    "NO_TOOLTIP_OR_LOCALIZED_CENTER_OF_TRADE_TEXT_READ",
    "NO_NATIVE_CALL_OR_ACTUAL_UI_OBSERVATION",
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


def _known(value: dict[str, Any], raw_inputs: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "known",
        "complete": False,
        "value": value,
        "raw_inputs": raw_inputs,
        "basis": _BASIS,
        "gaps": list(_GAPS),
    }


def _overlaps(first: tuple[int, int], second: tuple[int, int]) -> bool:
    return first[0] < second[1] and second[0] < first[1]


def _raw_binding(module_base: Any, province_binding: Any) -> dict[str, Any]:
    return {
        "module_base": _raw_scalar(module_base),
        "province_binding": {
            key: _raw_scalar(province_binding.get(key))
            for key in (
                "province_id",
                "record_id",
                "record_pointer",
                "id_address",
                "id_raw_hex",
            )
        } if isinstance(province_binding, Mapping) else _raw_scalar(province_binding),
    }


def _raw_base(module_base: int, binding: dict[str, Any]) -> dict[str, Any]:
    return {
        "module_base": hex(module_base),
        "province_binding": dict(binding),
        "field": FIELD_CENTER_OF_TRADE,
        "read_failures": [],
    }


def _read_part(reader: Any, address: int, size: int, label: str,
               raw_inputs: dict[str, Any], raw_key: str) -> bytes | None:
    try:
        data = _read_exact(reader, address, size, label)
    except Exception as exc:
        raw_inputs["read_failures"].append({
            "label": label,
            "address": hex(address) if type(address) is int else None,
            "size": size,
            "error": f"{type(exc).__name__}:{str(exc)[:160]}",
        })
        return None
    raw_inputs[raw_key] = data.hex()
    return data


def _validate_province_identity(module_base: Any, province_binding: Any
                                ) -> tuple[int, int, dict[str, Any]]:
    base, record, binding = _validate_binding(module_base, province_binding)
    province_id = binding["province_id"]
    if not MIN_PROVINCE_ID <= province_id <= MAX_PROVINCE_ID:
        raise ValueError("province_id_out_of_supported_range")
    return base, record, binding


def _read_center_of_trade(reader: Any, module_base: int, record: int,
                          binding: dict[str, Any]) -> dict[str, Any]:
    raw_inputs = _raw_base(module_base, binding)
    record_range = _checked_user_range(record, PROVINCE_RECORD_STRIDE, "province_record")
    pointer_address = record + PROVINCE_CENTER_OF_TRADE_POINTER_OFFSET
    raw_inputs["center_of_trade_pointer_address"] = hex(pointer_address)

    pointer_raw = _read_part(
        reader,
        pointer_address,
        8,
        "province_cot.center_of_trade_pointer",
        raw_inputs,
        "center_of_trade_pointer_raw_hex",
    )
    if pointer_raw is None:
        return _unknown("center_of_trade_pointer_read_failed", raw_inputs)

    center_of_trade = int.from_bytes(pointer_raw, "little", signed=False)
    raw_inputs["center_of_trade_pointer"] = hex(center_of_trade) if center_of_trade else None
    if center_of_trade == 0:
        raw_inputs["definition_pointer_address"] = None
        raw_inputs["definition_pointer_raw_hex"] = None
        raw_inputs["definition_pointer"] = None
        raw_inputs["definition_kind_address"] = None
        raw_inputs["definition_kind_raw_hex"] = None
        raw_inputs["definition_kind_raw"] = None
        raw_inputs["definition_level_address"] = None
        raw_inputs["definition_level_raw_hex"] = None
        raw_inputs["definition_level"] = None
        raw_inputs["branch"] = "null_center_of_trade_pointer"
        return _known({"present": False, "level": 0}, raw_inputs)

    try:
        _user_pointer(center_of_trade, "center_of_trade_pointer", aligned=True)
        center_range = _checked_user_range(
            center_of_trade,
            CENTER_OF_TRADE_OBJECT_READ_END,
            "center_of_trade_object",
        )
        if _overlaps(center_range, record_range):
            raise ValueError("center_of_trade_object_overlaps_province_record")
        definition_pointer_address = center_of_trade + CENTER_OF_TRADE_DEFINITION_POINTER_OFFSET
        _checked_user_range(
            definition_pointer_address,
            8,
            "center_of_trade_definition_pointer",
        )
    except ValueError as exc:
        raw_inputs["branch"] = "invalid_center_of_trade_pointer"
        raw_inputs["definition_pointer_address"] = None
        raw_inputs["definition_pointer_raw_hex"] = None
        raw_inputs["definition_pointer"] = None
        raw_inputs["definition_kind_address"] = None
        raw_inputs["definition_kind_raw_hex"] = None
        raw_inputs["definition_kind_raw"] = None
        raw_inputs["definition_level_address"] = None
        raw_inputs["definition_level_raw_hex"] = None
        raw_inputs["definition_level"] = None
        return _unknown(str(exc), raw_inputs)

    raw_inputs["center_of_trade_object_range"] = [hex(center_range[0]), hex(center_range[1])]
    raw_inputs["definition_pointer_address"] = hex(definition_pointer_address)
    definition_raw = _read_part(
        reader,
        definition_pointer_address,
        8,
        "province_cot.definition_pointer",
        raw_inputs,
        "definition_pointer_raw_hex",
    )
    if definition_raw is None:
        raw_inputs["definition_pointer"] = None
        raw_inputs["definition_kind_address"] = None
        raw_inputs["definition_kind_raw_hex"] = None
        raw_inputs["definition_kind_raw"] = None
        raw_inputs["definition_level_address"] = None
        raw_inputs["definition_level_raw_hex"] = None
        raw_inputs["definition_level"] = None
        raw_inputs["branch"] = "definition_pointer_read_failed"
        return _unknown("center_of_trade_definition_pointer_read_failed", raw_inputs)

    definition_pointer = int.from_bytes(definition_raw, "little", signed=False)
    raw_inputs["definition_pointer"] = hex(definition_pointer) if definition_pointer else None
    if definition_pointer == 0:
        raw_inputs["definition_kind_address"] = None
        raw_inputs["definition_kind_raw_hex"] = None
        raw_inputs["definition_kind_raw"] = None
        raw_inputs["definition_level_address"] = None
        raw_inputs["definition_level_raw_hex"] = None
        raw_inputs["definition_level"] = None
        raw_inputs["branch"] = "null_definition_pointer"
        return _unknown("center_of_trade_definition_pointer_null", raw_inputs)

    try:
        _user_pointer(definition_pointer, "center_of_trade_definition_pointer", aligned=True)
        definition_range = _checked_user_range(
            definition_pointer,
            DEFINITION_READ_END,
            "center_of_trade_definition",
        )
        if definition_pointer in (center_of_trade, record):
            raise ValueError("center_of_trade_definition_pointer_alias")
        if _overlaps(definition_range, center_range):
            raise ValueError("center_of_trade_definition_overlaps_object")
        if _overlaps(definition_range, record_range):
            raise ValueError("center_of_trade_definition_overlaps_province_record")
    except ValueError as exc:
        raw_inputs["definition_kind_address"] = None
        raw_inputs["definition_kind_raw_hex"] = None
        raw_inputs["definition_kind_raw"] = None
        raw_inputs["definition_level_address"] = None
        raw_inputs["definition_level_raw_hex"] = None
        raw_inputs["definition_level"] = None
        raw_inputs["branch"] = "invalid_definition_pointer"
        return _unknown(str(exc), raw_inputs)

    type_address = definition_pointer + DEFINITION_KIND_OFFSET
    level_address = definition_pointer + DEFINITION_LEVEL_OFFSET
    raw_inputs["definition_range"] = [hex(definition_range[0]), hex(definition_range[1])]
    raw_inputs["definition_kind_address"] = hex(type_address)
    kind_raw = _read_part(
        reader,
        type_address,
        4,
        "province_cot.definition_kind",
        raw_inputs,
        "definition_kind_raw_hex",
    )
    raw_inputs["definition_level_address"] = hex(level_address)
    level_raw = _read_part(
        reader,
        level_address,
        4,
        "province_cot.definition_level",
        raw_inputs,
        "definition_level_raw_hex",
    )
    if kind_raw is None or level_raw is None:
        raw_inputs["definition_kind_raw"] = (
            int.from_bytes(kind_raw, "little", signed=True) if kind_raw is not None else None
        )
        raw_inputs["definition_level"] = (
            int.from_bytes(level_raw, "little", signed=True) if level_raw is not None else None
        )
        raw_inputs["branch"] = "definition_scalar_read_failed"
        return _unknown("center_of_trade_definition_scalar_read_failed", raw_inputs)

    kind = int.from_bytes(kind_raw, "little", signed=True)
    level = int.from_bytes(level_raw, "little", signed=True)
    raw_inputs["definition_kind_raw"] = kind
    raw_inputs["definition_level"] = level
    raw_inputs["branch"] = "nonnull_definition"
    if level <= 0:
        return _unknown("center_of_trade_level_not_positive", raw_inputs)
    if level > MAX_SIGNED_I32:
        return _unknown("center_of_trade_level_out_of_range", raw_inputs)

    kind_name = "coastal" if kind == 1 else "inland"
    sprite_key = f"GFX_center_of_trade_{kind_name}_{level}"
    raw_inputs["sprite_key"] = sprite_key
    return _known({
        "present": True,
        "level": level,
        "kind": kind_name,
        "sprite_key": sprite_key,
    }, raw_inputs)


def read_fields(reader: Any, module_base: Any, province_binding: Any,
                fields: tuple[str, ...] | list[str]) -> dict[str, dict[str, Any]]:
    """Read the requested province center-of-trade display input.

    The binding must be the canonical row supplied by the parent province
    resolver. This leaf does not decide actor visibility or discovery.
    """
    if not isinstance(fields, (tuple, list)) or len(fields) > MAX_FIELDS:
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
        result[field] = _read_center_of_trade(reader, base, record, binding)
    return result


__all__ = [
    "FIELD_CENTER_OF_TRADE",
    "MAX_PROVINCE_ID",
    "PROVINCE_CENTER_OF_TRADE_POINTER_OFFSET",
    "read_fields",
]
