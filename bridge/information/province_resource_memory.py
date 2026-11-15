"""Bounded leaf for province resource localization-key and icon-index inputs.

The caller supplies a canonical province binding. This reader copies the
resource definition pointer, its ASCII String32 key, and the signed icon/table
index. It does not localize the key, read price/latent-resource data, or infer
UI visibility or rendering.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from . import province_identity_memory as _identity


FIELD_RESOURCE = "G02.resource"
SUPPORTED_FIELDS = (FIELD_RESOURCE,)

RESOURCE_POINTER_OFFSET = 0x458
RESOURCE_KEY_OFFSET = 0x18
RESOURCE_ICON_INDEX_OFFSET = 0x78
STRING32_SIZE = 32
STRING32_LENGTH_OFFSET = 0x10
STRING32_CAPACITY_OFFSET = 0x18
MAX_KEY_BYTES = 128
MAX_STRING_CAPACITY = 128
PROVINCE_ID_MAX = 65535
PROVINCE_RECORD_STRIDE = _identity.PROVINCE_RECORD_STRIDE
MAX_FIELDS = _identity.MAX_FIELDS
_KEY_RE = re.compile(rb"[A-Za-z0-9_.:-]{1,128}\Z")

_BASIS = "province_resource_definition_localization_key_and_icon_index"
_GAPS = [
    "LOCALIZATION_KEY_IS_NOT_A_TRANSLATED_NAME",
    "ICON_INDEX_IS_NOT_PROOF_OF_FRAME_OR_RENDERING",
    "RESOURCE_PRICE_AND_LATENT_RESOURCE_NOT_READ",
    "DISCOVERY_ROLE_AND_TWO_PASS_CONSISTENCY_ARE_PARENT_OWNED",
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


def _read_part(reader: Any, address: int, size: int, label: str,
               raw_inputs: dict[str, Any], raw_key: str) -> bytes | None:
    try:
        data = _identity._read_exact(reader, address, size, label)
    except Exception as exc:
        raw_inputs.setdefault("read_failures", []).append({
            "label": label,
            "address": hex(address) if type(address) is int else None,
            "size": size,
            "error": f"{type(exc).__name__}:{str(exc)[:160]}",
        })
        return None
    raw_inputs[raw_key] = data.hex()
    return data


def _overlaps(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def _read_resource(reader: Any, base: int, province_binding: Any) -> dict[str, Any]:
    raw_inputs: dict[str, Any] = {
        "module_base": _identity._raw_scalar(base),
        "province_binding": {},
        "field": FIELD_RESOURCE,
        "resource_pointer_offset": hex(RESOURCE_POINTER_OFFSET),
        "resource_key_offset": hex(RESOURCE_KEY_OFFSET),
        "resource_icon_index_offset": hex(RESOURCE_ICON_INDEX_OFFSET),
        "read_failures": [],
    }
    try:
        normalized_base, record, normalized_binding = _identity._validate_binding(base, province_binding)
    except Exception as exc:
        raw_inputs["province_binding"] = {
            key: _identity._raw_scalar(province_binding.get(key))
            for key in ("province_id", "record_id", "record_pointer", "id_address", "id_raw_hex")
        } if isinstance(province_binding, Mapping) else _identity._raw_scalar(province_binding)
        return _unknown(str(exc) or type(exc).__name__, raw_inputs)
    raw_inputs["module_base"] = hex(normalized_base)
    raw_inputs["province_binding"] = normalized_binding
    province_id = normalized_binding["province_id"]
    if province_id > PROVINCE_ID_MAX:
        return _unknown("province_id_out_of_supported_range", raw_inputs)

    record_range = (record, record + PROVINCE_RECORD_STRIDE)
    try:
        pointer_address = record + RESOURCE_POINTER_OFFSET
        pointer_range = _identity._checked_user_range(pointer_address, 8, "resource_pointer_slot")
    except Exception as exc:
        return _unknown(str(exc) or type(exc).__name__, raw_inputs)
    raw_inputs["resource_pointer_address"] = hex(pointer_address)
    pointer_raw = _read_part(reader, pointer_address, 8, "province_resource.definition_pointer",
                             raw_inputs, "resource_pointer_raw_hex")
    if pointer_raw is None:
        return _unknown("resource_definition_pointer_read_failed", raw_inputs)
    definition = int.from_bytes(pointer_raw, "little")
    raw_inputs["resource_definition_pointer"] = hex(definition) if definition else None
    if definition == 0:
        return _unknown("resource_definition_pointer_null", raw_inputs)
    try:
        _identity._user_pointer(definition, "resource_definition_pointer", aligned=True)
        definition_extent = _identity._checked_user_range(
            definition, RESOURCE_ICON_INDEX_OFFSET + 4, "resource_definition_extent")
        if _overlaps(definition_extent, record_range):
            return _unknown("resource_definition_aliases_province_record", raw_inputs)
    except Exception as exc:
        return _unknown(str(exc) or type(exc).__name__, raw_inputs)

    key_header_address = definition + RESOURCE_KEY_OFFSET
    icon_index_address = definition + RESOURCE_ICON_INDEX_OFFSET
    try:
        key_header_range = _identity._checked_user_range(
            key_header_address, STRING32_SIZE, "resource_key_header")
        icon_index_range = _identity._checked_user_range(icon_index_address, 4, "resource_icon_index")
        if (_overlaps(key_header_range, record_range) or _overlaps(icon_index_range, record_range)
                or _overlaps(key_header_range, pointer_range)
                or _overlaps(icon_index_range, pointer_range)
                or _overlaps(key_header_range, icon_index_range)):
            return _unknown("resource_header_alias", raw_inputs)
    except Exception as exc:
        return _unknown(str(exc) or type(exc).__name__, raw_inputs)
    raw_inputs["resource_key_header_address"] = hex(key_header_address)
    header = _read_part(reader, key_header_address, STRING32_SIZE,
                        "province_resource.String32_header", raw_inputs,
                        "string32_header_raw_hex")
    if header is None:
        return _unknown("resource_string32_header_read_failed", raw_inputs)

    length = int.from_bytes(header[STRING32_LENGTH_OFFSET:STRING32_LENGTH_OFFSET + 8], "little")
    capacity = int.from_bytes(header[STRING32_CAPACITY_OFFSET:STRING32_CAPACITY_OFFSET + 8], "little")
    storage = "inline" if capacity < 16 else "heap"
    raw_inputs.update({
        "string32_length": length,
        "string32_length_raw_hex": header[STRING32_LENGTH_OFFSET:STRING32_LENGTH_OFFSET + 8].hex(),
        "string32_capacity": capacity,
        "string32_capacity_raw_hex": header[STRING32_CAPACITY_OFFSET:STRING32_CAPACITY_OFFSET + 8].hex(),
        "string32_storage": storage,
    })
    if length < 1 or length > MAX_KEY_BYTES:
        return _unknown("resource_key_length_out_of_range", raw_inputs)
    if capacity < length or capacity > MAX_STRING_CAPACITY:
        return _unknown("resource_string32_capacity_invalid", raw_inputs)
    if storage == "inline":
        if length > 15:
            return _unknown("resource_string32_inline_length_invalid", raw_inputs)
        payload = header[:length + 1]
        raw_inputs["string32_inline_payload_raw_hex"] = payload.hex()
    else:
        heap_pointer_raw = header[:8]
        heap_pointer = int.from_bytes(heap_pointer_raw, "little")
        raw_inputs["string32_heap_pointer_raw_hex"] = heap_pointer_raw.hex()
        raw_inputs["string32_heap_pointer"] = hex(heap_pointer) if heap_pointer else None
        try:
            _identity._user_pointer(heap_pointer, "resource_string32_heap_pointer")
            heap_range = _identity._checked_user_range(
                heap_pointer, length + 1, "resource_string32_heap_payload")
        except Exception as exc:
            return _unknown(str(exc) or type(exc).__name__, raw_inputs)
        if (_overlaps(heap_range, key_header_range) or _overlaps(heap_range, definition_extent)
                or _overlaps(heap_range, record_range) or _overlaps(heap_range, pointer_range)):
            return _unknown("resource_string32_heap_alias", raw_inputs)
        payload = _read_part(reader, heap_pointer, length + 1,
                             "province_resource.String32_payload", raw_inputs,
                             "string32_heap_payload_raw_hex")
        if payload is None:
            return _unknown("resource_string32_payload_read_failed", raw_inputs)

    raw_inputs["string32_payload_raw_hex"] = payload.hex()
    if len(payload) != length + 1 or payload[-1] != 0:
        return _unknown("resource_string32_terminator_invalid", raw_inputs)
    key_bytes = payload[:length]
    if b"\0" in key_bytes:
        return _unknown("resource_string32_embedded_nul", raw_inputs)
    raw_inputs["localization_key_raw_hex"] = key_bytes.hex()
    if not _KEY_RE.fullmatch(key_bytes):
        return _unknown("resource_localization_key_ascii_grammar_invalid", raw_inputs)
    localization_key = key_bytes.decode("ascii")
    raw_inputs["localization_key_ascii"] = localization_key

    raw_inputs["icon_index_address"] = hex(icon_index_address)
    icon_raw = _read_part(reader, icon_index_address, 4, "province_resource.icon_index",
                          raw_inputs, "icon_index_raw_hex")
    if icon_raw is None:
        return _unknown("resource_icon_index_read_failed", raw_inputs)
    icon_index = int.from_bytes(icon_raw, "little", signed=True)
    raw_inputs["icon_index_signed_i32"] = icon_index
    return _known({"localization_key": localization_key, "icon_index": icon_index}, raw_inputs)


def read_fields(reader: Any, base: Any, binding: Any,
                fields: tuple[str, ...] | list[str]) -> dict[str, dict[str, Any]]:
    """Read only requested resource identity inputs from an already bound record.

    Discovery/admission, process ownership, and two-pass stability belong to
    the parent capture. Unsupported fields never cause a read.
    """
    if not isinstance(fields, (tuple, list)) or len(fields) > MAX_FIELDS:
        return {}
    if any(type(field) is not str for field in fields):
        return {}
    unique = tuple(dict.fromkeys(fields))
    if len(unique) != len(fields):
        return {field: _unknown("duplicate_field_requested") for field in unique}
    if not unique:
        return {}
    result = {field: _unknown("unsupported_field") for field in unique if field != FIELD_RESOURCE}
    if FIELD_RESOURCE in unique:
        result[FIELD_RESOURCE] = _read_resource(reader, base, binding)
    return {field: result[field] for field in unique}


__all__ = ["FIELD_RESOURCE", "SUPPORTED_FIELDS", "read_fields"]
