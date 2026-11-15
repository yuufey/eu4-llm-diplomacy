"""Bounded leaf reader for province culture/religion display inputs.

The caller supplies an already resolved canonical province record binding.
This module copies the two definition pointers, their EU4-escape String32
names, and (for religion only) the signed icon-frame input. It performs no
visibility/admission decision, process opening, native call, memory write, or
UI observation. Owner/discovery admission belongs to the caller.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from ..native_text import EU4_ESCAPE_CODEC, NativeTextError, decode_native_text_hex


FIELD_CULTURE = "G02.culture"
FIELD_RELIGION = "G02.religion"
SUPPORTED_FIELDS = (FIELD_CULTURE, FIELD_RELIGION)

PROVINCE_ID_OFFSET = 0x20
PROVINCE_RECORD_STRIDE = 0x2E10
CULTURE_POINTER_OFFSET = 0x440
RELIGION_POINTER_OFFSET = 0x448
CULTURE_NAME_OFFSET = 0x68
RELIGION_NAME_OFFSET = 0xB0
RELIGION_ICON_FRAME_OFFSET = 0x570
STRING32_SIZE = 32
STRING32_LENGTH_OFFSET = 0x10
STRING32_CAPACITY_OFFSET = 0x18
MAX_FIELDS = 16
MAX_NAME_BYTES = 128
MAX_STRING_CAPACITY = 128
MIN_USER_ADDRESS = 0x10000
MAX_USER_ADDRESS = 0x00007FFFFFFFFFFF

_HEX_RE = re.compile(r"[0-9A-Fa-f]+\Z")
_FIELD_LAYOUT = {
    FIELD_CULTURE: {
        "pointer_offset": CULTURE_POINTER_OFFSET,
        "name_offset": CULTURE_NAME_OFFSET,
        "icon_offset": None,
        "object_label": "culture",
    },
    FIELD_RELIGION: {
        "pointer_offset": RELIGION_POINTER_OFFSET,
        "name_offset": RELIGION_NAME_OFFSET,
        "icon_offset": RELIGION_ICON_FRAME_OFFSET,
        "object_label": "religion",
    },
}
_BASIS = "province_definition_string32_and_religion_icon_frame_input_only"
_GAPS = [
    "PROVINCE_VIEW_ADMISSION_AND_DISCOVERY_ARE_PARENT_OWNED",
    "OWNER_CONTROLLER_AND_DISPLAY_COLOR_NOT_READ",
    "LOCALIZED_TOOLTIP_AND_LANGUAGE_SOURCE_NOT_READ",
    "ICON_FRAME_REQUEST_IS_NOT_PROOF_OF_RENDERING",
    "NO_NATIVE_KEY_OR_ACTUAL_UI_OBSERVATION",
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


def _parse_uint(value: Any, label: str, *, maximum: int = (1 << 64) - 1) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label}_invalid")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value, 0)
        except ValueError as exc:
            raise ValueError(f"{label}_invalid") from exc
    else:
        raise ValueError(f"{label}_invalid")
    if not 0 <= parsed <= maximum:
        raise ValueError(f"{label}_out_of_range")
    return parsed


def _checked_user_range(address: int, size: int, label: str) -> tuple[int, int]:
    if type(address) is not int or type(size) is not int or size < 1:
        raise ValueError(f"{label}_range_invalid")
    end = address + size
    if (address < MIN_USER_ADDRESS or end <= address
            or end - 1 > MAX_USER_ADDRESS):
        raise ValueError(f"{label}_out_of_user_bounds")
    return address, end


def _user_pointer(value: int, label: str, *, aligned: bool = False) -> int:
    _checked_user_range(value, 1, label)
    if aligned and value & 7:
        raise ValueError(f"{label}_unaligned")
    return value


def _read_exact(reader: Any, address: int, size: int, label: str) -> bytes:
    _checked_user_range(address, size, "read")
    if callable(reader):
        result = reader(address, size, label)
    else:
        method = getattr(reader, "read", None)
        if not callable(method):
            raise ValueError("reader_read_unavailable")
        result = method(address, size, label)
    if not isinstance(result, (bytes, bytearray, memoryview)):
        raise ValueError("read_result_not_bytes")
    data = bytes(result)
    if len(data) != size:
        raise ValueError(f"short_read:{label}:{len(data)}:{size}")
    return data


def _raw_scalar(value: Any) -> Any:
    if value is None or type(value) in (str, int, bool):
        return value
    return f"<{type(value).__name__}>"


def _validate_binding(module_base: Any, province_binding: Any) -> tuple[int, int, dict[str, Any]]:
    base = _user_pointer(_parse_uint(module_base, "module_base"), "module_base")
    if not isinstance(province_binding, Mapping):
        raise ValueError("province_binding_invalid")
    province_id = province_binding.get("province_id")
    record_id = province_binding.get("record_id")
    if type(province_id) is not int or province_id <= 0:
        raise ValueError("province_id_invalid")
    if type(record_id) is not int or record_id != province_id:
        raise ValueError("province_record_id_mismatch")
    record = _user_pointer(
        _parse_uint(province_binding.get("record_pointer"), "record_pointer"),
        "record_pointer",
        aligned=True,
    )
    id_address = _user_pointer(
        _parse_uint(province_binding.get("id_address"), "id_address"),
        "id_address",
    )
    expected_id_address = record + PROVINCE_ID_OFFSET
    _checked_user_range(record, PROVINCE_RECORD_STRIDE, "province_record")
    if id_address != expected_id_address:
        raise ValueError("province_id_address_mismatch")
    id_raw_hex = province_binding.get("id_raw_hex")
    if not isinstance(id_raw_hex, str) or len(id_raw_hex) != 8 or not _HEX_RE.fullmatch(id_raw_hex):
        raise ValueError("province_id_raw_hex_invalid")
    id_raw = bytes.fromhex(id_raw_hex)
    if int.from_bytes(id_raw, "little", signed=True) != province_id:
        raise ValueError("province_id_raw_mismatch")
    normalized = {
        "province_id": province_id,
        "record_id": record_id,
        "record_pointer": hex(record),
        "id_address": hex(id_address),
        "id_raw_hex": id_raw.hex(),
    }
    return base, record, normalized


def _field_raw_base(module_base: int, binding: dict[str, Any], field: str) -> dict[str, Any]:
    return {
        "module_base": hex(module_base),
        "province_binding": dict(binding),
        "field": field,
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


def _decode_name_header(header: bytes, string_address: int, object_label: str,
                        reader: Any, raw_inputs: dict[str, Any]) -> tuple[str | None, str | None]:
    length = int.from_bytes(
        header[STRING32_LENGTH_OFFSET:STRING32_LENGTH_OFFSET + 8], "little")
    capacity = int.from_bytes(
        header[STRING32_CAPACITY_OFFSET:STRING32_CAPACITY_OFFSET + 8], "little")
    storage = "inline" if capacity < 16 else "heap"
    raw_inputs.update({
        "string32_address": hex(string_address),
        "string32_length": length,
        "string32_length_raw_hex": header[STRING32_LENGTH_OFFSET:STRING32_LENGTH_OFFSET + 8].hex(),
        "string32_capacity": capacity,
        "string32_capacity_raw_hex": header[STRING32_CAPACITY_OFFSET:STRING32_CAPACITY_OFFSET + 8].hex(),
        "string32_storage": storage,
    })
    if length == 0:
        return None, f"{object_label}_name_empty"
    if length > MAX_NAME_BYTES:
        return None, f"{object_label}_name_length_out_of_bound"
    if capacity < length:
        return None, f"{object_label}_string32_capacity_below_length"
    if capacity > MAX_STRING_CAPACITY:
        return None, f"{object_label}_string32_capacity_out_of_bound"
    if storage == "inline":
        if length > 15:
            return None, f"{object_label}_string32_inline_length_invalid"
        payload = header[:length + 1]
        raw_inputs["string32_inline_payload_raw_hex"] = payload.hex()
    else:
        heap_pointer_raw = header[:8]
        heap_pointer = int.from_bytes(heap_pointer_raw, "little")
        raw_inputs["string32_heap_pointer_raw_hex"] = heap_pointer_raw.hex()
        raw_inputs["string32_heap_pointer"] = hex(heap_pointer) if heap_pointer else None
        try:
            _user_pointer(heap_pointer, f"{object_label}_string32_heap_pointer")
            heap_range = _checked_user_range(
                heap_pointer, length + 1, f"{object_label}_string32_heap_payload")
            header_range = _checked_user_range(
                string_address, STRING32_SIZE, f"{object_label}_string32_header")
        except ValueError as exc:
            return None, str(exc)
        if heap_range[0] < header_range[1] and header_range[0] < heap_range[1]:
            return None, f"{object_label}_string32_heap_overlaps_header"
        payload = _read_part(
            reader,
            heap_pointer,
            length + 1,
            f"province_identity.{object_label}.String32_payload",
            raw_inputs,
            "string32_heap_payload_raw_hex",
        )
        if payload is None:
            return None, f"{object_label}_string32_heap_payload_read_failed"

    raw_inputs["string32_payload_raw_hex"] = payload.hex()
    if len(payload) != length + 1 or payload[-1] != 0:
        return None, f"{object_label}_string32_terminator_invalid"
    if b"\0" in payload[:length]:
        return None, f"{object_label}_string32_embedded_nul"
    name_hex = payload[:length].hex()
    raw_inputs["name_raw_hex"] = name_hex
    try:
        name = decode_native_text_hex(
            name_hex,
            codec=EU4_ESCAPE_CODEC,
            max_bytes=MAX_NAME_BYTES,
        )
    except NativeTextError as exc:
        raw_inputs["native_text_decoder"] = {
            "status": "invalid",
            "codec": EU4_ESCAPE_CODEC,
            "error_type": type(exc).__name__,
            "error": str(exc)[:160],
        }
        return None, f"{object_label}_name_decode_invalid"
    raw_inputs["native_text_decoder"] = {
        "status": "decoded",
        "codec": EU4_ESCAPE_CODEC,
        "gaps": ["COPIED_TEXT_IS_NOT_LOCALIZED_OR_A_NATIVE_KEY"],
    }
    if not name:
        return None, f"{object_label}_name_empty"
    return name, None


def _read_field(reader: Any, module_base: int, record: int,
                binding: dict[str, Any], field: str) -> dict[str, Any]:
    layout = _FIELD_LAYOUT[field]
    object_label = str(layout["object_label"])
    raw_inputs = _field_raw_base(module_base, binding, field)
    try:
        pointer_address = record + int(layout["pointer_offset"])
        _checked_user_range(pointer_address, 8, f"{object_label}_pointer")
        raw_inputs["definition_pointer_address"] = hex(pointer_address)
        pointer_raw = _read_part(
            reader,
            pointer_address,
            8,
            f"province_identity.{object_label}.definition_pointer",
            raw_inputs,
            "definition_pointer_raw_hex",
        )
        if pointer_raw is None:
            return _unknown(f"{object_label}_definition_pointer_read_failed", raw_inputs)
        definition_pointer = int.from_bytes(pointer_raw, "little")
        raw_inputs["definition_pointer"] = hex(definition_pointer) if definition_pointer else None
        if definition_pointer == 0:
            return _unknown(f"{object_label}_definition_pointer_null", raw_inputs)
        try:
            _user_pointer(definition_pointer, f"{object_label}_definition_pointer", aligned=True)
        except ValueError as exc:
            return _unknown(str(exc), raw_inputs)

        string_address = definition_pointer + int(layout["name_offset"])
        try:
            _checked_user_range(string_address, STRING32_SIZE, f"{object_label}_string32_header")
        except ValueError as exc:
            return _unknown(str(exc), raw_inputs)
        raw_inputs["string32_address"] = hex(string_address)
        header = _read_part(
            reader,
            string_address,
            STRING32_SIZE,
            f"province_identity.{object_label}.String32_header",
            raw_inputs,
            "string32_header_raw_hex",
        )

        icon_raw: bytes | None = None
        if layout["icon_offset"] is not None:
            icon_address = definition_pointer + int(layout["icon_offset"])
            try:
                _checked_user_range(icon_address, 4, f"{object_label}_icon_frame_request")
            except ValueError as exc:
                raw_inputs["icon_frame_request_address"] = hex(icon_address)
                return _unknown(str(exc), raw_inputs)
            raw_inputs["icon_frame_request_address"] = hex(icon_address)
            icon_raw = _read_part(
                reader,
                icon_address,
                4,
                "province_identity.religion.icon_frame_request",
                raw_inputs,
                "icon_frame_request_raw_hex",
            )

        if header is None:
            return _unknown(f"{object_label}_string32_header_read_failed", raw_inputs)
        name, name_error = _decode_name_header(
            header, string_address, object_label, reader, raw_inputs)
        if name_error is not None:
            return _unknown(name_error, raw_inputs)
        if name is None:
            return _unknown(f"{object_label}_name_unknown", raw_inputs)

        value: dict[str, Any] = {
            "name": {
                "text": name,
                "raw_hex": raw_inputs["name_raw_hex"],
                "encoding": EU4_ESCAPE_CODEC,
            }
        }
        if layout["icon_offset"] is not None:
            if icon_raw is None:
                return _unknown("religion_icon_frame_request_read_failed", raw_inputs)
            frame = int.from_bytes(icon_raw, "little", signed=True)
            raw_inputs["icon_frame_request_raw"] = frame
            value["icon_frame_request"] = frame
        return _known(value, raw_inputs)
    except Exception as exc:
        return _unknown(
            f"{object_label}_leaf_read_failed:{type(exc).__name__}:{str(exc)[:160]}",
            raw_inputs,
        )


def read_fields(reader: Any, module_base: Any, province_binding: Any,
                fields: tuple[str, ...] | list[str]) -> dict[str, dict[str, Any]]:
    """Read requested province display inputs through a canonical ID binding.

    The province binding must be the identity row produced by the parent
    province resolver. Unsupported fields are returned as unknown without
    issuing a memory read. Visibility, role checks, and two-pass consistency
    are owned by the caller.
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
        for field in unique_fields if field not in _FIELD_LAYOUT
    }
    supported = tuple(field for field in unique_fields if field in _FIELD_LAYOUT)
    if not supported:
        return unsupported
    try:
        base, record, binding = _validate_binding(module_base, province_binding)
    except Exception as exc:
        reason = str(exc) or type(exc).__name__
        return {
            **unsupported,
            **{field: _unknown(reason, {
                "module_base": _raw_scalar(module_base),
                "province_binding": {
                    key: _raw_scalar(province_binding.get(key))
                    for key in ("province_id", "record_id", "record_pointer", "id_address", "id_raw_hex")
                } if isinstance(province_binding, Mapping) else _raw_scalar(province_binding),
            }) for field in supported},
        }

    result = dict(unsupported)
    for field in supported:
        result[field] = _read_field(reader, base, record, binding, field)
    return result


__all__ = [
    "FIELD_CULTURE",
    "FIELD_RELIGION",
    "SUPPORTED_FIELDS",
    "CULTURE_POINTER_OFFSET",
    "RELIGION_POINTER_OFFSET",
    "CULTURE_NAME_OFFSET",
    "RELIGION_NAME_OFFSET",
    "RELIGION_ICON_FRAME_OFFSET",
    "STRING32_SIZE",
    "MAX_NAME_BYTES",
    "MAX_STRING_CAPACITY",
    "read_fields",
]
