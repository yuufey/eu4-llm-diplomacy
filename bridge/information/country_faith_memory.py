"""Bounded leaf reader for the selected country's primary-religion inputs.

This module only follows an already validated country binding and copies a
small EU4Escape String32 plus the icon-frame argument used by the
selected-country view. The copied string is treated as display-name text, not
as a religion configuration key or ID. This module does not open a process,
perform admission, call native code, or claim that a UI element was rendered.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from ..native_text import EU4_ESCAPE_CODEC, NativeTextError, decode_native_text_hex


FIELD_ID = "S02.faith"
COUNTRY_RELIGION_POINTER_OFFSET = 0xF30
RELIGION_KEY_OFFSET = 0xB0
RELIGION_ICON_FRAME_OFFSET = 0x570
STRING32_SIZE = 32
STRING32_LENGTH_OFFSET = 0x10
STRING32_CAPACITY_OFFSET = 0x18
RELIGION_NAME_OFFSET = RELIGION_KEY_OFFSET
MAX_NAME_BYTES = 128
# Compatibility alias for the old layout profile. This is a String32 byte
# bound; the copied text is not a religion configuration key.
MAX_KEY_BYTES = MAX_NAME_BYTES
MAX_STRING_CAPACITY = 128
MAX_USER_ADDRESS = 0x00007FFFFFFFFFFF
MIN_USER_ADDRESS = 0x10000

_TAG_RE = re.compile(r"[A-Z0-9]{3}\Z")


def _unknown(reason: str, raw_inputs: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "status": "unknown",
        "complete": False,
        "reason": reason,
        "raw_inputs": raw_inputs if raw_inputs is not None else {},
        "basis": "bounded_primary_religion_name_string32_and_icon_setter_input",
        "gaps": [
            "PRIMARY_RELIGION_CONFIGURATION_KEY_AND_ID_NOT_READ",
            "LOCALIZED_TOOLTIP_AND_LANGUAGE_SOURCE_NOT_READ",
            "ICON_FRAME_NOT_RENDERED_OR_OBSERVED",
            "RELIGION_GROUP_AND_FAITH_RULES_NOT_READ",
            "CALLER_ADMISSION_IS_PARENT_OWNED",
        ],
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


def _user_pointer(value: int, label: str, *, aligned: bool = False) -> int:
    if not MIN_USER_ADDRESS <= value <= MAX_USER_ADDRESS:
        raise ValueError(f"{label}_invalid")
    if aligned and value & 7:
        raise ValueError(f"{label}_unaligned")
    return value


def _read_exact(reader: Any, address: int, size: int, label: str) -> bytes:
    if not isinstance(address, int) or not isinstance(size, int) or size < 1:
        raise ValueError("read_range_invalid")
    end = address + size - 1
    if address < MIN_USER_ADDRESS or end > MAX_USER_ADDRESS or end < address:
        raise ValueError("read_range_out_of_user_bounds")
    if callable(reader):
        result = reader(address, size, label)
    else:
        method = getattr(reader, "read", None)
        if not callable(method):
            raise ValueError("limiter_read_unavailable")
        result = method(address, size, label)
    if not isinstance(result, (bytes, bytearray, memoryview)):
        raise ValueError("read_result_not_bytes")
    data = bytes(result)
    if len(data) != size:
        raise ValueError(f"short_read:{label}:{len(data)}:{size}")
    return data


def _binding(target_binding: Any) -> tuple[int, dict[str, Any]]:
    if not isinstance(target_binding, Mapping):
        raise ValueError("target_binding_invalid")
    tag = target_binding.get("tag")
    if not isinstance(tag, str) or not _TAG_RE.fullmatch(tag):
        raise ValueError("target_binding_tag_invalid")
    slot = target_binding.get("slot")
    if isinstance(slot, bool) or not isinstance(slot, int) or not 0 <= slot < 4096:
        raise ValueError("target_binding_slot_invalid")
    pointer = _user_pointer(
        _parse_uint(target_binding.get("country_pointer"), "country_pointer"),
        "country_pointer",
        aligned=True,
    )
    fullref = _parse_uint(target_binding.get("fullref"), "country_fullref")
    if ((fullref >> 32) & 0xFFFF) != slot:
        raise ValueError("target_binding_fullref_slot_mismatch")
    tag_bytes = (fullref & 0xFFFFFF).to_bytes(3, "little")
    try:
        fullref_tag = tag_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("target_binding_fullref_tag_invalid") from exc
    if fullref_tag != tag:
        raise ValueError("target_binding_fullref_tag_mismatch")
    expected_raw = fullref.to_bytes(8, "little").hex()
    supplied_raw = target_binding.get("fullref_raw_hex")
    if supplied_raw is not None and supplied_raw != expected_raw:
        raise ValueError("target_binding_fullref_raw_mismatch")
    retained = {
        "tag": tag,
        "slot": slot,
        "country_pointer": hex(pointer),
        "fullref": hex(fullref),
        "fullref_raw_hex": expected_raw,
        "country_fullref_address": target_binding.get("country_fullref_address"),
        "table_entry_address": target_binding.get("table_entry_address"),
        "table_entry_raw_hex": target_binding.get("table_entry_raw_hex"),
    }
    return pointer, retained


def _read_faith(reader: Any, module_base: int, target_binding: Any) -> dict[str, Any]:
    raw_inputs: dict[str, Any] = {"read_failures": []}
    try:
        base = _user_pointer(_parse_uint(module_base, "module_base"), "module_base")
        raw_inputs["module_base"] = hex(base)
        country_pointer, country_binding = _binding(target_binding)
        raw_inputs["country_binding"] = country_binding
        raw_inputs["country_pointer"] = hex(country_pointer)
    except Exception as exc:
        return _unknown(str(exc) or type(exc).__name__, raw_inputs)

    def read_part(address: int, size: int, label: str, raw_key: str) -> bytes | None:
        try:
            value = _read_exact(reader, address, size, label)
        except Exception as exc:
            raw_inputs["read_failures"].append({
                "label": label,
                "address": hex(address) if isinstance(address, int) else None,
                "size": size,
                "error": f"{type(exc).__name__}:{str(exc)[:160]}",
            })
            return None
        raw_inputs[raw_key] = value.hex()
        return value

    try:
        religion_pointer_address = country_pointer + COUNTRY_RELIGION_POINTER_OFFSET
        religion_pointer_raw = read_part(
            religion_pointer_address,
            8,
            "country_faith.primary_religion_pointer",
            "primary_religion_pointer_raw_hex",
        )
        if religion_pointer_raw is None:
            return _unknown("primary_religion_pointer_read_failed", raw_inputs)
        religion_pointer = int.from_bytes(religion_pointer_raw, "little")
        raw_inputs["primary_religion_pointer"] = hex(religion_pointer) if religion_pointer else None
        if religion_pointer == 0:
            return _unknown("primary_religion_pointer_null", raw_inputs)
        try:
            _user_pointer(religion_pointer, "primary_religion_pointer", aligned=True)
        except ValueError as exc:
            return _unknown(str(exc), raw_inputs)

        string_address = religion_pointer + RELIGION_NAME_OFFSET
        icon_address = religion_pointer + RELIGION_ICON_FRAME_OFFSET
        raw_inputs["string32_address"] = hex(string_address)
        raw_inputs["icon_frame_request_address"] = hex(icon_address)

        # Keep both independent raw inputs when one read fails, so an unknown
        # string does not discard an available icon-frame request (or vice
        # versa).
        header = read_part(
            string_address,
            STRING32_SIZE,
            "country_faith.primary_religion.String32_header",
            "string32_header_raw_hex",
        )
        icon_raw = read_part(
            icon_address,
            4,
            "country_faith.primary_religion.icon_frame_request",
            "icon_frame_request_raw_hex",
        )
        if icon_raw is not None:
            raw_inputs["icon_frame_request_raw"] = int.from_bytes(icon_raw, "little")

        name: str | None = None
        name_reason: str | None = None
        if header is not None:
            length = int.from_bytes(
                header[STRING32_LENGTH_OFFSET:STRING32_LENGTH_OFFSET + 8], "little")
            capacity = int.from_bytes(
                header[STRING32_CAPACITY_OFFSET:STRING32_CAPACITY_OFFSET + 8], "little")
            storage = "inline" if capacity < 16 else "heap"
            raw_inputs["string32_length_raw_hex"] = header[0x10:0x18].hex()
            raw_inputs["string32_capacity_raw_hex"] = header[0x18:0x20].hex()
            raw_inputs["string32_length"] = length
            raw_inputs["string32_capacity"] = capacity
            raw_inputs["string32_storage"] = storage

            if length == 0:
                name_reason = "primary_religion_name_empty"
            elif length > MAX_NAME_BYTES:
                name_reason = "primary_religion_name_length_out_of_bound"
            elif capacity < length:
                name_reason = "primary_religion_string32_capacity_below_length"
            elif capacity > MAX_STRING_CAPACITY:
                name_reason = "primary_religion_string32_capacity_out_of_bound"
            elif capacity < 16 and length > 15:
                name_reason = "primary_religion_string32_inline_length_invalid"
            else:
                if storage == "inline":
                    payload = header[:length + 1]
                    raw_inputs["string32_inline_bytes_raw_hex"] = payload.hex()
                else:
                    heap_pointer_raw = header[:8]
                    heap_pointer = int.from_bytes(heap_pointer_raw, "little")
                    raw_inputs["string32_heap_pointer_raw_hex"] = heap_pointer_raw.hex()
                    raw_inputs["string32_heap_pointer"] = hex(heap_pointer) if heap_pointer else None
                    try:
                        _user_pointer(heap_pointer, "primary_religion_name_heap_pointer")
                    except ValueError as exc:
                        name_reason = str(exc)
                        payload = None
                    else:
                        payload = read_part(
                            heap_pointer,
                            length + 1,
                            "country_faith.primary_religion.String32_payload",
                            "string32_payload_raw_hex",
                        )
                if name_reason is None and payload is not None:
                    raw_inputs["string32_payload_raw_hex"] = payload.hex()
                    if len(payload) != length + 1 or payload[length] != 0:
                        name_reason = "primary_religion_name_terminator_invalid"
                    elif b"\x00" in payload[:length]:
                        name_reason = "primary_religion_name_embedded_nul"
                    else:
                        encoded_hex = payload[:length].hex()
                        raw_inputs["primary_religion_name_raw_hex"] = encoded_hex
                        try:
                            decoded = decode_native_text_hex(
                                encoded_hex,
                                codec=EU4_ESCAPE_CODEC,
                                max_bytes=MAX_NAME_BYTES,
                            )
                        except NativeTextError as exc:
                            name_reason = "primary_religion_name_decode_invalid"
                            raw_inputs["native_text_decoder"] = {
                                "status": "invalid",
                                "codec": EU4_ESCAPE_CODEC,
                                "error_type": type(exc).__name__,
                                "gaps": ["STRICT_DECODER_REJECTED_PAYLOAD"],
                            }
                        else:
                            raw_inputs["native_text_decoder"] = {
                                "status": "decoded",
                                "codec": EU4_ESCAPE_CODEC,
                                "gaps": ["TEXT_IS_COPIED_NOT_LOCALIZED"],
                            }
                            if not decoded:
                                name_reason = "primary_religion_name_empty"
                            else:
                                name = decoded
                elif name_reason is None and payload is None:
                    name_reason = "primary_religion_name_payload_read_failed"

        if icon_raw is None:
            return _unknown("icon_frame_request_read_failed", raw_inputs)
        if header is None:
            return _unknown("primary_religion_string32_header_read_failed", raw_inputs)
        if name_reason is not None:
            return _unknown(name_reason, raw_inputs)
        if name is None:
            return _unknown("primary_religion_name_unknown", raw_inputs)
        return {
            "status": "known",
            "complete": False,
            "value": {
                "primary_religion_name": {
                    "text": name,
                    "raw_hex": raw_inputs["primary_religion_name_raw_hex"],
                    "encoding": EU4_ESCAPE_CODEC,
                },
                "icon_frame_request": int.from_bytes(icon_raw, "little"),
            },
            "raw_inputs": raw_inputs,
            "basis": "bounded_primary_religion_name_string32_and_icon_setter_input",
            "gaps": [
                "PRIMARY_RELIGION_CONFIGURATION_KEY_AND_ID_NOT_READ",
                "LOCALIZED_TOOLTIP_AND_LANGUAGE_SOURCE_NOT_READ",
                "ICON_FRAME_REQUEST_IS_NOT_PROOF_OF_DISPLAY",
                "RELIGION_GROUP_AND_FAITH_RULES_NOT_READ",
                "CALLER_ADMISSION_IS_PARENT_OWNED",
            ],
        }
    except Exception as exc:
        # A leaf-level failure is represented as unknown and keeps every raw
        # pointer/byte already copied into this field's private evidence.
        return _unknown(f"leaf_read_failed:{type(exc).__name__}:{str(exc)[:160]}", raw_inputs)


def read_fields(limiter: Any, base: int, target_binding: Mapping[str, Any],
                fields: tuple[str, ...]) -> dict[str, dict[str, Any]]:
    """Return requested country fields from an already checked binding.

    The only supported public catalog field is ``S02.faith``. Its value is
    limited to strictly decoded primary-religion display-name text and the
    raw frame input passed to the icon control; diagnostic pointers and bytes
    remain under ``raw_inputs``. This reader does not resolve a configuration
    key or numeric religion ID.
    """
    if not isinstance(fields, tuple) or any(not isinstance(field, str) for field in fields):
        return {FIELD_ID: _unknown("fields_shape_invalid")}
    if len(set(fields)) != len(fields):
        return {field: _unknown("duplicate_field_requested") for field in dict.fromkeys(fields)}
    result: dict[str, dict[str, Any]] = {}
    for field in fields:
        if field != FIELD_ID:
            result[field] = _unknown("unsupported_field")
            continue
        result[field] = _read_faith(limiter, base, target_binding)
    return result


__all__ = [
    "FIELD_ID",
    "COUNTRY_RELIGION_POINTER_OFFSET",
    "RELIGION_KEY_OFFSET",
    "RELIGION_NAME_OFFSET",
    "RELIGION_ICON_FRAME_OFFSET",
    "STRING32_SIZE",
    "STRING32_LENGTH_OFFSET",
    "STRING32_CAPACITY_OFFSET",
    "MAX_KEY_BYTES",
    "MAX_NAME_BYTES",
    "MAX_STRING_CAPACITY",
    "read_fields",
]
