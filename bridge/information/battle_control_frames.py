"""Project raw battle numeric/icon pairs into virtual setter requests.

This module describes what the fixed 1.37.4 popup path would request from a
widget. It does not invoke native code and does not claim a runtime widget or
popup state. Raw bytes are authoritative; renderer-provided decoded strings
are intentionally ignored for numeric parsing.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy


_MAX_RAW_BYTES = 8192
_I32_MIN = -(1 << 31)
_I32_MAX = (1 << 31) - 1
_U32_MASK = (1 << 32) - 1
_ASCII_WHITESPACE = frozenset((0x20, 0x09, 0x0A, 0x0B, 0x0C, 0x0D))

PROVENANCE = {
    "game_version": "1.37.4",
    "exe_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
    "image_base": "0x140000000",
    "numeric_to_frame": {
        "name": "FUN_141703ff0", "rva": "0x1703ff0",
        "evidence_id": "ev_f9135af27a020afd081eecd2c2ec5e1ae9b5ef6303e7c2ed15a42c909805f211",
    },
    "atol": {
        "name": "atol", "rva": "0x1a48f38",
        "evidence_id": "ev_117006856190eafb9db97e8afe49dfc16792e6049503da3759556eb83f981843",
    },
    "integer_parser": {
        "name": "__crt_strtox::parse_integer", "rva": "0x1a481cc",
        "evidence_id": "ev_eb15106d4303e49e7b06afdf2cdbca0749ffd5a3b3d7bd15d9488394d85ce4bb",
    },
    "virtual_slots": {"no_argument": "0x90", "value_argument": "0xa8"},
}

_NUMERIC_KEYS = {
    "land": frozenset((
        "OURFIRE", "OURSHOCK", "OURMANEUVER", "OURSIEGE",
        "ENEMYFIRE", "ENEMYSHOCK", "ENEMYMANEUVER", "ENEMYSIEGE",
    )),
    "naval": frozenset((
        "OURFIRE", "OURSHOCK", "OURMANEUVER",
        "ENEMYFIRE", "ENEMYSHOCK", "ENEMYMANEUVER",
    )),
}
_ICON_KEYS = frozenset(("OURLEADERICON", "ENEMYLEADERICON"))


def _i32_from_u32(value: int) -> int:
    value &= _U32_MASK
    return value if value < (1 << 31) else value - (1 << 32)


def _parse_native_i32(raw: bytes) -> dict:
    """Model bounded C-string/atol decimal-prefix parsing with i32 clamping."""
    nul = raw.find(b"\x00")
    c_bytes = raw if nul < 0 else raw[:nul]
    index = 0
    while index < len(c_bytes) and c_bytes[index] in _ASCII_WHITESPACE:
        index += 1

    # The process locale is not part of the copied record. If a high byte is
    # encountered before the optional sign/digits, do not guess whether that
    # locale would classify it as whitespace.
    if index < len(c_bytes) and c_bytes[index] >= 0x80:
        return {
            "status": "unknown",
            "reason": "NON_ASCII_PREFIX_LOCALE_UNRESOLVED",
            "parsed": None,
        }

    negative = False
    if index < len(c_bytes) and c_bytes[index] in (ord("+"), ord("-")):
        negative = c_bytes[index] == ord("-")
        index += 1

    limit = (1 << 31) if negative else _I32_MAX
    magnitude = 0
    digit_count = 0
    clamped = False
    while index < len(c_bytes):
        byte = c_bytes[index]
        if byte < ord("0") or byte > ord("9"):
            break
        digit = byte - ord("0")
        digit_count += 1
        if not clamped:
            if magnitude > (limit - digit) // 10:
                magnitude = limit
                clamped = True
            else:
                magnitude = magnitude * 10 + digit
        index += 1

    if digit_count == 0:
        parsed = 0
    else:
        parsed = -magnitude if negative else magnitude

    return {
        "status": "known",
        "reason": None,
        "parsed": {
            "signed_i32": parsed,
            "bits_u32": parsed & _U32_MASK,
            "digits": digit_count > 0,
            "no_digits": digit_count == 0,
            "range_clamped": clamped,
            "digit_count": digit_count,
            "raw_input_bytes": len(raw),
            "c_string_bytes": len(c_bytes),
        },
    }


def _unknown_item(item, reason: str, *, raw_input_bytes: int | None = None) -> dict:
    pair_index = item.get("pair_index") if isinstance(item, Mapping) else None
    return {
        "status": "unknown",
        "pair_index": pair_index,
        "reason": reason,
        "raw_input_bytes": raw_input_bytes,
        "parsed": None,
        "virtual_setter_request": None,
        "native_call_observed": False,
        "runtime_widget_state_verified": False,
    }


def _project_item(kind: str, binding: Mapping, item) -> dict:
    if not isinstance(item, Mapping):
        return _unknown_item(item, "INPUT_ITEM_NOT_OBJECT")

    pair_index = item.get("pair_index")
    if type(pair_index) is not int or pair_index < 0:
        return _unknown_item(item, "PAIR_INDEX_INVALID")

    raw_hex = item.get("value_raw_hex")
    if not isinstance(raw_hex, str):
        return _unknown_item(item, "RAW_HEX_NOT_STRING")
    if len(raw_hex) > _MAX_RAW_BYTES * 2:
        return _unknown_item(item, "RAW_INPUT_OVER_BOUND", raw_input_bytes=(len(raw_hex) + 1) // 2)
    if len(raw_hex) % 2 != 0:
        return _unknown_item(item, "RAW_HEX_ODD_LENGTH")
    if any(ch not in "0123456789abcdefABCDEF" for ch in raw_hex):
        return _unknown_item(item, "RAW_HEX_INVALID")

    raw = bytes.fromhex(raw_hex)
    if len(raw) > _MAX_RAW_BYTES:
        return _unknown_item(item, "RAW_INPUT_OVER_BOUND", raw_input_bytes=len(raw))
    parsed = _parse_native_i32(raw)
    if parsed["status"] != "known":
        return {
            "status": "unknown",
            "pair_index": pair_index,
            "reason": parsed["reason"],
            "raw_input_bytes": len(raw),
            "parsed": None,
            "virtual_setter_request": None,
            "native_call_observed": False,
            "runtime_widget_state_verified": False,
        }

    key = binding["template_key"]
    parsed_value = parsed["parsed"]
    parsed_i32 = parsed_value["signed_i32"]
    if key in _NUMERIC_KEYS[kind]:
        arg_u32 = (parsed_value["bits_u32"] + 1) & _U32_MASK
        request = {
            "vtable_offset": "0xa8",
            "arg_u32": arg_u32,
            "arg_i32": _i32_from_u32(arg_u32),
        }
    elif parsed_i32 < 1:
        # The exact UI meaning of this no-argument vtable request is unknown.
        request = {"vtable_offset": "0x90", "arguments": []}
    else:
        request = {
            "vtable_offset": "0xa8",
            "arg_u32": parsed_value["bits_u32"],
            "arg_i32": parsed_i32,
        }

    return {
        "status": "known",
        "pair_index": pair_index,
        "reason": None,
        "raw_input_bytes": len(raw),
        "parsed": parsed_value,
        "virtual_setter_request": request,
        "native_call_observed": False,
        "runtime_widget_state_verified": False,
    }


def project_native_frame_requests(kind: str, binding: dict,
                                  inputs: list) -> dict | None:
    """Project supported raw numeric/icon keys into ordered virtual requests.

    Supported keys are explicitly limited to land/naval fire, shock and
    maneuver values, land siege values, and both leader icons. Each input pair
    yields its own result in input order; duplicates are never coalesced.
    """
    if kind not in ("land", "naval") or not isinstance(binding, Mapping):
        return None
    key = binding.get("template_key")
    if not isinstance(key, str):
        return None
    if key in _NUMERIC_KEYS[kind]:
        expected_kind = "numeric_or_frame"
        request_kind = "numeric_plus_one"
    elif key in _ICON_KEYS:
        expected_kind = "icon_or_frame"
        request_kind = "icon_threshold"
    else:
        return None
    if binding.get("value_kind") != expected_kind:
        return None

    if not isinstance(inputs, list):
        items = [_unknown_item(None, "INPUTS_NOT_LIST")]
    elif not inputs:
        items = [_unknown_item(None, "CONTROL_INPUT_MISSING")]
    else:
        items = [_project_item(kind, binding, item) for item in inputs]

    statuses = [item["status"] for item in items]
    if all(status == "known" for status in statuses):
        status = "known"
    elif all(status == "unknown" for status in statuses):
        status = "unknown"
    else:
        status = "partial"

    return {
        "status": status,
        "basis": "static_virtual_setter_request_inferred_from_raw_pair_bytes",
        "battle_kind": kind,
        "template_key": key,
        "widget": binding.get("widget"),
        "request_kind": request_kind,
        "binding_provenance": deepcopy(PROVENANCE),
        "requests": items,
        "native_call_observed": False,
        "runtime_widget_state_verified": False,
        "full_display_complete": False,
    }
