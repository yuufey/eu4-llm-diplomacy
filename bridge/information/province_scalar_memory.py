"""Read the bounded province autonomy scalar from an already bound record.

The supported G02.autonomy projection is derived from B23 REA evidence
``ev_caee7cd6b92f6364aa1460e6ca2ef924151cc6b5b909c1c10b1ee4844dba2b38``
for executable SHA-256
``b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77``.
The panel update reads current value at record+0x428, lower bound at +0x2df0,
and upper bound at +0x2df4. The native order is
``min(max(current, lower), upper)`` followed by the display floor at zero and
scale 1000. This leaf accepts a binding created elsewhere; it does not open a
process, resolve a province, decide visibility, or certify that multiple
reads were atomic.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
import re
from typing import Any, Callable


FIELD_ID = "G02.autonomy"
CURRENT_OFFSET = 0x428
LOWER_OFFSET = 0x2DF0
UPPER_OFFSET = 0x2DF4
ID_OFFSET = 0x20
RECORD_ID_MAX = 0xFFFF
SCALE = 1000
MAX_FIELDS = 32
MIN_USER_ADDRESS = 0x10000
MAX_USER_ADDRESS_EXCLUSIVE = 0x800000000000
MAX_U64 = 0xFFFFFFFFFFFFFFFF
_BINDING_KEYS = frozenset({
    "province_id", "record_pointer", "id_address", "id_raw_hex", "record_id",
})
_POINTER_TEXT = re.compile(r"0x[0-9a-f]{1,16}\Z")
_ID_RAW_HEX = re.compile(r"[0-9a-f]{8}\Z")


class _Unknown(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _is_user_address(value: Any) -> bool:
    return (type(value) is int and MIN_USER_ADDRESS <= value < MAX_USER_ADDRESS_EXCLUSIVE
            and value <= MAX_U64)


def _checked_add(address: int, offset: int, label: str) -> int:
    if (not _is_user_address(address) or type(offset) is not int or offset < 0
            or address > MAX_U64 - offset):
        raise _Unknown(f"address_arithmetic_invalid:{label}")
    result = address + offset
    if not _is_user_address(result):
        raise _Unknown(f"address_arithmetic_invalid:{label}")
    return result


def _checked_range(address: int, size: int, label: str) -> None:
    if (not _is_user_address(address) or type(size) is not int or size <= 0
            or address > MAX_U64 - (size - 1)):
        raise _Unknown(f"address_range_invalid:{label}")
    last = address + size - 1
    if not _is_user_address(last):
        raise _Unknown(f"address_range_invalid:{label}")


def _parse_pointer(value: Any, label: str) -> int:
    if type(value) is not str or not _POINTER_TEXT.fullmatch(value):
        raise _Unknown(f"binding_{label}_invalid")
    parsed = int(value, 16)
    if hex(parsed) != value or not _is_user_address(parsed):
        raise _Unknown(f"binding_{label}_invalid")
    return parsed


def _bound_record(binding: Any) -> tuple[int, int]:
    if not isinstance(binding, Mapping) or set(binding) != _BINDING_KEYS:
        raise _Unknown("province_binding_shape_invalid")
    province_id = binding.get("province_id")
    record_id = binding.get("record_id")
    if (type(province_id) is not int or not 1 <= province_id <= RECORD_ID_MAX
            or type(record_id) is not int or record_id != province_id):
        raise _Unknown("province_binding_id_invalid")

    record = _parse_pointer(binding.get("record_pointer"), "record_pointer")
    id_address = _parse_pointer(binding.get("id_address"), "id_address")
    if record & 7:
        raise _Unknown("binding_record_pointer_unaligned")
    expected_id_address = _checked_add(record, ID_OFFSET, "binding_id_address")
    if id_address != expected_id_address:
        raise _Unknown("binding_id_address_mismatch")
    raw_hex = binding.get("id_raw_hex")
    if type(raw_hex) is not str or not _ID_RAW_HEX.fullmatch(raw_hex):
        raise _Unknown("binding_id_raw_hex_invalid")
    bound_id = int.from_bytes(bytes.fromhex(raw_hex), "little", signed=True)
    if bound_id != province_id:
        raise _Unknown("binding_id_raw_mismatch")

    for offset, label in ((CURRENT_OFFSET, "current"), (LOWER_OFFSET, "lower"),
                          (UPPER_OFFSET, "upper")):
        address = _checked_add(record, offset, label)
        _checked_range(address, 4, label)
    return province_id, record


def _read_i32(read: Callable[[int, int, str], bytes], address: int,
              label: str) -> tuple[int, bytes]:
    _checked_range(address, 4, label)
    try:
        raw = read(address, 4, label)
    except Exception as exc:
        raise _Unknown(f"read_failed:{label}:{type(exc).__name__}") from exc
    if not isinstance(raw, (bytes, bytearray, memoryview)) or len(raw) != 4:
        raise _Unknown(f"short_or_invalid_read:{label}")
    raw_bytes = bytes(raw)
    return int.from_bytes(raw_bytes, "little", signed=True), raw_bytes


def _unknown(reason: str) -> dict[str, Any]:
    return {
        "status": "unknown",
        "reason": reason,
        "scale": SCALE,
        "period": "current",
        "partial": True,
        "complete": False,
    }


def _normalize_fields(fields: Any) -> list[str] | None:
    if isinstance(fields, (str, bytes, bytearray, Mapping)):
        return None
    try:
        iterator = iter(fields)
    except TypeError:
        return None
    requested: list[str] = []
    try:
        for name in iterator:
            if len(requested) >= MAX_FIELDS or type(name) is not str or len(name) > 128:
                return None
            requested.append(name)
    except Exception:
        return None
    return requested


def read_fields(read: Callable[[int, int, str], bytes], module_base: int,
                province_binding: Mapping[str, Any], fields: Iterable[str]) -> dict[str, dict[str, Any]]:
    """Read G02.autonomy from a previously validated province record binding.

    ``fields`` uses complete catalog identifiers. Unsupported fields are
    returned as unknown without a corresponding memory read. A failed read or
    malformed binding never yields a numeric fallback or partial raw input.
    Caller-owned checks must establish observer/visibility, ROM/profile,
    budgets, session identity, and two-pass consistency before public export.
    """
    requested = _normalize_fields(fields)
    if requested is None:
        return {FIELD_ID: _unknown("field_selector_invalid")}
    if not requested:
        return {}
    unique = list(dict.fromkeys(requested))
    if len(unique) != len(requested):
        return {name: _unknown("duplicate_field") for name in unique}

    result = {
        name: _unknown("field_not_supported")
        for name in unique if name != FIELD_ID
    }
    if FIELD_ID not in unique:
        return result

    try:
        if not callable(read):
            raise _Unknown("reader_not_callable")
        if not _is_user_address(module_base):
            raise _Unknown("module_base_invalid")
        province_id, record = _bound_record(province_binding)

        # Match the accepted native read order: lower, current, then upper.
        lower_address = _checked_add(record, LOWER_OFFSET, "lower")
        lower_raw, lower_bytes = _read_i32(
            read, lower_address, f"province_scalar.autonomy.lower[{province_id}]")
        current_address = _checked_add(record, CURRENT_OFFSET, "current")
        current_raw, current_bytes = _read_i32(
            read, current_address, f"province_scalar.autonomy.current[{province_id}]")
        upper_address = _checked_add(record, UPPER_OFFSET, "upper")
        upper_raw, upper_bytes = _read_i32(
            read, upper_address, f"province_scalar.autonomy.upper[{province_id}]")

        effective_raw = min(max(current_raw, lower_raw), upper_raw)
        display_raw = max(0, effective_raw)
        result[FIELD_ID] = {
            "status": "known",
            "value": display_raw,
            "scale": SCALE,
            "period": "current",
            "partial": True,
            "complete": False,
            "raw_inputs": {
                "record_pointer": hex(record),
                "lower_address": hex(lower_address),
                "lower_raw": lower_raw,
                "lower_raw_hex": lower_bytes.hex(),
                "current_address": hex(current_address),
                "current_raw": current_raw,
                "current_raw_hex": current_bytes.hex(),
                "upper_address": hex(upper_address),
                "upper_raw": upper_raw,
                "upper_raw_hex": upper_bytes.hex(),
                "effective_raw": effective_raw,
                "effective_raw_hex": effective_raw.to_bytes(4, "little", signed=True).hex(),
            },
        }
    except _Unknown as exc:
        result[FIELD_ID] = _unknown(exc.reason)
    except Exception as exc:
        result[FIELD_ID] = _unknown(f"leaf_failed:{type(exc).__name__}")
    return result


__all__ = ["FIELD_ID", "read_fields"]
