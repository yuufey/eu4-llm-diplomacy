"""Pure, signed arithmetic and public DTO validation for governing capacity."""
from __future__ import annotations

from collections.abc import Mapping
import re


_I32_MIN = -(1 << 31)
_I32_MAX = (1 << 31) - 1
_I64_MIN = -(1 << 63)
_I64_MAX = (1 << 63) - 1
_SAFE_REASON = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")

_COPIED = "copied_native_governing_capacity_cache"
_DERIVED = "derived_from_copied_native_governing_capacity_inputs"

NUMBER_SPECS = {
    "used": {
        "unit": "governing_capacity", "scale": 1000, "width": 4,
        "basis": "native_governing_capacity_used_cache", "value_origin": _COPIED,
    },
    "limit": {
        "unit": "governing_capacity", "scale": 1000, "width": 4,
        "basis": "native_governing_capacity_limit_arithmetic", "value_origin": _DERIVED,
    },
    "used_fraction": {
        "unit": "ratio", "scale": 1000, "width": 4,
        "basis": "native_governing_capacity_used_fraction", "value_origin": _DERIVED,
    },
    "headroom": {
        "unit": "governing_capacity", "scale": 1000, "width": 8,
        "basis": "signed_limit_minus_used_capacity", "value_origin": _DERIVED,
    },
}


def _require_i32(value: int, name: str) -> int:
    if type(value) is not int or not _I32_MIN <= value <= _I32_MAX:
        raise ValueError(f"{name} must be a signed 32-bit integer")
    return value


def _wrap_i32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _trunc_zero(numerator: int, denominator: int) -> int:
    quotient = abs(numerator) // abs(denominator)
    return -quotient if (numerator < 0) != (denominator < 0) else quotient


def capacity_limit(base_raw: int, additive_raw: int, modifier_raw: int) -> int:
    """Apply base + modifier 409, then nonnegative 1000 + modifier 410."""
    base = _require_i32(base_raw, "base_raw")
    additive = _require_i32(additive_raw, "additive_raw")
    modifier = _require_i32(modifier_raw, "modifier_raw")
    additive_total = _wrap_i32(base + additive)
    multiplier = max(0, _wrap_i32(1000 + modifier))
    # The product of two signed-32 values fits in a signed-64 accumulator.
    product = additive_total * multiplier
    if not _I64_MIN <= product <= _I64_MAX:
        raise OverflowError("governing-capacity intermediate exceeds signed 64-bit range")
    return _wrap_i32(_trunc_zero(product, 1000))


def used_ratio(used_raw: int, limit_raw: int) -> int | None:
    """Return used / limit as a signed fixed-point ratio, or None at zero limit."""
    used = _require_i32(used_raw, "used_raw")
    limit = _require_i32(limit_raw, "limit_raw")
    if limit == 0:
        return None
    return _wrap_i32(_trunc_zero(used * 1000, limit))


def headroom_signed(used_raw: int, limit_raw: int) -> int:
    """Return the mathematical signed-64-bit difference limit - used."""
    used = _require_i32(used_raw, "used_raw")
    limit = _require_i32(limit_raw, "limit_raw")
    result = limit - used
    if not _I64_MIN <= result <= _I64_MAX:
        raise OverflowError("headroom exceeds signed 64-bit range")
    return result


def validate_number_field(name: str, field: object) -> bool:
    """Check one named scalar DTO against its exact public contract."""
    if not isinstance(name, str) or name not in NUMBER_SPECS:
        return False
    if not isinstance(field, Mapping):
        return False
    status = field.get("status")
    if status == "unknown":
        reason = field.get("reason")
        return (set(field) == {"status", "reason"} and isinstance(reason, str)
                and _SAFE_REASON.fullmatch(reason) is not None)
    if status == "not_applicable":
        reason = field.get("reason")
        return (name == "used_fraction"
                and set(field) == {"status", "reason"}
                and reason == "GOVERNANCE_CAPACITY_LIMIT_ZERO")
    if status != "known":
        return False
    spec = NUMBER_SPECS[name]
    width = spec["width"]
    keys = {"status", "value", "raw", "raw_hex", "unit", "scale", "period",
            "partial", "complete", "basis", "value_origin"}
    if set(field) != keys:
        return False
    value, raw, raw_hex = field["value"], field["raw"], field["raw_hex"]
    lower, upper = -(1 << (width * 8 - 1)), (1 << (width * 8 - 1)) - 1
    if (type(value) is not int or type(raw) is not int or value != raw
            or not lower <= raw <= upper or not isinstance(raw_hex, str)
            or re.fullmatch(rf"[0-9a-f]{{{width * 2}}}", raw_hex) is None
            or int.from_bytes(bytes.fromhex(raw_hex), "little", signed=True) != raw):
        return False
    return (field["unit"] == spec["unit"]
            and type(field["scale"]) is int and field["scale"] == spec["scale"]
            and field["period"] == "current" and field["partial"] is True
            and field["complete"] is False
            and field["basis"] == spec["basis"]
            and field["value_origin"] == spec["value_origin"])


def validate_public_field(field: object) -> bool:
    """Check the whole public governing-capacity summary DTO."""
    if not isinstance(field, Mapping):
        return False
    status = field.get("status")
    if status == "unknown":
        reason = field.get("reason")
        return (set(field) == {"status", "reason"} and isinstance(reason, str)
                and _SAFE_REASON.fullmatch(reason) is not None)
    if status != "known":
        return False

    outer_keys = {"status", "value", "unit", "scale", "period", "partial",
                  "complete", "basis", "value_origin"}
    if set(field) != outer_keys:
        return False
    if (field["unit"] != "governing_capacity_summary"
            or type(field["scale"]) is not int or field["scale"] != 1
            or field["period"] != "current" or field["partial"] is not True
            or field["complete"] is not False
            or field["basis"] != "native_governing_capacity_cache_and_limit_arithmetic"
            or field["value_origin"] != "derived_from_copied_native_governing_capacity_inputs"):
        return False

    numbers = field["value"]
    if not isinstance(numbers, Mapping) or set(numbers) != set(NUMBER_SPECS):
        return False
    if any(not validate_number_field(name, numbers[name]) for name in NUMBER_SPECS):
        return False

    used = numbers["used"]
    limit = numbers["limit"]
    fraction = numbers["used_fraction"]
    headroom = numbers["headroom"]
    used_known = used.get("status") == "known"
    limit_known = limit.get("status") == "known"
    if not (used_known or limit_known):
        return False

    # The ratio and difference need both native/arithmetic inputs. Their
    # public values must agree with the same pure helpers used by the reader.
    if not (used_known and limit_known):
        return (fraction.get("status") == "unknown"
                and headroom.get("status") == "unknown")

    used_raw = used["raw"]
    limit_raw = limit["raw"]
    expected_fraction = used_ratio(used_raw, limit_raw)
    if expected_fraction is None:
        if (fraction.get("status") != "not_applicable"
                or fraction.get("reason") != "GOVERNANCE_CAPACITY_LIMIT_ZERO"):
            return False
    else:
        if fraction.get("status") == "not_applicable":
            return False
        if fraction.get("status") == "known" and fraction["raw"] != expected_fraction:
            return False
    if (headroom.get("status") == "known"
            and headroom["raw"] != headroom_signed(used_raw, limit_raw)):
        return False
    return True
