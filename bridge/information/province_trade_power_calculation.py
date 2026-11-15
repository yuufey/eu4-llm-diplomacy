"""Exact integer arithmetic for the bounded current trade-power cache path."""
from __future__ import annotations

from typing import Any


_I32_MIN = -(1 << 31)
_I32_MAX = (1 << 31) - 1
_SCALE = 1000


def _wrap_i32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _signed_i64(value: int) -> int:
    value &= 0xFFFFFFFFFFFFFFFF
    return value - 0x10000000000000000 if value & 0x8000000000000000 else value


def _trunc_toward_zero(numerator: int, denominator: int) -> int:
    quotient = abs(numerator) // denominator
    return -quotient if numerator < 0 else quotient


def _validate_i32(name: str, value: Any) -> int:
    if type(value) is not int or not _I32_MIN <= value <= _I32_MAX:
        raise ValueError(f"{name} must be a signed 32-bit integer")
    return value


def calculate_current(
    flat: int,
    province_ratio: int,
    controller_ratio: int,
    further_ratio: int,
    owner_bonus: int,
) -> dict[str, int]:
    """Project the current cache value with native signed-width semantics.

    The supported path has the three additional writer inputs fixed at zero.
    Inputs and intermediate ratios wrap to signed i32 at the same boundaries as
    the native writer, while each multiply/divide uses signed i64 and truncates
    toward zero.
    """
    flat = _validate_i32("flat", flat)
    province_ratio = _validate_i32("province_ratio", province_ratio)
    controller_ratio = _validate_i32("controller_ratio", controller_ratio)
    further_ratio = _validate_i32("further_ratio", further_ratio)
    owner_bonus = _validate_i32("owner_bonus", owner_bonus)

    ratio_sum_raw = _wrap_i32(
        _SCALE + province_ratio + controller_ratio + owner_bonus
    )
    further_factor_raw = _wrap_i32(_SCALE + further_ratio)
    further_product_div1000 = _trunc_toward_zero(
        _signed_i64(ratio_sum_raw * further_factor_raw), _SCALE
    )
    effective_ratio_raw = max(0, _wrap_i32(further_product_div1000))
    unclamped_product_div1000 = _trunc_toward_zero(
        _signed_i64(flat * effective_ratio_raw), _SCALE
    )
    raw = max(0, _wrap_i32(unclamped_product_div1000))

    return {
        "raw": raw,
        "ratio_sum_raw": ratio_sum_raw,
        "further_factor_raw": further_factor_raw,
        "further_product_div1000": further_product_div1000,
        "effective_ratio_raw": effective_ratio_raw,
        "unclamped_product_div1000": unclamped_product_div1000,
    }


__all__ = ["calculate_current"]
