"""Pure fixed-point arithmetic for the supported current province-value path.

This module only models the retained integer equations. Callers own native
field acquisition, identity, eligibility, period, and cache freshness.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from . import trade_income_memory as _income_memory
from . import trade_power_memory as _power_memory


_I32_MIN = -(1 << 31)
_I32_MAX = (1 << 31) - 1
_SCALE = 1000
_NODE_DIVISOR = 12000
_MAX_NODE_INPUTS = 4096


def _require_i32(value: Any, name: str) -> int:
    if type(value) is not int or not _I32_MIN <= value <= _I32_MAX:
        raise ValueError(f"{name}_must_be_signed_i32")
    return value


def calculate_current(
    province_goods_base_raw: int,
    owner_goods_base_raw: int,
    province_goods_modifier_raw: int,
    owner_goods_modifier_raw: int,
    goods_price_raw: int,
    province_value_add_raw: int,
    province_value_modifier_raw: int,
) -> dict[str, int]:
    """Reconstruct the bounded current province-value arithmetic.

    Every input is one signed raw i32. Each native sum and narrowing boundary
    wraps to i32, and each fixed-point multiply truncates toward zero.
    """
    province_goods_base = _require_i32(province_goods_base_raw, "province_goods_base_raw")
    owner_goods_base = _require_i32(owner_goods_base_raw, "owner_goods_base_raw")
    province_goods_modifier = _require_i32(
        province_goods_modifier_raw, "province_goods_modifier_raw")
    owner_goods_modifier = _require_i32(owner_goods_modifier_raw, "owner_goods_modifier_raw")
    goods_price = _require_i32(goods_price_raw, "goods_price_raw")
    province_value_add = _require_i32(province_value_add_raw, "province_value_add_raw")
    province_value_modifier = _require_i32(
        province_value_modifier_raw, "province_value_modifier_raw")

    goods_base = _income_memory._wrap_i32(province_goods_base + owner_goods_base)
    combined_goods_modifier = _income_memory._wrap_i32(
        province_goods_modifier + owner_goods_modifier)
    goods_factor = _income_memory._wrap_i32(max(-_SCALE, combined_goods_modifier) + _SCALE)
    goods_raw = max(0, _income_memory._wrap_i32(
        _power_memory._trunc0_div(goods_base * goods_factor, _SCALE)))

    priced_raw = max(0, _income_memory._wrap_i32(
        _power_memory._trunc0_div(goods_raw * goods_price, _SCALE)))
    subtotal = _income_memory._wrap_i32(priced_raw + province_value_add)
    value_factor = max(10, min(2000, _income_memory._wrap_i32(
        province_value_modifier + _SCALE)))
    value_raw = _income_memory._wrap_i32(
        _power_memory._trunc0_div(subtotal * value_factor, _SCALE))

    return {
        "goods_base_raw": goods_base,
        "combined_goods_modifier_raw": combined_goods_modifier,
        "goods_factor_raw": goods_factor,
        "goods_raw": goods_raw,
        "priced_raw": priced_raw,
        "subtotal_raw": subtotal,
        "value_factor_raw": value_factor,
        "value_raw": value_raw,
    }


def aggregate_node_inputs(values: Sequence[int]) -> dict[str, int]:
    """Sum bounded province inputs with native i32 wrap and 12x conversion.

    An empty sequence is valid and maps to zero. Inputs must be a list or tuple
    of at most 4096 exact signed i32 values.
    """
    if type(values) not in (list, tuple) or len(values) > _MAX_NODE_INPUTS:
        raise ValueError("values_must_be_bounded_list_or_tuple")

    total = 0
    for index, value in enumerate(values):
        item = _require_i32(value, f"values[{index}]")
        total = _income_memory._wrap_i32(total + item)

    node_input = _income_memory._wrap_i32(
        _power_memory._trunc0_div(total * _SCALE, _NODE_DIVISOR))
    return {"sum_raw": total, "node_input_raw": node_input}


__all__ = ["aggregate_node_inputs", "calculate_current"]
