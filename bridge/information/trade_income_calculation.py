"""Pure current trade-income arithmetic for the retained native cache formula."""
from __future__ import annotations

from typing import Any

from . import trade_income_memory as _income_memory
from . import trade_power_memory as _power_memory


INT32_MIN = -(1 << 31)
INT32_MAX = (1 << 31) - 1
FIXED_POINT_SCALE = 1000
MODIFIER_MIN = 10
MODIFIER_MAX = 2000


def _require_i32(value: Any, name: str) -> int:
    if type(value) is not int or value < INT32_MIN or value > INT32_MAX:
        raise ValueError(f"{name}_must_be_signed_i32")
    return value


def calculate_current(
    share_raw: int,
    node_cash_raw: int,
    country_base_raw: int,
    modifier_raw: int,
    bonus_raw: int,
    bonus_applies: bool,
) -> dict[str, int]:
    """Reconstruct the current native two-stage fixed-point income value.

    Inputs are raw signed dwords.  This function models arithmetic only: its
    caller owns identity, eligibility, and any processor-presence checks.
    """
    share = _require_i32(share_raw, "share_raw")
    node_cash = _require_i32(node_cash_raw, "node_cash_raw")
    country_base = _require_i32(country_base_raw, "country_base_raw")
    modifier = _require_i32(modifier_raw, "modifier_raw")
    bonus = _require_i32(bonus_raw, "bonus_raw")
    if type(bonus_applies) is not bool:
        raise ValueError("bonus_applies_must_be_bool")

    combined = _income_memory._wrap_i32(country_base + modifier)
    clamped_modifier = max(MODIFIER_MIN, min(MODIFIER_MAX, combined))
    multiplier = _income_memory._wrap_i32(clamped_modifier + FIXED_POINT_SCALE)
    if bonus_applies:
        multiplier = _income_memory._wrap_i32(multiplier + bonus)

    income_before_multiplier = _income_memory._wrap_i32(
        _power_memory._trunc0_div(share * node_cash, FIXED_POINT_SCALE)
    )
    income = _income_memory._wrap_i32(
        _power_memory._trunc0_div(income_before_multiplier * multiplier, FIXED_POINT_SCALE)
    )

    return {
        "clamped_modifier_raw": clamped_modifier,
        "multiplier_raw": multiplier,
        "income_before_multiplier_raw": income_before_multiplier,
        "income_raw": income,
    }

