"""Small, pure helpers for EU4's raw date arithmetic.

The loan reader stores the four-byte engine date exactly as copied from the
native record.  This module only derives integer day/year/month components
from that raw value; it does not consult the wall clock, game process, or a
calendar service.  The month/day expansion follows the separately pinned
native fixed-365/fixed-February-28 formatter contract.
"""
from __future__ import annotations

from typing import Any


REFERENCE_RAW = 43_800_000
TICKS_PER_DAY = 24
DAYS_PER_YEAR = 365
MONTH_LENGTHS = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
MONTH_DAY_STATUS = "month_and_day_components_closed_static"
CALENDAR_SOURCE_PATH = (
    "work/runtime/information-country-records-localization-20261027-001/"
    "date-calendar-source-002.json"
)
CALENDAR_SOURCE_SHA256 = "fd851ea9a6869e61b2ae05dbb251136ff281fe3801907568900a60a8fa800957"
UINT32_MASK = 0xFFFFFFFF
INT32_SIGN = 0x80000000
UINT32_MODULUS = 0x100000000


def _signed32(value: int) -> int:
    """Interpret a DWORD result using the native signed branch semantics."""

    value &= UINT32_MASK
    return value - UINT32_MODULUS if value & INT32_SIGN else value


def _month_day(day_of_year: int) -> tuple[int, int]:
    remaining = day_of_year
    for month_index, month_length in enumerate(MONTH_LENGTHS):
        if remaining < month_length:
            return month_index + 1, remaining + 1
        remaining -= month_length
    raise ValueError("day_of_year_out_of_fixed_365_range")


def project_engine_date(
    raw: int,
    *,
    reference_raw: int = REFERENCE_RAW,
    ticks_per_day: int = TICKS_PER_DAY,
    days_per_year: int = DAYS_PER_YEAR,
) -> dict[str, Any]:
    """Return a deterministic integer projection of a native date DWORD.

    Python's ``//`` is floor division, matching the signed quotient used by
    the bounded native calendar leaf for values before the reference epoch.
    ``tick_of_day`` is normalized to ``0..ticks_per_day-1`` so negative dates
    remain replayable without relying on truncation toward zero.
    """

    if type(raw) is not int:
        raise TypeError("raw_must_be_int")
    if type(reference_raw) is not int or type(ticks_per_day) is not int or type(days_per_year) is not int:
        raise TypeError("date_parameters_must_be_int")
    if ticks_per_day <= 0 or days_per_year <= 0:
        raise ValueError("date_parameters_must_be_positive")

    # The native leaf loads both date words into 32-bit registers and performs
    # ``sub r32, imm32``.  Preserve that wrap before applying its signed
    # floor-style day/year corrections; Python's unbounded subtraction would
    # otherwise disagree for raw DWORDs near 0x80000000/0xffffffff.
    raw_unsigned = raw & UINT32_MASK
    reference_unsigned = reference_raw & UINT32_MASK
    delta_unsigned = (raw_unsigned - reference_unsigned) & UINT32_MASK
    delta = _signed32(delta_unsigned)
    day_index, tick_of_day = divmod(delta, ticks_per_day)
    year_index, day_of_year = divmod(day_index, days_per_year)
    native_parameters = ticks_per_day == TICKS_PER_DAY and days_per_year == DAYS_PER_YEAR
    if native_parameters:
        month, day = _month_day(day_of_year)
        date = f"{year_index}.{month}.{day}"
        month_day = f"{month}.{day}"
        month_index_zero_based = month - 1
        day_of_month_zero_based = day - 1
        month_day_status = MONTH_DAY_STATUS
    else:
        month = day = None
        date = month_day = None
        month_index_zero_based = day_of_month_zero_based = None
        month_day_status = "unavailable_non_native_parameters"
    return {
        "status": "derived",
        "raw": raw,
        "raw_unsigned": raw_unsigned,
        "raw_hex": raw_unsigned.to_bytes(4, "little", signed=False).hex(),
        "reference_raw": reference_raw,
        "reference_raw_unsigned": reference_unsigned,
        "reference_raw_hex": reference_unsigned.to_bytes(4, "little", signed=False).hex(),
        "delta_ticks_unsigned": delta_unsigned,
        "ticks_per_day": ticks_per_day,
        "days_per_year": days_per_year,
        "delta_ticks": delta,
        "day_index": day_index,
        "tick_of_day": tick_of_day,
        "year_index": year_index,
        "day_of_year": day_of_year,
        "unit": "eu4_hour_tick",
        "scale": 1,
        "algorithm": "signed32_wrap_floor((raw-reference_raw)/24),floor(day_index/365)",
        "month_index_zero_based": month_index_zero_based,
        "month": month,
        "day_of_month_zero_based": day_of_month_zero_based,
        "day": day,
        "month_day": month_day,
        "date": date,
        "month_day_status": month_day_status,
        "calendar_source": {
            "path": CALENDAR_SOURCE_PATH,
            "sha256": CALENDAR_SOURCE_SHA256,
            "status": "ordinary_pe_bounded_static_only",
        },
    }


__all__ = [
    "REFERENCE_RAW",
    "TICKS_PER_DAY",
    "DAYS_PER_YEAR",
    "MONTH_LENGTHS",
    "MONTH_DAY_STATUS",
    "CALENDAR_SOURCE_PATH",
    "CALENDAR_SOURCE_SHA256",
    "project_engine_date",
]
