"""Pure projection of B23's direct-truce date calculation.

The caller must separately verify the relation, code and runtime configuration.
This module neither reads a process nor declares that a truce is active.
"""
from __future__ import annotations

MONTH_DAYS = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
DATE_REFERENCE_RAW = 43_800_000
I32_MAX = (1 << 31) - 1


def _integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('TRUCE_DATE_INPUT_INVALID')
    return value


def _i32(value):
    return (value + (1 << 31)) % (1 << 32) - (1 << 31)


def _trunc(value, denominator):
    return value // denominator if value >= 0 else -((-value) // denominator)


def adjustment_months(adjustment, global_a, global_b):
    """Return the native integer argument to the calendar-month helper."""
    adjustment = _integer(adjustment, -128, 127)
    global_a = _integer(global_a, -(1 << 31), I32_MAX)
    global_b = _integer(global_b, -(1 << 31), I32_MAX)
    scaled = _i32(_i32(adjustment * global_a) * 1000)
    combined = _i32(_i32(global_b * 1000) + _trunc(scaled, 100))
    numerator = _i32(combined * 12 + 1000)
    return -((-numerator) // 1000)


def decode_date(raw):
    """Decode the supported nonnegative-year, fixed 365-day clock."""
    raw = _integer(raw, DATE_REFERENCE_RAW, I32_MAX)
    days, hour = divmod(raw - DATE_REFERENCE_RAW, 24)
    year, ordinal = divmod(days, 365)
    month = 0
    while ordinal >= MONTH_DAYS[month]:
        ordinal -= MONTH_DAYS[month]
        month += 1
    return year, month + 1, ordinal + 1, hour


def direct_truce_expiry(date_input, adjustment, global_a, global_b):
    """Derive the raw month-start expiry, preserving the stored hour.

    Native month addition clamps the day to the destination month, then its
    following day setter selects day index zero. Therefore the resulting day
    is the first day of the destination month regardless of the input day.
    Pre-reference dates and a result outside signed int32 are rejected rather
    than extrapolated through unverified calendar overflow behavior.
    """
    year, month, _day, hour = decode_date(date_input)
    step = adjustment_months(adjustment, global_a, global_b)
    year, month_index = divmod(year * 12 + month - 1 + step, 12)
    if year < 0:
        raise ValueError('TRUCE_DATE_PRE_REFERENCE_RESULT_UNSUPPORTED')
    raw = DATE_REFERENCE_RAW + year * 365 * 24 + sum(MONTH_DAYS[:month_index]) * 24 + hour
    if not DATE_REFERENCE_RAW <= raw <= I32_MAX:
        raise ValueError('TRUCE_DATE_RESULT_OVERFLOW_UNSUPPORTED')
    return {'raw': raw, 'date': f'{year}.{month_index + 1}.1', 'hour': hour,
            'unit': 'eu4_hour_tick', 'scale': 1}


__all__ = ['adjustment_months', 'decode_date', 'direct_truce_expiry']
