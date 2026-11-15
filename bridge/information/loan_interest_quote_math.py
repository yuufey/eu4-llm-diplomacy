"""Pure B23 loan-interest quote arithmetic, without memory or publication.

The model follows 0x86B6C0 and its caller 0x86B4E0.  It preserves DWORD
wrapping before widening, signed division toward zero, low-QWORD products,
arithmetic shifts, and each scalar binary32 rounding step.  RNE and masked
FP exceptions are explicit assumptions, not observations of the game thread.
The amount is a remaining-interest quote, not a debt principal or a bankruptcy
forecast.  Supplied loan records are not proof of a complete country list.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import math
from typing import Any

from . import bankruptcy_forecast_math as _fp
from .engine_dates import project_engine_date

SCHEMA = "information.loan_interest_quote_math.v1"
MAX_LOANS = 64
I32_MIN = -(1 << 31)
I32_MAX = (1 << 31) - 1
I64_MIN = -(1 << 63)
I64_MAX = (1 << 63) - 1
NATIVE_INTEREST_RVA = 0x86B6C0
NATIVE_LOAN_HELPER_RVA = 0x86B4E0
FIXED_DIVISOR = 0x1F40000
FAST_OFFSET = 0x189373
FAST_LIMIT_INCLUSIVE = 0x39580D
LOAN_KEYS = frozenset(("principal_i32", "stored_rate_i32", "expiry_raw_i32"))


def _i32(value: Any, label: str) -> int:
    if type(value) is not int or not I32_MIN <= value <= I32_MAX:
        raise ValueError(f"{label}_must_be_signed_i32")
    return value


def _wrap(value: int, width: int) -> int:
    value &= (1 << width) - 1
    return value - (1 << width) if value & (1 << (width - 1)) else value


def _div(numerator: int, denominator: int) -> int:
    quotient = abs(numerator) // denominator
    return -quotient if numerator < 0 else quotient


def _mul_f32(left: float, right: float) -> float:
    a, b = left.as_integer_ratio()
    c, d = right.as_integer_ratio()
    return _fp._f32_from_ratio(
        a * c, b * d,
        negative_zero=(a * c == 0 and (math.copysign(1.0, left) < 0)
                       != (math.copysign(1.0, right) < 0)),
    )


def _base() -> dict[str, Any]:
    return {
        "schema": SCHEMA, "status": "known", "unit": "ducats", "scale": 1000,
        "complete": False, "publication_admitted": False,
        "native_execution_observed": False, "native_fp_environment_verified": False,
        "fp_assumptions": {
            "rounding": "binary32_round_to_nearest_ties_to_even",
            "exceptions": "masked; invalid CVTTSS2SI produces INT_MIN before positive clamp",
        },
        "basis": "static_b23_remaining_interest_quote_arithmetic",
    }


def evaluate(*, principal_scaled_i32: int, stored_rate_i32: int,
             months_i32: int) -> dict[str, Any]:
    """Model the helper's three input dwords, including unusual signed inputs.

    ``principal_scaled_i32`` is already the caller's low32(principal*1000).
    The month and rate fast/slow paths are compiler reciprocal divisions;
    their equivalent signed quotients are evaluated exactly here.
    """
    principal = _i32(principal_scaled_i32, "principal_scaled_i32")
    rate = _i32(stored_rate_i32, "stored_rate_i32")
    months = _i32(months_i32, "months_i32")
    month_scaled = _wrap(months * 1000, 32)
    month_fast = ((month_scaled + FAST_OFFSET) & 0xFFFFFFFF) <= FAST_LIMIT_INCLUSIVE
    month_numerator = (_wrap(month_scaled * 1000, 32)
                       if month_fast else month_scaled * 1000)
    month_factor = _wrap(_div(month_numerator, 100000), 32)
    rate_fast = ((rate + FAST_OFFSET) & 0xFFFFFFFF) <= FAST_LIMIT_INCLUSIVE
    rate_numerator = _wrap(rate * 1000, 32) if rate_fast else rate * 1000
    rate_factor = _wrap(_div(rate_numerator, 12000), 32)

    principal_fixed = _div(principal << 30, FIXED_DIVISOR)
    month_fixed = _div(month_factor << 30, FIXED_DIVISOR)
    rate_fixed = _div(rate_factor << 30, FIXED_DIVISOR)
    first_product = _wrap(month_fixed * principal_fixed, 64)
    first_shifted = first_product >> 15
    second_product = _wrap(rate_fixed * first_shifted, 64)
    second_shifted = second_product >> 15

    converted = _fp._f32_from_ratio(second_shifted)
    unscaled = _mul_f32(converted, _fp._f32_from_ratio(1, 32768))
    scaled = _mul_f32(unscaled, _fp._f32_from_ratio(1000))
    biased = _fp._f32_add(scaled, _fp._f32_from_ratio(1, 2))
    negative_branch = unscaled < 0
    # Every reachable input is finite.  floorf has no NaN branch in this model.
    rounded = _fp._f32_from_ratio(math.floor(biased)) if negative_branch else biased
    converted_i32, conversion_invalid = _fp._cvttss2si(rounded)
    amount = converted_i32 if converted_i32 > 0 else 0
    trace = {
        "principal_scaled_i32": principal, "stored_rate_i32": rate, "months_i32": months,
        "month_scaled_i32": month_scaled, "month_fast_path": month_fast,
        "month_numerator": month_numerator, "month_factor_i32": month_factor,
        "rate_fast_path": rate_fast, "rate_numerator": rate_numerator, "rate_factor_i32": rate_factor,
        "principal_fixed_i64": principal_fixed, "month_fixed_i64": month_fixed,
        "rate_fixed_i64": rate_fixed,
        "first_product_i64": first_product, "first_shifted_i64": first_shifted,
        "second_product_i64": second_product, "second_shifted_i64": second_shifted,
        "first_product_wrapped": not I64_MIN <= month_fixed * principal_fixed <= I64_MAX,
        "second_product_wrapped": not I64_MIN <= rate_fixed * first_shifted <= I64_MAX,
        "converted_f32_bits": _fp._f32_bits(converted),
        "unscaled_f32_bits": _fp._f32_bits(unscaled),
        "scaled_f32_bits": _fp._f32_bits(scaled),
        "biased_f32_bits": _fp._f32_bits(biased),
        "negative_floor_branch": negative_branch, "rounded_f32_bits": _fp._f32_bits(rounded),
        "conversion_i32": converted_i32, "conversion_invalid": conversion_invalid,
    }
    result = _base()
    result.update(source_function_rva=hex(NATIVE_INTEREST_RVA), amount_i32=amount,
                  value=amount / 1000, conversion_invalid=conversion_invalid, trace=trace)
    return result


def months_between(*, expiry_raw_i32: int, as_of_raw_i32: int) -> int:
    """Return the native fixed-calendar month-index difference, without clamping."""
    expiry = project_engine_date(_i32(expiry_raw_i32, "expiry_raw_i32"))
    current = project_engine_date(_i32(as_of_raw_i32, "as_of_raw_i32"))
    return _wrap((expiry["year_index"] - current["year_index"]) * 12
                 + expiry["month_index_zero_based"] - current["month_index_zero_based"], 32)


def quote_loan(*, principal_i32: int, stored_rate_i32: int,
               expiry_raw_i32: int, as_of_raw_i32: int) -> dict[str, Any]:
    """Reproduce one 0x86B4E0 interest result and its principal-plus-interest term."""
    principal = _i32(principal_i32, "principal_i32")
    rate = _i32(stored_rate_i32, "stored_rate_i32")
    months = months_between(expiry_raw_i32=expiry_raw_i32, as_of_raw_i32=as_of_raw_i32)
    scaled = _wrap(principal * 1000, 32)
    interest = evaluate(principal_scaled_i32=scaled, stored_rate_i32=rate, months_i32=months)
    combined = _wrap(scaled + interest["amount_i32"], 32)
    result = _base()
    result.update(
        source_function_rva=hex(NATIVE_LOAN_HELPER_RVA), principal_i32=principal,
        principal_scaled_i32=scaled, principal_scaling_wrapped=scaled != principal * 1000,
        stored_rate_i32=rate, expiry_raw_i32=expiry_raw_i32, as_of_raw_i32=as_of_raw_i32,
        months_i32=months, interest=interest, quote_i32=combined, quote_value=combined / 1000,
        quote_addition_wrapped=combined != scaled + interest["amount_i32"],
    )
    return result


def quote_total(*, loans: Sequence[Mapping[str, int]], as_of_raw_i32: int) -> dict[str, Any]:
    """Fold at most64 supplied records as the description's signed dword sum.

    This validates the supplied records and arithmetic; it does not establish
    country identity, list membership/completeness, visibility, or ROM guards.
    """
    _i32(as_of_raw_i32, "as_of_raw_i32")
    if not isinstance(loans, (list, tuple)) or len(loans) > MAX_LOANS:
        raise ValueError("loans_must_be_list_or_tuple_with_at_most_64_records")
    rows = []
    total = principal_total = interest_total = 0
    sum_wrapped = False
    for loan in loans:
        if not isinstance(loan, Mapping) or set(loan) != LOAN_KEYS:
            raise ValueError("loan_fields_must_match_principal_rate_expiry_contract")
        row = quote_loan(as_of_raw_i32=as_of_raw_i32, **loan)
        expected = total + row["quote_i32"]
        total = _wrap(expected, 32)
        sum_wrapped |= total != expected
        principal_total = _wrap(principal_total + row["principal_scaled_i32"], 32)
        interest_total = _wrap(interest_total + row["interest"]["amount_i32"], 32)
        rows.append(row)
    result = _base()
    result.update(source_function_rva="0x7c2eb0", loan_count=len(rows), loans=rows,
                  input_scope="supplied_loans_only", source_list_completeness_verified=False,
                  principal_scaled_i32=principal_total, interest_scaled_i32=interest_total,
                  quote_i32=total, quote_value=total / 1000, sum_wrapped=sum_wrapped,
                  invalid_conversion_count=sum(row["interest"]["conversion_invalid"] for row in rows))
    return result


__all__ = ["evaluate", "months_between", "quote_loan", "quote_total"]
