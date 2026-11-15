"""Pure fixed-width arithmetic for the B23 finance and bankruptcy forecast.

This module models only the bounded arithmetic documented in
``ordinary-bankruptcy-forecast-001/ordinary-bankruptcy-forecast-correction-002.json``
and ``ordinary-finance-projection-001/ordinary-finance-projection-correction-002.json``.
It reads no memory and performs no game or permission operations. In particular,
``helper_return_i32`` is deliberately opaque: the audited callers use that
signed dword but its meaning is not established here.

The forecast's SSE operations are modeled as IEEE-754 binary32 with
round-to-nearest, ties-to-even at each conversion and scalar operation. The
current thread's MXCSR control word is not observed by this pure module. For
masked-invalid CVTTSS2SI, out-of-range conversion yields INT_MIN and the native
subsequent positive-only selection clamps that result to zero; the returned
``conversion_invalid`` flag preserves this distinction for the caller.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import math
import struct
from typing import Any


SCHEMA = "information.bankruptcy_forecast_math.v1"
MAX_LOANS = 64

I32_MIN = -(1 << 31)
I32_MAX = (1 << 31) - 1
U32_MASK = (1 << 32) - 1

BALANCE_POSITIVE_OFFSETS = (
    0x770, 0x774, 0x778, 0x77C, 0x780, 0x784, 0x788, 0x790,
    0x7AC, 0x7B0, 0x7B4, 0x7B8,
)
BALANCE_SUBTRACT_OFFSETS = (
    0x7BC, 0x7C4, 0x7C8, 0x7D0, 0x7D4, 0x7D8, 0x7DC, 0x7E0,
    0x7E4, 0x824, 0x828, 0x834,
)
BALANCE_ADJUSTMENT_OFFSETS = (0x78C, 0x7CC)
ELIGIBLE_INCOME_OFFSETS = (
    0x770, 0x774, 0x778, 0x77C, 0x780, 0x784, 0x788, 0x790, 0x7AC, 0x7B0,
)
ELIGIBLE_INCOME_INDICES = (0, 1, 2, 3, 4, 5, 6, 8, 15, 16)
REQUIRED_LEDGER_OFFSETS = tuple(sorted(
    set(BALANCE_POSITIVE_OFFSETS)
    | set(BALANCE_SUBTRACT_OFFSETS)
    | set(BALANCE_ADJUSTMENT_OFFSETS)
))
NATIVE_INCOME_CACHE_OFFSETS = tuple(0x770 + 4 * index for index in range(19))
ALLOWED_LEDGER_OFFSETS = tuple(sorted(
    set(REQUIRED_LEDGER_OFFSETS) | set(NATIVE_INCOME_CACHE_OFFSETS)
))

F32_1000 = struct.unpack("<f", bytes.fromhex("00007a44"))[0]
F32_NEGATIVE_005 = struct.unpack("<f", bytes.fromhex("cdcc4cbd"))[0]
F32_SIGN_MASK = 0x80000000
U32_SIGN_MASK = 0x80000000


def _wrap_i32(value: int) -> int:
    value &= U32_MASK
    return value - (1 << 32) if value & U32_SIGN_MASK else value


def _as_i32(value: Any, label: str) -> int:
    if type(value) is not int or not I32_MIN <= value <= I32_MAX:
        raise ValueError(f"{label}_must_be_signed_i32")
    return value


def _trunc_div(numerator: int, denominator: int) -> int:
    """Signed integer division with C++/x86 truncation toward zero."""
    if denominator == 0:
        raise ZeroDivisionError("native_formula_zero_denominator")
    quotient = abs(numerator) // abs(denominator)
    return -quotient if (numerator < 0) != (denominator < 0) else quotient


def _round_ratio_ties_even(numerator: int, denominator: int) -> int:
    quotient, remainder = divmod(numerator, denominator)
    twice = remainder * 2
    if twice > denominator or (twice == denominator and quotient & 1):
        quotient += 1
    return quotient


def _floor_log2_ratio(numerator: int, denominator: int) -> int:
    exponent = numerator.bit_length() - denominator.bit_length()
    if exponent >= 0:
        if numerator < (denominator << exponent):
            exponent -= 1
    elif (numerator << -exponent) < denominator:
        exponent -= 1
    return exponent


def _f32_from_ratio(numerator: int, denominator: int = 1,
                    *, negative_zero: bool = False) -> float:
    """Round an exact rational directly to IEEE binary32, ties-to-even."""
    if denominator == 0:
        raise ZeroDivisionError("binary32_division_by_zero")
    if denominator < 0:
        numerator = -numerator
        denominator = -denominator
    if numerator == 0:
        bits = F32_SIGN_MASK if negative_zero else 0
        return struct.unpack("<f", struct.pack("<I", bits))[0]

    sign = F32_SIGN_MASK if numerator < 0 else 0
    numerator = abs(numerator)
    exponent = _floor_log2_ratio(numerator, denominator)

    if exponent < -126:
        significand = _round_ratio_ties_even(numerator << 149, denominator)
        if significand == 0:
            bits = sign
        elif significand >= (1 << 23):
            bits = sign | (1 << 23)  # rounded up to the smallest normal
        else:
            bits = sign | significand
        return struct.unpack("<f", struct.pack("<I", bits))[0]

    shift = 23 - exponent
    if shift >= 0:
        significand = _round_ratio_ties_even(numerator << shift, denominator)
    else:
        significand = _round_ratio_ties_even(numerator, denominator << -shift)
    if significand >= (1 << 24):
        significand >>= 1
        exponent += 1
    if exponent > 127:
        bits = sign | 0x7F800000
    else:
        bits = sign | ((exponent + 127) << 23) | (significand - (1 << 23))
    return struct.unpack("<f", struct.pack("<I", bits))[0]


def _f32_from_i32(value: int) -> float:
    return _f32_from_ratio(value)


def _f32_parts(value: float) -> tuple[int, int]:
    if not math.isfinite(value):
        raise ValueError("binary32_operation_expected_finite_input")
    return value.as_integer_ratio()


def _f32_add(left: float, right: float) -> float:
    left_num, left_den = _f32_parts(left)
    right_num, right_den = _f32_parts(right)
    numerator = left_num * right_den + right_num * left_den
    denominator = left_den * right_den
    negative_zero = (
        numerator == 0
        and math.copysign(1.0, left) < 0
        and math.copysign(1.0, right) < 0
    )
    return _f32_from_ratio(numerator, denominator, negative_zero=negative_zero)


def _f32_div(numerator_value: float, denominator_value: float) -> float:
    numerator, numerator_den = _f32_parts(numerator_value)
    denominator, denominator_den = _f32_parts(denominator_value)
    if denominator == 0:
        raise ZeroDivisionError("native_forecast_binary32_denominator_zero")
    exact_numerator = numerator * denominator_den
    exact_denominator = numerator_den * denominator
    negative_zero = (
        numerator == 0
        and (math.copysign(1.0, numerator_value) < 0)
        != (math.copysign(1.0, denominator_value) < 0)
    )
    return _f32_from_ratio(
        exact_numerator, exact_denominator, negative_zero=negative_zero)


def _f32_bits(value: float) -> str:
    return f"0x{struct.unpack('<I', struct.pack('<f', value))[0]:08X}"


def _negate_f32(value: float) -> float:
    bits = struct.unpack("<I", struct.pack("<f", value))[0] ^ F32_SIGN_MASK
    return struct.unpack("<f", struct.pack("<I", bits))[0]


def _prepare_inputs(
    ledger_words: Mapping[int, int],
    loans: Sequence[Mapping[str, int]],
    helper_return_i32: int,
    treasury_raw_i32: int,
    factor_u8: int,
    factor_raw_i32: int,
) -> tuple[dict[int, int], list[dict[str, int]], int, int, int, int]:
    if not isinstance(ledger_words, Mapping):
        raise ValueError("ledger_words_must_be_mapping")
    words: dict[int, int] = {}
    for offset, value in ledger_words.items():
        if type(offset) is not int or offset < 0:
            raise ValueError("ledger_word_offset_must_be_nonnegative_int")
        words[offset] = _as_i32(value, f"ledger_word_{offset:x}")
    if len(words) > 64:
        raise ValueError("ledger_words_exceed_64_word_bound")
    missing = sorted(set(REQUIRED_LEDGER_OFFSETS) - words.keys())
    if missing:
        raise ValueError("ledger_words_missing_offsets:" + ",".join(f"0x{x:X}" for x in missing))
    unexpected = sorted(words.keys() - set(ALLOWED_LEDGER_OFFSETS))
    if unexpected:
        raise ValueError("ledger_words_unrecognized_offsets:" + ",".join(f"0x{x:X}" for x in unexpected))

    if not isinstance(loans, Sequence) or isinstance(loans, (str, bytes, bytearray)):
        raise ValueError("loans_must_be_a_sequence")
    if len(loans) > MAX_LOANS:
        raise ValueError(f"loans_exceed_{MAX_LOANS}_record_bound")
    normalized_loans: list[dict[str, int]] = []
    for index, loan in enumerate(loans):
        if not isinstance(loan, Mapping):
            raise ValueError(f"loan_{index}_must_be_mapping")
        normalized_loans.append({
            "principal": _as_i32(loan.get("principal"), f"loan_{index}_principal"),
            "stored_rate": _as_i32(loan.get("stored_rate"), f"loan_{index}_stored_rate"),
            "marker27": _as_u8(loan.get("marker27"), f"loan_{index}_marker27"),
            "flag35": _as_u8(loan.get("flag35"), f"loan_{index}_flag35"),
        })

    helper = _as_i32(helper_return_i32, "helper_return_i32")
    treasury = _as_i32(treasury_raw_i32, "treasury_raw_i32")
    factor_raw = _as_i32(factor_raw_i32, "factor_raw_i32")
    factor = _as_u8(factor_u8, "factor_u8")
    return words, normalized_loans, helper, treasury, factor, factor_raw


def _as_u8(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= 0xFF:
        raise ValueError(f"{label}_must_be_u8")
    return value


def _monthly_balance(words: Mapping[int, int], loans: Sequence[Mapping[str, int]],
                      helper_return_i32: int) -> tuple[int, dict[str, Any]]:
    positive = 0
    for offset in BALANCE_POSITIVE_OFFSETS:
        positive = _wrap_i32(positive + words[offset])

    loan_total = 0
    loan_rows: list[dict[str, Any]] = []
    for index, loan in enumerate(loans):
        use_helper = loan["marker27"] == 0 and loan["flag35"] == 0
        rate = helper_return_i32 if use_helper else loan["stored_rate"]
        principal_scaled_i32 = _wrap_i32(loan["principal"] * 1000)
        interest_product_i64 = principal_scaled_i32 * rate
        payment_scaled_i32 = _wrap_i32(_trunc_div(interest_product_i64, 1000))
        payment_i32 = _wrap_i32(_trunc_div(payment_scaled_i32 * 1000, 1_200_000))
        loan_total = _wrap_i32(loan_total + payment_i32)
        loan_rows.append({
            "index": index,
            "rate_source": "helper_return_i32" if use_helper else "stored_rate",
            "rate_i32": rate,
            "principal_scaled_i32": principal_scaled_i32,
            "payment_scaled_i32": payment_scaled_i32,
            "monthly_payment_i32": payment_i32,
            "loan_payment_sum_i32": loan_total,
        })

    subtract_fields = 0
    for offset in BALANCE_SUBTRACT_OFFSETS:
        subtract_fields = _wrap_i32(subtract_fields + words[offset])
    subtract_total = _wrap_i32(subtract_fields + loan_total)
    adjustment = _wrap_i32(words[0x78C] - words[0x7CC])
    balance = _wrap_i32(_wrap_i32(positive - subtract_total) - adjustment)
    return balance, {
        "positive_offsets": [f"0x{x:X}" for x in BALANCE_POSITIVE_OFFSETS],
        "positive_total_i32": positive,
        "subtract_offsets": [f"0x{x:X}" for x in BALANCE_SUBTRACT_OFFSETS],
        "subtract_fields_total_i32": subtract_fields,
        "loan_payment_sum_i32": loan_total,
        "loan_payments": loan_rows,
        "combined_subtract_total_i32": subtract_total,
        "adjustment_78c_minus_7cc_i32": adjustment,
        "monthly_balance_i32": balance,
    }


def _eligible_income(words: Mapping[int, int]) -> int:
    total = 0
    for offset in ELIGIBLE_INCOME_OFFSETS:
        value = words[offset]
        if value != 0:
            total = _wrap_i32(total + value)
    return total


def _loan_capacity(
    eligible_income_sum_i32: int,
    helper_return_i32: int,
    factor_u8: int,
    factor_raw_i32: int,
) -> tuple[int, dict[str, Any]]:
    factor_product_i32 = _wrap_i32(factor_u8 * factor_raw_i32)
    clamped_factor_i32 = 1000 if factor_product_i32 < 1000 else factor_product_i32
    unsigned_factor_thousands = (clamped_factor_i32 & U32_MASK) // 1000
    a_i32 = _wrap_i32(unsigned_factor_thousands * 1000)

    b_i32 = _wrap_i32(_trunc_div(a_i32 * helper_return_i32, 1000))
    c_i32 = _wrap_i32(_trunc_div(b_i32 * 1000, 100_000))
    d_i32 = _wrap_i32(_trunc_div(c_i32 * 1000, 12_000))

    diagnostics: dict[str, Any] = {
        "factor_product_i32": factor_product_i32,
        "factor_clamped_i32": clamped_factor_i32,
        "unsigned_factor_div_1000": unsigned_factor_thousands,
        "a_i32": a_i32,
        "helper_return_i32": helper_return_i32,
        "b_i32": b_i32,
        "c_i32": c_i32,
        "denominator_i32": d_i32,
        "eligible_income_sum_i32": eligible_income_sum_i32,
    }
    if d_i32 == 0:
        diagnostics.update({
            "denominator_zero_returns_capacity_3": True,
            "idiv_path": None,
            "balance_quotient_i32": None,
        })
        return 3, diagnostics

    biased_u32 = (eligible_income_sum_i32 + 0x189373) & U32_MASK
    small_path = biased_u32 <= 0x39580D
    if small_path:
        numerator_i32 = _wrap_i32(eligible_income_sum_i32 * 1000)
        quotient = _trunc_div(numerator_i32, d_i32)
        if not I32_MIN <= quotient <= I32_MAX:
            raise AssertionError("audited_32_bit_idiv_range_invariant_failed")
        quotient_i32 = quotient
        diagnostics.update({
            "idiv_path": "signed_i32",
            "path_bias_u32": biased_u32,
            "division_numerator_i32": numerator_i32,
            "division_quotient_i32": quotient_i32,
        })
    else:
        numerator_i64 = eligible_income_sum_i32 * 1000
        quotient_i64 = _trunc_div(numerator_i64, d_i32)
        quotient_i32 = _wrap_i32(quotient_i64)
        diagnostics.update({
            "idiv_path": "signed_i64",
            "path_bias_u32": biased_u32,
            "division_numerator_i64": numerator_i64,
            "division_quotient_i64": quotient_i64,
            "division_quotient_low_i32": quotient_i32,
        })

    if quotient_i32 < 0:
        diagnostics.update({
            "negative_quotient_returns_capacity_3": True,
            "balance_quotient_i32": quotient_i32,
        })
        return 3, diagnostics

    quotient_per_thousand = _trunc_div(quotient_i32, 1000)
    computed = quotient_per_thousand + 1
    capacity = max(3, computed)
    diagnostics.update({
        "negative_quotient_returns_capacity_3": False,
        "balance_quotient_i32": quotient_i32,
        "quotient_div_1000_i32": quotient_per_thousand,
        "capacity_before_minimum": computed,
        "capacity_i32": capacity,
    })
    return capacity, diagnostics


def _cvttss2si(value: float) -> tuple[int, bool]:
    invalid = (
        not math.isfinite(value)
        or value < float(I32_MIN)
        or value >= float(1 << 31)
    )
    if invalid:
        return I32_MIN, True
    # int(float) truncates toward zero; binary32 values are exactly representable
    # as Python doubles, so this reproduces the valid CVTTSS2SI integer result.
    return int(value), False


def evaluate(
    *,
    ledger_words: Mapping[int, int],
    loans: Sequence[Mapping[str, int]],
    helper_return_i32: int,
    treasury_raw_i32: int,
    factor_u8: int,
    factor_raw_i32: int,
) -> dict[str, Any]:
    """Return exact B23 arithmetic outputs and private diagnostics.

    ``ledger_words`` maps country-relative byte offsets to signed 32-bit words.
    Each loan mapping supplies ``principal``, ``stored_rate``, ``marker27`` and
    ``flag35``. No date is calculated or returned.
    """
    words, normalized_loans, helper, treasury, factor, factor_raw = _prepare_inputs(
        ledger_words, loans, helper_return_i32, treasury_raw_i32, factor_u8,
        factor_raw_i32)
    balance, balance_diag = _monthly_balance(words, normalized_loans, helper)
    balance_float = _f32_from_i32(balance)
    balance_scaled = _f32_div(balance_float, F32_1000)
    threshold_diag = {
        "balance_i32": balance,
        "balance_cvtdq2ps_f32": balance_float,
        "balance_cvtdq2ps_bits": _f32_bits(balance_float),
        "balance_div_1000_f32": balance_scaled,
        "balance_div_1000_bits": _f32_bits(balance_scaled),
        "threshold_left_f32": F32_NEGATIVE_005,
        "threshold_left_bits": _f32_bits(F32_NEGATIVE_005),
        "ordered_comparison_left_le_right": F32_NEGATIVE_005 <= balance_scaled,
        "comparison_model": "COMISS -0.05f, balance_f32/1000f; JBE when left<=right (all constructed operands are finite).",
    }
    diagnostics: dict[str, Any] = {
        "monthly_balance": balance_diag,
        "threshold": threshold_diag,
        "float_model": {
            "format": "IEEE-754 binary32",
            "rounding": "roundTiesToEven after each CVTDQ2PS, DIVSS and ADDSS model step",
            "assumption": "The current thread MXCSR rounding mode and exception masks were not observed; this is the requested mathematical model only.",
            "cvttss2si": "truncate toward zero; masked invalid/out-of-range gives INT_MIN, followed by the native positive-only clamp to zero",
        },
    }

    if threshold_diag["ordered_comparison_left_le_right"]:
        months = 1000
        conversion_invalid = False
        no_material_deficit = True
        diagnostics["forecast"] = {
            "branch": "threshold_sentinel",
            "capacity": None,
            "eligible_income_sum_i32": None,
            "active_loan_count_i32": None,
            "remaining_capacity_i32": None,
            "cvttss2si_result_i32": None,
        }
    else:
        eligible_sum = _eligible_income(words)
        capacity, capacity_diag = _loan_capacity(eligible_sum, helper, factor, factor_raw)

        active_count = 0
        for loan in normalized_loans:
            if loan["marker27"] == 0:
                active_count = _wrap_i32(active_count + 1)
        remaining_difference = _wrap_i32(capacity - active_count)
        # The native CMOVNS tests SF==0 on the wrapped SUB result.
        remaining_capacity = remaining_difference if remaining_difference >= 0 else 0

        forecast_factor_product = _wrap_i32(factor * factor_raw)
        forecast_factor = 1000 if forecast_factor_product < 1000 else forecast_factor_product
        forecast_factor_div_1000 = (forecast_factor & U32_MASK) // 1000
        forecast_scaled_capacity = _wrap_i32(forecast_factor_div_1000 * remaining_capacity)

        scaled_capacity_f32 = _f32_from_i32(forecast_scaled_capacity)
        treasury_f32 = _f32_from_i32(treasury)
        treasury_per_thousand_f32 = _f32_div(treasury_f32, F32_1000)
        numerator_f32 = _f32_add(scaled_capacity_f32, treasury_per_thousand_f32)
        denominator_f32 = _negate_f32(balance_scaled)
        ratio_f32 = _f32_div(numerator_f32, denominator_f32)
        cvtt_result, conversion_invalid = _cvttss2si(ratio_f32)
        months = cvtt_result if cvtt_result > 0 else 0
        no_material_deficit = False

        diagnostics["forecast"] = {
            "branch": "computed_months",
            "eligible_income_indices": list(ELIGIBLE_INCOME_INDICES),
            "eligible_income_sum_i32": eligible_sum,
            "loan_capacity": capacity,
            "loan_capacity_diagnostics": capacity_diag,
            "active_loan_count_i32": active_count,
            "capacity_minus_active_count_i32": remaining_difference,
            "remaining_capacity_sign_flag": 1 if remaining_difference < 0 else 0,
            "remaining_capacity_i32": remaining_capacity,
            "factor_product_i32": forecast_factor_product,
            "factor_clamped_i32": forecast_factor,
            "factor_unsigned_div_1000": forecast_factor_div_1000,
            "factor_times_remaining_capacity_i32": forecast_scaled_capacity,
            "capacity_float32": scaled_capacity_f32,
            "capacity_float32_bits": _f32_bits(scaled_capacity_f32),
            "treasury_raw_i32": treasury,
            "treasury_cvtdq2ps_f32": treasury_f32,
            "treasury_div_1000_f32": treasury_per_thousand_f32,
            "treasury_div_1000_bits": _f32_bits(treasury_per_thousand_f32),
            "numerator_addss_f32": numerator_f32,
            "numerator_addss_bits": _f32_bits(numerator_f32),
            "denominator_negated_balance_f32": denominator_f32,
            "denominator_bits": _f32_bits(denominator_f32),
            "ratio_divss_f32": ratio_f32,
            "ratio_divss_bits": _f32_bits(ratio_f32),
            "cvttss2si_result_i32": cvtt_result,
            "conversion_invalid": conversion_invalid,
            "positive_only_clamp_applied": cvtt_result <= 0,
            "months_clamped_i32": months,
        }

    return {
        "schema": SCHEMA,
        "months_raw_i32": months,
        "warning": months < 12,
        "imminent": months == 0,
        "no_material_deficit": no_material_deficit,
        "conversion_invalid": conversion_invalid,
        "diagnostics": diagnostics,
    }
