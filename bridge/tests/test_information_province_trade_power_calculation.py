"""Independent arithmetic checks for the province trade-power cache writer."""
from __future__ import annotations

import random

import pytest

from bridge.information.province_trade_power_calculation import calculate_current


I32_MIN = -(1 << 31)
I32_MAX = (1 << 31) - 1
I64_MIN = -(1 << 63)
I64_MAX = (1 << 63) - 1
MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1
MAGIC_DIV1000 = 0x20C49BA5E353F7CF
OUTPUT_KEYS = {
    "raw",
    "ratio_sum_raw",
    "further_factor_raw",
    "further_product_div1000",
    "effective_ratio_raw",
    "unclamped_product_div1000",
}


def _i32(value: int) -> int:
    value &= MASK32
    return value - (1 << 32) if value & (1 << 31) else value


def _native_div1000(numerator: int) -> int:
    """Model signed high-half IMUL, SAR 7, then logical-sign correction."""
    assert I64_MIN <= numerator <= I64_MAX
    high_signed = (numerator * MAGIC_DIV1000) >> 64
    quotient_after_sar7 = high_signed >> 7
    logical_sign_correction = (numerator & MASK64) >> 63
    return quotient_after_sar7 + logical_sign_correction


def _oracle(flat: int, province_ratio: int, controller_ratio: int,
            further_ratio: int, owner_bonus: int) -> dict[str, int]:
    ratio_sum_raw = _i32(1000 + province_ratio + controller_ratio + owner_bonus)
    further_factor_raw = _i32(1000 + further_ratio)
    further_product_div1000 = _native_div1000(
        ratio_sum_raw * further_factor_raw
    )
    effective_ratio_raw = max(0, _i32(further_product_div1000))
    unclamped_product_div1000 = _native_div1000(flat * effective_ratio_raw)
    raw = max(0, _i32(unclamped_product_div1000))
    return {
        "raw": raw,
        "ratio_sum_raw": ratio_sum_raw,
        "further_factor_raw": further_factor_raw,
        "further_product_div1000": further_product_div1000,
        "effective_ratio_raw": effective_ratio_raw,
        "unclamped_product_div1000": unclamped_product_div1000,
    }


FIXED_CASES = [
    (125000, 0, 0, 0, 0),
    (17520, 250, -100, -25, 100),
    (0, 1000, 500, 200, 300),
    (-12345, 0, 0, 0, 0),
    (12345, -1002, 0, 0, 0),
    (I32_MIN, I32_MIN, I32_MAX, I32_MIN, I32_MAX),
    (I32_MAX, I32_MAX - 1000, 0, I32_MAX - 1000, 0),
    # q1 is large positive, but its signed low 32 bits are negative and clamp to 0.
    (I32_MAX, I32_MAX - 1000, 0, I32_MAX - 1000, 0),
    # q2 exceeds 2^32; its signed low 32 bits are positive and remain the result.
    (I32_MAX, 1001, 0, 0, 0),
    # q2 has a negative signed low word, so the writer clamps after i32 conversion.
    (I32_MAX, 1, 0, 0, 0),
    (I32_MAX, I32_MAX, I32_MAX, I32_MAX, I32_MAX),
    (I32_MIN, I32_MAX, I32_MIN, I32_MAX, I32_MIN),
]


@pytest.mark.parametrize("inputs", FIXED_CASES)
def test_fixed_signed_and_wrap_cases_match_native_magic_oracle(inputs):
    result = calculate_current(*inputs)

    assert set(result) == OUTPUT_KEYS
    assert result == _oracle(*inputs)
    assert 0 <= result["raw"] <= I32_MAX


def test_low_32_bit_signed_clamp_boundaries_are_applied_after_division():
    q1_wraps_negative = calculate_current(
        I32_MAX, I32_MAX - 1000, 0, I32_MAX - 1000, 0
    )
    assert q1_wraps_negative["further_product_div1000"] > I32_MAX
    assert _i32(q1_wraps_negative["further_product_div1000"]) < 0
    assert q1_wraps_negative["effective_ratio_raw"] == 0
    assert q1_wraps_negative["raw"] == 0

    q2_wraps_positive = calculate_current(I32_MAX, 1001, 0, 0, 0)
    assert q2_wraps_positive["unclamped_product_div1000"] > (1 << 32)
    assert _i32(q2_wraps_positive["unclamped_product_div1000"]) == 2147481
    assert q2_wraps_positive["raw"] == 2147481

    q2_wraps_negative = calculate_current(I32_MAX, 1, 0, 0, 0)
    assert _i32(q2_wraps_negative["unclamped_product_div1000"]) < 0
    assert q2_wraps_negative["raw"] == 0


def test_seeded_random_inputs_match_independent_native_magic_oracle():
    rng = random.Random(204)
    small = (-100000, -5000, -1001, -1000, -999, -1, 0, 1, 999, 1000,
             1001, 5000, 100000)
    boundary = (I32_MIN, I32_MIN + 1, I32_MIN + 999, -1, 0, 1,
                I32_MAX - 1000, I32_MAX - 1, I32_MAX)

    for index in range(768):
        values = []
        for _ in range(5):
            if index % 3 == 0:
                values.append(rng.randint(I32_MIN, I32_MAX))
            elif index % 3 == 1:
                values.append(rng.choice(small))
            else:
                values.append(rng.choice(boundary))
        inputs = tuple(values)
        result = calculate_current(*inputs)
        assert result == _oracle(*inputs), (index, inputs, result, _oracle(*inputs))


def test_magic_division_oracle_matches_truncation_for_signed_64_edges():
    rng = random.Random(1000)
    values = [I64_MIN, I64_MIN + 1, -1000001, -1000, -999, -1, 0, 1,
              999, 1000, 1000001, I64_MAX - 1, I64_MAX]
    values.extend(rng.randint(I64_MIN, I64_MAX) for _ in range(768))
    for value in values:
        expected = abs(value) // 1000
        if value < 0:
            expected = -expected
        assert _native_div1000(value) == expected


@pytest.mark.parametrize("bad_value", [True, False, 1.0, -0.5, "1", None])
@pytest.mark.parametrize("position", range(5))
def test_non_integer_values_are_rejected(bad_value, position: int):
    values = [0, 0, 0, 0, 0]
    values[position] = bad_value
    with pytest.raises(ValueError):
        calculate_current(*values)


@pytest.mark.parametrize("bad_value", [I32_MIN - 1, I32_MAX + 1])
@pytest.mark.parametrize("position", range(5))
def test_out_of_signed_32_bit_values_are_rejected(bad_value: int, position: int):
    values = [0, 0, 0, 0, 0]
    values[position] = bad_value
    with pytest.raises(ValueError):
        calculate_current(*values)
