from __future__ import annotations

import random

import pytest

from bridge.information import trade_income_calculation as calculation


INT32_MIN = -(1 << 31)
INT32_MAX = (1 << 31) - 1
MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1
MASK128 = (1 << 128) - 1
MAGIC_DIV1000 = 0x20C49BA5E353F7CF


def _wrap_i32_reference(value: int) -> int:
    value &= MASK32
    return value - (1 << 32) if value & (1 << 31) else value


def _magic_trunc0_div1000(value: int) -> int:
    """Independent signed-high-multiply oracle for the native /1000 sequence."""
    product_128 = (value * MAGIC_DIV1000) & MASK128
    high_u64 = (product_128 >> 64) & MASK64
    high_i64 = high_u64 - (1 << 64) if high_u64 & (1 << 63) else high_u64
    quotient_after_sar7 = high_i64 >> 7
    sign_correction = 1 if quotient_after_sar7 < 0 else 0
    return quotient_after_sar7 + sign_correction


def _trunc0_reference(value: int, divisor: int) -> int:
    return value // divisor if value >= 0 else -((-value) // divisor)


def _reference_calculate(args: tuple[int, int, int, int, int, bool]) -> dict[str, int]:
    share, node_cash, country_base, modifier, bonus, bonus_applies = args
    combined = _wrap_i32_reference(country_base + modifier)
    clamped = max(10, min(2000, combined))
    multiplier = _wrap_i32_reference(clamped + 1000)
    if bonus_applies:
        multiplier = _wrap_i32_reference(multiplier + bonus)
    before_multiplier = _wrap_i32_reference(
        _magic_trunc0_div1000(share * node_cash)
    )
    income = _wrap_i32_reference(
        _magic_trunc0_div1000(before_multiplier * multiplier)
    )
    return {
        "clamped_modifier_raw": clamped,
        "multiplier_raw": multiplier,
        "income_before_multiplier_raw": before_multiplier,
        "income_raw": income,
    }


def test_known_current_income_example_and_exact_result_shape():
    result = calculation.calculate_current(408, 9221, 120, 0, 100, True)

    assert result == {
        "clamped_modifier_raw": 120,
        "multiplier_raw": 1220,
        "income_before_multiplier_raw": 3762,
        "income_raw": 4589,
    }
    assert set(result) == {
        "clamped_modifier_raw", "multiplier_raw",
        "income_before_multiplier_raw", "income_raw",
    }


def test_bonus_is_applied_only_when_flag_is_true():
    with_bonus = calculation.calculate_current(408, 9221, 120, 0, 100, True)
    without_bonus = calculation.calculate_current(408, 9221, 120, 0, 100, False)

    assert with_bonus["multiplier_raw"] == 1220
    assert without_bonus["multiplier_raw"] == 1120
    assert with_bonus["income_raw"] == 4589
    assert without_bonus["income_raw"] == 4213


@pytest.mark.parametrize(
    ("country_base", "modifier", "expected_clamped"),
    [
        (-2000, 100, 10),
        (3000, 0, 2000),
        (INT32_MAX, 1, 10),
        (INT32_MIN, -1, 2000),
    ],
)
def test_modifier_sum_wraps_before_signed_clamp(country_base, modifier, expected_clamped):
    result = calculation.calculate_current(1, 1000, country_base, modifier, 0, False)

    assert result["clamped_modifier_raw"] == expected_clamped
    assert result["multiplier_raw"] == expected_clamped + 1000


def test_bonus_addition_wraps_as_signed_i32_without_a_second_clamp():
    result = calculation.calculate_current(1, 1000, 2000, 0, INT32_MAX, True)

    assert result["clamped_modifier_raw"] == 2000
    assert result["multiplier_raw"] == _wrap_i32_reference(3000 + INT32_MAX)
    assert result["multiplier_raw"] < 0


def test_negative_income_is_not_clamped_to_zero():
    result = calculation.calculate_current(-10, 1000, 0, 0, 0, False)

    assert result["income_before_multiplier_raw"] == -10
    assert result["income_raw"] == -10


def test_each_fixed_point_stage_truncates_before_the_next_stage():
    args = (1, 999, 1000, 0, 0, False)
    result = calculation.calculate_current(*args)
    multiplier = 2000
    collapsed = _trunc0_reference(args[0] * args[1] * multiplier, 1_000_000)

    assert result["income_before_multiplier_raw"] == 0
    assert result["income_raw"] == 0
    assert collapsed == 1
    assert result["income_raw"] != collapsed


def test_i32_wrap_is_applied_after_each_division_stage():
    args = (INT32_MAX, INT32_MAX, 2000, 0, 1000, True)

    result = calculation.calculate_current(*args)

    assert result == _reference_calculate(args)
    assert INT32_MIN <= result["income_before_multiplier_raw"] <= INT32_MAX
    assert INT32_MIN <= result["income_raw"] <= INT32_MAX


def test_signed_high_multiply_oracle_matches_truncation_reference():
    rng = random.Random(2091000)
    values = [INT32_MIN * INT32_MAX, INT32_MAX * INT32_MAX, -999, -1001, 999, 1001]
    values.extend(rng.randint(-(1 << 62), (1 << 62) - 1) for _ in range(256))

    for value in values:
        assert _magic_trunc0_div1000(value) == _trunc0_reference(value, 1000)


def test_fixed_seed_random_inputs_match_independent_native_arithmetic_oracle():
    rng = random.Random(209)

    for _ in range(256):
        args = (
            rng.randint(INT32_MIN, INT32_MAX),
            rng.randint(INT32_MIN, INT32_MAX),
            rng.randint(INT32_MIN, INT32_MAX),
            rng.randint(INT32_MIN, INT32_MAX),
            rng.randint(INT32_MIN, INT32_MAX),
            bool(rng.getrandbits(1)),
        )
        assert calculation.calculate_current(*args) == _reference_calculate(args)


@pytest.mark.parametrize(
    ("index", "bad_value"),
    [
        (0, True), (0, 1.0), (0, INT32_MAX + 1), (0, INT32_MIN - 1),
        (1, False), (1, "1000"), (1, INT32_MAX + 1),
        (2, True), (2, 2.5), (2, INT32_MIN - 1),
        (3, False), (3, None), (3, INT32_MAX + 1),
        (4, True), (4, 3.0), (4, INT32_MIN - 1),
    ],
)
def test_non_i32_numeric_inputs_are_rejected(index, bad_value):
    args: list[object] = [1, 1000, 120, 0, 0, False]
    args[index] = bad_value

    with pytest.raises(ValueError):
        calculation.calculate_current(*args)


@pytest.mark.parametrize("bad_flag", [0, 1, None, "true"])
def test_bonus_flag_requires_exact_bool(bad_flag):
    with pytest.raises(ValueError, match="bonus_applies_must_be_bool"):
        calculation.calculate_current(1, 1000, 120, 0, 0, bad_flag)

