from __future__ import annotations

from fractions import Fraction
import random

import pytest

from bridge.information import province_trade_value_calculation as calculation


I32_MIN = -(1 << 31)
I32_MAX = (1 << 31) - 1
SCALE = 1000


def _wrap_i32_independent(value: int) -> int:
    return ((value + (1 << 31)) % (1 << 32)) - (1 << 31)


def _trunc0_fraction(numerator: int, denominator: int) -> int:
    return int(Fraction(numerator, denominator))


def _oracle_current(args: tuple[int, ...]) -> dict[str, int]:
    province_goods, owner_goods, province_modifier, owner_modifier, price, value_add, value_modifier = args
    goods_base = _wrap_i32_independent(province_goods + owner_goods)
    combined_modifier = _wrap_i32_independent(province_modifier + owner_modifier)
    goods_factor = _wrap_i32_independent(max(-SCALE, combined_modifier) + SCALE)
    goods_raw = max(0, _wrap_i32_independent(
        _trunc0_fraction(goods_base * goods_factor, SCALE)))
    priced_raw = max(0, _wrap_i32_independent(
        _trunc0_fraction(goods_raw * price, SCALE)))
    subtotal = _wrap_i32_independent(priced_raw + value_add)
    value_factor = max(10, min(2000, _wrap_i32_independent(value_modifier + SCALE)))
    value_raw = _wrap_i32_independent(
        _trunc0_fraction(subtotal * value_factor, SCALE))
    return {
        "goods_base_raw": goods_base,
        "combined_goods_modifier_raw": combined_modifier,
        "goods_factor_raw": goods_factor,
        "goods_raw": goods_raw,
        "priced_raw": priced_raw,
        "subtotal_raw": subtotal,
        "value_factor_raw": value_factor,
        "value_raw": value_raw,
    }


def _oracle_aggregate(values: list[int] | tuple[int, ...]) -> dict[str, int]:
    total = 0
    for item in values:
        total = _wrap_i32_independent(total + item)
    return {
        "sum_raw": total,
        "node_input_raw": _wrap_i32_independent(
            _trunc0_fraction(total * SCALE, 12000)),
    }


def test_known_values_and_each_fixed_point_stage_are_preserved():
    args = (20, 491, 21, 184, 1500, 101, 112)
    result = calculation.calculate_current(*args)
    assert result == _oracle_current(args)
    assert result == {
        "goods_base_raw": 511,
        "combined_goods_modifier_raw": 205,
        "goods_factor_raw": 1205,
        "goods_raw": 615,
        "priced_raw": 922,
        "subtotal_raw": 1023,
        "value_factor_raw": 1112,
        "value_raw": 1137,
    }


def test_minimum_and_maximum_clamps_and_negative_arithmetic_match_oracle():
    lower = (1000, 0, -1500, 0, 1000, -5, -5000)
    upper = (1000, 0, 0, 0, 1000, 0, 3000)
    negative_final = (0, 0, 0, 0, 1000, -100, 0)

    lower_result = calculation.calculate_current(*lower)
    upper_result = calculation.calculate_current(*upper)
    negative_result = calculation.calculate_current(*negative_final)

    assert lower_result == _oracle_current(lower)
    assert lower_result["goods_factor_raw"] == 0
    assert lower_result["goods_raw"] == 0
    assert lower_result["value_factor_raw"] == 10
    assert upper_result == _oracle_current(upper)
    assert upper_result["value_factor_raw"] == 2000
    assert negative_result["value_raw"] == -100


def test_fixed_point_stages_are_not_collapsed():
    args = (1, 0, -1, 0, 2000, 0, 0)
    result = calculation.calculate_current(*args)
    collapsed = _trunc0_fraction(1 * 999 * 2000, 1_000_000)

    assert result == _oracle_current(args)
    assert result["goods_raw"] == 0
    assert result["priced_raw"] == 0
    assert result["value_raw"] == 0
    assert collapsed == 1


def test_signed_i32_wrapping_and_signed_product_edges_match_oracle():
    cases = [
        (I32_MAX, 1, 0, 0, I32_MAX, I32_MAX, I32_MAX),
        (I32_MIN, -1, I32_MIN, -1, I32_MIN, I32_MIN, I32_MIN),
        (I32_MAX, I32_MAX, I32_MAX, 1, 2000, 1, 1000),
        (-1000, 0, -500, 0, 1500, -1, -990),
    ]
    for args in cases:
        assert calculation.calculate_current(*args) == _oracle_current(args)


def test_fixed_seed_random_signed_inputs_match_fraction_oracle():
    rng = random.Random(210)
    for _ in range(160):
        args = tuple(rng.randint(I32_MIN, I32_MAX) for _ in range(7))
        assert calculation.calculate_current(*args) == _oracle_current(args)


@pytest.mark.parametrize("index", range(7))
@pytest.mark.parametrize("invalid", [True, 1.0, "1", I32_MAX + 1, I32_MIN - 1])
def test_calculation_rejects_non_i32_inputs(index, invalid):
    args = [0] * 7
    args[index] = invalid
    with pytest.raises(ValueError):
        calculation.calculate_current(*args)


def test_empty_and_signed_aggregate_inputs_match_independent_oracle():
    assert calculation.aggregate_node_inputs([]) == {"sum_raw": 0, "node_input_raw": 0}
    values = (I32_MAX, 1, -7, I32_MIN, -12001, 1)
    assert calculation.aggregate_node_inputs(values) == _oracle_aggregate(values)
    assert calculation.aggregate_node_inputs(values)["node_input_raw"] == -1000


def test_node_aggregate_truncates_toward_zero_and_wraps_each_addition():
    for values in ([-11], [11], [I32_MAX, 1], [I32_MIN, -1]):
        assert calculation.aggregate_node_inputs(values) == _oracle_aggregate(values)
    assert calculation.aggregate_node_inputs([-11])["node_input_raw"] == 0
    assert calculation.aggregate_node_inputs([11])["node_input_raw"] == 0


def test_node_aggregate_accepts_maximum_bounded_list():
    values = [1] * 4096
    assert calculation.aggregate_node_inputs(values) == {
        "sum_raw": 4096,
        "node_input_raw": 341,
    }


@pytest.mark.parametrize("values", [None, "123", range(3), [True], [1.5], [I32_MAX + 1], [0] * 4097])
def test_node_aggregate_rejects_invalid_type_domain_or_size(values):
    with pytest.raises(ValueError):
        calculation.aggregate_node_inputs(values)


def test_fixed_seed_random_node_aggregates_match_fraction_oracle():
    rng = random.Random(210_12)
    for _ in range(128):
        values = [rng.randint(I32_MIN, I32_MAX) for _ in range(rng.randint(0, 32))]
        assert calculation.aggregate_node_inputs(values) == _oracle_aggregate(values)
