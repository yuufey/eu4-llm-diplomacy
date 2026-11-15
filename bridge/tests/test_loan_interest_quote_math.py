import pytest

from bridge.information import loan_interest_quote_math as model


def evaluate(principal=100_000, rate=4_000, months=12):
    return model.evaluate(principal_scaled_i32=principal, stored_rate_i32=rate, months_i32=months)


def test_one_year_example_preserves_native_fixed_point_loss():
    result = evaluate()
    # Hand calculation: month factor120 -> fixed3932; rate factor333 ->
    # fixed10911; 3932*3276800>>15=393200; 10911*393200>>15=130926.
    # The final binary32 steps and truncation produce raw3996.
    assert result["amount_i32"] == 3996
    assert result["value"] == 3.996
    trace = result["trace"]
    assert trace["first_shifted_i64"] == 393_200
    assert trace["second_shifted_i64"] == 130_926
    assert trace["negative_floor_branch"] is False
    assert result["conversion_invalid"] is False


@pytest.mark.parametrize("principal,rate,months", [(0, 4000, 12), (100000, 0, 12), (100000, 4000, 0)])
def test_zero_input_produces_zero_interest(principal, rate, months):
    result = evaluate(principal, rate, months)
    assert result["amount_i32"] == 0
    assert result["trace"]["unscaled_f32_bits"] == "0x00000000"
    assert result["trace"]["biased_f32_bits"] == "0x3F000000"


def test_negative_months_reach_floor_branch_before_positive_clamp():
    result = evaluate(months=-12)
    assert result["trace"]["month_factor_i32"] == -120
    assert result["trace"]["negative_floor_branch"] is True
    assert result["trace"]["conversion_i32"] < 0
    assert result["amount_i32"] == 0


def test_two_negative_factors_can_produce_positive_interest():
    result = evaluate(principal=-100000, rate=-4000)
    assert result["amount_i32"] == 3996
    assert result["trace"]["negative_floor_branch"] is False


@pytest.mark.parametrize("months,fast", [(-1611, False), (-1610, True), (2147, True), (2148, False)])
def test_month_selector_covers_both_signed_boundaries(months, fast):
    assert evaluate(months=months)["trace"]["month_fast_path"] is fast


@pytest.mark.parametrize("rate,fast", [(-1610612, False), (-1610611, True), (2147482, True), (2147483, False)])
def test_rate_selector_covers_both_signed_boundaries(rate, fast):
    assert evaluate(rate=rate)["trace"]["rate_fast_path"] is fast


def test_months_wrap_as_dword_before_slow_path_widens():
    result = evaluate(months=0x7FFFFFFF)
    trace = result["trace"]
    assert trace["month_scaled_i32"] == -1000
    assert trace["month_fast_path"] is True
    assert trace["month_factor_i32"] == -10


def test_low64_product_wrap_is_retained():
    trace = evaluate(principal=0x7FFFFFFF, months=1_000_000)["trace"]
    assert trace["first_product_wrapped"] is True
    assert -(1 << 63) <= trace["first_product_i64"] < 1 << 63


def test_invalid_cvtt_conversion_remains_distinct_from_normal_zero():
    result = evaluate(principal=2_000_000_000, rate=1_200_000, months=120)
    assert result["conversion_invalid"] is True
    assert result["trace"]["conversion_i32"] == -(1 << 31)
    assert result["amount_i32"] == 0
    assert evaluate(principal=0)["conversion_invalid"] is False


def test_signed32_inputs_are_strict_and_reject_bool():
    good = dict(principal_scaled_i32=0, stored_rate_i32=0, months_i32=0)
    for key in good:
        for bad in (True, False, None, 0.0, "0", -(1 << 31) - 1, 1 << 31):
            with pytest.raises(ValueError, match=f"{key}_must_be_signed_i32"):
                model.evaluate(**{**good, key: bad})


def test_math_result_retains_explicit_environment_and_scope_limits():
    result = evaluate()
    assert result["complete"] is False
    assert result["publication_admitted"] is False
    assert result["native_execution_observed"] is False
    assert result["native_fp_environment_verified"] is False
    assert result["fp_assumptions"]["rounding"] == "binary32_round_to_nearest_ties_to_even"
    assert "masked" in result["fp_assumptions"]["exceptions"]
