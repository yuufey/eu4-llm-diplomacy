from bridge.information import bankruptcy_forecast_math as math_model
import pytest


def ledger(**values):
    words = {offset: 0 for offset in math_model.REQUIRED_LEDGER_OFFSETS}
    words.update({int(offset, 16): value for offset, value in values.items()})
    return words


def evaluate(words, loans=(), *, helper=0, treasury=0, factor=0, factor_raw=0):
    return math_model.evaluate(
        ledger_words=words,
        loans=loans,
        helper_return_i32=helper,
        treasury_raw_i32=treasury,
        factor_u8=factor,
        factor_raw_i32=factor_raw,
    )


def loan(principal, rate, marker27=0, flag35=0):
    return {
        "principal": principal,
        "stored_rate": rate,
        "marker27": marker27,
        "flag35": flag35,
    }


def test_monthly_balance_selects_rate_per_two_flag_bytes_and_truncates_steps():
    result = evaluate(
        ledger(**{"770": 25, "7bc": 5, "78c": 40, "7cc": 10}),
        [loan(1200, 0, marker27=0, flag35=0),
         loan(2400, 2000, marker27=0, flag35=1)],
        helper=1000,
    )

    balance = result["diagnostics"]["monthly_balance"]
    assert [row["rate_source"] for row in balance["loan_payments"]] == [
        "helper_return_i32", "stored_rate"]
    assert [row["monthly_payment_i32"] for row in balance["loan_payments"]] == [
        1000, 4000]
    assert balance["loan_payment_sum_i32"] == 5000
    assert balance["monthly_balance_i32"] == -5010


def test_monthly_balance_accumulators_wrap_as_signed_32_bit_words():
    result = evaluate(ledger(**{"770": 0x7FFFFFFF, "774": 1}))

    balance = result["diagnostics"]["monthly_balance"]
    assert balance["positive_total_i32"] == -0x80000000
    assert balance["monthly_balance_i32"] == -0x80000000


def test_unknown_ledger_offset_is_rejected():
    words = ledger()
    words[0x900] = 1

    with pytest.raises(ValueError, match="ledger_words_unrecognized_offsets"):
        evaluate(words)


def test_capacity_uses_only_the_ten_eligible_indices_and_counts_marker27_zero():
    words = ledger(**{
        "770": 40_000,       # eligible index 0
        "78c": 50,           # excluded index 7; also the balance adjustment
        "794": 300_000,       # excluded index 9
        "798": 400_000,       # excluded index 10
        "79c": 500_000,       # excluded index 11
        "7a0": 600_000,       # excluded index 12
        "7a4": 700_000,       # excluded index 13
        "7a8": 800_000,       # excluded index 14
        "7ac": 43_000,        # eligible index 15
        "7b4": 900_000,       # excluded index 17, but a balance inflow
        "7bc": 1_000_000,
    })
    result = evaluate(
        words,
        [loan(0, 0, marker27=0, flag35=1)],
        helper=100_000,
        factor=1,
        factor_raw=1000,
    )

    forecast = result["diagnostics"]["forecast"]
    assert forecast["eligible_income_indices"] == [0, 1, 2, 3, 4, 5, 6, 8, 15, 16]
    assert forecast["eligible_income_sum_i32"] == 83_000
    assert forecast["loan_capacity"] == 1001
    assert forecast["loan_capacity_diagnostics"]["denominator_i32"] == 83
    assert forecast["active_loan_count_i32"] == 1
    assert forecast["remaining_capacity_i32"] == 1000
    assert result["months_raw_i32"] == 58
    assert result["warning"] is False
    assert result["imminent"] is False


def test_f32_threshold_includes_minus_50_and_normal_result_1000_is_not_sentinel():
    at_boundary = evaluate(ledger(**{"7bc": 50}))
    below_boundary = evaluate(ledger(**{"7bc": 51}))
    warning_range = evaluate(ledger(**{"7bc": 251}))
    calculated_1000 = evaluate(
        ledger(**{"770": 999, "7bc": 1999}), helper=1200)

    assert at_boundary["months_raw_i32"] == 1000
    assert at_boundary["no_material_deficit"] is True
    assert at_boundary["diagnostics"]["forecast"]["branch"] == "threshold_sentinel"

    assert below_boundary["months_raw_i32"] == 58
    assert below_boundary["no_material_deficit"] is False
    assert below_boundary["diagnostics"]["forecast"]["branch"] == "computed_months"

    assert warning_range["months_raw_i32"] == 11
    assert warning_range["warning"] is True
    assert warning_range["imminent"] is False

    # A calculated value can also be 1000; the branch flag keeps it distinct
    # from the no-material-deficit sentinel.
    assert calculated_1000["months_raw_i32"] == 1000
    assert calculated_1000["no_material_deficit"] is False
    assert calculated_1000["warning"] is False


def test_masked_cvtt_invalid_is_reported_before_the_native_zero_clamp():
    words = ledger(**{"770": 110_000_000, "7bc": 110_000_051})
    result = evaluate(
        words,
        helper=1200,
        factor=1,
        factor_raw=1_100_000,
    )

    forecast = result["diagnostics"]["forecast"]
    assert forecast["loan_capacity"] == 100_001
    assert forecast["factor_times_remaining_capacity_i32"] == 110_001_100
    assert forecast["cvttss2si_result_i32"] == -0x80000000
    assert result["conversion_invalid"] is True
    assert forecast["months_clamped_i32"] == 0
    assert result["months_raw_i32"] == 0
    assert result["warning"] is True
    assert result["imminent"] is True
