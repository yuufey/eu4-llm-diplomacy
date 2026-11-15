import pytest

from bridge.information import loan_interest_quote_math as quote_math


REFERENCE_RAW = 43_800_000
TICKS_PER_DAY = 24
DAYS_PER_YEAR = 365


def raw_day(day_index):
    """Encode a day offset from the native reference as EU4 hour ticks."""
    return REFERENCE_RAW + TICKS_PER_DAY * day_index


def loan(principal, rate, expiry):
    return {
        "principal_i32": principal,
        "stored_rate_i32": rate,
        "expiry_raw_i32": expiry,
    }


def test_month_buckets_cover_same_month_cross_month_and_cross_year():
    assert quote_math.months_between(
        expiry_raw_i32=raw_day(29), as_of_raw_i32=raw_day(4)
    ) == 0
    assert quote_math.months_between(
        expiry_raw_i32=raw_day(31), as_of_raw_i32=raw_day(30)
    ) == 1
    assert quote_math.months_between(
        expiry_raw_i32=raw_day(DAYS_PER_YEAR),
        as_of_raw_i32=raw_day(DAYS_PER_YEAR - 1),
    ) == 1


def test_fixed_calendar_keeps_february_at_28_days_in_year_four():
    february_28_year_four = raw_day(4 * DAYS_PER_YEAR + 58)
    following_day = raw_day(4 * DAYS_PER_YEAR + 59)

    assert quote_math.months_between(
        expiry_raw_i32=following_day,
        as_of_raw_i32=february_28_year_four,
    ) == 1


def test_raw_zero_and_minus_one_straddle_the_reference_year_boundary():
    assert quote_math.months_between(expiry_raw_i32=0, as_of_raw_i32=0) == 0
    assert quote_math.months_between(expiry_raw_i32=0, as_of_raw_i32=-1) == 1
    assert quote_math.months_between(expiry_raw_i32=-1, as_of_raw_i32=0) == -1


def test_month_date_inputs_accept_signed_i32_edges_but_reject_bool_and_overflow():
    assert quote_math.months_between(
        expiry_raw_i32=-(1 << 31), as_of_raw_i32=-(1 << 31)
    ) == 0
    assert quote_math.months_between(
        expiry_raw_i32=(1 << 31) - 1, as_of_raw_i32=(1 << 31) - 1
    ) == 0

    with pytest.raises(ValueError, match="expiry_raw_i32_must_be_signed_i32"):
        quote_math.months_between(expiry_raw_i32=True, as_of_raw_i32=0)
    with pytest.raises(ValueError, match="as_of_raw_i32_must_be_signed_i32"):
        quote_math.months_between(expiry_raw_i32=0, as_of_raw_i32=False)
    with pytest.raises(ValueError, match="expiry_raw_i32_must_be_signed_i32"):
        quote_math.months_between(expiry_raw_i32=1 << 31, as_of_raw_i32=0)


def test_negative_month_difference_is_not_clamped_before_interest_evaluation():
    result = quote_math.quote_loan(
        principal_i32=1_500_000,
        stored_rate_i32=1000,
        expiry_raw_i32=raw_day(-1),
        as_of_raw_i32=REFERENCE_RAW,
    )

    assert result["months_i32"] == -1
    assert result["interest"]["trace"]["negative_floor_branch"] is True


def test_principal_times_1000_wraps_to_signed_i32_before_quoting():
    result = quote_math.quote_loan(
        principal_i32=(1 << 31) - 1,
        stored_rate_i32=0,
        expiry_raw_i32=REFERENCE_RAW,
        as_of_raw_i32=REFERENCE_RAW,
    )

    assert result["principal_scaled_i32"] == -1000
    assert result["principal_scaling_wrapped"] is True
    assert result["quote_i32"] == -1000
    assert result["complete"] is False
    assert result["publication_admitted"] is False


def test_two_zero_interest_quotes_sum_with_signed_i32_wrap():
    loans = [
        loan(1_500_000, 0, REFERENCE_RAW),
        loan(1_500_000, 0, REFERENCE_RAW),
    ]

    result = quote_math.quote_total(loans=loans, as_of_raw_i32=REFERENCE_RAW)

    assert [row["quote_i32"] for row in result["loans"]] == [
        1_500_000_000, 1_500_000_000]
    assert result["quote_i32"] == -1_294_967_296
    assert result["sum_wrapped"] is True
    assert result["interest_scaled_i32"] == 0
    assert result["complete"] is False
    assert result["publication_admitted"] is False
    assert result["source_list_completeness_verified"] is False
    assert result["input_scope"] == "supplied_loans_only"


def test_empty_and_64_supplied_records_remain_incomplete_private_quotes():
    empty = quote_math.quote_total(loans=[], as_of_raw_i32=REFERENCE_RAW)
    sixty_four = quote_math.quote_total(
        loans=[loan(0, 0, REFERENCE_RAW) for _ in range(64)],
        as_of_raw_i32=REFERENCE_RAW,
    )

    assert empty["loan_count"] == 0
    assert empty["quote_i32"] == 0
    assert empty["complete"] is False
    assert empty["publication_admitted"] is False
    assert sixty_four["loan_count"] == 64
    assert sixty_four["quote_i32"] == 0
    assert sixty_four["source_list_completeness_verified"] is False


def test_quote_total_rejects_more_than_64_records():
    with pytest.raises(ValueError, match="at_most_64_records"):
        quote_math.quote_total(
            loans=[loan(0, 0, REFERENCE_RAW) for _ in range(65)],
            as_of_raw_i32=REFERENCE_RAW,
        )


def test_quote_total_requires_exact_loan_keys():
    with pytest.raises(ValueError, match="loan_fields_must_match"):
        quote_math.quote_total(
            loans=[{
                "principal_i32": 1,
                "expiry_raw_i32": REFERENCE_RAW,
            }],
            as_of_raw_i32=REFERENCE_RAW,
        )

    with pytest.raises(ValueError, match="loan_fields_must_match"):
        quote_math.quote_total(
            loans=[{
                **loan(1, 0, REFERENCE_RAW),
                "unverified_interest": 7,
            }],
            as_of_raw_i32=REFERENCE_RAW,
        )
