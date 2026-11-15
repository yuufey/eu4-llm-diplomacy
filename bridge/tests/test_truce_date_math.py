"""Calendar boundaries for the private direct-truce date projection."""
import pytest

from bridge.information.truce_date_math import (
    DATE_REFERENCE_RAW, MONTH_DAYS, adjustment_months, decode_date, direct_truce_expiry,
)


def encoded(year, month, day, hour=0):
    return (year + 5000) * 365 * 24 + (sum(MONTH_DAYS[:month - 1]) + day - 1) * 24 + hour


@pytest.mark.parametrize('parts', [(1444, 11, 11, 0), (1455, 8, 20, 0), (1456, 4, 12, 0),
                                  (1600, 2, 28, 23), (1821, 12, 31, 1), (0, 1, 1, 0)])
def test_hour_clock_and_fixed_calendar(parts):
    assert decode_date(encoded(*parts)) == parts


@pytest.mark.parametrize('adjustment,months', [(0, 61), (23, 89), (50, 121), (99, 180), (100, 181), (-128, -92)])
def test_integer_argument_uses_ceiling_and_signed_byte(adjustment, months):
    assert adjustment_months(adjustment, 10, 5) == months


def test_current_saved_input_prediction_keeps_raw_clock_unit():
    # This case is a model prediction, separately checked by the owned CPU fixture.
    assert direct_truce_expiry(56551344, 23, 10, 5) == {
        'raw': 56615880, 'date': '1463.1.1', 'hour': 0, 'unit': 'eu4_hour_tick', 'scale': 1}


@pytest.mark.parametrize('day', [1, 28, 30, 31])
def test_january_month_end_selects_february_first(day):
    # A=0/B=0 gives one month, followed by native day-index zero.
    result = direct_truce_expiry(encoded(1456, 1, day, 23), 0, 0, 0)
    assert result['raw'] == encoded(1456, 2, 1, 23)
    assert result['date'] == '1456.2.1' and result['hour'] == 23


def test_december_wraps_year_without_gregorian_leap_days():
    result = direct_truce_expiry(encoded(1600, 12, 31, 1), 0, 0, 0)
    assert result['raw'] == encoded(1601, 1, 1, 1)


def test_negative_month_argument_crosses_year():
    # A=0/B=-1 => -11 months after the native +1000/ceil adjustment.
    result = direct_truce_expiry(encoded(1456, 1, 31, 7), 0, 0, -1)
    assert result['raw'] == encoded(1455, 2, 1, 7)


@pytest.mark.parametrize('raw', [True, None, 1.0, '56551344', DATE_REFERENCE_RAW - 1, (1 << 31)])
def test_invalid_or_pre_reference_clock_rejected(raw):
    with pytest.raises(ValueError):
        direct_truce_expiry(raw, 23, 10, 5)


@pytest.mark.parametrize('arguments', [(True, 10, 5), (128, 10, 5), (-129, 10, 5),
                                      (23, True, 5), (23, 10, False), (23, 1 << 31, 5)])
def test_invalid_adjustment_or_configuration_rejected(arguments):
    with pytest.raises(ValueError):
        adjustment_months(*arguments)


def test_result_before_reference_is_explicitly_unsupported():
    with pytest.raises(ValueError, match='PRE_REFERENCE'):
        direct_truce_expiry(DATE_REFERENCE_RAW, 0, 0, -1)


def test_result_overflow_is_explicitly_unsupported():
    with pytest.raises(ValueError, match='OVERFLOW'):
        direct_truce_expiry((1 << 31) - 1, 0, 0, 100)
