"""Analytical invariants for the explicit conditional income model."""
from copy import deepcopy
from fractions import Fraction
import pytest
from bridge.information.trade_scenarios import project_scenarios

def baseline(income=12000, own=30000, total=100000, eligible=True):
    def scalar(raw, unit):
        return {'status': 'known', 'raw': raw, 'value': raw, 'unit': unit, 'scale': 1000}
    fields = {'income': dict(scalar(income, 'ducats'), eligible=eligible),
              'collection': {'status': 'known', 'value': eligible},
              'country_power': scalar(own, 'trade_power'), 'total_power': scalar(total, 'trade_power')}
    return {'status': 'known', 'fields': fields, 'source': {'single_parent_capture': True}}

def scenario(id, own=0, total=0):
    return {'id': id, 'country_power_delta_raw': own, 'total_power_delta_raw': total}

def exact(money):
    return Fraction(int(money['exact_raw']['numerator']), int(money['exact_raw']['denominator']))

def test_control_redistribution_and_competitor_growth_have_hand_calculated_incomes():
    result = project_scenarios(baseline(), [scenario('control'), scenario('redistribute', 10000), scenario('dilute', 0, 20000)])
    rows = result['expected_trade']['value']['scenarios']
    assert [exact(r['expected_income']) for r in rows] == [12000, 16000, 10000]
    assert [exact(r['income_delta']) for r in rows] == [0, 4000, -2000]
    assumptions = result['assumptions']['value']
    assert assumptions['calibrated_income_factor_raw']['exact_raw'] == {'numerator': '40000', 'denominator': '1'}
    assert all(v['status'] == 'unknown' and 'value' not in v for v in assumptions['unmeasured_fixed_components'])
    assert assumptions['collection_policy']['value'] is True
    assert result['expected_trade']['game_fact'] is False

def test_proportional_growth_leaves_modeled_income_unchanged():
    result = project_scenarios(baseline(), [scenario('both-double', 30000, 100000)])
    row = result['expected_trade']['value']['scenarios'][0]
    assert exact(row['expected_income']) == 12000 and exact(row['income_delta']) == 0

def test_fraction_is_exact_and_display_rounding_does_not_change_authoritative_value():
    result = project_scenarios(baseline(1000, 3, 10), [scenario('four-power', 1)])
    row = result['expected_trade']['value']['scenarios'][0]
    assert exact(row['expected_income']) == Fraction(4000, 3)
    assert row['expected_income']['decimal'] == '1.333333'
    assert exact(row['income_delta']) == Fraction(1000, 3)

def test_explicit_withdrawal_to_zero_is_known_but_invalid_siblings_stay_unknown():
    result = project_scenarios(baseline(), [scenario('zero-own', -30000), scenario('negative-own', -30001), scenario('zero-total', 0, -100000)])
    rows = result['expected_trade']['value']['scenarios']
    assert rows[0]['status'] == 'known' and exact(rows[0]['expected_income']) == 0
    assert [r['status'] for r in rows[1:]] == ['unknown', 'unknown']
    assert all('expected_income' not in r for r in rows[1:])

@pytest.mark.parametrize('sample', [baseline(0, 0, 100000), baseline(0, 30000, 100000, False), baseline(-1)])
def test_uncalibrated_or_ineligible_baselines_do_not_turn_into_zero_predictions(sample):
    result = project_scenarios(sample, [scenario('control')])
    assert result['expected_trade']['status'] == 'unknown'
    assert 'value' not in result['expected_trade']
    assert result['assumptions']['value']['calibrated_income_factor_raw']['status'] == 'unknown'

def test_verified_zero_income_is_distinct_from_missing_and_inputs_are_not_mutated():
    sample = baseline(0)
    original = deepcopy(sample)
    result = project_scenarios(sample, [scenario('control')])
    assert exact(result['expected_trade']['value']['scenarios'][0]['expected_income']) == 0
    assert sample == original
    missing = project_scenarios({'status': 'unknown', 'reason': 'NO_CAPTURE'}, [scenario('control')])
    assert missing['expected_trade']['reason'] == 'NO_CAPTURE' and 'value' not in missing['expected_trade']
