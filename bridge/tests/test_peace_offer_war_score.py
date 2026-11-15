import pytest

from bridge.diplomacy import DiplomacyTools
from bridge.peace_costs import project_offer_war_score


@pytest.mark.parametrize('value', [-10, 0, 10, 101])
def test_aggregate_getter_values_are_integer_war_score_points(value):
    result = project_offer_war_score({'called': True, 'aggregate_score_available': True,
                                     'aggregate_score_raw': value})
    assert result['value'] == value and result['unit'] == 'war_score_point'
    assert result['scale'] == 1 and result['scale_verified'] is True


@pytest.mark.parametrize('value', [True, None, 10.0, 1 << 31, -(1 << 31) - 1])
def test_invalid_or_missing_integer_is_not_promoted(value):
    assert project_offer_war_score({'called': True, 'aggregate_score_available': True,
                                    'aggregate_score_raw': value}) is None


def test_unavailable_observation_cannot_turn_default_zero_into_cost():
    assert project_offer_war_score({'called': True, 'aggregate_score_available': False,
                                    'aggregate_score_raw': 0}) is None


def test_normal_bridge_projection_exposes_p02_cost_without_changing_acceptance():
    inspection = {'costs': {}, 'acceptance': {}}
    DiplomacyTools._apply_peace_query_evaluation(inspection, {'native_evaluation': {
        'called': True, 'aggregate_score_available': True, 'aggregate_score_raw': 10,
        'score_available': True, 'score_raw': 91}})
    assert inspection['costs']['war_score']['value'] == 10
    assert inspection['costs']['native_evaluation']['unit'] == 'war_score_point'
    assert inspection['acceptance']['native_total'] == 91
