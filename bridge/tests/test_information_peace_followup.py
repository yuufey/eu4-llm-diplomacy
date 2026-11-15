from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.model import InformationError
from bridge.information.peace_followup import PeaceFollowupSource, project_obligations
from bridge.information.tools import InformationTools
from bridge.information.sources import RecordedSource
from bridge.tests.test_information_foreign_technology import Base
from bridge.tests.test_information_foreign_technology_capture import make_valid_capture


WAR = 'war_0123456789abcdef_00000001'
RULES = {'values': {'WAR_REPARATIONS_FACTOR': 0.1, 'WAR_REPARATIONS_YEARS': 10,
    'PO_TRADE_POWER_AMOUNT': 0.5, 'ANNUL_TREATIES_YEARS': 10,
    'TRUCE_YEARS': 5, 'SCALED_TRUCE_YEARS': 10}, 'source': {}, 'reasons': {}}


def query(terms=None, direction='demand'):
    if terms is None:
        payer, claimant = ('ENG', 'FRA') if direction == 'demand' else ('FRA', 'ENG')
        terms = [{'action_id': 'war_reparations', 'payer': payer, 'claimant': claimant}]
    return {'topic': 'P06', 'object': {'type': 'war', 'actor': 'FRA', 'recipient': 'ENG'},
        'fields': ['obligations'], 'parameters': {
            'peace_context': {'war_id': WAR, 'direction': direction, 'terms': terms}}}


class Rules:
    def read(self):
        return deepcopy(RULES)


def make_source(tmp_path, *, applied=True):
    _, context, creation, _ = make_valid_capture()
    base = Base(tmp_path, context, creation)
    calls = []

    def inspect(action, actor, recipient, phase, parameters):
        calls.append((action, actor, recipient, phase, deepcopy(parameters)))
        return {'parameters': {'actual': deepcopy(parameters) if applied else None},
                'peace_consequences': {'requested_terms_applied': applied},
                'costs': {'war_score': {'status': 'known', 'value': 10,
                    'unit': 'war_score_point', 'scale': 1, 'scale_verified': True}},
                'war_context': {'war_score': {'max_score': {'value': 100,
                    'unit': 'war_score_point', 'scale': 1, 'scale_verified': True}}}}

    return PeaceFollowupSource(base, rules=Rules(), inspector=inspect), base, calls


@pytest.mark.parametrize('direction', ['demand', 'offer'])
def test_normal_query_returns_selected_reparation_parties_percent_and_term(tmp_path, direction):
    adapter, base, calls = make_source(tmp_path)
    service = InformationService(CompositeSource(base, [adapter]), tmp_path / 'information.sqlite3')
    try:
        api = InformationTools(service)
        result = api.call('information_query', {'request_id': 'reparations', 'queries': [query(direction=direction)]})
        payer, recipient = ('ENG', 'FRA') if direction == 'demand' else ('FRA', 'ENG')
        assert result['items'] == [{'actor': 'FRA', 'recipient': 'ENG', 'war_id': WAR,
            'obligations': [{'type': 'war_reparations', 'payer': payer,
                'recipient': recipient, 'income_percent': 10.0, 'duration_years': 10}]}]
        assert service.get_result(result['result_id'])['complete'] is True
        assert len(calls) == 1 and calls[0][:4] == ('war_reparations', 'FRA', 'ENG', 'initiate')
        assert api.call('information_get_result', {'result_id': result['result_id']}) == result
    finally:
        service.close()


def test_white_peace_has_no_new_ongoing_obligations(tmp_path):
    source, _, calls = make_source(tmp_path)
    result = source.read(query([]))
    assert result['fields']['obligations']['value'] == [] and result['complete'] is True
    assert calls[0][0] == 'white_peace'


def test_forward_game_clock_keeps_selected_obligation_values_available(tmp_path):
    adapter, base, calls = make_source(tmp_path)
    original = adapter.inspector

    def advancing_inspect(*args):
        result = original(*args)
        base.current['game_date'] += 24
        return result

    adapter.inspector = advancing_inspect
    service = InformationService(CompositeSource(base, [adapter]), tmp_path / 'information.sqlite3')
    try:
        result = service.query('advancing', [query()])
        assert result['complete'] is True
        assert result['items'][0]['fields']['obligations']['value'][0]['income_percent'] == 10
        assert result['items'][0]['observation_window']['end_game_date'] == base.current['game_date']
        assert len(calls) == 1
    finally:
        service.close()


def test_unapplied_selection_cannot_be_presented_as_empty_obligations(tmp_path):
    source, _, calls = make_source(tmp_path, applied=False)
    result = source.read(query())
    assert result['complete'] is False
    assert result['fields']['obligations'] == {'status': 'unknown', 'reason': 'PEACE_SELECTED_TERMS_NOT_APPLIED'}
    assert len(calls) == 1


def test_annulment_and_trade_power_project_their_distinct_duration_rules():
    result = project_obligations({'claimant': 'FRA', 'terms': [
        {'action_id': 'annul_treaties', 'country': 'ENG', 'treaty_partners': ['CAS']},
        {'action_id': 'transfer_trade_power', 'source': 'ENG', 'beneficiary': 'FRA'}]}, RULES)
    assert result['complete'] is True
    assert result['value'][0] == {'type': 'annul_treaties', 'country': 'ENG',
                                 'partners': ['CAS'], 'duration_years': 10}
    assert result['value'][1]['trade_power_percent'] == 50
    assert result['value'][1]['duration_years'] is None
    assert result['value'][1]['end_condition'] == 'truce_ends'


def test_missing_rule_preserves_selected_obligation_and_other_known_component():
    rules = deepcopy(RULES)
    rules['values']['WAR_REPARATIONS_YEARS'] = None
    rules['reasons']['WAR_REPARATIONS_YEARS'] = {'code': 'DEFINE_EXPRESSION_UNSUPPORTED',
                                                'message': 'nonliteral override'}
    result = project_obligations(dict(query()['parameters']['peace_context'], claimant='FRA'), rules)
    assert result['value'][0]['income_percent'] == 10
    assert result['value'][0]['duration_years'] is None and result['complete'] is False
    assert result['gaps'] == ['DEFINE_EXPRESSION_UNSUPPORTED']


def test_new_subject_obligations_remain_partial_until_type_rules_are_projected():
    result = project_obligations({'claimant': 'FRA', 'terms': [
        {'action_id': 'force_vassalization', 'country': 'ENG', 'beneficiary': 'FRA'}]}, RULES)
    assert result['value'][0] == {'type': 'subject_obligations', 'country': 'ENG',
        'overlord': 'FRA', 'subject_type': 'vassal', 'details': None}
    assert result['complete'] is False


@pytest.mark.parametrize('invalid', ['missing_terms', 'response', 'other_actor', 'war_mismatch', 'wrong_payer'])
def test_invalid_selection_fails_before_native_inspection(tmp_path, invalid):
    source, _, calls = make_source(tmp_path)
    selected = query()
    if invalid == 'missing_terms':
        selected['parameters'] = {}
    elif invalid == 'response':
        selected['parameters']['phase'] = 'accept'
    elif invalid == 'other_actor':
        selected['object']['actor'] = 'CAS'
    elif invalid == 'war_mismatch':
        selected['object']['war_id'] = WAR[:-1] + '2'
    else:
        selected['parameters']['peace_context']['terms'][0]['payer'] = 'FRA'
    with pytest.raises(InformationError):
        source.read(selected)
    assert calls == []


def test_combined_truce_and_obligations_share_one_selected_offer_preview(tmp_path):
    adapter, base, calls = make_source(tmp_path)
    base.current['game_date'] = 56682672
    service = InformationService(CompositeSource(base, [adapter]), tmp_path / 'information.sqlite3')
    try:
        selected = query()
        selected['fields'] = ['obligations', 'new_truce']
        result = InformationTools(service).call('information_query', {
            'request_id': 'combined-truce', 'queries': [selected]})
        assert result['items'][0]['new_truce'] == {
            'if_signed_on': '1470.8.17', 'estimated_until': '1476.9.1'}
        assert result['items'][0]['obligations'][0]['income_percent'] == 10
        assert service.get_result(result['result_id'])['complete'] is True
        assert len(calls) == 1
    finally:
        service.close()


@pytest.mark.parametrize('cost,expected,months', [
    (0, '1475.9.1', 61), (10, '1476.9.1', 73), (23, '1478.1.1', 89),
    (30, '1478.9.1', 97), (100, '1485.9.1', 181),
    (120, '1485.9.1', 181), (-1, '1475.9.1', 61)])
def test_truce_reuses_native_clamp_and_calendar_rules(cost, expected, months):
    from bridge.information.peace_truce import project_new_truce
    metric = {'value': cost, 'unit': 'war_score_point', 'scale': 1, 'scale_verified': True}
    inspection = {'costs': {'war_score': metric}, 'war_context': {'war_score': {
        'max_score': dict(metric, value=100)}}}
    result = project_new_truce(inspection, RULES, {'game_date': 56682672})
    assert result['value']['estimated_until'] == expected
    assert result['calculation']['duration_months'] == months


def test_unknown_offer_cost_stays_unknown_while_obligations_remain_known(tmp_path):
    adapter, base, calls = make_source(tmp_path)
    original = adapter.inspector

    def unknown_cost(*args):
        result = original(*args)
        result['costs']['war_score']['scale_verified'] = False
        return result

    adapter.inspector = unknown_cost
    result = adapter.read(dict(query(), fields=['new_truce', 'obligations']))
    assert result['fields']['new_truce']['status'] == 'unknown'
    assert result['fields']['obligations']['status'] == 'known'
    assert len(calls) == 1


def test_normandy_signed_peace_prediction_matches_actual_direct_truce(tmp_path):
    path = Path(__file__).parent / 'fixtures' / 'information_peace_FRA_ENG_normandy_truce_live_1374.json'
    fixture = json.loads(path.read_text(encoding='utf-8'))
    adapter, base, calls = make_source(tmp_path)
    base.current = deepcopy(fixture['context'])
    adapter.rules = SimpleNamespace(read=lambda: deepcopy(fixture['rules']))
    execution = fixture['execution']
    assert execution['status'] == 'accepted'
    assert execution['date_raw'] == fixture['context']['game_date']
    selected = fixture['inspection']['parameters']['actual']
    assert selected == fixture['inspection']['parameters']['requested']
    assert selected['peace_context']['war_id'] == execution['war_id']
    assert selected['peace_context']['terms'][0]['province_ids'] == execution['province_ids']

    def inspect(action, actor, recipient, phase, parameters):
        assert (action, actor, recipient, phase) == ('cede_province', 'FRA', 'ENG', 'initiate')
        assert parameters == selected
        calls.append((action, actor, recipient, phase, deepcopy(parameters)))
        return deepcopy(fixture['inspection'])

    adapter.inspector = inspect
    chosen = {'topic': 'P06', 'object': {'type': 'war', 'actor': 'FRA', 'recipient': 'ENG'},
              'fields': ['new_truce', 'restart_conditions'], 'parameters': deepcopy(selected)}
    database = tmp_path / 'information.sqlite3'
    service = InformationService(CompositeSource(base, [adapter]), database)
    try:
        api = InformationTools(service)
        result = api.call('information_query', {'request_id': 'normandy-actual-truce', 'queries': [chosen]})
        row = result['items'][0]
        actual = fixture['actual_truce']
        assert actual['status'] == 'known' and actual['direct_record_flag'] is True
        assert row['new_truce'] == {'if_signed_on': '1470.10.26', 'estimated_until': actual['date']}
        assert row['restart_conditions']['without_truce_break_after'] == actual['date'] == '1479.2.1'
        full = api.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})
        calculation = full['items'][0]['fields']['new_truce']['calculation']
        assert calculation['aggregate_war_score'] == 32
        assert calculation['duration_months'] == 100
        assert calculation['raw_expiry'] == actual['raw']
        assert full['complete'] is True and len(calls) == 1
    finally:
        service.close()

    reopened = InformationService(RecordedSource({}), database)
    try:
        assert InformationTools(reopened).call('information_get_result', {
            'result_id': result['result_id']}) == result
        assert reopened.get_result(result['result_id']) == full
        assert len(calls) == 1
    finally:
        reopened.close()
