"""Current native favor quotes bound to one actual received proposal."""
from contextlib import closing
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from bridge.diplomacy import ObserverSession
from bridge.information import InformationService
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools
from bridge.information.presentation import present_concise
from bridge.tests.test_information_inbound_current import FakeTools, PUBLIC_ID
from bridge.tests.test_favor_trade_inbound import inspection_event as gold_event
from bridge.tests.test_favor_resources_inbound import inspection_event as trust_event
from bridge.tests.test_favor_resources import men_query


def native_event(kind):
    if kind == 'gold':
        return gold_event()
    event = trust_event()
    if kind == 'men':
        event.update(action_id='trade_favors_for_men', favor_trade=men_query())
    return event


class FavorTools(FakeTools):
    def _envelope(self, event, public_id):
        action = event['action_id']
        native = ObserverSession._public_native_inbound_inspection(event, event['date_raw'], action)
        return {
            'action_id': action, 'actor': event['actor'], 'recipient': 'FRA', 'phase': 'accept',
            'decision_country': 'FRA', 'decision_country_verified': native['decision_country_verified'],
            'parameters': {'requested': {'proposal_id': public_id},
                           'actual': {'proposal_id': public_id, 'decision_country': 'FRA'}},
            'session': self.session.health(), 'native_inbound_inspection': native,
            'observed_inbound_proposal': {'proposal_id': public_id, 'action_id': action,
                'actor': event['actor'], 'recipient': 'FRA', 'currently_pending': native['pending_active']},
        }


def source_and_query(kind, event=None):
    event = native_event(kind) if event is None else event
    tools = FavorTools(event)
    proposal = {'proposal_id': PUBLIC_ID, 'action_id': event['action_id'], 'actor': event['actor'],
                'recipient': 'FRA', 'observer_status': 'observed_pending'}
    tools.session.read_native_alliance_inbound_offers = lambda: [deepcopy(proposal)]
    query = {'topic': 'A04', 'object': {'type': 'session'}, 'fields': ['parameters'],
             'parameters': {'proposal_id': PUBLIC_ID, 'fresh_pending': True}}
    return DiplomacySource(tools), tools, query


@pytest.mark.parametrize('kind', ['gold', 'trust', 'men'])
@pytest.mark.parametrize('mixed', [False, True])
def test_quote_supplies_resource_direction_and_favor_price_in_one_inspection(kind, mixed):
    event = native_event(kind)
    source, tools, query = source_and_query(kind, event)
    if mixed:
        query['fields'] += ['proposal_status', 'currently_pending']
    result = source.read(query, source.context())
    field = result['fields']['parameters']
    assert field['status'] == 'known' and field['scope'] == 'current_native_rule_quote'
    assert field['proposal_id'] == PUBLIC_ID and field['observation_game_date'] == event['date_raw']
    quote = field['value']['favor_trade']
    assert quote['kind'] == kind
    assert quote['amount']['raw'] == event['favor_trade']['amount_raw']
    assert quote['amount']['scale'] == (1000 if kind == 'gold' else 1)
    if kind == 'trust':
        assert quote['amount']['trustor'] == 'FRA' and quote['amount']['trusted'] == event['actor']
    else:
        assert quote['amount']['payer'] == 'FRA' and quote['amount']['receiver'] == event['actor']
    favors = quote['favors']
    assert favors['held_by'] == event['actor'] and favors['owed_by'] == 'FRA'
    assert favors['cost_raw'] == event['favor_trade']['favor_cost_raw']
    assert favors['scale'] == 1000 and favors['cost'] == favors['cost_raw'] / 1000
    assert len(tools.inspect_calls) == 1
    assert tools.inspect_calls[0][3] == 'accept'
    assert 'proposal_parameters' not in result['fields'].get('proposal_status', {})


@pytest.mark.parametrize('damage', [
    'kind', 'partial', 'source', 'amount_unreadable', 'favors_unreadable', 'payer', 'holder',
    'unit', 'amount_scale', 'favor_scale', 'bool_scale', 'negative', 'overflow', 'bool_raw',
    'bool_value', 'value_mismatch', 'cost_negative', 'cost_bool', 'cost_value', 'missing_amount',
])
def test_malformed_public_quote_cannot_be_published(damage):
    source, tools, query = source_and_query('gold')
    quote = tools.envelope['native_inbound_inspection']['favor_trade']
    amount, favors = quote['amount'], quote['favors']
    if damage == 'kind':
        quote['kind'] = 'men'
    elif damage == 'partial':
        quote['complete'] = False
    elif damage == 'source':
        quote['source'] = 'unknown'
    elif damage == 'amount_unreadable':
        amount['available'] = False
    elif damage == 'favors_unreadable':
        favors['available'] = False
    elif damage == 'payer':
        amount['payer'] = 'POR'
    elif damage == 'holder':
        favors['held_by'] = 'POR'
    elif damage == 'unit':
        amount['unit'] = 'men'
    elif damage == 'amount_scale':
        amount['scale'] = 1
    elif damage == 'favor_scale':
        favors['scale'] = 1
    elif damage == 'bool_scale':
        amount['scale'] = True
    elif damage == 'negative':
        amount['raw'] = -1
    elif damage == 'overflow':
        amount['raw'] = 2**31
    elif damage == 'bool_raw':
        amount['raw'] = True
    elif damage == 'bool_value':
        amount['value'] = True
    elif damage == 'value_mismatch':
        amount['value'] += 1
    elif damage == 'cost_negative':
        favors['cost_raw'] = -1
    elif damage == 'cost_bool':
        favors['cost_raw'] = True
    elif damage == 'cost_value':
        favors['cost'] += 1
    else:
        quote.pop('amount')
    result = source.read(query, source.context())
    assert result['fields']['parameters']['status'] == 'unknown'
    assert len(tools.inspect_calls) == 1


@pytest.mark.parametrize('damage', ['binding', 'inactive', 'invalid', 'rules'])
def test_quote_requires_a_current_bound_active_native_proposal(damage):
    source, tools, query = source_and_query('men')
    native = tools.envelope['native_inbound_inspection']
    if damage == 'binding':
        tools.envelope['observed_inbound_proposal']['proposal_id'] = 'b' * 32
    elif damage == 'inactive':
        native.update(pending_active=False, reason='PENDING_NOT_ACTIVE')
        tools.envelope['observed_inbound_proposal']['currently_pending'] = False
    elif damage == 'invalid':
        native['native_validity'] = False
    else:
        native['response_rules_complete'] = False
    assert source.read(query, source.context())['fields']['parameters']['status'] == 'unknown'
    assert len(tools.inspect_calls) == 1


@pytest.mark.parametrize('kind', ['gold', 'trust', 'men'])
def test_zero_quote_is_known_and_private_fields_are_excluded(kind):
    event = native_event(kind)
    event['favor_trade'].update(amount_raw=0, favor_cost_raw=0)
    source, tools, query = source_and_query(kind, event)
    quote = tools.envelope['native_inbound_inspection']['favor_trade']
    quote['private_extra'] = 'private-path'
    quote['amount']['native_pointer'] = '0xprivate'
    field = source.read(query, source.context())['fields']['parameters']
    assert field['status'] == 'known'
    assert field['value']['favor_trade']['amount']['value'] == 0
    assert field['value']['favor_trade']['favors']['cost'] == 0
    assert 'private' not in json.dumps(field)


@pytest.mark.parametrize('kind', ['gold', 'trust', 'men'])
def test_time_advance_preserves_the_observed_favor_quote(kind):
    source, tools, query = source_and_query(kind)
    tools.drift_after_inspect = 24
    result = source.read(query, source.context())
    field = result['fields']['parameters']
    assert field['status'] == 'known'
    assert field['observation_game_date'] == tools.envelope['native_inbound_inspection']['date_raw']
    assert len(tools.inspect_calls) == 1


@pytest.mark.parametrize('kind', ['gold', 'trust', 'men'])
@pytest.mark.parametrize('detail', ['full', 'brief'])
def test_normal_tool_quote_delivery_and_reopen_preserve_the_observation(kind, detail, tmp_path):
    source, tools, query = source_and_query(kind)
    database = tmp_path / 'information.sqlite3'
    with closing(InformationService(source, database)) as service:
        information_tools = InformationTools(service)
        report = service.manage_report('quote-report', 'create', config={
            'name': 'received favor quote', 'detail': detail, 'queries': [query]})['report']
        result = information_tools.call('information_query', {'request_id': 'quote-query', 'report_id': report['id']})
        full = service.get_result(result['result_id'])
        assert full['items'][0]['fields']['parameters']['status'] == 'known'
        assert present_concise(full) == result
        plain = deepcopy(query)
        plain['parameters'].pop('fresh_pending')
        assert source.read(plain, source.context())['fields']['parameters']['status'] == 'unknown'
        snapshot = source.replay_event(query, source.context(), {
            'event_type': 'diplomatic_proposal', 'observer': 'FRA', 'session_id': tools.session.session_id,
            'payload': tools.envelope['observed_inbound_proposal']})
        assert snapshot['fields']['parameters']['status'] == 'unknown'
        assert len(tools.inspect_calls) == 1
    with closing(InformationService(source, database)) as reopened:
        assert reopened.get_result(full['result_id']) == full
    assert len(tools.inspect_calls) == 1


def test_archived_actual_gold_quote_has_its_original_provenance(tmp_path):
    root = Path(__file__).resolve().parents[2]
    path = root / 'work/runtime/r71-favor-inbound-accept-20261020-001/native.jsonl'
    raw = path.read_bytes()
    assert len(raw) == 29645
    assert hashlib.sha256(raw).hexdigest() == '23bf3c2bda4a659a8ba20a8fd43aa31a4034662fc2450edad6cc9996ecafb092'
    event = json.loads(raw.splitlines()[1])
    assert ObserverSession._valid_native_inbound_inspection(
        event, event['query_id'], event['session_id'], event['actor'], event['phase'],
        event['native_proposal_id'], event['date_raw'], event['action_id'])
    source, tools, query = source_and_query('gold', event)
    database = tmp_path / 'information.sqlite3'
    with closing(InformationService(source, database)) as service:
        result = InformationTools(service).call('information_query', {
            'request_id': 'archived-gold-quote', 'queries': [query]})
        quote = service.get_result(result['result_id'])['items'][0]['fields']['parameters']['value']['favor_trade']
        assert quote['amount']['raw'] == 41508 and quote['amount']['value'] == 41.508
        assert quote['amount']['payer'] == 'FRA' and quote['amount']['receiver'] == 'SAV'
        assert quote['favors']['cost_raw'] == 10000 and quote['favors']['cost'] == 10
        assert len(tools.inspect_calls) == 1
    (tmp_path / 'archived-gold-query.json').write_text(json.dumps({
        'evidence_kind': 'archived_native_event_in_memory_inspector_harness',
        'native_source': str(path.relative_to(root)), 'source_line': 2,
        'current_game_inspection': False, 'result': result,
    }, ensure_ascii=False, indent=2), encoding='utf-8')
