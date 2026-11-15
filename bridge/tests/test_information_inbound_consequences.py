"""Conditional received-favor consequences stay separate from actual responses."""
from contextlib import closing
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from bridge.favor_resources import conditional_settlement, validate_result, NATIVE_ACCEPT, NATIVE_REJECT
from bridge.favor_trade import validate_result as validate_gold_result
from bridge.information import InformationService
from bridge.information.catalog import get_topic
from bridge.information.tools import InformationTools
from bridge.information.presentation import present_concise
from bridge.tests.test_information_inbound_favor_parameters import source_and_query
from bridge.tests.test_information_inbound_current import _source, _fixture_event, ACTIVE_FIXTURE


def effects_query(kind):
    source, tools, query = source_and_query(kind)
    query['fields'] = ['response_consequences']
    return source, tools, query


@pytest.mark.parametrize('kind', ['gold', 'trust', 'men'])
@pytest.mark.parametrize('mixed', [False, True])
def test_response_branches_share_one_inspection_and_keep_partial_conditional_semantics(kind, mixed):
    source, tools, query = effects_query(kind)
    if mixed:
        query['fields'] += ['parameters', 'currently_pending', 'proposal_status']
    result = source.read(query, source.context())
    field = result['fields']['response_consequences']
    assert field['status'] == 'known' and field['derived'] is True
    assert field['conditional_on'] == 'response_completes_in_inspected_state'
    assert field['complete'] is False and field['partial'] is True
    assert field['response_executed'] is False and field['response_authority'] is False
    assert 'OTHER_RELATION_PRESTIGE_OR_SCRIPT_EFFECTS_NOT_PROJECTED' in field['gaps']
    accepted, rejected = field['value']['accept'], field['value']['reject']
    assert accepted['legality'] == 'checked_for_current_inspection'
    assert rejected['legality'] == 'not_inspected'
    assert all(change['delta_raw'] == 0 for change in rejected['changes'])
    for change in rejected['changes']:
        if 'before_raw' in change:
            assert change['before_raw'] == change['after_raw']
    assert len(tools.inspect_calls) == 1
    assert 'response_consequences' not in result['fields'].get('proposal_status', {})
    if kind == 'gold':
        resources = {row['country']: row['delta_raw'] for row in accepted['changes'] if row['resource'] == 'treasury'}
        assert resources == {'LIT': 10500, 'FRA': -10500}
    elif kind == 'trust':
        trust = next(row for row in accepted['changes'] if row['resource'] == 'trust')
        assert trust['before_raw'] == 95 and trust['after_raw'] == 100 and trust['delta_raw'] == 5
    else:
        resources = {row['country']: row['delta_raw'] for row in accepted['changes'] if row['resource'] == 'manpower'}
        assert resources == {'PAP': 25, 'FRA': -25}


@pytest.mark.parametrize('kind', ['trust', 'men'])
@pytest.mark.parametrize('state', [NATIVE_ACCEPT, NATIVE_REJECT])
def test_conditional_arithmetic_is_the_same_contract_used_to_verify_actual_settlement(kind, state):
    before = {'complete': True, 'favors_raw': 20000, 'cost_raw': 7000}
    amount = 10
    if kind == 'trust':
        before['recipient_trust_raw'] = 95
    else:
        before.update(actor_manpower_raw=100, recipient_manpower_raw=50)
    original = deepcopy(before)
    after = conditional_settlement(before, amount, kind, state)
    assert before == original and after is not None
    observed = {'kind': kind, 'before': before, 'after': after, 'amount_raw': amount,
                'complete': True, 'verified': True}
    assert validate_result(observed, state)
    observed['after']['favors_raw'] += 1
    assert not validate_result(observed, state)


@pytest.mark.parametrize('damage', ['amount_bool', 'kind', 'incomplete', 'state_bool', 'unaffordable', 'overflow'])
def test_conditional_settlement_rejects_unsupported_or_inconsistent_states(damage):
    before = {'complete': True, 'favors_raw': 20000, 'cost_raw': 7000,
              'actor_manpower_raw': 100, 'recipient_manpower_raw': 50}
    amount, kind, state = 10, 'men', NATIVE_ACCEPT
    if damage == 'amount_bool':
        amount = True
    elif damage == 'kind':
        kind = []
    elif damage == 'incomplete':
        before['complete'] = False
    elif damage == 'state_bool':
        state = True
    elif damage == 'unaffordable':
        before['favors_raw'] = 1
    else:
        before['actor_manpower_raw'] = 2**31 - 1
    assert conditional_settlement(before, amount, kind, state) is None


@pytest.mark.parametrize('damage', [
    'favors_missing', 'favors_bool', 'favors_display', 'favors_insufficient', 'favors_underflow',
    'trust_bool', 'trust_unit', 'trust_party', 'trust_cap',
    'men_missing', 'men_party', 'men_insufficient', 'men_overflow',
])
def test_invalid_consequence_inputs_preserve_known_request_parameters(damage):
    kind = 'gold'
    if damage.startswith('trust'):
        kind = 'trust'
    elif damage.startswith('men') or damage == 'favors_insufficient':
        kind = 'men'
    source, tools, query = effects_query(kind)
    query['fields'] += ['parameters', 'currently_pending']
    quote = tools.envelope['native_inbound_inspection']['favor_trade']
    if damage == 'favors_missing':
        quote['favors'].pop('current_raw')
    elif damage == 'favors_bool':
        quote['favors']['current_raw'] = True
    elif damage == 'favors_display':
        quote['favors']['current'] += 1
    elif damage == 'favors_insufficient':
        quote['favors'].update(current_raw=0, current=0)
    elif damage == 'favors_underflow':
        quote['favors'].update(current_raw=-(2**31), current=-(2**31) / 1000)
    elif damage == 'trust_bool':
        quote['trust']['raw'] = True
    elif damage == 'trust_unit':
        quote['trust']['unit'] = 'men'
    elif damage == 'trust_party':
        quote['trust']['trustor'] = 'POR'
    elif damage == 'trust_cap':
        quote['trust'].update(raw=100, value=100)
    elif damage == 'men_missing':
        quote.pop('manpower')
    elif damage == 'men_party':
        quote['manpower']['actor'] = 'POR'
    elif damage == 'men_insufficient':
        quote['manpower']['recipient_raw'] = 0
    else:
        quote['manpower']['actor_raw'] = 2**31 - 1
    fields = source.read(query, source.context())['fields']
    assert fields['response_consequences']['status'] == 'unknown'
    assert fields['parameters']['status'] == 'known'
    assert fields['currently_pending']['value'] is True
    assert len(tools.inspect_calls) == 1


def test_gold_conditional_favor_delta_preserves_the_existing_signed_settlement_contract():
    source, tools, query = effects_query('gold')
    quote = tools.envelope['native_inbound_inspection']['favor_trade']
    quote['favors'].update(current_raw=0, current=0)
    field = source.read(query, source.context())['fields']['response_consequences']
    assert field['status'] == 'known'
    favor_change = next(row for row in field['value']['accept']['changes'] if row['resource'] == 'favors')
    assert favor_change['before_raw'] == 0 and favor_change['after_raw'] == -10000


def test_plain_snapshot_and_unsupported_action_do_not_trigger_current_inspection():
    source, tools, query = effects_query('gold')
    query['parameters'].pop('fresh_pending')
    assert source.read(query, source.context())['fields']['response_consequences']['status'] == 'unknown'
    assert tools.inspect_calls == []
    source, tools = _source(_fixture_event(ACTIVE_FIXTURE))
    proposal = tools.session.read_native_alliance_inbound_offers()[0]
    proposal['action_id'] = 'support_independence'
    tools.session.read_native_alliance_inbound_offers = lambda: [deepcopy(proposal)]
    query['parameters']['fresh_pending'] = True
    assert source.read(query, source.context())['fields']['response_consequences']['status'] == 'unknown'
    assert tools.inspect_calls == []


@pytest.mark.parametrize('kind', ['gold', 'trust', 'men'])
@pytest.mark.parametrize('detail', ['full', 'brief'])
def test_normal_queries_and_reopen_preserve_conditional_changes(kind, detail, tmp_path):
    source, tools, query = effects_query(kind)
    database = tmp_path / 'information.sqlite3'
    with closing(InformationService(source, database)) as service:
        report = service.manage_report('effect-report', 'create', config={
            'name': 'received request consequences', 'detail': detail, 'queries': [query]})['report']
        result = InformationTools(service).call('information_query', {
            'request_id': 'effect-query', 'report_id': report['id']})
        full = service.get_result(result['result_id'])
        assert full['items'][0]['fields']['response_consequences']['status'] == 'known'
        assert present_concise(full) == result
        snapshot = source.replay_event(query, source.context(), {
            'event_type': 'diplomatic_proposal', 'observer': 'FRA', 'session_id': tools.session.session_id,
            'payload': tools.envelope['observed_inbound_proposal']})
        assert snapshot['fields']['response_consequences']['status'] == 'unknown'
        assert len(tools.inspect_calls) == 1
    with closing(InformationService(source, database)) as reopened:
        assert reopened.get_result(full['result_id']) == full


def test_catalog_declares_partial_favor_scope():
    field = get_topic('A04')['fields']['response_consequences']
    assert field['coverage'] == 'partial' and field['complete'] is False
    assert field['derived'] is True and field['response_authority'] is False
    assert len(field['supported_actions']) == 8


def test_archived_native_gold_quote_projects_conditional_changes_through_the_tool(tmp_path):
    root = Path(__file__).resolve().parents[2]
    path = root / 'work/runtime/r71-favor-inbound-accept-20261020-001/native.jsonl'
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == '23bf3c2bda4a659a8ba20a8fd43aa31a4034662fc2450edad6cc9996ecafb092'
    event = json.loads(raw.splitlines()[1])
    source, tools, query = source_and_query('gold', event)
    query['fields'] += ['response_consequences', 'currently_pending']
    database = tmp_path / 'information.sqlite3'
    with closing(InformationService(source, database)) as service:
        result = InformationTools(service).call('information_query', {
            'request_id': 'archived-gold-effects', 'queries': [query]})
        field = service.get_result(result['result_id'])['items'][0]['fields']['response_consequences']
        assert field['status'] == 'known' and field['derived'] is True
        accepted = field['value']['accept']['changes']
        assert {row['country']: row['delta_raw'] for row in accepted if row['resource'] == 'treasury'} == {
            'SAV': 41508, 'FRA': -41508}
        favors = next(row for row in accepted if row['resource'] == 'favors')
        assert favors['before_raw'] == 20231 and favors['after_raw'] == 10231
        assert favors['delta_raw'] == -10000
        assert field['response_executed'] is False and len(tools.inspect_calls) == 1
        archived_events = [json.loads(line) for line in raw.splitlines()]
        actual = next(row for row in archived_events
                      if row.get('event') == 'native_diplomacy_favor_trade_response_result')
        assert all(actual[key] == event[key] for key in ('actor', 'recipient', 'session_id', 'date_raw'))
        assert actual['native_state'] == NATIVE_ACCEPT
        assert validate_gold_result(actual['favor_trade'], actual['native_state'])
        settlement = actual['favor_trade']
        assert settlement['amount_raw'] == event['favor_trade']['amount_raw']
        assert settlement['before']['favors_raw'] == favors['before_raw']
        assert settlement['after']['favors_raw'] == favors['after_raw']
        for country, key in (('SAV', 'actor_treasury_raw'), ('FRA', 'recipient_treasury_raw')):
            delta = settlement['after'][key] - settlement['before'][key]
            predicted = next(row for row in accepted if row['resource'] == 'treasury' and row['country'] == country)
            assert delta == predicted['delta_raw']
    (tmp_path / 'archived-gold-effects.json').write_text(json.dumps({
        'evidence_kind': 'conditional_projection_from_archived_native_quote',
        'actual_new_response': False, 'current_game_inspection': False, 'result': result,
    }, ensure_ascii=False, indent=2), encoding='utf-8')
