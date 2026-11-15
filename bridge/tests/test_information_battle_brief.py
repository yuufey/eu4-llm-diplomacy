"""Decision-oriented brief views use selected fields and original side identities."""
from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge.information import InformationService
from bridge.information.presentation import present_result, present_concise
from bridge.information.tools import InformationTools
from bridge.information.truce_date_math import decode_date
from bridge.tests.test_information_battles import (
    LIVE_V3_FIXTURE_PATH, LIVE_V4_FIXTURE_PATH, event_id, make_source,
)
from bridge.tests.test_information_service import FakeClock, FakeOutput, subscription_config


CONFIG = Path(__file__).resolve().parents[2] / 'docs/02-使用与接口/战争与战报/宏观战报简报配置.json'


def configuration(record_id=None):
    value = json.loads(CONFIG.read_text(encoding='utf-8'))
    if record_id is not None:
        for query in value['queries']:
            query['parameters']['event_id'] = record_id
    return value


def fixture_source(tmp_path, path=LIVE_V4_FIXTURE_PATH):
    fixture = json.loads(path.read_text(encoding='utf-8'))
    return make_source(tmp_path, fixture, observer=fixture.get('recorded_observer_tag', 'FRA'))


def modeled_result(source, record_id):
    return {'result_id': 'brief-model', 'detail': 'brief', 'context': source.context(),
            'items': [source.read(query, source.context()) for query in configuration(record_id)['queries']]}


def summary(result):
    return result['presentation']['battle_summaries'][0]


@pytest.mark.parametrize('path', [LIVE_V4_FIXTURE_PATH, LIVE_V3_FIXTURE_PATH])
def test_recorded_land_and_naval_summaries_use_combat_mapping_and_original_units(tmp_path, path):
    source, _primary, fixture, _db, _payload = fixture_source(tmp_path, path)
    original = modeled_result(source, event_id(fixture))
    before = deepcopy(original)
    shown = present_result(original)
    view = summary(shown)
    assert view['status'] == 'known'
    assert view['missing_core_fields'] == []
    assert view['complete'] is False and view['is_native_raw_text'] is False
    assert original == before and shown['items'] == original['items']
    assert present_result(shown) == shown
    facts = view['facts']
    by_combat = {side['combat_side_index']: side for side in facts['sides']['value']}
    for side in view['sides']:
        index = side['combat_side_index']
        assert side['participants'] == by_combat[index]['participants']
        assert side['role'] == by_combat[index]['role']
        for field_name in ('initial_forces', 'losses', 'remaining_forces'):
            metric = side[field_name]
            source_side = next(part for part in facts[field_name]['value']['sides']
                               if part['combat_side_index'] == index)
            assert metric['value'] == source_side['component_sum']
            assert metric['unit'] == facts[field_name]['value']['unit']
            assert metric['source_path'].startswith(view['source_paths'][field_name])
            pointed = shown
            for part in metric['source_path'].split('/')[1:]:
                pointed = pointed[int(part)] if isinstance(pointed, list) else pointed[part]
            assert pointed == metric['value']
        for field_name, effect in side['effects'].items():
            assert effect['status'] == 'known'
            source_value = facts[field_name]['value']
            source_side = next(part for part in source_value['sides']
                               if part['combat_side_index'] == index)
            assert effect['raw'] == source_side['raw']
            assert effect['display_numeric'] == source_side['display_numeric']
            assert effect['scope'] == 'whole_combat_side'
            assert effect['quantity'] == 'result_window_side_operand'
            assert effect['unit'] == source_value['unit'] and effect['scale'] == 1000
            assert effect['display_numeric'] in view['text']
            for path_name, expected in (('source_path', effect['raw']),
                                        ('display_source_path', effect['display_numeric'])):
                pointed = shown
                for part in effect[path_name].split('/')[1:]:
                    pointed = pointed[int(part)] if isinstance(pointed, list) else pointed[part]
                assert pointed == expected
    if path == LIVE_V3_FIXTURE_PATH:
        assert all(side['losses']['quantity'] == 'net_ship_change' for side in view['sides'])
        assert '舰船净变化' in view['text']
        assert '各类损失合计' not in view['text']
        assert '陆军传统' not in view['text']
        assert all('army_tradition' not in side['effects'] for side in view['sides'])


@pytest.mark.parametrize('field_name', ['war_score', 'prestige', 'army_tradition'])
@pytest.mark.parametrize('damage', ['party', 'duplicate', 'unknown', 'unit', 'raw', 'side_bool', 'legacy'])
def test_effect_failure_is_local_and_keeps_known_counts(tmp_path, field_name, damage):
    source, _primary, fixture, _db, _payload = fixture_source(tmp_path)
    result = modeled_result(source, event_id(fixture))
    fields = result['items'][2]['fields']
    effect = fields[field_name]
    index = effect['value']['sides'][0]['combat_side_index']
    if damage == 'party':
        effect['value']['sides'][0]['participants'] = ['WRONG']
    elif damage == 'duplicate':
        effect['value']['sides'].append(deepcopy(effect['value']['sides'][0]))
    elif damage == 'unknown':
        fields[field_name] = {'status': 'unknown', 'reason': 'NOT_CAPTURED'}
    elif damage == 'unit':
        effect['value']['unit'] = 'wrong_unit'
    elif damage == 'raw':
        effect['value']['sides'][0]['raw'] = True
    elif damage == 'side_bool':
        effect['value']['sides'][0]['combat_side_index'] = bool(index)
    else:
        effect['value'] = {'old_format': 'unresolved'}
    view = summary(present_result(result))
    assert view['status'] == 'known'
    side = next(value for value in view['sides'] if value['combat_side_index'] == index)
    assert side['effects'][field_name]['status'] == 'unknown'
    assert 'raw' not in side['effects'][field_name]
    assert side['losses']['status'] == 'known'
    assert view['facts'][field_name] == fields[field_name]


def test_effect_side_order_and_signed_zero_preserve_source_values(tmp_path):
    source, _primary, fixture, _db, _payload = fixture_source(tmp_path)
    result = modeled_result(source, event_id(fixture))
    fields = result['items'][2]['fields']
    value = fields['war_score']['value']
    value['sides'].reverse()
    side = value['sides'][0]
    side.update(raw=-5, amount_decimal='-0.005', display_numeric='-0.00')
    view = summary(present_result(result))
    projected = next(part for part in view['sides'] if part['combat_side_index'] == side['combat_side_index'])
    assert projected['effects']['war_score']['raw'] == -5
    assert projected['effects']['war_score']['amount_decimal'] == '-0.005'
    assert '战争分-0.00' in view['text']


def test_unselected_effects_do_not_appear_in_brief_text(tmp_path):
    source, _primary, fixture, _db, _payload = fixture_source(tmp_path)
    result = modeled_result(source, event_id(fixture))
    result['items'].pop(2)
    view = summary(present_result(result))
    assert all('effects' not in side for side in view['sides'])
    assert '战争分' not in view['text'] and '威望' not in view['text']


def test_different_record_ids_remain_separate_even_with_identical_dates(tmp_path):
    source, _primary, fixture, _db, _payload = fixture_source(tmp_path)
    result = modeled_result(source, event_id(fixture))
    other = deepcopy(result['items'])
    for item in other:
        item['query']['parameters']['event_id'] = 'another-record'
        if 'event_id' in item['fields']:
            item['fields']['event_id']['value'] = 'another-record'
    result['items'] += other
    views = present_result(result)['presentation']['battle_summaries']
    assert [view['event_id'] for view in views] == [event_id(fixture), 'another-record']


@pytest.mark.parametrize('damage', ['party', 'duplicate', 'unknown'])
def test_unknown_or_mismatched_counts_do_not_turn_into_zero_or_other_side_values(tmp_path, damage):
    source, _primary, fixture, _db, _payload = fixture_source(tmp_path)
    result = modeled_result(source, event_id(fixture))
    losses = result['items'][1]['fields']['losses']
    index = losses['value']['sides'][0]['combat_side_index']
    if damage == 'party':
        losses['value']['sides'][0]['participants'] = ['WRONG']
    elif damage == 'duplicate':
        losses['value']['sides'].append(deepcopy(losses['value']['sides'][0]))
    else:
        result['items'][1]['fields']['losses'] = {'status': 'unknown', 'reason': 'NOT_CAPTURED'}
    view = summary(present_result(result))
    side = next(value for value in view['sides'] if value['combat_side_index'] == index)
    assert side['losses']['status'] == 'unknown'
    assert 'value' not in side['losses']
    assert '损失合计未知' in view['text']


def test_selected_fields_only_and_conflicts_are_local_to_presentation(tmp_path):
    source, _primary, fixture, _db, _payload = fixture_source(tmp_path)
    result = modeled_result(source, event_id(fixture))
    result['event'] = {'event_type': 'battle_observation', 'event_id': event_id(fixture),
                       'payload': {'secret_not_selected': 42}}
    result['items'] = result['items'][:1]
    result['items'][0]['fields'].pop('winner')
    view = summary(present_result(result))
    assert 'winner' in view['missing_core_fields']
    assert 'winner' not in view['facts'] and 'secret_not_selected' not in json.dumps(view)
    assert '胜负未知' in view['text']
    duplicate = deepcopy(result['items'][0])
    duplicate['fields']['name']['value'] = 'conflicting-name'
    result['items'].append(duplicate)
    before = deepcopy(result)
    shown = present_result(result)
    assert summary(shown)['status'] == 'unknown'
    assert shown['items'] == result['items'] and result == before


@pytest.mark.parametrize('item', [
    {'topic': 'B01', 'fields': None},
    {'topic': 'B01', 'query': 'legacy-invalid-query'},
    {'topic': 'B01', 'query': {'parameters': None}},
])
def test_malformed_legacy_selectors_do_not_break_other_brief_fields(item):
    original = {'result_id': 'legacy-brief', 'detail': 'brief', 'event': 'legacy-event',
                'items': [item, {'topic': 'other', 'fields': {'value': {'status': 'known', 'value': 7}}}]}
    before = deepcopy(original)
    shown = present_result(original)
    assert shown['items'] == original['items'] and original == before
    assert 'battle_summaries' not in shown['presentation']


@pytest.mark.parametrize('path', [LIVE_V4_FIXTURE_PATH, LIVE_V3_FIXTURE_PATH])
def test_public_query_event_delivery_and_reopen_preserve_complete_records(tmp_path, path):
    source, _primary, fixture, _db, _payload = fixture_source(tmp_path, path)
    database = tmp_path / 'information.sqlite3'
    output, clock = FakeOutput(), FakeClock()
    with closing(InformationService(source, database, output=output, clock=clock)) as service:
        tools = InformationTools(service)
        report = tools.call('information_manage_report', {
            'request_id': 'battle-brief-report', 'operation': 'create',
            'config': configuration(event_id(fixture)),
        })['report']
        queried = tools.call('information_query', {
            'request_id': 'battle-brief-query', 'report_id': report['id'],
        })
        query_full = tools.call('information_get_result', {'result_id': queried['result_id'], 'view': 'full'})
        assert summary(present_result(query_full))['status'] == 'known'
        raw_date = query_full['items'][0]['fields']['end_date']['value']['raw']
        year, month, day, _hour = decode_date(raw_date)
        assert queried['items'][0]['end_date'] == f'{year}.{month}.{day}'
        event_report = tools.call('information_manage_report', {
            'request_id': 'battle-event-report', 'operation': 'create', 'config': configuration(),
        })['report']
        tools.call('information_manage_subscription', {
            'request_id': 'battle-event-subscription', 'operation': 'create',
            'config': subscription_config(event_report['id'], kind='event',
                                          event={'types': ['battle_observation']}),
        })
        delivered = tools.call('information_tick', {})['results']
        assert len(delivered) == 1
        full = tools.call('information_get_result', {'result_id': delivered[0]['result_id'], 'view': 'full'})
        view = summary(present_result(full))
        assert view['event_id'] == event_id(fixture)
        assert view['facts'] == summary(present_result(query_full))['facts']
        event_output = next(value for value in output.delivered if value["result_id"] == full["result_id"])
        assert event_output == present_concise(full)
        assert 'presentation' not in full
        assert present_concise(full) == delivered[0]
        assert delivered[0]['items'][0]['end_date'] == queried['items'][0]['end_date']
        assert tools.call('information_tick', {})['results'] == []
    with closing(InformationService(source, database, clock=clock)) as service:
        tools = InformationTools(service)
        listed = tools.call('information_list_results', {})['results']
        old = next(value for value in listed if value['result_id'] == full['result_id'])
        assert old == present_concise(full)
        assert tools.call('information_get_result', {'result_id': full['result_id'], 'view': 'full'}) == full
