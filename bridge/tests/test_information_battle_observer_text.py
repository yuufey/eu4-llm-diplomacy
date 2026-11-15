"""Synthetic client text must retain its scope when composed for another country."""
from contextlib import closing
from copy import deepcopy
import hashlib
from pathlib import Path
import struct

import pytest

from bridge.information import InformationService
from bridge.information.battle_display import project_display
from bridge.information.battle_display_composition import project_display_composition, project_readable_text
from bridge.information.battle_outcome_composition import project_outcome_text_composition
from bridge.information.tools import InformationTools
from bridge.tests.test_information_battle_display_composition import _decoded
from bridge.tests.test_information_battle_outcome_composition import _configure
from bridge.tests.test_information_battle_outcome_tail import fixture13
from bridge.tests.test_information_battle_text import _v4_container_frame
from bridge.tests.test_information_battles import battle_topic_query, event_id, make_source
from work.information_battle_outcome_tail_wire import decode


def _client_text(decoded, values=(b'Physical client outcome',)):
    decoded['message_template'] = {
        'source_kind': 'formatter_container_before_cleanup',
        'raw_container_word_10': 0, 'raw_container_flag_14': 0,
        'pair_count': len(values), 'pairs': [
            {'key_raw_hex': b'WINORLOSE'.hex(), 'value_raw_hex': value.hex()}
            for value in values],
    }


def _outcome_control(composition):
    return next(row for row in composition['controls'] if row['template_key'] == 'WINORLOSE')


@pytest.mark.parametrize('winner,observer_side', [(0, 0), (0, 1), (1, 0), (1, 1)])
@pytest.mark.parametrize('kind', [1, 2])
def test_an_opposing_physical_client_cannot_supply_the_observer_outcome(winner, observer_side, kind):
    if kind == 1:
        _, _, _, decoded = fixture13()
    else:
        path = Path(__file__).parent / 'fixtures/information_battle_independent_line_base13_naval.bin'
        decoded = decode(path.read_bytes())
    mapping, observer = _configure(decoded, winner=winner, observer_side=observer_side)
    decoded['context']['physical_player_full_ref'] = (
        decoded['context']['sides'][1 - observer_side]['participants']['full_refs'][0])
    _client_text(decoded)
    before = deepcopy(decoded)
    composed = project_display_composition(decoded, mapping=mapping, observer_ref=observer)
    control = _outcome_control(composed)
    candidate = project_outcome_text_composition(decoded, mapping=mapping, observer_ref=observer)['winorlose']
    assert control['text']['status'] == candidate['status'] == 'known'
    assert control['text']['raw_hex'] == candidate['raw_hex']
    assert control['text']['view_scope'] == 'selected_observer_not_physical_client'
    assert control['text']['derived'] is True
    assert control['native_client_text']['value'] == 'Physical client outcome'
    assert control['native_client_text']['derived'] is False
    assert control['native_client_text']['view_scope'] == 'physical_client'
    assert decoded == before
    readable = project_readable_text(composed)
    assert 'Physical client outcome' not in readable['text']
    assert 'control_text:winORLose' not in composed['remaining_gaps']
    assert readable['complete'] is composed['full_display_complete'] is False


@pytest.mark.parametrize('failure', ['tail', 'legacy', 'absent_observer', 'unknown_physical'])
def test_unknown_observer_text_cannot_fall_back_to_a_known_client_phrase(failure):
    _, _, _, decoded = fixture13(failed=failure == 'tail')
    mapping, observer = _configure(decoded, winner=0, observer_side=0)
    _client_text(decoded)
    if failure == 'legacy':
        decoded.pop('wire12')
        decoded.pop('outcome_text')
    elif failure == 'absent_observer':
        observer = decoded['context']['physical_player_full_ref'] + (1 << 48)
    elif failure == 'unknown_physical':
        decoded.pop('wire13')
        decoded['context'].pop('physical_player_full_ref')
    composed = project_display_composition(decoded, mapping=mapping, observer_ref=observer)
    control = _outcome_control(composed)
    assert control['text']['status'] == 'unknown'
    assert control['native_client_text']['status'] == 'known'
    assert 'Physical client outcome' not in project_readable_text(composed)['text']
    assert 'control_text:winORLose' in composed['remaining_gaps']


def test_unspecified_observer_keeps_the_copied_client_text_with_explicit_scope():
    _, _, _, decoded = fixture13()
    _client_text(decoded)
    display = project_display(decoded)
    raw_control = next(row for row in display['value']['controls'] if row['template_key'] == 'WINORLOSE')
    assert raw_control['text_view_scope'] == 'physical_client'
    control = _outcome_control(project_display_composition(decoded))
    assert control['text']['value'] == 'Physical client outcome'
    assert control['text']['derived'] is False
    assert 'native_client_text' not in control


def test_gap_list_follows_selected_controls_and_known_frame_requests():
    decoded = _decoded(layout=1)
    _client_text(decoded)
    decoded['message_template']['pairs'].append(
        {'key_raw_hex': b'OURFIRE'.hex(), 'value_raw_hex': b'3'.hex()})
    decoded['message_template']['pair_count'] += 1
    composed = project_display_composition(decoded)
    assert 'window_title' not in composed['remaining_gaps']
    assert 'unsupported_control_text_and_frame_inputs' not in composed['remaining_gaps']
    assert 'native_line1' in composed['remaining_gaps']
    assert 'control_input:our_fire_value' not in composed['remaining_gaps']
    assert 'control_input:our_shock_value' in composed['remaining_gaps']
    assert 'control_text:OurLost' not in composed['remaining_gaps']  # compact branch excluded
    assert 'control_text:winORLose' not in composed['remaining_gaps']
    assert composed['projection_version'] == 2
    assert project_readable_text(composed)['projection_version'] == 3


def _replace_client_text(frame):
    version, size = struct.unpack_from('<HI', frame, 4)
    base = frame[10:10 + size]
    if version == 4:
        return _v4_container_frame(base, raw_word=0, raw_flag=0,
                                   pairs=[(b'WINORLOSE', b'Physical client outcome')])
    assert version > 4
    replacement = _replace_client_text(base)
    return frame[:6] + struct.pack('<I', len(replacement)) + replacement + frame[10 + size:]


@pytest.mark.parametrize('failed_tail', [False, True])
@pytest.mark.parametrize('detail', ['full', 'brief'])
def test_observer_scope_survives_normal_query_delivery_dedup_and_reopen(tmp_path, failed_tail, detail):
    fixture, _, frame, _ = fixture13(failed=failed_tail)
    frame = _replace_client_text(frame)
    fixture = deepcopy(fixture)
    fixture['payload_hex'] = frame.hex()
    fixture['provenance'].update(real_capture=False, synthetic_extension=True,
        source_mode='synthetic_client_outcome_over_retained_v13_base',
        payload_sha256=hashlib.sha256(frame).hexdigest())
    source, *_ = make_source(tmp_path, fixture, observer='FRA', message_ids=('280',))
    query = battle_topic_query('B04', ['details', 'raw_text'], selected_event=event_id(fixture, '280'))
    database = tmp_path / 'observer-text.sqlite3'
    with closing(InformationService(source, database)) as service:
        tools = InformationTools(service)
        public = tools.call('information_query', {'request_id': 'observer-text-query', 'queries': [query]})
        item = service.get_result(public['result_id'])['items'][0]
        control = _outcome_control(item['fields']['details']['value']['display_composition'])
        assert control['native_client_text']['value'] == 'Physical client outcome'
        assert control['text']['status'] == ('unknown' if failed_tail else 'known')
        assert item['source']['display_composition_projection_version'] == 2
        report = tools.call('information_manage_report', {'request_id': 'observer-text-report',
            'operation': 'create', 'config': {'name': 'Observer battle text', 'detail': detail,
            'queries': [battle_topic_query('B04', ['details', 'raw_text'])]}})['report']
        subscription = tools.call('information_manage_subscription', {'request_id': 'observer-text-subscribe',
            'operation': 'create', 'config': {'name': 'Observer battle text', 'kind': 'event',
            'report_id': report['id'], 'enabled': True, 'event': {'types': ['battle_observation']}}})['subscription']
        result, = tools.call('information_tick', {})['results']
        full = tools.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})
        assert full['items'][0]['fields'] == item['fields']
        assert full['complete'] is False
        if detail == 'brief':
            assert 'Physical client outcome' not in result['items'][0]['details']
        assert tools.call('information_tick', {})['results'] == []
        tools.call('information_manage_subscription', {'request_id': 'observer-text-cancel',
            'operation': 'cancel', 'subscription_id': subscription['id'],
            'expected_version': subscription['version']})
    with closing(InformationService(source, database)) as reopened:
        assert reopened.get_result(result['result_id']) == full
