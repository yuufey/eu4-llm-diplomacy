"""Regression checks for independent same-event result-frame inputs."""
from copy import deepcopy
import hashlib
import struct

import pytest

from bridge.information.battle_display import project_display
from bridge.information.battle_display_composition import project_display_composition
from bridge.tests.test_information_battle_display_composition import _decoded
from bridge.tests.test_information_battle_outcome_tail import fixture13
from bridge.tests.test_information_battle_outcome_composition import _configure
from bridge.tests.test_information_battles import make_source, event_id, battle_topic_query
from bridge.information.service import InformationService
from bridge.information.tools import InformationTools
from work.information_battle_outcome_tail_wire import decode


@pytest.mark.parametrize('kind,count', [(1, 41), (2, 42)])
def test_uncaptured_template_keeps_binding_rows_and_independent_line_and_buttons(kind, count):
    decoded = _decoded(kind=kind)
    decoded.pop('message_template', None)
    original = deepcopy(decoded)
    assert project_display(decoded)['status'] != 'known'
    bindings = project_display(decoded, include_uncaptured_bindings=True)
    assert bindings['status'] == 'known'
    assert bindings['value']['template_capture']['status'] != 'known'
    assert len(bindings['value']['controls']) == count
    assert all(row['inputs'] == [] for row in bindings['value']['controls'])
    composed = project_display_composition(decoded)
    assert composed['status'] == 'known'
    assert composed['control_template_capture']['status'] != 'known'
    assert len(composed['controls']) == count
    for row in composed['controls']:
        candidate = row.get('compact_loss_candidate') or row.get('quantity_candidate') or row.get('effect_candidate')
        expected = candidate['status'] if candidate else 'unknown'
        if row.get('widget') in ('OurLost', 'EnemyLost') and 'compact_loss_candidate' not in row:
            expected = 'unknown'
        assert row['text']['status'] == expected
    assert composed['buttons']['status'] == 'known'
    assert [button['text'] for button in composed['buttons']['controls']] == ['OK', 'Accept', 'Cancel']
    if kind == 1:
        assert composed['line1']['status'] == 'known'
    assert composed['full_display_complete'] is False
    assert decoded == original


@pytest.mark.parametrize('failed_tail', [False, True])
def test_v13_winorlose_model_can_supply_only_the_missing_outcome_control(failed_tail):
    _, _, _, decoded = fixture13(failed=failed_tail)
    decoded.pop('message_template', None)
    mapping, observer = _configure(decoded, winner=0, observer_side=0)
    original = deepcopy(decoded)
    composed = project_display_composition(decoded, mapping=mapping, observer_ref=observer)
    assert composed['line1']['status'] == 'known'
    assert composed['buttons']['status'] == 'known'
    outcome = next(row for row in composed['controls'] if row.get('widget') == 'winORLose')
    if failed_tail:
        assert outcome['text']['status'] == 'unknown'
        assert outcome['selected_observer_candidate']['status'] == 'unknown'
    else:
        assert outcome['text']['status'] == 'known'
        assert outcome['text']['raw_hex'] == outcome['selected_observer_candidate']['raw_hex']
        assert outcome['text']['basis'] == 'derived_selected_observer_winorlose'
        assert outcome['text']['view_scope'] == 'selected_observer_not_physical_client'
        assert outcome['text']['native_parameter_assignment_verified'] is False
    assert all(row['text']['status'] == 'unknown'
               for row in composed['controls']
               if row.get('widget') != 'winORLose'
               and 'quantity_candidate' not in row and 'effect_candidate' not in row)
    assert composed['full_display_complete'] is False
    assert decoded == original


@pytest.mark.parametrize('values', [(b'Copied outcome',), (b'First', b'Second'), (b'\x10',)])
def test_model_preserves_copied_values_duplicate_ambiguity_and_invalid_copied_text(values):
    _, _, _, decoded = fixture13()
    mapping, observer = _configure(decoded, winner=0, observer_side=0)
    decoded['context']['physical_player_full_ref'] = observer
    decoded['message_template'] = {
        'source_kind': 'formatter_container_before_cleanup',
        'raw_container_word_10': 0, 'raw_container_flag_14': 0,
        'pair_count': len(values), 'pairs': [
            {'key_raw_hex': b'WINORLOSE'.hex(), 'value_raw_hex': value.hex()}
            for value in values],
    }
    composed = project_display_composition(decoded, mapping=mapping, observer_ref=observer)
    control = next(row for row in composed['controls'] if row['widget'] == 'winORLose')
    assert control['selected_observer_candidate']['status'] == 'known'
    if values == (b'Copied outcome',):
        assert control['text']['raw_hex'] == values[0].hex()
        assert control['text']['derived'] is False
    else:
        assert control['text']['status'] == 'unknown'


def test_unknown_name_line_does_not_hide_captured_button_labels():
    decoded = _decoded()
    decoded.pop('message_template', None)
    decoded['display_context']['fields']['body_template'] = {
        'state': 'observed', 'raw_hex': b'$UNSUPPORTED$'.hex()}
    composed = project_display_composition(decoded)
    assert composed['line1']['status'] == 'unknown'
    assert composed['buttons']['status'] == 'known'
    assert len(composed['controls']) == 41


def _without_template(frame):
    """Remove the optional v4 container from a synthetic nested wire frame."""
    version, size = struct.unpack_from('<HI', frame, 4)
    base = frame[10:10 + size]
    if version == 4:
        return frame[:10] + base + b'\0'
    assert version > 4
    replacement = _without_template(base)
    return frame[:6] + struct.pack('<I', len(replacement)) + replacement + frame[10 + size:]


def test_uncaptured_container_keeps_partial_result_through_query_report_and_event(tmp_path):
    fixture, _, frame, _ = fixture13()
    frame = _without_template(frame)
    assert decode(frame)['message_template'] is None
    fixture = deepcopy(fixture)
    fixture['payload_hex'] = frame.hex()
    fixture['provenance'].update(
        real_capture=False, synthetic_extension=True,
        source_mode='synthetic_v13_with_uncaptured_native_template',
        payload_sha256=hashlib.sha256(frame).hexdigest())
    source, *_ = make_source(tmp_path, fixture=fixture, observer='FRA', message_ids=('232',))
    query = battle_topic_query('B04', ['details', 'raw_text'],
                              selected_event=event_id(fixture, '232'))
    item = source.read(query, source.context())
    composed = item['fields']['details']['value']['display_composition']
    assert item['source']['projection_version'] == 30
    assert item['source']['hash_basis'] == 'observer_visible_battle_fields'
    assert composed['status'] == 'known'
    assert composed['control_template_capture']['status'] != 'known'
    assert composed['line1']['status'] == 'known'
    assert composed['buttons']['status'] == 'known'
    assert len(composed['controls']) == 41
    outcome = next(row for row in composed['controls'] if row.get('widget') == 'winORLose')
    assert outcome['text']['status'] == 'known' and outcome['text']['derived']
    quantities = [row for row in composed['controls'] if 'quantity_candidate' in row]
    assert len(quantities) == 20
    assert all(row['quantity_candidate']['status'] == 'known' for row in quantities)
    assert all(row['text']['status'] == 'known' and row['text']['derived']
               for row in quantities if row.get('widget') not in ('OurLost', 'EnemyLost'))
    effects = [row for row in composed['controls'] if 'effect_candidate' in row]
    assert len(effects) == 6
    assert all(row['text']['status'] == 'known' and row['text']['derived'] for row in effects)
    assert item['fields']['raw_text']['status'] == 'unknown'
    service = InformationService(source, tmp_path / 'information.sqlite3')
    tools = InformationTools(service)
    try:
        expected = service.query('partial-query', queries=[query])['items'][0]['fields']
        report = tools.call('information_manage_report', dict(
            request_id='partial-report', operation='create', config=dict(
                name='partial result frame', detail='full', queries=[query])))['report']
        reported = tools.call('information_query', dict(view="full", 
            request_id='partial-run-report', report_id=report['id']))
        assert reported['items'][0]['fields'] == expected
        subscription = tools.call('information_manage_subscription', dict(
            request_id='partial-event', operation='create', config=dict(
                name='partial result event', kind='event', report_id=report['id'], enabled=True,
                binding=dict(session_id=fixture['provenance']['session_id'], observer='FRA',
                    game_version='1.37.4', game_sha256=fixture['provenance']['game_sha256']),
                event=dict(types=['battle_observation']))))['subscription']
        delivered = tools.call('information_tick', {"view": "full"})['results']
        assert len(delivered) == 1 and delivered[0]['items'][0]['fields'] == expected
        assert delivered[0]['complete'] is False
        tools.call('information_manage_subscription', dict(
            request_id='partial-cancel', operation='cancel', subscription_id=subscription['id'],
            expected_version=subscription['version']))
    finally:
        service.close()
