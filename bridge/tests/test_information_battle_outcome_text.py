"""Synthetic v12 cache inputs never select a native outcome branch."""
from copy import deepcopy
import hashlib

import pytest

from bridge.information.battle_outcome_text import FIELDS, project_outcome_text_sources
from bridge.information.battle_display_composition import project_display_composition
from bridge.information.battle_name_sources import project_name_candidate
from bridge.information.tools import InformationTools
from bridge.information.service import InformationService
from bridge.tests.test_information_battle_name_sources_integration import _fixture
from bridge.tests.test_information_battles import make_source, event_id, battle_topic_query
from work import information_battle_name_sources_wire as base_wire
from work import information_battle_outcome_text_wire as wire
from work.ingest_information_battle_raw_live import _decode_payload, RawIngestError


def _field(raw=b'', state='known'):
    return {'state': state, 'length': len(raw), 'raw_hex': raw.hex()}


def _snapshot(base, *, failed=False):
    decoded = base_wire.decode(base)
    fields = {name: _field(state='unknown') if failed else _field(b'l_english' if name == 'language'
               else b'$COUNTRY$ won' if name == 'YOU_WON' else name.encode('ascii')) for name in FIELDS}
    if not failed:
        fields['ALLIES_LOST'] = _field(state='absent')
        fields['YOU_LOST'] = _field()
    return {'sequence': decoded['observation']['sequence'],
            'raw_date': decoded['observation']['result']['raw_date'],
            'kind': decoded['context']['kind'], 'failure': 3 if failed else 0,
            'text_fields': fields}


def _decoded(*, failed=False):
    fixture, base = _fixture()
    frame = wire.encode(base, _snapshot(base, failed=failed))
    return fixture, base, frame, wire.decode(frame)


def test_cached_templates_preserve_absent_empty_and_unexpanded_placeholders():
    _, base, _, decoded = _decoded()
    result = project_outcome_text_sources(decoded)
    assert result['status'] == 'known'
    assert result['text_fields']['ALLIES_LOST']['status'] == 'absent'
    assert result['text_fields']['YOU_LOST']['decoded']['value'] == ''
    assert result['text_fields']['YOU_WON']['decoded']['value'] == '$COUNTRY$ won'
    assert result['selection_status'] == 'unresolved'
    assert result['native_branch_selection_verified'] is False
    assert result['native_line1_verified'] is False
    assert result['native_formatter_invoked'] is False
    assert result['full_display_complete'] is False
    assert result['selection_status'] == 'unresolved'
    assert result['field_roles']['OTHERRESULT'] == 'legacy_cache_probe_of_format_parameter_name'
    assert result['field_roles']['MESSENGER'] == 'legacy_cache_probe_of_format_parameter_name'
    assert result['format_parameter_names'] == ['OTHERRESULT', 'MESSENGER']
    assert set(result['localization_keys']) == set(FIELDS[1:]) - {'OTHERRESULT', 'MESSENGER'}
    assert project_display_composition(decoded) == project_display_composition(base_wire.decode(base))


def test_failed_new_group_preserves_base_name_and_existing_composition():
    _, base, _, decoded = _decoded(failed=True)
    before = base_wire.decode(base)
    result = project_outcome_text_sources(decoded)
    assert result['status'] == 'unknown' and result['failure'] == 3
    assert all(item['status'] == 'unknown' for item in result['text_fields'].values())
    assert project_name_candidate(decoded) == project_name_candidate(before)
    assert project_display_composition(decoded) == project_display_composition(before)


def test_codec_failure_keeps_raw_source_and_other_templates():
    _, _, _, decoded = _decoded()
    decoded['outcome_text']['text_fields']['RESULT_WON'] = _field(b'\x10')
    result = project_outcome_text_sources(decoded)
    item = result['text_fields']['RESULT_WON']
    assert item['status'] == 'known' and item['raw_hex'] == '10'
    assert item['decoded']['status'] == 'unknown'
    assert result['text_fields']['RESULT_LOSS']['decoded']['status'] == 'known'


@pytest.mark.parametrize('mutation', ['sequence', 'date', 'kind_bool', 'failure_bool',
                                     'missing_key', 'extra_key', 'length_bool', 'NUL', 'language_absent',
                                     'mixed_failed_group', 'overlong_hex'])
def test_projection_rejects_invalid_or_cross_event_sources(mutation):
    _, _, _, decoded = _decoded()
    source = decoded['outcome_text']
    if mutation == 'sequence':
        source['sequence'] += 1
    elif mutation == 'date':
        source['raw_date'] += 1
    elif mutation == 'kind_bool':
        source['kind'] = True
    elif mutation == 'failure_bool':
        source['failure'] = False
    elif mutation == 'missing_key':
        source['text_fields'].pop('OTHERRESULT')
    elif mutation == 'extra_key':
        source['text_fields']['FAKE'] = _field()
    elif mutation == 'length_bool':
        source['text_fields']['YOU_WON']['length'] = True
    elif mutation == 'NUL':
        source['text_fields']['YOU_WON'] = _field(b'\0')
    elif mutation == 'language_absent':
        source['text_fields']['language'] = _field(state='absent')
    elif mutation == 'mixed_failed_group':
        source['failure'] = 1
    else:
        source['text_fields']['YOU_WON']['raw_hex'] = 'aa' * 8193
    assert project_outcome_text_sources(decoded)['reason'] == 'OUTCOME_TEXT_INVALID_OR_EVENT_MISMATCH'


def test_legacy11_does_not_gain_new_cache_sources():
    _, base = _fixture()
    assert wire.decode(base) == base_wire.decode(base)
    assert project_outcome_text_sources(wire.decode(base))['reason'] == 'OUTCOME_TEXT_NOT_CAPTURED'


@pytest.mark.parametrize('failed', [False, True])
def test_v12_ingest_public_query_report_and_event_remain_partial(tmp_path, failed):
    fixture, base, frame, decoded = _decoded(failed=failed)
    version, received = _decode_payload(frame)
    assert version == 12 and received == decoded
    fixture = deepcopy(fixture)
    fixture['payload_hex'] = frame.hex()
    fixture['provenance'].update(real_capture=False, synthetic_extension=True,
        source_mode='synthetic_v12_cache_inputs_over_retained_base',
        payload_sha256=hashlib.sha256(frame).hexdigest())
    source, *_ = make_source(tmp_path, fixture=fixture, observer='FRA', message_ids=('225',))
    selected = event_id(fixture, '225')
    query = battle_topic_query('B04', ['details', 'raw_text'], selected_event=selected)
    item = source.read(query, source.context())
    details = item['fields']['details']['value']
    assert details['outcome_text_sources'] == project_outcome_text_sources(decoded)
    assert details['display_composition']['full_display_complete'] is False
    composition = details['outcome_text_composition']
    assert composition['status'] == ('unknown' if failed else 'known')
    assert composition['native_formatter_invoked'] is False
    assert composition['native_branch_selection_verified'] is False
    assert composition['full_display_complete'] is False
    assert details['name_source_candidate'] == project_name_candidate(base_wire.decode(base))
    assert item['fields']['raw_text']['status'] == 'unknown'
    assert item['source']['name'] == 'IBOW.v12' and item['source']['projection_version'] == 30
    assert 'payload_sha256' not in item['source']
    assert item['source']['hash_basis'] == 'observer_visible_battle_fields'
    service = InformationService(source, tmp_path / 'information.sqlite3')
    tools = InformationTools(service)
    try:
        expected = service.query('outcome-query', queries=[query])['items'][0]['fields']
        assert expected['details']['value']['outcome_text_composition'] == composition
        report = tools.call('information_manage_report', dict(request_id='outcome-report', operation='create',
            config=dict(name='cached outcome alternatives', detail='full',
                        queries=[battle_topic_query('B04', ['details', 'raw_text'])])))['report']
        tools.call('information_manage_subscription', dict(request_id='outcome-event', operation='create',
            config=dict(name='cache event', kind='event', report_id=report['id'], enabled=True,
                binding=dict(session_id=fixture['provenance']['session_id'], observer='FRA',
                             game_version='1.37.4', game_sha256=fixture['provenance']['game_sha256']),
                event=dict(types=['battle_observation']))))
        delivered = tools.call('information_tick', {"view": "full"})['results']
        assert len(delivered) == 1 and delivered[0]['event']['event_id'] == selected
        assert delivered[0]['items'][0]['fields'] == expected
        assert (delivered[0]['items'][0]['fields']['details']['value']
                ['outcome_text_composition'] == composition)
        assert delivered[0]['complete'] is False
    finally:
        service.close()


def test_v12_receiver_rejects_trailing_data():
    _, _, frame, _ = _decoded()
    with pytest.raises(RawIngestError, match='v12_decode_failed'):
        _decode_payload(frame + b'\0')
