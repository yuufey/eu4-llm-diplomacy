"""Synthetic NSRC extension over a retained base: ingest and public API flow."""
from copy import deepcopy
import hashlib
import struct

import pytest

from bridge.information import InformationService
from bridge.information.tools import InformationTools
from bridge.information.presentation import present_result
from bridge.tests.test_information_battle_display_context_integration import GAME_SHA256, _v7_fixture
from bridge.tests.test_information_battles import battle_topic_query, event_id, make_source, _full_ref
from bridge.tests.test_information_battle_name_sources import _with_synthetic_sources, _field
from bridge.information.battle_body_candidate import project_body_candidate
from work import information_battle_end_state_wire as v9
from work import information_battle_retreat_wire as v10
from work import information_battle_name_sources_wire as v11
from work import ingest_information_battle_raw_live as ingest


def _fixture(transform_mode=1):
    fixture, _, base7 = _v7_fixture()
    base = v10.encode(v9.encode(base7, {'state': 'unknown'}), {'state': 'unknown'})
    decoded = v10.decode(base)
    snapshot = dict(sequence=decoded['observation']['sequence'],
                    raw_date=decoded['observation']['result']['raw_date'],
                    kind=decoded['context']['kind'], raw_failure=0, prefix_failure=0,
                    transform_mode=transform_mode, text_fields={})
    values = (dict(owner_name=b'Paris', global_name=b' ', battle_of_template=b' battle', language=b'l_english')
              if transform_mode == 2 else dict(owner_name=b'', global_name=b'PARIS',
                  battle_of_template=b'BATTLE_OF_', language=b'l_english'))
    for key, value in values.items():
        snapshot['text_fields'][key] = dict(state='known', length=len(value), raw_hex=value.hex())
    payload = v11.encode(base, snapshot)
    fixture = deepcopy(fixture)
    fixture['payload_hex'] = payload.hex()
    fixture['provenance'].update(real_capture=False, synthetic_extension=True,
        source_mode='synthetic_v11_name_sources_over_retained_base',
        payload_sha256=hashlib.sha256(payload).hexdigest())
    return fixture, payload


@pytest.mark.parametrize('mode', [1, 2])
@pytest.mark.parametrize('detail', ['full', 'brief'])
def test_v11_ingest_query_report_and_event_keep_inputs_and_partial_semantics(tmp_path, mode, detail):
    fixture, payload = _fixture(mode)
    version, decoded = ingest._decode_payload(payload)
    assert version == 11 and decoded == v11.decode(payload)
    source, *_ = make_source(tmp_path, fixture=fixture, observer='FRA', message_ids=('221',))
    selected = event_id(fixture, '221')
    query = battle_topic_query('B04', ['details', 'raw_text'], selected_event=selected)
    direct = source.read(query, source.context())
    details = direct['fields']['details']['value']
    assert details['name_source_candidate']['decoded']['value'] == ('Paris battle' if mode == 2 else 'BATTLE_OF_PARIS')
    assert details['name_sources']['capture_stage'] == 'entry_before_client_gate'
    assert details['name_sources']['complete'] is False
    assert direct['fields']['raw_text']['status'] == 'unknown'
    assert direct['source']['name'] == 'IBOW.v11'
    assert direct['source']['projection_version'] == 30
    assert 'payload_sha256' not in direct['source']
    assert direct['source']['hash_basis'] == 'observer_visible_battle_fields'
    service = InformationService(source, tmp_path / 'information.sqlite3')
    tools = InformationTools(service)
    try:
        item = service.query('name-source-query', queries=[query])['items'][0]
        assert item['fields']['details'] == direct['fields']['details']
        assert item['fields']['raw_text'] == dict(direct['fields']['raw_text'], unit='native_text_sections')
        report = tools.call('information_manage_report', dict(request_id='name-source-report',
            operation='create', config=dict(name='name source report', detail=detail,
                queries=[battle_topic_query('B04', ['details', 'raw_text'])])))['report']
        tools.call('information_manage_subscription', dict(request_id='name-source-event',
            operation='create', config=dict(name='name source event', kind='event',
                report_id=report['id'], enabled=True,
                binding=dict(session_id=fixture['provenance']['session_id'], observer='FRA',
                    game_version='1.37.4', game_sha256=GAME_SHA256),
                event=dict(types=['battle_observation']))))
        delivered = tools.call('information_tick', {"view": "full"})['results']
        assert len(delivered) == 1 and delivered[0]['event']['event_id'] == selected
        assert delivered[0]['items'][0]['fields'] == item['fields']
        assert delivered[0]['complete'] is False
        if detail == 'brief':
            view = present_result(delivered[0])['items'][0]['presentation']['battle_text']
            assert view['status'] == 'known'
            assert view['is_native_raw_text'] is view['complete'] is False
            assert '[Line1]' in view['text']
            assert view['sections'][0]['source_path'] == '/line1'
            selected_report = tools.call('information_manage_report', dict(request_id='battle-text-selected',
                operation='create', config=dict(name='selected battle text', detail='brief', queries=[query])))['report']
            queried = tools.call('information_query', dict(view="full", request_id='battle-text-query',
                report_id=selected_report['id']))
            assert present_result(queried)['items'][0]['presentation']['battle_text'] == view
            stored = tools.call('information_get_result', {"view": "full", 'result_id': delivered[0]['result_id']})
            assert 'presentation' not in stored['items'][0]
            assert stored['items'][0]['fields'] == item['fields']
        else:
            assert 'presentation' not in delivered[0]['items'][0]
    finally:
        service.close()
    if detail == 'brief':
        reopened = InformationService(source, tmp_path / 'information.sqlite3')
        try:
            listed = InformationTools(reopened).call('information_list_results', {"view": "full"})['results']
            restored = next(result for result in listed if result['result_id'] == delivered[0]['result_id'])
            assert present_result(restored)['items'][0]['presentation']['battle_text'] == view
            assert restored['event'] == delivered[0]['event']
        finally:
            reopened.close()


def test_v11_pinned_plugin_preserves_sources_and_qualifies_pre_assignment_value(tmp_path):
    fixture, _ = _fixture(2)
    source, *_ = make_source(tmp_path, fixture=fixture, observer='FRA')
    details = source.poll_events(source.context(), None)['events'][0]['payload']['battle_fields']['details']['value']
    assert details['name_sources']['text_fields']['global_name']['status'] == 'known'
    candidate = details['name_source_candidate']
    assert candidate['decoded']['value'] == 'Paris battle'
    assert candidate['value_stage'] == 'plugin_pre_assignment_text'
    assert candidate['native_assignment_verified'] is False


def test_v11_nonparticipant_gets_no_battle_or_name_inputs(tmp_path):
    fixture, _ = _fixture()
    source, *_ = make_source(tmp_path, fixture=fixture, observer='XYZ', observer_ref=_full_ref('XYZ'))
    assert source.poll_events(source.context(), None)['events'] == []


def test_body_candidate_does_not_mix_name_prefix_and_body_languages():
    decoded = _with_synthetic_sources(prefix=b'BATTLE_OF_', global_name=b'PARIS', owner=b'')
    decoded['native_text']['text_fields']['title_helper_candidate'].update(status='unknown', state='unknown', raw_hex='')
    decoded['name_sources']['text_fields']['language'] = _field(b'l_french')
    candidate = project_body_candidate(decoded)
    assert candidate['status'] == 'unknown'
    assert candidate['reason'] == 'BODY_CANDIDATE_NAME_LANGUAGE_MISMATCH'


@pytest.mark.parametrize('mutation', ['identity', 'trailing', 'nested_version'])
def test_v11_ingest_rejects_malformed_new_envelope(mutation):
    _, raw = _fixture()
    payload = bytearray(raw)
    if mutation == 'identity':
        payload[20 + struct.unpack_from('<I', payload, 6)[0]] ^= 1
    elif mutation == 'nested_version':
        payload[14:16] = (11).to_bytes(2, 'little')
    else:
        payload += b'\0'
    with pytest.raises(ingest.RawIngestError, match='v11_decode_failed'):
        ingest._decode_payload(bytes(payload))
