"""Retained battle bases with explicitly synthetic independent formatter output."""
from contextlib import closing
from copy import deepcopy
import hashlib
from pathlib import Path
import shutil
import subprocess

import pytest

from bridge.information import InformationService
from bridge.information.battle_body_candidate import project_body_candidate
from bridge.information.battle_display_context import project_display_context
from bridge.information.battle_independent_line import project_independent_line
from bridge.information.tools import InformationTools
from bridge.information.presentation import present_result
from bridge.tests.test_information_battle_body_candidate import _decoded_v7
from bridge.tests.test_information_battle_name_sources_integration import _fixture as fixture11
from bridge.tests.test_information_battle_outcome_text_wire import _known_snapshot
from bridge.tests.test_information_battle_outcome_tail_wire import _snapshot as snapshot13
from bridge.tests.test_information_battles import battle_topic_query, event_id, make_source
from work import information_battle_end_state_wire as v9
from work import information_battle_retreat_wire as v10
from work import information_battle_name_sources_wire as v11
from work import information_battle_outcome_text_wire as v12
from work import information_battle_outcome_tail_wire as v13
from work import information_battle_independent_line_wire as v14
from work.ingest_information_battle_raw_live import _decode_payload

ROOT = Path(__file__).resolve().parents[2]


def fixture14(mode=1, failed=False):
    fixture, base11 = fixture11(mode)
    if mode == 2:
        # Current producer builds do not invoke the helper. Keep the same
        # event inputs while removing the old synthetic helper observation.
        source = v11.decode(base11)['name_sources']
        _, base7 = _decoded_v7(title_state='unknown')
        base10 = v10.encode(v9.encode(base7, {'state': 'unknown'}), {'state': 'unknown'})
        base11 = v11.encode(base10, source)
    base12 = v12.encode(base11, _known_snapshot(base11))
    base13 = v13.encode(base12, snapshot13(base12))
    decoded = v13.decode(base13)
    body = project_body_candidate(decoded)
    assert body['status'] == 'known'
    context = project_display_context(decoded)
    snapshot = {'sequence': context['sequence'], 'raw_date': context['raw_date'],
                'kind': context['battle_kind'], 'state': 'unknown' if failed else 'known',
                'failure': 8 if failed else 0, 'transform_mode': 0 if failed else mode,
                'flags': 7 if failed else 15, 'text_fields': {}}
    values = {name: bytes.fromhex(context['text_fields'][name]['raw_hex'])
              for name in ('language', 'definition_key', 'body_template')}
    values.update(name_input=bytes.fromhex(body['raw_hex']), output=b'Native formatted battle')
    for name, value in values.items():
        snapshot['text_fields'][name] = {'state': 'unknown' if failed else 'known',
                                         'length': 0 if failed else len(value),
                                         'raw_hex': '' if failed else value.hex()}
    payload = v14.encode(base13, snapshot)
    fixture = deepcopy(fixture)
    fixture['payload_hex'] = payload.hex()
    fixture['provenance'].update(real_capture=False, synthetic_extension=True,
        source_mode='synthetic_independent_formatter_output_over_retained_base',
        payload_sha256=hashlib.sha256(payload).hexdigest())
    return fixture, base13, payload


@pytest.mark.parametrize('mode', [1, 2])
def test_independent_output_keeps_input_derivation_and_popup_limitations(mode):
    _, _, payload = fixture14(mode)
    version, decoded = _decode_payload(payload)
    assert version == 14
    result = project_independent_line(decoded)
    assert result['status'] == 'known'
    assert result['text'] == 'Native formatted battle'
    assert result['native_formatter_invoked'] is result['native_output_copied'] is True
    assert result['native_line1_verified'] is result['is_native_raw_text'] is result['complete'] is False
    assert result['input_value_stage'] == ('plugin_pre_assignment_text' if mode == 2
                                            else 'derived_original_helper_inputs')


@pytest.mark.parametrize('damage', ['name_input', 'language', 'identity', 'mode', 'bad_text'])
def test_mismatched_inputs_and_invalid_text_stay_unknown(damage):
    _, _, payload = fixture14()
    decoded = v14.decode(payload)
    source = decoded['independent_line']
    if damage in ('name_input', 'language', 'bad_text'):
        key = 'output' if damage == 'bad_text' else damage
        raw = b'\x10' if damage == 'bad_text' else b'other'
        source['text_fields'][key].update(raw_hex=raw.hex(), length=len(raw))
    elif damage == 'mode':
        source['transform_mode'] = 2
    else:
        source['sequence'] += 1
    assert project_independent_line(decoded)['status'] == 'unknown'


def test_naval_wire_and_projection_keep_the_retained_base_and_derived_input():
    path = ROOT / 'bridge/tests/fixtures/information_battle_independent_line_base13_naval.bin'
    base13 = path.read_bytes()
    assert hashlib.sha256(base13).hexdigest() == 'e14e57ff77c205e1265743d68e8344fb26e0523fbce31d2f6aceaef1a28288bf'
    decoded = v13.decode(base13)
    assert decoded['context']['kind'] == 2
    context = project_display_context(decoded)
    candidate = project_body_candidate(decoded)
    assert candidate['status'] == 'known'
    source = {'sequence': context['sequence'], 'raw_date': context['raw_date'], 'kind': 2,
              'state': 'known', 'failure': 0, 'flags': 15,
              'transform_mode': decoded['name_sources']['transform_mode'], 'text_fields': {}}
    values = {name: context['text_fields'][name]['raw_hex']
              for name in ('language', 'definition_key', 'body_template')}
    # The IFMT output is synthetic. The embedded 2816-byte naval record is
    # the retained batch231 sample, without any new native execution claim.
    values.update(name_input=candidate['raw_hex'], output=candidate['raw_hex'])
    for name, raw_hex in values.items():
        source['text_fields'][name] = {'state': 'known', 'length': len(raw_hex) // 2, 'raw_hex': raw_hex}
    payload = v14.encode(base13, source)
    version, parsed = _decode_payload(payload)
    assert version == 14 and parsed['native_text'] == decoded['native_text']
    result = project_independent_line(parsed)
    assert result['status'] == 'known' and result['battle_kind'] == 2
    assert result['text'] == candidate['decoded']['value']
    assert result['native_name_handoff_verified'] is False


@pytest.mark.parametrize('mode', [1, 2])
@pytest.mark.parametrize('detail', ['full', 'brief'])
def test_query_event_full_read_dedup_and_reopen_preserve_independent_output(tmp_path, mode, detail):
    fixture, _, _ = fixture14(mode)
    source, _, _, _, _ = make_source(tmp_path, fixture, observer='FRA', message_ids=('278',))
    query = battle_topic_query('B04', ['details', 'raw_text'], selected_event=event_id(fixture, '278'))
    database = tmp_path / 'information.sqlite3'
    with closing(InformationService(source, database)) as service:
        tools = InformationTools(service)
        direct = tools.call('information_query', {"view": "full", 'request_id': 'independent-direct', 'queries': [query]})
        item = direct['items'][0]
        fields = item['fields']
        output = fields['details']['value']['independent_line']
        assert output['status'] == 'known'
        assert fields['details']['value']['display_composition']['line1']['text'] == output['text']
        assert fields['raw_text']['status'] == 'unknown'
        assert item['source']['projection_version'] == 31
        assert item['source']['name'] == 'IBOW.v14'
        assert 'payload_sha256' not in item['source']
        topic = next(topic for topic in source.catalog() if topic['topic_id'] == 'B04')
        assert topic['fields']['details']['independent_line']['capture_wire'] == 14
        report = tools.call('information_manage_report', {'request_id': 'independent-report', 'operation': 'create',
            'config': {'name': 'independent battle line', 'detail': detail,
                       'queries': [battle_topic_query('B04', ['details', 'raw_text'])]}})['report']
        subscription = tools.call('information_manage_subscription', {
            'request_id': 'independent-subscribe', 'operation': 'create',
            'config': {'name': 'independent battle line', 'kind': 'event', 'report_id': report['id'],
                       'enabled': True, 'event': {'types': ['battle_observation']}}})['subscription']
        results = tools.call('information_tick', {"view": "full"})['results']
        assert len(results) == 1
        result = results[0]
        full = tools.call('information_get_result', {"view": "full", 'result_id': result['result_id']})
        assert full['items'][0]['fields'] == fields
        if detail == 'brief':
            brief = present_result(result)
            assert '[Line1] Native formatted battle' in brief['items'][0]['presentation']['battle_text']['text']
        assert tools.call('information_tick', {"view": "full"})['results'] == []
        tools.call('information_manage_subscription', {'request_id': 'independent-cancel', 'operation': 'cancel',
            'subscription_id': subscription['id'], 'expected_version': subscription['version']})
    with closing(InformationService(source, database)) as reopened:
        assert reopened.get_result(result['result_id']) == full


def test_failed_independent_render_preserves_existing_name_and_other_fields(tmp_path):
    fixture, base13, _ = fixture14(failed=True)
    source, _, _, _, _ = make_source(tmp_path, fixture, observer='FRA', message_ids=('278',))
    query = battle_topic_query('B04', ['details'], selected_event=event_id(fixture, '278'))
    result = source.read(query, source.context())
    details = result['fields']['details']['value']
    assert details['independent_line']['status'] == 'unknown'
    assert details['independent_line']['native_formatter_invoked'] is True
    assert details['display_composition']['line1']['text'] == project_body_candidate(v13.decode(base13))['decoded']['value']


def test_cpp_owned_output_encodes_the_identical_protocol_and_projects(tmp_path):
    compiler = shutil.which('g++')
    if compiler is None:
        pytest.skip('requires the existing native fixture compiler')
    executable = tmp_path / 'independent-line.exe'
    command = [compiler, '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror', '-fno-exceptions', '-fno-rtti',
               '-I', 'work/candidates/information-battle-format-input-1374',
               'work/native/tests/information-battle-owned-independent-line-test.cpp', '-o', str(executable)]
    compiled = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert compiled.returncode == 0, compiled.stderr
    _, base13, _ = fixture14()
    base_path, output_path = tmp_path / 'base13.bin', tmp_path / 'native14.bin'
    base_path.write_bytes(base13)
    result = subprocess.run([str(executable), str(base_path), str(output_path)],
                            cwd=ROOT, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    decoded = v14.decode(output_path.read_bytes())
    assert decoded['native_text'] == v13.decode(base13)['native_text']
    projected = project_independent_line(decoded)
    assert projected['status'] == 'known'
    assert projected['text'] == 'BATTLE_OF_PARIS'
