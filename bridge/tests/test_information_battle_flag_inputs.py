"""Typed flag inputs over retained battle bases, with explicit synthetic extensions."""
from contextlib import closing
from copy import deepcopy
import hashlib
from pathlib import Path
import shutil
import struct
import subprocess

import pytest

from bridge.information import InformationService
from bridge.information.battle_display_composition import project_display_composition
from bridge.information.battle_flag_inputs import project_flag_inputs
from bridge.information.tools import InformationTools
from bridge.tests.test_information_battle_independent_line import fixture14
from bridge.tests.test_information_battle_text import _v4_container_frame, _v4_frame
from bridge.tests.test_information_battles import make_source, event_id, battle_topic_query
from work import information_battle_flag_inputs_wire as wire
from work import information_battle_independent_line_wire as v14
from work.ingest_information_battle_raw_live import _decode_payload

ROOT = Path(__file__).resolve().parents[2]


def _replace_template(frame, pairs, message_date=None):
    version, size = struct.unpack_from('<HI', frame, 4)
    base = frame[10:10 + size]
    if version == 4:
        if message_date is not None:
            return _v4_frame(base, native_date=message_date, pairs=pairs, auxiliary=b'message-only metadata')
        return _v4_container_frame(base, raw_word=0, raw_flag=0, pairs=pairs)
    replacement = _replace_template(base, pairs, message_date)
    return frame[:6] + struct.pack('<I', len(replacement)) + replacement + frame[10 + size:]


def fixture15(numeric=b'123', *, failed=False):
    fixture, _, base14 = fixture14(mode=2)
    base14 = _replace_template(base14, [(b'OURFLAG', b''), (b'ENEMYFLAG', b''), (b'OURFLAG', numeric)])
    decoded = v14.decode(base14)
    ref = decoded['context']['sides'][0]['participants']['full_refs'][0]
    snapshot = {'sequence': decoded['observation']['sequence'],
        'raw_date': decoded['observation']['result']['raw_date'], 'kind': 1,
        'state': 'unknown' if failed else 'known', 'failure': 5 if failed else 0,
        'entries': [] if failed else [
            {'pair_index': 0, 'side': 0, 'mode': 2, 'country_ref': ref, 'rebel_raw': 0},
            {'pair_index': 1, 'side': 1, 'mode': 3, 'country_ref': 0, 'rebel_raw': 77},
            {'pair_index': 2, 'side': 0, 'mode': 1, 'country_ref': 0, 'rebel_raw': 0}]}
    payload = wire.encode(base14, snapshot)
    fixture = deepcopy(fixture)
    fixture['payload_hex'] = payload.hex()
    fixture['provenance'].update(real_capture=False, synthetic_extension=True,
        source_mode='synthetic_typed_flag_inputs_over_retained_battle',
        payload_sha256=hashlib.sha256(payload).hexdigest())
    return fixture, base14, snapshot, payload


def test_country_rebel_and_numeric_requests_preserve_order_and_typed_sources():
    _, _, _, payload = fixture15()
    decoded = wire.decode(payload)
    original = deepcopy(decoded)
    projected = project_flag_inputs(decoded)
    ours, enemy = projected['controls']
    assert ours['status'] == enemy['status'] == 'known'
    country, number = ours['requests']
    ref = decoded['context']['sides'][0]['participants']['full_refs'][0]
    assert country['country_ref'] == f'{ref:016x}'
    assert country['virtual_setter_requests'][0]['vtable_offset'] == '0x218'
    assert country['virtual_setter_requests'][1]['vtable_offset'] == '0x1b0'
    assert [row['pair_index'] for row in ours['requests']] == [0, 2]
    assert number['requested_flag_id_u32'] == 123
    assert enemy['requests'][0]['rebel_flag_raw_u32'] == 77
    assert enemy['requests'][0]['requested_flag_id_u32'] == (~77) & 0xffffffff
    assert all(row['native_call_observed'] is row['runtime_widget_state_verified'] is False
               for control in projected['controls'] for row in control['requests'])
    assert all(control['list_reset_request']['vtable_offset'] == '0x278' for control in projected['controls'])
    composed = project_display_composition(decoded)
    assert 'control_input:OURFLAG' not in composed['remaining_gaps']
    assert 'control_input:ENEMYFLAG' not in composed['remaining_gaps']
    assert composed['full_display_complete'] is False
    assert decoded == original


@pytest.mark.parametrize('raw,expected', [(b'', 0xffffffff), (b'0', 0xffffffff),
    (b'-1', 0xfffffffe), (b' +12tail', 12), (b'-2147483648', 0x7fffffff)])
def test_numeric_flag_id_uses_the_existing_native_i32_prefix_model(raw, expected):
    _, _, _, payload = fixture15(raw)
    result = project_flag_inputs(wire.decode(payload))
    assert result['controls'][0]['requests'][1]['requested_flag_id_u32'] == expected


def test_non_ascii_numeric_prefix_retains_unknown_instead_of_an_image_id():
    _, _, _, payload = fixture15(b'\xff0')
    control = project_flag_inputs(wire.decode(payload))['controls'][0]
    assert control['status'] == 'partial'
    assert control['requests'][1]['reason'] == 'NON_ASCII_PREFIX_LOCALE_UNRESOLVED'


@pytest.mark.parametrize('mutation', ['foreign_side', 'incomplete_side', 'missing_entry', 'wrong_side', 'bad_identity'])
def test_unverified_or_mismatched_inputs_do_not_gain_a_known_flag_request(mutation):
    _, _, _, payload = fixture15()
    decoded = wire.decode(payload)
    if mutation == 'foreign_side':
        decoded['flag_inputs']['entries'][0]['country_ref'] = (
            decoded['context']['sides'][1]['participants']['full_refs'][0])
    elif mutation == 'incomplete_side':
        decoded['context']['sides'][0]['participants']['complete'] = False
    elif mutation == 'missing_entry':
        decoded['flag_inputs']['entries'].pop()
    elif mutation == 'wrong_side':
        decoded['flag_inputs']['entries'][0]['side'] = 1
    else:
        decoded['flag_inputs']['sequence'] += 1
    projected = project_flag_inputs(decoded)
    if mutation in ('foreign_side', 'incomplete_side'):
        request = projected['controls'][0]['requests'][0]
        assert request['status'] == 'unknown'
        assert 'country_ref' not in request
    else:
        assert projected['status'] == 'unknown'
    assert 'control_input:OURFLAG' in project_display_composition(decoded)['remaining_gaps']


def test_failed_flag_copy_preserves_base_fields_and_original_text_completeness():
    _, base14, _, payload = fixture15(failed=True)
    decoded = wire.decode(payload)
    assert decoded['message_template'] == v14.decode(base14)['message_template']
    assert project_flag_inputs(decoded)['reason'] == 'FLAG_INPUT_CAPTURE_FAILED'
    assert 'control_input:OURFLAG' in project_display_composition(decoded)['remaining_gaps']


def test_known_empty_and_naval_not_applicable_are_distinct_from_old_missing_inputs():
    from bridge.tests.test_information_battle_flag_inputs_wire import _naval_base14
    _, base14, snapshot, _ = fixture15()
    empty = _replace_template(base14, [(b'OTHER', b'')])
    snapshot['entries'] = []
    result = project_flag_inputs(wire.decode(wire.encode(empty, snapshot)))
    assert result['status'] == 'known'
    assert all(control['status'] == 'known' and control['requests'] == [] for control in result['controls'])
    naval = _naval_base14()
    decoded = v14.decode(naval)
    snapshot = {'sequence': decoded['observation']['sequence'],
        'raw_date': decoded['observation']['result']['raw_date'], 'kind': 2,
        'state': 'not_applicable', 'failure': 0, 'entries': []}
    assert project_flag_inputs(wire.decode(wire.encode(naval, snapshot)))['status'] == 'not_applicable'
    assert project_flag_inputs(v14.decode(base14))['reason'] == 'FLAG_INPUTS_NOT_CAPTURED'


def test_native_message_pairs_can_match_the_cleanup_flag_inputs_without_replacing_metadata():
    _, base14, snapshot, _ = fixture15()
    message = _replace_template(base14, [(b'OURFLAG', b''), (b'ENEMYFLAG', b''), (b'OURFLAG', b'123')],
                                message_date=snapshot['raw_date'])
    decoded = wire.decode(wire.encode(message, snapshot))
    assert decoded['message_template']['native_date'] == snapshot['raw_date']
    assert decoded['message_template']['auxiliary_text_hex'] == b'message-only metadata'.hex()
    assert project_flag_inputs(decoded)['controls'][0]['status'] == 'known'


@pytest.mark.parametrize('detail', ['full', 'brief'])
def test_flag_inputs_reach_query_event_full_read_dedup_and_reopen(tmp_path, detail):
    fixture, _, _, payload = fixture15()
    version, decoded = _decode_payload(payload)
    assert version == 15
    source, *_ = make_source(tmp_path, fixture, observer='FRA', message_ids=('282',))
    query = battle_topic_query('B04', ['details', 'raw_text'], selected_event=event_id(fixture, '282'))
    database = tmp_path / 'information.sqlite3'
    with closing(InformationService(source, database)) as service:
        tools = InformationTools(service)
        item = tools.call('information_query', {"view": "full", 'request_id': 'flags-query', 'queries': [query]})['items'][0]
        assert item['source']['projection_version'] == 32
        assert item['source']['hash_basis'] == 'observer_visible_battle_fields'
        assert 'payload_sha256' not in item['source']
        assert item['fields']['details']['value']['flag_inputs'] == project_flag_inputs(decoded)
        assert item['fields']['raw_text']['status'] == 'unknown'
        report = tools.call('information_manage_report', {'request_id': 'flags-report', 'operation': 'create',
            'config': {'name': 'Typed flags', 'detail': detail,
                       'queries': [battle_topic_query('B04', ['details', 'raw_text'])]}})['report']
        sub = tools.call('information_manage_subscription', {'request_id': 'flags-subscribe', 'operation': 'create',
            'config': {'name': 'Typed flags', 'kind': 'event', 'enabled': True, 'report_id': report['id'],
                       'event': {'types': ['battle_observation']}}})['subscription']
        delivered, = tools.call('information_tick', {"view": "full"})['results']
        full = tools.call('information_get_result', {"view": "full", 'result_id': delivered['result_id']})
        assert full['items'][0]['fields'] == item['fields']
        assert delivered['complete'] is False
        assert tools.call('information_tick', {"view": "full"})['results'] == []
        tools.call('information_manage_subscription', {'request_id': 'flags-cancel', 'operation': 'cancel',
            'subscription_id': sub['id'], 'expected_version': sub['version']})
    with closing(InformationService(source, database)) as reopened:
        assert reopened.get_result(full['result_id']) == full


def test_cpp_owned_copy_and_v15_encoding_agree_with_python(tmp_path):
    compiler = shutil.which('g++')
    if compiler is None:
        pytest.skip('requires the existing native fixture compiler')
    executable = tmp_path / 'flag-inputs.exe'
    built = subprocess.run([compiler, '-std=c++20', '-DINFORMATION_BATTLE_FLAG_INPUTS=1', '-Iwork/native',
        'work/native/tests/information-battle-owned-flag-inputs-test.cpp', '-o', str(executable)],
        cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert built.returncode == 0, built.stderr
    _, base14, _, _ = fixture15()
    base = tmp_path / 'base14.bin'
    target = tmp_path / 'output15.bin'
    base.write_bytes(base14)
    ref = v14.decode(base14)['context']['sides'][0]['participants']['full_refs'][0]
    ran = subprocess.run([str(executable), str(base), str(target), f'{ref:016x}'],
                         cwd=ROOT, capture_output=True, text=True, timeout=20)
    assert ran.returncode == 0, ran.stderr
    decoded = wire.decode(target.read_bytes())
    assert decoded['message_template'] == v14.decode(base14)['message_template']
    assert [entry['mode'] for entry in decoded['flag_inputs']['entries']] == [2, 3, 1]
    assert project_flag_inputs(decoded)['controls'][0]['status'] == 'known'
