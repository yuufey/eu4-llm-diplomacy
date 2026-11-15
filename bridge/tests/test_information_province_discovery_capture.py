"""Identity-bound discovery capture and replay, entirely synthetic memory."""
from copy import deepcopy
import hashlib
import json

import pytest

from bridge.information import province_discovery_capture as capture
from bridge.tests.test_information_province_discovery_memory_v2 import make_image, BASES
from bridge.tests.test_information_foreign_technology_capture import RecordingReader

BASE = BASES[0]
CREATION = 134381481521109200


@pytest.fixture(scope='module')
def profile():
    return capture._load_profile()


def bundle(profile, values=(True, False, True)):
    image = make_image(values)
    for guard in profile['code_guards']:
        image.put(BASE + int(guard['rva'], 16), bytes.fromhex(guard['bytes']))
    reader = RecordingReader(image)
    observation = capture._observe(reader, BASE, 'FRA', profile)
    identity = {'binding_verified': True, 'process_creation_filetime': CREATION,
        'process_path': 'synthetic-eu4.exe', 'process_path_sha256': capture._owner.EXE_SHA256}
    report = {'schema': capture.SCHEMA, 'status': 'observed', 'completed': True,
        'request': {'country': 'FRA', 'observer': 'FRA', 'creation_filetime': CREATION,
            'session_id': 'discovery-capture-test'}, 'profile_sha256': capture.PROFILE_SHA256,
        'identity': identity, 'identity_after': deepcopy(identity), 'module_base': hex(BASE),
        'observation': observation, 'raw_reads': reader.read_log,
        'cleanup': {'status': 'closed', 'closed': True, 'success': True}, 'errors': [],
        'access': {'read_only': True, 'native_function_invoked': False, 'writes': False,
            'UI_control': False, 'date_advance': False, 'save_or_reload': False,
            'limit_bytes': 524288, 'calls': reader.calls, 'bytes_requested': reader.bytes_requested}}
    context = {'observer': 'FRA', 'session_id': 'discovery-capture-test',
        'game_version': '1.37.4', 'game_sha256': capture._owner.EXE_SHA256,
        'game_date': observation['context_before']['game_date']}
    return report, context


@pytest.mark.parametrize('values,expected', [((True, False, True), [1, 3]), ((False, False), [])])
def test_strict_replay_and_projection_preserve_positive_membership_and_known_empty(profile, values, expected):
    report, context = bundle(profile, values)
    assert report['observation']['stable'] is True
    assert capture.validate_capture(report, context, CREATION) is True
    fields = capture.project_fields(report)
    assert fields == {'discovered_provinces': {'status': 'known', 'value': expected,
        'candidate_count': len(values), 'candidate_id_range': [1, len(values)],
        'domain_complete': False, 'bitmap_words_native_length_bounded': True}}
    assert '0x' not in json.dumps(fields)


@pytest.mark.parametrize('kind', ['word', 'header', 'result', 'identity', 'context', 'access', 'cleanup'])
def test_tampering_fails_strict_replay(profile, kind):
    report, context = bundle(profile)
    if kind in ('word', 'header'):
        label = 'province_bitmap.word_u32' if kind == 'word' else 'province_bitmap.header'
        row = next(row for row in report['raw_reads'] if row['label'] == label)
        data = bytearray.fromhex(row['raw_hex']); data[-1] ^= 1; row['raw_hex'] = data.hex()
    elif kind == 'result':
        report['observation']['backend']['targets'][0]['discovery']['value'] = []
    elif kind == 'identity':
        report['identity_after']['process_creation_filetime'] += 1
    elif kind == 'context':
        context['game_date'] += 24
    elif kind == 'access':
        report['access']['calls'] += 1
    elif kind == 'cleanup':
        report['cleanup']['closed'] = False
    assert capture.validate_capture(report, context, CREATION) is False


@pytest.mark.parametrize('value', [[True], [0], [4], [1, 1], [3, 1], None])
def test_projection_rejects_invalid_ids_without_copying_private_fields(profile, value):
    report, _ = bundle(profile)
    raw = report['observation']['backend']['targets'][0]['discovery']
    raw['value'] = value
    with pytest.raises(ValueError, match='DISCOVERY_PROJECTION_INVALID'):
        capture.project_fields(report)


@pytest.mark.parametrize('key,value', [('domain_complete', True), ('candidate_count', True),
                                     ('bitmap_words_native_length_bounded', False)])
def test_projection_rejects_false_completeness_or_scope_claims(profile, key, value):
    report, _ = bundle(profile)
    report['observation']['backend']['targets'][0]['discovery']['scope'][key] = value
    with pytest.raises(ValueError, match='DISCOVERY_PROJECTION_INVALID'):
        capture.project_fields(report)


def test_profile_requires_current_bitmap_reader_pin(monkeypatch):
    original = capture._owner._sha
    monkeypatch.setattr(capture._owner, '_sha', lambda path:
        '0' * 64 if path.name == 'province_discovery_memory_v2.py' else original(path))
    with pytest.raises(ValueError, match='DISCOVERY_PROFILE_SOURCE_CHANGED'):
        capture._load_profile()


def test_profile_rejects_changed_extra_guard_range_even_with_recomputed_profile_hash(tmp_path, monkeypatch, profile):
    changed = deepcopy(profile)
    changed['code_guards'][-1]['end_rva_exclusive'] = '0x1'
    path = tmp_path / 'changed-profile.json'
    data = json.dumps(changed).encode();path.write_bytes(data)
    monkeypatch.setattr(capture, 'PROFILE_FILE', path)
    monkeypatch.setattr(capture, 'PROFILE_SHA256', hashlib.sha256(data).hexdigest())
    with pytest.raises(ValueError, match='DISCOVERY_GUARD_RANGE_OR_HASH'):
        capture._load_profile()


def test_capture_rejects_player_or_other_observer_before_opening_process(tmp_path):
    report = capture.capture(tmp_path / 'missing-installation.json', observer='POR')
    assert report['status'] == 'unknown' and report['cleanup']['status'] == 'not_opened'
    assert report['errors'][0]['reason'] == 'FOREIGN_TECH_REQUEST_SCOPE'


def test_failed_native_nonplayer_role_withdraws_observation_before_province_words(profile):
    from bridge.tests.test_information_province_state_memory import WORLD
    image = make_image((True,))
    image.put_i32(WORLD + 0xa60, 2)
    for guard in profile['code_guards']:
        image.put(BASE + int(guard['rva'], 16), bytes.fromhex(guard['bytes']))
    reader = RecordingReader(image)
    observed = capture._observe(reader, BASE, 'FRA', profile)
    assert observed['stable'] is False
    assert observed['backend']['targets'][0]['discovery']['status'] == 'unknown'
    assert not any(row['label'].startswith('province_bitmap.') for row in reader.read_log)
