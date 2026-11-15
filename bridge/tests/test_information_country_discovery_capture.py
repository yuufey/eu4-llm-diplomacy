"""Identity-bound country discovery capture and replay on synthetic memory."""
from copy import deepcopy
import hashlib
import json

import pytest

from bridge.information import country_discovery_capture as capture
from bridge.tests.test_information_country_discovery_memory_v2 import make_image
from bridge.tests.test_information_foreign_technology_capture import RecordingReader
from bridge.tests.test_information_province_state_memory import BASES, WORLD


BASE = BASES[0]
CREATION = 134381481521109200
SESSION_ID = 'country-discovery-capture-test'


@pytest.fixture(scope='module')
def profile():
    return capture._load_profile()


def _observe(profile, image=None, source=None):
    if image is None:
        image, _bindings = make_image()
    _write_profile_guards(image, profile)
    reader = RecordingReader(image if source is None else source)
    observation = capture._observe(reader, BASE, 'FRA', profile)
    identity = {'binding_verified': True, 'process_creation_filetime': CREATION,
        'process_path': 'synthetic-eu4.exe', 'process_path_sha256': capture._owner.EXE_SHA256}
    observed = observation['stable'] is True
    report = {'schema': capture.SCHEMA, 'status': 'observed' if observed else 'unknown',
        'completed': observed,
        'request': {'country': 'FRA', 'observer': 'FRA', 'creation_filetime': CREATION,
            'session_id': SESSION_ID},
        'profile_sha256': capture.PROFILE_SHA256,
        'identity': deepcopy(identity), 'identity_after': deepcopy(identity),
        'module_base': hex(BASE), 'observation': observation, 'raw_reads': reader.read_log,
        'cleanup': {'status': 'closed', 'closed': True, 'success': True}, 'errors': [],
        'access': {'read_only': True, 'native_function_invoked': False, 'writes': False,
            'UI_control': False, 'date_advance': False, 'save_or_reload': False,
            'limit_bytes': 524288, 'calls': reader.calls,
            'bytes_requested': reader.bytes_requested}}
    context = {'observer': 'FRA', 'session_id': SESSION_ID, 'game_version': '1.37.4',
        'game_sha256': capture._owner.EXE_SHA256,
        'game_date': observation['context_before']['game_date']}
    return report, context, reader


def _write_profile_guards(image, profile):
    for guard in profile['code_guards']:
        image.put(BASE + int(guard['rva'], 16), bytes.fromhex(guard['bytes']))


def _raw_discovery(report):
    return report['observation']['backend']['targets'][0]['country_discovery']


def test_strict_replay_and_projection_expose_only_existing_known_countries(profile):
    report, context, _reader = _observe(profile)

    assert report['observation']['stable'] is True
    assert capture.validate_capture(report, context, CREATION) is True
    fields = capture.project_fields(report)
    assert fields == {'discovered_countries': {'status': 'known',
        'value': ['DEN', 'FRA', 'SWE'], 'candidate_count': 4,
        'existing_candidate_count': 4, 'country_existence_filter_applied': True,
        'domain_complete': False}}
    assert set(fields) == {'discovered_countries'}
    assert set(fields['discovered_countries']) == {'status', 'value', 'candidate_count',
        'existing_candidate_count', 'country_existence_filter_applied', 'domain_complete'}
    assert '0x' not in json.dumps(fields)


def test_false_existence_skips_unreadable_capital_and_is_not_projected(profile):
    image, bindings = make_image()
    den = int(bindings['DEN']['country_pointer'], 16)
    image.put_i32(den + 0x1344, 0)
    image.put_u64(den + 0x14b0, 0)
    report, _context, reader = _observe(profile, image=image)

    result = _raw_discovery(report)
    assert result['status'] == 'known'
    assert result['value'] == ['FRA', 'SWE']
    assert result['scope']['country_existence_filter_applied'] is True
    assert result['scope']['candidate_count'] == 4
    assert result['scope']['existing_candidate_count'] == 3
    for current in result['passes']:
        den_row = next(row for row in current['candidates'] if row['tag'] == 'DEN')
        assert den_row['exists'] is False and den_row['knowledge_evaluated'] is False
    assert not any(row['address'] == hex(den + 0x14b0) for row in reader.read_log)


def test_missing_existence_read_withdraws_collection_instead_of_becoming_empty(profile):
    image, bindings = make_image()
    missing_address = int(bindings['DEN']['country_pointer'], 16) + 0x1344

    class MissingExistenceRead:
        def read(self, address, size, label):
            if address == missing_address and label == 'country_existence.dword_u32':
                return b''
            return image.read(address, size, label)

    report, _context, _reader = _observe(profile, image=image, source=MissingExistenceRead())
    result = _raw_discovery(report)
    assert result['status'] == 'unknown'
    assert 'value' not in result
    with pytest.raises(ValueError, match='COUNTRY_DISCOVERY_PROJECTION_INVALID'):
        capture.project_fields(report)


@pytest.mark.parametrize('kind', ['exists', 'bitmap', 'result', 'identity', 'context',
                                  'access', 'cleanup'])
def test_tampering_fails_strict_replay(profile, kind):
    report, context, _reader = _observe(profile)
    if kind in ('exists', 'bitmap'):
        label = 'country_existence.dword_u32' if kind == 'exists' else 'province_bitmap.word_u32'
        row = next(row for row in report['raw_reads'] if row['label'] == label)
        data = bytearray.fromhex(row['raw_hex'])
        data[-1] ^= 1
        row['raw_hex'] = data.hex()
    elif kind == 'result':
        _raw_discovery(report)['value'] = []
    elif kind == 'identity':
        report['identity_after']['process_creation_filetime'] += 1
    elif kind == 'context':
        context['game_date'] += 24
    elif kind == 'access':
        report['access']['calls'] += 1
    elif kind == 'cleanup':
        report['cleanup']['closed'] = False
    assert capture.validate_capture(report, context, CREATION) is False


def test_profile_requires_current_country_reader_pin(monkeypatch):
    original = capture._owner._sha
    monkeypatch.setattr(capture._owner, '_sha', lambda path:
        '0' * 64 if path.name == 'country_discovery_memory_v2.py' else original(path))
    with pytest.raises(ValueError, match='DISCOVERY_PROFILE_SOURCE_CHANGED'):
        capture._load_profile()


def test_profile_rejects_changed_extra_guard_range_even_with_recomputed_hash(
        tmp_path, monkeypatch, profile):
    changed = deepcopy(profile)
    changed['code_guards'][-1]['end_rva_exclusive'] = '0x1'
    path = tmp_path / 'changed-country-profile.json'
    data = json.dumps(changed).encode()
    path.write_bytes(data)
    monkeypatch.setattr(capture, 'PROFILE_FILE', path)
    monkeypatch.setattr(capture, 'PROFILE_SHA256', hashlib.sha256(data).hexdigest())
    with pytest.raises(ValueError, match='COUNTRY_DISCOVERY_GUARD_RANGE_OR_HASH'):
        capture._load_profile()


def test_wrong_observer_capture_is_rejected_before_opening_process(tmp_path):
    report = capture.capture(tmp_path / 'missing-installation.json', observer='POR')
    assert report['status'] == 'unknown' and report['cleanup']['status'] == 'not_opened'
    assert report['errors'][0]['reason'] == 'FOREIGN_TECH_REQUEST_SCOPE'


def test_failed_nonplayer_role_stops_before_existence_or_knowledge_reads(profile):
    image, _bindings = make_image()
    image.put_i32(WORLD + 0xA60, 2)
    report, _context, reader = _observe(profile, image=image)

    assert report['observation']['stable'] is False
    assert _raw_discovery(report)['status'] == 'unknown'
    assert not any(row['label'].startswith(('country_existence.', 'country_knowledge.'))
                   for row in reader.read_log)
