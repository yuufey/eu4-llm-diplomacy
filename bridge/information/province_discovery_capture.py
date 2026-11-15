"""Own a current, bounded positive-index discovery sweep for logical FRA.

The existing province profile owns session/role and base layout evidence.
This independent profile adds the discovery word-count layout and guards;
the saved-snapshot parser and the established G02 reader remain separate.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from . import foreign_technology_capture as _owner
from . import province_state_capture as _base
from . import province_discovery_memory_v2 as _memory


ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name('profiles') / 'province-discovery-memory-1374-v1-sampling-r1.json'
PROFILE_SHA256 = '342be128660a95b0f633754770295deefd7226495ad5be515dd14ab473ba3298'
PROFILE_ID = 'province-discovery-memory-1374'
SCHEMA = 'information.province_discovery_capture.v1'
INNER_SCHEMA = 'information.province_discovery_observer_snapshot.v1'
FIELD = 'discovered_provinces'
_STAGE = 'work/runtime/information-live-discovery-20261103-127-001/'
_SOURCES = frozenset(_STAGE + name for name in (
    'rea-manager-c2fb0-001/evidence.json', 'rea-loop-73a300-001/evidence.json',
    'rea-bitset-helper-c62e0-001/evidence.json', 'rea-bitset-setter-a2ebf0-001/evidence.json',
    'static-manager-small-methods-001/attempt-002/report.json',
    'static-bitset-reallocation-001/report.json', 'source-findings-001.json'))
_DEPENDENCIES = frozenset('bridge/information/' + name for name in (
    'province_discovery_memory.py', 'province_discovery_memory_v2.py',
    'province_discovery_bitmap_memory.py'))
_EXTRA_GUARDS = {
    'discovery_positive_id_guard': (0xC2FB0, 0xC3035),
    'discovery_native_record_loop': (0x73A300, 0x73A7A1),
    'discovery_word_getter': (0xC62E0, 0xC62F9),
    'discovery_word_setter': (0xA2EBF0, 0xA2EC23),
    'discovery_word_storage_replace': (0xCF9F0, 0xCFA50),
    'discovery_word_storage_shrink': (0xCFA50, 0xCFAAC),
}
_LAYOUT = {'bitmap_offset': '0x5d8', 'vtable_rva': '0x1c57270',
    'pointer_offset': '0x5e0', 'capacity_words_offset': '0x5e8',
    'length_words_offset': '0x5ec', 'inline_offset': '0x5f0',
    'word_bytes': 4, 'word_bits': 32, 'bridge_max_capacity_words': 128,
    'record_stride': '0x2e10', 'province_domain': '1..count-1', 'domain_complete': False}


def _pin(item):
    if (not isinstance(item, dict) or not isinstance(item.get('path'), str)
            or type(item.get('bytes')) is not int or item['bytes'] < 0
            or not isinstance(item.get('sha256'), str)
            or re.fullmatch(r'[0-9a-f]{64}', item['sha256']) is None):
        raise ValueError('DISCOVERY_PROFILE_SOURCE_SHAPE')
    path = (ROOT / item['path']).resolve()
    path.relative_to(ROOT)
    if path.stat().st_size != item['bytes'] or _owner._sha(path) != item['sha256']:
        raise ValueError('DISCOVERY_PROFILE_SOURCE_CHANGED')
    return path


def _load_profile():
    if not 0 < PROFILE_FILE.stat().st_size <= 256 * 1024:
        raise ValueError('DISCOVERY_PROFILE_SIZE')
    data = PROFILE_FILE.read_bytes()
    if hashlib.sha256(data).hexdigest() != PROFILE_SHA256:
        raise ValueError('DISCOVERY_PROFILE_PIN')
    profile = json.loads(data)
    if (profile.get('profile_id') != PROFILE_ID or profile.get('profile_version') != 1
            or profile.get('game_version') != '1.37.4' or profile.get('observer') != 'FRA'
            or profile.get('executable', {}).get('sha256') != _owner.EXE_SHA256
            or profile.get('layout') != _LAYOUT
            or profile.get('limits') != {'read_bytes': 524288, 'read_calls': 40000,
                'single_read_bytes': 65536, 'leaf_single_read_bytes': 1024}):
        raise ValueError('DISCOVERY_PROFILE_BUILD_OR_LAYOUT')
    base_pin = profile.get('base_profile')
    if (_pin(base_pin) != _base.PROFILE_FILE.resolve()
            or base_pin['sha256'] != _base.PROFILE_SHA256):
        raise ValueError('DISCOVERY_BASE_PROFILE_PIN')
    base = _base._load_profile()
    for key, expected in (('source_evidence', _SOURCES), ('layout_dependencies', _DEPENDENCIES)):
        rows = profile.get(key)
        if (not isinstance(rows, list) or len(rows) != len(expected)
                or {x.get('path') for x in rows if isinstance(x, dict)} != expected):
            raise ValueError('DISCOVERY_REQUIRED_SOURCES')
        for item in rows:
            _pin(item)
    guards = profile.get('code_guards')
    base_count = len(base['code_guards'])
    if (not isinstance(guards, list) or guards[:base_count] != base['code_guards']
            or len(guards) != base_count + len(_EXTRA_GUARDS)):
        raise ValueError('DISCOVERY_BASE_GUARDS_CHANGED')
    extras = guards[base_count:]
    if {row.get('name') for row in extras} != set(_EXTRA_GUARDS):
        raise ValueError('DISCOVERY_REQUIRED_GUARDS')
    for row in extras:
        start, end = _EXTRA_GUARDS[row['name']]
        raw = bytes.fromhex(row['bytes'])
        if (row['rva'] != hex(start) or row['end_rva_exclusive'] != hex(end)
                or len(raw) != end - start or hashlib.sha256(raw).hexdigest() != row['sha256']):
            raise ValueError('DISCOVERY_GUARD_RANGE_OR_HASH')
    return profile


def _observe(reader, module_base, country, profile):
    def backend(read, base, target):
        if target != 'FRA':
            raise ValueError('DISCOVERY_OBSERVER_SCOPE')
        result = _memory.read_two_pass(read, base, 'FRA')
        return {'schema': INNER_SCHEMA,
            'status': 'observed' if result['status'] == 'known' else 'unknown',
            'consistency': result['consistency'], 'targets': [{
                'admission_by_pass': {f'pass{i+1}': row['admission']
                    for i, row in enumerate(result.get('passes', []))},
                'discovery': result}]}
    return _owner._observe(reader, module_base, country, profile, backend_reader=backend)


def capture(installation, *, observer='FRA'):
    return _owner._capture_common(installation, 'FRA', observer=observer, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile, observe=_observe,
        allow_observer_target=True)


def validate_capture(report, context, creation):
    return _owner._validate_capture_common(report, context, creation, 'FRA',
        schema=SCHEMA, profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe, allow_observer_target=True, require_access=True)


def project_fields(report):
    """Strip raw pointers and digests; validation/replay belongs to the owner."""
    raw = report['observation']['backend']['targets'][0]['discovery']
    scope = raw.get('scope', {})
    count, values = scope.get('candidate_count'), raw.get('value')
    if (raw.get('schema') != _memory.SCHEMA or raw.get('status') != 'known'
            or raw.get('complete') is not False or raw.get('domain_complete') is not False
            or scope.get('domain_complete') is not False
            or scope.get('bitmap_words_native_length_bounded') is not True
            or type(count) is not int or not 0 < count < 65536
            or not isinstance(values, list) or len(values) > count
            or any(type(pid) is not int or not 1 <= pid <= count for pid in values)
            or values != sorted(set(values))):
        raise ValueError('DISCOVERY_PROJECTION_INVALID')
    return {FIELD: {'status': 'known', 'value': list(values), 'candidate_count': count,
        'candidate_id_range': [1, count], 'domain_complete': False,
        'bitmap_words_native_length_bounded': True}}


__all__ = ['capture', 'validate_capture', 'project_fields', 'PROFILE_FILE',
           'PROFILE_SHA256', 'SCHEMA', 'INNER_SCHEMA', 'FIELD']
