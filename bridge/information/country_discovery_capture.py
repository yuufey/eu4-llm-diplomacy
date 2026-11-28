"""Bounded native exists/knows_country sweep for the configured observer."""
from __future__ import annotations

from functools import partial
import hashlib
import json
from pathlib import Path
import re

from . import foreign_technology_capture as _owner
from . import province_discovery_capture as _base
from . import country_discovery_memory_v2 as _memory


ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name('profiles') / 'country-discovery-memory-1374-v1-sampling-r1.json'
PROFILE_SHA256 = '136b6d6b49bd6e9d5f3aea71f2e6dd17dcf755c218c42934dbc89a5dbf22f19a'
PROFILE_ID = 'country-discovery-memory-1374'
SCHEMA = 'information.country_discovery_capture.v1'
INNER_SCHEMA = 'information.country_discovery_observer_snapshot.v1'
FIELD = 'discovered_countries'
_PRIOR = 'work/runtime/information-country-discovery-20261103-129-001/'
_STAGE = 'work/runtime/information-country-discovery-20261103-130-001/'
_SOURCES = frozenset((
    _PRIOR + 'rea-knows-predicate-c78900-001/evidence.json',
    _PRIOR + 'static-knows-trigger-methods-001/report.json',
    _PRIOR + 'static-knows-constructor-001/report.json',
    _STAGE + 'exists-token-001/report.json',
    _STAGE + 'exists-dispatch-001/report.json',
    _STAGE + 'static-exists-constructor-001/report.json',
    _STAGE + 'static-exists-predicate-001/report.json',
))
_DEPENDENCIES = frozenset('bridge/information/' + name for name in (
    'country_knowledge_memory.py', 'country_existence_memory.py',
    'country_discovery_memory.py', 'country_discovery_memory_v2.py'))
_REVIEWED_LAYOUT_REVISIONS = {
    'bridge/information/country_knowledge_memory.py': (
        13601, 'fe8a8b8663f01ebf90d59133132f7359717e32e019dc52cde6a2f65d3e779ab2'),
    'bridge/information/country_discovery_memory.py': (
        10610, 'd23ead4b495058e236b97101ab0d31797e990fa2a077cf94dc63d2bd26d50855'),
    'bridge/information/country_discovery_memory_v2.py': (
        798, '5672f0178f876736730b0f61a91449667220583ab6cee26848e52a7266dce98c'),
}
_EXTRA_GUARDS = {
    'country_knowledge_constructor': (0xBAC950, 0xBAC9C2),
    'country_knowledge_predicate': (0xC78900, 0xC78CCD),
    'country_exists_constructor': (0xBA6960, 0xBA69D4),
    'country_exists_predicate': (0xC107A0, 0xC10866),
}
_LAYOUT = {'country_exists_state_offset': '0x1344', 'country_kind_offset': '0x26',
    'exists_state_predicate': 'u32_nonzero_or_kind_7',
    'candidate_domain': 'ordinary_canonical_country_table_rows',
    'target_capital_offset': '0x14b0', 'capital_knowledge_flags_offset': '0x959',
    'capital_knowledge_bit': '0x10', 'observer': 'FRA', 'domain_complete': False}


def _load_profile():
    if not 0 < PROFILE_FILE.stat().st_size <= 256 * 1024:
        raise ValueError('COUNTRY_DISCOVERY_PROFILE_SIZE')
    data = PROFILE_FILE.read_bytes()
    if hashlib.sha256(data).hexdigest() != PROFILE_SHA256:
        raise ValueError('COUNTRY_DISCOVERY_PROFILE_PIN')
    profile = json.loads(data)
    if (profile.get('profile_id') != PROFILE_ID or profile.get('profile_version') != 1
            or profile.get('game_version') != '1.37.4' or profile.get('observer') != 'FRA'
            or profile.get('executable', {}).get('sha256') != _owner.EXE_SHA256
            or profile.get('layout') != _LAYOUT
            or profile.get('limits') != {'read_bytes': 524288, 'read_calls': 40000,
                'single_read_bytes': 65536, 'leaf_single_read_bytes': 1024}):
        raise ValueError('COUNTRY_DISCOVERY_PROFILE_BUILD_OR_LAYOUT')
    base_pin = profile.get('base_profile')
    if base_pin != {'path': _base.PROFILE_FILE.relative_to(ROOT).as_posix(), 'bytes': 139570,
                    'sha256': _base._LEGACY_PROFILE_SHA256}:
        raise ValueError('COUNTRY_DISCOVERY_BASE_PROFILE_PIN')
    base = _base._load_profile()
    for key, expected in (('source_evidence', _SOURCES), ('layout_dependencies', _DEPENDENCIES)):
        rows = profile.get(key)
        if (not isinstance(rows, list) or len(rows) != len(expected)
                or {x.get('path') for x in rows if isinstance(x, dict)} != expected):
            raise ValueError('COUNTRY_DISCOVERY_REQUIRED_SOURCES')
        for item in rows:
            try:
                _base._pin(item)
            except ValueError:
                revision = _REVIEWED_LAYOUT_REVISIONS.get(item['path'])
                if revision is None:
                    raise
                _base._pin(dict(item, bytes=revision[0], sha256=revision[1]))
    guards = profile.get('code_guards')
    base_count = len(base['code_guards'])
    if (not isinstance(guards, list) or guards[:base_count] != base['code_guards']
            or len(guards) != base_count + len(_EXTRA_GUARDS)):
        raise ValueError('COUNTRY_DISCOVERY_BASE_GUARDS_CHANGED')
    extras = guards[base_count:]
    if {row.get('name') for row in extras} != set(_EXTRA_GUARDS):
        raise ValueError('COUNTRY_DISCOVERY_REQUIRED_GUARDS')
    for row in extras:
        start, end = _EXTRA_GUARDS[row['name']]
        raw = bytes.fromhex(row['bytes'])
        if (row['rva'] != hex(start) or row['end_rva_exclusive'] != hex(end)
                or len(raw) != end - start or hashlib.sha256(raw).hexdigest() != row['sha256']):
            raise ValueError('COUNTRY_DISCOVERY_GUARD_RANGE_OR_HASH')
    return profile


def _observe(reader, module_base, country, profile, *, observer='FRA'):
    def backend(read, base, target):
        if target != observer:
            raise ValueError('COUNTRY_DISCOVERY_OBSERVER_SCOPE')
        options = {'observer_scoped': True} if observer != 'FRA' else {}
        result = _memory.read_two_pass(read, base, observer, **options)
        return {'schema': INNER_SCHEMA,
            'status': 'observed' if result['status'] == 'known' else 'unknown',
            'consistency': result['consistency'], 'targets': [{
                'admission_by_pass': {f'pass{i+1}': row['admission']
                    for i, row in enumerate(result.get('passes', []))},
                'country_discovery': result}]}
    return _owner._observe(reader, module_base, country, profile, backend_reader=backend)


def capture(installation, *, observer='FRA'):
    return _owner._capture_common(installation, observer, observer=observer, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile, observe=partial(_observe, observer=observer),
        allow_observer_target=True, observer_scoped=True)


def validate_capture(report, context, creation):
    observer = context.get('observer') if isinstance(context, dict) else None
    return _owner._validate_capture_common(report, context, creation, observer,
        schema=SCHEMA, profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=partial(_observe, observer=observer), allow_observer_target=True, require_access=True,
        observer_scoped=True)


def project_fields(report):
    raw = report['observation']['backend']['targets'][0]['country_discovery']
    scope = raw.get('scope', {})
    count, existing, values = (scope.get('candidate_count'), scope.get('existing_candidate_count'), raw.get('value'))
    if (raw.get('schema') != _memory.SCHEMA or raw.get('status') != 'known'
            or raw.get('observer') != report['request']['observer']
            or raw.get('complete') is not False or raw.get('domain_complete') is not False
            or scope.get('domain_complete') is not False
            or scope.get('country_existence_filter_applied') is not True
            or type(count) is not int or not 1 <= count <= 4096
            or type(existing) is not int or not 0 <= existing <= count
            or not isinstance(values, list) or len(values) > existing
            or any(type(tag) is not str or re.fullmatch('[A-Z0-9]{3}', tag) is None for tag in values)
            or values != sorted(set(values))):
        raise ValueError('COUNTRY_DISCOVERY_PROJECTION_INVALID')
    return {FIELD: {'status': 'known', 'value': list(values), 'candidate_count': count,
        'existing_candidate_count': existing, 'domain_complete': False,
        'country_existence_filter_applied': True}}


__all__ = ['capture', 'validate_capture', 'project_fields', 'PROFILE_FILE',
           'PROFILE_SHA256', 'SCHEMA', 'INNER_SCHEMA', 'FIELD']
