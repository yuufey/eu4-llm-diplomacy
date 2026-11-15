"""Pinned two-pass diplomat-capacity capture using the shared read-only owner."""
from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

from . import foreign_country_memory as _backend
from . import foreign_quality_capture as _base
from . import foreign_technology as _technology
from . import foreign_technology_capture as _owner
from . import diplomats_total_memory as _memory

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = 'information.diplomats_total_capture.v1'
PROFILE_FILE = Path(__file__).with_name('profiles')/'diplomats-total-memory-1374-v3.json'
PROFILE_SHA256 = 'c71cc1eb9146c8ea0c17a43d5e6ce080da44fadf577c146cf3c2d9047317704b'
PROFILE_ID = 'diplomats-total-memory-1374'
PROFILE_VERSION = 3
FIELDS = _memory.FIELDS


def _load_profile():
    parent = _base._load_profile()
    if not 0 < PROFILE_FILE.stat().st_size <= 256*1024:
        raise ValueError('DIPLOMATS_TOTAL_PROFILE_SIZE')
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError('DIPLOMATS_TOTAL_PROFILE_PIN')
    profile = json.loads(raw)
    if (profile.get('profile_id') != PROFILE_ID or profile.get('profile_version') != PROFILE_VERSION
            or profile.get('executable', {}).get('sha256') != _owner.EXE_SHA256
            or profile.get('base_profile', {}).get('sha256') != _base.PROFILE_SHA256
            or profile.get('code_guards', [])[:len(parent['code_guards'])] != parent['code_guards']):
        raise ValueError('DIPLOMATS_TOTAL_PROFILE_BUILD_OR_PARENT')
    for record in profile['source_evidence'] + profile['layout_dependencies']:
        path = (ROOT/record['path']).resolve()
        path.relative_to(ROOT)
        if path.stat().st_size != record['bytes'] or _owner._sha(path) != record['sha256']:
            raise ValueError('DIPLOMATS_TOTAL_PROFILE_DEPENDENCY')
    return profile


def _read_backend(reader, base, country):
    if country != 'FRA':
        raise ValueError('DIPLOMATS_TOTAL_SCOPE')
    def admission(read, module, scan, observer, target):
        gate = _owner._bound_admission(read, module, scan, observer, target)
        if not isinstance(gate, Mapping) or gate.get('observer_nonplayer_role', {}).get('verified') is not True:
            gate = deepcopy(dict(gate)) if isinstance(gate, Mapping) else {}
            gate.update(status='unknown', admitted=None, reason='OBSERVER_NONPLAYER_ROLE_UNVERIFIED')
        return gate
    return _backend.read_two_pass(reader, base, 'FRA', ['FRA'], FIELDS,
                                  read_fields=_memory.read_fields, admission_reader=admission)


def _observe(reader, base, country, profile):
    return _owner._observe(reader, base, country, profile, backend_reader=_read_backend)


def capture(installation, *, observer='FRA'):
    if observer != 'FRA':
        raise ValueError('DIPLOMATS_TOTAL_OBSERVER_SCOPE')
    return _owner._capture_common(installation, 'FRA', observer=observer, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile, observe=_observe, allow_observer_target=True)


def validate_capture(report, context, creation):
    return _owner._validate_capture_common(report, context, creation, 'FRA', schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile, observe=_observe,
        allow_observer_target=True, require_access=True)


def project_fields(report):
    if (not isinstance(report, Mapping) or report.get('schema') != SCHEMA
            or report.get('profile_sha256') != PROFILE_SHA256 or report.get('completed') is not True
            or report.get('status') != 'observed' or report.get('observation', {}).get('stable') is not True):
        raise ValueError('DIPLOMATS_TOTAL_CAPTURE_NOT_VALIDATED')
    item = _technology._backend_item(report, 'FRA')
    for phase in ('pass1', 'pass2'):
        gate = item['admission_by_pass'][phase]
        if (gate.get('status') != 'known' or gate.get('admitted') is not True
                or gate.get('observer_nonplayer_role', {}).get('verified') is not True):
            raise ValueError('DIPLOMATS_TOTAL_PUBLICATION_GATE')
    field = item.get('fields', {}).get(_memory.FIELD)
    if not isinstance(field, Mapping):
        return {'diplomats_total': {'status': 'unknown', 'reason': 'DIPLOMATS_TOTAL_FIELD_UNSTABLE'}}
    if field.get('status') != 'known':
        reason = field.get('reason')
        if not isinstance(reason, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', reason):
            reason = 'DIPLOMATS_TOTAL_FIELD_UNKNOWN'
        return {'diplomats_total': {'status': 'unknown', 'reason': reason}}
    if item.get('field_consistency', {}).get(_memory.FIELD, {}).get('status') != 'stable':
        return {'diplomats_total': {'status': 'unknown', 'reason': 'DIPLOMATS_TOTAL_FIELD_UNSTABLE'}}
    expected = {'unit': _memory.UNIT, 'scale': 1000, 'period': 'current', 'partial': True,
                'complete': False, 'basis': _memory.BASIS, 'value_origin': _memory.VALUE_ORIGIN}
    value, raw_hex = field.get('value'), field.get('raw_hex')
    if (type(value) is not int or not -(1<<31) <= value < (1<<31)
            or type(field.get('raw')) is not int or field['raw'] != value
            or not isinstance(raw_hex, str) or not re.fullmatch(r'[0-9a-f]{8}', raw_hex)
            or int.from_bytes(bytes.fromhex(raw_hex), 'little', signed=True) != value
            or any(type(field.get(key)) is not type(want) or field.get(key) != want for key, want in expected.items())):
        raise ValueError('DIPLOMATS_TOTAL_FIELD_INVALID')
    return {'diplomats_total': {'status': 'known', 'value': value, 'raw': value,
                                     'raw_hex': raw_hex, **expected}}
