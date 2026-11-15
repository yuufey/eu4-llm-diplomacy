"""Strict FRA-only capture of native diplomatic relation arithmetic."""
from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

from work.document_paths import resolve_repo_path

from . import foreign_country_memory as _backend
from . import foreign_quality_capture as _base
from . import foreign_technology as _technology
from . import foreign_technology_capture as _owner
from . import relations_capacity_memory as _memory

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = 'information.relations_capacity_capture.v1'
PROFILE_FILE = Path(__file__).with_name('profiles') / 'relations-capacity-memory-1374-v2.json'
PROFILE_SHA256 = '2a1a0ab2bf07becb67834db085c29a25ccf43c84e1c599206bfc7df97d4bf7b8'
PROFILE_ID = 'relations-capacity-memory-1374'
FIELDS = ('N05.relations_count', 'N05.relations_limit')
_REASON = re.compile(r'[A-Z][A-Z0-9_]{0,127}\Z')
_HEX = re.compile(r'[0-9a-f]{8}\Z')
_BASIS = 'native_diplomatic_relation_trigger_arithmetic'
_ORIGIN = 'derived_from_copied_native_modifier_and_relation_caches'

def _load_profile():
    original = _base._load_profile()
    if not 0 < PROFILE_FILE.stat().st_size <= 256 * 1024:
        raise ValueError('RELATIONS_CAPACITY_PROFILE_SIZE')
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError('RELATIONS_CAPACITY_PROFILE_PIN')
    profile = json.loads(raw)
    if (profile.get('profile_id') != PROFILE_ID or profile.get('profile_version') != 2
            or profile.get('game_version') != '1.37.4'
            or profile.get('executable', {}).get('sha256') != _owner.EXE_SHA256
            or profile.get('base_profile', {}).get('sha256') != _base.PROFILE_SHA256
            or profile.get('code_guards', [])[:len(original['code_guards'])] != original['code_guards']):
        raise ValueError('RELATIONS_CAPACITY_PROFILE_BUILD_OR_PARENT')
    for item in profile['source_evidence'] + profile['layout_dependencies']:
        path = resolve_repo_path(ROOT, item['path']).resolve()
        path.relative_to(ROOT)
        if path.stat().st_size != item['bytes'] or _owner._sha(path) != item['sha256']:
            raise ValueError('RELATIONS_CAPACITY_PROFILE_DEPENDENCY')
    return profile

def _read_backend(reader, base, country):
    if country != 'FRA':
        raise ValueError('RELATIONS_CAPACITY_SCOPE')
    def admission(read, module_base, scan, observer, target):
        gate = _owner._bound_admission(read, module_base, scan, observer, target)
        if (not isinstance(gate, Mapping)
                or gate.get('observer_nonplayer_role', {}).get('verified') is not True):
            gate = deepcopy(dict(gate)) if isinstance(gate, Mapping) else {}
            gate.update(status='unknown', admitted=None, reason='OBSERVER_NONPLAYER_ROLE_UNVERIFIED')
        return gate
    return _backend.read_two_pass(reader, base, 'FRA', ['FRA'], FIELDS,
                                  read_fields=_memory.read_fields, admission_reader=admission)

def _observe(reader, base, country, profile):
    return _owner._observe(reader, base, country, profile, backend_reader=_read_backend)

def capture(installation, *, observer='FRA'):
    if observer != 'FRA':
        raise ValueError('RELATIONS_CAPACITY_OBSERVER_SCOPE')
    return _owner._capture_common(installation, 'FRA', observer=observer,
        schema=SCHEMA, profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe, allow_observer_target=True)

def validate_capture(report, context, creation):
    return _owner._validate_capture_common(report, context, creation, 'FRA',
        schema=SCHEMA, profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe, allow_observer_target=True, require_access=True)

def _unknown(reason):
    return {'status': 'unknown', 'reason': reason}

def project_fields(report):
    if (not isinstance(report, Mapping) or report.get('schema') != SCHEMA
            or report.get('profile_sha256') != PROFILE_SHA256 or report.get('completed') is not True
            or report.get('status') != 'observed' or report.get('observation', {}).get('stable') is not True):
        raise ValueError('RELATIONS_CAPACITY_CAPTURE_NOT_VALIDATED')
    item = _technology._backend_item(report, 'FRA')
    for phase in ('pass1', 'pass2'):
        gate = item['admission_by_pass'][phase]
        if (gate.get('status') != 'known' or gate.get('admitted') is not True
                or gate.get('observer_nonplayer_role', {}).get('verified') is not True):
            raise ValueError('RELATIONS_CAPACITY_PUBLICATION_GATE')
    output = {}
    for field_id in FIELDS:
        key = field_id.split('.', 1)[1]
        field = item.get('fields', {}).get(field_id)
        consistency = item.get('field_consistency', {}).get(field_id)
        if not isinstance(field, Mapping) or not isinstance(consistency, Mapping) or consistency.get('status') != 'stable':
            output[key] = _unknown('RELATIONS_CAPACITY_FIELD_UNSTABLE')
            continue
        if field.get('status') != 'known':
            reason = field.get('reason')
            output[key] = _unknown(reason if isinstance(reason, str) and _REASON.fullmatch(reason)
                                   else 'RELATIONS_CAPACITY_FIELD_UNKNOWN')
            continue
        value = field.get('value')
        raw_hex = field.get('raw_hex')
        expected = {'unit': 'diplomatic_relation', 'scale': 1, 'period': 'current',
                    'partial': True, 'complete': False, 'basis': _BASIS, 'value_origin': _ORIGIN}
        if (type(value) is not int or not -(1 << 31) <= value < (1 << 31)
                or type(field.get('raw')) is not int or field['raw'] != value
                or not isinstance(raw_hex, str) or not _HEX.fullmatch(raw_hex)
                or int.from_bytes(bytes.fromhex(raw_hex), 'little', signed=True) != value
                or any(type(field.get(k)) is not type(v) or field[k] != v for k, v in expected.items())):
            output[key] = _unknown('RELATIONS_CAPACITY_FIELD_INVALID')
            continue
        output[key] = {'status': 'known', 'value': value, 'raw': value, 'raw_hex': raw_hex, **expected}
    return output
