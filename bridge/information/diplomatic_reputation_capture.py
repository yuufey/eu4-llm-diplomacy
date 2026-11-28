"""Pinned two-pass reputation capture using the shared read-only owner."""
from collections.abc import Mapping
from copy import deepcopy
from functools import partial
import hashlib
import json
from pathlib import Path
import re

from work.document_paths import resolve_repo_path

from . import foreign_country_memory as _backend
from . import foreign_quality_capture as _base
from . import foreign_technology as _technology
from . import foreign_technology_capture as _owner
from . import diplomatic_reputation_memory as _memory

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = 'information.diplomatic_reputation_capture.v1'
PROFILE_FILE = Path(__file__).with_name('profiles')/'diplomatic-reputation-memory-1374-v2.json'
PROFILE_SHA256 = '9449d3f449d472e081976aae29666b4dbd7156687f47027e5876a25cf2cb29b4'
PROFILE_ID = 'diplomatic-reputation-memory-1374'
FIELDS = _memory.FIELDS


def _load_profile():
    parent = _base._load_profile()
    if not 0 < PROFILE_FILE.stat().st_size <= 256*1024:
        raise ValueError('DIPLOMATIC_REPUTATION_PROFILE_SIZE')
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError('DIPLOMATIC_REPUTATION_PROFILE_PIN')
    profile = json.loads(raw)
    if (profile.get('profile_id') != PROFILE_ID or profile.get('profile_version') != 2
            or profile.get('executable', {}).get('sha256') != _owner.EXE_SHA256
            or profile.get('base_profile', {}).get('sha256') != _base.PROFILE_SHA256
            or profile.get('code_guards', [])[:len(parent['code_guards'])] != parent['code_guards']):
        raise ValueError('DIPLOMATIC_REPUTATION_PROFILE_BUILD_OR_PARENT')
    for record in profile['source_evidence'] + profile['layout_dependencies']:
        path = resolve_repo_path(ROOT, record['path']).resolve()
        path.relative_to(ROOT)
        # The pinned profile retains the historical Python source references.
        # Current layout and instruction bytes are verified independently.
        if path.suffix == '.py':
            continue
        if path.stat().st_size != record['bytes'] or _owner._sha(path) != record['sha256']:
            raise ValueError('DIPLOMATIC_REPUTATION_PROFILE_DEPENDENCY')
    return profile


def _read_backend(reader, base, country):
    def admission(read, module, scan, observer, target):
        gate = _owner._bound_admission(read, module, scan, observer, target)
        return gate
    return _backend.read_two_pass(reader, base, country, [country], FIELDS,
        read_fields=partial(_memory.read_fields, observer=country), admission_reader=admission)


def _observe(reader, base, country, profile):
    return _owner._observe(reader, base, country, profile, backend_reader=_read_backend)


def capture(installation, *, observer='FRA'):
    return _owner._capture_common(installation, observer, observer=observer, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile, observe=_observe,
        allow_observer_target=True, observer_scoped=True)


def validate_capture(report, context, creation):
    observer = context.get('observer') if isinstance(context, Mapping) else None
    return _owner._validate_capture_common(report, context, creation, observer, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile, observe=_observe,
        allow_observer_target=True, require_access=True, observer_scoped=True)


def project_fields(report):
    if (not isinstance(report, Mapping) or report.get('schema') != SCHEMA
            or report.get('profile_sha256') != PROFILE_SHA256 or report.get('completed') is not True
            or report.get('status') != 'observed' or report.get('observation', {}).get('stable') is not True):
        raise ValueError('DIPLOMATIC_REPUTATION_CAPTURE_NOT_VALIDATED')
    item = _technology._backend_item(report, report['request']['observer'])
    for phase in ('pass1', 'pass2'):
        gate = item['admission_by_pass'][phase]
        if gate.get('status') != 'known' or gate.get('admitted') is not True:
            raise ValueError('DIPLOMATIC_REPUTATION_PUBLICATION_GATE')
    field = item.get('fields', {}).get(_memory.FIELD)
    if (not isinstance(field, Mapping)
            or item.get('field_consistency', {}).get(_memory.FIELD, {}).get('status') != 'stable'):
        return {'diplomatic_reputation': {'status': 'unknown', 'reason': 'DIPLOMATIC_REPUTATION_FIELD_UNSTABLE'}}
    if field.get('status') != 'known':
        reason = field.get('reason')
        if not isinstance(reason, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', reason):
            reason = 'DIPLOMATIC_REPUTATION_FIELD_UNKNOWN'
        return {'diplomatic_reputation': {'status': 'unknown', 'reason': reason}}
    expected = {'unit': _memory.UNIT, 'scale': 1000, 'period': 'current', 'partial': True,
                'complete': False, 'basis': _memory.BASIS, 'value_origin': _memory.VALUE_ORIGIN}
    value, raw_hex = field.get('value'), field.get('raw_hex')
    if (type(value) is not int or not -(1<<31) <= value < (1<<31)
            or type(field.get('raw')) is not int or field['raw'] != value
            or not isinstance(raw_hex, str) or not re.fullmatch(r'[0-9a-f]{8}', raw_hex)
            or int.from_bytes(bytes.fromhex(raw_hex), 'little', signed=True) != value
            or any(type(field.get(key)) is not type(want) or field.get(key) != want for key, want in expected.items())):
        raise ValueError('DIPLOMATIC_REPUTATION_FIELD_INVALID')
    return {'diplomatic_reputation': {'status': 'known', 'value': value, 'raw': value,
                                     'raw_hex': raw_hex, **expected}}
