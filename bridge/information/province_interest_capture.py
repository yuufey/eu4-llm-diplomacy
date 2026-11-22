"""Own a guarded, replayable readonly G01 province-membership observation."""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

from . import foreign_technology_capture as _owner
from . import province_state_capture as _base
from . import province_interest_memory as _fields

ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name('profiles') / 'province-interest-memory-1374-v1-r2-sampling-r1.json'
PROFILE_SHA256 = '099b7941bf630168f2eb13ad7a89db8c03428e9f9fe7b2b376ea42edeb48a8aa'
SCHEMA = 'information.province_interest_capture.v1'
INNER_SCHEMA = 'information.province_interest_observer_snapshot.v1'
FIELDS = ('G01.cores', 'G01.claims')
TAG = re.compile(r'[A-Z0-9]{3}\Z')
REASON = re.compile(r'[A-Za-z0-9_:-]{1,160}\Z')


def _load_profile():
    # Preserve the complete immutable identity, role and discovery dependency
    # chain; the new profile adds the two separately audited membership paths.
    _base._load_profile()
    if not 0 < PROFILE_FILE.stat().st_size <= 256 * 1024:
        raise ValueError('PROVINCE_INTEREST_PROFILE_SIZE')
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError('PROVINCE_INTEREST_PROFILE_PIN')
    profile = json.loads(raw)
    if (profile.get('profile_id') != 'province-interest-memory-1374'
            or profile.get('profile_version') != 1
            or profile.get('game_version') != '1.37.4'
            or profile.get('executable', {}).get('sha256') != _owner.EXE_SHA256):
        raise ValueError('PROVINCE_INTEREST_PROFILE_BUILD')
    for item in profile['source_evidence'] + profile['layout_dependencies']:
        if not _base._matches_reviewed_layout(item):
            raise ValueError('PROVINCE_INTEREST_PROFILE_DEPENDENCY')
    return profile


def _observe_for(province_id, observer='FRA'):
    def observe(reader, base, country, profile):
        if country != observer or not _base._valid_id(province_id):
            raise ValueError('PROVINCE_INTEREST_OBSERVER_SCOPE')

        def backend(read, module_base, observer_country):
            if observer_country != observer:
                raise ValueError('PROVINCE_INTEREST_OBSERVER_SCOPE')
            return _fields.read_two_pass(read, module_base, province_id,
                                         observer=observer, fields=FIELDS, observer_scoped=True)
        return _owner._observe(reader, base, country, profile, backend_reader=backend)
    return observe


def capture(installation: Path, province_id: int, *, observer='FRA'):
    if not _base._valid_id(province_id) or not isinstance(observer, str) or not TAG.fullmatch(observer):
        raise ValueError('PROVINCE_INTEREST_REQUEST_SCOPE')
    inner = _owner._capture_common(
        installation, observer, observer=observer, schema=INNER_SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe_for(province_id, observer), allow_observer_target=True, observer_scoped=True)
    return {'schema': SCHEMA, 'observer': observer,
            'object': {'type': 'province', 'province_id': province_id}, 'capture': inner}


def validate_capture(report, context, creation, province_id):
    if not isinstance(context, Mapping):
        return False
    observer = context.get('observer')
    if (not isinstance(observer, str) or not TAG.fullmatch(observer)
            or not _base._valid_id(province_id) or not isinstance(report, dict)
            or set(report) != {'schema', 'observer', 'object', 'capture'}
            or report.get('schema') != SCHEMA or report.get('observer') != observer
            or not _owner._same(report.get('object'), {'type': 'province', 'province_id': province_id})):
        return False
    return _owner._validate_capture_common(
        report['capture'], context, creation, observer, schema=INNER_SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe_for(province_id, observer), allow_observer_target=True,
        require_access=True, observer_scoped=True)


def project_fields(report):
    """Whitelist the already validated private result; never copy raw pointers."""
    backend = report['capture']['observation']['backend']
    targets = backend['targets']
    observer = report.get('observer')
    if (len(targets) != 1 or not isinstance(observer, str)
            or not TAG.fullmatch(observer) or backend['observer']['tag'] != observer):
        raise ValueError('PROVINCE_INTEREST_PROJECTION_SCOPE')
    target = targets[0]
    for phase in ('pass1', 'pass2'):
        gate = target['admission_by_pass'][phase]
        discovery = target['discovery_by_pass'][phase]
        if (gate.get('status') != 'known' or gate.get('admitted') is not True
                or gate.get('observer_nonplayer_role', {}).get('verified') is not True
                or discovery.get('status') != 'known' or discovery.get('value') is not True):
            raise ValueError('PROVINCE_INTEREST_PUBLICATION_GATE')
    output = {}
    for field in FIELDS:
        name = field.split('.', 1)[1]
        value = target['fields'].get(field)
        projected = {'status': 'unknown', 'reason': 'NATIVE_MEMBERSHIP_NOT_ESTABLISHED',
                     'unit': 'country_tag', 'scale': 1, 'period': 'current',
                     'complete': False, 'basis': 'native_province_membership_after_positive_actor_discovery',
                     'value_origin': 'copied_native_canonical_country_references'}
        if isinstance(value, Mapping) and value.get('status') == 'known':
            tags = value.get('value')
            if (isinstance(tags, list) and len(tags) <= _fields.MAX_MEMBERS
                    and all(isinstance(tag, str) and TAG.fullmatch(tag) for tag in tags)
                    and len(tags) == len(set(tags))):
                projected.update(status='known', value=sorted(tags))
                projected.pop('reason')
        elif isinstance(value, Mapping):
            reason = value.get('reason')
            if isinstance(reason, str) and REASON.fullmatch(reason) and '0x' not in reason.lower():
                projected['reason'] = reason
        output[name] = projected
    return deepcopy(output)


__all__ = ['capture', 'validate_capture', 'project_fields']
