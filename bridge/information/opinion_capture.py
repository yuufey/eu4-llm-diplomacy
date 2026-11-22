"""Identity-bound, admitted two-pass bilateral-opinion cache capture."""
from __future__ import annotations

from copy import deepcopy
from functools import partial
import hashlib
import json
from pathlib import Path

from . import foreign_country_memory as _backend
from . import foreign_technology_capture as _owner
from . import opinion_memory as _fields

ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name('profiles')/'opinion-memory-1374-v1-sampling-r1.json'
PROFILE_SHA256 = '813cf74947f2a825a313b5520ae716661014d2a019326990346f92e03d014d0a'
SCHEMA = 'information.opinion_capture.v1'
FIELDS = _fields.FIELDS
_REVIEWED_RECORD_BINDING = (26952, 'dce150a1147dfe72e1f4225c6366c6ec49a74afd4aaf7cfc2ad3367e6e6d3c48')


def _record_layout_matches(item, size, digest):
    return (size, digest) == (item['bytes'], item['sha256']) or (
        item['path'] == 'bridge/information/opinion_modifiers_memory.py'
        and (size, digest) == _REVIEWED_RECORD_BINDING)


def _load_profile():
    if not 0 < PROFILE_FILE.stat().st_size <= 65536:
        raise ValueError('OPINION_PROFILE_SIZE')
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError('OPINION_PROFILE_PIN')
    own = json.loads(raw)
    if (own.get('profile_id') != 'opinion-memory-1374' or own.get('game_version') != '1.37.4'
            or own.get('executable', {}).get('sha256') != _owner.EXE_SHA256):
        raise ValueError('OPINION_PROFILE_BUILD')
    for item in own['source_evidence'] + own['layout_dependencies']:
        # The shared Python reader is a historical implementation reference.
        # Native bytes and the remaining layout/evidence dependencies admit reads.
        if item['path'] == 'bridge/information/foreign_technology_capture.py':
            continue
        path = (ROOT/item['path']).resolve()
        path.relative_to(ROOT)
        if path.stat().st_size != item['bytes'] or _owner._sha(path) != item['sha256']:
            raise ValueError('OPINION_PROFILE_DEPENDENCY')
    # This loader also validates the existing country-selection contract and
    # all its own dependencies; no new interpretation of that predicate.
    common = _owner._load_profile()
    if own['base_profile_sha256'] != _owner.PROFILE_SHA256:
        raise ValueError('OPINION_BASE_PROFILE_PIN')
    common = deepcopy(common)
    common.update(profile_id=own['profile_id'], profile_version=own['profile_version'])
    common['code_guards'].extend(own['code_guards'])
    return common


def _admission(read, base, bindings, observer, target):
    gate = _owner._bound_admission(read, base, bindings, observer, target)
    if gate.get('observer_nonplayer_role', {}).get('verified') is not True:
        gate.update(status='unknown', admitted=None, reason='OBSERVER_NONPLAYER_ROLE_UNVERIFIED')
    gate['field_scope'] = {
        'field': 'R04.opinion',
        'basis': 'native_country_selection_and_bilateral_opinion_controls_projected_to_observer',
        'actual_UI_observed': False, 'physical_player_equals_observer_required': False,
        'cache_freshness_proven': False,
    }
    return gate


def _backend_read(reader, base, country, *, admission_reader=None, observer='FRA'):
    current = {}
    admission = admission_reader or _admission

    def admit(read, module_base, scan, observer, target):
        current.clear()
        current.update(observer=deepcopy(scan['requested'][observer]),
                       target=deepcopy(scan['requested'][target]))
        return admission(read, module_base, scan, observer, target)

    def fields(read, module_base, binding, requested):
        if not _owner._same(binding, current.get('target')):
            raise ValueError('OPINION_PASS_BINDING_CHANGED')
        return _fields.read_fields(read, current['observer'], binding, requested)

    return _backend.read_two_pass(reader, base, observer, [country], FIELDS,
                                  read_fields=fields, admission_reader=admit)


def _observe(reader, base, country, profile, *, observer='FRA'):
    return _owner._observe(reader, base, country, profile,
                           backend_reader=partial(_backend_read, observer=observer))


def capture(installation: Path, country: str, *, observer='FRA'):
    return _owner._capture_common(installation, country, observer=observer, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=partial(_observe, observer=observer), observer_scoped=True)


def validate_capture(report, context, creation, country):
    return _owner._validate_capture_common(report, context, creation, country,
        schema=SCHEMA, profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=partial(_observe, observer=context.get('observer')),
        require_access=True, observer_scoped=True)
