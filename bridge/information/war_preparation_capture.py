"""Capture bilateral preparation pledges with the shared country RPM owner."""
from copy import deepcopy
from functools import partial
import hashlib
import json
from pathlib import Path

from . import foreign_country_memory as _backend
from . import foreign_technology_capture as _owner
from . import war_preparation_memory as _leaf


PROFILE_FILE = Path(__file__).with_name('profiles') / 'war-preparation-memory-1374.json'
PROFILE_SHA256 = '9bb4cb4c3c373c74a1bba069ef42c68a3e0eb780c12054a20ae13937c0cfb436'
SCHEMA = 'information.war_preparation_capture.v1'


def _load_profile():
    if not 0 < PROFILE_FILE.stat().st_size <= 16384:
        raise ValueError('WAR_PREPARATION_PROFILE_SIZE')
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError('WAR_PREPARATION_PROFILE_PIN')
    profile = json.loads(raw)
    parent = _owner._load_profile()
    profile['code_guards'] = deepcopy(parent['code_guards']) + profile['code_guards']
    return profile


def _observe(reader, base, country, profile, *, observer='FRA'):
    current = {}

    def admission(read, module_base, scan, observer, target):
        gate = _owner._bound_admission(read, module_base, scan, observer, target)
        current['observer'] = _backend._binding(scan, observer)
        return gate

    def fields(limited, module_base, binding, requested):
        return _leaf.read_fields(limited, module_base, binding, requested,
                                 observer_binding=current['observer'])

    def backend(read, module_base, target):
        return _backend.read_two_pass(read, module_base, observer, [target], (_leaf.FIELD,),
                                      read_fields=fields, admission_reader=admission)

    return _owner._observe(reader, base, country, profile, backend_reader=backend)


def capture(installation, country, *, observer='FRA'):
    return _owner._capture_common(
        installation, country, observer=observer, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=partial(_observe, observer=observer), observer_scoped=True)


def validate_capture(report, context, creation, country):
    return _owner._validate_capture_common(
        report, context, creation, country, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=partial(_observe, observer=context.get('observer')),
        require_access=True, observer_scoped=True)
