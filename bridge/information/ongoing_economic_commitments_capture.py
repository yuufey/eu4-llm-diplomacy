"""Capture current subsidies and reparations in one bound country-pair read."""
from copy import deepcopy
from functools import partial
import hashlib

from . import economic_commitments as _subsidies
from . import economic_commitments_capture as _subsidy_capture
from . import reparations_commitments as _reparations
from . import reparations_commitments_capture as _reparations_capture
from . import foreign_country_memory as _backend
from . import foreign_technology_capture as _owner


SCHEMA = 'information.ongoing_economic_commitments_capture.v1'
PROFILE_SHA256 = hashlib.sha256((_subsidy_capture.PROFILE_SHA256
                                + _reparations_capture.PROFILE_SHA256).encode('ascii')).hexdigest()
FAMILIES = ('subsidies', 'reparations')
FIELDS = tuple(family + '.' + field for family in FAMILIES
               for field in ('economic_support', 'expiry'))


def _load_profile():
    subsidy = _subsidy_capture._load_profile()
    reparations = _reparations_capture._load_profile()
    profile = deepcopy(subsidy)
    guards = {row['rva']: row for row in subsidy['code_guards']}
    for row in reparations['code_guards']:
        if row['rva'] in guards and guards[row['rva']]['bytes'] != row['bytes']:
            raise ValueError('ECONOMIC_COMMITMENTS_GUARD_CONFLICT')
        guards[row['rva']] = row
    profile['code_guards'] = list(guards.values())
    return profile


def _observe(reader, base, country, profile, *, observer='FRA', installation=None, observer_binding=None):
    current = {}

    def admission(read, module_base, scan, observer, target):
        current['observer'] = scan['requested'][observer]
        return _owner._bound_admission(read, module_base, scan, observer, target)

    def fields(limited, module_base, binding, requested):
        world = int.from_bytes(limited.read(module_base + 0x233FE58, 8,
                                            'ongoing_commitments.world'), 'little')
        now = int.from_bytes(limited.read(world + 0x1DD0, 4,
                                          'ongoing_commitments.current_date'), 'little', signed=True)
        result = {}
        for family, leaf in (('subsidies', _subsidies), ('reparations', _reparations)):
            values = leaf.read_fields(limited, module_base, current['observer'], binding,
                                      leaf.FIELDS, observed_date=now)
            result.update({family + '.' + name.removeprefix('R07.'): value
                           for name, value in values.items()})
        return {name: result[name] for name in requested}

    def backend(read, module_base, target):
        return _backend.read_two_pass(read, module_base, observer, [target], FIELDS,
                                      read_fields=fields, admission_reader=admission)

    return _subsidy_capture._observe_guarded(reader, base, country, profile, backend_reader=backend,
        installation=installation, observer_binding=observer_binding)


def capture(installation, country, *, observer='FRA'):
    return _owner._capture_common(installation, country, observer=observer, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=partial(_observe, observer=observer, installation=installation), observer_scoped=True)


def validate_capture(report, context, creation, country):
    if report.get('schema') == _subsidy_capture.SCHEMA:
        return _subsidy_capture.validate_capture(report, context, creation, country)
    return _owner._validate_capture_common(report, context, creation, country, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=partial(_observe, observer=context.get('observer'), observer_binding=_subsidy_capture._capture_binding(report)),
        require_access=True, observer_scoped=True)


def _merge_lists(fields):
    rows = [deepcopy(row) for field in fields if field.get('status') == 'known'
            for row in field.get('value', [])]
    complete = all(field.get('status') == 'known' and field.get('complete') is True for field in fields)
    if complete or rows:
        return {'status': 'known', 'value': rows, 'complete': complete, 'partial': not complete}
    return {'status': 'unknown', 'reason': 'CURRENT_ECONOMIC_COMPONENT_UNAVAILABLE'}


def project_fields(report):
    if report.get('schema') == _subsidy_capture.SCHEMA:
        return _subsidy_capture.project_fields(report)
    raw = report['observation']['backend']['targets'][0]['fields']
    supports = [raw[family + '.economic_support'] for family in FAMILIES]
    value = {key: deepcopy(child) for field in supports if field.get('status') == 'known'
             for key, child in field['value'].items() if key != 'active_payment_obligations'}
    active = _merge_lists([field.get('value', {}).get('active_payment_obligations', {})
                           if field.get('status') == 'known' else field for field in supports])
    value['active_payment_obligations'] = active
    support = {'status': 'known', 'value': value, 'complete': False}
    if all(field.get('status') != 'known' for field in supports):
        support = {'status': 'unknown', 'reason': 'CURRENT_ECONOMIC_COMPONENTS_UNAVAILABLE'}
    return {'economic_support': support,
            'expiry': _merge_lists([raw[family + '.expiry'] for family in FAMILIES])}
