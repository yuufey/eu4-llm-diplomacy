"""Batch the existing foreign war-exhaustion scalar and admission readers."""
from copy import deepcopy
import hashlib

from . import foreign_country_memory as _countries
from . import foreign_pressure as _pressure
from . import foreign_technology_capture as _owner
from .trade_income import _context_reason, _session_binding


SCHEMA = 'information.war_pressure_capture.v1'
PROFILE_SHA256 = hashlib.sha256(
    (_pressure._LEGACY_PROFILE_SHA256 + SCHEMA).encode('ascii')).hexdigest()
MAX_TARGETS = _countries.MAX_TARGETS


def _normalize(countries):
    countries = list(countries)
    if (not countries or len(countries) > MAX_TARGETS or len(set(countries)) != len(countries)
            or any(not isinstance(tag, str) or _pressure._TAG.fullmatch(tag) is None
                   or tag == 'FRA' for tag in countries)):
        raise ValueError('WAR_PRESSURE_BATCH_SCOPE')
    return countries


def _observe_for(countries):
    def observe(reader, base, anchor, profile):
        def fields(read, module_base, binding, selected):
            return {_pressure.FIELD: _pressure.read_war_exhaustion(
                read, binding, profile['pressure_scalar'])}

        def backend(read, module_base, target):
            return _countries.read_two_pass(read, module_base, 'FRA', countries,
                fields=[_pressure.FIELD], admission_reader=_owner._bound_admission,
                read_fields=fields)

        return _owner._observe(reader, base, anchor, profile, backend_reader=backend)
    return observe


def capture(installation, countries):
    countries = _normalize(countries)
    report = _owner._capture_common(installation, countries[0], observer='FRA',
        schema=SCHEMA, profile_sha256=PROFILE_SHA256,
        load_profile=_pressure._load_legacy_profile, observe=_observe_for(countries))
    report['request']['countries'] = countries
    return report


def validate_capture(report, context, creation, countries):
    try:
        countries = _normalize(countries)
    except (TypeError, ValueError):
        return False
    if not isinstance(report, dict) or report.get('request', {}).get('countries') != countries:
        return False
    return _owner._validate_capture_common(report, context, creation, countries[0],
        schema=SCHEMA, profile_sha256=PROFILE_SHA256,
        load_profile=_pressure._load_legacy_profile, observe=_observe_for(countries),
        require_access=True)


def read_countries(source, countries, context):
    """Return each member independently, retaining the existing injected reader."""
    countries = list(dict.fromkeys(countries))
    values = {}

    def individual(batch):
        for country in batch:
            sample = source.read({'topic': 'F04', 'object': {'type': 'country', 'country': country},
                                  'fields': ['war_exhaustion'], 'parameters': {}}, context)
            values[country] = deepcopy(sample['fields']['war_exhaustion'])

    if source.capture is not None:
        individual(countries)
        return values
    installation, creation, reason = _session_binding(source.base_source)
    reason = reason or _context_reason(context, 'FRA')
    if reason:
        return {country: {'status': 'unknown', 'reason': reason} for country in countries}
    for start in range(0, len(countries), MAX_TARGETS):
        batch = countries[start:start + MAX_TARGETS]
        try:
            report = capture(installation, batch)
            if not validate_capture(report, context, creation, batch):
                raise ValueError('WAR_PRESSURE_CAPTURE_INVALID')
            values.update({target['tag']: deepcopy(target['fields'][_pressure.FIELD])
                           for target in report['observation']['backend']['targets']})
        except Exception:
            # A missing binding or failed batch must not erase other members.
            individual(batch)
    return values
