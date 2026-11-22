"""W03 country-level occupation and blockade summaries from existing sources."""
from copy import deepcopy
import hashlib
import json
import re

from . import country_occupation_memory as _occupation
from . import foreign_country_memory as _countries
from . import foreign_pressure as _pressure
from . import foreign_technology_capture as _owner
from . import province_modifier_sources_capture as _province_sources
from .model import InformationError
from .sources import _result, _source_info
from .trade_income import NativeTradeIncomeSource, _observer_context_reason, _session_binding


SCHEMA = 'information.war_territory_capture.v1'
PROFILE_SHA256 = hashlib.sha256((_pressure._OCCUPATION_PROFILE_SHA256
    + _province_sources.PROFILE_SHA256).encode('ascii')).hexdigest()
FIELDS = ('occupations', 'blockades')
_TAG = re.compile(r'[A-Z0-9]{3}\Z')


def _load_profile():
    profile = _pressure._load_occupation_profile()
    raw = _province_sources.PROFILE_FILE.read_bytes()
    if (len(raw) > 256 * 1024
            or hashlib.sha256(raw).hexdigest() != _province_sources.PROFILE_SHA256):
        raise ValueError('WAR_BLOCKADE_PROFILE_PIN')
    existing = json.loads(raw)
    layout = existing['layout']['province_modifier_sources']
    profile['blockade'] = {'flags_offset': int(layout['province_flags_offset'], 0),
                           'mask': int(layout['blockade_mask'], 0)}
    guard = next(row for row in existing['code_guards'] if row['name'] == 'direct_source_callback20')
    profile['code_guards'].append(deepcopy(guard))
    return profile


def _observe_for(fields, observer='FRA'):
    def observe(reader, base, country, profile):
        bindings, rows = {}, {}

        def admission(read, module_base, scan, observer_tag, target):
            bindings.update(scan['requested'])
            rows.clear()
            rows.update({row['fullref']: row for row in scan['rows'] if row['fullref']})
            return _owner._bound_admission(read, module_base, scan, observer_tag, target)

        def read_fields(read, module_base, binding, selected):
            summary = _occupation.read_occupation(read, module_base, binding, bindings[observer],
                rows, profile['occupation'], include_occupation='occupations' in fields,
                blockade_spec=profile['blockade'] if 'blockades' in fields else None)
            blockades = summary.pop('blockades', None)
            values = {'occupations': summary, 'blockades': blockades}
            return {'W03.' + name: values[name] for name in fields}

        def backend(read, module_base, target):
            return _countries.read_two_pass(read, module_base, observer, [target],
                fields=['W03.' + name for name in fields], admission_reader=admission,
                read_fields=read_fields)

        return _owner._observe(reader, base, country, profile, backend_reader=backend)
    return observe


def capture(installation, country, *, fields, observer='FRA'):
    report = _owner._capture_common(installation, country, observer=observer, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe_for(fields, observer), allow_observer_target=True, observer_scoped=True)
    report['request']['fields'] = list(fields)
    return report


def validate_capture(report, context, creation, country, fields):
    if (not isinstance(context, dict) or not isinstance(report, dict)
            or report.get('request', {}).get('fields') != fields):
        return False
    return _owner._validate_capture_common(report, context, creation, country,
        schema=SCHEMA, profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe_for(fields, context.get('observer')), allow_observer_target=True,
        require_access=True, observer_scoped=True)


class NativeWarTerritorySource(NativeTradeIncomeSource):
    def catalog(self):
        return [{'topic_id': 'W03', 'catalog_ids': ['W03'], 'title': '占领、封锁与战损',
            'status': 'available', 'fields': {name: {
                'coverage': 'available', 'complete': True, 'period': 'current',
                'source': __name__ + '.capture', 'unit': 'province_counts',
                'description': description} for name, description in zip(FIELDS, (
                    '所选国家已发现领土的受占领数量及控制国汇总',
                    '所选国家已发现领土的受封锁省份数量'))},
            'object_types': ['country'], 'observer_roles': [], 'observer_scope': [],
            'context_scope': 'visible_scope', 'visibility': 'visible_scope',
            'supported_versions': ['1.37.4'], 'triggers': ['query', 'periodic'],
            'parameters': {'type': 'object', 'properties': {}, 'additionalProperties': False},
            'source': type(self).__name__}]

    def validate_query(self, query, context=None):
        if (not isinstance(query, dict) or query.get('topic') != 'W03'
                or set(query) - {'topic', 'object', 'fields', 'parameters'}):
            raise InformationError('invalid_parameters', 'Expected a W03 query')
        obj, fields = query.get('object'), query.get('fields')
        if (not isinstance(obj, dict) or set(obj) != {'type', 'country'}
                or obj.get('type') != 'country' or not isinstance(obj.get('country'), str)
                or not _TAG.fullmatch(obj['country'])):
            raise InformationError('invalid_object', 'W03 territory requires a country tag')
        if (not isinstance(fields, list) or not fields
                or any(not isinstance(name, str) or name not in FIELDS for name in fields)
                or len(set(fields)) != len(fields)):
            raise InformationError('invalid_fields', 'Unsupported W03 territory fields')
        if query.get('parameters', {}) != {}:
            raise InformationError('invalid_parameters', 'W03 territory has no extra parameters')
        if context is not None and (not isinstance(context, dict)
                or not isinstance(context.get('observer'), str) or not _TAG.fullmatch(context['observer'])):
            raise InformationError('observer_scope_mismatch', 'W03 requires a bound observer country')
        return deepcopy(query) | {'parameters': {}}

    def read(self, query, context=None):
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        query = self.validate_query(query, current)
        country = query['object']['country']
        fields = {name: {'status': 'unknown', 'reason': 'WAR_TERRITORY_UNAVAILABLE'}
                  for name in query['fields']}
        installation, creation, reason = _session_binding(self.base_source)
        reason = reason or _observer_context_reason(current)
        if reason:
            fields = {name: {'status': 'unavailable', 'reason': reason} for name in fields}
        else:
            try:
                report = (self.capture or capture)(installation, country, fields=query['fields'],
                                                   observer=current['observer'])
                if validate_capture(report, current, creation, country, query['fields']):
                    values = report['observation']['backend']['targets'][0]['fields']
                    fields = {name: deepcopy(values['W03.' + name]) for name in query['fields']}
            except Exception:
                fields = {name: {'status': 'unknown', 'reason': 'WAR_TERRITORY_CAPTURE_FAILED'}
                          for name in fields}
        complete = all(field.get('status') == 'known' and field.get('complete', True)
                       for field in fields.values())
        return _result(query, current, fields, complete,
            _source_info(type(self).__name__, current, complete=complete, provenance={
                'basis': 'discovered_owned_province_control_and_blockade_summary',
                'read_only': True, 'native_function_invoked': False,
                'profile_sha256': PROFILE_SHA256}))
