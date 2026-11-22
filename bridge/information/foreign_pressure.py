"""Foreign war endurance and occupation through existing bounded readers."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

from . import domestic_pressure_memory as _pressure
from . import foreign_country_memory as _countries
from . import foreign_technology_capture as _owner
from . import country_occupation_memory as _occupation
from . import average_unrest_memory as _unrest
from .model import InformationError
from .sources import _result, _source_info
from .trade_income import NativeTradeIncomeSource, _observer_context_reason, _session_binding


SCHEMA = 'information.foreign_pressure_capture.v1'
_LEGACY_PROFILE_SHA256 = hashlib.sha256(
    (_owner.PROFILE_SHA256 + _pressure.EXPECTED_PROFILE_SHA256).encode('ascii')
).hexdigest()
ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name('profiles') / 'foreign-occupation-memory-1374-v1.json'
PROFILE_FILE_SHA256 = '2de29a604af405a07e5c510bbc461fa90d24860830df4763cbde816eef281673'
_OCCUPATION_PROFILE_SHA256 = hashlib.sha256(
    (_LEGACY_PROFILE_SHA256 + PROFILE_FILE_SHA256).encode('ascii')).hexdigest()
PROFILE_SHA256 = hashlib.sha256(
    (_OCCUPATION_PROFILE_SHA256 + _unrest.EXPECTED_PROFILE_SHA256).encode('ascii')).hexdigest()
FIELD = 'F04.war_exhaustion'
FIELDS = ('war_exhaustion', 'occupied', 'unrest')
_TAG = re.compile(r'[A-Z0-9]{3}\Z')


def _load_legacy_profile():
    profile = deepcopy(_owner._load_profile())
    profile['pressure_scalar'] = _pressure._load_profile()['scalars']['war_exhaustion']
    return profile


def _load_occupation_profile():
    raw = PROFILE_FILE.read_bytes()
    if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != PROFILE_FILE_SHA256:
        raise ValueError('FOREIGN_OCCUPATION_PROFILE_PIN')
    spec = json.loads(raw)
    for entry in [spec['source_evidence'], *spec['dependencies']]:
        if _owner._sha(ROOT / entry['path']) != entry['sha256']:
            raise ValueError('FOREIGN_OCCUPATION_SOURCE_PIN')
    profile = _load_legacy_profile()
    profile['code_guards'].extend(spec['code_guards'])
    profile['occupation'] = spec['layout']
    return profile


def _load_profile():
    profile = _load_occupation_profile()
    unrest = _unrest._load_profile()
    profile['code_guards'].extend({
        'name': 'average_unrest.' + guard['name'], 'rva': guard['rva'],
        'end_rva_exclusive': hex(int(guard['rva'], 0) + len(guard['hex']) // 2),
        'bytes': guard['hex'], 'sha256': guard['sha256']}
        for guard in unrest['code_guards'])
    profile['unrest_scalar'] = {'offset': unrest['layout']['country_average_unrest_offset'],
                               'unit': 'unrest', 'scale': 1000}
    return profile


def read_war_exhaustion(read, binding, spec):
    """Read the existing signed current scalar for one admitted country."""
    address = int(binding['country_pointer'], 0) + int(spec['offset'], 0)
    raw = read.read(address, 4, 'foreign_pressure.war_exhaustion')
    value = int.from_bytes(raw, 'little', signed=True)
    return {'status': 'known', 'value': value, 'raw': value,
            'raw_hex': raw.hex(), 'scale': spec['scale'], 'unit': spec['unit']}


def _observe_for(fields, observer='FRA'):
    def observe(reader, base, country, profile):
        bindings, rows = {}, {}

        def admission(read, module_base, scan, observer_tag, target):
            bindings.update(scan['requested'])
            rows.clear()
            rows.update({row['fullref']: row for row in scan['rows'] if row['fullref']})
            return _owner._bound_admission(read, module_base, scan, observer_tag, target)

        def read_fields(read, module_base, binding, selected):
            result = {}
            if 'war_exhaustion' in fields:
                result[FIELD] = read_war_exhaustion(read, binding, profile['pressure_scalar'])
            if 'unrest' in fields:
                spec = profile['unrest_scalar']
                raw = read.read(int(binding['country_pointer'], 0) + int(spec['offset'], 0),
                                4, 'foreign_pressure.average_unrest')
                value = int.from_bytes(raw, 'little', signed=True)
                result['F04.unrest'] = {'status': 'known', 'value': value, 'raw': value,
                    'raw_hex': raw.hex(), 'scale': spec['scale'], 'unit': spec['unit'],
                    'basis': 'native_country_average_unrest_cache'}
            if 'occupied' in fields:
                try:
                    result['F04.occupied'] = _occupation.read_occupation(read, module_base,
                        binding, bindings[observer], rows, profile['occupation'])
                except Exception as exc:
                    result['F04.occupied'] = {'status': 'unknown', 'reason': str(exc)}
            return result

        def backend(read, module_base, target):
            return _countries.read_two_pass(read, module_base, observer, [target],
                fields=['F04.' + name for name in fields], admission_reader=admission,
                read_fields=read_fields)

        return _owner._observe(reader, base, country, profile, backend_reader=backend)
    return observe


def _observe(reader, base, country, profile):
    return _observe_for(['war_exhaustion'])(reader, base, country, profile)


def capture(installation, country, *, observer='FRA', fields=None):
    fields = ['war_exhaustion'] if fields is None else list(fields)
    report = _owner._capture_common(installation, country, observer=observer, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe_for(fields, observer), observer_scoped=True)
    report['request']['fields'] = fields
    return report


def validate_capture(report, context, creation, country, fields=None):
    fields = ['war_exhaustion'] if fields is None else fields
    if (not isinstance(report, dict) or not isinstance(context, dict)
            or report.get('request', {}).get('fields', ['war_exhaustion']) != fields):
        return False
    legacy = report.get('profile_sha256') == _LEGACY_PROFILE_SHA256
    occupation = report.get('profile_sha256') == _OCCUPATION_PROFILE_SHA256
    profile_sha = _LEGACY_PROFILE_SHA256 if legacy else (
        _OCCUPATION_PROFILE_SHA256 if occupation else PROFILE_SHA256)
    loader = _load_legacy_profile if legacy else (
        _load_occupation_profile if occupation else _load_profile)
    return _owner._validate_capture_common(report, context, creation, country,
        schema=SCHEMA, profile_sha256=profile_sha, load_profile=loader,
        observe=_observe_for(fields, context.get('observer')), require_access=True, observer_scoped=True)


class NativeForeignPressureSource(NativeTradeIncomeSource):
    def read_war_exhaustion_batch(self, countries, context):
        """Share country-table sampling for the selected war's foreign members."""
        from .war_pressure_capture import read_countries
        return read_countries(self, countries, context)

    def catalog(self):
        return [{'topic_id': 'F04', 'catalog_ids': ['F04'], 'title': '外国压力与继承风险',
            'status': 'available', 'fields': {'war_exhaustion': {
                'coverage': 'available', 'complete': True, 'unit': 'war_exhaustion',
                'scale': 1000, 'raw': True, 'period': 'current',
                'description': '目标国家厌战度，通常范围0到20，用于判断战争承受能力',
                'source': __name__ + '.capture', 'basis': 'native_country_war_exhaustion_cache'},
                'occupied': {'coverage': 'available', 'complete': True, 'unit': 'province_counts',
                    'period': 'current', 'source': __name__ + '.capture',
                    'description': '目标国家领土中的已知受占领省份数量及控制国汇总',
                    'basis': 'discovered_owned_province_controller_summary'},
                'unrest': {'coverage': 'available', 'complete': True, 'unit': 'unrest',
                    'scale': 1000, 'period': 'current', 'source': __name__ + '.capture',
                    'description': '目标国家平均叛乱度，保留负值，以点数表示',
                    'basis': 'native_country_average_unrest_cache'}},
            'object_types': ['country'], 'observer_roles': [], 'observer_scope': [],
            'parameters': {'type': 'object', 'properties': {}, 'additionalProperties': False},
            'supported_versions': ['1.37.4'], 'triggers': ['query', 'periodic'],
            'source': type(self).__name__, 'context_scope': 'visible_scope',
            'visibility': 'visible_scope'}]

    def validate_query(self, query, context=None):
        if (not isinstance(query, dict) or query.get('topic') != 'F04'
                or set(query) - {'topic', 'object', 'fields', 'parameters'}):
            raise InformationError('invalid_parameters', 'Expected an F04 query')
        obj = query.get('object')
        if (not isinstance(obj, dict) or set(obj) != {'type', 'country'}
                or obj.get('type') != 'country' or not isinstance(obj.get('country'), str)
                or not _TAG.fullmatch(obj['country'])):
            raise InformationError('invalid_object', 'F04 requires a foreign country tag')
        fields = query.get('fields')
        if (not isinstance(fields, list) or not fields or any(name not in FIELDS for name in fields)
                or len(set(fields)) != len(fields)):
            raise InformationError('invalid_fields', 'Unsupported F04 fields')
        if query.get('parameters', {}) != {}:
            raise InformationError('invalid_parameters', 'F04 has no extra parameters')
        if context is not None:
            observer = context.get('observer') if isinstance(context, dict) else None
            if not isinstance(observer, str) or not _TAG.fullmatch(observer):
                raise InformationError('observer_scope_mismatch', 'F04 requires a configured observer country')
            if obj['country'] == observer:
                raise InformationError('invalid_object', 'F04 requires a foreign country tag')
        return {'topic': 'F04', 'object': deepcopy(obj), 'fields': list(fields), 'parameters': {}}

    def read(self, query, context=None):
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        query = self.validate_query(query, current)
        country = query['object']['country']
        fields = {name: {'status': 'unknown', 'reason': 'FOREIGN_PRESSURE_CAPTURE_UNAVAILABLE'}
                  for name in query['fields']}
        installation, creation, session_reason = _session_binding(self.base_source)
        reason = _observer_context_reason(current) or session_reason
        if reason:
            for field in fields.values():
                field['reason'] = reason
        else:
            try:
                arguments = {'country': country, 'observer': current['observer']}
                if query['fields'] != ['war_exhaustion']:
                    arguments['fields'] = query['fields']
                report = (self.capture or capture)(installation, **arguments)
                if validate_capture(report, current, creation, country, query['fields']):
                    values = report['observation']['backend']['targets'][0]['fields']
                    fields = {name: deepcopy(values['F04.' + name]) for name in query['fields']}
            except Exception:
                for field in fields.values():
                    field['reason'] = 'FOREIGN_PRESSURE_CAPTURE_FAILED'
        complete = all(field.get('status') == 'known' and field.get('complete', True)
                       for field in fields.values())
        return _result(query, current, fields, complete,
            _source_info(type(self).__name__, current, complete=complete, provenance={
                'basis': 'country_pressure_and_occupation_summary', 'read_only': True,
                'native_function_invoked': False, 'profile_sha256': PROFILE_SHA256}))
