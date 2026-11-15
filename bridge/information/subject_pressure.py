"""Subject state and obligations through existing country and native queries."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

from . import ai_attitude as _attitude
from . import foreign_country_memory as _countries
from . import foreign_technology_capture as _owner
from . import observation_time as _time
from . import subject_type_memory as _subject_types
from . import subject_integration_memory as _integration
from .model import InformationError
from .sources import _result, _source_info
from .trade_income import NativeTradeIncomeSource, _context_reason, _identity, _session_binding


SCHEMA = 'information.subject_pressure_capture.v1'
BINDING_SCHEMA = 'information.subject_binding_capture.v1'
ROOT = Path(__file__).resolve().parents[2]
_V1_PROFILE_FILE = Path(__file__).with_name('profiles') / 'subject-pressure-memory-1374-v1.json'
_V1_PROFILE_FILE_SHA256 = '96c0eb620a0b7878e3ca950e5f7727e61ad4343ac312175605d31f779b8078d9'
_V2_PROFILE_FILE = Path(__file__).with_name('profiles') / 'subject-pressure-memory-1374-v2.json'
_V2_PROFILE_FILE_SHA256 = '0e95ee3f802afbaea1bc7f558cf2b1774d79997cbb927385cd985c131401a35c'
PROFILE_FILE = Path(__file__).with_name('profiles') / 'subject-pressure-memory-1374-v3.json'
PROFILE_FILE_SHA256 = 'c9e3d0fd66b029a65a488a2b2f1392e61457dee39f9231a10991313ecba3f2fe'
PROFILE_SHA256 = hashlib.sha256(
    (_attitude.PROFILE_SHA256 + PROFILE_FILE_SHA256).encode('ascii')).hexdigest()
_PREVIOUS_PROFILES = {
    hashlib.sha256((_attitude.PROFILE_SHA256 + digest).encode('ascii')).hexdigest(): (path, digest)
    for path, digest in ((_V1_PROFILE_FILE, _V1_PROFILE_FILE_SHA256),
                         (_V2_PROFILE_FILE, _V2_PROFILE_FILE_SHA256))}
_LEGACY_PROFILE_SHA256 = hashlib.sha256(
    (_attitude.PROFILE_SHA256 + ':subject-pressure-v1').encode('ascii')).hexdigest()
_BINDING_FIELD = 'S03.subject_binding'
_TAG = re.compile(r'[A-Z0-9]{3}\Z')
_FIELDS = {'S03': ('liberty_desire', 'loyalty', 'support_independence', 'tribute', 'levy', 'integration'),
           'F04': ('subject_loyalty',)}


def _load_profile(path=PROFILE_FILE, expected_sha256=PROFILE_FILE_SHA256):
    raw = path.read_bytes()
    if len(raw) > 16384 or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError('SUBJECT_PRESSURE_PROFILE_PIN')
    spec = json.loads(raw)
    evidence = spec['source_evidence']
    if _owner._sha(ROOT / evidence['path']) != evidence['sha256']:
        raise ValueError('SUBJECT_SUPPORT_SOURCE_PIN')
    profile = deepcopy(_attitude._load_profile())
    profile['code_guards'].extend(spec['code_guards'])
    profile['subject_support'] = spec['support_independence']
    if 'obligations' in spec:
        evidence = spec['obligation_source_evidence']
        if _owner._sha(ROOT / evidence['path']) != evidence['sha256']:
            raise ValueError('SUBJECT_OBLIGATION_SOURCE_PIN')
        profile['subject_obligations'] = spec['obligations']
    if 'integration_task' in spec:
        evidence = spec['integration_source_evidence']
        if _owner._sha(ROOT / evidence['path']) != evidence['sha256']:
            raise ValueError('SUBJECT_INTEGRATION_SOURCE_PIN')
        profile['subject_integration_task'] = spec['integration_task']
    return profile


def _read_support_partners(read, pointer, rows, spec):
    count = int.from_bytes(read.read(pointer + spec['count_offset'], 4,
        'subject_support.count'), 'little', signed=True)
    if not 0 <= count <= spec['max_entries']:
        raise ValueError('SUBJECT_SUPPORT_COUNT_INVALID')
    if count == 0:
        return {'status': 'known', 'value': []}
    vector = int.from_bytes(read.read(pointer + spec['vector_offset'], 8,
        'subject_support.vector'), 'little')
    records = read.read(vector, count * spec['element_stride'], 'subject_support.records')
    tags = {row['slot']: row['tag'] for row in rows.values() if row.get('tag')}
    partners = set()
    for offset in range(0, len(records), spec['element_stride']):
        slot = int.from_bytes(records[offset:offset + 4], 'little', signed=True)
        if slot not in tags:
            raise ValueError('SUBJECT_SUPPORT_PARTNER_BINDING_UNAVAILABLE')
        partners.add(tags[slot])
    return {'status': 'known', 'value': sorted(partners)}


def _country_for(query):
    obj = query['object']
    return obj['country'] if obj['type'] == 'country' else (
        obj['recipient'] if obj['actor'] == 'FRA' else obj['actor'])


def _integration_result(captured, native, overlord):
    result = deepcopy(captured)
    if result.get('status') != 'known':
        return result
    values = result['value']
    values['overlord'] = overlord
    rules = values['type_rules']
    eligible = rules.get('annexation_allowed') is True or rules.get('union_integration_allowed') is True
    if not eligible:
        values['can_start'] = {'status': 'known', 'value': False}
        values['total_diplomatic_power'] = {'status': 'not_applicable', 'reason': 'TYPE_INTEGRATION_DISABLED'}
    elif (isinstance(native, dict) and native.get('verified') is True
            and native.get('applicable') is True and type(native.get('can_start')) is bool
            and type(native.get('total_diplomatic_power')) is int
            and native['total_diplomatic_power'] >= 0):
        values['can_start'] = {'status': 'known', 'value': native['can_start']}
        values['total_diplomatic_power'] = {'status': 'known', 'value': native['total_diplomatic_power']}
        if native['can_start'] is False and native.get('conditions'):
            values['conditions'] = native['conditions']
    spent = values.get('diplomatic_power_spent')
    progress_known = type(values.get('in_progress')) is bool and (
        type(spent) in (int, float) or isinstance(spent, dict) and spent.get('status') == 'known')
    result['complete'] = progress_known and values['can_start'].get('status') == 'known' and (
        values['total_diplomatic_power'].get('status') in ('known', 'not_applicable'))
    return result


def _observe_for(query, countries=None):
    def observe(reader, base, country, profile):
        bindings = {}
        rows = {}

        def admission(read, module_base, scan, observer, target):
            bindings.update(scan['requested'])
            rows.clear()
            rows.update({row['fullref']: row for row in scan['rows'] if row['fullref']})
            return _owner._bound_admission(read, module_base, scan, observer, target)

        def parent_ref(read, binding):
            raw = read.read(int(binding['country_pointer'], 0) + 0x18f0, 8, 'subject_pressure.overlord')
            return int.from_bytes(raw, 'little')

        def read_fields(read, module_base, target, selected):
            if query['object']['type'] == 'country':
                subject = target
                parent = parent_ref(read, subject)
            else:
                endpoints = [bindings['FRA'], bindings[country]]
                candidates = [(binding, parent_ref(read, binding)) for binding in endpoints]
                related = [(binding, parent) for binding, parent in candidates
                           if any(parent == int(other['fullref'], 0) and other is not binding
                                  for other in endpoints)]
                if len(related) > 1:
                    raise ValueError('SUBJECT_PAIR_ROLES_CONFLICT')
                if not related:
                    return {_BINDING_FIELD: {'status': 'known', 'value': None}}
                subject, parent = related[0]
            if parent >> 56 == 0:
                return {_BINDING_FIELD: {'status': 'known', 'value': None}}
            overlord = rows.get(hex(parent))
            if not overlord or not overlord.get('tag'):
                raise ValueError('SUBJECT_OVERLORD_BINDING_UNAVAILABLE')
            state = {'subject': subject['tag'], 'overlord': overlord['tag']}
            obligations = [name for name in query['fields'] if name in ('tribute', 'levy', 'integration')]
            if obligations:
                try:
                    name, values = _subject_types.read_obligations(read, module_base, subject,
                        profile['attitude']['personality'], profile['subject_obligations'], obligations)
                    state['subject_type'] = name
                    state.update(values)
                except Exception as exc:
                    state.update({name: {'status': 'unknown', 'reason': str(exc)}
                                  for name in obligations})
            if state.get('integration', {}).get('status') == 'known':
                rules = state['integration']['value']
                values = {'type_rules': rules,
                          'can_start': {'status': 'unknown', 'reason': 'INTEGRATION_START_CONDITIONS_UNAVAILABLE'},
                          'total_diplomatic_power': {'status': 'unknown', 'reason': 'INTEGRATION_TOTAL_COST_UNAVAILABLE'}}
                try:
                    values.update(_integration.read_progress(read, module_base, subject, overlord,
                        profile['attitude']['personality'], profile['subject_integration_task']))
                except Exception as exc:
                    values.update({name: {'status': 'unknown', 'reason': str(exc)}
                                   for name in ('in_progress', 'diplomatic_power_spent')})
                state['integration'].update(value=values, complete=False)
            if 'support_independence' in query['fields']:
                try:
                    state['support_independence'] = _read_support_partners(
                        read, int(subject['country_pointer'], 0), rows, profile['subject_support'])
                except Exception as exc:
                    state['support_independence'] = {'status': 'unknown', 'reason': str(exc)}
            if query['topic'] == 'F04' or 'loyalty' in query['fields']:
                try:
                    state['loyalty'] = _attitude._read_attitude(
                        read, module_base, int(subject['country_pointer'], 0), overlord,
                        profile['attitude'])
                except Exception as exc:
                    state['loyalty'] = {'status': 'unknown', 'reason': str(exc)}
            return {_BINDING_FIELD: {'status': 'known', 'value': state}}

        def backend(read, module_base, target):
            targets = [target] if countries is None else countries
            return _countries.read_two_pass(read, module_base, 'FRA', targets, fields=[_BINDING_FIELD],
                admission_reader=admission, read_fields=read_fields)

        return _owner._observe(reader, base, country, profile, backend_reader=backend)
    return observe


def capture(installation, query):
    report = _owner._capture_common(installation, _country_for(query), observer='FRA', schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe_for(query), allow_observer_target=True)
    report['request']['query'] = deepcopy(query)
    return report


def validate_capture(report, context, creation, query):
    legacy = isinstance(report, dict) and report.get('profile_sha256') == _LEGACY_PROFILE_SHA256
    previous = _PREVIOUS_PROFILES.get(report.get('profile_sha256')) if isinstance(report, dict) else None
    profile_sha = _LEGACY_PROFILE_SHA256 if legacy else (
        report['profile_sha256'] if previous else PROFILE_SHA256)

    def load_profile():
        if legacy:
            return _attitude._load_profile()
        if previous:
            return _load_profile(*previous)
        return _load_profile()

    return (isinstance(report, dict) and report.get('request', {}).get('query') == query
        and _owner._validate_capture_common(report, context, creation, _country_for(query),
            schema=SCHEMA, profile_sha256=profile_sha, load_profile=load_profile,
            observe=_observe_for(query), allow_observer_target=True, require_access=True))


def _binding_countries(countries):
    if (not isinstance(countries, (list, tuple)) or not countries
            or len(countries) > _countries.MAX_TARGETS
            or any(not isinstance(country, str) or not _TAG.fullmatch(country) for country in countries)
            or len(set(countries)) != len(countries)):
        raise ValueError('SUBJECT_BINDING_COUNTRIES_INVALID')
    return list(countries)


def _binding_observation(countries):
    query = {'topic': 'S03', 'object': {'type': 'country', 'country': countries[0]},
             'fields': ['liberty_desire'], 'parameters': {}}
    return _observe_for(query, countries)


def capture_bindings(installation, countries):
    """Share the existing country scan and guards for at most eight bindings."""
    countries = _binding_countries(countries)
    report = _owner._capture_common(installation, countries[0], observer='FRA', schema=BINDING_SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_binding_observation(countries), allow_observer_target=True)
    report['request']['countries'] = countries
    return report


def validate_binding_capture(report, context, creation, countries):
    try:
        countries = _binding_countries(countries)
    except ValueError:
        return False
    return (isinstance(report, dict) and report.get('request', {}).get('countries') == countries
        and _owner._validate_capture_common(report, context, creation, countries[0],
            schema=BINDING_SCHEMA, profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
            observe=_binding_observation(countries), allow_observer_target=True, require_access=True))


class NativeSubjectPressureSource(NativeTradeIncomeSource):
    def catalog(self):
        result = []
        for topic, fields in _FIELDS.items():
            metadata = {name: {'coverage': 'available', 'complete': True,
                'source': __name__, 'period': 'current',
                'unit': 'percent' if name == 'liberty_desire' else 'subject_loyalty',
                'scale': 1000 if name == 'liberty_desire' else 1,
                'basis': ('native_effective_liberty_desire' if name != 'loyalty'
                          else 'native_subject_attitude_towards_overlord')}
                for name in fields}
            if 'support_independence' in metadata:
                metadata['support_independence'].update(unit='country_tags',
                    basis='native_support_independence_membership',
                    description='该属国当前独立支持关系中的其它国家，空列表表示没有相关关系')
            for name in ('tribute', 'levy'):
                if name in metadata:
                    metadata[name].update(unit='obligation_rules', scale=1,
                        basis='loaded_subject_type_obligation_rules',
                        description='当前已加载属国类型的贡赋规则' if name == 'tribute'
                                    else '当前已加载属国类型的兵役贡献规则')
            if 'integration' in metadata:
                metadata['integration'].update(coverage='available', complete=True,
                    unit='integration_state', scale=1, basis='loaded_type_rules_current_task_and_native_checks',
                    description='整合类型规则、当前任务与已投入外交点，以及原生当前开始条件和有效总成本')
            result.append({'topic_id': topic, 'catalog_ids': [topic],
                'title': '属国忠诚与义务' if topic == 'S03' else '外国压力与继承风险',
                'status': 'available', 'fields': metadata,
                'object_types': ['country', 'country_pair'] if topic == 'S03' else ['country'],
                'observer_roles': [], 'observer_scope': ['FRA'],
                'parameters': {'type': 'object', 'properties': {}, 'additionalProperties': False},
                'supported_versions': ['1.37.4'], 'triggers': ['query', 'periodic'],
                'source': type(self).__name__, 'context_scope': 'visible_scope', 'visibility': 'visible_scope'})
        return result

    def validate_query(self, query, context=None):
        if (not isinstance(query, dict) or query.get('topic') not in _FIELDS
                or set(query) - {'topic', 'object', 'fields', 'parameters'}):
            raise InformationError('invalid_parameters', 'Expected an S03 or F04 query')
        obj = query.get('object')
        if not isinstance(obj, dict):
            raise InformationError('invalid_object', 'Expected a country or country pair')
        if obj.get('type') == 'country':
            if (set(obj) != {'type', 'country'} or not isinstance(obj.get('country'), str)
                    or not _TAG.fullmatch(obj['country'])
                    or (query['topic'] == 'F04' and obj['country'] == 'FRA')):
                raise InformationError('invalid_object', 'Invalid subject country')
        elif (query['topic'] != 'S03' or set(obj) != {'type', 'actor', 'recipient'}
                or obj.get('type') != 'country_pair'
                or any(not isinstance(obj.get(key), str) or not _TAG.fullmatch(obj[key])
                       for key in ('actor', 'recipient'))
                or obj['actor'] == obj['recipient'] or 'FRA' not in (obj['actor'], obj['recipient'])):
            raise InformationError('invalid_object', 'Subject country pair must include FRA')
        fields = query.get('fields')
        if (not isinstance(fields, list) or not fields
                or any(name not in _FIELDS[query['topic']] for name in fields)
                or len(set(fields)) != len(fields)):
            raise InformationError('invalid_fields', 'Unsupported subject pressure fields')
        if query.get('parameters', {}) != {}:
            raise InformationError('invalid_parameters', 'Subject pressure has no extra parameters')
        if context is not None and (not isinstance(context, dict) or context.get('observer') != 'FRA'):
            raise InformationError('observer_scope_mismatch', 'The supported observer is FRA')
        return {'topic': query['topic'], 'object': deepcopy(obj), 'fields': list(fields), 'parameters': {}}

    def read(self, query, context=None):
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        query = self.validate_query(query, current)
        invoked = False

        def result(fields, complete=False):
            return _result(query, current, fields, complete, _source_info(type(self).__name__, current,
                complete=complete, provenance={'native_function_invoked': invoked,
                'read_only': True, 'profile_sha256': PROFILE_SHA256}))

        def failure(reason):
            return result({name: {'status': 'unknown', 'reason': reason} for name in query['fields']})

        installation, creation, reason = _session_binding(self.base_source)
        if reason or _context_reason(current):
            return failure(reason or _context_reason(current))
        try:
            report = (self.capture or capture)(installation, query)
            if not validate_capture(report, current, creation, query):
                return failure('SUBJECT_PRESSURE_CAPTURE_INVALID')
            binding = report['observation']['backend']['targets'][0]['fields'][_BINDING_FIELD]
            if binding.get('status') != 'known':
                return result({name: deepcopy(binding) for name in query['fields']})
            state = binding['value']
            if state is None:
                return result({name: {'status': 'not_applicable', 'reason': 'NO_SUBJECT_RELATION'}
                               for name in query['fields']}, True)
            liberty = {'status': 'unknown', 'reason': 'NATIVE_SUBJECT_STATE_UNAVAILABLE'}
            integration = state.get('integration',
                {'status': 'unknown', 'reason': 'SUBJECT_INTEGRATION_UNAVAILABLE'})
            rules = integration.get('value', {}).get('type_rules', {})
            integration_needed = 'integration' in query['fields'] and (
                rules.get('annexation_allowed') is True or rules.get('union_integration_allowed') is True)
            native_integration = None
            if query['topic'] == 'F04' or 'liberty_desire' in query['fields'] or integration_needed:
                recipient = state['overlord'] if state['subject'] == 'FRA' else state['subject']
                tools = getattr(self.base_source, 'diplomacy_tools', None)
                inspector = getattr(tools, 'inspect_diplomatic_action', None)
                if callable(inspector):
                    invoked = True
                    try:
                        inspection = inspector('offer_vassalization', 'FRA', recipient, 'initiate', {})
                    except Exception:
                        inspection = {}
                    if not isinstance(inspection, dict):
                        inspection = {}
                    key = 'actor_subject_state' if state['subject'] == 'FRA' else 'recipient_subject_state'
                    native = inspection.get(key)
                    if (inspection.get('actor') == 'FRA' and inspection.get('recipient') == recipient
                            and isinstance(native, dict) and native.get('verified') is True
                            and native.get('is_subject') is True and native.get('overlord') == state['overlord']
                            and type(native.get('liberty_desire_raw')) is int and native.get('scale') == 1000):
                        liberty = {'status': 'known', 'value': native['liberty_desire_raw'],
                                   'raw': native['liberty_desire_raw'], 'scale': 1000, 'unit': 'percent'}
                        if native.get('subject_type') == state.get('subject_type'):
                            native_integration = native.get('integration')
            after = self.context()
            if (_context_reason(after) or _identity(after) != _identity(current)
                    or not _time.dates_match(current['game_date'], after['game_date'])):
                return failure('SUBJECT_PRESSURE_CONTEXT_CHANGED')
            loyalty = state.get('loyalty', {'status': 'unknown', 'reason': 'SUBJECT_ATTITUDE_UNAVAILABLE'})
            if query['topic'] == 'S03':
                values = {'liberty_desire': liberty, 'loyalty': loyalty,
                          'support_independence': state.get('support_independence',
                              {'status': 'unknown', 'reason': 'SUBJECT_SUPPORT_UNAVAILABLE'}),
                          'tribute': state.get('tribute',
                              {'status': 'unknown', 'reason': 'SUBJECT_TRIBUTE_UNAVAILABLE'}),
                          'levy': state.get('levy',
                              {'status': 'unknown', 'reason': 'SUBJECT_LEVY_UNAVAILABLE'}),
                          'integration': _integration_result(integration, native_integration, state['overlord'])}
                selected = {name: values[name] for name in query['fields']}
            else:
                selected = {'subject_loyalty': {'status': 'known', 'value': {
                    'overlord': state['overlord'], 'liberty_desire': liberty, 'loyalty': loyalty}}}
            complete = all(value.get('status') == 'known' and value.get('complete', True)
                           for value in selected.values())
            if query['topic'] == 'F04':
                complete = liberty.get('status') == loyalty.get('status') == 'known'
            return result(selected, complete)
        except Exception:
            return failure('SUBJECT_PRESSURE_READ_FAILED')
