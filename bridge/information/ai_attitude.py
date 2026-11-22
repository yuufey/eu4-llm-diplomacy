"""Read directed AI attitude and historical relationships for an admitted pair."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
from types import SimpleNamespace

from . import foreign_country_memory as _countries
from . import foreign_technology_capture as _owner
from . import mission_memory as _strings
from . import ai_personality_memory as _personality
from .model import InformationError
from .sources import _result, _source_info
from .trade_income import NativeTradeIncomeSource, _identity, _observer_context_reason, _session_binding


ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name('profiles') / 'ai-attitude-memory-1374-v3.json'
PROFILE_FILE_SHA256 = '1e5318d251674977d52c79e1255abc60622fbcaa48faf65de718ef745792c584'
PROFILE_SHA256 = hashlib.sha256(
    (_owner.PROFILE_SHA256 + PROFILE_FILE_SHA256).encode('ascii')).hexdigest()
SCHEMA = 'information.ai_attitude_capture.v1'
FIELD = 'R06.ai_attitude'
HISTORY_FIELD = 'R06.history'
PERSONALITY_FIELD = 'R06.personality'
TENDENCY_FIELD = 'R06.relationship_tendency'
_FIELDS = ('ai_attitude', 'history', 'personality', 'relationship_tendency')
_TAG = re.compile(r'[A-Z0-9]{3}\Z')
_NAME = re.compile(r'attitude_[a-z_]+\Z')


def _load_profile():
    raw = PROFILE_FILE.read_bytes()
    if len(raw) > 16384 or hashlib.sha256(raw).hexdigest() != PROFILE_FILE_SHA256:
        raise ValueError('AI_ATTITUDE_PROFILE_PIN')
    spec = json.loads(raw)
    evidence = spec['source_evidence']
    if _owner._sha(ROOT / evidence['path']) != evidence['sha256']:
        raise ValueError('AI_ATTITUDE_SOURCE_PIN')
    evidence = spec['historical_source_evidence']
    if _owner._sha(ROOT / evidence['path']) != evidence['sha256']:
        raise ValueError('HISTORICAL_RELATIONS_SOURCE_PIN')
    evidence = spec['personality_source_evidence']
    if _owner._sha(ROOT / evidence['path']) != evidence['sha256']:
        raise ValueError('AI_PERSONALITY_SOURCE_PIN')
    profile = deepcopy(_owner._load_profile())
    profile['code_guards'].extend(spec['code_guards'])
    profile['attitude'] = spec
    return profile


def _read_history(read, pointer, target_slot, spec):
    values = {}
    for name in ('historical_friend', 'historical_rival'):
        try:
            header = read.read(pointer + spec[name], 20, 'history.' + name + '.header')
            node = int.from_bytes(header[:8], 'little')
            count = int.from_bytes(header[spec['count_offset']:spec['count_offset'] + 4],
                                   'little', signed=True)
            if not 0 <= count <= spec['max_entries']:
                raise ValueError('HISTORICAL_RELATIONS_COUNT_INVALID')
            seen = set()
            matched = False
            for _ in range(count):
                if node == 0 or node in seen:
                    raise ValueError('HISTORICAL_RELATIONS_CHAIN_INVALID')
                seen.add(node)
                raw = read.read(node, 24, 'history.' + name + '.node')
                fullref = int.from_bytes(raw[:8], 'little')
                matched = matched or ((fullref >> 32) & 0xffff) == target_slot
                offset = spec['node_next_offset']
                node = int.from_bytes(raw[offset:offset + 8], 'little')
            if node != 0:
                raise ValueError('HISTORICAL_RELATIONS_CHAIN_COUNT_MISMATCH')
            values[name] = {'status': 'known', 'value': matched}
        except Exception as exc:
            values[name] = {'status': 'unknown', 'reason': str(exc)}
    return {'status': 'known', 'value': values, 'unit': 'historical_relationship', 'scale': 1}


def _read_attitude(read, module_base, pointer, other, spec):
    table = int.from_bytes(read.read(pointer + spec['relation_table_offset'], 8,
        'ai_attitude.relation_table'), 'little')
    row = read.read(table + other['slot'] * spec['relation_row_stride'],
        spec['relation_row_stride'], 'ai_attitude.relation_row')
    ref_offset = spec['recipient_fullref_offset']
    fullref = int.from_bytes(row[ref_offset:ref_offset + 8], 'little')
    if fullref != int(other['fullref'], 0):
        return {'status': 'unknown', 'reason': 'AI_ATTITUDE_RECIPIENT_MISMATCH'}
    offset = spec['attitude_pointer_offset']
    definition = int.from_bytes(row[offset:offset + 8], 'little')
    if definition == 0:
        return {'status': 'unknown', 'reason': 'AI_ATTITUDE_DEFINITION_ABSENT'}
    address = definition + spec['definition_name_offset']
    header = read.read(address, 32, 'ai_attitude.name')
    decoded = _strings._decode_string32(
        SimpleNamespace(read=read.read, module_base=module_base), address, header, 'ai_attitude.name')
    name = decoded.get('text')
    if (decoded['status'] != 'observed' or not isinstance(name, str)
            or len(name) > spec['max_name_bytes'] or not _NAME.fullmatch(name)):
        return {'status': 'unknown', 'reason': 'AI_ATTITUDE_NAME_UNAVAILABLE'}
    return {'status': 'known', 'value': name.removeprefix('attitude_'),
            'raw_name': name, 'unit': 'attitude', 'scale': 1}


def _observe_for(actor, recipient, fields=('ai_attitude',), observer='FRA'):
    def observe(reader, base, country, profile):
        bindings = {}
        country_rows = {}
        spec = profile['attitude']

        def admission(read, module_base, scan, observer, target):
            bindings.update(scan['requested'])
            country_rows.clear()
            country_rows.update({row['slot']: row for row in scan['rows']})
            return _owner._bound_admission(read, module_base, scan, observer, target)

        def read_fields(read, module_base, target, selected):
            holder = bindings[actor]
            other = bindings[recipient]
            pointer = int(holder['country_pointer'], 0)
            result = {}
            if HISTORY_FIELD in selected:
                result[HISTORY_FIELD] = _read_history(read, pointer, other['slot'], spec['history'])
            if PERSONALITY_FIELD in selected:
                try:
                    result[PERSONALITY_FIELD] = _personality.read_personality(
                        read, module_base, holder, country_rows, spec['personality'])
                except Exception as exc:
                    result[PERSONALITY_FIELD] = {'status': 'unknown', 'reason': str(exc)}
            attitude_fields = [field for field in (FIELD, TENDENCY_FIELD) if field in selected]
            if attitude_fields:
                try:
                    value = _read_attitude(read, module_base, pointer, other, spec)
                except Exception as exc:
                    value = {'status': 'unknown', 'reason': str(exc)}
                result.update({field: deepcopy(value) for field in attitude_fields})
            return result

        def backend(read, module_base, target):
            return _countries.read_two_pass(read, module_base, observer, [target],
                fields=['R06.' + field for field in fields],
                admission_reader=admission, read_fields=read_fields)

        return _owner._observe(reader, base, country, profile, backend_reader=backend)
    return observe


def capture(installation, actor, recipient, fields=('ai_attitude',), observer='FRA'):
    if observer not in (actor, recipient) or actor == recipient:
        raise ValueError('AI_ATTITUDE_OBSERVER_SCOPE')
    country = recipient if actor == observer else actor
    report = _owner._capture_common(installation, country, observer=observer, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe_for(actor, recipient, fields, observer), observer_scoped=True)
    report['request'].update(actor=actor, recipient=recipient, fields=list(fields))
    return report


def validate_capture(report, context, creation, actor, recipient, fields=('ai_attitude',)):
    if (not isinstance(report, dict) or report.get('request', {}).get('actor') != actor
            or report.get('request', {}).get('recipient') != recipient
            or report.get('request', {}).get('fields', ['ai_attitude']) != list(fields)):
        return False
    observer = context.get('observer') if isinstance(context, dict) else None
    if observer not in (actor, recipient) or actor == recipient:
        return False
    country = recipient if actor == observer else actor
    return _owner._validate_capture_common(report, context, creation, country, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe_for(actor, recipient, fields, observer), require_access=True, observer_scoped=True)


class NativeAiAttitudeSource(NativeTradeIncomeSource):
    def catalog(self):
        return [{'topic_id': 'R06', 'catalog_ids': ['R06'], 'title': 'AI态度与公开关系倾向',
            'status': 'available', 'fields': {'ai_attitude': {
                'coverage': 'available', 'complete': True, 'unit': 'attitude', 'scale': 1,
                'description': 'actor对recipient的当前AI态度，独立于好感与具体行动接受度',
                'source': __name__ + '.capture', 'period': 'current',
                'basis': 'native_directed_relation_attitude'},
                'history': {'coverage': 'available', 'complete': True,
                    'unit': 'historical_relationship', 'scale': 1,
                    'description': 'actor对recipient的历史好友及历史宿敌状态',
                    'source': __name__ + '.capture', 'period': 'current',
                    'basis': 'native_country_historical_relationship_lists'},
                'personality': {'coverage': 'available', 'complete': True,
                    'unit': 'ai_personality', 'scale': 1,
                    'description': 'actor当前生效的AI战略性格，包含共享君主时的继承规则',
                    'source': __name__ + '.capture', 'period': 'current',
                    'basis': 'native_effective_ai_personality_cache'},
                'relationship_tendency': {'coverage': 'available', 'complete': True,
                    'unit': 'attitude', 'scale': 1, 'alias_of': 'ai_attitude',
                    'description': 'actor对recipient的当前关系倾向，沿用ai_attitude原生值',
                    'source': __name__ + '.capture', 'period': 'current',
                    'basis': 'native_directed_relation_attitude'}},
            'object_types': ['country_pair'], 'observer_roles': [], 'observer_scope': [],
            'parameters': {'type': 'object', 'properties': {}, 'additionalProperties': False},
            'supported_versions': ['1.37.4'], 'triggers': ['query', 'periodic'],
            'source': type(self).__name__, 'context_scope': 'visible_scope', 'visibility': 'visible_scope'}]

    def validate_query(self, query, context=None):
        if (not isinstance(query, dict) or query.get('topic') != 'R06'
                or set(query) - {'topic', 'object', 'fields', 'parameters'}):
            raise InformationError('invalid_parameters', 'Expected an R06 query')
        obj = query.get('object')
        if (not isinstance(obj, dict) or set(obj) != {'type', 'actor', 'recipient'}
                or obj.get('type') != 'country_pair'
                or any(not isinstance(obj.get(key), str) or not _TAG.fullmatch(obj[key])
                       for key in ('actor', 'recipient')) or obj['actor'] == obj['recipient']):
            raise InformationError('invalid_object', 'R06 requires two distinct country tags')
        if context is None:
            context = self.context()
        observer = context.get('observer') if isinstance(context, dict) else None
        if observer not in (obj['actor'], obj['recipient']):
            raise InformationError('observer_scope_mismatch', 'The R06 country pair must include the configured observer')
        fields = query.get('fields')
        if (not isinstance(fields, list) or not fields or len(fields) > len(_FIELDS)
                or any(field not in _FIELDS for field in fields) or len(set(fields)) != len(fields)):
            raise InformationError('invalid_fields', 'Unsupported R06 fields')
        if query.get('parameters', {}) != {}:
            raise InformationError('invalid_parameters', 'R06 has no extra parameters')
        return {'topic': 'R06', 'object': deepcopy(obj), 'fields': list(fields), 'parameters': {}}

    def read(self, query, context=None):
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        query = self.validate_query(query, current)
        obj = query['object']
        fields = {name: {'status': 'unknown', 'reason': 'AI_ATTITUDE_CAPTURE_UNAVAILABLE'}
                  for name in query['fields']}
        installation, creation, session_reason = _session_binding(self.base_source)
        reason = _observer_context_reason(current) or session_reason
        if reason:
            fields = {name: {'status': 'unknown', 'reason': reason} for name in query['fields']}
        else:
            try:
                report = (self.capture or capture)(installation, obj['actor'], obj['recipient'],
                                                   query['fields'], current['observer'])
                after = self.context()
                if _identity(current) != _identity(after):
                    fields = {name: {'status': 'unknown', 'reason': 'AI_ATTITUDE_CONTEXT_CHANGED'}
                              for name in query['fields']}
                elif validate_capture(report, current, creation, obj['actor'], obj['recipient'], query['fields']):
                    captured = report['observation']['backend']['targets'][0]['fields']
                    fields = {name: deepcopy(captured['R06.' + name]) for name in query['fields']}
            except Exception:
                fields = {name: {'status': 'unknown', 'reason': 'AI_ATTITUDE_CAPTURE_FAILED'}
                          for name in query['fields']}
        complete = all(field.get('status') == 'known' for field in fields.values())
        if 'history' in fields and fields['history'].get('status') == 'known':
            complete &= all(value.get('status') == 'known'
                            for value in fields['history']['value'].values())
        return _result(query, current, fields, complete,
            _source_info(type(self).__name__, current, complete=complete, provenance={
                'basis': 'native_directed_ai_relationships', 'read_only': True,
                'native_function_invoked': False, 'profile_sha256': PROFILE_SHA256}))
