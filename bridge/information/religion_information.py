"""Current native religion identity joined to names and configured declarations."""
from __future__ import annotations

from copy import deepcopy
import hashlib
from importlib import import_module
import re

from .country_faith import NativeCountryFaithSource
from .religion_group import NativeReligionGroupSource
from . import religion_values as _values
from .model import InformationError, canonical
from .religion_binding import binding_digests
from .sources import _result, _source_info
from .trade_income import NativeTradeIncomeSource, _identity, _session_binding

FIELDS = ('faith', 'religion_group', 'mechanics')
_SHA = re.compile(r'[0-9a-f]{64}\Z')
MAX_RULE_CACHE_ENTRIES = 16
MAX_RULE_CACHE_BYTES = 8 * 1024 * 1024
_SPECS = {
    'faith': ('native_display_name_and_icon_frame_request',
              'native_primary_faith_name_icon_and_configuration_identity',
              'copied_native_primary_faith_and_configuration_keys'),
    'religion_group': ('native_display_name',
                       'native_primary_religion_group_and_configuration_identity',
                       'copied_native_religion_group_and_configuration_keys'),
    'mechanics': ('native_identity_and_configured_religion_rules',
                  'native_religion_keys_and_configured_CWTools_declarations',
                  'native_identity_joined_to_unexecuted_configured_script_AST'),
}


class NativeReligionInformationSource(NativeTradeIncomeSource):
    """Share native identities across S02 fields without executing script rules."""

    event_types: tuple[str, ...] = ()

    def __init__(self, base_source, *, faith_source=None, group_source=None,
                 definitions=None, capture=None):
        super().__init__(base_source, capture=capture)
        self.faith_source = faith_source if faith_source is not None else NativeCountryFaithSource(base_source)
        self.group_source = group_source if group_source is not None else NativeReligionGroupSource(base_source)
        self.definitions = definitions
        self._rule_cache = {}
        self._rule_cache_entry_bytes = {}
        self._rule_cache_bytes = 0

    def _clear_rule_cache(self):
        self._rule_cache.clear()
        self._rule_cache_entry_bytes.clear()
        self._rule_cache_bytes = 0

    def _cache_rule(self, key, rules):
        entry_bytes = len(canonical([key, rules]).encode('utf-8'))
        if (MAX_RULE_CACHE_ENTRIES < 1 or MAX_RULE_CACHE_BYTES < 1
                or entry_bytes > MAX_RULE_CACHE_BYTES):
            return False
        if key in self._rule_cache:
            self._rule_cache_bytes -= self._rule_cache_entry_bytes.pop(key)
            del self._rule_cache[key]
        while self._rule_cache and (
                len(self._rule_cache) >= MAX_RULE_CACHE_ENTRIES
                or self._rule_cache_bytes + entry_bytes > MAX_RULE_CACHE_BYTES):
            oldest = next(iter(self._rule_cache))
            del self._rule_cache[oldest]
            self._rule_cache_bytes -= self._rule_cache_entry_bytes.pop(oldest)
        self._rule_cache[key] = deepcopy(rules)
        self._rule_cache_entry_bytes[key] = entry_bytes
        self._rule_cache_bytes += entry_bytes
        return True

    def catalog(self):
        topic = deepcopy(NativeCountryFaithSource.catalog(self)[0])
        fields = {**topic['fields'], **NativeReligionGroupSource.catalog(self)[0]['fields']}
        fields['mechanics'] = {'coverage': 'partial', 'complete': False,
                               'paths': ['native religion identity', 'configured religion/group declaration syntax']}
        for name in FIELDS:
            unit, basis, origin = _SPECS[name]
            fields[name].update(coverage='partial', complete=False, source=type(self).__name__,
                                unit=unit, scale=1, period='current', basis=basis,
                                value_origin=origin, supported_observers=['FRA'],
                                triggers=['query', 'periodic'],
                                runtime_validation='religion_identity_capture.validate_capture')
            fields[name]['gaps'] = ['MAIN_THREAD_ATOMICITY_AND_CACHE_FRESHNESS_NOT_PROVEN',
                                    'ACTUAL_UI_RENDERING_NOT_OBSERVED']
            if name == 'mechanics':
                fields[name]['gaps'] += ['CONDITIONS_AND_EFFECTS_NOT_EXECUTED',
                                         'RUNTIME_MECHANIC_STATE_NOT_READ',
                                         'CONFIGURED_FILES_EQUIVALENCE_TO_LOADED_RUNTIME_NOT_PROVEN']
                fields[name]['raw_semantics'] = ('current canonical native keys plus the matching configured '
                                                  'religion/group declarations; conditions are not evaluated '
                                                  'and effects are not current applied modifiers')
            else:
                fields[name]['raw_semantics'] = ('the existing native display-name projection with a separately '
                                                  'validated canonical religion/group identity component')
        topic.update(fields=fields, source=type(self).__name__)
        topic['scope_note'] = ('FRA为逻辑非玩家观察方；名称、准确配置key和配置文件声明分别标记。'
                               '声明不等于当前已应用效果，显示名不参与key反查；多次采集不宣称原子。')
        return [topic]

    def validate_query(self, query, context=None):
        if not isinstance(query, dict):
            raise InformationError('invalid_parameters', 'S02 query must be an object')
        fields = query.get('fields')
        if (not isinstance(fields, list) or not fields or len(fields) > len(FIELDS)
                or any(not isinstance(name, str) or name not in FIELDS for name in fields)
                or len(set(fields)) != len(fields)):
            raise InformationError('invalid_fields', 'Select supported S02 fields once')
        projected = deepcopy(query); projected['fields'] = ['faith']
        normalized = NativeCountryFaithSource.validate_query(self, projected, context)
        normalized['fields'] = list(fields)
        return normalized

    @staticmethod
    def _context_reason(context):
        reason = NativeCountryFaithSource._context_reason(context)
        return reason.replace('COUNTRY_FAITH_', 'RELIGION_INFORMATION_', 1) if reason else None

    @staticmethod
    def _field(name, status, *, reason=None, value=None):
        unit, basis, origin = _SPECS[name]
        item = {'status': status, 'unit': unit, 'scale': 1, 'period': 'current',
                'partial': True, 'complete': False, 'basis': basis, 'value_origin': origin}
        if reason is not None:
            item['reason'] = reason
        if status == 'known' and value is not None:
            item['value'] = deepcopy(value)
        return item

    def _capture_identity(self, installation, creation, target, context, provenance):
        try:
            module = import_module('.religion_identity_capture', __package__)
            capture = self.capture if self.capture is not None else module.capture
            report = capture(installation, country=target, observer='FRA')
            if module.validate_capture(report, context, creation, target) is not True:
                raise ValueError('CAPTURE_INVALID')
            item = report['observation']['backend']['targets'][0]
            if item.get('tag') != target:
                raise ValueError('TARGET_INVALID')
            admission = item['admission_by_pass']['pass2']
            if admission.get('status') != 'known' or type(admission.get('admitted')) is not bool:
                return {'status': 'unknown', 'reason': 'RELIGION_IDENTITY_ADMISSION_UNKNOWN'}
            if not admission['admitted']:
                return {'status': 'invisible', 'reason': 'RELIGION_IDENTITY_NOT_ADMITTED'}
            field = item['fields']['S02.religion_identity']
            if field.get('status') != 'known':
                return {'status': 'unknown', 'reason': 'RELIGION_IDENTITY_INPUT_UNAVAILABLE'}
            if (field.get('complete') is not False
                    or field.get('basis') != 'bounded_native_religion_and_group_configuration_keys'):
                raise ValueError('IDENTITY_FIELD_INVALID')
            keys = _values.identity_value(field['value'])
            bindings = binding_digests(field, target, require_group=True)
            if not isinstance(module.PROFILE_SHA256, str) or _SHA.fullmatch(module.PROFILE_SHA256) is None:
                raise ValueError('IDENTITY_PROFILE_INVALID')
            provenance['identity_profile_sha256'] = module.PROFILE_SHA256
            provenance['identity_capture_sha256'] = hashlib.sha256(canonical(report).encode('utf-8')).hexdigest()
            provenance['identity_bindings'] = bindings
            return {'status': 'known', **keys}
        except Exception:
            return {'status': 'unknown', 'reason': 'RELIGION_IDENTITY_CAPTURE_INVALID'}

    def _name_field(self, name, query, context, identity, provenance):
        child = self.faith_source if name == 'faith' else self.group_source
        child_query = dict(deepcopy(query), fields=[name])
        try:
            sample = child.read(child_query, context)
            source = sample['source']
            if (sample.get('topic') != 'S02' or sample.get('objects') != [query['object']]
                    or sample.get('game_date') != context.get('game_date')
                    or sample.get('complete') is not False
                    or source.get('name') != type(child).__name__
                    or source.get('mode') != context.get('mode')
                    or source.get('status') != 'observed'
                    or source.get('observer') != 'FRA'
                    or source.get('session_id') != context.get('session_id')
                    or source.get('complete') is not False
                    or set(sample['fields']) != {name}):
                raise ValueError('NAME_SOURCE_INVALID')
            field = sample['fields'][name]
            if field.get('status') in ('unknown', 'invisible', 'unavailable'):
                reason = NativeCountryFaithSource._safe_reason(field.get('reason'), 'RELIGION_NAME_UNAVAILABLE')
                return self._field(name, field['status'], reason=reason)
            if field.get('status') != 'known' or field.get('complete') is not False or field.get('partial') is not True:
                raise ValueError('NAME_FIELD_INVALID')
            value = (_values.faith_value(field['value']) if name == 'faith'
                     else NativeReligionGroupSource._public_value(field['value']))
            capture_sha = source.get('provenance', {}).get('capture_report_sha256')
            if not isinstance(capture_sha, str) or _SHA.fullmatch(capture_sha) is None:
                raise ValueError('NAME_PROVENANCE_INVALID')
            if (source['provenance'].get('read_only') is not True
                    or source['provenance'].get('native_function_invoked') is not False):
                raise ValueError('NAME_READ_BOUNDARY_INVALID')
            if identity['status'] == 'known':
                required = ['religion_binding_sha256']
                if name == 'religion_group':
                    required.append('religion_group_binding_sha256')
                expected = provenance.get('identity_bindings', {})
                received = source['provenance']
                if any(not isinstance(received.get(key), str) or _SHA.fullmatch(received[key]) is None
                       or not isinstance(expected.get(key), str) or _SHA.fullmatch(expected[key]) is None
                       for key in required):
                    return self._field(name, 'unknown', reason='RELIGION_NAME_IDENTITY_UNVERIFIED')
                if any(expected[key] != received[key] for key in required):
                    return self._field(name, 'unknown', reason='RELIGION_NAME_IDENTITY_CHANGED')
            provenance.setdefault('name_sources', {})[name] = {'source': type(child).__name__, 'capture_sha256': capture_sha}
            if identity['status'] == 'known':
                provenance['name_sources'][name]['identity_bindings'] = {key: received[key] for key in required}
            value['identity'] = deepcopy(identity)
            return self._field(name, 'known', value=value)
        except Exception:
            return self._field(name, 'unknown', reason='RELIGION_NAME_SOURCE_INVALID')

    def _configured_rules(self, identity):
        unknown = {'status': 'unknown', 'reason': 'RELIGION_RULES_UNAVAILABLE'}
        try:
            if self.definitions is None:
                from .religion_definitions import ReligionDefinitionIndex
                from work.local_config import game_root, user_data
                self.definitions = ReligionDefinitionIndex(game_root(), user_data())
            index = self.definitions
            index.assert_current(); before = index.context()
            if before.get('status') != 'ready':
                raise ValueError('DEFINITIONS_UNREADY')
            key = canonical([identity['religion_key'], identity['religion_group_key'], before])
            if key not in self._rule_cache:
                religion = index.definition(identity['religion_key'])
                group = index.group_definition(identity['religion_group_key'])
                if (religion.get('status') == 'known'
                        and religion.get('religion_group_key') != identity['religion_group_key']):
                    raise ValueError('CONFIGURED_GROUP_DIFFERS_FROM_NATIVE_GROUP')
                def rule(record, name, group=False):
                    try:
                        return _values.rule_value(record, name, group=group)
                    except Exception:
                        return deepcopy(unknown)
                rules = (rule(religion, identity['religion_key']),
                         rule(group, identity['religion_group_key'], True))
                index.assert_current()
                if canonical(index.context()) != canonical(before):
                    raise ValueError('DEFINITIONS_CHANGED')
                self._cache_rule(key, rules)
                return deepcopy(rules)
            else:
                index.assert_current()
                if canonical(index.context()) != canonical(before):
                    raise ValueError('DEFINITIONS_CHANGED')
            return deepcopy(self._rule_cache[key])
        except Exception:
            self._clear_rule_cache()
            return deepcopy(unknown), deepcopy(unknown)

    def read(self, query, context=None):
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        normalized = self.validate_query(query, current)
        provenance = {'read_only': True, 'native_function_invoked': False,
                      'observer': 'FRA', 'target': normalized['object']['country'],
                      'actual_UI_observed': False, 'atomic_snapshot': False,
                      'configured_rules_are_applied_effects': False}

        def result(fields, ctx):
            source = _source_info(type(self).__name__, ctx, complete=False, provenance=deepcopy(provenance))
            source.update(context_scope='visible_scope', projection_version=1)
            return _result(normalized, ctx, fields, False, source)

        def failure(reason, ctx):
            return result({name: self._field(name, 'unavailable', reason=reason) for name in normalized['fields']}, ctx)

        reason = self._context_reason(current)
        if reason:
            return failure(reason, current)
        try:
            before = self.context()
        except Exception:
            return failure('RELIGION_INFORMATION_CONTEXT_UNAVAILABLE', current)
        if self._context_reason(before) or _identity(current) != _identity(before):
            return failure('RELIGION_INFORMATION_CONTEXT_STALE', before)
        installation, creation, binding_reason = _session_binding(self.base_source)
        if binding_reason or installation is None or creation is None:
            return failure('RELIGION_INFORMATION_SESSION_UNAVAILABLE', before)
        identity = self._capture_identity(installation, creation, normalized['object']['country'], before, provenance)
        fields = {}
        for name in normalized['fields']:
            if name in ('faith', 'religion_group'):
                fields[name] = self._name_field(name, normalized, before, identity, provenance)
            elif identity['status'] != 'known':
                fields[name] = self._field(name, identity['status'], reason=identity['reason'])
            else:
                religion, group = self._configured_rules(identity)
                fields[name] = self._field(name, 'known', value={
                    'identity': identity, 'religion_rules': religion, 'group_rules': group,
                    'runtime_state': {'status': 'unknown', 'reason': 'RELIGION_MECHANIC_STATE_NOT_READ'},
                    'conditions_evaluated': False, 'effects_executed': False})
        try:
            after = self.context()
        except Exception:
            after = {}
        if self._context_reason(after) or _identity(before) != _identity(after):
            return failure('RELIGION_INFORMATION_CONTEXT_CHANGED_DURING_CAPTURE', before)
        next_installation, next_creation, next_reason = _session_binding(self.base_source)
        if next_reason or installation != next_installation or creation != next_creation:
            return failure('RELIGION_INFORMATION_SESSION_CHANGED_DURING_CAPTURE', before)
        return result(fields, before)
