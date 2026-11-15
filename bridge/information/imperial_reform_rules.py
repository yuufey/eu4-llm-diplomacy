"""Expose configured HRE reform declarations without claiming current effects."""
from __future__ import annotations

from copy import deepcopy
from pathlib import PurePosixPath
import re

from .catalog import get_topic
from .empire_live import NativeEmpireSource
from .model import canonical
from .sources import _result, _source_info


MAX_DEFINITIONS = 4096
MAX_AST_NODES = 262144
MAX_AST_DEPTH = 96
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
_ID = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}\Z')
_SHA = re.compile(r'[0-9a-f]{64}\Z')
_BASIS = 'cwtools_effective_imperial_reform_declarations'
_OPERATORS = {None, '=', '==', '!=', '<', '>', '<=', '>=', '?='}


def _same(first, second):
    return canonical(first) == canonical(second)


def _public_definitions(records):
    if not isinstance(records, list) or len(records) > MAX_DEFINITIONS:
        raise ValueError('IMPERIAL_REFORM_DEFINITION_LIMIT')
    count = 0

    def nodes(rows, depth=0):
        nonlocal count
        if not isinstance(rows, list) or depth > MAX_AST_DEPTH:
            raise ValueError('IMPERIAL_REFORM_AST_LIMIT')
        output = []
        for row in rows:
            count += 1
            if count > MAX_AST_NODES or not isinstance(row, dict):
                raise ValueError('IMPERIAL_REFORM_AST_LIMIT')
            key, value = row.get('key'), row.get('value')
            kind, assignment = row.get('kind'), row.get('assignment')
            if (not isinstance(key, str) or not key or len(key) > 65536
                    or value is not None and (not isinstance(value, str) or len(value) > 65536)
                    or kind not in {'block', 'scalar', 'bare'}
                    or not isinstance(assignment, (str, type(None))) or assignment not in _OPERATORS):
                raise ValueError('IMPERIAL_REFORM_AST_SHAPE')
            children = nodes(row.get('children', []), depth + 1)
            if ((kind == 'block' and value is not None)
                    or (kind == 'scalar' and (value is None or children or assignment is None))
                    or (kind == 'bare' and (value is not None or children or assignment is not None))):
                raise ValueError('IMPERIAL_REFORM_AST_SHAPE')
            item = {'key': key, 'assignment': assignment, 'kind': kind,
                    'value': value, 'children': children}
            for name in ('line', 'column', 'end_line', 'end_column'):
                if name in row:
                    position = row[name]
                    if type(position) is not int or position < (1 if name in {'line', 'end_line'} else 0):
                        raise ValueError('IMPERIAL_REFORM_AST_LOCATION')
                    item[name] = position
            output.append(item)
        return output

    output, seen = [], set()
    for record in records:
        if not isinstance(record, dict):
            raise ValueError('IMPERIAL_REFORM_DEFINITION_SHAPE')
        identifier, relative = record.get('reform_id'), record.get('relative_file')
        line = record.get('line')
        if (not isinstance(identifier, str) or _ID.fullmatch(identifier) is None
                or identifier in seen or record.get('empire') != 'hre'
                or not isinstance(relative, str) or len(relative) > 512
                or '\\' in relative or ':' in relative
                or PurePosixPath(relative).is_absolute() or '..' in PurePosixPath(relative).parts
                or not relative.startswith('common/imperial_reforms/') or not relative.endswith('.txt')
                or type(line) is not int or line < 1):
            raise ValueError('IMPERIAL_REFORM_DEFINITION_SHAPE')
        seen.add(identifier)
        output.append({'reform_id': identifier, 'empire': 'hre', 'relative_file': relative,
                       'line': line, 'declarations': nodes(record.get('declarations'))})
    if len(canonical(output).encode('utf-8')) > MAX_OUTPUT_BYTES:
        raise ValueError('IMPERIAL_REFORM_OUTPUT_LIMIT')
    return output


class StaticImperialReformRulesSource:
    """The global definition namespace is independent of country membership."""

    event_types = ()

    def __init__(self, base_source, index):
        self.base_source = base_source
        self.index = index

    def context(self):
        return deepcopy(self.base_source.context())

    def catalog(self):
        topic = get_topic('S01')
        topic.update(status='available', source=type(self).__name__, visibility='static_definitions',
                     context_scope='static_rules', supported_versions=['1.37.4'],
                     triggers=['query', 'periodic'], observer_roles=[],
                     object_semantics='global_hre_rules_country_selector_does_not_filter')
        topic['parameters'] = {'type': 'object', 'properties': {}, 'additionalProperties': False}
        topic['fields'] = {'reforms': {
            'coverage': 'partial', 'source': type(self).__name__, 'complete': False,
            'unit': 'imperial_reform_definition', 'scale': 1, 'period': 'static_definition',
            'basis': _BASIS, 'value_origin': 'cwtools_normalized_script_ast',
            'supported_object_types': ['country', 'session'],
            'description': '配置文件中明确属于神罗的改革定义与未求值脚本；不表示当前已通过、可用或生效的改革。',
            'gaps': ['CURRENT_PASSED_REFORMS_NOT_OBSERVED', 'CONDITIONS_AND_EFFECTS_NOT_EVALUATED',
                     'ENGINE_LOADED_DEFINITION_SET_NOT_VERIFIED'],
        }}
        return [topic]

    def validate_query(self, query, context=None):
        # This owner shares the empty parameter schema and selector contract
        # with the disjoint live emperor/elector owner.
        return NativeEmpireSource.validate_query(self, query, context)

    def read(self, query, context=None):
        query = self.validate_query(query, context)
        before = self.context()
        fields = {name: {'status': 'unsupported', 'reason': 'S01_RULE_FIELD_NOT_IMPLEMENTED'}
                  for name in query['fields']}
        provenance = {'read_only': True, 'native_function_invoked': False,
                      'conditions_evaluated': False, 'effects_applied': False,
                      'current_passed_reforms_observed': False,
                      'loaded_definition_set_verified': False,
                      'country_selector_semantics': 'global_definitions_not_membership'}

        def result():
            source = _source_info(type(self).__name__, before, mode='static_definition',
                                  complete=False, provenance=provenance)
            source.update(context_scope='static_rules', projection_version=1,
                          status='observed' if fields.get('reforms', {}).get('status') == 'known' else 'unavailable')
            return _result(query, before, fields, False, source)

        def failure(reason):
            fields['reforms'] = {'status': 'unavailable', 'reason': reason, 'complete': False,
                                  'period': 'static_definition'}
            return result()

        if 'reforms' not in fields:
            return result()
        try:
            if context is not None and not _same(context, before):
                return failure('IMPERIAL_REFORM_CONTEXT_MISMATCH')
            if ('session_id' in query['object']
                    and query['object']['session_id'] != before.get('session_id')):
                return failure('IMPERIAL_REFORM_SESSION_MISMATCH')
            index_before = deepcopy(self.index.context())
            if not isinstance(index_before, dict) or index_before.get('status') != 'ready':
                return failure('IMPERIAL_REFORM_INDEX_UNAVAILABLE')
            version = index_before.get('game_version')
            if version != '1.37.4' or before.get('game_version') not in (None, version):
                return failure('IMPERIAL_REFORM_GAME_VERSION_MISMATCH')
            if any(not isinstance(index_before.get(key), str) or _SHA.fullmatch(index_before[key]) is None
                   for key in ('configuration_sha256', 'definitions_sha256')):
                return failure('IMPERIAL_REFORM_INDEX_IDENTITY_INVALID')
            definitions = _public_definitions(self.index.definitions(empire='hre'))
            index_after = self.index.context()
            after = self.context()
            if not _same(index_before, index_after):
                return failure('IMPERIAL_REFORM_DEFINITIONS_CHANGED')
            if not _same(before, after):
                return failure('IMPERIAL_REFORM_CONTEXT_CHANGED')
            provenance['definition_index'] = {key: index_before[key] for key in (
                'game_version', 'configuration_sha256', 'definitions_sha256')}
            fields['reforms'] = {
                'status': 'known', 'value': definitions, 'unit': 'imperial_reform_definition',
                'scale': 1, 'period': 'static_definition', 'complete': False, 'basis': _BASIS,
                'conditions_evaluated': False, 'effects_applied': False,
                'current_passed_reforms_observed': False, 'loaded_definition_set_verified': False,
            }
            return result()
        except Exception:
            return failure('IMPERIAL_REFORM_DEFINITIONS_UNAVAILABLE')


__all__ = ['StaticImperialReformRulesSource']
