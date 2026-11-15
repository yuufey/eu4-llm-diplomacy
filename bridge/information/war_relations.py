"""Expose the existing F01 country-war index through R03, without recapturing it."""
from __future__ import annotations

from copy import deepcopy
import re

from .catalog import get_topic, validate_query
from .country_scale import NativeCountryScaleSource
from .model import InformationError
from .observation_time import dates_match
from .sources import _result, _source_info
from .trade_income import _identity as _scale_identity

_SHA = re.compile(r'[0-9a-f]{64}\Z')
_STATES = {'unknown', 'unavailable', 'invisible', 'not_applicable', 'stale', 'unsupported'}


def _identity(context):
    return (*_scale_identity(context), context.get('mode'), context.get('status'),
            context.get('world_id'), context.get('dll_sha256'),
            context.get('world_generation'), context.get('physical_client_country'))


class NativeWarRelationsSource:
    event_types = ()

    def __init__(self, country_scale_source):
        self.country_scale_source = country_scale_source

    def context(self):
        return deepcopy(self.country_scale_source.context())

    def catalog(self):
        topic = get_topic('R03')
        upstream = next(entry for entry in self.country_scale_source.catalog()
                        if entry['topic_id'] == 'F01')
        field = deepcopy(upstream['fields']['wars'])
        field.update(source=type(self).__name__, supported_object_types=['country'],
                     paths=['NativeCountryScaleSource.read(F01).fields.wars'],
                     description='当前国家战争索引及已核对的双方成员；保留身份遮蔽，不保证全局枚举或战争生命周期。')
        topic.update(status='available', fields={'wars': field}, source=type(self).__name__,
                     supported_versions=deepcopy(upstream['supported_versions']),
                     object_types=['country', 'country_pair'], observer_roles=[],
                     observer_scope=['FRA'], context_scope='visible_scope', visibility='visible_scope',
                     triggers=['query', 'periodic'],
                     scope_note='country视图复用F01同一读器；country_pair尚未实现。完整性不足，不支持变化订阅。')
        return [topic]

    @staticmethod
    def _mapped(query):
        return {'topic': 'F01', 'object': deepcopy(query['object']),
                'fields': ['wars'], 'parameters': {}}

    def validate_query(self, query, context=None):
        if context is not None and not isinstance(context, dict):
            raise InformationError('invalid_context', 'R03 context must be an object')
        normalized = validate_query(query, context)
        if normalized['topic'] != 'R03':
            raise InformationError('unsupported_topic', 'War relations source supports R03 only')
        if normalized['object']['type'] == 'country':
            self.country_scale_source.validate_query(self._mapped(normalized), context)
        return normalized

    @staticmethod
    def _project(field):
        if not isinstance(field, dict):
            raise ValueError('WAR_RELATIONS_UPSTREAM_FIELD_INVALID')
        if field.get('status') != 'known':
            status, reason = field.get('status'), field.get('reason')
            safe = NativeCountryScaleSource._safe_reason(reason, '')
            if status not in _STATES or not safe or safe != reason:
                raise ValueError('WAR_RELATIONS_UPSTREAM_STATE_INVALID')
            return {'status': status, 'reason': safe, 'complete': False}
        projected = NativeCountryScaleSource._project_value('wars', field)
        if projected.get('status') != 'known':
            raise ValueError('WAR_RELATIONS_UPSTREAM_VALUE_INVALID')
        return projected

    def read(self, query, context=None):
        query = self.validate_query(query, context)
        before = self.context()
        anchor_game_date = context.get('game_date') if isinstance(context, dict) else before.get('game_date')
        fields = {name: {'status': 'unsupported', 'reason': 'R03_FIELD_NOT_IMPLEMENTED'}
                  for name in query['fields']}
        provenance = {'delegated_topic': 'F01', 'delegated_field': 'wars',
                      'shared_reader': 'NativeCountryScaleSource', 'read_only': True,
                      'global_war_enumeration': False, 'war_lifetime_verified': False}
        if 'wars' in fields:
            if query['object']['type'] != 'country':
                fields['wars'] = {'status': 'unsupported', 'reason': 'WAR_RELATIONS_PAIR_VIEW_NOT_IMPLEMENTED'}
            elif context is not None and _identity(context) != _identity(before):
                fields['wars'] = {'status': 'unavailable', 'reason': 'WAR_RELATIONS_CONTEXT_MISMATCH'}
            else:
                try:
                    upstream = self.country_scale_source.read(self._mapped(query), context)
                    source = upstream.get('source')
                    if (not isinstance(source, dict) or source.get('name') != 'NativeCountryScaleSource'
                            or any(source.get(key) != before.get(key) for key in ('mode', 'observer', 'session_id'))
                            or type(upstream.get('game_date')) is not int
                            or upstream.get('objects') != [query['object']]
                            or upstream.get('complete') is not False):
                        raise ValueError('WAR_RELATIONS_UPSTREAM_IDENTITY_INVALID')
                    if not dates_match(before.get('game_date'), upstream.get('game_date')):
                        raise ValueError('WAR_RELATIONS_UPSTREAM_DATE_INVALID')
                    projected = self._project(upstream.get('fields', {}).get('wars'))
                    report_hash = source.get('provenance', {}).get('capture_report_sha256')
                    if projected['status'] == 'known':
                        if not isinstance(report_hash, str) or _SHA.fullmatch(report_hash) is None:
                            raise ValueError('WAR_RELATIONS_UPSTREAM_EVIDENCE_MISSING')
                        provenance['capture_report_sha256'] = report_hash
                    provenance['upstream_source'] = {key: deepcopy(source.get(key)) for key in
                                                     ('name', 'mode', 'status', 'session_id', 'observer', 'complete')}
                    fields['wars'] = projected
                except Exception:
                    fields['wars'] = {'status': 'unavailable', 'reason': 'WAR_RELATIONS_UPSTREAM_READ_INVALID'}
        if 'wars' in fields and query['object']['type'] == 'country':
            after = self.context()
            if (_identity(after) != _identity(before) or
                    not dates_match(anchor_game_date, before.get('game_date'),
                                    after.get('game_date'))):
                fields['wars'] = {'status': 'unavailable', 'reason': 'WAR_RELATIONS_CONTEXT_CHANGED_DURING_READ'}
        source = _source_info(type(self).__name__, before, complete=False, provenance=provenance)
        source['context_scope'] = 'visible_scope'
        return _result(query, before, fields, False, source)

    def poll_events(self, context, cursor):
        return {'events': [], 'cursor': deepcopy(cursor or {}), 'complete': True, 'gaps': []}


__all__ = ['NativeWarRelationsSource']
