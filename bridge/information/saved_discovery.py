"""Expose the observer's discovery list from a dated EU4 save.

The existing province snapshot owns parsing, validation and file freshness.
This adapter shares that snapshot with the G01 owner; no parser is launched
by a discovery query and no other country's exploration view is exported.
"""
from __future__ import annotations

from copy import deepcopy
import re

from .catalog import get_topic
from .model import InformationError
from .sources import _result, _source_info


FIELD = 'discovered_provinces'
_FIELDS = frozenset(get_topic('C02')['fields'])
_TAG = re.compile(r'[A-Z0-9]{3}\Z')


class SavedProvinceDiscoverySource:
    event_types = ()

    def __init__(self, snapshot):
        self.snapshot = snapshot

    def context(self):
        return deepcopy(self.snapshot.context())

    def catalog(self):
        topic = get_topic('C02')
        topic.update(source=type(self).__name__, status='available',
                     visibility='observer_snapshot_discovery', context_scope='saved_snapshot',
                     supported_versions=['1.37.4'], triggers=['query'], observer_roles=[],
                     object_semantics='session_or_bound_observer_country',
                     parameters={'type': 'object', 'properties': {},
                                 'additionalProperties': False})
        topic['fields'] = {FIELD: {
            'source': type(self).__name__, 'coverage': 'partial', 'complete': False,
            'unit': 'province_id', 'scale': 1, 'period': 'saved_snapshot',
            'value_origin': 'jomini_eu4save_snapshot',
            'basis': 'saved_province.discovered_by',
            'supported_object_types': ['session', 'country'],
            'description': '保存时明确记录为观察国已发现的省份ID；不切换为其他国家视角。',
            'detail_fields': ['snapshot_membership_complete', 'omitted_unknown_discovery_records'],
            'gaps': ['HISTORICAL_SNAPSHOT_NOT_LIVE', 'COMPLETE_UI_VISIBILITY_NOT_VERIFIED',
                     'MISSING_DISCOVERY_RECORDS_REMAIN_UNKNOWN',
                     'LIVE_SESSION_BOUND_PERIODIC_SOURCE_NOT_IMPLEMENTED'],
        }}
        return [topic]

    def validate_query(self, query, context=None):
        if (not isinstance(query, dict)
                or not {'topic', 'object', 'fields'} <= set(query)
                or set(query) - {'topic', 'object', 'fields', 'parameters'}):
            raise InformationError('invalid_parameters', 'C02 query has missing or unknown keys')
        if query['topic'] != 'C02':
            raise InformationError('unsupported_topic', 'Saved discovery supports C02 only')
        obj = query['object']
        valid = isinstance(obj, dict) and obj == {'type': 'session'}
        if isinstance(obj, dict) and obj.get('type') == 'country':
            valid = (set(obj) == {'type', 'country'} and isinstance(obj.get('country'), str)
                     and _TAG.fullmatch(obj['country']) is not None)
        if not valid:
            raise InformationError('invalid_object', 'C02 requires the saved session or a country selector')
        fields = query['fields']
        if (not isinstance(fields, list) or not fields
                or any(not isinstance(name, str) or name not in _FIELDS for name in fields)
                or len(fields) != len(set(fields))):
            raise InformationError('invalid_fields', 'C02 requires unique declared fields')
        if not isinstance(query.get('parameters', {}), dict) or query.get('parameters', {}):
            raise InformationError('invalid_parameters', 'C02 snapshot parameters must be empty')
        return {'topic': 'C02', 'object': deepcopy(obj), 'fields': list(fields), 'parameters': {}}

    @staticmethod
    def _project(value):
        """Copy contracted data only, including from injected test backends."""
        if not isinstance(value, dict) or value.get('status') not in ('known', 'unknown'):
            raise ValueError('SAVED_DISCOVERY_PROJECTION_STATUS')
        missing = value.get('omitted_unknown_discovery_records')
        complete = value.get('snapshot_membership_complete')
        if (type(missing) is not int or not 0 <= missing <= 65535
                or type(complete) is not bool or complete != (missing == 0)):
            raise ValueError('SAVED_DISCOVERY_PROJECTION_COMPLETENESS')
        result = {'status': value['status'], 'unit': 'province_id', 'scale': 1,
                  'period': 'saved_snapshot', 'complete': False,
                  'basis': 'saved_province.discovered_by',
                  'snapshot_membership_complete': complete,
                  'omitted_unknown_discovery_records': missing}
        if value['status'] == 'known':
            ids = value.get('value')
            if (not isinstance(ids, list) or len(ids) > 65535
                    or any(type(pid) is not int or not 1 <= pid <= 65535 for pid in ids)
                    or len(ids) != len(set(ids)) or (not ids and missing)):
                raise ValueError('SAVED_DISCOVERY_PROJECTION_IDS')
            result['value'] = sorted(ids)
        elif missing and value.get('reason') == 'SNAPSHOT_DISCOVERY_NOT_ESTABLISHED':
            result['reason'] = value['reason']
        else:
            raise ValueError('SAVED_DISCOVERY_PROJECTION_UNKNOWN')
        return result

    def read(self, query, context=None):
        query = self.validate_query(query, context)
        before = self.context()
        fields = {name: {'status': 'unsupported', 'reason': 'SAVED_DISCOVERY_FIELD_NOT_IMPLEMENTED'}
                  for name in query['fields']}
        if FIELD in fields:
            obj = query['object']
            if context is not None and context != before:
                item = {'status': 'unavailable', 'reason': 'SAVED_DISCOVERY_CONTEXT_MISMATCH'}
            elif before.get('status') != 'ready' or before.get('mode') != 'recorded':
                item = {'status': 'unavailable', 'reason': 'SAVED_DISCOVERY_SOURCE_UNREADY'}
            elif obj['type'] == 'country' and obj['country'] != before.get('observer'):
                item = {'status': 'not_applicable', 'reason': 'OBSERVER_DISCOVERY_VIEW_ONLY'}
            else:
                try:
                    item = self._project(self.snapshot.discovered_provinces())
                except (OSError, ValueError):
                    item = {'status': 'unavailable', 'reason': 'SAVED_DISCOVERY_INPUT_OR_PROJECTION_CHANGED'}
            fields[FIELD] = item
        if self.context() != before and FIELD in fields:
            fields[FIELD] = {'status': 'unavailable', 'reason': 'SAVED_DISCOVERY_INPUT_OR_PARSER_CHANGED'}
        source = _source_info(type(self).__name__, before, mode='recorded', complete=False,
                              provenance={'archive': deepcopy(before['archive']),
                                          'parser': deepcopy(before['parser']),
                                          'live_state_observed': False,
                                          'view_country': before['observer']})
        source['context_scope'] = 'saved_snapshot'
        return _result(query, before, fields, False, source)

    def poll_events(self, context, cursor):
        return {'events': [], 'cursor': deepcopy(cursor or {}), 'complete': True, 'gaps': []}


__all__ = ['SavedProvinceDiscoverySource']
