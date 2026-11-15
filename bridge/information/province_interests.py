"""Query cores and claims from an explicit, visibility-filtered save snapshot."""
from __future__ import annotations

from copy import deepcopy
import re

from .catalog import get_topic, list_topics
from .model import InformationError
from .sources import _field_result, _result, _source_info, validate_query


class SavedProvinceInterestsSource:
    event_types = ()

    def __init__(self, snapshot):
        self.snapshot = snapshot

    def context(self):
        return self.snapshot.context()

    def catalog(self):
        topics = list_topics()
        for topic in topics:
            topic['triggers'] = ['query']
            topic['status'] = 'planned'
            for field in topic['fields'].values():
                field['coverage'] = 'planned'
            if topic['topic_id'] == 'C01':
                topic.update(source=type(self).__name__, status='available')
                for name in ('observer', 'game_date', 'game_version', 'status'):
                    topic['fields'][name].update(source=type(self).__name__, coverage='available')
            elif topic['topic_id'] == 'G01':
                topic.update(source=type(self).__name__, status='available', visibility='visible_scope',
                             context_scope='saved_snapshot', supported_versions=['1.37.4'])
                topic['parameters'] = {'type': 'object', 'properties': {}, 'additionalProperties': False}
                for name in ('cores', 'claims'):
                    topic['fields'][name] = {
                        'coverage': 'partial', 'source': type(self).__name__, 'complete': False,
                        'period': 'saved_snapshot', 'scale': 1,
                        'value_origin': 'jomini_eu4save_snapshot',
                        'basis': 'saved_province_current_membership',
                        'supported_object_types': ['province', 'country'],
                        'units_by_object_type': {'province': 'country_tag', 'country': 'province_id'},
                        'visibility': 'positive_snapshot_discovered_by',
                        'description': ('保存时省份核心归属；国家查询仅列观察方已发现省份。' if name == 'cores'
                                        else '保存时省份宣称归属；不区分永久宣称或解释到期时间。'),
                        'gaps': ['HISTORICAL_SNAPSHOT_NOT_LIVE', 'COMPLETE_UI_VISIBILITY_NOT_VERIFIED',
                                 'CLAIM_EXPIRY_AND_PERMANENCE_NOT_CAPTURED'],
                    }
        return topics

    def validate_query(self, query, context=None):
        normalized = validate_query(query, context)
        if normalized['topic'] != 'G01':
            return normalized
        obj = normalized['object']
        if obj.get('type') == 'province':
            valid = (set(obj) == {'type', 'province_id'} and type(obj.get('province_id')) is int
                     and 1 <= obj['province_id'] <= 65535)
        elif obj.get('type') == 'country':
            valid = (set(obj) == {'type', 'country'} and isinstance(obj.get('country'), str)
                     and re.fullmatch(r'[A-Z0-9]{3}', obj['country']) is not None)
        else:
            valid = False
        if not valid:
            raise InformationError('invalid_object', 'G01 requires an explicit province or country')
        if normalized.get('parameters', {}) != {}:
            raise InformationError('invalid_parameters', 'G01 snapshot parameters must be empty')
        return normalized

    def read(self, query, context=None):
        query = self.validate_query(query, context)
        current = self.context()
        if query['topic'] == 'C01':
            fields, complete = _field_result(query['fields'], current, get_topic('C01'))
        elif query['topic'] == 'G01':
            fields = {}
            for name in query['fields']:
                if current['status'] != 'ready':
                    fields[name] = {'status': 'unavailable', 'reason': 'SAVED_INTERESTS_SOURCE_UNREADY'}
                else:
                    try:
                        fields[name] = self.snapshot.lookup(query['object'], name)
                    except (OSError, ValueError):
                        fields[name] = {'status': 'unavailable', 'reason': 'SAVED_INTERESTS_INPUT_CHANGED'}
            after = self.context()
            if after != current:
                fields = {name: {'status': 'unavailable', 'reason': 'SAVED_INTERESTS_INPUT_CHANGED'}
                          for name in fields}
            complete = False
        else:
            fields = {name: {'status': 'unsupported', 'reason': 'TOPIC_NOT_ADAPTED'}
                      for name in query['fields']}
            complete = False
        source = _source_info(type(self).__name__, current, mode='recorded', complete=complete,
                              provenance={'archive': deepcopy(current['archive']),
                                          'parser': deepcopy(current['parser']),
                                          'live_state_observed': False})
        source['context_scope'] = 'saved_snapshot'
        return _result(query, current, fields, complete, source)

    def poll_events(self, context, cursor):
        return {'events': [], 'cursor': deepcopy(cursor or {}), 'complete': True, 'gaps': []}


__all__ = ['SavedProvinceInterestsSource']
