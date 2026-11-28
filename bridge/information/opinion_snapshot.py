"""Read stored opinion-modifier records for pairs involving the observer."""
from __future__ import annotations

from copy import deepcopy
import re

from .catalog import get_topic, list_topics
from .model import InformationError
from .saved_opinions import _record
from .sources import _field_result, _result, _source_info, validate_query

FIELD = 'opinion_modifiers'
_TAG = re.compile(r'[A-Z0-9]{3}\Z')


class SavedOpinionSource:
    event_types = ()

    def __init__(self, snapshot):
        self.snapshot = snapshot

    def context(self):
        return deepcopy(self.snapshot.context())

    def catalog(self):
        topics = list_topics()
        for topic in topics:
            topic.update(status='planned', triggers=['query'])
            for field in topic['fields'].values():
                field['coverage'] = 'planned'
            if topic['topic_id'] == 'C01':
                topic.update(status='available', source=type(self).__name__,
                             supported_versions=['1.37.4'], context_scope='saved_snapshot')
                for name in ('observer', 'game_date', 'game_version', 'status'):
                    topic['fields'][name].update(coverage='available', source=type(self).__name__)
            elif topic['topic_id'] == 'R04':
                topic.update(status='available', source=type(self).__name__,
                             supported_versions=['1.37.4'], context_scope='saved_snapshot',
                             visibility='observer_involved_snapshot_pair',
                             observer_roles=['actor', 'recipient'],
                             parameters={'type': 'object', 'properties': {}, 'additionalProperties': False})
                topic['fields'][FIELD] = {
                    'source': type(self).__name__, 'coverage': 'partial', 'complete': False,
                    'unit': 'directed_saved_opinion_modifiers', 'scale': 1, 'period': 'saved_snapshot',
                    'basis': 'saved_country.active_relations.opinion',
                    'value_origin': 'jomini_eu4save_snapshot', 'supported_object_types': ['country_pair'],
                    'description': '观察国参与的国家对中，两个方向各条好感修正的保存记录；不表示最终好感。',
                    'detail_fields': ['modifier_id', 'recorded_date', 'current_opinion_decimal', 'expiry_date_flag'],
                    'gaps': ['HISTORICAL_SNAPSHOT_NOT_LIVE', 'FINAL_OPINION_NOT_EVALUATED',
                             'DECAY_AND_END_DATE_NOT_EVALUATED', 'COMPLETE_UI_VISIBILITY_NOT_VERIFIED',
                             'RELATIONS_WITHOUT_STORED_OPINIONS_OMITTED'],
                }
        return topics

    def validate_query(self, query, context=None):
        normalized = validate_query(query, context)
        if normalized['topic'] != 'R04':
            return normalized
        obj = normalized['object']
        if (not isinstance(obj, dict) or set(obj) != {'type', 'actor', 'recipient'}
                or obj.get('type') != 'country_pair'
                or any(not isinstance(obj.get(key), str) or _TAG.fullmatch(obj[key]) is None
                       for key in ('actor', 'recipient')) or obj['actor'] == obj['recipient']):
            raise InformationError('invalid_object', 'R04 requires two distinct explicit country tags')
        if normalized.get('parameters', {}) != {}:
            raise InformationError('invalid_parameters', 'R04 snapshot parameters must be empty')
        return normalized

    @staticmethod
    def _project(value, obj):
        if not isinstance(value, dict) or value.get('status') not in ('known', 'unknown'):
            raise ValueError('SAVED_OPINION_PROJECTION_STATUS')
        known = value['status'] == 'known'
        directions = value.get('value' if known else 'directions')
        if not isinstance(directions, list) or len(directions) != 2:
            raise ValueError('SAVED_OPINION_PROJECTION_DIRECTIONS')
        expected = ((obj['actor'], obj['recipient']), (obj['recipient'], obj['actor']))
        copied = []
        for row, (holder, target) in zip(directions, expected):
            if (not isinstance(row, dict) or row.get('holder') != holder or row.get('target') != target
                    or row.get('status') not in ('known', 'unknown')):
                raise ValueError('SAVED_OPINION_PROJECTION_PAIR')
            item = {'holder': holder, 'target': target, 'status': row['status']}
            if row['status'] == 'known':
                records = row.get('records')
                if not isinstance(records, list) or not 1 <= len(records) <= 65536:
                    raise ValueError('SAVED_OPINION_PROJECTION_RECORDS')
                item['records'] = [_record({
                    'modifier': record['modifier_id'], 'date': record['recorded_date'],
                    'current_opinion': record['current_opinion_decimal'],
                    'expiry_date': record['expiry_date_flag'],
                }) for record in records]
            else:
                if row.get('reason') not in ('COUNTRY_NOT_IN_SNAPSHOT', 'SAVED_ACTIVE_RELATIONS_NOT_CAPTURED',
                                            'SAVED_RELATION_NOT_RECORDED', 'SAVED_OPINION_RECORDS_NOT_ESTABLISHED'):
                    raise ValueError('SAVED_OPINION_PROJECTION_REASON')
                item['reason'] = row['reason']
            copied.append(item)
        if known != any(row['status'] == 'known' for row in copied):
            raise ValueError('SAVED_OPINION_PROJECTION_COMPLETENESS')
        result = {'status': value['status'], 'unit': 'directed_saved_opinion_modifiers',
                  'scale': 1, 'period': 'saved_snapshot', 'complete': False,
                  'basis': 'saved_country.active_relations.opinion'}
        if known:
            result['value'] = copied
        else:
            result.update(reason='SAVED_OPINION_RELATIONS_NOT_ESTABLISHED', directions=copied)
        return result

    def read(self, query, context=None):
        query = self.validate_query(query, context)
        before = self.context()
        complete = False
        if query['topic'] == 'C01':
            fields, complete = _field_result(query['fields'], before, get_topic('C01'))
        else:
            fields = {name: {'status': 'unsupported', 'reason': 'SAVED_OPINION_FIELD_NOT_IMPLEMENTED'}
                      for name in query['fields']}
        if query['topic'] == 'R04' and FIELD in fields:
            obj = query['object']
            if context is not None and context != before:
                item = {'status': 'unavailable', 'reason': 'SAVED_OPINION_CONTEXT_MISMATCH'}
            elif before.get('status') != 'ready':
                item = {'status': 'unavailable', 'reason': 'SAVED_OPINION_SOURCE_UNREADY'}
            elif before['observer'] not in (obj['actor'], obj['recipient']):
                item = {'status': 'not_applicable', 'reason': 'OBSERVER_COUNTRY_PAIR_REQUIRED'}
            else:
                try:
                    item = self._project(self.snapshot.lookup_pair(obj), obj)
                except (OSError, ValueError, KeyError, TypeError):
                    item = {'status': 'unavailable', 'reason': 'SAVED_OPINION_INPUT_OR_PROJECTION_CHANGED'}
            fields[FIELD] = item
        if self.context() != before and query['topic'] == 'R04' and FIELD in fields:
            fields[FIELD] = {'status': 'unavailable', 'reason': 'SAVED_OPINION_INPUT_OR_PARSER_CHANGED'}
        source = _source_info(type(self).__name__, before, mode='recorded', complete=complete,
                              provenance={'archive': deepcopy(before['archive']),
                                          'parser': deepcopy(before['parser']),
                                          'live_state_observed': False,
                                          'final_opinion_evaluated': False,
                                          'decay_or_end_date_evaluated': False})
        source['context_scope'] = 'saved_snapshot'
        return _result(query, before, fields, complete, source)

    def poll_events(self, context, cursor):
        return {'events': [], 'cursor': deepcopy(cursor or {}), 'complete': True, 'gaps': []}


__all__ = ['SavedOpinionSource']
