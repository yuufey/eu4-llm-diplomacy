"""H02 history of observed diplomatic-contact cooldown deadlines."""
from copy import deepcopy

from . import cooldown_expiry as observation
from .catalog import get_topic, validate_query
from .model import InformationError
from .sources import _result, _source_info

FIELD = 'cooldown_expiry'


class CooldownExpiryHistorySource:
    event_types = ()

    def __init__(self, base_source, *, history_reader=None):
        self.base_source = base_source
        self.history_reader = history_reader

    def context(self):
        return deepcopy(self.base_source.context())

    def catalog(self):
        topic = get_topic('H02')
        topic['fields'] = {FIELD: {
            'coverage': 'partial', 'complete': True, 'source': type(self).__name__,
            'unit': 'cooldown_expiry_events', 'period': 'observed_history',
            'description': 'A01已明确观察的外交官联络等待期限到期，按方向性的国家对记录。',
            'event_filter': {'types': [observation.EVENT_TYPE]},
        }}
        topic.update(source=type(self).__name__, context_scope='recorded',
                     observer_roles=['actor', 'recipient'])
        return [topic]

    def validate_query(self, query, context=None):
        normalized = validate_query(query, context)
        if normalized['topic'] != 'H02':
            raise InformationError('unsupported_topic', 'Cooldown expiry history supports H02 only')
        return normalized

    @staticmethod
    def _legacy(query):
        return any(key in query['parameters'] for key in ('request_id', 'case'))

    @staticmethod
    def _matches(obj, payload):
        if obj['type'] == 'country':
            return obj['country'] in (payload['actor'], payload['recipient'])
        if obj['type'] == 'country_pair':
            return (obj['actor'], obj['recipient']) == (payload['actor'], payload['recipient'])
        return True

    def _read(self, query, context, event=None):
        context = deepcopy(context) if context is not None else self.context()
        query = self.validate_query(query, context)
        if self._legacy(query):
            return (self.base_source.read(query, context) if event is None
                    else self.base_source.replay_event(query, context, event))
        if event is not None:
            batch = {'events': [event], 'complete': True, 'gaps': []}
        elif callable(self.history_reader):
            batch = self.history_reader(context, event_types=[observation.EVENT_TYPE],
                                        limit=query['parameters'].get('limit', 50),
                                        cursor=query['parameters'].get('cursor'))
        else:
            raise InformationError('EVENT_HISTORY_READER_NOT_BOUND', 'Cooldown history reader is missing')
        rows = []
        kind = query['parameters'].get('event_type', observation.EVENT_TYPE)
        for snapshot in batch['events'] if kind == observation.EVENT_TYPE else []:
            if snapshot.get('event_type') != observation.EVENT_TYPE:
                continue
            if not observation.valid_event_snapshot(snapshot, context):
                raise InformationError('COOLDOWN_EXPIRY_SNAPSHOT_INVALID', 'Invalid recorded cooldown expiry')
            payload = snapshot['payload']
            if self._matches(query['object'], payload):
                rows.append({'event_id': snapshot['event_id'], 'event_type': observation.EVENT_TYPE,
                             'actor': payload['actor'], 'recipient': payload['recipient'],
                             'cooldown': payload['cooldown'],
                             'available_on': {'status': 'known', 'value': snapshot['game_date'],
                                              'unit': 'game_date_raw'}})
        field = {'status': 'known', 'value': rows, 'complete': batch['complete'],
                 'gaps': deepcopy(batch['gaps']), 'unit': 'cooldown_expiry_events'}
        if batch.get('next_cursor'):
            field['next_cursor'] = batch['next_cursor']
        fields = {name: (field if name == FIELD else {'status': 'unsupported', 'reason': 'H02_FIELD_NOT_IMPLEMENTED'})
                  for name in query['fields']}
        complete = all(value.get('complete') is True for value in fields.values())
        source = _source_info(type(self).__name__, context, complete=complete)
        source.update(coverage=observation.SCOPE, projection='event_snapshot' if event else 'persisted_event_history')
        if event is not None:
            source.update(event_id=event['event_id'], date_semantics=observation.DATE_SEMANTICS)
            context['game_date'] = event['game_date']
        return _result(query, context, fields, complete, source)

    def read(self, query, context=None):
        return self._read(query, context)

    def read_event(self, query, context, event):
        query = self.validate_query(query, context)
        if self._legacy(query):
            return self.base_source.read_event(query, context, event)
        return self._read(query, context, event)

    def replay_event(self, query, context, event):
        return self._read(query, context, event)

    def poll_events(self, context, cursor):
        return {'events': [], 'cursor': deepcopy(cursor or {}), 'complete': True, 'gaps': []}
