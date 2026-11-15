"""H02 directional direct-truce expiries from validated native snapshots."""
from copy import deepcopy

from .. import truce_expiry_observation as observation
from .catalog import get_topic, validate_query
from .model import InformationError
from .sources import _result, _source_info


FIELD = 'truce_expiry'
_C04_FIELDS = ['event_id', 'event_type', 'event_date', 'event_payload']


def _date(raw):
    return {'status': 'known', 'value': raw, 'unit': 'game_date_raw'}


class NativeTruceExpiryHistorySource:
    event_types = ()

    def __init__(self, base_source, *, history_reader=None):
        self.base_source = base_source
        self.history_reader = history_reader

    def context(self):
        return deepcopy(self.base_source.context())

    def catalog(self):
        topic = get_topic('H02')
        topic.update(source=type(self).__name__, context_scope='recorded',
                     observer_roles=['actor', 'recipient'], observer_scope=['FRA'])
        topic['fields'] = {FIELD: {
            'coverage': 'available', 'complete': True, 'source': type(self).__name__,
            'unit': 'truce_expiry_events', 'period': 'observed_history',
            'direction': 'actor_to_recipient',
            'native_source_available': observation.EVENT_TYPE in self.base_source.event_types,
            'description': '已采集的FRA参与国家对中，指定方向直接停战记录的自然到期。',
            'event_filter': {'types': [observation.EVENT_TYPE]},
        }}
        return [topic]

    def validate_query(self, query, context=None):
        normalized = validate_query(query, context)
        if normalized['topic'] != 'H02':
            raise InformationError('unsupported_topic', 'Truce expiry history supports H02 only')
        return normalized

    @staticmethod
    def _legacy(query):
        return any(key in query['parameters'] for key in ('request_id', 'case'))

    @staticmethod
    def _matches(obj, payload):
        if obj['type'] == 'country':
            return obj['country'] in (payload['actor'], payload['recipient'])
        if obj['type'] == 'country_pair':
            return obj['actor'] == payload['actor'] and obj['recipient'] == payload['recipient']
        return True

    def _row(self, obj, context, event):
        if event.get('event_type') != observation.EVENT_TYPE:
            return None
        mapped = {'topic': 'C04', 'object': {'type': 'session'},
                  'fields': list(_C04_FIELDS), 'parameters': {'event_type': observation.EVENT_TYPE}}
        projected = self.base_source.replay_event(mapped, context, event)
        fields = projected.get('fields', {})
        if (projected.get('complete') is not True
                or any(fields.get(name, {}).get('status') != 'known' for name in _C04_FIELDS)):
            raise InformationError('TRUCE_EXPIRY_SNAPSHOT_INVALID',
                                   'The existing C04 snapshot projection did not validate the expiry')
        payload = fields['event_payload']['value']
        if not self._matches(obj, payload):
            return None
        return {'event_id': fields['event_id']['value'], 'event_type': fields['event_type']['value'],
                'actor': payload['actor'], 'recipient': payload['recipient'],
                'end_date': _date(payload['end_date_raw']),
                'event_date': _date(fields['event_date']['value'])}

    def _native(self, query, context, event=None):
        if context.get('observer') != 'FRA':
            return {'status': 'unavailable', 'reason': 'TRUCE_EXPIRY_OBSERVER_SCOPE_MISMATCH'}
        if query['parameters'].get('event_type', observation.EVENT_TYPE) != observation.EVENT_TYPE:
            return {'status': 'known', 'value': [], 'complete': True}
        if event is not None:
            batch = {'events': [event], 'complete': True, 'gaps': []}
        else:
            if not callable(self.history_reader):
                return {'status': 'unavailable', 'reason': 'EVENT_HISTORY_READER_NOT_BOUND'}
            batch = self.history_reader(context, event_types=[observation.EVENT_TYPE],
                                        limit=query['parameters'].get('limit', 50),
                                        cursor=query['parameters'].get('cursor'))
        rows = [row for snapshot in batch['events']
                if (row := self._row(query['object'], context, snapshot)) is not None]
        field = {'status': 'known', 'value': rows, 'unit': 'truce_expiry_events',
                 'complete': batch['complete'], 'gaps': deepcopy(batch['gaps'])}
        if batch.get('next_cursor'):
            field['next_cursor'] = batch['next_cursor']
        return field

    def _read(self, query, context, event=None):
        current = deepcopy(context) if context is not None else self.context()
        query = self.validate_query(query, current)
        if self._legacy(query):
            return (self.base_source.read(query, current) if event is None
                    else self.base_source.replay_event(query, current, event))
        fields = {name: {'status': 'unsupported', 'reason': 'H02_FIELD_NOT_IMPLEMENTED'}
                  for name in query['fields']}
        if FIELD in fields:
            fields[FIELD] = self._native(query, current, event)
        complete = all(field.get('status') == 'known' and field.get('complete') is True
                       for field in fields.values())
        source = _source_info(type(self).__name__, current, complete=complete)
        source.update(projection='event_snapshot' if event is not None else 'persisted_event_history',
                      coverage=observation.SCOPE, direction='actor_to_recipient')
        if event is not None:
            source.update(event_id=event.get('event_id'), collected_game_date=current.get('game_date'),
                          date_semantics=observation.DATE_SEMANTICS)
            current['game_date'] = event.get('game_date')
        return _result(query, current, fields, complete, source)

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
