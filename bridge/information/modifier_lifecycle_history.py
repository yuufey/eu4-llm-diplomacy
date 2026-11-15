"""H02 history and event views of the existing C04 modifier snapshots."""
from copy import deepcopy

from .. import country_modifier_observation as observation
from .catalog import get_topic, validate_query
from .model import InformationError
from .sources import _result, _source_info


FIELD = 'modifier_lifecycle'
EVENT_TYPES = tuple(observation.EVENT_SEMANTICS)
_C04_FIELDS = ['event_id', 'event_type', 'event_date', 'event_payload']
_UNSET_DATES = (0x29C77F8, 43800000)


def _date(raw):
    return {'status': 'known', 'value': raw, 'unit': 'game_date_raw'}


class NativeModifierLifecycleHistorySource:
    event_types = ()

    def __init__(self, base_source, *, history_reader=None):
        self.base_source = base_source
        self.history_reader = history_reader

    def context(self):
        return deepcopy(self.base_source.context())

    def catalog(self):
        topic = get_topic('H02')
        topic.update(source=type(self).__name__, context_scope='session_scope',
                     observer_roles=['country'], observer_scope=['FRA'],
                     scope_note='当前会话已采集的FRA直接临时国家修正新增、移除及自然到期事件。')
        topic['fields'] = {FIELD: {
            'coverage': 'partial', 'source': type(self).__name__,
            'unit': 'modifier_lifecycle', 'period': 'observed_history',
            'paths': ['C04.event_payload'],
            'description': '最近优先的修正生命周期记录，事件日期为原生实际发生日。',
        }}
        return [topic]

    def validate_query(self, query, context=None):
        normalized = validate_query(query, context)
        if normalized['topic'] != 'H02':
            raise InformationError('unsupported_topic', 'Modifier lifecycle history supports H02 only')
        return normalized

    @staticmethod
    def _legacy(query):
        return any(key in query['parameters'] for key in ('request_id', 'case'))

    @staticmethod
    def _scope_reason(query, context):
        obj = query['object']
        if obj['type'] == 'country_pair':
            return 'MODIFIER_LIFECYCLE_COUNTRY_PAIR_NOT_APPLICABLE'
        if context.get('observer') != 'FRA' or (
                obj['type'] == 'country' and obj['country'] != 'FRA'):
            return 'MODIFIER_LIFECYCLE_COUNTRY_NOT_OBSERVED'
        kind = query['parameters'].get('event_type')
        if kind is not None and kind not in EVENT_TYPES:
            return 'MODIFIER_LIFECYCLE_EVENT_TYPE_NOT_APPLICABLE'
        return None

    @staticmethod
    def _result(query, context, field, *, projection, event=None, gaps=None):
        fields = {name: {'status': 'unsupported', 'reason': 'H02_FIELD_NOT_IMPLEMENTED'}
                  for name in query['fields']}
        if FIELD in fields:
            fields[FIELD] = field
        complete = all(value.get('status') == 'known' and value.get('complete') is True
                       for value in fields.values())
        source = _source_info('NativeModifierLifecycleHistorySource', context, complete=complete)
        source.update(projection=projection, coverage=observation.SCOPE)
        if gaps:
            source['gaps'] = deepcopy(gaps)
        if event is not None:
            source.update(event_id=event.get('event_id'),
                          collected_game_date=context.get('game_date'),
                          date_semantics=event.get('source', {}).get('date_semantics'))
            context = dict(context, game_date=event.get('game_date'))
        return _result(query, context, fields, complete, source)

    def _project_event(self, event, context):
        query = {'topic': 'C04', 'object': {'type': 'session'},
                 'fields': list(_C04_FIELDS),
                 'parameters': {'event_type': event.get('event_type')}}
        projected = self.base_source.replay_event(query, context, event)
        fields = projected.get('fields', {})
        if (projected.get('complete') is not True
                or any(fields.get(name, {}).get('status') != 'known' for name in _C04_FIELDS)):
            raise InformationError('MODIFIER_LIFECYCLE_SNAPSHOT_INVALID',
                                   'The existing C04 snapshot projection did not validate the event')
        payload = fields['event_payload']['value']
        row = {name: deepcopy(payload[name]) for name in ('country', 'modifier_id', 'change')}
        row.update(event_id=fields['event_id']['value'], event_type=fields['event_type']['value'],
                   event_date=_date(fields['event_date']['value']))
        for name in ('start', 'end'):
            raw = payload[name + '_date_raw']
            row[name + '_date'] = None if raw in _UNSET_DATES else _date(raw)
        return row

    def read(self, query, context=None):
        query = self.validate_query(query, context)
        context = deepcopy(context) if context is not None else self.context()
        if self._legacy(query):
            return self.base_source.read(query, context)
        reason = self._scope_reason(query, context)
        if reason:
            return self._result(query, context, {'status': 'not_applicable', 'reason': reason},
                                projection='persisted_event_history')
        if not callable(self.history_reader):
            return self._result(query, context, {
                'status': 'unavailable', 'reason': 'MODIFIER_LIFECYCLE_HISTORY_READER_REQUIRED'},
                projection='persisted_event_history')
        params = query['parameters']
        types = (params['event_type'],) if 'event_type' in params else EVENT_TYPES
        try:
            history = self.history_reader(context, event_types=types,
                                          limit=params.get('limit', 50), cursor=params.get('cursor'))
            rows = [self._project_event(event, context) for event in history['events']]
        except InformationError:
            raise
        except Exception as exc:
            raise InformationError('MODIFIER_LIFECYCLE_HISTORY_READ_FAILED',
                                   'The persisted modifier history could not be read') from exc
        field = {'status': 'known', 'value': rows, 'unit': 'modifier_lifecycle',
                 'complete': history['complete'], 'next_cursor': history['next_cursor']}
        return self._result(query, context, field, projection='persisted_event_history',
                            gaps=history['gaps'])

    def read_event(self, query, context, event):
        query = self.validate_query(query, context)
        if self._legacy(query):
            return self.base_source.read_event(query, context, event)
        return self.replay_event(query, context, event)

    def replay_event(self, query, context, event):
        query = self.validate_query(query, context)
        if self._legacy(query):
            return self.base_source.replay_event(query, context, event)
        reason = self._scope_reason(query, context)
        if reason:
            return self._result(query, context, {'status': 'not_applicable', 'reason': reason},
                                projection='event_snapshot')
        kind = event.get('event_type')
        if kind not in EVENT_TYPES:
            return self._result(query, context, {
                'status': 'known', 'value': [], 'unit': 'modifier_lifecycle', 'complete': True},
                projection='event_snapshot', event=event)
        row = self._project_event(event, context)
        rows = [row] if query['parameters'].get('event_type', kind) == kind else []
        return self._result(query, context, {
            'status': 'known', 'value': rows, 'unit': 'modifier_lifecycle', 'complete': True},
            projection='event_snapshot', event=event)

    def poll_events(self, context, cursor):
        return {'events': [], 'cursor': deepcopy(cursor or {}), 'complete': True, 'gaps': []}
