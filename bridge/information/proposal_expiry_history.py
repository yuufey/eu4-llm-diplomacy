"""H02 expiry history projected from the already-admitted proposal snapshots."""
from copy import deepcopy

from ..proposal_expiry import ended_lifecycle
from .catalog import get_topic, validate_query
from .model import InformationError
from .sources import _result, _source_info


FIELD = 'proposal_expiry'
LEGACY_FIELDS = ()
PROPOSAL_FIELDS = ['proposal_id', 'action_id', 'actor', 'recipient', 'proposal_status', 'currently_pending']


class NativeProposalExpiryHistorySource:
    event_types = ()

    def __init__(self, base_source, *, history_reader=None):
        self.base_source = base_source
        self.history_reader = history_reader

    def context(self):
        return deepcopy(self.base_source.context())

    def catalog(self):
        topic = get_topic('H02')
        topic.update(status='available', source=type(self).__name__, context_scope='recorded',
                     observer_roles=['actor', 'recipient'], observer_scope=[],
                     supported_versions=['1.37.4'], triggers=['query', 'periodic', 'change', 'event'])
        topic['fields'] = {name: topic['fields'][name] for name in LEGACY_FIELDS}
        for field in topic['fields'].values():
            field.update(coverage='partial', native_source_available=False,
                         description='按request_id读取已有记录，原生自动到期来源尚未接入')
        topic['fields'][FIELD] = {
            'coverage': 'available', 'complete': True, 'source': type(self).__name__,
            'period': 'recorded', 'unit': 'proposal_expiry_events', 'scale': 1,
            'description': '已记录的外交提议实际到期通知，包含提议、双方和实际发生日期',
            'event_filter': {'types': ['diplomatic_proposal'], 'proposal_statuses': ['expired']}}
        return [topic]

    def validate_query(self, query, context=None):
        normalized = validate_query(query, context)
        if normalized['topic'] != 'H02':
            raise InformationError('unsupported_topic', 'Proposal expiry history supports H02')
        return normalized

    def _row(self, query, context, event):
        if event.get('event_type') != 'diplomatic_proposal':
            return None
        payload = event.get('payload', {})
        if (payload.get('observer_status') != 'expired'
                or context.get('observer') not in (payload.get('actor'), payload.get('recipient'))):
            return None
        obj = query['object']
        if obj['type'] == 'country' and obj.get('country') not in (payload.get('actor'), payload.get('recipient')):
            return None
        if obj['type'] == 'country_pair' and any(obj.get(key) != payload.get(key) for key in ('actor', 'recipient')):
            return None
        lifecycle = ended_lifecycle(payload)
        if lifecycle is None or lifecycle['kind'] != 'expired':
            raise ValueError('PROPOSAL_EXPIRY_SNAPSHOT_INVALID')
        mapped = {'topic': 'A04', 'object': {'type': 'session'},
                  'fields': PROPOSAL_FIELDS, 'parameters': {}}
        snapshot = self.base_source.replay_event(mapped, context, event)
        fields = snapshot['fields']
        if (any(fields[name].get('status') != 'known' for name in PROPOSAL_FIELDS)
                or fields['proposal_status']['value'] != 'expired'
                or fields['currently_pending']['value'] is not False):
            raise ValueError('PROPOSAL_EXPIRY_SNAPSHOT_UNAVAILABLE')
        row = {name: deepcopy(fields[name]['value']) for name in ('proposal_id', 'action_id', 'actor', 'recipient')}
        row.update(event_id=event['event_id'], event_date={
            'value': lifecycle['game_date_raw'], 'unit': 'game_date_raw', 'scale': 1})
        return row

    def _native(self, query, context, event=None):
        if query['parameters'].get('event_type', 'diplomatic_proposal') != 'diplomatic_proposal':
            return {'status': 'known', 'value': [], 'complete': True}
        if event is not None:
            batch = {'events': [event], 'complete': True, 'gaps': []}
        else:
            if self.history_reader is None:
                return {'status': 'unavailable', 'reason': 'EVENT_HISTORY_READER_NOT_BOUND'}
            filters = {'observer_status': 'expired'}
            obj = query['object']
            if obj['type'] == 'country_pair':
                filters.update({key: obj[key] for key in ('actor', 'recipient')})
            elif obj['type'] == 'country' and obj['country'] != context.get('observer'):
                filters['actor'] = obj['country']
            batch = self.history_reader(context, event_types=['diplomatic_proposal'],
                limit=query['parameters'].get('limit', 50), cursor=query['parameters'].get('cursor'),
                payload_filters=filters)
        rows = [row for event in batch['events'] if (row := self._row(query, context, event)) is not None]
        field = {'status': 'known', 'value': rows, 'complete': batch.get('complete') is True,
                 'gaps': deepcopy(batch.get('gaps', []))}
        if batch.get('next_cursor'):
            field['next_cursor'] = batch['next_cursor']
        return field

    def _read(self, query, context, event=None):
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        query = self.validate_query(query, current)
        parameters = query['parameters']
        if parameters.get('request_id') is not None or parameters.get('case') is not None:
            method = self.base_source.replay_event if event is not None else self.base_source.read
            return method(query, current, event) if event is not None else method(query, current)
        legacy = [name for name in query['fields'] if name in LEGACY_FIELDS]
        fields = {}
        if legacy:
            mapped = dict(query, fields=legacy)
            if FIELD not in query['fields']:
                return (self.base_source.replay_event(mapped, current, event) if event is not None
                        else self.base_source.read(mapped, current))
            fields.update(self.base_source.read(mapped, current)['fields'])
        if FIELD in query['fields']:
            try:
                fields[FIELD] = self._native(query, current, event)
            except InformationError:
                raise
            except Exception:
                fields[FIELD] = {'status': 'unknown', 'reason': 'PROPOSAL_EXPIRY_HISTORY_UNAVAILABLE'}
        complete = all(field.get('status') == 'known' and field.get('complete', True) for field in fields.values())
        return _result(query, current, fields, complete,
            _source_info(type(self).__name__, current, complete=complete, provenance={
                'basis': 'durable_native_proposal_expiry_snapshots', 'read_only': True}))

    def read(self, query, context=None):
        return self._read(query, context)

    def read_event(self, query, context, event):
        parameters = query.get('parameters', {})
        if (FIELD not in query.get('fields', []) or parameters.get('request_id') is not None
                or parameters.get('case') is not None):
            return self.base_source.read_event(query, context, event)
        return self._read(query, context, event)

    def replay_event(self, query, context, event):
        return self._read(query, context, event)

    def poll_events(self, context, cursor):
        return {'events': [], 'cursor': deepcopy(cursor or {}), 'complete': True, 'gaps': []}
