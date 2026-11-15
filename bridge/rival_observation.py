"""Owned rival membership changes from B23 command and record returns."""
from copy import deepcopy
import hashlib
import re

from . import country_modifier_observation
from .country_control_ack import supports_observer_version
from .native_change_observation import NativeChangeCollector

GAME_SHA256 = country_modifier_observation.GAME_SHA256
CAPABILITY = 'native_rival_change_observation'
EVENT_TYPE = 'rival_changed'
NATIVE_EVENT = 'native_rival_changed'
NATIVE_GAP = 'native_rival_capture_gap'
SOURCE = 'rival_command_normal_return'
DATE_SEMANTICS = 'native_rival_command_return_game_date'
SCOPE = 'FRA_actor_target_or_old_rival_at_three_country_command_entries'
RECORD_CAPABILITY = 'native_rival_record_observation'
RECORD_SCOPE = 'FRA_actor_or_target_at_country_rival_record_entries'
COMBINED_SCOPE = 'FRA_actor_target_or_old_rival_at_command_or_country_rival_record_returns'
COUNT_BASIS = 'active_nonretired_nodes'
RECORD_DATE_SEMANTICS = 'native_rival_record_return_game_date'
DATE_SEMANTICS_BY_SCOPE = {SCOPE: DATE_SEMANTICS, RECORD_SCOPE: RECORD_DATE_SEMANTICS}
RECORD_PATHS = {'country_rival_add': ('set', 'country_rival_add_return'),
                'country_rival_remove': ('remove', 'country_rival_remove_return')}
MAX_EVENTS = 1024
_TAG = re.compile(r'[A-Z0-9]{3}')
_REFERENCE = re.compile(r'0x[0-9a-f]{1,16}')
_STATE_FIELDS = {'count', 'target_active', 'target_since_date_raw', 'old_active', 'old_since_date_raw'}
_PAYLOAD_FIELDS = {'country', 'actor', 'recipient', 'old_rival', 'operation', 'before', 'after', 'scope'}
_NATIVE_FIELDS = {'event', 'schema_version', 'session_id', 'sequence', 'country', 'actor', 'target',
    'old_rival', 'actor_fullref', 'target_fullref', 'old_rival_fullref', 'operation', 'date_raw',
    'before', 'after', 'source', 'complete'}


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _tag(value):
    return isinstance(value, str) and _TAG.fullmatch(value) is not None


def _reference_matches(value, tag):
    if not isinstance(value, str) or _REFERENCE.fullmatch(value) is None:
        return False
    reference = int(value, 16)
    return (reference & 0xffffff == int.from_bytes(tag.encode('ascii'), 'little')
            and ((reference >> 32) & 0xffff) < 4096)


def _state(value, date, replace):
    if (not isinstance(value, dict) or set(value) != _STATE_FIELDS
            or not _integer(value.get('count'), 0, 64)
            or any(type(value.get(key)) is not bool for key in ('target_active', 'old_active'))):
        return False
    for active, since in (('target_active', 'target_since_date_raw'), ('old_active', 'old_since_date_raw')):
        if value[active]:
            if not _integer(value[since], 0, date):
                return False
        elif type(value[since]) is not int or value[since] != -1:
            return False
    observed_count = int(value['target_active']) + int(replace and value['old_active'])
    return value['count'] >= observed_count and (replace or not value['old_active'])


def _valid_payload(payload, date):
    if not isinstance(payload, dict):
        return False
    record = payload.get('scope') == RECORD_SCOPE
    fields = _PAYLOAD_FIELDS | {'observation_path', 'count_basis'} if record else _PAYLOAD_FIELDS
    if (set(payload) != fields or payload.get('country') != 'FRA'
            or payload.get('scope') not in (SCOPE, RECORD_SCOPE)
            or not _tag(payload.get('actor')) or not _tag(payload.get('recipient'))
            or payload['actor'] == payload['recipient']
            or payload.get('operation') not in ('set', 'replace', 'remove')
            or not _integer(date, 1, 2**31 - 1)):
        return False
    replace = payload['operation'] == 'replace'
    old = payload.get('old_rival')
    if replace:
        if not _tag(old) or old in (payload['actor'], payload['recipient']):
            return False
    elif old is not None:
        return False
    if 'FRA' not in (payload['actor'], payload['recipient'], old):
        return False
    before, after = payload.get('before'), payload.get('after')
    if not _state(before, date, replace) or not _state(after, date, replace):
        return False
    delta = int(after['target_active']) - int(before['target_active'])
    if replace:
        delta += int(after['old_active']) - int(before['old_active'])
    changed = before['target_active'] != after['target_active'] or (replace and before['old_active'] != after['old_active'])
    if record:
        path = payload.get('observation_path')
        if (not isinstance(path, str) or path not in RECORD_PATHS
                or payload.get('count_basis') != COUNT_BASIS
                or RECORD_PATHS[path][0] != payload['operation']
                or before['target_active'] == (payload['operation'] == 'set')
                or after['target_active'] != (payload['operation'] == 'set')):
            return False
    return changed and after['count'] - before['count'] == delta


def event_id(session_id, sequence):
    identity = hashlib.sha256((session_id+'\0rival-change\0'+str(sequence)).encode()).hexdigest()[:32]
    return 'rival-change:'+identity


def objects(payload):
    countries = [payload['actor'], payload['recipient']]
    if payload['old_rival'] is not None:
        countries.append(payload['old_rival'])
    return [{'type': 'country', 'country': country} for country in countries]


def supported_ack(ack, game_sha256):
    return (country_modifier_observation.supported_expiry_ack(ack, game_sha256)
            and supports_observer_version(ack, (48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64))
            and ack.get(CAPABILITY) is True
            and type(ack.get('native_rival_change_wire')) is int
            and ack['native_rival_change_wire'] == (2 if supports_observer_version(ack, (61, 62, 63, 64)) else 1)
            and ack.get('native_rival_change_scope') == (COMBINED_SCOPE if supports_observer_version(ack, (61, 62, 63, 64)) else SCOPE)
            and (not supports_observer_version(ack, (61, 62, 63, 64)) or (ack.get(RECORD_CAPABILITY) is True
                 and ack.get('native_rival_record_count_basis') == COUNT_BASIS)))


def supported_record_ack(ack, game_sha256):
    return supported_ack(ack, game_sha256) and supports_observer_version(ack, (61, 62, 63, 64))


def public_observation(event, session_id):
    if not isinstance(event, dict) or type(event.get('schema_version')) is not int:
        return None
    record = event['schema_version'] == 2
    path = event.get('observation_path')
    if record and (not isinstance(path, str) or path not in RECORD_PATHS):
        return None
    fields = _NATIVE_FIELDS | {'observation_path', 'count_basis'} if record else _NATIVE_FIELDS
    if (not isinstance(session_id, str) or not session_id or len(session_id) > 256
            or set(event) != fields
            or event.get('event') != NATIVE_EVENT or event.get('session_id') != session_id
            or event['schema_version'] not in (1, 2)
            or event.get('source') != (RECORD_PATHS[path][1] if record else SOURCE)
            or event.get('complete') is not True
            or not _integer(event.get('sequence'), 1, 2**63 - 1)):
        return None
    payload = {'country': event.get('country'), 'actor': event.get('actor'), 'recipient': event.get('target'),
        'old_rival': None if event.get('old_rival') == '---' else event.get('old_rival'),
        'operation': event.get('operation'), 'before': event.get('before'), 'after': event.get('after'),
        'scope': RECORD_SCOPE if record else SCOPE}
    if record:
        payload.update(observation_path=path,count_basis=event.get('count_basis'))
    if (not _valid_payload(payload, event.get('date_raw'))
            or not _reference_matches(event.get('actor_fullref'), payload['actor'])
            or not _reference_matches(event.get('target_fullref'), payload['recipient'])):
        return None
    if payload['operation'] == 'replace':
        if not _reference_matches(event.get('old_rival_fullref'), payload['old_rival']):
            return None
    elif event.get('old_rival') != '---' or event.get('old_rival_fullref') != '0x0':
        return None
    return {'event_id': event_id(session_id, event['sequence']), 'native_sequence': event['sequence'],
        'game_date': event['date_raw'], 'objects': objects(payload), 'payload': deepcopy(payload)}


def valid_event_snapshot(event, context):
    if not isinstance(event, dict) or not isinstance(context, dict):
        return False
    session_id = context.get('session_id')
    payload, source = event.get('payload'), event.get('source')
    if not isinstance(payload, dict) or not isinstance(payload.get('scope'), str):
        return False
    scope = payload['scope']
    date_semantics = DATE_SEMANTICS_BY_SCOPE.get(scope)
    if date_semantics is None:
        return False
    if (not isinstance(session_id, str) or not session_id or len(session_id) > 256
            or event.get('session_id') != session_id or event.get('observer') != 'FRA'
            or context.get('observer') != 'FRA' or context.get('game_sha256') != GAME_SHA256
            or event.get('event_type') != EVENT_TYPE or event.get('complete') is not True
            or not _valid_payload(payload, event.get('game_date'))
            or event.get('objects') != objects(payload)
            or not isinstance(source, dict) or source.get('session_id') != session_id
            or source.get('scope') != scope or source.get('mode') != 'live' or source.get('complete') is not True
            or source.get('date_semantics') != date_semantics
            or not _integer(source.get('native_sequence'), 1, 2**63 - 1)):
        return False
    return event.get('event_id') == event_id(session_id, source['native_sequence'])


class Collector(NativeChangeCollector):
    def __init__(self, session_id):
        super().__init__(session_id, native_event=NATIVE_EVENT, native_gap=NATIVE_GAP,
            health_key='rival_change_source', prefix='RIVAL', decoder=public_observation, max_events=MAX_EVENTS)

    def observe(self, event, *, allow_record=False):
        if (isinstance(event, dict) and event.get('session_id') == self.session_id
                and event.get('event') == self.native_event and event.get('schema_version') == 2
                and allow_record is not True):
            self.gaps.add(self.prefix+'_OBSERVATION_INVALID')
            return
        super().observe(event)
