"""Owned before/after relation states at the return of B23 pair commands."""
from copy import deepcopy
import hashlib
import re

from . import war_declaration_observation
from .native_change_observation import NativeChangeCollector

GAME_SHA256 = war_declaration_observation.GAME_SHA256
CAPABILITY = 'native_relation_change_observation'
RECORD_CAPABILITY = 'native_alliance_record_observation'
ROYAL_RECORD_CAPABILITY = 'native_royal_record_observation'
DIRECTED_RECORD_CAPABILITY = 'native_directed_record_observation'
SUPPORT_SUBJECT_RECORD_CAPABILITY = 'native_support_subject_record_observation'
EVENT_TYPE = 'relation_changed'
NATIVE_EVENT = 'native_relation_changed'
NATIVE_GAP = 'native_relation_capture_gap'
SOURCE = 'relation_command_return_actual_pair_state'
DATE_SEMANTICS = 'native_relation_command_return_game_date'
SCOPE = 'FRA_pair_at_six_relation_command_returns'
RECORD_SOURCE = 'relation_command_or_alliance_record_return_actual_pair_state'
RECORD_SCOPE = 'FRA_pair_at_six_relation_command_or_alliance_record_returns'
ROYAL_RECORD_SOURCE = 'relation_command_or_alliance_or_royal_record_return_actual_pair_state'
ROYAL_RECORD_SCOPE = 'FRA_pair_at_six_relation_command_or_alliance_or_royal_record_returns'
DIRECTED_RECORD_SOURCE = 'relation_command_or_alliance_or_royal_or_directed_record_return_actual_pair_state'
DIRECTED_RECORD_SCOPE = 'FRA_pair_at_six_relation_command_or_alliance_or_royal_or_directed_record_returns'
SUPPORT_SUBJECT_RECORD_SOURCE = 'relation_command_or_six_family_record_return_actual_pair_state'
SUPPORT_SUBJECT_RECORD_SCOPE = 'FRA_pair_at_six_relation_command_or_six_family_record_returns'
RECORD_DATE_SEMANTICS = 'native_relation_command_or_record_return_game_date'
DATE_SEMANTICS_BY_SCOPE = {
    SCOPE: DATE_SEMANTICS,
    RECORD_SCOPE: RECORD_DATE_SEMANTICS,
    ROYAL_RECORD_SCOPE: RECORD_DATE_SEMANTICS,
    DIRECTED_RECORD_SCOPE: RECORD_DATE_SEMANTICS,
    SUPPORT_SUBJECT_RECORD_SCOPE: RECORD_DATE_SEMANTICS,
}
MAX_EVENTS = 1024
KINDS = ('alliance', 'royal_marriage', 'military_access', 'guarantee', 'support_independence', 'subject')
_TAG = re.compile(r'[A-Z0-9]{3}')
_REFERENCE = re.compile(r'0x[0-9a-f]{1,16}')
_NATIVE_FIELDS = {'event', 'schema_version', 'session_id', 'sequence', 'country', 'actor', 'recipient',
    'actor_fullref', 'recipient_fullref', 'date_raw', 'relation_kind', 'command_state', 'command_mode',
    'before', 'after', 'source', 'complete'}
_RECORD_NATIVE_FIELDS = _NATIVE_FIELDS | {'observation_path'}
_PAYLOAD_FIELDS = {'country', 'actor', 'recipient', 'relation_kind', 'command_state', 'command_mode',
    'before', 'after', 'scope'}
_RECORD_PAYLOAD_FIELDS = _PAYLOAD_FIELDS | {'observation_path'}
_RECORD_PATHS = frozenset(('command_return', 'alliance_record_enable', 'alliance_record_disable'))
_ROYAL_RECORD_PATHS = frozenset(('command_return', 'alliance_record_enable', 'alliance_record_disable',
    'royal_record_enable', 'royal_record_disable'))
_DIRECTED_RECORD_PATH_KINDS = {
    'alliance_record_enable': 'alliance', 'alliance_record_disable': 'alliance',
    'royal_record_enable': 'royal_marriage', 'royal_record_disable': 'royal_marriage',
    'guarantee_record_enable': 'guarantee', 'guarantee_record_disable': 'guarantee',
    'military_record_enable': 'military_access', 'military_record_disable': 'military_access',
}
_DIRECTED_RECORD_PATHS = frozenset(_DIRECTED_RECORD_PATH_KINDS) | {'command_return'}
_SUPPORT_SUBJECT_RECORD_PATH_KINDS = dict(_DIRECTED_RECORD_PATH_KINDS,
    support_record_enable='support_independence', support_record_disable='support_independence',
    subject_record_enable='subject', subject_record_disable='subject')
_SUPPORT_SUBJECT_RECORD_PATHS = frozenset(_SUPPORT_SUBJECT_RECORD_PATH_KINDS) | {'command_return'}


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _state(kind, state):
    if (not isinstance(state, dict) or set(state) != {'active', 'guarantee', 'support_roles', 'subject'}
            or type(state['active']) is not bool):
        return False
    guarantee = state['guarantee']
    if kind == 'guarantee':
        if (not isinstance(guarantee, dict) or set(guarantee) != {'actor_grants', 'recipient_grants'}
                or any(type(value) is not bool for value in guarantee.values())
                or state['active'] != any(guarantee.values())):
            return False
    elif guarantee is not None:
        return False
    roles = state['support_roles']
    if kind == 'support_independence':
        if (not isinstance(roles, dict) or set(roles) != {'actor_is_subject', 'recipient_is_subject'}
                or any(type(value) is not bool for value in roles.values())):
            return False
    elif roles is not None:
        return False
    subject = state['subject']
    if kind != 'subject':
        return subject is None
    if (not isinstance(subject, dict) or set(subject) != {'actor_is_overlord', 'actor_is_subject', 'type'}
            or any(type(subject[key]) is not bool for key in ('actor_is_overlord', 'actor_is_subject'))):
        return False
    if not state['active']:
        return subject == {'actor_is_overlord': False, 'actor_is_subject': False, 'type': None}
    identifier = subject['type']
    return (subject['actor_is_overlord'] != subject['actor_is_subject']
            and isinstance(identifier, str) and 1 <= len(identifier) <= 64
            and all(0x20 <= ord(byte) <= 0x7e and byte not in '"\\' for byte in identifier))


def _valid_payload(payload, date, scope):
    if not isinstance(payload, dict) or not isinstance(scope, str):
        return False
    expected_fields = (_PAYLOAD_FIELDS if scope == SCOPE else _RECORD_PAYLOAD_FIELDS
                       if scope in DATE_SEMANTICS_BY_SCOPE else None)
    if (expected_fields is None or set(payload) != expected_fields
            or payload.get('country') != 'FRA' or payload.get('scope') != scope
            or not _integer(date, 1, 2**31 - 1)
            or any(not isinstance(payload[key], str) or _TAG.fullmatch(payload[key]) is None
                   for key in ('actor', 'recipient'))
            or payload['actor'] == payload['recipient'] or 'FRA' not in (payload['actor'], payload['recipient'])
            or not isinstance(payload['relation_kind'], str) or payload['relation_kind'] not in KINDS):
        return False
    if scope == SCOPE:
        if not _integer(payload['command_state'], 0, 2) or not _integer(payload['command_mode'], 0, 1):
            return False
    elif scope == RECORD_SCOPE:
        path = payload.get('observation_path')
        if not isinstance(path, str) or path not in _RECORD_PATHS:
            return False
        if path == 'command_return':
            if not _integer(payload['command_state'], 0, 2) or not _integer(payload['command_mode'], 0, 1):
                return False
        elif (payload['relation_kind'] != 'alliance'
                or payload['command_state'] is not None or payload['command_mode'] is not None):
            return False
    else:
        path = payload.get('observation_path')
        paths = (_SUPPORT_SUBJECT_RECORD_PATHS if scope == SUPPORT_SUBJECT_RECORD_SCOPE else
                 _DIRECTED_RECORD_PATHS if scope == DIRECTED_RECORD_SCOPE else _ROYAL_RECORD_PATHS)
        if not isinstance(path, str) or path not in paths:
            return False
        if path == 'command_return':
            if not _integer(payload['command_state'], 0, 2) or not _integer(payload['command_mode'], 0, 1):
                return False
        else:
            expected_kind = _SUPPORT_SUBJECT_RECORD_PATH_KINDS[path]
            if (payload['relation_kind'] != expected_kind
                    or payload['command_state'] is not None or payload['command_mode'] is not None):
                return False
    kind, before, after = payload['relation_kind'], payload['before'], payload['after']
    if not _state(kind, before) or not _state(kind, after):
        return False
    if before['active'] != after['active']:
        return True
    if kind == 'guarantee':
        return before['guarantee'] != after['guarantee']
    return kind == 'subject' and before['active'] and before['subject'] != after['subject']


def event_id(session_id, sequence):
    identity = hashlib.sha256((session_id+'\0relation-change\0'+str(sequence)).encode()).hexdigest()[:32]
    return 'relation-changed:'+identity


def objects(payload):
    return [{'type': 'country_pair', 'actor': payload['actor'], 'recipient': payload['recipient']},
            {'type': 'country', 'country': payload['actor']}, {'type': 'country', 'country': payload['recipient']}]


def supported_ack(ack, game_sha256):
    if (not isinstance(ack, dict) or not war_declaration_observation.supported_ack(ack, game_sha256)
            or type(ack.get('version')) is not int or ack.get(CAPABILITY) is not True):
        return False
    version = ack['version']
    wire = ack.get('native_relation_change_wire')
    if version not in (60, 61, 62, 63, 64) and ack.get(SUPPORT_SUBJECT_RECORD_CAPABILITY) is True:
        return False
    if version not in (59, 60, 61, 62, 63, 64) and ack.get(DIRECTED_RECORD_CAPABILITY) is True:
        return False
    if version in (50, 51, 52, 53):
        return (ack.get(RECORD_CAPABILITY) is not True and ack.get(ROYAL_RECORD_CAPABILITY) is not True
                and type(wire) is int and wire == 1
                and ack.get('native_relation_change_scope') == SCOPE)
    if version in (54, 55, 56, 57):
        return (ack.get(RECORD_CAPABILITY) is True and ack.get(ROYAL_RECORD_CAPABILITY) is not True
                and type(wire) is int and wire == 2
                and ack.get('native_relation_change_scope') == RECORD_SCOPE)
    if version == 58:
        return (ack.get(RECORD_CAPABILITY) is True and ack.get(ROYAL_RECORD_CAPABILITY) is True
                and type(wire) is int and wire == 3
                and ack.get('native_relation_change_scope') == ROYAL_RECORD_SCOPE)
    if version == 59:
        return (ack.get(RECORD_CAPABILITY) is True and ack.get(ROYAL_RECORD_CAPABILITY) is True
                and ack.get(DIRECTED_RECORD_CAPABILITY) is True
                and type(wire) is int and wire == 4
                and ack.get('native_relation_change_scope') == DIRECTED_RECORD_SCOPE)
    if version in (60, 61, 62, 63, 64):
        return (ack.get(RECORD_CAPABILITY) is True and ack.get(ROYAL_RECORD_CAPABILITY) is True
                and ack.get(DIRECTED_RECORD_CAPABILITY) is True
                and ack.get(SUPPORT_SUBJECT_RECORD_CAPABILITY) is True
                and type(wire) is int and wire == 5
                and ack.get('native_relation_change_scope') == SUPPORT_SUBJECT_RECORD_SCOPE)
    return False


def supported_record_ack(ack, game_sha256):
    return (supported_ack(ack, game_sha256) and ack['version'] in (54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64)
            and ack.get(RECORD_CAPABILITY) is True)


def supported_royal_record_ack(ack, game_sha256):
    return (supported_ack(ack, game_sha256) and ack['version'] in (58, 59, 60, 61, 62, 63, 64)
            and ack.get(RECORD_CAPABILITY) is True and ack.get(ROYAL_RECORD_CAPABILITY) is True)


def supported_directed_record_ack(ack, game_sha256):
    return (supported_ack(ack, game_sha256) and ack['version'] in (59, 60, 61, 62, 63, 64)
            and ack.get(DIRECTED_RECORD_CAPABILITY) is True)


def supported_support_subject_record_ack(ack, game_sha256):
    return (supported_ack(ack, game_sha256) and ack['version'] in (60, 61, 62, 63, 64)
            and ack.get(SUPPORT_SUBJECT_RECORD_CAPABILITY) is True)


def scope_for_capabilities(capabilities):
    if isinstance(capabilities, (str, bytes, dict)) or capabilities is None:
        return None
    try:
        caps = set(capabilities)
    except (TypeError, ValueError):
        return None
    if CAPABILITY not in caps:
        return None
    if SUPPORT_SUBJECT_RECORD_CAPABILITY in caps:
        if not {RECORD_CAPABILITY, ROYAL_RECORD_CAPABILITY, DIRECTED_RECORD_CAPABILITY} <= caps:
            return None
        return SUPPORT_SUBJECT_RECORD_SCOPE
    if DIRECTED_RECORD_CAPABILITY in caps:
        if RECORD_CAPABILITY not in caps or ROYAL_RECORD_CAPABILITY not in caps:
            return None
        return DIRECTED_RECORD_SCOPE
    if ROYAL_RECORD_CAPABILITY in caps:
        if RECORD_CAPABILITY not in caps:
            return None
        return ROYAL_RECORD_SCOPE
    return RECORD_SCOPE if RECORD_CAPABILITY in caps else SCOPE


def public_observation(event, session_id):
    if (not isinstance(session_id, str) or not session_id or len(session_id) > 256
            or not isinstance(event, dict) or type(event.get('schema_version')) is not int):
        return None
    if event['schema_version'] == 1:
        fields, payload_fields, scope, expected_source = _NATIVE_FIELDS, _PAYLOAD_FIELDS, SCOPE, SOURCE
    elif event['schema_version'] == 2:
        fields, payload_fields, scope, expected_source = (
            _RECORD_NATIVE_FIELDS, _RECORD_PAYLOAD_FIELDS, RECORD_SCOPE, RECORD_SOURCE)
    elif event['schema_version'] == 3:
        fields, payload_fields, scope, expected_source = (
            _RECORD_NATIVE_FIELDS, _RECORD_PAYLOAD_FIELDS, ROYAL_RECORD_SCOPE, ROYAL_RECORD_SOURCE)
    elif event['schema_version'] == 4:
        fields, payload_fields, scope, expected_source = (
            _RECORD_NATIVE_FIELDS, _RECORD_PAYLOAD_FIELDS, DIRECTED_RECORD_SCOPE, DIRECTED_RECORD_SOURCE)
    elif event['schema_version'] == 5:
        fields, payload_fields, scope, expected_source = (
            _RECORD_NATIVE_FIELDS, _RECORD_PAYLOAD_FIELDS, SUPPORT_SUBJECT_RECORD_SCOPE, SUPPORT_SUBJECT_RECORD_SOURCE)
    else:
        return None
    if (set(event) != fields or event.get('event') != NATIVE_EVENT
            or event.get('session_id') != session_id or event.get('source') != expected_source
            or event.get('complete') is not True
            or not _integer(event.get('sequence'), 1, 2**63 - 1)):
        return None
    payload = {key: event[key] for key in payload_fields if key != 'scope'}
    payload['scope'] = scope
    if not _valid_payload(payload, event['date_raw'], scope):
        return None
    for role in ('actor', 'recipient'):
        raw = event[role+'_fullref']
        if not isinstance(raw, str) or _REFERENCE.fullmatch(raw) is None:
            return None
        reference = int(raw, 16)
        if (reference & 0xffffff != int.from_bytes(payload[role].encode('ascii'), 'little')
                or ((reference >> 32) & 0xffff) >= 4096):
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
            or not _valid_payload(payload, event.get('game_date'), scope) or event.get('objects') != objects(payload)
            or not isinstance(source, dict) or source.get('session_id') != session_id
            or source.get('scope') != scope or source.get('mode') != 'live' or source.get('complete') is not True
            or source.get('date_semantics') != date_semantics
            or not _integer(source.get('native_sequence'), 1, 2**63 - 1)):
        return False
    return event.get('event_id') == event_id(session_id, source['native_sequence'])


class Collector(NativeChangeCollector):
    def __init__(self, session_id):
        super().__init__(session_id, native_event=NATIVE_EVENT, native_gap=NATIVE_GAP,
            health_key='relation_source', prefix='RELATION', decoder=public_observation, max_events=MAX_EVENTS)

    def observe(self, event, *, allow_record=False, allow_royal_record=False, allow_directed_record=False,
                allow_support_subject_record=False):
        if (isinstance(event, dict) and event.get('session_id') == self.session_id
                and event.get('event') == self.native_event):
            expected_version = (5 if allow_support_subject_record is True and allow_directed_record is True
                                and allow_record is True and allow_royal_record is True else
                                4 if allow_directed_record is True and allow_record is True
                                and allow_royal_record is True else
                                3 if allow_record is True and allow_royal_record is True else
                                2 if allow_record is True else 1)
            if type(event.get('schema_version')) is not int or event['schema_version'] != expected_version:
                self.gaps.add(self.prefix+'_OBSERVATION_INVALID')
                return
        super().observe(event)
