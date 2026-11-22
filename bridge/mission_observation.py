"""Decode native completed-mission observations from two compatible wires."""
from copy import deepcopy
import hashlib
import re

from . import relation_observation
from .country_control_ack import supports_observer_version
from .native_change_observation import NativeChangeCollector

GAME_SHA256 = relation_observation.GAME_SHA256
CAPABILITY = 'native_mission_completion_observation'
SET_CAPABILITY = 'native_mission_completed_set_observation'
EVENT_TYPE = 'mission_completed'
NATIVE_EVENT = 'native_mission_completed'
NATIVE_GAP = 'native_mission_capture_gap'

# Wire 1 describes an observed false-to-true membership transition at the
# mission command return. Keep these public constants stable for archived data.
SOURCE = 'mission_command_return_completed_membership_transition'
DATE_SEMANTICS = 'native_mission_command_return_game_date'
SCOPE = 'FRA_completed_transition_at_native_mission_command_return'

# Wire 2 reports insertion into the completed set at a specific native return.
SET_SOURCE = 'mission_completed_set_insert_normal_return'
SET_SCOPE = 'FRA_completed_set_insert_at_command_or_effect_return'
CONFIGURED_SET_SCOPE = 'configured_observer_completed_set_insert_at_command_or_effect_return'
SCOPED_CAPABILITY = 'native_mission_completion_configured_observers'
SET_DATE_SEMANTICS = 'native_completed_set_insert_return_game_date'
DATE_SEMANTICS_BY_SCOPE = {
    SCOPE: DATE_SEMANTICS,
    SET_SCOPE: SET_DATE_SEMANTICS,
    CONFIGURED_SET_SCOPE: SET_DATE_SEMANTICS,
}
MAX_EVENTS = 1024
_HEX_NAME = re.compile(r'(?:[0-9a-f]{2}){1,256}')
_REFERENCE = re.compile(r'0x[0-9a-f]{1,16}')
_COMPLETION_PATHS = frozenset(('command_handler', 'script_effect'))
_NATIVE_FIELDS = {
    'event', 'schema_version', 'session_id', 'sequence', 'country', 'country_fullref',
    'date_raw', 'mission_id_hex', 'completed_before', 'completed_after', 'source', 'complete',
}
_SET_NATIVE_FIELDS = _NATIVE_FIELDS | {'completion_path'}
_PAYLOAD_FIELDS = {'country', 'mission_id', 'completed_before', 'completed_after', 'scope'}
_SET_PAYLOAD_FIELDS = _PAYLOAD_FIELDS | {'completion_path'}
_TAG = re.compile(r'[A-Z0-9]{3}')


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _valid_name(name):
    return (isinstance(name, str) and 1 <= len(name) <= 256
            and all(0x20 <= ord(character) <= 0x7e for character in name))


def _valid_fullref(raw, country):
    if (not isinstance(country, str) or _TAG.fullmatch(country) is None
            or not isinstance(raw, str) or _REFERENCE.fullmatch(raw) is None):
        return False
    reference = int(raw, 16)
    return (reference & 0xffffff == int.from_bytes(country.encode("ascii"), "little")
            and ((reference >> 32) & 0xffff) < 4096)


def _valid_payload(payload, date, scope):
    if not isinstance(payload, dict) or not isinstance(scope, str):
        return False
    expected_fields = (_PAYLOAD_FIELDS if scope == SCOPE else _SET_PAYLOAD_FIELDS
                       if scope in (SET_SCOPE, CONFIGURED_SET_SCOPE) else None)
    country = payload.get('country')
    if (expected_fields is None or set(payload) != expected_fields
            or not isinstance(country, str) or _TAG.fullmatch(country) is None
            or (scope != CONFIGURED_SET_SCOPE and country != 'FRA') or payload.get('scope') != scope
            or not _integer(date, 1, 2**31 - 1)
            or payload.get('completed_before') is not False
            or payload.get('completed_after') is not True
            or not _valid_name(payload.get('mission_id'))):
        return False
    if scope in (SET_SCOPE, CONFIGURED_SET_SCOPE):
        path = payload.get('completion_path')
        return isinstance(path, str) and path in _COMPLETION_PATHS
    return True


def event_id(session_id, sequence):
    identity = hashlib.sha256((session_id+'\0mission-completion\0'+str(sequence)).encode()).hexdigest()[:32]
    return 'mission-completed:'+identity


def objects(payload):
    return [{'type': 'country', 'country': payload['country']}]


def _capabilities_set(capabilities):
    if isinstance(capabilities, (str, bytes, dict)) or capabilities is None:
        return None
    try:
        return set(capabilities)
    except (TypeError, ValueError):
        return None


def scope_for_capabilities(capabilities):
    caps = _capabilities_set(capabilities)
    if caps is None:
        return None
    if CAPABILITY not in caps:
        return None
    if SET_CAPABILITY in caps:
        return CONFIGURED_SET_SCOPE if SCOPED_CAPABILITY in caps else SET_SCOPE
    return SCOPE


def supported_ack(ack, game_sha256):
    if (not isinstance(ack, dict) or not relation_observation.supported_ack(ack, game_sha256)
            or type(ack.get('version')) is not int or ack.get(CAPABILITY) is not True):
        return False
    version = ack['version']
    wire = ack.get('native_mission_completion_wire')
    if version in (51, 52):
        return (ack.get(SET_CAPABILITY) is not True and type(wire) is int and wire == 1
                and ack.get('native_mission_completion_scope') == SCOPE)
    if supports_observer_version(ack, (53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64)):
        return (ack.get(SET_CAPABILITY) is True and type(wire) is int and wire == 2
                and ack.get('native_mission_completion_scope') == SET_SCOPE)
    return False


def supported_set_ack(ack, game_sha256):
    return (supported_ack(ack, game_sha256) and supports_observer_version(ack, (53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64))
            and ack.get(SET_CAPABILITY) is True)


def public_observation(event, session_id):
    if (not isinstance(session_id, str) or not session_id or len(session_id) > 256
            or not isinstance(event, dict)):
        return None
    schema_version = event.get('schema_version')
    if type(schema_version) is not int:
        return None
    if schema_version == 1:
        fields, scope, expected_source = _NATIVE_FIELDS, SCOPE, SOURCE
    elif schema_version in (2, 3):
        fields, scope, expected_source = _SET_NATIVE_FIELDS, SET_SCOPE, SET_SOURCE
        if schema_version == 3:
            scope = CONFIGURED_SET_SCOPE
    else:
        return None
    country = event.get('country')
    if (set(event) != fields or event.get('event') != NATIVE_EVENT
            or event.get('session_id') != session_id or (schema_version < 3 and country != 'FRA')
            or event.get('source') != expected_source or event.get('complete') is not True
            or not _integer(event.get('sequence'), 1, 2**63 - 1)
            or not _integer(event.get('date_raw'), 1, 2**31 - 1)
            or event.get('completed_before') is not False or event.get('completed_after') is not True
            or not _valid_fullref(event.get('country_fullref'), country)):
        return None
    if schema_version in (2, 3):
        path = event.get('completion_path')
        if not isinstance(path, str) or path not in _COMPLETION_PATHS:
            return None
    encoded_name = event.get('mission_id_hex')
    if not isinstance(encoded_name, str) or _HEX_NAME.fullmatch(encoded_name) is None:
        return None
    try:
        name = bytes.fromhex(encoded_name).decode('ascii')
    except UnicodeError:
        return None
    payload = {
        'country': country, 'mission_id': name,
        'completed_before': False, 'completed_after': True, 'scope': scope,
    }
    if schema_version in (2, 3):
        payload['completion_path'] = path
    if not _valid_payload(payload, event['date_raw'], scope):
        return None
    return {
        'event_id': event_id(session_id, event['sequence']),
        'native_sequence': event['sequence'], 'game_date': event['date_raw'],
        'objects': objects(payload), 'payload': deepcopy(payload),
    }


def valid_event_snapshot(event, context):
    if not isinstance(event, dict) or not isinstance(context, dict):
        return False
    session_id = context.get('session_id')
    payload, source = event.get('payload'), event.get('source')
    if not isinstance(payload, dict):
        return False
    scope = payload.get('scope')
    if not isinstance(scope, str):
        return False
    date_semantics = DATE_SEMANTICS_BY_SCOPE.get(scope)
    if date_semantics is None:
        return False
    if (not isinstance(session_id, str) or not session_id or len(session_id) > 256
            or event.get('session_id') != session_id or event.get('observer') != payload.get('country')
            or context.get('observer') != payload.get('country') or context.get('game_sha256') != GAME_SHA256
            or event.get('event_type') != EVENT_TYPE or event.get('complete') is not True
            or not _valid_payload(payload, event.get('game_date'), scope)
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
            health_key='mission_source', prefix='MISSION', decoder=public_observation, max_events=MAX_EVENTS)

    def observe(self, event, *, allow_set=False, allow_scoped=False):
        if (isinstance(event, dict) and event.get('session_id') == self.session_id
                and event.get('event') == self.native_event):
            expected_version = (3 if allow_scoped else 2) if allow_set is True else 1
            if type(event.get('schema_version')) is not int or event['schema_version'] != expected_version:
                self.gaps.add(self.prefix+'_OBSERVATION_INVALID')
                return
        super().observe(event)
