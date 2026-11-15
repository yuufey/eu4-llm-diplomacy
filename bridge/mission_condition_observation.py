"""Decode bounded observations of individual mission root-condition returns.

These records describe only child results observed during the root
conjunction walk. They do not claim complete condition coverage or the instant
at which the underlying game state changed.
"""
from copy import deepcopy
import hashlib
import re

from . import mission_availability_observation
from .country_control_ack import supports_observer_version
from .native_change_observation import NativeChangeCollector

GAME_SHA256 = mission_availability_observation.GAME_SHA256
CAPABILITY = 'native_mission_condition_observation'
PROVINCE_CAPABILITY = 'native_mission_province_condition_observation'
EVENT_TYPE = 'mission_condition_changed'
NATIVE_EVENT = 'native_mission_condition_changed'
NATIVE_GAP = 'native_mission_condition_capture_gap'
SOURCE = 'mission_root_conjunction_child_return'
DATE_SEMANTICS = 'native_mission_condition_observation_game_date'
SCOPE = 'FRA_root_conjunction_child_returns'
PROVINCE_SOURCE = 'mission_direct_area_province_holding_return'
PROVINCE_SCOPE = 'FRA_direct_root_area_ROOT_province_holding_returns'
COMBINED_SCOPE = 'FRA_root_and_direct_area_province_holding_returns'
MAX_EVENTS = 1024
_HEX_NAME = re.compile(r'(?:[0-9a-f]{2}){1,256}')
_HEX_VALUE = re.compile(r'0x[0-9a-f]{1,16}')
_FRA_FULLREF_LOW = int.from_bytes(b'FRA', 'little')
_MIN_USER_ADDRESS = 0x10000
_MAX_USER_ADDRESS_EXCLUSIVE = 0x800000000000
_NATIVE_FIELDS = {
    'event', 'schema_version', 'session_id', 'sequence', 'country', 'country_fullref',
    'date_raw', 'previous_observed_date_raw', 'mission_id_hex', 'condition_index',
    'condition_node', 'condition_method_rva', 'satisfied_before', 'satisfied_after',
    'native_return_before', 'native_return_after', 'root_condition_count',
    'observed_condition_count', 'source', 'complete',
}
_PROVINCE_NATIVE_FIELDS = _NATIVE_FIELDS | {'child_index', 'child_count', 'province_id'}
_PAYLOAD_FIELDS = {
    'country', 'mission_id', 'condition_index', 'condition_node',
    'condition_method_rva', 'satisfied_before', 'satisfied_after',
    'native_return_before', 'native_return_after', 'root_condition_count',
    'observed_condition_count', 'previous_observed_date_raw', 'scope',
}
_PROVINCE_PAYLOAD_FIELDS = _PAYLOAD_FIELDS | {
    'child_index', 'child_count', 'province_id', 'condition_name', 'comparison_country',
}


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _canonical_fra_fullref(value):
    if not isinstance(value, str) or _HEX_VALUE.fullmatch(value) is None:
        return False
    reference = int(value, 16)
    return (reference & 0xffffff == _FRA_FULLREF_LOW
            and ((reference >> 32) & 0xffff) < 4096)


def _valid_user_pointer(value):
    if not isinstance(value, str) or _HEX_VALUE.fullmatch(value) is None:
        return False
    pointer = int(value, 16)
    return _MIN_USER_ADDRESS <= pointer < _MAX_USER_ADDRESS_EXCLUSIVE


def _valid_native_return(value):
    return isinstance(value, str) and _HEX_VALUE.fullmatch(value) is not None


def _valid_name(value):
    return (isinstance(value, str) and 1 <= len(value) <= 256
            and all(0x20 <= ord(character) <= 0x7e for character in value))


def _valid_payload(payload, date, scope):
    if not isinstance(payload, dict):
        return False
    if scope == SCOPE:
        expected_fields = _PAYLOAD_FIELDS
    elif scope == PROVINCE_SCOPE:
        expected_fields = _PROVINCE_PAYLOAD_FIELDS
    else:
        return False
    if (set(payload) != expected_fields
            or payload.get('country') != 'FRA' or payload.get('scope') != scope
            or not _integer(date, 1, 2**31 - 1)
            or not _integer(payload.get('previous_observed_date_raw'), 1, 2**31 - 1)
            or payload['previous_observed_date_raw'] > date
            or not _integer(payload.get('condition_index'), 0, 127)
            or not _integer(payload.get('root_condition_count'), 1, 128)
            or not _integer(payload.get('observed_condition_count'), 1, 128)
            or payload['observed_condition_count'] < payload['condition_index'] + 1
            or payload['observed_condition_count'] > payload['root_condition_count']
            or not _integer(payload.get('condition_method_rva'), 0x1000, 0x1bfffff)
            or (scope == PROVINCE_SCOPE and payload['condition_method_rva'] != 0xbe9300)
            or not _valid_user_pointer(payload.get('condition_node'))
            or type(payload.get('satisfied_before')) is not bool
            or type(payload.get('satisfied_after')) is not bool
            or payload['satisfied_before'] is payload['satisfied_after']
            or not _valid_native_return(payload.get('native_return_before'))
            or not _valid_native_return(payload.get('native_return_after'))):
        return False
    if scope == PROVINCE_SCOPE:
        child_index = payload.get('child_index')
        child_count = payload.get('child_count')
        if (not _integer(child_count, 1, 128)
                or not _integer(child_index, 0, child_count - 1)
                or not _integer(payload.get('province_id'), 1, 65535)
                or payload.get('condition_name') != 'country_or_non_sovereign_subject_holds'
                or payload.get('comparison_country') != 'ROOT'):
            return False
    before = int(payload['native_return_before'], 16)
    after = int(payload['native_return_after'], 16)
    return ((before & 0xff != 0) is payload['satisfied_before']
            and (after & 0xff != 0) is payload['satisfied_after']
            and _valid_name(payload.get('mission_id')))


def event_id(session_id, sequence):
    identity = hashlib.sha256(
        (session_id + '\0mission-condition\0' + str(sequence)).encode()
    ).hexdigest()[:32]
    return 'mission-condition:' + identity


def objects(payload):
    return [{'type': 'country', 'country': payload['country']}]


def supported_ack(ack, game_sha256):
    if (not isinstance(ack, dict)
            or not mission_availability_observation.supported_ack(ack, game_sha256)
            or type(ack.get('version')) is not int or ack.get(CAPABILITY) is not True):
        return False
    wire = ack.get('native_mission_condition_wire')
    if ack['version'] == 56:
        return (type(wire) is int and wire == 1
                and ack.get('native_mission_condition_scope') == SCOPE)
    if supports_observer_version(ack, (57, 58, 59, 60, 61, 62, 63, 64)):
        return (type(wire) is int and wire == 2
                and ack.get('native_mission_condition_scope') == COMBINED_SCOPE
                and ack.get(PROVINCE_CAPABILITY) is True)
    return False


def supported_province_ack(ack, game_sha256):
    return (supported_ack(ack, game_sha256)
            and supports_observer_version(ack, (57, 58, 59, 60, 61, 62, 63, 64)))


def public_observation(event, session_id):
    if (not isinstance(session_id, str) or not session_id or len(session_id) > 256
            or not isinstance(event, dict)):
        return None
    schema_version = event.get('schema_version')
    if type(schema_version) is not int:
        return None
    if schema_version == 1:
        fields, scope, expected_source = _NATIVE_FIELDS, SCOPE, SOURCE
    elif schema_version == 2:
        fields, scope, expected_source = _PROVINCE_NATIVE_FIELDS, PROVINCE_SCOPE, PROVINCE_SOURCE
    else:
        return None
    if (set(event) != fields
            or event.get('event') != NATIVE_EVENT or event.get('session_id') != session_id
            or event.get('country') != 'FRA'
            or not _integer(event.get('sequence'), 1, 2**63 - 1)
            or event.get('source') != expected_source or event.get('complete') is not False
            or not _canonical_fra_fullref(event.get('country_fullref'))):
        return None
    date = event.get('date_raw')
    if (not _integer(date, 1, 2**31 - 1)
            or type(event.get('satisfied_before')) is not bool
            or type(event.get('satisfied_after')) is not bool):
        return None
    encoded_name = event.get('mission_id_hex')
    if not isinstance(encoded_name, str) or _HEX_NAME.fullmatch(encoded_name) is None:
        return None
    try:
        name = bytes.fromhex(encoded_name).decode('ascii')
    except UnicodeError:
        return None
    payload = {
        'country': 'FRA',
        'mission_id': name,
        'condition_index': event.get('condition_index'),
        'condition_node': event.get('condition_node'),
        'condition_method_rva': event.get('condition_method_rva'),
        'satisfied_before': event['satisfied_before'],
        'satisfied_after': event['satisfied_after'],
        'native_return_before': event.get('native_return_before'),
        'native_return_after': event.get('native_return_after'),
        'root_condition_count': event.get('root_condition_count'),
        'observed_condition_count': event.get('observed_condition_count'),
        'previous_observed_date_raw': event.get('previous_observed_date_raw'),
        'scope': scope,
    }
    if schema_version == 2:
        payload.update({
            'child_index': event.get('child_index'),
            'child_count': event.get('child_count'),
            'province_id': event.get('province_id'),
            'condition_name': 'country_or_non_sovereign_subject_holds',
            'comparison_country': 'ROOT',
        })
    if not _valid_payload(payload, date, scope):
        return None
    return {
        'event_id': event_id(session_id, event['sequence']),
        'native_sequence': event['sequence'],
        'game_date': date,
        'objects': objects(payload),
        'payload': deepcopy(payload),
    }


def valid_event_snapshot(event, context):
    if not isinstance(event, dict) or not isinstance(context, dict):
        return False
    session_id = context.get('session_id')
    payload, source = event.get('payload'), event.get('source')
    if (not isinstance(session_id, str) or not session_id or len(session_id) > 256
            or event.get('session_id') != session_id or event.get('observer') != 'FRA'
            or context.get('observer') != 'FRA' or context.get('game_sha256') != GAME_SHA256
            or event.get('event_type') != EVENT_TYPE or event.get('complete') is not False
            or not isinstance(payload, dict)
            or not _valid_payload(payload, event.get('game_date'), payload.get('scope'))
            or event.get('objects') != objects(payload)
            or not isinstance(source, dict) or source.get('session_id') != session_id
            or source.get('scope') != payload.get('scope') or source.get('mode') != 'live'
            or source.get('complete') is not False or source.get('date_semantics') != DATE_SEMANTICS
            or not _integer(source.get('native_sequence'), 1, 2**63 - 1)):
        return False
    return event.get('event_id') == event_id(session_id, source['native_sequence'])


class Collector(NativeChangeCollector):
    def __init__(self, session_id):
        super().__init__(session_id, native_event=NATIVE_EVENT, native_gap=NATIVE_GAP,
            health_key='mission_condition_source', prefix='MISSION_CONDITION',
            decoder=public_observation, max_events=MAX_EVENTS)
