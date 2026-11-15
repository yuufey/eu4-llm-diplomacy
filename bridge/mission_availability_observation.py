"""Decode sampled native mission eligibility changes for FRA.

An event reports a change between two successful native predicate evaluations.
The first sample only establishes a baseline. These records do not represent
all mission conditions, branch visibility, or the instant a game state changed.
"""
from copy import deepcopy
import hashlib
import re

from . import mission_observation, relation_observation
from .native_change_observation import NativeChangeCollector

GAME_SHA256 = relation_observation.GAME_SHA256
CAPABILITY = 'native_mission_availability_observation'
EVENT_TYPE = 'mission_availability_changed'
NATIVE_EVENT = 'native_mission_availability_changed'
NATIVE_GAP = 'native_mission_availability_capture_gap'
SOURCE = 'mission_eligibility_native_return'
DATE_SEMANTICS = 'native_mission_eligibility_observation_game_date'
SCOPE = 'FRA_native_task_eligibility_return'
MAX_EVENTS = 1024
_HEX_NAME = re.compile(r'(?:[0-9a-f]{2}){1,256}')
_REFERENCE = re.compile(r'0x[0-9a-f]{1,16}')
_NATIVE_FIELDS = {
    'event', 'schema_version', 'session_id', 'sequence', 'country', 'country_fullref',
    'date_raw', 'previous_observed_date_raw', 'mission_id_hex',
    'eligible_before', 'eligible_after', 'source', 'complete',
}
_PAYLOAD_FIELDS = {
    'country', 'mission_id', 'eligible_before', 'eligible_after',
    'previous_observed_date_raw', 'scope',
}
_FRA_FULLREF_LOW = int.from_bytes(b'FRA', 'little')


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _valid_payload(payload, date):
    if (not isinstance(payload, dict) or set(payload) != _PAYLOAD_FIELDS
            or payload.get('country') != 'FRA' or payload.get('scope') != SCOPE
            or not _integer(date, 1, 2**31 - 1)
            or not _integer(payload.get('previous_observed_date_raw'), 1, 2**31 - 1)
            or payload['previous_observed_date_raw'] > date
            or type(payload.get('eligible_before')) is not bool
            or type(payload.get('eligible_after')) is not bool
            or payload['eligible_before'] is payload['eligible_after']):
        return False
    name = payload.get('mission_id')
    return (isinstance(name, str) and 1 <= len(name) <= 256
            and all(0x20 <= ord(character) <= 0x7e for character in name))


def event_id(session_id, sequence):
    identity = hashlib.sha256(
        (session_id + '\0mission-availability\0' + str(sequence)).encode()
    ).hexdigest()[:32]
    return 'mission-availability:' + identity


def objects(payload):
    return [{'type': 'country', 'country': payload['country']}]


def supported_ack(ack, game_sha256):
    return (mission_observation.supported_ack(ack, game_sha256)
            and ack['version'] in (52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64) and ack.get(CAPABILITY) is True
            and type(ack.get('native_mission_availability_wire')) is int
            and ack['native_mission_availability_wire'] == 1
            and ack.get('native_mission_availability_scope') == SCOPE)


def _canonical_fra_fullref(value):
    if not isinstance(value, str) or _REFERENCE.fullmatch(value) is None:
        return False
    reference = int(value, 16)
    return (reference & 0xffffff == _FRA_FULLREF_LOW
            and ((reference >> 32) & 0xffff) < 4096)


def public_observation(event, session_id):
    if (not isinstance(session_id, str) or not session_id or len(session_id) > 256
            or not isinstance(event, dict) or set(event) != _NATIVE_FIELDS
            or event.get('event') != NATIVE_EVENT or event.get('session_id') != session_id
            or event.get('country') != 'FRA'
            or type(event.get('schema_version')) is not int or event['schema_version'] != 1
            or not _integer(event.get('sequence'), 1, 2**63 - 1)
            or event.get('source') != SOURCE or event.get('complete') is not True):
        return None
    date = event.get('date_raw')
    previous_date = event.get('previous_observed_date_raw')
    if (not _integer(date, 1, 2**31 - 1)
            or not _integer(previous_date, 1, 2**31 - 1) or previous_date > date
            or type(event.get('eligible_before')) is not bool
            or type(event.get('eligible_after')) is not bool
            or event['eligible_before'] is event['eligible_after']
            or not _canonical_fra_fullref(event.get('country_fullref'))):
        return None
    encoded_name = event.get('mission_id_hex')
    if not isinstance(encoded_name, str) or _HEX_NAME.fullmatch(encoded_name) is None:
        return None
    try:
        name = bytes.fromhex(encoded_name).decode('ascii')
    except UnicodeError:
        return None
    payload = {
        'country': 'FRA', 'mission_id': name,
        'eligible_before': event['eligible_before'], 'eligible_after': event['eligible_after'],
        'previous_observed_date_raw': previous_date, 'scope': SCOPE,
    }
    if not _valid_payload(payload, date):
        return None
    return {
        'event_id': event_id(session_id, event['sequence']),
        'native_sequence': event['sequence'], 'game_date': date,
        'objects': objects(payload), 'payload': deepcopy(payload),
    }


def valid_event_snapshot(event, context):
    if not isinstance(event, dict) or not isinstance(context, dict):
        return False
    session_id = context.get('session_id')
    payload, source = event.get('payload'), event.get('source')
    if (not isinstance(session_id, str) or not session_id or len(session_id) > 256
            or event.get('session_id') != session_id or event.get('observer') != 'FRA'
            or context.get('observer') != 'FRA' or context.get('game_sha256') != GAME_SHA256
            or event.get('event_type') != EVENT_TYPE or event.get('complete') is not True
            or not _valid_payload(payload, event.get('game_date'))
            or event.get('objects') != objects(payload)
            or not isinstance(source, dict) or source.get('session_id') != session_id
            or source.get('scope') != SCOPE or source.get('mode') != 'live'
            or source.get('complete') is not True or source.get('date_semantics') != DATE_SEMANTICS
            or not _integer(source.get('native_sequence'), 1, 2**63 - 1)):
        return False
    return event.get('event_id') == event_id(session_id, source['native_sequence'])


class Collector(NativeChangeCollector):
    def __init__(self, session_id):
        super().__init__(session_id, native_event=NATIVE_EVENT, native_gap=NATIVE_GAP,
            health_key='mission_availability_source', prefix='MISSION_AVAILABILITY',
            decoder=public_observation, max_events=MAX_EVENTS)
