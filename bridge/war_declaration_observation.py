"""Owned declaration-time war and participant snapshots from B23 commands."""
from copy import deepcopy
import hashlib
import re

from . import rival_observation
from .country_control_ack import supports_observer_version
from .native_change_observation import NativeChangeCollector
from .war_participants import project_war_participants

GAME_SHA256 = rival_observation.GAME_SHA256
CAPABILITY = 'native_war_declaration_observation'
EVENT_TYPE = 'war_declared'
NATIVE_EVENT = 'native_war_declared'
NATIVE_GAP = 'native_war_declaration_capture_gap'
SOURCE = 'declare_war_command_return_new_pair_reference'
DATE_SEMANTICS = 'native_declare_war_command_return_game_date'
ROLE_BASIS = 'declaring_command_actor_participant_side'
SCOPE = 'FRA_member_in_new_declared_pair_war'
MAX_EVENTS = 1024
_TAG = re.compile(r'[A-Z0-9]{3}')
_REFERENCE = re.compile(r'0x[0-9a-f]{1,16}')
_WAR_ID = re.compile(r'war_[0-9a-f]{16}_[0-9a-f]{8}')
_NATIVE_FIELDS = {'event', 'schema_version', 'session_id', 'sequence', 'country', 'actor', 'recipient',
    'actor_fullref', 'recipient_fullref', 'observer_fullref', 'war_id', 'date_raw', 'actor_side',
    'recipient_side', 'observer_side', 'participants', 'source', 'complete'}
_PAYLOAD_FIELDS = {'country', 'actor', 'recipient', 'war_id', 'participants', 'observer_side', 'scope'}
_SIDES = {1: 'side_a', 2: 'side_b'}


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


def _valid_payload(payload, date):
    if (not isinstance(payload, dict) or set(payload) != _PAYLOAD_FIELDS
            or payload.get('country') != 'FRA' or payload.get('scope') != SCOPE
            or not _integer(date, 1, 2**31 - 1)
            or not _tag(payload.get('actor')) or not _tag(payload.get('recipient'))
            or payload['actor'] == payload['recipient']
            or not isinstance(payload.get('war_id'), str) or _WAR_ID.fullmatch(payload['war_id']) is None
            or not isinstance(payload.get('observer_side'), str) or payload['observer_side'] not in _SIDES.values()):
        return False
    participants = project_war_participants(payload.get('participants'), payload['actor'], payload['recipient'])
    return (participants is not None and participants['status'] == 'available'
            and participants['complete'] is True and 'FRA' in participants[payload['observer_side']])


def event_id(session_id, sequence):
    identity = hashlib.sha256((session_id+'\0war-declaration\0'+str(sequence)).encode()).hexdigest()[:32]
    return 'war-declared:'+identity


def objects(payload):
    participants = payload['participants']
    countries = list(dict.fromkeys([payload['actor'], payload['recipient'],
        *participants['side_a'], *participants['side_b']]))
    return [{'type': 'war', 'war_id': payload['war_id'], 'actor': payload['actor'], 'recipient': payload['recipient']},
            *[{'type': 'country', 'country': country} for country in countries]]


def project_role_labels(payload):
    """Label a validated declaration snapshot using its declaring actor's side."""
    result = deepcopy(payload)
    participants = result['participants']
    attacking_side = participants['actor_side']
    defending_side = participants['recipient_side']
    result.update(
        attackers=list(participants[attacking_side]),
        defenders=list(participants[defending_side]),
        observer_role='attacker' if result['observer_side'] == attacking_side else 'defender',
    )
    return result


def supported_ack(ack, game_sha256):
    return (rival_observation.supported_ack(ack, game_sha256)
            and supports_observer_version(ack, (49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64)) and ack.get(CAPABILITY) is True
            and type(ack.get('native_war_declaration_wire')) is int and ack['native_war_declaration_wire'] == 1
            and ack.get('native_war_declaration_scope') == SCOPE)


def public_observation(event, session_id):
    if (not isinstance(session_id, str) or not session_id or len(session_id) > 256
            or not isinstance(event, dict) or set(event) != _NATIVE_FIELDS
            or event.get('event') != NATIVE_EVENT or event.get('session_id') != session_id
            or type(event.get('schema_version')) is not int or event['schema_version'] != 1
            or event.get('source') != SOURCE or event.get('complete') is not True
            or not _integer(event.get('sequence'), 1, 2**63 - 1)
            or any(not _integer(event.get(key), 1, 2) for key in ('actor_side', 'recipient_side', 'observer_side'))):
        return None
    payload = {'country': event.get('country'), 'actor': event.get('actor'), 'recipient': event.get('recipient'),
        'war_id': event.get('war_id'), 'participants': event.get('participants'),
        'observer_side': _SIDES[event['observer_side']], 'scope': SCOPE}
    if (not _valid_payload(payload, event.get('date_raw'))
            or payload['participants']['actor_side'] != _SIDES[event['actor_side']]
            or payload['participants']['recipient_side'] != _SIDES[event['recipient_side']]
            or not _reference_matches(event.get('actor_fullref'), payload['actor'])
            or not _reference_matches(event.get('recipient_fullref'), payload['recipient'])
            or not _reference_matches(event.get('observer_fullref'), 'FRA')):
        return None
    return {'event_id': event_id(session_id, event['sequence']), 'native_sequence': event['sequence'],
        'game_date': event['date_raw'], 'objects': objects(payload), 'payload': deepcopy(payload)}


def valid_event_snapshot(event, context):
    if not isinstance(event, dict) or not isinstance(context, dict):
        return False
    session_id = context.get('session_id')
    payload, source = event.get('payload'), event.get('source')
    if (not isinstance(session_id, str) or not session_id or len(session_id) > 256
            or event.get('session_id') != session_id or event.get('observer') != 'FRA'
            or context.get('observer') != 'FRA' or context.get('game_sha256') != GAME_SHA256
            or event.get('event_type') != EVENT_TYPE or event.get('complete') is not True
            or not _valid_payload(payload, event.get('game_date')) or event.get('objects') != objects(payload)
            or not isinstance(source, dict) or source.get('session_id') != session_id
            or source.get('scope') != SCOPE or source.get('mode') != 'live' or source.get('complete') is not True
            or source.get('date_semantics') != DATE_SEMANTICS
            or not _integer(source.get('native_sequence'), 1, 2**63 - 1)):
        return False
    return event.get('event_id') == event_id(session_id, source['native_sequence'])


class Collector(NativeChangeCollector):
    def __init__(self, session_id):
        super().__init__(session_id, native_event=NATIVE_EVENT, native_gap=NATIVE_GAP,
            health_key='war_declaration_source', prefix='WAR_DECLARATION', decoder=public_observation,
            max_events=MAX_EVENTS)
