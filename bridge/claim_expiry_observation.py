"""Owned claim removals from B23's confirmed natural-expiry call site."""
import hashlib
import re

from .country_control_ack import supports_observer_version
from .country_modifier_observation import GAME_SHA256
from .native_change_observation import NativeChangeCollector


CAPABILITY = 'native_claim_expiry_observation'
EVENT_TYPE = 'claim_expired'
NATIVE_EVENT = 'native_claim_expired'
NATIVE_GAP = 'native_claim_expiry_capture_gap'
SOURCE = 'claim_record_natural_expiry_remove_return'
DATE_SEMANTICS = 'native_claim_expiry_remove_return_game_date'
SCOPE = 'FRA_claimant_or_current_owner_at_native_claim_expiry_remove_return'
MAX_EVENTS = 1024
_REFERENCE = re.compile(r'0x[0-9a-f]{1,16}')
_TAG = re.compile(r'[A-Z0-9]{3}')
_NATIVE_FIELDS = {'event', 'session_id', 'sequence', 'date_raw', 'claimant_ref',
                  'owner_ref', 'observer_ref', 'province_id', 'source', 'wire'}
_PAYLOAD_FIELDS = {'claimant', 'owner', 'province_id', 'scope'}


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _reference_tag(value, *, allow_empty=False):
    if not isinstance(value, str) or _REFERENCE.fullmatch(value) is None:
        return None
    reference = int(value, 16)
    if ((reference >> 32) & 0xffff) >= 4096:
        return None
    tag = (reference & 0xffffff).to_bytes(3, 'little').decode('ascii', errors='replace')
    if _TAG.fullmatch(tag) is not None or (allow_empty and tag == '---'):
        return tag
    return None


def _valid_payload(payload, date):
    return (isinstance(payload, dict) and set(payload) == _PAYLOAD_FIELDS
            and isinstance(payload.get('claimant'), str) and _TAG.fullmatch(payload['claimant']) is not None
            and (payload.get('owner') is None or (
                isinstance(payload['owner'], str) and _TAG.fullmatch(payload['owner']) is not None))
            and 'FRA' in (payload['claimant'], payload['owner'])
            and _integer(payload.get('province_id'), 1, 65535) and payload.get('scope') == SCOPE
            and _integer(date, 0, 2**31 - 1))


def event_id(session_id, sequence):
    identity = hashlib.sha256((session_id + '\0claim-expiry\0' + str(sequence)).encode()).hexdigest()[:32]
    return 'claim-expired:' + identity


def objects(payload):
    result = [{'type': 'country', 'country': payload['claimant']},
              {'type': 'province', 'province_id': payload['province_id']}]
    if payload['owner'] is not None and payload['owner'] != payload['claimant']:
        result.extend(({'type': 'country', 'country': payload['owner']},
                       {'type': 'country_pair', 'actor': payload['claimant'], 'recipient': payload['owner']}))
    return result


def supported_ack(ack, game_sha256):
    return (isinstance(ack, dict) and game_sha256 == GAME_SHA256
            and supports_observer_version(ack, (63, 64))
            and ack.get(CAPABILITY) is True
            and type(ack.get('native_claim_expiry_wire')) is int and ack['native_claim_expiry_wire'] == 1
            and ack.get('native_claim_expiry_scope') == SCOPE)


def public_observation(event, session_id):
    if (not isinstance(session_id, str) or not session_id or len(session_id) > 256
            or not isinstance(event, dict) or set(event) != _NATIVE_FIELDS
            or event.get('event') != NATIVE_EVENT or event.get('session_id') != session_id
            or not _integer(event.get('sequence'), 1, 2**63 - 1)
            or type(event.get('wire')) is not int or event['wire'] != 1
            or event.get('source') != SOURCE):
        return None
    claimant = _reference_tag(event['claimant_ref'])
    owner = _reference_tag(event['owner_ref'], allow_empty=True)
    if (claimant is None or owner is None or _reference_tag(event['observer_ref']) != 'FRA'
            or int(event['observer_ref'], 16) not in (int(event['claimant_ref'], 16), int(event['owner_ref'], 16))):
        return None
    payload = {'claimant': claimant, 'owner': None if owner == '---' else owner,
               'province_id': event['province_id'], 'scope': SCOPE}
    if not _valid_payload(payload, event['date_raw']):
        return None
    return {'event_id': event_id(session_id, event['sequence']), 'native_sequence': event['sequence'],
            'game_date': event['date_raw'], 'payload': payload, 'objects': objects(payload)}


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
                         health_key='claim_expiry_source', prefix='CLAIM_EXPIRY',
                         decoder=public_observation, max_events=MAX_EVENTS)
