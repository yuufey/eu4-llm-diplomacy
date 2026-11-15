"""Owned B23 subsidy-expiry snapshots from the native removal return."""
import hashlib
import re

from .country_modifier_observation import GAME_SHA256
from .native_change_observation import NativeChangeCollector


CAPABILITY = 'native_subsidy_expiry_observation'
EVENT_TYPE = 'subsidy_expired'
NATIVE_EVENT = 'native_subsidy_expired'
NATIVE_GAP = 'native_subsidy_expiry_capture_gap'
SOURCE = 'subsidy_record_expiry_remove_return'
DATE_SEMANTICS = 'native_subsidy_expiry_remove_return_game_date'
SCOPE = 'FRA_payer_or_recipient_subsidy_expiry_returns'
MAX_EVENTS = 1024
_REFERENCE = re.compile(r'0x[0-9a-f]{1,16}')
_TAG = re.compile(r'[A-Z0-9]{3}')
_NATIVE_FIELDS = {'event', 'session_id', 'sequence', 'date_raw', 'payer_ref',
    'recipient_ref', 'observer_ref', 'start_date_raw', 'end_date_raw',
    'monthly_amount_raw', 'source', 'wire'}
_PAYLOAD_FIELDS = {'payer', 'recipient', 'start_date_raw', 'end_date_raw',
                   'monthly_amount_raw', 'scope'}


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _reference_tag(value):
    if not isinstance(value, str) or _REFERENCE.fullmatch(value) is None:
        return None
    reference = int(value, 16)
    if ((reference >> 32) & 0xffff) >= 4096:
        return None
    tag = (reference & 0xffffff).to_bytes(3, 'little').decode('ascii', errors='replace')
    return tag if _TAG.fullmatch(tag) is not None else None


def _valid_payload(payload, date):
    return (isinstance(payload, dict) and set(payload) == _PAYLOAD_FIELDS
            and all(isinstance(payload.get(key), str) and _TAG.fullmatch(payload[key]) is not None
                    for key in ('payer', 'recipient'))
            and payload['payer'] != payload['recipient']
            and 'FRA' in (payload['payer'], payload['recipient']) and payload.get('scope') == SCOPE
            and all(_integer(payload.get(key), -2**31, 2**31 - 1)
                    for key in ('start_date_raw', 'end_date_raw', 'monthly_amount_raw'))
            and _integer(date, 0, 2**31 - 1) and date > payload['end_date_raw'])


def event_id(session_id, sequence):
    identity = hashlib.sha256((session_id + '\0subsidy-expiry\0' + str(sequence)).encode()).hexdigest()[:32]
    return 'subsidy-expired:' + identity


def objects(payload):
    return [{'type': 'country_pair', 'actor': payload['payer'], 'recipient': payload['recipient']},
            {'type': 'country', 'country': payload['payer']},
            {'type': 'country', 'country': payload['recipient']}]


def supported_ack(ack, game_sha256):
    return (isinstance(ack, dict) and game_sha256 == GAME_SHA256
            and type(ack.get('version')) is int and ack['version'] in (62, 63, 64)
            and ack.get(CAPABILITY) is True
            and type(ack.get('native_subsidy_expiry_wire')) is int
            and ack['native_subsidy_expiry_wire'] == 1)


def public_observation(event, session_id):
    if (not isinstance(session_id, str) or not session_id or len(session_id) > 256
            or not isinstance(event, dict) or set(event) != _NATIVE_FIELDS
            or event.get('event') != NATIVE_EVENT or event.get('session_id') != session_id
            or not _integer(event.get('sequence'), 1, 2**63 - 1)
            or type(event.get('wire')) is not int or event['wire'] != 1
            or event.get('source') != SOURCE):
        return None
    payer, recipient = _reference_tag(event['payer_ref']), _reference_tag(event['recipient_ref'])
    if (payer is None or recipient is None or _reference_tag(event['observer_ref']) != 'FRA'
            or int(event['observer_ref'], 16) not in (
                int(event['payer_ref'], 16), int(event['recipient_ref'], 16))):
        return None
    payload = {key: event[key] for key in ('start_date_raw', 'end_date_raw', 'monthly_amount_raw')}
    payload.update(payer=payer, recipient=recipient, scope=SCOPE)
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
                         health_key='subsidy_expiry_source', prefix='SUBSIDY_EXPIRY',
                         decoder=public_observation, max_events=MAX_EVENTS)
