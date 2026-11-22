"""Owned directional direct-truce expiries from the B23 maintenance return."""
import hashlib
import re

from .country_control_ack import supports_observer_version
from .country_modifier_observation import GAME_SHA256
from .information.truce_date_math import direct_truce_expiry
from .native_change_observation import NativeChangeCollector


CAPABILITY = 'native_truce_expiry_observation'
SCOPED_CAPABILITY = 'native_truce_expiry_scoped'
EVENT_TYPE = 'truce_expired'
NATIVE_EVENT = 'native_truce_expired'
NATIVE_GAP = 'native_truce_expiry_capture_gap'
SOURCE = 'direct_truce_maintenance_return'
DATE_SEMANTICS = 'native_direct_truce_maintenance_return_game_date'
SCOPE = 'FRA_actor_or_recipient_directional_direct_truce_expiry_returns'
CONFIGURED_SCOPE = 'configured_observer_' + SCOPE.removeprefix('FRA_')
MAX_EVENTS = 1024
_REFERENCE = re.compile(r'0x[0-9a-f]{1,16}')
_TAG = re.compile(r'[A-Z0-9]{3}')
_INPUTS = ('date_input_raw', 'adjustment_raw', 'configuration_a_raw', 'configuration_b_raw', 'end_date_raw')
_NATIVE_FIELDS = {'event', 'session_id', 'sequence', 'date_raw', 'actor_ref',
                  'recipient_ref', 'observer_ref', 'source', 'wire', *_INPUTS}
_PAYLOAD_FIELDS = {'actor', 'recipient', 'scope', *_INPUTS}


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


def _payload_observer(payload):
    if not isinstance(payload, dict):
        return None
    if payload.get('scope') == SCOPE:
        return 'FRA'
    if payload.get('scope') != CONFIGURED_SCOPE:
        return None
    observer = payload.get('observer')
    return observer if isinstance(observer, str) and _TAG.fullmatch(observer) is not None else None


def _valid_payload(payload, date):
    observer = _payload_observer(payload)
    expected_fields = _PAYLOAD_FIELDS | {'observer'} if isinstance(payload, dict) and payload.get('scope') == CONFIGURED_SCOPE else _PAYLOAD_FIELDS
    if (observer is None or set(payload) != expected_fields
            or any(not isinstance(payload.get(key), str) or _TAG.fullmatch(payload[key]) is None
                   for key in ('actor', 'recipient'))
            or payload['actor'] == payload['recipient']
            or observer not in (payload['actor'], payload['recipient'])
            or not _integer(date, 0, 2**31 - 1)
            or not _integer(payload.get('adjustment_raw'), -128, 127)
            or any(not _integer(payload.get(key), -2**31, 2**31 - 1)
                   for key in ('date_input_raw', 'configuration_a_raw', 'configuration_b_raw', 'end_date_raw'))):
        return False
    try:
        expiry = direct_truce_expiry(payload['date_input_raw'], payload['adjustment_raw'],
                                     payload['configuration_a_raw'], payload['configuration_b_raw'])
    except ValueError:
        return False
    return payload['date_input_raw'] <= date and payload['end_date_raw'] == expiry['raw'] <= date


def event_id(session_id, sequence):
    identity = hashlib.sha256((session_id + '\0truce-expiry\0' + str(sequence)).encode()).hexdigest()[:32]
    return 'truce-expired:' + identity


def objects(payload):
    return [{'type': 'country_pair', 'actor': payload['actor'], 'recipient': payload['recipient']},
            {'type': 'country', 'country': payload['actor']},
            {'type': 'country', 'country': payload['recipient']}]


def supported_ack(ack, game_sha256):
    return (isinstance(ack, dict) and game_sha256 == GAME_SHA256
            and supports_observer_version(ack, (62, 63, 64))
            and ack.get(CAPABILITY) is True
            and type(ack.get('native_truce_expiry_wire')) is int and ack['native_truce_expiry_wire'] == 1
            and ack.get('native_truce_expiry_scope') == SCOPE)


def public_observation(event, session_id):
    if (not isinstance(session_id, str) or not session_id or len(session_id) > 256
            or not isinstance(event, dict) or set(event) != _NATIVE_FIELDS
            or event.get('event') != NATIVE_EVENT or event.get('session_id') != session_id
            or not _integer(event.get('sequence'), 1, 2**63 - 1)
            or type(event.get('wire')) is not int or event['wire'] not in (1, 2)
            or event.get('source') != SOURCE):
        return None
    actor = _reference_tag(event['actor_ref'])
    recipient = _reference_tag(event['recipient_ref'])
    observer = _reference_tag(event['observer_ref'])
    if (actor is None or recipient is None or observer is None or (event['wire'] == 1 and observer != 'FRA')
            or int(event['observer_ref'], 16) not in (int(event['actor_ref'], 16), int(event['recipient_ref'], 16))):
        return None
    payload = {key: event[key] for key in _INPUTS}
    payload.update(actor=actor, recipient=recipient, scope=SCOPE)
    if event['wire'] == 2:
        payload.update(scope=CONFIGURED_SCOPE, observer=observer)
    if not _valid_payload(payload, event['date_raw']):
        return None
    return {'event_id': event_id(session_id, event['sequence']), 'native_sequence': event['sequence'],
            'game_date': event['date_raw'], 'payload': payload, 'objects': objects(payload)}


def valid_event_snapshot(event, context):
    if not isinstance(event, dict) or not isinstance(context, dict):
        return False
    session_id = context.get('session_id')
    payload, source = event.get('payload'), event.get('source')
    observer = context.get('observer')
    if (not isinstance(session_id, str) or not session_id or len(session_id) > 256
            or event.get('session_id') != session_id or event.get('observer') != observer
            or _payload_observer(payload) != observer or context.get('game_sha256') != GAME_SHA256
            or event.get('event_type') != EVENT_TYPE or event.get('complete') is not True
            or not _valid_payload(payload, event.get('game_date')) or event.get('objects') != objects(payload)
            or not isinstance(source, dict) or source.get('session_id') != session_id
            or source.get('scope') != payload['scope'] or source.get('mode') != 'live' or source.get('complete') is not True
            or source.get('date_semantics') != DATE_SEMANTICS
            or not _integer(source.get('native_sequence'), 1, 2**63 - 1)):
        return False
    return event.get('event_id') == event_id(session_id, source['native_sequence'])


class Collector(NativeChangeCollector):
    def __init__(self, session_id):
        super().__init__(session_id, native_event=NATIVE_EVENT, native_gap=NATIVE_GAP,
                         health_key='truce_expiry_source', prefix='TRUCE_EXPIRY',
                         decoder=public_observation, max_events=MAX_EVENTS)

    def observe(self, event, *, allow_scoped=False):
        if (isinstance(event, dict) and event.get('event') == NATIVE_EVENT
                and event.get('session_id') == self.session_id and event.get('wire') != (2 if allow_scoped else 1)):
            self.gaps.add(self.prefix + '_OBSERVATION_INVALID')
            return
        super().observe(event)
