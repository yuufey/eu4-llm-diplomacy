"""Accepted land promises tied to an observed command and a registered war."""
import hashlib
import re

from .country_control_ack import supports_observer_version
from .native_change_observation import NativeChangeCollector
from .rival_observation import GAME_SHA256


CAPABILITY = 'native_land_promise_observation'
SCOPED_CAPABILITY = 'native_land_promise_configured_observers'
EVENT_TYPE = 'land_promise_established'
NATIVE_EVENT = 'native_land_promise_established'
NATIVE_GAP = 'native_land_promise_capture_gap'
DATE_SEMANTICS = 'native_promise_command_return_game_date'
SCOPE = 'FRA_member_in_observed_promise_war'
CONFIGURED_SCOPE = 'configured_observer_member_in_observed_promise_war'
SOURCES = {
    'declare_war_return_promised_participant': 'declare_war',
    'call_action_return_new_promised_participant': 'call_to_arms',
}
MAX_EVENTS = 1024
_TAG = re.compile(r'[A-Z0-9]{3}')
_REFERENCE = re.compile(r'0x[0-9a-f]{1,16}')
_WAR_ID = re.compile(r'war_[0-9a-f]{16}_[0-9a-f]{8}')
_NATIVE_FIELDS = {'event', 'session_id', 'sequence', 'date_raw', 'promisor_ref',
                  'beneficiary_ref', 'observer_ref', 'war_id', 'source', 'wire'}
_PAYLOAD_FIELDS = {'promisor', 'beneficiary', 'war_id', 'action_id', 'scope'}


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
    if not isinstance(payload, dict):
        return False
    scope = payload.get('scope')
    expected = _PAYLOAD_FIELDS | {'observer'} if scope == CONFIGURED_SCOPE else _PAYLOAD_FIELDS
    return (set(payload) == expected
            and (scope == SCOPE or (scope == CONFIGURED_SCOPE and isinstance(payload['observer'], str)
                                   and _TAG.fullmatch(payload['observer']) is not None))
            and all(isinstance(payload.get(key), str) and _TAG.fullmatch(payload[key]) is not None
                    for key in ('promisor', 'beneficiary'))
            and payload['promisor'] != payload['beneficiary']
            and isinstance(payload.get('war_id'), str) and _WAR_ID.fullmatch(payload['war_id']) is not None
            and payload.get('action_id') in SOURCES.values()
            and _integer(date, 1, 2**31 - 1))


def event_id(session_id, sequence):
    identity = hashlib.sha256((session_id + '\0land-promise\0' + str(sequence)).encode()).hexdigest()[:32]
    return 'land-promise:' + identity


def objects(payload):
    return [{'type': 'war', 'war_id': payload['war_id']},
            {'type': 'country', 'country': payload['promisor']},
            {'type': 'country', 'country': payload['beneficiary']},
            {'type': 'country_pair', 'actor': payload['promisor'], 'recipient': payload['beneficiary']}]


def supported_ack(ack, game_sha256):
    return (isinstance(ack, dict) and game_sha256 == GAME_SHA256
            and supports_observer_version(ack, (64,))
            and ack.get(CAPABILITY) is True
            and type(ack.get('native_land_promise_wire')) is int and ack['native_land_promise_wire'] == 1
            and ack.get('native_land_promise_scope') == SCOPE)


def public_observation(event, session_id):
    if (not isinstance(session_id, str) or not session_id or len(session_id) > 256
            or not isinstance(event, dict) or set(event) != _NATIVE_FIELDS
            or event.get('event') != NATIVE_EVENT or event.get('session_id') != session_id
            or not _integer(event.get('sequence'), 1, 2**63 - 1)
            or type(event.get('wire')) is not int or event['wire'] not in (1, 2)
            or not isinstance(event.get('source'), str) or event['source'] not in SOURCES):
        return None
    promisor = _reference_tag(event['promisor_ref'])
    beneficiary = _reference_tag(event['beneficiary_ref'])
    observer = _reference_tag(event['observer_ref'])
    if promisor is None or beneficiary is None or observer is None or (event['wire'] == 1 and observer != 'FRA'):
        return None
    payload = {'promisor': promisor, 'beneficiary': beneficiary, 'war_id': event['war_id'],
               'action_id': SOURCES[event['source']], 'scope': SCOPE}
    if event['wire'] == 2:
        payload.update(observer=observer, scope=CONFIGURED_SCOPE)
    if not _valid_payload(payload, event['date_raw']):
        return None
    return {'event_id': event_id(session_id, event['sequence']), 'native_sequence': event['sequence'],
            'game_date': event['date_raw'], 'payload': payload, 'objects': objects(payload)}


def valid_event_snapshot(event, context):
    if not isinstance(event, dict) or not isinstance(context, dict):
        return False
    session_id = context.get('session_id')
    payload, source = event.get('payload'), event.get('source')
    if not _valid_payload(payload, event.get('game_date')):
        return False
    observer = payload.get('observer', 'FRA')
    if (not isinstance(session_id, str) or not session_id or len(session_id) > 256
            or event.get('session_id') != session_id or event.get('observer') != observer
            or context.get('observer') != observer or context.get('game_sha256') != GAME_SHA256
            or event.get('event_type') != EVENT_TYPE or event.get('complete') is not True
            or event.get('objects') != objects(payload)
            or not isinstance(source, dict) or source.get('session_id') != session_id
            or source.get('scope') != payload['scope'] or source.get('mode') != 'live' or source.get('complete') is not True
            or source.get('date_semantics') != DATE_SEMANTICS
            or not _integer(source.get('native_sequence'), 1, 2**63 - 1)):
        return False
    return event.get('event_id') == event_id(session_id, source['native_sequence'])


class Collector(NativeChangeCollector):
    def __init__(self, session_id):
        super().__init__(session_id, native_event=NATIVE_EVENT, native_gap=NATIVE_GAP,
                         health_key='land_promise_source', prefix='LAND_PROMISE',
                         decoder=public_observation, max_events=MAX_EVENTS)

    def observe(self, event, *, allow_scoped=False):
        if (isinstance(event, dict) and event.get('event') == NATIVE_EVENT
                and event.get('session_id') == self.session_id
                and event.get('wire') != (2 if allow_scoped else 1)):
            self.gaps.add(self.prefix + '_OBSERVATION_INVALID')
            return
        super().observe(event)
