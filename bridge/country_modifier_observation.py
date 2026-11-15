"""Bounded, session-bound copies of B23 temporary country-modifier changes."""
from collections import OrderedDict
from copy import deepcopy
import hashlib
import json
import re

from .country_control_ack import supports_observer_version

GAME_SHA256 = 'b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77'
CAPABILITY = 'native_country_modifier_add_observation'
REMOVE_CAPABILITY = 'native_country_modifier_remove_observation'
EXPIRY_CAPABILITY = 'native_country_modifier_expiry_observation'
EVENT_TYPE = 'country_modifier_added'
REMOVE_EVENT_TYPE = 'country_modifier_removed'
EXPIRY_EVENT_TYPE = 'country_modifier_expired'
NATIVE_EVENT = 'native_country_modifier_added'
REMOVE_NATIVE_EVENT = 'native_country_modifier_removed'
EXPIRY_NATIVE_EVENT = 'native_country_modifier_expired'
NATIVE_GAP = 'native_country_modifier_capture_gap'
SOURCE = 'temporary_country_modifier_insert_return'
REMOVE_SOURCE = 'temporary_country_modifier_remove_return'
EXPIRY_SOURCE = 'temporary_country_modifier_expiry_remove_return'
NATIVE_SEMANTICS = {
    NATIVE_EVENT: ('added', SOURCE),
    REMOVE_NATIVE_EVENT: ('removed', REMOVE_SOURCE),
    EXPIRY_NATIVE_EVENT: ('expired', EXPIRY_SOURCE),
}
EVENT_SEMANTICS = {
    EVENT_TYPE: ('added', 'native_insert_return_game_date'),
    REMOVE_EVENT_TYPE: ('removed', 'native_remove_return_game_date'),
    EXPIRY_EVENT_TYPE: ('expired', 'native_expiry_remove_return_game_date'),
}
CHANGE_EVENT_TYPES = {semantics[0]: kind for kind, semantics in EVENT_SEMANTICS.items()}
SCOPE = 'FRA_direct_temporary_records'
MAX_EVENTS = 1024
_KEY = re.compile(r'[A-Za-z0-9_.-]{1,127}')
_FIELDS = frozenset({'event', 'schema_version', 'session_id', 'sequence', 'country',
    'country_fullref', 'modifier_id', 'date_raw', 'start_date_raw', 'end_date_raw',
    'flags', 'source', 'complete'})


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _valid_values(key, start, end, flags):
    return (isinstance(key, str) and _KEY.fullmatch(key) is not None
            and _integer(start, -2**31, 2**31 - 1) and _integer(end, -2**31, 2**31 - 1)
            and isinstance(flags, list) and len(flags) == 4
            and all(_integer(flag, 0, 1) for flag in flags))


def _event_id(session_id, sequence, change='added'):
    name = 'country-modifier-' + change
    identity = hashlib.sha256((session_id + '\0' + name + '\0' + str(sequence)).encode()).hexdigest()[:32]
    return name + ':' + identity


def supported_ack(ack, game_sha256):
    return (isinstance(ack, dict) and game_sha256 == GAME_SHA256
            and supports_observer_version(ack, (44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64))
            and (not supports_observer_version(ack, (57, 58, 59, 60, 61, 62, 63, 64)) or (
                ack.get('native_mission_condition_observation') is True
                and type(ack.get('native_mission_condition_wire')) is int
                and ack['native_mission_condition_wire'] == 2
                and ack.get('native_mission_condition_scope') == 'FRA_root_and_direct_area_province_holding_returns'))
            and (not supports_observer_version(ack, (58, 59, 60, 61, 62, 63, 64)) or (
                ack.get('native_mission_province_condition_observation') is True
                and ack.get('native_relation_change_observation') is True
                and ack.get('native_alliance_record_observation') is True
                and ack.get('native_royal_record_observation') is True
                and type(ack.get('native_relation_change_wire')) is int
                and ack['native_relation_change_wire'] == (5 if supports_observer_version(ack, (60, 61, 62, 63, 64)) else 4 if ack['version'] == 59 else 3)
                and ack.get('native_relation_change_scope')
                == ('FRA_pair_at_six_relation_command_or_six_family_record_returns'
                    if supports_observer_version(ack, (60, 61, 62, 63, 64)) else
                    'FRA_pair_at_six_relation_command_or_alliance_or_royal_or_directed_record_returns'
                    if ack['version'] == 59 else
                    'FRA_pair_at_six_relation_command_or_alliance_or_royal_record_returns')))
            and (not supports_observer_version(ack, (59, 60, 61, 62, 63, 64)) or ack.get('native_directed_record_observation') is True)
            and (not supports_observer_version(ack, (60, 61, 62, 63, 64)) or ack.get('native_support_subject_record_observation') is True)
            and (not supports_observer_version(ack, (61, 62, 63, 64)) or (
                ack.get('native_rival_record_observation') is True
                and type(ack.get('native_rival_change_wire')) is int
                and ack['native_rival_change_wire'] == 2
                and ack.get('native_rival_change_scope')
                == 'FRA_actor_target_or_old_rival_at_command_or_country_rival_record_returns'
                and ack.get('native_rival_record_count_basis') == 'active_nonretired_nodes'))
            and ack.get(CAPABILITY) is True
            and type(ack.get('native_country_modifier_add_wire')) is int
            and ack['native_country_modifier_add_wire'] == 1
            and ack.get('native_country_modifier_scope') == SCOPE)


def supported_remove_ack(ack, game_sha256):
    return (supported_ack(ack, game_sha256) and supports_observer_version(ack, (46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64))
            and ack.get(REMOVE_CAPABILITY) is True
            and type(ack.get('native_country_modifier_remove_wire')) is int
            and ack['native_country_modifier_remove_wire'] == 1)


def supported_expiry_ack(ack, game_sha256):
    return (supported_remove_ack(ack, game_sha256) and supports_observer_version(ack, (47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64))
            and ack.get(EXPIRY_CAPABILITY) is True
            and type(ack.get('native_country_modifier_expiry_wire')) is int
            and ack['native_country_modifier_expiry_wire'] == 1)


def public_observation(event, session_id):
    kind = event.get('event') if isinstance(event, dict) else None
    semantics = NATIVE_SEMANTICS.get(kind) if isinstance(kind, str) else None
    if semantics is None:
        return None
    change, source = semantics
    if (not isinstance(session_id, str) or not session_id or len(session_id) > 256
            or not isinstance(event, dict) or set(event) != _FIELDS
            or event.get('session_id') != session_id
            or type(event.get('schema_version')) is not int or event['schema_version'] != 1
            or not _integer(event.get('sequence'), 1, 2**63 - 1)
            or event.get('country') != 'FRA' or event.get('source') != source
            or event.get('complete') is not True
            or not _integer(event.get('date_raw'), 0, 2**31 - 1)
            or not _valid_values(event.get('modifier_id'), event.get('start_date_raw'),
                                 event.get('end_date_raw'), event.get('flags'))):
        return None
    if change == 'expired' and event['end_date_raw'] > event['date_raw']:
        return None
    reference = event.get('country_fullref')
    if not isinstance(reference, str) or re.fullmatch(r'0x[0-9a-f]{1,16}', reference) is None:
        return None
    reference = int(reference, 16)
    if reference & 0xffffff != 0x415246 or ((reference >> 32) & 0xffff) >= 4096:
        return None
    return {'event_id': _event_id(session_id, event['sequence'], change), 'native_sequence': event['sequence'],
            'game_date': event['date_raw'], 'payload': {
                'country': 'FRA', 'modifier_id': event['modifier_id'], 'change': change,
                'start_date_raw': event['start_date_raw'], 'end_date_raw': event['end_date_raw'],
                'flags_raw': list(event['flags']), 'scope': SCOPE}}


def valid_event_snapshot(event, context):
    session_id = context.get('session_id')
    payload = event.get('payload')
    source = event.get('source')
    event_type = event.get('event_type')
    semantics = EVENT_SEMANTICS.get(event_type) if isinstance(event_type, str) else None
    if semantics is None:
        return False
    change, date_semantics = semantics
    if (not isinstance(session_id, str) or not session_id or len(session_id) > 256
            or event.get('session_id') != session_id
            or event.get('observer') != 'FRA' or context.get('observer') != 'FRA'
            or context.get('game_sha256') != GAME_SHA256 or event.get('complete') is not True
            or not _integer(event.get('game_date'), 0, 2**31 - 1)
            or event.get('objects') != [{'type': 'country', 'country': 'FRA'}]
            or not isinstance(payload, dict)
            or set(payload) != {'country', 'modifier_id', 'change', 'start_date_raw', 'end_date_raw', 'flags_raw', 'scope'}
            or payload.get('country') != 'FRA' or payload.get('change') != change or payload.get('scope') != SCOPE
            or not _valid_values(payload.get('modifier_id'), payload.get('start_date_raw'),
                                 payload.get('end_date_raw'), payload.get('flags_raw'))
            or not isinstance(source, dict) or source.get('session_id') != session_id
            or source.get('scope') != SCOPE or source.get('mode') != 'live' or source.get('complete') is not True
            or source.get('date_semantics') != date_semantics
            or not _integer(source.get('native_sequence'), 1, 2**63 - 1)):
        return False
    if change == 'expired' and payload['end_date_raw'] > event['game_date']:
        return False
    return event.get('event_id') == _event_id(session_id, source['native_sequence'], change)


class Collector:
    """One cache on the existing native log cursor, with bounded replay memory."""

    def __init__(self, session_id):
        self.session_id = session_id
        self.events = OrderedDict()
        self.fingerprints = OrderedDict()
        self.last_sequence = 0
        self.evicted_through = 0
        self.gaps = set()
        self.last_status = None

    def observe(self, event, *, allow_removal=False, allow_expiry=False):
        if not isinstance(event, dict) or event.get('session_id') != self.session_id:
            return
        kind = event.get('event')
        if kind == NATIVE_GAP:
            if (event.get('complete') is False
                    and _integer(event.get('dropped'), 1, 2**31 - 1)):
                self.gaps.add('COUNTRY_MODIFIER_CAPTURE_DROPPED')
            else:
                self.gaps.add('COUNTRY_MODIFIER_GAP_INVALID')
            return
        if kind == 'diplomacy_observer_health':
            status = event.get('country_modifier_source')
            if status is None:
                self.gaps.add('COUNTRY_MODIFIER_HEALTH_INVALID')
                return
            if (not isinstance(status, dict)
                    or any(type(status.get(key)) is not bool for key in
                           ('installed', 'transport_fault', 'queue_readable'))
                    or not _integer(status.get('total_dropped'), 0, 2**31 - 1)
                    or not _integer(status.get('queued'), 0, 64)):
                self.gaps.add('COUNTRY_MODIFIER_HEALTH_INVALID')
                return
            self.last_status = deepcopy(status)
            if status['transport_fault']:
                self.gaps.add('COUNTRY_MODIFIER_TRANSPORT_FAULT')
            if status['total_dropped']:
                self.gaps.add('COUNTRY_MODIFIER_CAPTURE_DROPPED')
            return
        if (kind != NATIVE_EVENT
                and not (kind == REMOVE_NATIVE_EVENT and allow_removal is True)
                and not (kind == EXPIRY_NATIVE_EVENT and allow_expiry is True)):
            return
        public = public_observation(event, self.session_id)
        if public is None:
            self.gaps.add('COUNTRY_MODIFIER_OBSERVATION_INVALID')
            return
        sequence = public['native_sequence']
        fingerprint = hashlib.sha256(json.dumps(event, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        previous = self.fingerprints.get(sequence)
        if previous is not None:
            if previous != fingerprint:
                self.gaps.add('COUNTRY_MODIFIER_SEQUENCE_CONFLICT')
            return
        if sequence <= self.last_sequence:
            return
        if sequence != self.last_sequence + 1:
            self.gaps.add('COUNTRY_MODIFIER_SEQUENCE_GAP')
        self.last_sequence = sequence
        self.events[sequence] = public
        self.fingerprints[sequence] = fingerprint
        if len(self.events) > MAX_EVENTS:
            self.evicted_through, _ = self.events.popitem(last=False)
        if len(self.fingerprints) > MAX_EVENTS:
            self.fingerprints.popitem(last=False)

    def batch(self, after_sequence):
        if not _integer(after_sequence, 0, 2**63 - 1):
            raise ValueError('COUNTRY_MODIFIER_CURSOR_INVALID')
        gaps = set(self.gaps)
        if after_sequence < self.evicted_through:
            gaps.add('COUNTRY_MODIFIER_CACHE_EVICTED')
        if self.last_status is not None and not self.last_status['installed']:
            gaps.add('COUNTRY_MODIFIER_SOURCE_UNAVAILABLE')
        return {'events': [deepcopy(event) for sequence, event in self.events.items()
                           if sequence > after_sequence],
                'complete': not gaps, 'gaps': sorted(gaps)}
