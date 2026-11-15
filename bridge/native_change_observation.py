"""Bounded native change records fed by the shared ObserverSession log reader."""
from collections import OrderedDict
from copy import deepcopy
import hashlib
import json


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


class NativeChangeCollector:
    """Keep owned snapshots, sequence gaps and health for one native source."""

    def __init__(self, session_id, *, native_event, native_gap, health_key, prefix, decoder, max_events):
        self.session_id = session_id
        self.native_event = native_event
        self.native_gap = native_gap
        self.health_key = health_key
        self.prefix = prefix
        self.decoder = decoder
        self.max_events = max_events
        self.events, self.fingerprints = OrderedDict(), OrderedDict()
        self.last_sequence = self.evicted_through = 0
        self.gaps = set()
        self.last_status = None

    def observe(self, event):
        if not isinstance(event, dict) or event.get('session_id') != self.session_id:
            return
        kind = event.get('event')
        if kind == self.native_gap:
            if event.get('complete') is False and _integer(event.get('dropped'), 1, 2**31 - 1):
                self.gaps.add(self.prefix+'_CAPTURE_DROPPED')
            else:
                self.gaps.add(self.prefix+'_GAP_INVALID')
            return
        if kind == 'diplomacy_observer_health':
            status = event.get(self.health_key)
            if (not isinstance(status, dict)
                    or any(type(status.get(key)) is not bool for key in ('installed', 'transport_fault', 'queue_readable'))
                    or not _integer(status.get('total_dropped'), 0, 2**31 - 1)
                    or not _integer(status.get('queued'), 0, 64)):
                self.gaps.add(self.prefix+'_HEALTH_INVALID')
                return
            self.last_status = deepcopy(status)
            if status['transport_fault']:
                self.gaps.add(self.prefix+'_TRANSPORT_FAULT')
            if status['total_dropped']:
                self.gaps.add(self.prefix+'_CAPTURE_DROPPED')
            return
        if kind != self.native_event:
            return
        public = self.decoder(event, self.session_id)
        if public is None:
            self.gaps.add(self.prefix+'_OBSERVATION_INVALID')
            return
        sequence = public['native_sequence']
        fingerprint = hashlib.sha256(json.dumps(event, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        previous = self.fingerprints.get(sequence)
        if previous is not None:
            if previous != fingerprint:
                self.gaps.add(self.prefix+'_SEQUENCE_CONFLICT')
            return
        if sequence <= self.last_sequence:
            return
        if sequence != self.last_sequence + 1:
            self.gaps.add(self.prefix+'_SEQUENCE_GAP')
        self.last_sequence = sequence
        self.events[sequence], self.fingerprints[sequence] = public, fingerprint
        if len(self.events) > self.max_events:
            self.evicted_through, _ = self.events.popitem(last=False)
        if len(self.fingerprints) > self.max_events:
            self.fingerprints.popitem(last=False)

    def batch(self, after_sequence):
        if not _integer(after_sequence, 0, 2**63 - 1):
            raise ValueError(self.prefix+'_CURSOR_INVALID')
        gaps = set(self.gaps)
        if after_sequence < self.evicted_through:
            gaps.add(self.prefix+'_CACHE_EVICTED')
        if self.last_status is not None and not self.last_status['installed']:
            gaps.add(self.prefix+'_SOURCE_UNAVAILABLE')
        return {'events': [deepcopy(event) for sequence, event in self.events.items() if sequence > after_sequence],
                'complete': not gaps, 'gaps': sorted(gaps)}
