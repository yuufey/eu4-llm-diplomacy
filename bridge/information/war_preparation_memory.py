"""Read bilateral, current prepare-for-war pledges from admitted countries."""
from __future__ import annotations

import struct

from .engine_dates import project_engine_date


FIELD = 'R07.war_commitments'
DEADLINE_OFFSET = 0x2728


def read_fields(reader, base, binding, requested, *, observer_binding):
    read = getattr(reader, 'read', reader)
    evidence = []
    try:
        world_raw = read(base + 0x233FE58, 8, 'war_preparation.world')
        world = int.from_bytes(world_raw, 'little')
        if len(world_raw) != 8 or not 0x10000 <= world < 0x800000000000:
            raise ValueError('WAR_PREPARATION_WORLD_INVALID')
        date_raw = read(world + 0x1DD0, 4, 'war_preparation.current_date')
        if len(date_raw) != 4:
            raise ValueError('WAR_PREPARATION_DATE_SHORT_READ')
        current = int.from_bytes(date_raw, 'little', signed=True)
        promises = []
        for preparing, requester in ((binding, observer_binding), (observer_binding, binding)):
            pointer = int(preparing['country_pointer'], 0)
            raw = read(pointer + DEADLINE_OFFSET, 12, 'war_preparation.' + preparing['tag'])
            if len(raw) != 12:
                raise ValueError('WAR_PREPARATION_SHORT_READ')
            deadline, reference = struct.unpack('<iQ', raw)
            evidence.append({'country': preparing['tag'], 'raw_hex': raw.hex()})
            # Native readiness compares year/day components, ignoring hour-of-day.
            if deadline // 24 > current // 24 and reference == int(requester['fullref'], 0):
                promises.append({'kind': 'war_preparation', 'country': preparing['tag'],
                                 'for': requester['tag'],
                                 'until': project_engine_date(deadline)['date']})
        field = {'status': 'known', 'value': sorted(promises, key=lambda row: row['country']),
                 'complete': True, 'period': 'current',
                 'raw_inputs': {'records': evidence}}
    except (ValueError, KeyError, TypeError, struct.error) as exc:
        field = {'status': 'unknown', 'reason': str(exc), 'raw_inputs': {'records': evidence}}
    return {name: field if name == FIELD else {'status': 'unsupported'} for name in requested}
