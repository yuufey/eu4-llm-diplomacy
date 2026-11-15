"""Project the native war overview's participation shares for active members."""
from ctypes import c_int32
import struct

from . import war_land_commitments_memory as _participants


def participation_share(target_reference, side_a_references, records):
    """Reproduce B23 d95820, including signed accumulation and its zero-total rule."""
    target_slot = (target_reference >> 32) & 0xffff
    side_a_slots = {(reference >> 32) & 0xffff for reference in side_a_references}
    target_side_a = target_slot in side_a_slots
    same_side = [(slot, points) for slot, points in records
                 if (slot in side_a_slots) == target_side_a]
    total = c_int32(sum(points for _, points in same_side)).value
    numerator = c_int32(sum(points for slot, points in same_side if slot == target_slot)).value
    if total <= 0:
        return 1000 if records and records[0][0] == target_slot else 0
    quotient = abs(numerator * 1000) // total
    return c_int32(-quotient if numerator < 0 else quotient).value


def read_contribution(reader, base, war_field, layout):
    if war_field.get('status') != 'known':
        return {'status': 'unknown', 'reason': 'WAR_CONTRIBUTION_WARS_UNAVAILABLE'}
    wars = war_field['value']['wars']
    private_wars = war_field['raw_inputs']['war_objects']
    if len(wars) != len(private_wars):
        return {'status': 'unknown', 'reason': 'WAR_CONTRIBUTION_WAR_SHAPE'}
    values, evidence, unavailable = [], [], set()
    complete = True
    try:
        stride = layout['participant_stride']
        country_offset = int(layout['participant_country_offset'], 0)
        points_offset = int(layout['participation_points_offset'], 0)
        table = base + int(layout['participant_vtable_rva'], 0)
        for war, private in zip(wars, private_wars):
            active = _participants._active_members(war, private)
            body, header = _participants._participant_rows(reader, base, private, layout)
            records, retained = [], []
            for offset in range(0, len(body), stride):
                record = body[offset:offset + stride]
                if struct.unpack_from('<Q', record)[0] != table:
                    raise ValueError('WAR_CONTRIBUTION_RECORD_TYPE')
                reference = struct.unpack_from('<Q', record, country_offset)[0]
                points = struct.unpack_from('<i', record, points_offset)[0]
                records.append(((reference >> 32) & 0xffff, points))
                retained.append({'country_reference': hex(reference), 'points_raw': points})
            side_a = [reference for reference, (side, _) in active.items() if side == 'side_a']
            item = {'war_id': war['war_id'].get('value'), 'our_side': {}, 'opposing_side': {},
                    'complete': True, 'gaps': []}
            for reference, (side, descriptor) in active.items():
                label = 'our_side' if side == war['target_side'] else 'opposing_side'
                if descriptor.get('status') != 'known':
                    complete = False
                    item['complete'] = False
                    item['gaps'].append({'side': label, 'reason': descriptor.get('reason', 'MEMBER_UNAVAILABLE')})
                    unavailable.add(reference.to_bytes(8, 'little')[:3].decode('ascii'))
                    continue
                share = participation_share(reference, side_a, records)
                item[label][descriptor['country']] = {
                    'status': 'known', 'value': {'percent': share / 10}, 'raw': share,
                    'unit': 'side_participation_ratio', 'scale': 1000, 'complete': True}
            values.append(item)
            evidence.append({'war_pointer': private['native_pointer'], 'vector_raw_hex': header.hex(),
                             'participant_records': retained})
    except (ValueError, KeyError, TypeError, struct.error) as exc:
        return {'status': 'unknown', 'reason': str(exc)}
    return {'status': 'known', 'value': values, 'complete': complete,
            'raw_inputs': {'wars': evidence, 'unavailable_countries': sorted(unavailable)}}
