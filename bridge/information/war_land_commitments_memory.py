"""Read current participants' land-promise flags from an admitted war index."""
from __future__ import annotations

import struct


MAX_SINGLE_READ = 65536
MIN_ADDRESS = 0x10000
MAX_ADDRESS = 0x800000000000


def _read(reader, address, size, label):
    if (type(address) is not int or not MIN_ADDRESS <= address < MAX_ADDRESS
            or type(size) is not int or not 0 < size <= MAX_SINGLE_READ
            or address > MAX_ADDRESS - size):
        raise ValueError('LAND_COMMITMENTS_READ_RANGE')
    method = getattr(reader, 'read', reader)
    raw = method(address, size, 'land_commitments.' + label)
    if not isinstance(raw, bytes) or len(raw) != size:
        raise ValueError('LAND_COMMITMENTS_SHORT_READ')
    return raw


def _active_members(war, private):
    members = {}
    for side in ('side_a', 'side_b'):
        raw = bytes.fromhex(private[side + '_raw_hex'])
        descriptors = war[side]
        if len(raw) != len(descriptors) * 8:
            raise ValueError('LAND_COMMITMENTS_MEMBER_SHAPE')
        for index, descriptor in enumerate(descriptors):
            reference = struct.unpack_from('<Q', raw, index * 8)[0]
            members[reference] = (side, descriptor)
    return members


def _participant_rows(reader, base, private, layout):
    pointer = int(private['native_pointer'], 0)
    prefix = bytes.fromhex(private['prefix_raw_hex'])
    if _read(reader, pointer, len(prefix), 'war_prefix') != prefix:
        raise ValueError('LAND_COMMITMENTS_WAR_CHANGED')
    vector_offset = int(layout['participant_vector_offset'], 0)
    header = _read(reader, pointer + vector_offset, 24, 'vector')
    begin, end, capacity = struct.unpack('<QQQ', header)
    stride = layout['participant_stride']
    if (end < begin or capacity < end or (end - begin) % stride
            or (end - begin) // stride > layout['max_participant_records']):
        raise ValueError('LAND_COMMITMENTS_VECTOR_SHAPE')
    body = bytearray()
    for offset in range(0, end - begin, MAX_SINGLE_READ):
        body.extend(_read(reader, begin + offset,
                          min(MAX_SINGLE_READ, end - begin - offset), 'records'))
    if _read(reader, pointer + vector_offset, 24, 'vector_after') != header:
        raise ValueError('LAND_COMMITMENTS_VECTOR_CHANGED')
    if _read(reader, pointer, len(prefix), 'war_prefix_after') != prefix:
        raise ValueError('LAND_COMMITMENTS_WAR_CHANGED')
    for side in ('side_a', 'side_b'):
        vector = private[side + '_vector']
        expected = bytes.fromhex(private[side + '_raw_hex'])
        if expected and _read(reader, vector['begin'], len(expected), side + '_after') != expected:
            raise ValueError('LAND_COMMITMENTS_MEMBERS_CHANGED')
    return bytes(body), header


def read_land_commitments(reader, base, war_field, layout):
    """Project flags for active, visible members and retain bounded raw evidence."""
    if war_field.get('status') != 'known':
        return {'status': 'unknown', 'reason': 'LAND_COMMITMENTS_WARS_UNAVAILABLE'}
    value = war_field['value']
    private_wars = war_field['raw_inputs']['war_objects']
    if len(value['wars']) != len(private_wars):
        return {'status': 'unknown', 'reason': 'LAND_COMMITMENTS_WAR_SHAPE'}
    rows, evidence, unavailable = [], [], set()
    complete = True
    try:
        stride = layout['participant_stride']
        table = base + int(layout['participant_vtable_rva'], 0)
        country_offset = int(layout['participant_country_offset'], 0)
        promise_offset = int(layout['promised_land_offset'], 0)
        for war, private in zip(value['wars'], private_wars):
            active = _active_members(war, private)
            body, header = _participant_rows(reader, base, private, layout)
            seen = set()
            active_evidence = []
            war_id = war['war_id'].get('value') if war['war_id'].get('status') == 'known' else None
            for offset in range(0, len(body), stride):
                record = body[offset:offset + stride]
                if struct.unpack_from('<Q', record)[0] != table:
                    raise ValueError('LAND_COMMITMENTS_RECORD_TYPE')
                reference = struct.unpack_from('<Q', record, country_offset)[0]
                if reference not in active:
                    continue
                if reference in seen:
                    raise ValueError('LAND_COMMITMENTS_DUPLICATE_MEMBER')
                seen.add(reference)
                active_evidence.append({'country_reference': hex(reference),
                                        'promised_land_raw': record[promise_offset]})
                side, descriptor = active[reference]
                if descriptor.get('status') != 'known':
                    complete = False
                    unavailable.add(reference.to_bytes(8, 'little')[:3].decode('ascii'))
                    continue
                if record[promise_offset] == layout['promised_land_true_byte']:
                    commitment = {
                        'war_id': war_id,
                        'beneficiary': descriptor['country'],
                        'side': 'our_side' if side == war['target_side'] else 'opposing_side',
                    }
                    if war_id is None:
                        opposing_side = 'side_b' if side == 'side_a' else 'side_a'
                        opponents = [member['country'] for member in war[opposing_side]
                                     if member.get('status') == 'known']
                        commitment['opponents'] = opponents or None
                    rows.append(commitment)
            if set(active) != seen:
                raise ValueError('LAND_COMMITMENTS_ACTIVE_MEMBER_MISSING')
            evidence.append({'war_pointer': private['native_pointer'],
                             'vector_raw_hex': header.hex(), 'active_records': active_evidence})
    except (ValueError, KeyError, TypeError, struct.error) as exc:
        return {'status': 'unknown', 'reason': str(exc), 'raw_inputs': {'wars': evidence}}
    return {'status': 'known', 'value': rows, 'complete': complete,
            'raw_inputs': {'wars': evidence, 'unavailable_beneficiaries': sorted(unavailable)}}
