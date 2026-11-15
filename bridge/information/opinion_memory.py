"""Bounded signed cells from the native bilateral-opinion display cache.

This leaf owns no process handle and grants no visibility. A parent must bind
the build/session, admit the observer, and compare two complete observations.
"""
from __future__ import annotations

from . import country_reference_memory as _ref

TABLE_BEGIN = 0x2380
TABLE_END = 0x2388
MAX_ENTRIES = 4096
UNIT = 'opinion_points'
FIELDS = ('R04.opinion.outgoing', 'R04.opinion.incoming')
UNKNOWN_REASONS = frozenset({
    'OPINION_BINDING_TAG', 'OPINION_BINDING_SLOT', 'OPINION_BINDING_POINTER',
    'OPINION_BINDING_FULLREF', 'OPINION_BINDING_ALIAS', 'OPINION_CELL_READ_BUDGET',
    'OPINION_CELL_SHORT_READ', 'OPINION_COUNTRY_REBOUND', 'OPINION_TABLE_HEADER_INVALID',
    'OPINION_TABLE_HEADER_CHANGED', 'OPINION_TABLE_SLOT_ABSENT', 'OPINION_CELL_READ_FAILED',
})


def _binding(value):
    tag = value['tag']
    slot = value['slot']
    pointer = value['country_pointer']
    fullref = value['fullref']
    if not isinstance(tag, str) or len(tag) != 3 or not all(
            'A' <= char <= 'Z' or '0' <= char <= '9' for char in tag):
        raise ValueError('OPINION_BINDING_TAG')
    if type(slot) is not int or not 0 <= slot < MAX_ENTRIES:
        raise ValueError('OPINION_BINDING_SLOT')
    if type(pointer) is str:
        pointer = int(pointer, 0)
    if type(fullref) is str:
        fullref = int(fullref, 0)
    if not _ref._is_user_address(pointer) or pointer & 7:
        raise ValueError('OPINION_BINDING_POINTER')
    if (type(fullref) is not int or not 0 <= fullref <= _ref.MAX_U64
            or (fullref >> 32) & 0xffff != slot
            or (fullref & 0xffffff).to_bytes(3, 'little') != tag.encode('ascii')):
        raise ValueError('OPINION_BINDING_FULLREF')
    return tag, slot, pointer, fullref


def read_direction(reader, holder_binding, target_binding):
    """Copy one requested cell, retaining absence and instability as unknown."""
    try:
        holder, _, pointer, holder_ref = _binding(holder_binding)
        target, slot, target_pointer, target_ref = _binding(target_binding)
        if holder == target or pointer == target_pointer or holder_ref == target_ref:
            raise ValueError('OPINION_BINDING_ALIAS')
        calls = requested = 0

        def read(base, offset, size, suffix):
            nonlocal calls, requested
            address = _ref._checked_add(base, offset, label=suffix)
            _ref._checked_range(address, size, label=suffix)
            calls += 1
            requested += size
            if calls > 9 or requested > 66 or size not in (2, 8):
                raise ValueError('OPINION_CELL_READ_BUDGET')
            raw = reader.read(address, size, f'opinion.{holder}.to.{target}.{suffix}')
            if not isinstance(raw, (bytes, bytearray, memoryview)) or len(raw) != size:
                raise ValueError('OPINION_CELL_SHORT_READ')
            return bytes(raw)

        def refs(suffix):
            return (read(pointer, 0x20, 8, 'holder_ref.'+suffix),
                    read(target_pointer, 0x20, 8, 'target_ref.'+suffix))

        before_refs = refs('before')
        expected_refs = (holder_ref.to_bytes(8, 'little'), target_ref.to_bytes(8, 'little'))
        if before_refs != expected_refs:
            raise ValueError('OPINION_COUNTRY_REBOUND')
        begin_raw = read(pointer, TABLE_BEGIN, 8, 'begin.before')
        end_raw = read(pointer, TABLE_END, 8, 'end.before')
        begin, end = int.from_bytes(begin_raw, 'little'), int.from_bytes(end_raw, 'little')
        if (begin == end == 0):
            count = 0
        elif (not _ref._is_user_address(begin) or end > _ref.MAX_USER_ADDRESS_EXCLUSIVE
              or begin & 1 or end & 1 or end < begin or (end-begin)//2 > MAX_ENTRIES):
            raise ValueError('OPINION_TABLE_HEADER_INVALID')
        else:
            count = (end-begin)//2
        raw = read(begin, slot*2, 2, 'cell') if slot < count else None
        after_header = (read(pointer, TABLE_BEGIN, 8, 'begin.after'),
                        read(pointer, TABLE_END, 8, 'end.after'))
        after_refs = refs('after')
        if before_refs != after_refs:
            raise ValueError('OPINION_COUNTRY_REBOUND')
        if (begin_raw, end_raw) != after_header:
            raise ValueError('OPINION_TABLE_HEADER_CHANGED')
        if raw is None:
            raise ValueError('OPINION_TABLE_SLOT_ABSENT')
        return {'status': 'known', 'value': {
            'holder': holder, 'target': target,
            'opinion': int.from_bytes(raw, 'little', signed=True), 'raw_hex': raw.hex(),
        }, 'unit': UNIT, 'scale': 1, 'complete': False}
    except Exception as exc:
        reason = str(exc)
        if reason not in UNKNOWN_REASONS:
            reason = 'OPINION_CELL_READ_FAILED'
        return {'status': 'unknown', 'reason': reason}


def read_fields(reader, observer_binding, target_binding, fields=FIELDS):
    result = {}
    for field in fields:
        if field == FIELDS[0]:
            result[field] = read_direction(reader, observer_binding, target_binding)
        elif field == FIELDS[1]:
            result[field] = read_direction(reader, target_binding, observer_binding)
        else:
            raise ValueError('OPINION_FIELD_UNSUPPORTED')
    return result
