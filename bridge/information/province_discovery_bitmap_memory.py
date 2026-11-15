"""Private B23 discovery-bit leaf with native word-count bounds.

The containing two-pass observer must establish the non-player observer and
province identities. This leaf reads membership only; it grants no other
province visibility and establishes no completeness of the province domain.
The 128-word limit is a bridge budget, not a universal native capacity.
"""
from __future__ import annotations

from . import province_reference_memory as _province


SCHEMA = 'information.province_discovery_bitmap_memory.v1'
BITMAP_OFFSET = 0x5D8
BITMAP_HEADER_BYTES = 24
BITMAP_VTABLE_RVA = 0x1C57270
INLINE_OFFSET = 0x5F0
INLINE_WORDS = 128
MAX_CAPACITY_WORDS = 128
MAX_OBSERVER_SLOTS = 4096


def _unknown(reason, raw):
    return {'status': 'unknown', 'reason': reason, 'raw_inputs': raw}


def read_discovery(reader, record: int, observer_slot: int, module_base: int):
    """Read one bounded membership sample; the caller compares both passes."""
    raw_inputs = {}
    if (type(observer_slot) is not int or not 0 <= observer_slot < MAX_OBSERVER_SLOTS):
        return _unknown('OBSERVER_SLOT_OUT_OF_RANGE', raw_inputs)
    if (type(module_base) is not int or not _province._is_user_address(module_base)
            or module_base & 7 or type(record) is not int
            or not _province._is_user_address(record) or record & 7):
        return _unknown('BITMAP_BASE_OR_RECORD_INVALID', raw_inputs)
    try:
        record_start, record_end = _province._checked_range(
            record, _province.RECORD_STRIDE, 'bitmap_province_record')
        header_address = _province._checked_add(record, BITMAP_OFFSET, 'bitmap_header')
        method = getattr(reader, 'read', None)
        read = method if callable(method) else reader
        if not callable(read):
            raise ValueError('BITMAP_READER_NOT_CALLABLE')

        def exact(address, size, label):
            _province._checked_range(address, size, label)
            data = read(address, size, label)
            if not isinstance(data, (bytes, bytearray, memoryview)) or len(data) != size:
                raise ValueError('BITMAP_SHORT_OR_INVALID_READ')
            return bytes(data)

        header = exact(header_address, BITMAP_HEADER_BYTES, 'province_bitmap.header')
        vtable = int.from_bytes(header[:8], 'little')
        pointer = int.from_bytes(header[8:16], 'little')
        capacity = int.from_bytes(header[16:20], 'little', signed=True)
        length = int.from_bytes(header[20:24], 'little', signed=True)
        raw_inputs.update(header_address=hex(header_address), header_raw_hex=header.hex(),
            bitset_pointer_raw_hex=header[8:16].hex(), bitset_pointer=hex(pointer),
            capacity_words=capacity, length_words=length, observer_slot=observer_slot)
        if vtable != module_base + BITMAP_VTABLE_RVA:
            return _unknown('BITMAP_TYPE_MISMATCH', raw_inputs)
        if not 0 <= length <= capacity <= MAX_CAPACITY_WORDS:
            return _unknown('BITMAP_LENGTH_OR_CAPACITY_INVALID', raw_inputs)
        word_index, bit_index = observer_slot >> 5, observer_slot & 31
        if word_index >= length:
            return _unknown('OBSERVER_OUTSIDE_BITMAP_LENGTH', raw_inputs)
        if not _province._is_user_address(pointer) or pointer & 3:
            return _unknown('BITMAP_POINTER_INVALID', raw_inputs)
        storage_start, storage_end = _province._checked_range(pointer, capacity * 4, 'bitmap_storage')
        inline = pointer == record + INLINE_OFFSET
        if inline:
            if capacity > INLINE_WORDS or storage_end > record_end:
                return _unknown('BITMAP_INLINE_RANGE_INVALID', raw_inputs)
        elif storage_start < record_end and record_start < storage_end:
            return _unknown('BITMAP_STORAGE_OVERLAPS_RECORD', raw_inputs)
        word_address = pointer + word_index * 4
        word_raw = exact(word_address, 4, 'province_bitmap.word_u32')
        word = int.from_bytes(word_raw, 'little')
        raw_inputs.update(word_index=word_index, bit_index=bit_index,
            word_address=hex(word_address), word_raw_hex=word_raw.hex(),
            word_u32=word, inline_storage=inline)
        return {'schema': SCHEMA, 'status': 'known', 'value': bool((word >> bit_index) & 1),
            'basis': 'native_bounded_province_discovery_bit_for_observer_slot',
            'raw_inputs': raw_inputs}
    except Exception as exc:
        reason = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        return _unknown(reason[:160], raw_inputs)


__all__ = ['read_discovery', 'SCHEMA']
