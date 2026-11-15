from __future__ import annotations

import importlib
import struct

import pytest


m = importlib.import_module("bridge.information.opinion_modifiers_memory")

BASE = 0x140000000
HOLDER = 0x200000
RELATIONS = 0x210000
MANAGER = 0x220000
OUTER = 0x230000
ENTRIES = 0x240000
OBJECT = 0x250000
DEFINITION = 0x260000
FULLREF = 0x123456789


class Memory:
    def __init__(self):
        self.segments = {}

    def put(self, address, data):
        self.segments[address] = bytearray(data)

    def patch(self, address, data):
        for start, segment in self.segments.items():
            if start <= address and address + len(data) <= start + len(segment):
                begin = address - start
                segment[begin:begin + len(data)] = data
                return
        raise AssertionError(f"unmapped patch {address:#x}")

    def read(self, address, size, label):
        for start, segment in self.segments.items():
            if start <= address and address + size <= start + len(segment):
                return bytes(segment[address - start:address - start + size])
        raise AssertionError(f"unmapped {label}: {address:#x}+{size:#x}")


def qword(value):
    return struct.pack("<Q", value)


def fixture(*, candidate_count=1, selected_count=None, pointers=None):
    memory = Memory()
    memory.put(HOLDER + 0x1510, qword(RELATIONS))
    relation = bytearray(24)
    relation[:8] = qword(MANAGER)
    relation[16:24] = qword(FULLREF)
    memory.put(RELATIONS, relation)

    outer = bytearray(16)
    outer[:8] = qword(OUTER)
    outer[12:16] = struct.pack("<i", 1)
    memory.put(MANAGER + 0x308, outer)
    candidate = bytearray(24)
    candidate[8:16] = qword(ENTRIES)
    candidate[20:24] = struct.pack("<i", candidate_count)
    memory.put(OUTER, candidate)

    if selected_count is None:
        selected_count = candidate_count
    fallback = bytearray(24)
    fallback[20:24] = struct.pack("<i", selected_count)
    fallback[8:16] = qword(ENTRIES)
    memory.put(MANAGER + 0x318, fallback)

    if pointers is None:
        pointers = [OBJECT] * selected_count
    if selected_count:
        memory.put(ENTRIES, b"".join(qword(pointer) for pointer in pointers))

    header = bytearray(0x30)
    header[:8] = qword(BASE + m.MODIFIER_VTABLE_RVA)
    header[16:24] = qword(DEFINITION)
    struct.pack_into("<i", header, 0x18, -1234)
    struct.pack_into("<i", header, 0x1C, 7)
    struct.pack_into("<i", header, 0x20, -50000)
    header[0x24] = 1
    header[0x25] = 0xA5
    header[0x26] = 0
    header[0x27] = 0x5A
    memory.put(OBJECT, header)

    vtable = bytearray(24)
    vtable[m.MODIFIER_SERIALIZER_SLOT * 8:m.MODIFIER_SERIALIZER_SLOT * 8 + 8] = qword(
        BASE + m.MODIFIER_SERIALIZER_RVA)
    memory.put(BASE + m.MODIFIER_VTABLE_RVA, vtable)

    definition = bytearray(0x40)
    key = b"insult"
    definition[0x10:0x10 + len(key)] = key
    definition[0x10 + len(key)] = 0
    definition[0x20:0x28] = qword(len(key))
    definition[0x28:0x30] = qword(15)
    memory.put(DEFINITION, definition)
    holder = {"tag": "FRA", "country_pointer": hex(HOLDER), "fullref": hex(1), "slot": 0}
    indexed = {"tag": "ENG", "country_pointer": hex(0x280000),
               "fullref": hex(FULLREF), "slot": 0}
    return memory, holder, indexed


def test_known_row_has_only_the_seven_internal_keys_and_raw_values():
    memory, holder, indexed = fixture()
    result = m._direction(memory, BASE, holder, indexed)
    assert result["status"] == "known"
    row = result["records"][0]
    assert set(row) == {
        "status", "modifier_id", "current_opinion_raw", "raw_hex",
        "record_date_raw", "multiplier_raw", "flags_raw",
    }
    assert row["modifier_id"] == "insult"
    assert row["current_opinion_raw"] == -50000
    assert row["raw_hex"] == "b03cffff"
    assert row["record_date_raw"] == -1234
    assert row["multiplier_raw"] == 7
    assert row["flags_raw"] == {"24": 1, "26": 0}


def test_unknown_class_is_a_row_unknown_without_dropping_known_sibling():
    memory, holder, indexed = fixture(candidate_count=2, pointers=[OBJECT, OBJECT + 0x1000])
    memory.put(OBJECT + 0x1000, bytes(memory.segments[OBJECT]))
    memory.patch(OBJECT + 0x1000, qword(BASE + 0x123456))
    result = m._direction(memory, BASE, holder, indexed)
    assert result["status"] == "known"
    assert result["records"][0]["status"] == "known"
    assert result["records"][1] == {
        "status": "unknown", "reason": "OPINION_MODIFIER_CLASS_UNSUPPORTED",
    }


def test_unmaterialized_limit_duplicate_and_empty_fallback_are_distinct():
    memory, holder, indexed = fixture()
    memory.patch(MANAGER + 0x308 + 12, struct.pack("<i", 0))
    assert m._direction(memory, BASE, holder, indexed) == {
        "status": "unknown", "reason": "OPINION_MODIFIER_CONTAINER_UNMATERIALIZED",
    }

    memory, holder, indexed = fixture(candidate_count=m.MAX_RECORDS + 1)
    assert m._direction(memory, BASE, holder, indexed) == {
        "status": "unknown", "reason": "OPINION_MODIFIER_RECORD_LIMIT",
    }

    memory, holder, indexed = fixture(candidate_count=2, pointers=[OBJECT, OBJECT])
    assert m._direction(memory, BASE, holder, indexed) == {
        "status": "unknown", "reason": "OPINION_MODIFIER_DUPLICATE_OBJECT",
    }

    memory, holder, indexed = fixture(candidate_count=0, selected_count=0, pointers=[])
    result = m._direction(memory, BASE, holder, indexed)
    assert result["status"] == "knownempty" and result["records"] == []

    memory, holder, indexed = fixture(candidate_count=0, selected_count=1,
                                      pointers=[OBJECT])
    assert m._direction(memory, BASE, holder, indexed) == {
        "status": "unknown", "reason": "OPINION_MODIFIER_NATIVE_FALLBACK_NONEMPTY",
    }


def test_padding_25_27_is_not_read_or_part_of_stability():
    memory, holder, indexed = fixture()
    original = memory.read
    changed = False

    def mutate_padding(address, size, label):
        nonlocal changed
        raw = original(address, size, label)
        if label == "modifier.record[0].before.flag26" and not changed:
            changed = True
            memory.patch(OBJECT + 0x25, b"\xFF")
            memory.patch(OBJECT + 0x27, b"\xEE")
        return raw

    memory.read = mutate_padding
    result = m._direction(memory, BASE, holder, indexed)
    assert result["status"] == "known"
    assert changed is True


def test_header_change_retracts_direction():
    memory, holder, indexed = fixture()
    original = memory.read
    changed = False

    def mutate_header(address, size, label):
        nonlocal changed
        raw = original(address, size, label)
        if label == "modifier.record[0].before.header" and not changed:
            changed = True
            memory.patch(OBJECT, qword(BASE + 0x123456))
        return raw

    memory.read = mutate_header
    result = m._direction(memory, BASE, holder, indexed)
    assert result == {"status": "unknown", "reason": "OPINION_MODIFIER_RECORD_CHANGED"}


def test_profile_is_independent_and_serializer_guard_is_263_bytes():
    profile = m._load_profile()
    assert profile["profile_id"] == m.PROFILE_ID
    guard = profile["code_guards"][-1]
    assert guard["name"] == "opinion_modifier_serializer"
    assert len(bytes.fromhex(guard["bytes"])) == 263
    assert profile["code_guards"][:-1]  # inherited opinion guards remain
