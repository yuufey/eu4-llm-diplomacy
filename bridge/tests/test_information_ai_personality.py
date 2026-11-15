from __future__ import annotations

import pytest

from bridge.information import ai_attitude, ai_personality_memory
from bridge.information.mission_memory import STRING_CAPACITY_OFFSET, STRING_LENGTH_OFFSET
from bridge.tests.test_information_foreign_technology_memory import MemoryReader


MODULE_BASE = 0x140000000
COUNTRY_BASE = 0x6400000000
DEFINITION_BASE = 0x6600000000
RELATION_TABLE_BASE = 0x6700000000
SUBJECT_VECTOR_BASE = 0x6800000000
RELATION_BASE = 0x6900000000
SUBJECT_DEFINITION_BASE = 0x6A00000000


@pytest.fixture(scope="module")
def spec():
    return ai_attitude._load_profile()["attitude"]["personality"]


def _fullref(tag: str, slot: int) -> int:
    return (0x0100 << 48) | (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


def _put_name(image: MemoryReader, address: int, spec: dict, name: str) -> None:
    raw = name.encode("ascii")
    header = bytearray(32)
    header[:len(raw)] = raw
    header[len(raw)] = 0
    header[STRING_LENGTH_OFFSET:STRING_LENGTH_OFFSET + 8] = len(raw).to_bytes(8, "little")
    header[STRING_CAPACITY_OFFSET:STRING_CAPACITY_OFFSET + 8] = (15).to_bytes(8, "little")
    image.put(address + spec["definition_name_offset"], bytes(header))


def _add_country(image: MemoryReader, rows: dict, spec: dict, tag: str, slot: int, definition: int):
    pointer = COUNTRY_BASE + slot * 0x10000
    reference = _fullref(tag, slot)
    state = pointer + spec["country_state_offset"]
    image.put_u64(state + spec["cached_definition_offset"], definition)
    image.put_u64(state + spec["state_country_ref_offset"], reference)
    image.put_u64(pointer + spec["overlord_fullref_offset"], 0)
    rows[slot] = {"fullref": hex(reference), "country_pointer": hex(pointer)}
    return pointer, reference


def _share_ruler(image: MemoryReader, spec: dict, child: int, child_slot: int,
                 parent: int, parent_ref: int, parent_slot: int, shared: bool) -> None:
    table = RELATION_TABLE_BASE + child_slot * 0x1000
    image.put_u64(child + spec["overlord_fullref_offset"], parent_ref)
    image.put_u64(child + spec["relation_table_offset"], table)
    row = bytearray(24)
    row[:8] = parent.to_bytes(8, "little")
    row[16:24] = parent_ref.to_bytes(8, "little")
    image.put(table + parent_slot * spec["relation_row_stride"], bytes(row))

    vector = SUBJECT_VECTOR_BASE + parent_slot * 0x1000
    relation = RELATION_BASE + child_slot * 0x1000
    subject_definition = SUBJECT_DEFINITION_BASE + child_slot * 0x1000
    header = bytearray(16)
    header[:8] = vector.to_bytes(8, "little")
    header[12:16] = (1).to_bytes(4, "little", signed=True)
    image.put(parent + spec["subject_types_offset"], bytes(header))
    record = bytearray(16)
    record[:4] = parent_slot.to_bytes(4, "little", signed=True)
    record[8:16] = relation.to_bytes(8, "little")
    image.put(vector, bytes(record))
    image.put_u64(relation + spec["subject_definition_offset"], subject_definition)
    image.put(subject_definition + spec["shared_ruler_flag_offset"], bytes([shared]))


def _read(image: MemoryReader, pointer: int, rows: dict, spec: dict):
    return ai_personality_memory.read_personality(
        image, MODULE_BASE, {"country_pointer": hex(pointer)}, rows, spec
    )


def test_uses_country_personality_cache(spec):
    image, rows = MemoryReader(), {}
    definition = DEFINITION_BASE
    _put_name(image, definition, spec, "ai_diplomat")
    pointer, _ = _add_country(image, rows, spec, "FRA", 189, definition)

    result = _read(image, pointer, rows, spec)

    assert result["status"] == "known"
    assert result["value"] == "diplomat"
    assert result["raw_name"] == "ai_diplomat"


def test_inherits_personality_when_subject_shares_ruler(spec):
    image, rows = MemoryReader(), {}
    _put_name(image, DEFINITION_BASE, spec, "ai_diplomat")
    _put_name(image, DEFINITION_BASE + 0x1000, spec, "ai_militarist")
    child, _ = _add_country(image, rows, spec, "FRA", 189, DEFINITION_BASE)
    parent, parent_ref = _add_country(image, rows, spec, "HAB", 300, DEFINITION_BASE + 0x1000)
    _share_ruler(image, spec, child, 189, parent, parent_ref, 300, True)

    result = _read(image, child, rows, spec)

    assert result["status"] == "known"
    assert result["value"] == "militarist"


def test_subject_flag_zero_keeps_country_personality(spec):
    image, rows = MemoryReader(), {}
    _put_name(image, DEFINITION_BASE, spec, "ai_diplomat")
    _put_name(image, DEFINITION_BASE + 0x1000, spec, "ai_militarist")
    child, _ = _add_country(image, rows, spec, "FRA", 189, DEFINITION_BASE)
    parent, parent_ref = _add_country(image, rows, spec, "HAB", 300, DEFINITION_BASE + 0x1000)
    _share_ruler(image, spec, child, 189, parent, parent_ref, 300, False)

    result = _read(image, child, rows, spec)

    assert result["status"] == "known"
    assert result["value"] == "diplomat"


def test_zero_cache_uses_global_default(spec):
    image, rows = MemoryReader(), {}
    default_global = MODULE_BASE + spec["default_definition_rva"]
    default_definition = DEFINITION_BASE + 0x3000
    _put_name(image, default_definition, spec, "ai_default")
    pointer, _ = _add_country(image, rows, spec, "FRA", 189, 0)
    image.put_u64(default_global, default_definition)

    result = _read(image, pointer, rows, spec)

    assert result["status"] == "known"
    assert result["value"] == "default"


def test_rejects_shared_ruler_inheritance_cycle(spec):
    image, rows = MemoryReader(), {}
    _put_name(image, DEFINITION_BASE, spec, "ai_diplomat")
    _put_name(image, DEFINITION_BASE + 0x1000, spec, "ai_militarist")
    first, first_ref = _add_country(image, rows, spec, "FRA", 189, DEFINITION_BASE)
    second, second_ref = _add_country(image, rows, spec, "HAB", 300, DEFINITION_BASE + 0x1000)
    _share_ruler(image, spec, first, 189, second, second_ref, 300, True)
    _share_ruler(image, spec, second, 300, first, first_ref, 189, True)

    with pytest.raises(ValueError, match="AI_PERSONALITY_INHERITANCE_CYCLE"):
        _read(image, first, rows, spec)


@pytest.mark.parametrize(("name", "unreadable"), [("invalid", False), ("ai_diplomat", True)])
def test_unreadable_or_invalid_personality_name_is_unknown(spec, name, unreadable):
    image, rows = MemoryReader(), {}
    _put_name(image, DEFINITION_BASE, spec, name)
    pointer, _ = _add_country(image, rows, spec, "FRA", 189, DEFINITION_BASE)
    if unreadable:
        image.short_label = "ai_personality.name"

    result = _read(image, pointer, rows, spec)

    assert result == {"status": "unknown", "reason": "AI_PERSONALITY_NAME_UNAVAILABLE"}
