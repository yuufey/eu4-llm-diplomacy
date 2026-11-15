from __future__ import annotations

import struct

import pytest

from bridge.information import country_scale_development_memory as memory


BASE = 0x140000000
DATABASE_GLOBAL_RVA = 0x233D8B0
DATABASE = 0x50000000
TABLE = 0x51000000
TARGET_PTR = 0x60000000
VECTOR = 0x64000000
WEIGHT = 0x233F8AC
OVERLORD_SLOT = 189


class FakeReader:
    def __init__(self):
        self.bytes: dict[int, int] = {}
        self.calls: list[tuple[int, int, str]] = []
        self.short_labels: set[str] = set()
        self.error_labels: set[str] = set()

    def put(self, address: int, raw: bytes) -> None:
        for offset, value in enumerate(raw):
            self.bytes[address + offset] = value

    def read(self, address: int, size: int, label: str) -> bytes:
        self.calls.append((address, size, label))
        if label in self.error_labels:
            raise OSError("fixture read failure")
        try:
            raw = bytes(self.bytes[address + i] for i in range(size))
        except KeyError as exc:
            raise OSError(f"unmapped:{address:x}+{size:x}") from exc
        if label in self.short_labels:
            return raw[:-1]
        return raw


def fullref(slot: int, tag: str, *, generation: int = 1) -> int:
    assert len(tag) == 3 and tag.isascii()
    return ((generation & 0xFF) << 56) | (slot << 32) | int.from_bytes(
        tag.encode("ascii") + b"\x00", "little")


def qword(value: int) -> bytes:
    return int(value).to_bytes(8, "little", signed=False)


def i32(value: int) -> bytes:
    return int(value).to_bytes(4, "little", signed=True)


def install_country(reader: FakeReader, *, slot: int, tag: str, pointer: int,
                    generation: int = 1) -> int:
    ref = fullref(slot, tag, generation=generation)
    reader.put(TABLE + slot * 8, qword(pointer))
    reader.put(pointer + 0x20, qword(ref))
    return ref


def environment(*, own_development: int = 1234,
                subjects: list[tuple[str, int, int]] | None = None,
                weight: int = 1000):
    """subjects tuples are (tag, slot, development); returns reader/binding."""
    reader = FakeReader()
    reader.put(BASE + DATABASE_GLOBAL_RVA, qword(DATABASE))
    reader.put(DATABASE + 0x118, qword(TABLE))
    count = max([122, OVERLORD_SLOT, *(slot for _, slot, _ in subjects or [])]) + 1
    reader.put(DATABASE + 0x124, i32(count))
    target_ref = install_country(reader, slot=122, tag="FRA", pointer=TARGET_PTR)
    reader.put(TARGET_PTR + 0xE1C, i32(own_development))
    reader.put(BASE + WEIGHT, i32(weight))
    subjects = subjects or []
    refs = []
    ptrs = {}
    for index, (tag, slot, dev) in enumerate(subjects):
        pointer = 0x61000000 + index * 0x10000
        ptrs[tag] = pointer
        ref = install_country(reader, slot=slot, tag=tag, pointer=pointer)
        refs.append(ref)
        reader.put(pointer + 0xE1C, i32(dev))
        reader.put(pointer + 0x18F0, qword(0))
    if refs:
        refs_raw = b"".join(qword(ref) for ref in refs)
        reader.put(TARGET_PTR + 0x1A18, qword(VECTOR))
        reader.put(TARGET_PTR + 0x1A20, qword(VECTOR + len(refs_raw)))
        reader.put(VECTOR, refs_raw)
    else:
        reader.put(TARGET_PTR + 0x1A18, qword(0))
        reader.put(TARGET_PTR + 0x1A20, qword(0))
    binding = {"tag": "FRA", "slot": 122, "country_pointer": hex(TARGET_PTR),
               "fullref": hex(target_ref), "fullref_raw_hex": qword(target_ref).hex()}
    return reader, binding, ptrs


def add_overlord(reader: FakeReader, child_pointer: int, *, child_tag: str,
                 child_slot: int, owner_pointer: int, relation_table: int,
                 association_entries: list[tuple[int, int]],
                 association_count: int | None = None,
                 overlord_generation: int = 1) -> tuple[int, int]:
    overlord_ptr = 0x63000000
    overlord_ref = install_country(reader, slot=OVERLORD_SLOT, tag="OVR",
                                   pointer=overlord_ptr,
                                   generation=overlord_generation)
    reader.put(child_pointer + 0x18F0, qword(overlord_ref))
    reader.put(child_pointer + 0x1510, qword(relation_table))
    row = relation_table + OVERLORD_SLOT * memory.RELATION_ROW_STRIDE
    row_raw = bytearray(0x18)
    row_raw[:8] = qword(owner_pointer)
    row_raw[0x10:0x18] = qword(overlord_ref)
    reader.put(row, bytes(row_raw))
    entries_pointer = owner_pointer + 0x1000
    count = len(association_entries) if association_count is None else association_count
    reader.put(owner_pointer + 0x128, qword(entries_pointer))
    reader.put(owner_pointer + 0x130, b"\x00" * 4)
    reader.put(owner_pointer + 0x134, i32(count))
    for index, (other_slot, association_pointer) in enumerate(association_entries):
        entry = bytearray(16)
        entry[:4] = i32(other_slot)
        entry[8:16] = qword(association_pointer)
        reader.put(entries_pointer + index * 16, bytes(entry))
    return overlord_ptr, overlord_ref


def call(reader, binding, fields=memory.FIELDS):
    return memory.read_fields(reader, BASE, binding, fields)


def test_development_and_subject_scale_keep_raw_own_value_and_native_weighting():
    reader, binding, ptrs = environment(
        own_development=-1234,
        subjects=[("AAA", 500, 1001), ("BBB", 501, -2001)], weight=750)
    # BBB has a canonical overlord relation whose six native flags exclude it.
    add_overlord(reader, ptrs["BBB"], child_tag="BBB", child_slot=501,
                 owner_pointer=0x66000000, relation_table=0x65000000,
                 association_entries=[(OVERLORD_SLOT, 0x67000000)])
    type_pointer = 0x68000000
    reader.put(0x67000000 + 0x40, qword(type_pointer))
    for offset, value in zip(memory.TYPE_FLAG_OFFSETS, (1, 2, 0, 0, 0, 9)):
        reader.put(type_pointer + offset, bytes([value]))

    result = call(reader, binding)
    assert result[memory.FIELD_DEVELOPMENT]["status"] == "known"
    assert result[memory.FIELD_DEVELOPMENT]["value"] == -1234
    assert result[memory.FIELD_DEVELOPMENT]["scale"] == 1000
    assert result[memory.FIELD_SUBJECT_SCALE]["status"] == "known"
    assert result[memory.FIELD_SUBJECT_SCALE]["value"] == {
        "reference_count": 2, "included_count": 1, "excluded_count": 1,
        "weighted_development_raw": 750, "development_scale": 1000,
        "weight_raw": 750, "weight_scale": 1000,
    }
    private_subject = result[memory.FIELD_SUBJECT_SCALE]["raw_inputs"]["subjects"][1]
    assert private_subject["branch"] == "exclude_type_flags_match"
    assert [row["matched"] for row in private_subject["relation_flags"]] == [True] * 6


def test_empty_vector_is_known_zero_and_preserves_actual_weight():
    reader, binding, _ = environment(subjects=[], weight=-1777)
    result = call(reader, binding, (memory.FIELD_SUBJECT_SCALE,))[
        memory.FIELD_SUBJECT_SCALE]
    assert result["status"] == "known"
    assert result["value"] == {
        "reference_count": 0, "included_count": 0, "excluded_count": 0,
        "weighted_development_raw": 0, "development_scale": 1000,
        "weight_raw": -1777, "weight_scale": 1000,
    }


def test_nonzero_low_bytes_with_zero_high_byte_take_no_overlord_branch():
    reader, binding, ptrs = environment(subjects=[("AAA", 500, 45)])
    # Synthetic sentinel shape only: the raw value is nonzero, but the native
    # branch tests the top byte. This fixture does not claim a live sentinel.
    reader.put(ptrs["AAA"] + 0x18F0, qword(0x1234))
    result = call(reader, binding, (memory.FIELD_SUBJECT_SCALE,))[
        memory.FIELD_SUBJECT_SCALE]
    assert result["status"] == "known"
    assert result["value"]["included_count"] == 1
    subject = result["raw_inputs"]["subjects"][0]
    assert subject["overlord_fullref_raw_hex"] == qword(0x1234).hex()
    assert subject["overlord_high_byte"] == 0
    assert subject["branch"] == "include_no_overlord_high_byte_zero"
    assert not any("overlord.database_global" in label
                   for _, _, label in reader.calls)


@pytest.mark.parametrize("flags,expected_count", [
    ((0,), 1),
    ((1, 0), 1),
    ((1, 1, 1), 1),
    ((1, 1, 0, 1), 1),
    ((1, 1, 0, 0, 1), 1),
])
def test_each_failed_exclusion_flag_short_circuits_later_reads(flags, expected_count):
    reader, binding, ptrs = environment(subjects=[("AAA", 500, 400)], weight=1000)
    add_overlord(reader, ptrs["AAA"], child_tag="AAA", child_slot=500,
                 owner_pointer=0x66000000, relation_table=0x65000000,
                 association_entries=[(OVERLORD_SLOT, 0x67000000)])
    type_pointer = 0x68000000
    reader.put(0x67000000 + 0x40, qword(type_pointer))
    for index, value in enumerate(flags):
        reader.put(type_pointer + memory.TYPE_FLAG_OFFSETS[index], bytes([value]))
    # Any flag after the first mismatch is intentionally unmapped. Reading it
    # would incorrectly turn the native short-circuit branch into unknown.
    result = call(reader, binding, (memory.FIELD_SUBJECT_SCALE,))[
        memory.FIELD_SUBJECT_SCALE]
    assert result["status"] == "known"
    assert result["value"]["included_count"] == expected_count
    flags_read = result["raw_inputs"]["subjects"][0]["relation_flags"]
    assert len(flags_read) == len(flags)
    assert flags_read[-1]["matched"] is False


@pytest.mark.parametrize("association_entries,expected_branch", [
    ([(OVERLORD_SLOT, 0)], "include_null_association"),
    ([(OVERLORD_SLOT + 1, 0x67000000)], "include_no_matching_association"),
])
def test_null_or_nonmatching_association_includes_subject(association_entries,
                                                          expected_branch):
    reader, binding, ptrs = environment(subjects=[("AAA", 500, 45)])
    add_overlord(reader, ptrs["AAA"], child_tag="AAA", child_slot=500,
                 owner_pointer=0x66000000, relation_table=0x65000000,
                 association_entries=association_entries)
    result = call(reader, binding, (memory.FIELD_SUBJECT_SCALE,))[
        memory.FIELD_SUBJECT_SCALE]
    assert result["status"] == "known"
    assert result["value"]["included_count"] == 1
    assert result["raw_inputs"]["subjects"][0]["branch"] == expected_branch


def test_null_type_definition_includes_and_stops_without_flag_reads():
    reader, binding, ptrs = environment(subjects=[("AAA", 500, 25)])
    add_overlord(reader, ptrs["AAA"], child_tag="AAA", child_slot=500,
                 owner_pointer=0x66000000, relation_table=0x65000000,
                 association_entries=[(OVERLORD_SLOT, 0x67000000)])
    reader.put(0x67000000 + 0x40, qword(0))
    result = call(reader, binding, (memory.FIELD_SUBJECT_SCALE,))[
        memory.FIELD_SUBJECT_SCALE]
    assert result["status"] == "known"
    assert result["value"]["included_count"] == 1
    assert result["raw_inputs"]["subjects"][0]["branch"] == "include_null_type_definition"


def test_negative_fraction_truncates_toward_zero_and_i32_sum_wraps():
    reader, binding, _ = environment(
        subjects=[("AAA", 500, -1), ("BBB", 501, 2147483647)], weight=2000)
    # Each child contributes trunc(raw*2000/1000) cast to i32. -1 -> -2;
    # 2147483647*2 -> 4294967294 -> -2; adding wraps to -4.
    result = call(reader, binding, (memory.FIELD_SUBJECT_SCALE,))[
        memory.FIELD_SUBJECT_SCALE]
    assert result["status"] == "known"
    assert result["value"]["weighted_development_raw"] == -4
    assert [s["weighted_development_raw"] for s in result["raw_inputs"]["subjects"]] == [-2, -2]


def test_vector_and_relation_count_limits_fail_closed_without_false_zero():
    reader, binding, _ = environment(subjects=[])
    reader.put(TARGET_PTR + 0x1A18, qword(VECTOR))
    reader.put(TARGET_PTR + 0x1A20, qword(VECTOR + 8 * (memory.MAX_SUBJECTS + 1)))
    result = call(reader, binding, (memory.FIELD_SUBJECT_SCALE,))[
        memory.FIELD_SUBJECT_SCALE]
    assert result["status"] == "unknown"
    assert "count_out_of_range" in result["reason"]

    reader, binding, ptrs = environment(subjects=[("AAA", 500, 12)])
    add_overlord(reader, ptrs["AAA"], child_tag="AAA", child_slot=500,
                 owner_pointer=0x66000000, relation_table=0x65000000,
                 association_entries=[], association_count=memory.MAX_RELATION_ENTRIES + 1)
    result = call(reader, binding, (memory.FIELD_SUBJECT_SCALE,))[
        memory.FIELD_SUBJECT_SCALE]
    assert result["status"] == "unknown"
    assert result["reason"] == "relation_association_count_out_of_range"


@pytest.mark.parametrize("corruption", ["overlord_ref", "row_recipient", "subject_ref"])
def test_bad_or_noncanonical_subject_and_overlord_refs_are_unknown(corruption):
    reader, binding, ptrs = environment(subjects=[("AAA", 500, 15)])
    add_overlord(reader, ptrs["AAA"], child_tag="AAA", child_slot=500,
                 owner_pointer=0x66000000, relation_table=0x65000000,
                 association_entries=[])
    if corruption == "overlord_ref":
        # Change the child ref while keeping it nonzero but unbound in the DB.
        reader.put(ptrs["AAA"] + 0x18F0, qword(fullref(190, "BAD")))
    elif corruption == "row_recipient":
        row = 0x65000000 + OVERLORD_SLOT * memory.RELATION_ROW_STRIDE
        reader.put(row + 0x10, qword(fullref(190, "BAD")))
    else:
        # A subject ref with a changed generation no longer matches its slot's
        # canonical country+0x20 fullref.
        reader.put(VECTOR, qword(fullref(500, "AAA", generation=2)))
    result = call(reader, binding, (memory.FIELD_SUBJECT_SCALE,))[
        memory.FIELD_SUBJECT_SCALE]
    assert result["status"] == "unknown"


def test_subject_field_read_failure_does_not_retract_own_development():
    reader, binding, _ = environment(own_development=7, subjects=[])
    reader.short_labels.add("country_scale.subject_vector_header")
    result = call(reader, binding)
    assert result[memory.FIELD_DEVELOPMENT]["status"] == "known"
    assert result[memory.FIELD_DEVELOPMENT]["value"] == 7
    assert result[memory.FIELD_SUBJECT_SCALE]["status"] == "unknown"


def test_own_development_read_failure_does_not_retract_subject_scale():
    reader, binding, _ = environment(subjects=[], weight=333)
    reader.error_labels.add("country_scale.development.own_i32")
    result = call(reader, binding)
    assert result[memory.FIELD_DEVELOPMENT]["status"] == "unknown"
    assert result[memory.FIELD_SUBJECT_SCALE]["status"] == "known"
    assert result[memory.FIELD_SUBJECT_SCALE]["value"]["weight_raw"] == 333


def test_invalid_target_binding_and_unsupported_field_do_not_read_memory():
    reader, binding, _ = environment(subjects=[])
    bad = dict(binding, slot=123)
    result = call(reader, bad, (memory.FIELD_DEVELOPMENT,))
    assert result[memory.FIELD_DEVELOPMENT]["status"] == "unknown"
    assert reader.calls == []

    result = call(reader, binding, ("F01.major_power", "F01.wars"))
    assert all(value["reason"] == "unsupported_field" for value in result.values())
    assert reader.calls == []


def test_target_database_binding_is_rechecked_before_field_reads():
    reader, binding, _ = environment(own_development=99, subjects=[])
    # DB slot still points at TARGET_PTR, but the target's fullref generation
    # differs from the binding. The leaf must reject before reading e1c.
    reader.put(TARGET_PTR + 0x20, qword(fullref(122, "FRA", generation=2)))
    result = call(reader, binding, (memory.FIELD_DEVELOPMENT,))[
        memory.FIELD_DEVELOPMENT]
    assert result["status"] == "unknown"
    assert not any(label.endswith("own_i32") for _, _, label in reader.calls)


def test_short_read_or_reader_exception_becomes_unknown_not_zero():
    reader, binding, _ = environment(subjects=[])
    reader.short_labels.add("country_scale.subject_scale_weight_i32")
    result = call(reader, binding, (memory.FIELD_SUBJECT_SCALE,))[
        memory.FIELD_SUBJECT_SCALE]
    assert result["status"] == "unknown"
    assert "short_read" in result["reason"]

    reader, binding, _ = environment(own_development=0, subjects=[])
    reader.error_labels.add("country_scale.development.own_i32")
    result = call(reader, binding, (memory.FIELD_DEVELOPMENT,))[
        memory.FIELD_DEVELOPMENT]
    assert result["status"] == "unknown"
    assert "read_failed" in result["reason"]
