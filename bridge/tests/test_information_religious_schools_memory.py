from __future__ import annotations

import pytest

from bridge.information import religious_schools_memory as memory
from bridge.information import religious_schools_values as values


BASE = 0x140000000
COUNTRY = 0x200000
TABLE_ENTRY = 0x100000
RELIGION = 0x300000
GROUP = 0x320000
RELIGION_HEAP = 0x400000
GROUP_HEAP = 0x500000
SCHOOL = 0x600000
DEFINITION = 0x700000
SCHOOL_ARRAY = 0x800000
SCHOOL_HEAP = 0x900000
SLOT = 47
TAG = "POR"
FULLREF = (SLOT << 32) | int.from_bytes(TAG.encode("ascii"), "little")
BINDING = {
    "tag": TAG,
    "slot": SLOT,
    "country_pointer": hex(COUNTRY),
    "fullref": hex(FULLREF),
    "fullref_raw_hex": FULLREF.to_bytes(8, "little").hex(),
    "country_fullref_address": hex(COUNTRY + 0x20),
    "table_entry_address": hex(TABLE_ENTRY),
    "table_entry_raw_hex": COUNTRY.to_bytes(8, "little").hex(),
}


def _qword(value: int) -> bytes:
    return value.to_bytes(8, "little")


def _u32(value: int) -> bytes:
    return value.to_bytes(4, "little")


def _string32(value: bytes, *, storage: str = "inline", capacity: int | None = None,
              pointer: int = SCHOOL_HEAP, terminator: int = 0) -> bytes:
    if capacity is None:
        capacity = 15 if storage == "inline" else max(16, len(value))
    header = bytearray(32)
    if storage == "inline":
        header[:len(value)] = value
        if len(value) < 16:
            header[len(value)] = terminator
    else:
        header[:8] = _qword(pointer)
    header[0x10:0x18] = len(value).to_bytes(8, "little")
    header[0x18:0x20] = capacity.to_bytes(8, "little")
    return bytes(header)


class FakeMemory:
    """Byte-backed reader; the real religion identity and school leaf run."""

    def __init__(self, *, has_school: bool = True, school_key: bytes = b"shafi",
                 school_storage: str = "inline", school_capacity: int | None = None,
                 school_terminator: int = 0, count: int = 2, capacity: int = 2,
                 ordinal: int = 1, array_member: int | None = None,
                 school_pointer: int = SCHOOL, vtable: int | None = None,
                 method: int | None = None, definition_pointer: int = DEFINITION,
                 definition_owner: int = GROUP, owner_group: int = GROUP,
                 religion_key: bytes = b"catholic", group_key: bytes = b"christian",
                 religion_storage: str = "inline", group_storage: str = "inline",
                 overrides: dict[str, list[bytes | BaseException]] | None = None,
                 short_reads: set[str] | None = None):
        self.binding = dict(BINDING)
        self.calls: list[tuple[int, int, str]] = []
        self.overrides = {key: list(items) for key, items in (overrides or {}).items()}
        self.short_reads = set(short_reads or ())
        self.regions: dict[int, bytes] = {
            TABLE_ENTRY: _qword(COUNTRY),
            COUNTRY + 0x20: _qword(FULLREF),
            COUNTRY + 0xF30: _qword(RELIGION),
            COUNTRY + 0x28B8: _qword(school_pointer),
            RELIGION + 0x90: _string32(
                religion_key, storage=religion_storage, pointer=RELIGION_HEAP),
            RELIGION + 0xD8: _qword(GROUP),
            RELIGION + 0x90: _string32(
                religion_key, storage=religion_storage, pointer=RELIGION_HEAP),
            GROUP + 0x18: _string32(
                group_key, storage=group_storage, pointer=GROUP_HEAP),
        }
        if religion_storage == "heap":
            self.regions[RELIGION_HEAP] = religion_key + b"\0"
        if group_storage == "heap":
            self.regions[GROUP_HEAP] = group_key + b"\0"

        school_vtable = vtable if vtable is not None else (
            BASE + (0x1D21740 if has_school else 0x1C48598))
        expected_method = BASE + (0x8F440 if has_school else 0x8F450)
        self.regions[school_pointer] = _qword(school_vtable)
        self.regions[school_vtable + 0x88] = _qword(
            expected_method if method is None else method)
        if has_school:
            self.regions[GROUP + 0xA0] = _qword(definition_pointer)
            self.regions[definition_pointer + 0x10] = _qword(definition_owner)
            self.regions[definition_pointer + 0x20] = _qword(SCHOOL_ARRAY)
            self.regions[definition_pointer + 0x28] = _u32(capacity)
            self.regions[definition_pointer + 0x2C] = _u32(count)
            self.regions[school_pointer + 0x150] = _string32(
                school_key, storage=school_storage, capacity=school_capacity,
                pointer=SCHOOL_HEAP, terminator=school_terminator)
            self.regions[school_pointer + 0x170] = _qword(owner_group)
            self.regions[school_pointer + 0x178] = _u32(ordinal)
            member = school_pointer if array_member is None else array_member
            self.regions[SCHOOL_ARRAY + ordinal * 8] = _qword(member)
            if school_storage == "heap":
                self.regions[SCHOOL_HEAP] = school_key + b"\0"

    def read(self, address: int, size: int, label: str) -> bytes:
        self.calls.append((address, size, label))
        scripted = self.overrides.get(label)
        if scripted:
            result = scripted.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result
        for start, data in self.regions.items():
            offset = address - start
            if 0 <= offset and offset + size <= len(data):
                result = data[offset:offset + size]
                return result[:-1] if label in self.short_reads else result
        raise OSError(f"unmapped read: {label}")


def _read(reader: FakeMemory, fields=(memory.FIELD_ID,), *, base=BASE):
    return memory.read_fields(reader, base, reader.binding, fields)


def _unknown(field: dict, reason: str | None = None) -> None:
    assert field["status"] == "unknown"
    assert field["complete"] is False
    assert "value" not in field
    if reason is not None:
        assert reason in field["reason"]


def _mechanics_unknown(value: dict) -> None:
    assert value["uses_schools"] == {
        "status": "unknown", "reason": "RELIGIOUS_SCHOOLS_ACTIVATION_NOT_READ"}
    assert value["invited_scholars"] == {
        "status": "unknown", "reason": "INVITED_SCHOLARS_NOT_READ"}
    assert value["relations"] == {
        "status": "unknown", "reason": "SCHOOL_RELATIONS_NOT_READ"}


def test_inline_school_key_is_copied_and_mechanisms_remain_unknown():
    reader = FakeMemory(school_key=b"shafi")

    field = _read(reader)[memory.FIELD_ID]

    assert field["status"] == "known"
    assert field["complete"] is False
    assert field["basis"] == memory.BASIS
    value = field["value"]
    assert value["has_school"] is True
    assert value["religion_key"] == "catholic"
    assert value["religion_group_key"] == "christian"
    assert value["current_school"] == {"status": "known", "key": "shafi"}
    _mechanics_unknown(value)
    assert set(value) == {
        "has_school", "religion_key", "religion_group_key", "current_school",
        "uses_schools", "invited_scholars", "relations",
    }
    assert field["raw_inputs"]["school_ordinal"] == 1
    assert field["raw_inputs"]["school_count"] == 2
    assert field["raw_inputs"]["school_capacity"] == 2
    assert field["raw_inputs"]["budget"]["calls"] == len(reader.calls)
    assert field["raw_inputs"]["budget"]["bytes_requested"] <= memory.MAX_READ_BYTES
    assert "0x" not in repr(value)
    addresses = {label.removeprefix("religious_schools."): address
                 for address, _, label in reader.calls}
    assert addresses["school_group_definition"] == GROUP + 0xA0
    assert addresses["school_group_owner"] == DEFINITION + 0x10
    assert addresses["school_array"] == DEFINITION + 0x20
    assert addresses["school_capacity"] == DEFINITION + 0x28
    assert addresses["school_count"] == DEFINITION + 0x2C
    assert addresses["school_owner_group"] == SCHOOL + 0x170
    assert addresses["school_ordinal"] == SCHOOL + 0x178
    assert addresses["school_valid_method"] == (BASE + 0x1D21740 + 0x88)
    assert addresses["religion_identity.school_key.String32_header_before"] == SCHOOL + 0x150


def test_heap_school_key_is_read_and_rechecked():
    reader = FakeMemory(school_key=b"confucian", school_storage="heap", school_capacity=32)

    field = _read(reader)[memory.FIELD_ID]

    assert field["status"] == "known"
    assert field["value"]["current_school"] == {"status": "known", "key": "confucian"}
    labels = [label for _, _, label in reader.calls]
    assert labels.count("religious_schools.religion_identity.school_key.String32_header_before") == 1
    assert labels.count("religious_schools.religion_identity.school_key.String32_header_before_school_after") == 1
    assert labels.count("religious_schools.religion_identity.school_key.String32_heap_payload_before") == 1
    assert labels.count("religious_schools.religion_identity.school_key.String32_heap_payload_before_school_after") == 1


def test_native_no_school_sentinel_does_not_read_school_key_or_group_definition():
    reader = FakeMemory(has_school=False)

    field = _read(reader)[memory.FIELD_ID]

    assert field["status"] == "known"
    value = field["value"]
    assert value["has_school"] is False
    assert value["current_school"] == values.NONE
    _mechanics_unknown(value)
    labels = [label for _, _, label in reader.calls]
    assert not any("school_key" in label for label in labels)
    assert not any(label.endswith(name) for label in labels for name in (
        "school_group_definition", "school_group_owner", "school_owner_group",
        "school_count", "school_capacity", "school_ordinal", "school_array",
        "school_member",
    ))
    assert not any("uses_schools" in label or "invited_scholars" in label
                   or "relations" in label for label in labels)


@pytest.mark.parametrize("storage", ["inline", "heap"])
def test_school_string32_length_and_capacity_boundary_is_accepted(storage):
    reader = FakeMemory(school_key=b"a" * 15, school_storage=storage,
                        school_capacity=15 if storage == "inline" else 16)

    field = _read(reader)[memory.FIELD_ID]

    assert field["status"] == "known"
    assert field["value"]["current_school"]["key"] == "a" * 15


def test_school_string32_maximum_heap_key_length_is_accepted():
    reader = FakeMemory(school_key=b"a" * 128, school_storage="heap", school_capacity=8192)

    field = _read(reader)[memory.FIELD_ID]

    assert field["status"] == "known"
    assert field["value"]["current_school"]["key"] == "a" * 128


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"school_key": b""}, "school_read_failed"),
        ({"school_key": b"a" * 16, "school_storage": "inline", "school_capacity": 16},
         "school_read_failed"),
        ({"school_key": b"a", "school_storage": "heap", "school_capacity": 0},
         "school_read_failed"),
        ({"school_key": "学派".encode("utf-8"), "school_storage": "heap", "school_capacity": 16},
         "school_read_failed"),
        ({"school_key": b"school\0key"}, "school_read_failed"),
        ({"school_key": b"-bad"}, "school_read_failed"),
        ({"school_storage": "heap", "school_capacity": 8193}, "school_read_failed"),
    ],
)
def test_bad_school_string32_or_identifier_is_unknown(kwargs, reason):
    field = _read(FakeMemory(**kwargs))[memory.FIELD_ID]

    _unknown(field, reason)


@pytest.mark.parametrize(
    ("label", "reason"),
    [
        ("religious_schools.religion_identity.school_key.String32_header_before",
         "school_read_failed"),
        ("religious_schools.religion_identity.school_key.String32_heap_payload_before",
         "school_read_failed"),
    ],
)
def test_short_school_header_or_heap_payload_is_unknown(label, reason):
    reader = FakeMemory(school_storage="heap", school_capacity=16, short_reads={label})

    _unknown(_read(reader)[memory.FIELD_ID], reason)


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"school_pointer": 0}, "school_read_failed"),
        ({"vtable": BASE + 0x1D21748}, "unsupported_school_type"),
        ({"method": BASE + 0x8F450}, "unsupported_school_valid_method"),
        ({"definition_owner": GROUP + 8}, "school_group_owner_mismatch"),
        ({"owner_group": GROUP + 8}, "school_owner_group_mismatch"),
        ({"count": 0}, "school_array_bounds_invalid"),
        ({"count": 65}, "school_array_bounds_invalid"),
        ({"count": 2, "capacity": 1}, "school_array_bounds_invalid"),
        ({"count": 2, "capacity": 129}, "school_array_bounds_invalid"),
        ({"ordinal": 2, "count": 2}, "school_ordinal_out_of_bound"),
        ({"array_member": SCHOOL + 8}, "school_array_member_mismatch"),
        ({"definition_pointer": 0}, "school_read_failed"),
    ],
)
def test_invalid_vptr_ownership_membership_and_bounds_are_unknown(kwargs, reason):
    _unknown(_read(FakeMemory(**kwargs))[memory.FIELD_ID], reason)


@pytest.mark.parametrize(
    ("label", "replacement"),
    [
        ("religious_schools.religion_identity.school_key.String32_header_before_school_after",
         _string32(b"hanafi", capacity=15)),
        ("religious_schools.religion_identity.school_key.String32_heap_payload_before_school_after",
         b"hanaf\0"),
        ("religious_schools.religion_identity.primary_religion_pointer_before_school_after",
         _qword(RELIGION + 8)),
        ("religious_schools.religion_identity.group_pointer_before_school_after",
         _qword(GROUP + 8)),
    ],
)
def test_parent_identity_or_school_payload_drift_on_final_reread_revokes_field(
        label, replacement):
    storage = "heap" if "heap_payload" in label else "inline"
    reader = FakeMemory(school_storage=storage,
                        overrides={label: [replacement]})

    field = _read(reader)[memory.FIELD_ID]

    _unknown(field, "school_dependency_changed")
    assert field["raw_inputs"]["religion_identity"]["status"] == "known"


def test_parent_fullref_change_after_school_copy_revokes_field_even_without_date_change():
    label = "religious_schools.religion_identity.country_fullref_before_school_after"
    reader = FakeMemory(overrides={label: [_qword(FULLREF + 1)]})

    field = _read(reader)[memory.FIELD_ID]

    _unknown(field, "school_dependency_changed")


def test_leaf_budget_exhaustion_propagates(monkeypatch):
    reader = FakeMemory()
    monkeypatch.setattr(memory, "MAX_READ_BYTES", 0)

    with pytest.raises(ValueError, match="school_leaf_read_budget_exceeded"):
        _read(reader)


def test_shared_reader_budget_error_propagates():
    label = "religious_schools.religion_identity.country_table_entry_before"
    reader = FakeMemory(overrides={label: [RuntimeError("read_budget_exceeded")]})

    with pytest.raises(RuntimeError, match="read_budget_exceeded"):
        _read(reader)


def test_field_request_boundary_matches_other_religion_leaves():
    reader = FakeMemory()

    malformed = memory.read_fields(reader, BASE, reader.binding, [memory.FIELD_ID])
    duplicate = memory.read_fields(reader, BASE, reader.binding,
                                   (memory.FIELD_ID, memory.FIELD_ID))
    unsupported = memory.read_fields(reader, BASE, reader.binding, ("S02.other",))

    _unknown(malformed[memory.FIELD_ID], "fields_shape_invalid")
    _unknown(duplicate[memory.FIELD_ID], "duplicate_field_requested")
    _unknown(unsupported["S02.other"], "unsupported_field")
    assert reader.calls == []
