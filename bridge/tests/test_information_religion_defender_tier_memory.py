"""Fake-memory tests for S02.defender tier projection."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy

import pytest

from bridge.information import religion_defender_tier_memory as memory


BASE = 0x140000000
WORLD_GLOBAL_RVA = 0x233FE58
DATABASE_GLOBAL_RVA = 0x233D8B0
WORLD = 0x50000000
MANAGER = 0x51000000
RECORDS = 0x52000000
DATABASE = 0x53000000
TABLE = 0x54000000
RELIGION = 0x55000000
TARGET = 0x56000000
OTHER_RELIGION = 0x5A000000
COUNTRY_ARRAY = 0x59000000
TIER_ARRAY = 0x5B000000
WORLD_ARRAY_OFFSET = 0x1D08
WORLD_MANAGER_OFFSET = 0x25A8
COUNTRY_RELIGION_OFFSET = 0xF30
COUNTRY_FULLREF_OFFSET = 0x20
DATABASE_TABLE_OFFSET = 0x118
DATABASE_COUNT_OFFSET = 0x124
MAX_DATABASE_COUNT = 64


def _qword(value: int) -> bytes:
    return value.to_bytes(8, "little", signed=False)


def _i32(value: int) -> bytes:
    return value.to_bytes(4, "little", signed=True)


def _fullref(tag: str, slot: int, generation: int = 0xA5) -> int:
    return ((generation << 56) | (slot << 32)
            | int.from_bytes(tag.encode("ascii"), "little"))


class FakeReader:
    def __init__(self, cells):
        self.cells = dict(cells)
        self.calls = []
        self.occurrences = Counter()
        self.replacements = {}
        self.exceptions = {}

    def read(self, address, size, label):
        self.occurrences[address] += 1
        occurrence = self.occurrences[address]
        self.calls.append((address, size, label, occurrence))
        key = (address, occurrence)
        if key in self.exceptions:
            raise self.exceptions[key]
        return self.replacements.get(key, self.cells.get(address, bytes(size)))


def _tier_prefix(lower: int, upper: int, level: int) -> bytes:
    return bytes(0x20) + _i32(lower) + _i32(upper) + _i32(level) + bytes(0x30 - 0x2C)


def _scenario(*, matching_count=2, total_count=None, tiers=((0, 0, 7),),
              array_pointer=COUNTRY_ARRAY, tier_array_pointer=TIER_ARRAY,
              country_count_override=None, tier_count_override=None,
              database_count=MAX_DATABASE_COUNT):
    if total_count is None:
        total_count = matching_count if matching_count else 1
    cells = {
        BASE + WORLD_GLOBAL_RVA: _qword(WORLD),
        WORLD + WORLD_MANAGER_OFFSET: _qword(MANAGER),
        MANAGER + 0x30: _qword(RECORDS),
        BASE + DATABASE_GLOBAL_RVA: _qword(DATABASE),
        DATABASE + DATABASE_TABLE_OFFSET: _qword(TABLE),
        DATABASE + DATABASE_COUNT_OFFSET: _i32(database_count),
        TARGET + COUNTRY_RELIGION_OFFSET: _qword(RELIGION),
        TARGET + COUNTRY_FULLREF_OFFSET: _qword(_fullref("FRA", 10)),
        RELIGION: _qword(BASE + memory.holder.RELIGION_VTABLE_RVA),
        RELIGION + 0x70: _i32(1),
        RECORDS + 0x10: _qword(RELIGION),
        RECORDS + 0x34: _qword(_fullref("FRA", 10)),
        TABLE + 10 * 8: _qword(TARGET),
    }

    rows = []
    for index in range(total_count):
        if index == 0 and matching_count > 0:
            pointer, tag, slot = TARGET, "FRA", 10
        else:
            pointer = 0x57000000 + index * 0x10000
            tag, slot = f"C{index + 1:02d}", 11 + index
        faith_pointer = RELIGION if index < matching_count else OTHER_RELIGION
        reference = _fullref(tag, slot)
        cells[pointer + COUNTRY_FULLREF_OFFSET] = _qword(reference)
        cells[pointer + COUNTRY_RELIGION_OFFSET] = _qword(faith_pointer)
        cells[TABLE + slot * 8] = _qword(pointer)
        rows.append({"pointer": pointer, "tag": tag, "slot": slot,
                     "fullref": reference,
                     "fullref_address": pointer + COUNTRY_FULLREF_OFFSET,
                     "table_address": TABLE + slot * 8,
                     "religion_address": pointer + COUNTRY_RELIGION_OFFSET,
                     "religion": faith_pointer})

    if total_count == 0:
        array_pointer = 0
        pointer_bytes = b""
    else:
        pointer_bytes = b"".join(_qword(row["pointer"]) for row in rows)
        cells[array_pointer] = pointer_bytes
    country_count = total_count if country_count_override is None else country_count_override
    cells[WORLD + WORLD_ARRAY_OFFSET] = (
        _qword(array_pointer) + bytes(4) + _i32(country_count))

    tiers = tuple(tiers)
    tier_count = len(tiers) if tier_count_override is None else tier_count_override
    cells[BASE + memory.TIER_GLOBAL_RVA] = (
        _qword(tier_array_pointer) + bytes(4) + _i32(tier_count))
    for index, (lower, upper, level) in enumerate(tiers):
        cells[tier_array_pointer + index * memory.TIER_STRIDE] = _tier_prefix(lower, upper, level)

    target_ref = _fullref("FRA", 10)
    binding = {
        "tag": "FRA", "slot": 10, "country_pointer": hex(TARGET),
        "fullref": hex(target_ref), "fullref_raw_hex": _qword(target_ref).hex(),
        "country_fullref_address": hex(TARGET + COUNTRY_FULLREF_OFFSET),
        "table_entry_address": hex(TABLE + 10 * 8),
        "table_entry_raw_hex": _qword(TARGET).hex(),
    }
    layout = {"rows": rows, "world_header": WORLD + WORLD_ARRAY_OFFSET,
             "tier_header": BASE + memory.TIER_GLOBAL_RVA,
             "tier_row": tier_array_pointer}
    return FakeReader(cells), binding, layout


def _holder_value(binding):
    return {
        "status": "known", "complete": False,
        "basis": "bounded_native_religion_defender_country_reference",
        "value": {"defender_country": "FRA", "is_target_defender": True},
        "raw_inputs": {
            "religion_pointer": hex(RELIGION), "religion_state_id": 1,
            "world_pointer": hex(WORLD), "manager_pointer": hex(MANAGER),
            "records_pointer": hex(RECORDS), "record_pointer": hex(RECORDS),
            "holder_reference": hex(_fullref("FRA", 10)),
            "holder_country_pointer": hex(TARGET),
            "country_database_pointer": hex(DATABASE),
            "country_table_pointer": hex(TABLE),
            "country_binding": deepcopy(binding),
        },
        "gaps": [],
    }


def _read(reader, binding, monkeypatch, fields=None):
    requested = (memory.FIELD_ID,) if fields is None else fields

    def known_holder(_reader, _base, target_binding, names):
        field = _holder_value(target_binding)
        return {name: deepcopy(field) if name == memory.FIELD_ID else {
            "status": "unknown", "complete": False, "reason": "unsupported_field"
        } for name in names}

    monkeypatch.setattr(memory.holder, "read_fields", known_holder)
    return memory.read_fields(reader, BASE, binding, requested)


def _tier(field):
    return field["value"]["tier"]


def _assert_tier_unknown(field):
    assert field["status"] == "known"
    assert field["value"]["defender_country"] == "FRA"
    assert field["value"]["is_target_defender"] is True
    assert _tier(field) == {
        "status": "unknown", "reason": "RELIGION_DEFENDER_TIER_UNAVAILABLE"
    }


@pytest.mark.parametrize(("count", "expected_level"), [
    (4, None), (5, 71), (9, 71), (10, None),
])
def test_range_is_lower_inclusive_and_upper_exclusive(count, expected_level, monkeypatch):
    reader, binding, _ = _scenario(matching_count=count, tiers=((5, 10, 71),))
    field = _read(reader, binding, monkeypatch)[memory.FIELD_ID]
    if expected_level is None:
        _assert_tier_unknown(field)
    else:
        assert field["status"] == "known"
        assert _tier(field) == {
            "status": "known", "level": 71, "same_faith_country_count": count,
            "range_from": 5, "range_to_exclusive": 10,
        }


def test_zero_upper_is_open_ended_and_signed_custom_level_is_preserved(monkeypatch):
    reader, binding, _ = _scenario(matching_count=4, tiers=((2, 0, -9),))
    field = _read(reader, binding, monkeypatch)[memory.FIELD_ID]
    assert _tier(field) == {
        "status": "known", "level": -9, "same_faith_country_count": 4,
        "range_from": 2, "range_to_exclusive": None,
    }


def test_overlapping_ranges_choose_first_matching_record(monkeypatch):
    reader, binding, _ = _scenario(matching_count=2,
                                    tiers=((0, 4, 87), (0, 0, 99)))
    field = _read(reader, binding, monkeypatch)[memory.FIELD_ID]
    assert _tier(field)["level"] == 87


def test_no_matching_tier_keeps_holder_and_marks_only_nested_tier_unknown(monkeypatch):
    reader, binding, _ = _scenario(matching_count=2, tiers=((3, 0, 1),))
    field = _read(reader, binding, monkeypatch)[memory.FIELD_ID]
    _assert_tier_unknown(field)


@pytest.mark.parametrize(("country_count", "tier_count"), [
    (-1, 1), (memory.MAX_COUNTRIES + 1, 1), (1, -1), (1, memory.MAX_TIERS + 1),
])
def test_country_and_tier_counts_outside_software_bounds_are_unknown(
        country_count, tier_count, monkeypatch):
    reader, binding, _ = _scenario(matching_count=1,
                                    country_count_override=country_count,
                                    tier_count_override=tier_count)
    field = _read(reader, binding, monkeypatch)[memory.FIELD_ID]
    _assert_tier_unknown(field)


@pytest.mark.parametrize("which", ["country_array", "tier_array"])
def test_array_pointer_overflow_is_unknown(which, monkeypatch):
    boundary_pointer = memory.membership.MAX_USER_ADDRESS_EXCLUSIVE - 8
    if which == "country_array":
        reader, binding, _ = _scenario(matching_count=1, total_count=2,
                                        array_pointer=boundary_pointer)
    else:
        reader, binding, _ = _scenario(matching_count=1,
                                        tier_array_pointer=boundary_pointer)
    field = _read(reader, binding, monkeypatch)[memory.FIELD_ID]
    _assert_tier_unknown(field)


def test_country_array_read_ending_at_user_address_boundary_is_legal(monkeypatch):
    boundary_pointer = memory.membership.MAX_USER_ADDRESS_EXCLUSIVE - 8
    reader, binding, _ = _scenario(matching_count=1, array_pointer=boundary_pointer)
    field = _read(reader, binding, monkeypatch)[memory.FIELD_ID]
    assert field["status"] == "known"
    assert _tier(field) == {
        "status": "known", "level": 7, "same_faith_country_count": 1,
        "range_from": 0, "range_to_exclusive": None,
    }


@pytest.mark.parametrize("defect", [
    "duplicate_pointer", "duplicate_fullref", "invalid_fullref", "table_mismatch"
])
def test_candidate_country_identity_errors_make_tier_unknown(defect, monkeypatch):
    reader, binding, layout = _scenario(matching_count=2)
    first, second = layout["rows"]
    if defect == "duplicate_pointer":
        reader.cells[COUNTRY_ARRAY] = _qword(first["pointer"]) * 2
    elif defect == "duplicate_fullref":
        reader.cells[second["fullref_address"]] = _qword(first["fullref"])
    elif defect == "invalid_fullref":
        reader.cells[second["fullref_address"]] = _qword(0)
    else:
        reader.cells[second["table_address"]] = _qword(TARGET)
    field = _read(reader, binding, monkeypatch)[memory.FIELD_ID]
    _assert_tier_unknown(field)


@pytest.mark.parametrize("address_kind", ["fullref", "table", "religion"])
def test_country_row_dependencies_changed_after_copy_retract_only_tier(
        address_kind, monkeypatch):
    reader, binding, layout = _scenario(matching_count=2)
    row = layout["rows"][1]
    address = {"fullref": row["fullref_address"],
               "table": row["table_address"],
               "religion": row["religion_address"]}[address_kind]
    original = reader.cells[address]
    replacement = _qword(OTHER_RELIGION if address_kind == "religion" else TARGET)
    if address_kind == "fullref":
        replacement = _qword(_fullref("C77", 40))
    reader.replacements[(address, 2)] = replacement if replacement != original else _qword(OTHER_RELIGION)
    field = _read(reader, binding, monkeypatch)[memory.FIELD_ID]
    _assert_tier_unknown(field)


@pytest.mark.parametrize("dependency", ["country_header", "country_rows", "tier_header", "tier_row"])
def test_changed_list_or_tier_snapshot_retracts_only_nested_tier(dependency, monkeypatch):
    reader, binding, layout = _scenario(matching_count=2)
    address = {
        "country_header": layout["world_header"],
        "country_rows": COUNTRY_ARRAY,
        "tier_header": layout["tier_header"],
        "tier_row": layout["tier_row"],
    }[dependency]
    original = reader.cells[address]
    changed = bytearray(original)
    changed[0] ^= 1
    reader.replacements[(address, 2)] = bytes(changed)
    field = _read(reader, binding, monkeypatch)[memory.FIELD_ID]
    _assert_tier_unknown(field)


@pytest.mark.parametrize("address_kind", [
    "selected_entry", "selected_ref", "religion", "holder_ref_initial", "holder_ref_after"
])
def test_changed_shared_holder_or_binding_retracts_entire_field(address_kind, monkeypatch):
    reader, binding, _ = _scenario(matching_count=2)
    address = {
        "selected_entry": TABLE + 10 * 8,
        "selected_ref": TARGET + COUNTRY_FULLREF_OFFSET,
        "religion": TARGET + COUNTRY_RELIGION_OFFSET,
        "holder_ref_initial": RECORDS + 0x34,
        "holder_ref_after": RECORDS + 0x34,
    }[address_kind]
    changed = {
        "selected_entry": _qword(0x57000000),
        "selected_ref": _qword(_fullref("FRA", 10, 0xA4)),
        "religion": _qword(OTHER_RELIGION),
        "holder_ref_initial": _qword(_fullref("ENG", 11)),
        "holder_ref_after": _qword(_fullref("ENG", 11)),
    }[address_kind]
    occurrence = 2 if address_kind == "holder_ref_after" else 1
    reader.replacements[(address, occurrence)] = changed
    field = _read(reader, binding, monkeypatch)[memory.FIELD_ID]
    assert field["status"] == "unknown"
    assert field["reason"] == "RELIGION_DEFENDER_COMPONENTS_CHANGED"
    assert "value" not in field


def test_short_or_failed_tier_read_keeps_known_holder(monkeypatch):
    reader, binding, layout = _scenario(matching_count=2)
    reader.replacements[(layout["tier_row"], 1)] = b"short"
    field = _read(reader, binding, monkeypatch)[memory.FIELD_ID]
    _assert_tier_unknown(field)


@pytest.mark.parametrize(("limit_name", "message"), [
    ("MAX_READ_CALLS", "read_call_budget_exceeded"),
    ("MAX_READ_BYTES", "read_budget_exceeded"),
])
def test_leaf_budget_errors_propagate(monkeypatch, limit_name, message):
    reader, binding, _ = _scenario(matching_count=2)
    monkeypatch.setattr(memory, limit_name, 0)
    with pytest.raises(ValueError, match=message):
        _read(reader, binding, monkeypatch)


def test_outer_reader_budget_error_propagates(monkeypatch):
    reader, binding, _ = _scenario(matching_count=2)
    reader.exceptions[(TABLE + 10 * 8, 1)] = RuntimeError("read_budget_exceeded")
    with pytest.raises(RuntimeError, match="read_budget_exceeded"):
        _read(reader, binding, monkeypatch)


def test_requested_non_defender_field_does_not_read_tier(monkeypatch):
    reader, binding, _ = _scenario(matching_count=2)
    result = _read(reader, binding, monkeypatch, fields=("S02.unrelated",))
    assert result["S02.unrelated"]["status"] == "unknown"
    assert reader.calls == []

