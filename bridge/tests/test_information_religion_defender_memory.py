"""Fake-memory tests for the bounded S02 defender-of-faith leaf."""
from __future__ import annotations

from collections import Counter

import pytest

from bridge.information import religion_defender_memory as memory


MODULE_BASE = 0x140000000
WORLD_GLOBAL_RVA = 0x233FE58
DATABASE_GLOBAL_RVA = 0x233D8B0
WORLD_DEFENDER_MANAGER_OFFSET = 0x25A8
MANAGER_RECORDS_OFFSET = 0x30
COUNTRY_RELIGION_OFFSET = 0xF30
RELIGION_VTABLE_OFFSET = 0x0
RELIGION_STATE_ID_OFFSET = 0x70
RECORD_RELIGION_OFFSET = 0x10
RECORD_HOLDER_FULLREF_OFFSET = 0x34
DATABASE_TABLE_OFFSET = 0x118
DATABASE_COUNT_OFFSET = 0x124
COUNTRY_FULLREF_OFFSET = 0x20
COUNTRY_RECORD_STRIDE = 0x50

WORLD = 0x50000000
MANAGER = 0x51000000
RECORDS = 0x52000000
DATABASE = 0x53000000
TABLE = 0x54000000
RELIGION = 0x55000000
TARGET_COUNTRY = 0x56000000
HOLDER_COUNTRY = 0x57000000
OTHER = 0x58000000


def _qword(value: int) -> bytes:
    return value.to_bytes(8, "little", signed=False)


def _i32(value: int) -> bytes:
    return value.to_bytes(4, "little", signed=True)


def _fullref(tag: str, slot: int, generation: int = 0xA5) -> int:
    return (generation << 56) | (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


class FakeReader:
    """Address keyed memory with optional per-address occurrence changes."""

    def __init__(self, cells):
        self.cells = dict(cells)
        self.calls = []
        self.occurrences = Counter()
        self.replacements = {}
        self.exceptions = {}
        self.callbacks = {}

    def read(self, address, size, label):
        self.occurrences[address] += 1
        occurrence = self.occurrences[address]
        self.calls.append((address, size, label, occurrence))
        key = (address, occurrence)
        if key in self.exceptions:
            raise self.exceptions[key]
        value = self.replacements.get(key, self.cells.get(address, bytes(size)))
        callback = self.callbacks.get(key)
        if callback is not None:
            callback()
        return value


def _scenario(*, target_tag="FRA", holder_tag="FRA", target_slot=None,
              holder_slot=None, target_generation=0xA5, holder_generation=None,
              state_id=1, holder_reference=None, target_country_pointer=None,
              holder_country_pointer=None, overrides=None):
    if target_slot is None:
        target_slot = 10 if target_tag == "FRA" else 11
    if holder_slot is None:
        holder_slot = 10 if holder_tag == "FRA" else 11
    if holder_generation is None:
        holder_generation = target_generation
    target_ref = _fullref(target_tag, target_slot, target_generation)
    holder_ref = (_fullref(holder_tag, holder_slot, holder_generation)
                  if holder_reference is None else holder_reference)
    if target_country_pointer is None:
        target_country_pointer = TARGET_COUNTRY
    same_current_ref = target_slot == holder_slot and target_ref == holder_ref
    if holder_country_pointer is None:
        holder_country_pointer = target_country_pointer if same_current_ref else HOLDER_COUNTRY

    cells = {
        MODULE_BASE + WORLD_GLOBAL_RVA: _qword(WORLD),
        WORLD + WORLD_DEFENDER_MANAGER_OFFSET: _qword(MANAGER),
        MANAGER + MANAGER_RECORDS_OFFSET: _qword(RECORDS),
        target_country_pointer + COUNTRY_RELIGION_OFFSET: _qword(RELIGION),
        RELIGION + RELIGION_VTABLE_OFFSET: _qword(MODULE_BASE + memory.RELIGION_VTABLE_RVA),
        RELIGION + RELIGION_STATE_ID_OFFSET: _i32(state_id),
        MODULE_BASE + DATABASE_GLOBAL_RVA: _qword(DATABASE),
        DATABASE + DATABASE_TABLE_OFFSET: _qword(TABLE),
        DATABASE + DATABASE_COUNT_OFFSET: _i32(20),
        target_country_pointer + COUNTRY_FULLREF_OFFSET: _qword(target_ref),
        holder_country_pointer + COUNTRY_FULLREF_OFFSET: _qword(holder_ref),
    }
    if 1 <= state_id <= memory.MAX_RELIGION_STATE_ID:
        record_pointer = RECORDS + (state_id - 1) * COUNTRY_RECORD_STRIDE
        cells[record_pointer + RECORD_RELIGION_OFFSET] = _qword(RELIGION)
        cells[record_pointer + RECORD_HOLDER_FULLREF_OFFSET] = _qword(holder_ref)
    else:
        record_pointer = None

    cells[TABLE + target_slot * 8] = _qword(target_country_pointer)
    cells[TABLE + holder_slot * 8] = _qword(holder_country_pointer)
    layout = {
        "world_cell": MODULE_BASE + WORLD_GLOBAL_RVA,
        "world_manager_cell": WORLD + WORLD_DEFENDER_MANAGER_OFFSET,
        "manager_records_cell": MANAGER + MANAGER_RECORDS_OFFSET,
        "target_religion_cell": target_country_pointer + COUNTRY_RELIGION_OFFSET,
        "religion_vtable_cell": RELIGION + RELIGION_VTABLE_OFFSET,
        "religion_state_id_cell": RELIGION + RELIGION_STATE_ID_OFFSET,
        "record_pointer": record_pointer,
        "record_religion_cell": (record_pointer + RECORD_RELIGION_OFFSET
                                 if record_pointer is not None else None),
        "record_holder_cell": (record_pointer + RECORD_HOLDER_FULLREF_OFFSET
                               if record_pointer is not None else None),
        "database_cell": MODULE_BASE + DATABASE_GLOBAL_RVA,
        "database_table_cell": DATABASE + DATABASE_TABLE_OFFSET,
        "database_count_cell": DATABASE + DATABASE_COUNT_OFFSET,
        "holder_slot_cell": TABLE + holder_slot * 8,
        "holder_fullref_cell": holder_country_pointer + COUNTRY_FULLREF_OFFSET,
        "selected_slot_cell": TABLE + target_slot * 8,
        "selected_fullref_cell": target_country_pointer + COUNTRY_FULLREF_OFFSET,
        "manager": MANAGER,
        "target_slot": target_slot,
        "holder_slot": holder_slot,
        "target_ref": target_ref,
        "holder_ref": holder_ref,
    }
    for key, value in (overrides or {}).items():
        address = layout[key]
        cells[address] = value

    binding = {
        "tag": target_tag,
        "slot": target_slot,
        "country_pointer": hex(target_country_pointer),
        "fullref": hex(target_ref),
        "fullref_raw_hex": _qword(target_ref).hex(),
        "country_fullref_address": hex(target_country_pointer + COUNTRY_FULLREF_OFFSET),
        "table_entry_address": hex(TABLE + target_slot * 8),
        "table_entry_raw_hex": _qword(target_country_pointer).hex(),
    }
    return FakeReader(cells), binding, layout


def _read(reader, binding, fields=None):
    requested = (memory.FIELD_ID,) if fields is None else fields
    return memory.read_fields(reader, MODULE_BASE, binding, requested)


def _assert_unknown(field):
    assert field["status"] == "unknown"
    assert field["complete"] is False
    assert "value" not in field


@pytest.mark.parametrize(("target_tag", "holder_tag", "expected"), [
    ("FRA", "FRA", True),
    ("ENG", "FRA", False),
])
def test_valid_holder_and_exact_target_fullref_projection(target_tag, holder_tag, expected):
    reader, binding, layout = _scenario(target_tag=target_tag, holder_tag=holder_tag)

    field = _read(reader, binding)[memory.FIELD_ID]

    assert field["status"] == "known"
    assert field["complete"] is False
    assert field["basis"] == "bounded_native_religion_defender_country_reference"
    assert set(field["value"]) == {"defender_country", "is_target_defender"}
    assert field["value"] == {
        "defender_country": holder_tag,
        "is_target_defender": expected,
    }
    assert field["raw_inputs"]["budget"]["calls"] == len(reader.calls)
    assert len(reader.calls) <= memory.MAX_READ_CALLS
    assert field["raw_inputs"]["budget"]["bytes_requested"] <= memory.MAX_READ_BYTES
    assert all(address not in {layout["manager"] + 0x38,
                               layout["manager"] + 0x3C,
                               MODULE_BASE + memory.RELIGION_VTABLE_RVA + 0x40}
               for address, _, _, _ in reader.calls)


@pytest.mark.parametrize("holder_reference", [
    0,
    (0xA5 << 56) | (10 << 32) | int.from_bytes(b"F!A", "little"),
    (0xA5 << 56) | int.from_bytes(b"FRA", "little"),
    (10 << 32) | int.from_bytes(b"FRA", "little"),
])
def test_invalid_or_unproven_holder_reference_is_unknown(holder_reference):
    reader, binding, _ = _scenario(holder_reference=holder_reference)

    field = _read(reader, binding)[memory.FIELD_ID]

    _assert_unknown(field)


def test_same_slot_different_generation_never_becomes_false():
    reader, binding, _ = _scenario(
        target_tag="FRA", holder_tag="FRA", target_generation=0xA5,
        holder_generation=0xB6,
    )

    field = _read(reader, binding)[memory.FIELD_ID]

    _assert_unknown(field)


@pytest.mark.parametrize("state_id", [-1, 0, 4097, 0x7FFFFFFF])
def test_invalid_religion_state_id_never_projects_known_false(state_id):
    reader, binding, _ = _scenario(state_id=state_id)

    field = _read(reader, binding)[memory.FIELD_ID]

    _assert_unknown(field)


def test_maximum_software_bounded_religion_state_id_is_addressable():
    reader, binding, _ = _scenario(state_id=memory.MAX_RELIGION_STATE_ID)

    field = _read(reader, binding)[memory.FIELD_ID]

    assert field["status"] == "known"
    assert field["value"]["defender_country"] == "FRA"
    assert field["value"]["is_target_defender"] is True


def test_checked_record_address_arithmetic_rejects_user_space_overflow():
    max_aligned_user_address = 0x00007FFFFFFFFFF8
    reader, binding, _ = _scenario(
        state_id=2,
        overrides={"manager_records_cell": _qword(max_aligned_user_address)},
    )

    field = _read(reader, binding)[memory.FIELD_ID]

    _assert_unknown(field)
    assert all(address <= max_aligned_user_address for address, _, _, _ in reader.calls)


@pytest.mark.parametrize(("override", "value"), [
    ("world_cell", _qword(0)),
    ("world_manager_cell", _qword(0)),
    ("manager_records_cell", _qword(0)),
    ("target_religion_cell", _qword(0)),
    ("religion_vtable_cell", _qword(0)),
    ("religion_vtable_cell", _qword(MODULE_BASE + memory.RELIGION_VTABLE_RVA + 8)),
])
def test_null_or_wrong_type_pointers_are_unknown(override, value):
    reader, binding, _ = _scenario(overrides={override: value})

    field = _read(reader, binding)[memory.FIELD_ID]

    _assert_unknown(field)


def test_record_self_identity_must_match_the_selected_country_religion():
    reader, binding, layout = _scenario()
    reader.cells[layout["record_religion_cell"]] = _qword(OTHER)

    field = _read(reader, binding)[memory.FIELD_ID]

    _assert_unknown(field)


@pytest.mark.parametrize(("overrides", "target_tag", "holder_tag"), [
    ({"database_count_cell": _i32(0)}, "ENG", "FRA"),
    ({"database_count_cell": _i32(4097)}, "ENG", "FRA"),
    ({"database_count_cell": _i32(10)}, "ENG", "FRA"),
    ({"holder_slot_cell": _qword(0)}, "ENG", "FRA"),
    ({"holder_fullref_cell": _qword(_fullref("POR", 10, 0xB6))}, "ENG", "FRA"),
    ({"selected_slot_cell": _qword(OTHER)}, "ENG", "FRA"),
    ({"selected_fullref_cell": _qword(_fullref("ENG", 11, 0xB6))}, "ENG", "FRA"),
])
def test_country_database_binding_must_be_valid(overrides, target_tag, holder_tag):
    reader, binding, layout = _scenario(
        target_tag=target_tag, holder_tag=holder_tag,
    )
    for key, value in overrides.items():
        reader.cells[layout[key]] = value

    field = _read(reader, binding)[memory.FIELD_ID]

    _assert_unknown(field)


@pytest.mark.parametrize(("edge", "replacement"), [
    ("world_cell", _qword(OTHER)),
    ("world_manager_cell", _qword(OTHER)),
    ("manager_records_cell", _qword(OTHER)),
    ("target_religion_cell", _qword(OTHER)),
    ("religion_vtable_cell", _qword(MODULE_BASE + memory.RELIGION_VTABLE_RVA + 8)),
    ("religion_state_id_cell", _i32(2)),
    ("record_religion_cell", _qword(OTHER)),
    ("record_holder_cell", _qword(_fullref("POR", 12, 0xB6))),
    ("database_cell", _qword(OTHER)),
    ("database_table_cell", _qword(OTHER)),
    ("database_count_cell", _i32(21)),
    ("holder_slot_cell", _qword(OTHER)),
    ("holder_fullref_cell", _qword(_fullref("POR", 10, 0xB6))),
    ("selected_slot_cell", _qword(OTHER)),
    ("selected_fullref_cell", _qword(_fullref("ENG", 11, 0xB6))),
])
def test_every_selected_binding_edge_is_rechecked(edge, replacement):
    reader, binding, layout = _scenario(target_tag="ENG", holder_tag="FRA")
    address = layout[edge]
    reader.replacements[(address, 2)] = replacement

    field = _read(reader, binding)[memory.FIELD_ID]

    _assert_unknown(field)


@pytest.mark.parametrize(("kind", "error"), [
    ("raise", OSError("read failed")),
    ("budget", ValueError("read_budget_exceeded")),
    ("call_budget", ValueError("read_call_budget_exceeded")),
])
def test_reader_failures_are_unknown_but_outer_budget_exhaustion_propagates(kind, error):
    reader, binding, layout = _scenario()
    address = layout["world_cell"]
    if kind == "raise":
        reader.exceptions[(address, 1)] = error
        field = _read(reader, binding)[memory.FIELD_ID]
        _assert_unknown(field)
    else:
        reader.exceptions[(address, 1)] = error
        with pytest.raises(ValueError, match="read_(call_)?budget_exceeded"):
            _read(reader, binding)


def test_short_read_is_unknown_without_a_partial_public_value():
    reader, binding, layout = _scenario()
    reader.replacements[(layout["world_cell"], 1)] = b"\x01" * 7

    field = _read(reader, binding)[memory.FIELD_ID]

    _assert_unknown(field)


@pytest.mark.parametrize(("limit_name", "limit", "message"), [
    ("MAX_READ_CALLS", 0, "read_call_budget_exceeded"),
    ("MAX_READ_BYTES", 1, "read_budget_exceeded"),
])
def test_leaf_budget_exhaustion_propagates_to_outer_capture(monkeypatch, limit_name, limit, message):
    reader, binding, _ = _scenario()
    monkeypatch.setattr(memory, limit_name, limit)

    with pytest.raises(ValueError, match=message):
        _read(reader, binding)


@pytest.mark.parametrize("target_binding_change", [
    ("slot", 12),
    ("country_pointer", hex(OTHER)),
    ("table_entry_address", hex(TABLE + 12 * 8)),
])
def test_invalid_or_stale_selected_binding_is_unknown(target_binding_change):
    reader, binding, _ = _scenario(target_tag="ENG", holder_tag="FRA")
    key, value = target_binding_change
    binding[key] = value

    field = _read(reader, binding)[memory.FIELD_ID]

    _assert_unknown(field)


def test_only_requested_field_is_returned_and_other_fields_are_unknown():
    reader, binding, _ = _scenario()

    result = _read(reader, binding, fields=(memory.FIELD_ID, "S02.faith"))

    assert set(result) == {memory.FIELD_ID, "S02.faith"}
    assert result[memory.FIELD_ID]["status"] == "known"
    _assert_unknown(result["S02.faith"])
