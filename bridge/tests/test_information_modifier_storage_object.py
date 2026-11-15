"""Offline contract tests for the address-bound raw modifier storage core."""
from __future__ import annotations

import struct

import pytest

from bridge.information import foreign_quality_memory as quality
from bridge.information import modifier_storage


OBJECT = 0x50000000
COUNTRY = 0x52000000
VALUES = 0x54000000
UNIT = "ratio_modifier"


class Memory:
    def __init__(self):
        self.bytes: dict[int, int] = {}
        self.calls: list[tuple[int, int, str]] = []

    def put(self, address: int, value: bytes) -> None:
        self.bytes.update({address + index: byte for index, byte in enumerate(value)})

    def read(self, address: int, size: int, label: str) -> bytes:
        self.calls.append((address, size, label))
        try:
            return bytes(self.bytes[address + index] for index in range(size))
        except KeyError as exc:
            raise ValueError("fake_unmapped") from exc


def _trace(*, object_address=OBJECT, dense=True, values_pointer=VALUES,
           sparse_entries=(), count=None):
    memory = Memory()
    memory.put(object_address + quality.MODIFIER_DENSE_FLAG_OFFSET,
               bytes([1 if dense else 0]))
    memory.put(object_address + quality.MODIFIER_VALUES_POINTER_OFFSET,
               struct.pack("<Q", values_pointer))
    entry_count = len(sparse_entries) if count is None else count
    memory.put(object_address + quality.MODIFIER_SPARSE_COUNT_OFFSET,
               struct.pack("<I", entry_count))
    if sparse_entries:
        raw = b"".join(struct.pack("<ii", modifier_id, value)
                       for modifier_id, value in sparse_entries)
        memory.put(values_pointer, raw)
    return memory, quality._TraceReader(memory)


def _i32(value):
    return struct.pack("<i", value)


def test_object_api_dense_reads_from_supplied_object_and_records_raw_contract():
    memory, trace = _trace()
    memory.put(VALUES + 12, _i32(-3775))

    result = modifier_storage.read_raw_modifier_object(
        trace, OBJECT, 1, UNIT, name="province_index")

    assert result["status"] == "known"
    assert result["raw"] == result["value"] == -3775
    assert result["scale"] == 1000
    inputs = result["raw_inputs"]
    assert inputs["modifier_id"] == 1
    assert inputs["semantics"] == "raw_storage_only"
    assert inputs["modifier_object_storage"] == "explicit_address"
    assert inputs["mode"] == "dense"
    assert any(address == OBJECT + quality.MODIFIER_DENSE_FLAG_OFFSET
               for address, _, _ in memory.calls)
    assert all(label.startswith("modifier_storage.province_index.")
               for _, _, label in memory.calls)
    assert not any("processor" in label for _, _, label in memory.calls)


@pytest.mark.parametrize("modifier_id", [0, 0x286])
def test_object_api_accepts_both_inclusive_id_boundaries(modifier_id):
    memory, trace = _trace()
    value_address = VALUES + modifier_id * 8 + 4
    memory.put(value_address, _i32(modifier_id))

    result = modifier_storage.read_raw_modifier_object(
        trace, OBJECT, modifier_id, UNIT, name="boundary")

    assert result["status"] == "known"
    assert result["raw"] == modifier_id
    assert result["raw_inputs"]["storage_address"] == hex(value_address)


@pytest.mark.parametrize("modifier_id", [False, True, -1, 0x287, 1.0, "1", None])
def test_object_api_rejects_invalid_ids_before_any_read(modifier_id):
    memory, trace = _trace()

    result = modifier_storage.read_raw_modifier_object(
        trace, OBJECT, modifier_id, UNIT, name="bad_id")

    assert result["status"] == "unknown"
    assert result["reason"] == "MODIFIER_ID_INVALID"
    assert result["raw_inputs"]["modifier_id"] == modifier_id
    assert trace.calls == 0


@pytest.mark.parametrize("object_address", [0, False, 0x50000001, 0x800000000000])
def test_object_api_rejects_invalid_object_addresses_before_any_read(object_address):
    memory, trace = _trace()

    result = modifier_storage.read_raw_modifier_object(
        trace, object_address, 0, UNIT, name="bad_object")

    assert result["status"] == "unknown"
    assert result["reason"] == "MODIFIER_OBJECT_POINTER_INVALID"
    assert trace.calls == 0


def test_object_api_rejects_values_pointer_alias_to_object_or_forbidden_pointer():
    for values_pointer, forbidden in ((OBJECT, ()), (VALUES, (VALUES,))):
        memory, trace = _trace(values_pointer=values_pointer)
        result = modifier_storage.read_raw_modifier_object(
            trace, OBJECT, 1, UNIT, name="alias", forbidden_pointers=forbidden)
        assert result["status"] == "unknown"
        assert result["reason"] == "MODIFIER_VALUES_POINTER_ALIAS"


def test_object_api_sparse_returns_first_matching_true_zero():
    entries = [(8, 990), (7, 0), (7, 11)]
    memory, trace = _trace(dense=False, sparse_entries=entries)

    result = modifier_storage.read_raw_modifier_object(
        trace, OBJECT, 7, UNIT, name="sparse_zero")

    assert result["status"] == "known"
    assert result["raw"] == result["value"] == 0
    assert result["raw_inputs"]["first_match_index"] == 1
    assert [item["id"] for item in result["raw_inputs"]["entries_examined"]] == [8, 7]


def test_object_api_empty_sparse_returns_known_zero_without_value_read():
    memory, trace = _trace(dense=False, values_pointer=0, sparse_entries=[])

    result = modifier_storage.read_raw_modifier_object(
        trace, OBJECT, 7, UNIT, name="empty_sparse")

    assert result["status"] == "known"
    assert result["raw"] == result["value"] == 0
    assert result["raw_inputs"]["first_match_index"] is None
    assert not any("sparse_entries" in label for _, _, label in memory.calls)


def test_object_api_rejects_sparse_count_over_limit_before_entry_read():
    memory, trace = _trace(dense=False, sparse_entries=[], count=quality.MAX_SPARSE_ENTRIES + 1)

    result = modifier_storage.read_raw_modifier_object(
        trace, OBJECT, 7, UNIT, name="large_sparse")

    assert result["status"] == "unknown"
    assert result["reason"] == "MODIFIER_COUNT_OUT_OF_RANGE"
    assert not any("sparse_entries" in label for _, _, label in memory.calls)


def test_country_wrapper_preserves_inline_binding_inputs_and_results():
    object_address = COUNTRY + quality.COUNTRY_MODIFIER_OBJECT_OFFSET
    memory, trace = _trace(object_address=object_address)
    memory.put(VALUES + 220 * 8 + 4, _i32(-4412))

    result = modifier_storage.read_raw_modifier(
        trace, COUNTRY, 220, "diplomats", name="compat")

    assert result["status"] == "known"
    assert result["raw"] == result["value"] == -4412
    inputs = result["raw_inputs"]
    assert inputs["modifier_object_storage"] == "inline"
    assert inputs["modifier_id"] == 220
    assert inputs["mode"] == "dense"
    assert set(inputs) == {
        "modifier_id", "semantics", "modifier_object_storage", "dense_flag_address",
        "dense_flag", "values_pointer_cell", "values_pointer", "count_address", "count",
        "mode", "storage_address", "storage_raw_hex", "first_match_index", "modifier_raw",
    }
    assert any(address == object_address + quality.MODIFIER_DENSE_FLAG_OFFSET
               for address, _, _ in memory.calls)


def test_country_wrapper_keeps_country_and_object_alias_rejections():
    object_address = COUNTRY + quality.COUNTRY_MODIFIER_OBJECT_OFFSET
    for values_pointer in (COUNTRY, object_address):
        memory, trace = _trace(object_address=object_address, values_pointer=values_pointer)
        result = modifier_storage.read_raw_modifier(
            trace, COUNTRY, 220, "diplomats", name="legacy_alias")
        assert result["status"] == "unknown"
        assert result["reason"] == "MODIFIER_VALUES_POINTER_ALIAS"

