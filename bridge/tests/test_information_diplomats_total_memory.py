"""Bounded offline tests for the N05 native diplomat-capacity cache leaf."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import diplomats_total_memory as memory
from bridge.information import foreign_quality_memory as quality
from bridge.tests import test_information_country_scale_development_memory as scale_fixture


BASE = scale_fixture.BASE
TARGET_PTR = scale_fixture.TARGET_PTR
MANAGER = 0x70000000
VALUES = 0x71000000


def _qword(value: int) -> bytes:
    return int(value).to_bytes(8, "little", signed=False)


def _i32(value: int) -> bytes:
    return int(value).to_bytes(4, "little", signed=True)


def _install(reader, *, modifier_raw: int = 2500, cache_state: int = 0,
             dense: bool = True, sparse_entries: list[tuple[int, int]] | None = None,
             processor: int = 0, values_pointer: int | None = None):
    reader.put(TARGET_PTR + quality.COUNTRY_CACHE_STATE_OFFSET, _i32(cache_state))
    reader.put(BASE + quality.MODIFIER_PROCESSOR_GLOBAL_RVA, _qword(MANAGER))
    processor_cell = (MANAGER + memory.MODIFIER_ID * quality.MODIFIER_PROCESSOR_STRIDE
                      + quality.MODIFIER_PROCESSOR_OFFSET)
    reader.put(processor_cell, _qword(processor))

    modifier = TARGET_PTR + quality.COUNTRY_MODIFIER_OBJECT_OFFSET
    reader.put(modifier + quality.MODIFIER_DENSE_FLAG_OFFSET,
               bytes([1 if dense else 0]))
    entries = list(sparse_entries or [])
    if dense:
        pointer = VALUES if values_pointer is None else values_pointer
        reader.put(modifier + quality.MODIFIER_VALUES_POINTER_OFFSET, _qword(pointer))
        reader.put(modifier + quality.MODIFIER_SPARSE_COUNT_OFFSET, _i32(0))
        if pointer == VALUES:
            # IDs 133 and 159 are sentinels; this leaf must use 34 only.
            reader.put(VALUES + memory.MODIFIER_ID * 8 + 4, _i32(modifier_raw))
            reader.put(VALUES + 133 * 8 + 4, _i32(-88888))
            reader.put(VALUES + 159 * 8 + 4, _i32(99000))
    else:
        pointer = (VALUES if entries else 0) if values_pointer is None else values_pointer
        reader.put(modifier + quality.MODIFIER_VALUES_POINTER_OFFSET, _qword(pointer))
        reader.put(modifier + quality.MODIFIER_SPARSE_COUNT_OFFSET, _i32(len(entries)))
        if pointer == VALUES:
            for index, (modifier_id, value) in enumerate(entries):
                reader.put(VALUES + index * 8, _i32(modifier_id) + _i32(value))


def _environment(**kwargs):
    reader, binding, _ = scale_fixture.environment()
    _install(reader, **kwargs)
    return reader, binding


def _read(reader, binding, fields=memory.FIELDS):
    before = deepcopy(reader.bytes)
    result = memory.read_fields(reader, BASE, binding, fields)
    assert reader.bytes == before, "the cache reader must not write its input memory"
    return result


def test_dense_id_34_returns_unrounded_signed_fixed_point_value():
    reader, binding = _environment(modifier_raw=2500)
    field = _read(reader, binding)[memory.FIELD]

    assert memory.MODIFIER_ID == 34
    assert field["status"] == "known"
    assert field["value"] == field["raw"] == 2500
    assert field["raw_hex"] == _i32(2500).hex()
    assert field["unit"] == memory.UNIT == "diplomats"
    assert field["scale"] == memory.SCALE == 1000
    assert field["period"] == "current"
    assert field["partial"] is True and field["complete"] is False
    assert field["basis"] == memory.BASIS
    assert field["value_origin"] == memory.VALUE_ORIGIN
    component = field["raw_inputs"]["modifier_component"]
    assert component["status"] == "known"
    assert component["raw_inputs"]["modifier_id"] == 34
    assert component["raw_inputs"]["mode"] == "dense"
    assert component["value"] == 2500
    assert field["raw_inputs"]["budget"]["calls"] == len(field["raw_inputs"]["reads"])

    reader, binding = _environment(modifier_raw=-1750)
    field = _read(reader, binding)[memory.FIELD]
    assert field["status"] == "known"
    assert field["value"] == field["raw"] == -1750
    assert field["raw_hex"] == _i32(-1750).hex()


def test_zero_and_empty_sparse_vector_are_known_zero():
    reader, binding = _environment(modifier_raw=0)
    field = _read(reader, binding)[memory.FIELD]
    assert field["status"] == "known"
    assert field["value"] == field["raw"] == 0
    assert field["raw_hex"] == "00000000"

    reader, binding = _environment(dense=False, sparse_entries=[])
    field = _read(reader, binding)[memory.FIELD]
    assert field["status"] == "known"
    assert field["value"] == field["raw"] == 0
    component = field["raw_inputs"]["modifier_component"]
    assert component["raw_inputs"]["mode"] == "sparse"
    assert component["raw_inputs"]["first_match_index"] is None


def test_sparse_returns_first_id_34_match_not_133_or_159():
    reader, binding = _environment(
        dense=False,
        sparse_entries=[(133, -88888), (34, 2500), (34, -9000), (159, 99000)],
    )
    field = _read(reader, binding)[memory.FIELD]
    assert field["status"] == "known"
    assert field["value"] == field["raw"] == 2500
    component = field["raw_inputs"]["modifier_component"]
    inputs = component["raw_inputs"]
    assert inputs["modifier_id"] == 34
    assert inputs["mode"] == "sparse"
    assert inputs["first_match_index"] == 1
    assert [entry["id"] for entry in inputs["entries_examined"]] == [133, 34]


def test_calculating_cache_and_nonnull_processor_are_unknown_not_zero():
    reader, binding = _environment(cache_state=1)
    field = _read(reader, binding)[memory.FIELD]
    assert field["status"] == "unknown"
    assert field["reason"] == "MILITARY_CACHE_CALCULATING"
    assert not any("processor_manager" in label or ".processor_pointer" in label
                   for _, _, label in reader.calls)

    reader, binding = _environment(processor=0x72000000)
    field = _read(reader, binding)[memory.FIELD]
    assert field["status"] == "unknown"
    assert field["reason"] == "MODIFIER_PROCESSOR_PRESENT"
    assert "value" not in field
    assert field["raw_inputs"]["modifier_component"]["reason"] == (
        "MODIFIER_PROCESSOR_PRESENT")


def test_fixed_fra_binding_rejects_other_country_and_changed_database_reference():
    reader, binding = _environment()
    wrong_scope = deepcopy(binding)
    wrong_scope["tag"] = "ENG"
    wrong_fullref = scale_fixture.fullref(122, "ENG")
    wrong_scope["fullref"] = hex(wrong_fullref)
    wrong_scope["fullref_raw_hex"] = _qword(wrong_fullref).hex()
    field = _read(reader, wrong_scope)[memory.FIELD]
    assert field["status"] == "unknown"
    assert field["reason"] == "TARGET_COUNTRY_SCOPE"
    assert reader.calls == []

    reader, binding = _environment()
    reader.put(TARGET_PTR + 0x20,
               _qword(scale_fixture.fullref(122, "FRA", generation=2)))
    field = _read(reader, binding)[memory.FIELD]
    assert field["status"] == "unknown"
    assert not any(label == "diplomats_total.cache_state_i32"
                   for _, _, label in reader.calls)


def test_bad_values_pointer_and_modifier_read_failure_are_unknown_not_zero():
    reader, binding = _environment(values_pointer=0x10)
    field = _read(reader, binding)[memory.FIELD]
    assert field["status"] == "unknown"
    assert "value" not in field
    component = field["raw_inputs"]["modifier_component"]
    assert component["status"] == "unknown"
    assert "POINTER" in component["reason"]

    reader, binding = _environment(modifier_raw=0)
    reader.error_labels.add("quality.diplomats_total.dense_value_i32")
    field = _read(reader, binding)[memory.FIELD]
    assert field["status"] == "unknown"
    assert "value" not in field
    assert field["raw_inputs"]["modifier_component"]["status"] == "unknown"


def test_read_budget_failure_cannot_produce_known_value(monkeypatch):
    reader, binding = _environment(modifier_raw=0)
    monkeypatch.setattr(quality, "MAX_TOTAL_READ_BYTES", 1)
    field = _read(reader, binding)[memory.FIELD]
    assert field["status"] == "unknown"
    assert field["reason"] == "DIPLOMATS_TOTAL_READ_BUDGET_EXCEEDED"
    assert "value" not in field
    assert len(reader.calls) < 10
    assert field["raw_inputs"]["budget"]["bytes_requested"] <= 1

