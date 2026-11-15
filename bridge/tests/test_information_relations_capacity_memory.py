"""Bounded offline tests for the N05 relation-capacity arithmetic leaf."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import foreign_quality_memory as quality
from bridge.information import relations_capacity_memory as memory
from bridge.tests import test_information_country_scale_development_memory as scale_fixture


BASE = scale_fixture.BASE
TARGET_PTR = scale_fixture.TARGET_PTR
MANAGER = 0x70000000
VALUES = 0x71000000


def _qword(value: int) -> bytes:
    return int(value).to_bytes(8, "little", signed=False)


def _i32(value: int) -> bytes:
    return int(value).to_bytes(4, "little", signed=True)


def _install(reader, *, base_cache: int = 10, free_slots: int = 3,
             modifier_raw: int = 1500, cache_state: int = 0,
             dense: bool = True, sparse_entries: list[tuple[int, int]] | None = None,
             processor: int = 0):
    reader.put(TARGET_PTR + memory.BASE_CACHE_OFFSET, _i32(base_cache))
    reader.put(TARGET_PTR + memory.FREE_SLOTS_OFFSET, _i32(free_slots))
    reader.put(TARGET_PTR + quality.COUNTRY_CACHE_STATE_OFFSET, _i32(cache_state))
    reader.put(BASE + quality.MODIFIER_PROCESSOR_GLOBAL_RVA, _qword(MANAGER))
    processor_cell = (MANAGER + memory.MODIFIER_ID * quality.MODIFIER_PROCESSOR_STRIDE
                      + quality.MODIFIER_PROCESSOR_OFFSET)
    reader.put(processor_cell, _qword(processor))

    modifier = TARGET_PTR + quality.COUNTRY_MODIFIER_OBJECT_OFFSET
    reader.put(modifier + quality.MODIFIER_DENSE_FLAG_OFFSET, bytes([1 if dense else 0]))
    entries = list(sparse_entries or [])
    if dense:
        reader.put(modifier + quality.MODIFIER_VALUES_POINTER_OFFSET, _qword(VALUES))
        reader.put(modifier + quality.MODIFIER_SPARSE_COUNT_OFFSET, _i32(0))
        reader.put(VALUES + memory.MODIFIER_ID * 8 + 4, _i32(modifier_raw))
    else:
        values_pointer = VALUES if entries else 0
        reader.put(modifier + quality.MODIFIER_VALUES_POINTER_OFFSET, _qword(values_pointer))
        reader.put(modifier + quality.MODIFIER_SPARSE_COUNT_OFFSET, _i32(len(entries)))
        for index, (modifier_id, value) in enumerate(entries):
            row = _i32(modifier_id) + _i32(value)
            reader.put(VALUES + index * 8, row)


def _environment(**kwargs):
    reader, binding, _ = scale_fixture.environment()
    _install(reader, **kwargs)
    return reader, binding


def _read(reader, binding, fields=memory.FIELDS):
    return memory.read_fields(reader, BASE, binding, fields)


def test_dense_signed_arithmetic_and_raw_contract():
    # The native UI helper exposes the modifier-derived upkeep allowance as
    # limit; the base/free caches only contribute to the current count.
    reader, binding = _environment(base_cache=3, free_slots=1, modifier_raw=5000)
    result = _read(reader, binding)

    limit = result[memory.FIELD_LIMIT]
    count = result[memory.FIELD_COUNT]
    assert limit["status"] == count["status"] == "known"
    assert limit["value"] == limit["raw"] == 5
    assert count["value"] == count["raw"] == 7
    for field in (limit, count):
        assert field["raw_hex"] == field["raw"].to_bytes(4, "little", signed=True).hex()
        assert field["unit"] == "diplomatic_relation" and field["scale"] == 1
        assert field["period"] == "current"
        assert field["partial"] is True and field["complete"] is False
        assert field["basis"] == memory.BASIS
        assert field["value_origin"] == memory.VALUE_ORIGIN
        raw = field["raw_inputs"]
        assert raw["base_cache"]["raw_hex"] == (3).to_bytes(4, "little", signed=True).hex()
        assert raw["free_slots_cache"]["raw_hex"] == (1).to_bytes(4, "little", signed=True).hex()
        component = raw["modifier_component"]
        assert component["status"] == "known"
        assert component["raw_inputs"]["modifier_id"] == 159
        assert component["raw_inputs"]["mode"] == "dense"
        assert raw["reads"] and raw["budget"]["calls"] == len(raw["reads"])


def test_negative_modifier_uses_truncation_toward_zero_and_signed_wrap():
    reader, binding = _environment(base_cache=-3, free_slots=4, modifier_raw=-1500)
    result = _read(reader, binding)
    assert result[memory.FIELD_LIMIT]["value"] == -1
    assert result[memory.FIELD_COUNT]["value"] == -8
    assert result[memory.FIELD_LIMIT]["raw_hex"] == "ffffffff"
    assert result[memory.FIELD_COUNT]["raw_hex"] == "f8ffffff"


def test_count_wraps_after_base_free_subtraction():
    reader, binding = _environment(base_cache=2_147_483_647,
                                    free_slots=-1, modifier_raw=1000)
    result = _read(reader, binding)
    assert result[memory.FIELD_LIMIT]["value"] == 1
    assert result[memory.FIELD_COUNT]["value"] == -2_147_483_647


def test_sparse_first_match_and_empty_sparse_are_known_without_relation_enumeration():
    reader, binding = _environment(
        base_cache=8, free_slots=2, dense=False,
        sparse_entries=[(7, 111), (159, -2500), (159, 9999)])
    result = _read(reader, binding)
    assert result[memory.FIELD_LIMIT]["value"] == -2
    assert result[memory.FIELD_COUNT]["value"] == 4
    component = result[memory.FIELD_COUNT]["raw_inputs"]["modifier_component"]
    assert component["raw_inputs"]["mode"] == "sparse"
    assert component["raw_inputs"]["first_match_index"] == 1
    assert [row["id"] for row in component["raw_inputs"]["entries_examined"]] == [7, 159]
    assert not any("relation_record" in row["label"] for row in result[memory.FIELD_COUNT]
                   .get("raw_inputs", {}).get("reads", []))

    reader, binding = _environment(base_cache=8, free_slots=2, dense=False,
                                    sparse_entries=[])
    result = _read(reader, binding)
    assert result[memory.FIELD_LIMIT]["value"] == 0
    assert result[memory.FIELD_COUNT]["value"] == 6
    component = result[memory.FIELD_COUNT]["raw_inputs"]["modifier_component"]
    assert component["raw_inputs"]["mode"] == "sparse"
    assert component["raw_inputs"]["first_match_index"] is None
    assert component["value"] == component["raw"] == 0


def test_nonnull_processor_is_unknown_and_does_not_fake_zero():
    reader, binding = _environment(processor=0x72000000)
    result = _read(reader, binding)
    for field in memory.FIELDS:
        assert result[field]["status"] == "unknown"
        assert result[field]["reason"] == "MODIFIER_PROCESSOR_PRESENT"
    assert result[memory.FIELD_COUNT]["raw_inputs"]["modifier_component"]["reason"] == (
        "MODIFIER_PROCESSOR_PRESENT")


def test_calculating_cache_is_unknown_and_skips_processor_manager_read():
    reader, binding = _environment(cache_state=1)
    result = _read(reader, binding)
    for field in memory.FIELDS:
        assert result[field]["status"] == "unknown"
        assert result[field]["reason"] == "MILITARY_CACHE_CALCULATING"
    assert not any("processor_manager" in label for _, _, label in reader.calls)


def test_fixed_fra_binding_and_canonical_database_mismatch_fail_before_cache_reads():
    reader, binding = _environment()
    wrong_scope = deepcopy(binding)
    wrong_scope["tag"] = "ENG"
    result = _read(reader, wrong_scope)
    assert all(result[field]["status"] == "unknown" for field in memory.FIELDS)
    assert reader.calls == []

    reader, binding = _environment()
    reader.put(TARGET_PTR + 0x20,
               _qword(scale_fixture.fullref(122, "FRA", generation=2)))
    result = _read(reader, binding)
    assert all(result[field]["status"] == "unknown" for field in memory.FIELDS)
    assert not any(label.startswith("relations_capacity.base_cache")
                   for _, _, label in reader.calls)


def test_base_cache_failure_keeps_limit_known_but_count_unknown():
    reader, binding = _environment()
    reader.error_labels.add("relations_capacity.base_cache_i32")
    result = _read(reader, binding)
    assert result[memory.FIELD_LIMIT]["status"] == "known"
    assert result[memory.FIELD_LIMIT]["value"] == 1
    assert result[memory.FIELD_COUNT]["status"] == "unknown"
    assert result[memory.FIELD_COUNT]["reason"] == "RELATIONS_BASE_CACHE_READ_FAILED"
    assert "READ_FAILED:relations_capacity.base_cache_i32" in (
        result[memory.FIELD_COUNT]["raw_inputs"]["base_cache"]["error"])
    assert result[memory.FIELD_COUNT]["raw_inputs"]["free_slots_cache"]["raw_hex"]


def test_free_cache_failure_keeps_modifier_limit_known_but_count_unknown():
    reader, binding = _environment()
    reader.error_labels.add("relations_capacity.free_slots_i32")
    result = _read(reader, binding)
    assert result[memory.FIELD_LIMIT]["status"] == "known"
    assert result[memory.FIELD_LIMIT]["value"] == 1
    assert result[memory.FIELD_COUNT]["status"] == "unknown"
    assert result[memory.FIELD_COUNT]["reason"] == "RELATIONS_FREE_SLOTS_READ_FAILED"
    assert "READ_FAILED:relations_capacity.free_slots_i32" in (
        result[memory.FIELD_COUNT]["raw_inputs"]["free_slots_cache"]["error"])


def test_unsupported_and_empty_requests_do_not_read_memory():
    reader, binding = _environment()
    result = _read(reader, binding, ("N05.relation_records",))
    assert result["N05.relation_records"] == {
        "status": "unknown", "reason": "unsupported_field"}
    assert reader.calls == []
    assert _read(reader, binding, []) == {}
    assert reader.calls == []


def test_leaf_budget_failure_is_unknown_without_unbounded_reads(monkeypatch):
    reader, binding = _environment()
    monkeypatch.setattr(quality, "MAX_TOTAL_READ_BYTES", 1)
    result = _read(reader, binding)
    assert all(result[field]["status"] == "unknown" for field in memory.FIELDS)
    assert reader.calls == []
    assert len(reader.calls) < 10

