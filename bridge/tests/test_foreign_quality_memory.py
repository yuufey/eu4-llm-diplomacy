"""Offline tests for the foreign military-quality component reader."""
from __future__ import annotations

from copy import deepcopy
import json
import math
import sys
import types

import pytest

from bridge.information import foreign_quality_memory as memory
from bridge.information import foreign_quality_visibility_memory as visibility
from bridge.information import country_ledger_membership_memory as ledger_membership
from bridge.information import military_effective_memory as discipline


BASE = 0x140000000
DB = 0x6000000000
TABLE = 0x6100000000
WORLD = 0x6200000000
OPTIONS = 0x6300000000
COUNTRIES = 0x6400000000
CAPITAL = 0x6500000000
MODIFIER_MANAGER = 0x6600000000
VALUES_DENSE = 0x6700000000
VALUES_SPARSE = 0x6800000000
COUNTRY_CANDIDATES = 0x6900000000
OBSERVER_SLOT = 189
TARGET_SLOT = 300


def _fullref(tag: str, slot: int, generation: int = 0x1234) -> int:
    return ((generation & 0xFFFF) << 48) | (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


class MemoryImage:
    def __init__(self) -> None:
        self.data: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.error_at: set[int] = set()
        self.short_at: set[int] = set()

    def put(self, address: int, raw: bytes) -> None:
        self.data.update({address + index: byte for index, byte in enumerate(raw)})

    def put_u8(self, address: int, value: int) -> None:
        self.put(address, bytes([value & 0xFF]))

    def put_u32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=False))

    def put_i32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=True))

    def put_u64(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(8, "little", signed=False))

    def put_i64(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(8, "little", signed=True))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if address in self.error_at:
            raise OSError("synthetic RPM failure")
        try:
            raw = bytes(self.data[address + index] for index in range(size))
        except KeyError as exc:
            raise OSError("unmapped fake memory") from exc
        return raw[:-1] if address in self.short_at else raw


def _binding(tag: str, slot: int, pointer: int, generation: int) -> dict:
    fullref = _fullref(tag, slot, generation)
    return {
        "tag": tag,
        "slot": slot,
        "country_pointer": hex(pointer),
        "country_fullref_address": hex(pointer + 0x20),
        "fullref": hex(fullref),
        "fullref_raw_hex": fullref.to_bytes(8, "little").hex(),
        "table_entry_address": hex(TABLE + slot * 8),
        "table_entry_raw_hex": pointer.to_bytes(8, "little").hex(),
    }


def _environment(*, permission_option: int = 0, cache_state: int = 1) -> tuple[MemoryImage, dict, dict, dict]:
    image = MemoryImage()
    observer_ptr = COUNTRIES + OBSERVER_SLOT * 0x1000
    target_ptr = COUNTRIES + TARGET_SLOT * 0x1000
    observer = _binding("FRA", OBSERVER_SLOT, observer_ptr, 0x1234)
    target = _binding("ENG", TARGET_SLOT, target_ptr, 0x2345)

    image.put_u64(BASE + visibility.DATABASE_GLOBAL_RVA, DB)
    image.put_u64(DB + visibility.DATABASE_TABLE_OFFSET, TABLE)
    image.put_i32(DB + visibility.DATABASE_COUNT_OFFSET, TARGET_SLOT + 1)
    image.put_u64(TABLE + OBSERVER_SLOT * 8, observer_ptr)
    image.put_u64(TABLE + TARGET_SLOT * 8, target_ptr)
    image.put_u64(observer_ptr + visibility.COUNTRY_FULLREF_OFFSET,
                  _fullref("FRA", OBSERVER_SLOT, 0x1234))
    image.put_u64(target_ptr + visibility.COUNTRY_FULLREF_OFFSET,
                  _fullref("ENG", TARGET_SLOT, 0x2345))

    image.put_u64(BASE + visibility.WORLD_GLOBAL_RVA, WORLD)
    image.put_u64(WORLD + ledger_membership.WORLD_COUNTRY_POINTERS_OFFSET,
                  COUNTRY_CANDIDATES)
    image.put_i32(WORLD + ledger_membership.WORLD_COUNTRY_COUNT_OFFSET, 2)
    image.put(COUNTRY_CANDIDATES,
              observer_ptr.to_bytes(8, "little") + target_ptr.to_bytes(8, "little"))
    image.put_u64(WORLD + visibility.WORLD_OPTIONS_POINTER_OFFSET, OPTIONS)
    image.put_u32(OPTIONS + visibility.OPTIONS_QUALITY_INDEX * 4, permission_option)
    image.put_u8(BASE + visibility.WORLD_PAGE_ENABLE_RVA, 1)
    image.put_u8(BASE + visibility.WORLD_PAGE_TLS_RVA, 0)
    for index, (_name, rva) in enumerate(visibility.SPECIAL_TARGET_SLOT_RVAS):
        image.put_i32(BASE + rva, -10 - index)
    image.put_u64(target_ptr + visibility.COUNTRY_CAPITAL_OFFSET, CAPITAL)
    image.put_u8(CAPITAL + visibility.CAPITAL_QUALITY_FLAGS_OFFSET, 0)
    image.put_u64(BASE + memory.MODIFIER_PROCESSOR_GLOBAL_RVA, MODIFIER_MANAGER)
    image.put_i32(target_ptr + memory.COUNTRY_CACHE_STATE_OFFSET, cache_state)
    image.put_i32(target_ptr + 0x9874, 1011)
    image.put_i32(target_ptr + 0x987C, 750)
    image.put_i64(target_ptr + 0x50, 123456789)
    image.put_i32(target_ptr + 0xE40, 25125)
    image.put_i32(target_ptr + 0xE44, -501)
    for modifier_id, _group, _unit in memory.MODIFIER_COMPONENTS.values():
        image.put_u64(MODIFIER_MANAGER + modifier_id * 0x60 + 0x40, 0)

    permission = visibility.read_permission(image, BASE, observer, target)
    assert permission["status"] == "known" and permission["admitted"] is (permission_option == 0)
    image.reads.clear()
    return image, observer, target, permission


@pytest.fixture
def discipline_unknown(monkeypatch):
    monkeypatch.setattr(discipline, "read_fields", lambda *_a, **_k: {
        "status": "unknown", "reason": "fixture_discipline_unknown"})


def _run(image: MemoryImage, target: dict, permission: dict, *, model_profile=None) -> dict:
    return memory.read_fields(image, BASE, target, memory.FIELDS,
                              permission=permission, model_profile=model_profile)[memory.FIELD_ID]


def _set_dense(image: MemoryImage, *, values_pointer: int = VALUES_DENSE,
               count: int = 3) -> None:
    target_ptr = COUNTRIES + TARGET_SLOT * 0x1000
    modifier = target_ptr + memory.COUNTRY_MODIFIER_OBJECT_OFFSET
    image.put_u8(modifier + memory.MODIFIER_DENSE_FLAG_OFFSET, 1)
    image.put_u64(modifier + memory.MODIFIER_VALUES_POINTER_OFFSET, values_pointer)
    image.put_u32(modifier + memory.MODIFIER_SPARSE_COUNT_OFFSET, count)
    for name, (modifier_id, _group, _unit) in memory.MODIFIER_COMPONENTS.items():
        image.put_i32(values_pointer + modifier_id * 8 + 4,
                      {"army.siege_ability": 225, "army.defensiveness": -70,
                       "navy.ship_durability": 1000}[name])


def _set_sparse(image: MemoryImage, entries: list[tuple[int, int]]) -> None:
    target_ptr = COUNTRIES + TARGET_SLOT * 0x1000
    modifier = target_ptr + memory.COUNTRY_MODIFIER_OBJECT_OFFSET
    image.put_u8(modifier + memory.MODIFIER_DENSE_FLAG_OFFSET, 0)
    image.put_u64(modifier + memory.MODIFIER_VALUES_POINTER_OFFSET, VALUES_SPARSE)
    image.put_u32(modifier + memory.MODIFIER_SPARSE_COUNT_OFFSET, len(entries))
    for index, (entry_id, value) in enumerate(entries):
        image.put_i32(VALUES_SPARSE + index * 8, entry_id)
        image.put_i32(VALUES_SPARSE + index * 8 + 4, value)


def test_permission_denial_or_mismatch_causes_zero_quality_reads(discipline_unknown):
    image, _observer, target, denied = _environment(permission_option=1)
    result = _run(image, target, denied)
    assert result["status"] == "unknown"
    assert result["reason"] == "QUALITY_PERMISSION_NOT_ADMITTED"
    assert image.reads == []
    assert all(component["status"] == "unknown"
               for component in result["raw_inputs"]["components"].values())

    image, _observer, target, permission = _environment()
    changed = deepcopy(target)
    changed_ref = _fullref("ENG", TARGET_SLOT, 0x9876)
    changed["fullref"] = hex(changed_ref)
    changed["fullref_raw_hex"] = changed_ref.to_bytes(8, "little").hex()
    result = _run(image, changed, permission)
    assert result["status"] == "unknown"
    assert result["reason"] == "QUALITY_PERMISSION_NOT_ADMITTED"
    assert image.reads == []


def test_target_live_fullref_change_withdraws_every_component_before_cache_reads(discipline_unknown):
    image, _observer, target, permission = _environment()
    image.put_u64(int(target["country_pointer"], 0) + 0x20,
                  _fullref("ENG", TARGET_SLOT, 0x9999))
    result = _run(image, target, permission)
    assert result["status"] == "unknown"
    assert result["reason"] == "TARGET_BINDING_REVALIDATION_FAILED"
    assert not any(label.startswith("quality.") for _, _, label in image.reads)
    assert all(component["status"] == "unknown"
               for component in result["raw_inputs"]["components"].values())


def test_direct_cache_values_preserve_i32_scale_i64_precision_and_tradition_row_encoding(discipline_unknown):
    image, _observer, target, permission = _environment()
    target_ptr = int(target["country_pointer"], 0)
    professionalism = (1 << 53) + 17
    image.put_i32(target_ptr + 0x9874, -1250)
    image.put_i32(target_ptr + 0x987C, 0)
    image.put_i64(target_ptr + 0x50, professionalism)
    image.put_i32(target_ptr + 0xE40, -150501)
    image.put_i32(target_ptr + 0xE44, 25500)

    result = _run(image, target, permission)
    assert result["status"] == "known" and result["partial"] is True
    assert result["complete"] is False
    value = result["value"]
    assert value["army"]["morale"]["value"] == -1250
    assert value["army"]["morale"]["raw"] == -1250
    assert value["army"]["morale"]["unit"] == "morale"
    assert value["army"]["morale"]["scale"] == 1000
    assert value["navy"]["morale"]["status"] == "known"
    assert value["navy"]["morale"]["value"] == 0
    prof = value["army"]["professionalism"]
    assert prof["raw"] == str(professionalism)
    assert type(prof["value"]) is float and math.isfinite(prof["value"])
    assert prof["value"] == professionalism / 32768.0
    assert prof["unit"] == "ratio" and prof["scale"] == 32768
    tradition = value["army"]["tradition"]
    assert tradition["value"] == -150501 and tradition["unit"] == "tradition_points"
    assert tradition["raw_inputs"]["native_row_encoding"]["raw"] == -1505
    assert tradition["raw_inputs"]["native_row_encoding"]["scale"] == 1000
    assert all(value["navy"][name]["status"] == "unknown"
               for name in ("heavy_ship_model", "light_ship_model", "galley_model"))
    assert all(size <= memory.MAX_SINGLE_READ_BYTES for _addr, size, _label in image.reads)
    assert result["raw_inputs"]["budget"]["bytes_requested"] == sum(
        size for _addr, size, _label in image.reads)
    json.dumps(result)


def test_dense_modifier_values_use_id_times_eight_plus_four_and_null_processors(discipline_unknown):
    image, _observer, target, permission = _environment(cache_state=0)
    _set_dense(image)
    result = _run(image, target, permission)
    assert result["status"] == "known"
    for name, expected in (("siege_ability", 225), ("defensiveness", -70)):
        component = result["value"]["army"][name]
        assert component["status"] == "known"
        assert component["value"] == expected and component["raw"] == expected
        assert component["unit"] == "ratio_modifier" and component["scale"] == 1000
        assert component["raw_inputs"]["modifier_object_storage"] == "inline"
        assert component["raw_inputs"]["processor_pointer"] == "0x0"
    navy = result["value"]["navy"]["ship_durability"]
    assert navy["value"] == 1000
    siege_address = VALUES_DENSE + 182 * 8 + 4
    assert any(address == siege_address and label == "quality.army.siege_ability.dense_value_i32"
               for address, _size, label in image.reads)


def test_sparse_modifier_uses_first_match_and_absent_id_is_known_zero(discipline_unknown):
    image, _observer, target, permission = _environment(cache_state=0)
    entries = [(182, 17), (182, 900), (127, -31), (999, 4)]
    _set_sparse(image, entries)
    result = _run(image, target, permission)
    army = result["value"]["army"]
    navy = result["value"]["navy"]["ship_durability"]
    assert army["siege_ability"]["value"] == 17
    assert army["siege_ability"]["raw_inputs"]["first_match_index"] == 0
    assert army["defensiveness"]["value"] == -31
    assert army["defensiveness"]["raw_inputs"]["first_match_index"] == 2
    assert navy["status"] == "known" and navy["value"] == 0
    assert navy["raw_inputs"]["first_match_index"] is None
    assert len([label for _a, _s, label in image.reads
                if label.startswith("quality.navy.ship_durability.sparse_entries")]) == 1


def test_sparse_empty_list_is_known_zero_even_with_null_values_pointer(discipline_unknown):
    image, _observer, target, permission = _environment(cache_state=0)
    modifier = int(target["country_pointer"], 0) + memory.COUNTRY_MODIFIER_OBJECT_OFFSET
    image.put_u8(modifier + memory.MODIFIER_DENSE_FLAG_OFFSET, 0)
    image.put_u64(modifier + memory.MODIFIER_VALUES_POINTER_OFFSET, 0)
    image.put_u32(modifier + memory.MODIFIER_SPARSE_COUNT_OFFSET, 0)
    result = _run(image, target, permission)
    assert result["value"]["army"]["siege_ability"]["value"] == 0
    assert result["value"]["navy"]["ship_durability"]["value"] == 0


def test_nonnull_processor_keeps_only_its_modifier_unknown_and_never_uses_cache(discipline_unknown):
    image, _observer, target, permission = _environment(cache_state=0)
    _set_dense(image)
    manager_cell = MODIFIER_MANAGER + 182 * 0x60 + 0x40
    image.put_u64(manager_cell, 0x6900000000)
    result = _run(image, target, permission)
    siege = result["value"]["army"]["siege_ability"]
    assert siege["status"] == "unknown"
    assert siege["reason"] == "MODIFIER_PROCESSOR_PRESENT"
    assert "value" not in siege and "raw" not in siege
    assert "quality.army.siege_ability.dense_value_i32" not in [label for _, _, label in image.reads]
    assert result["value"]["army"]["defensiveness"]["status"] == "known"
    assert result["value"]["navy"]["ship_durability"]["status"] == "known"


def test_cache_state_one_withdraws_modifiers_without_reading_processor_or_cache_values(discipline_unknown):
    image, _observer, target, permission = _environment(cache_state=1)
    _set_dense(image)
    result = _run(image, target, permission)
    assert result["status"] == "known"  # Direct cache fields remain available.
    assert result["value"]["army"]["morale"]["status"] == "known"
    for name in ("siege_ability", "defensiveness"):
        component = result["value"]["army"][name]
        assert component["status"] == "unknown"
        assert component["reason"] == "MILITARY_CACHE_CALCULATING"
    labels = [label for _, _, label in image.reads]
    assert not any(label.endswith("processor_pointer") for label in labels)
    assert not any(label.endswith("dense_value_i32") for label in labels)


def test_cache_state_nonone_is_not_conflated_with_calculating_state(discipline_unknown):
    image, _observer, target, permission = _environment(cache_state=2)
    _set_dense(image)
    result = _run(image, target, permission)
    assert result["value"]["army"]["siege_ability"]["status"] == "known"


def test_discipline_numeric_component_is_extracted_without_inheriting_helper_scope(monkeypatch):
    image, _observer, target, permission = _environment(cache_state=1)
    target_pointer = int(target["country_pointer"], 0)

    def fake_read_fields(reader, base, country_pointer, profile=None):
        assert base == BASE and country_pointer == target_pointer
        return {
            "status": "observed", "country": "FRA",
            "country_pointer": hex(country_pointer),
            "fields": {"discipline": {"status": "known", "value": 1044,
                                       "raw": 1044, "unit": "ratio", "scale": 1000,
                                       "basis": "native_country_discipline_calculation",
                                       "complete": False}},
        }

    monkeypatch.setattr(discipline, "read_fields", fake_read_fields)
    result = _run(image, target, permission)
    item = result["value"]["army"]["discipline"]
    assert item["status"] == "known" and item["value"] == 1044
    assert "country" not in item
    assert item["raw_inputs"]["helper_scope_is_not_target_proof"] is True
    assert item["raw_inputs"]["helper_record"]["country"] == "FRA"
    assert result["raw_inputs"]["target_binding"]["tag"] == "ENG"


@pytest.mark.parametrize("failure", ["short", "error"])
def test_one_direct_cache_read_failure_is_field_local_and_has_no_public_raw_value(
        discipline_unknown, failure: str):
    image, _observer, target, permission = _environment()
    address = int(target["country_pointer"], 0) + 0x9874
    (image.short_at if failure == "short" else image.error_at).add(address)
    result = _run(image, target, permission)
    component = result["value"]["army"]["morale"]
    assert component["status"] == "unknown"
    assert "value" not in component and "raw" not in component
    assert result["value"]["army"]["professionalism"]["status"] == "known"
    assert result["status"] == "known"
    assert component["raw_inputs"]["reads"][-1]["status"] == "failed"


def test_invalid_sparse_count_is_local_unknown_without_affecting_direct_fields(discipline_unknown):
    image, _observer, target, permission = _environment(cache_state=0)
    modifier = int(target["country_pointer"], 0) + memory.COUNTRY_MODIFIER_OBJECT_OFFSET
    image.put_u8(modifier + memory.MODIFIER_DENSE_FLAG_OFFSET, 0)
    image.put_u64(modifier + memory.MODIFIER_VALUES_POINTER_OFFSET, VALUES_SPARSE)
    image.put_u32(modifier + memory.MODIFIER_SPARSE_COUNT_OFFSET, memory.MAX_SPARSE_ENTRIES + 1)
    result = _run(image, target, permission)
    assert result["status"] == "known"
    assert result["value"]["army"]["morale"]["status"] == "known"
    assert result["value"]["army"]["siege_ability"]["status"] == "unknown"
    assert result["value"]["army"]["siege_ability"]["reason"] == "MODIFIER_COUNT_OUT_OF_RANGE"


def test_total_budget_failure_withdraws_all_components(discipline_unknown, monkeypatch):
    image, _observer, target, permission = _environment()
    monkeypatch.setattr(memory, "MAX_READ_CALLS", 3)
    result = _run(image, target, permission)
    assert result["status"] == "unknown"
    assert result["reason"] == "SHARED_READ_BUDGET_EXCEEDED"
    assert all(item["status"] == "unknown"
               for item in result["raw_inputs"]["components"].values())
    assert not any(label.startswith("quality.army.morale.cache") for _, _, label in image.reads)


def test_model_components_stay_unknown_without_a_pinned_getter_contract(discipline_unknown):
    image, _observer, target, permission = _environment()
    result = _run(image, target, permission, model_profile=None)
    for name in ("heavy_ship_model", "light_ship_model", "galley_model"):
        component = result["value"]["navy"][name]
        assert component["status"] == "unknown"
        assert component["reason"] == "MODEL_GETTER_CONTRACT_PENDING"
        assert "value" not in component and "raw" not in component


def test_model_reader_is_lazily_used_only_when_model_profile_is_supplied(
        discipline_unknown, monkeypatch):
    calls = []
    helper = types.ModuleType("bridge.information.foreign_quality_models_memory")

    def read_models(reader, base, target_binding, *, model_profile):
        calls.append((base, target_binding["tag"], model_profile["profile_id"]))
        return {
            name: {"status": "known", "value": {
                "localization_key": f"TEST_{index}",
                "name": {"status": "unknown", "reason": "fixture_name_unknown"}},
                "raw": f"TEST_{index}", "unit": "ship_model", "scale": 1,
                "raw_inputs": {"slot": index}}
            for index, name in enumerate(memory.MODEL_COMPONENTS)
        }

    helper.read_models = read_models
    monkeypatch.setitem(sys.modules, "bridge.information.foreign_quality_models_memory", helper)
    image, _observer, target, permission = _environment()
    result = _run(image, target, permission,
                  model_profile={"profile_id": "pinned-model-profile"})
    assert calls == [(BASE, "ENG", "pinned-model-profile")]
    for index, name in enumerate(memory.MODEL_COMPONENTS):
        model_name = name.removeprefix("navy.")
        component = result["value"]["navy"][model_name]
        assert component["status"] == "known"
        assert component["value"]["localization_key"] == f"TEST_{index}"
        assert component["unit"] == "ship_model" and component["scale"] == 1
        assert component["raw_inputs"]["reads"] == []
        assert "helper_reads" not in component["raw_inputs"]
        trace_ref = component["raw_inputs"]["wholefield_trace_slice"]
        assert trace_ref["start_index"] == trace_ref["end_index"]
        assert trace_ref["read_count"] == 0
        assert trace_ref["end_index"] <= len(result["raw_inputs"]["reads"])


def test_model_components_keep_only_local_reads_and_reference_whole_trace_once(
        discipline_unknown, monkeypatch):
    helper = types.ModuleType("bridge.information.foreign_quality_models_memory")
    image, _observer, target, permission = _environment()
    model_rows = {}

    def read_models(reader, base, target_binding, *, model_profile):
        output = {}
        for index, name in enumerate(memory.MODEL_COMPONENTS):
            address = 0x6910000000 + index * 0x100
            label = f"quality_model.fixture.{index}"
            payload = bytes([0x41 + index, 0x42, 0x43, 0x44])
            image.put(address, payload)
            raw = reader.read(address, len(payload), label)
            local_read = {
                "ordinal": 1, "address": hex(address), "size": len(payload),
                "label": label, "status": "ok", "raw_hex": raw.hex(),
            }
            model_rows[name] = local_read
            output[name] = {
                "status": "known",
                "value": {"localization_key": f"TEST_MODEL_{index}",
                          "name": {"status": "unknown", "reason": "fixture_name_unknown"}},
                "raw": f"TEST_MODEL_{index}", "unit": "ship_model", "scale": 1,
                "raw_inputs": {"component_index": index, "reads": [local_read]},
            }
        return output

    helper.read_models = read_models
    monkeypatch.setitem(sys.modules, "bridge.information.foreign_quality_models_memory", helper)
    result = _run(image, target, permission,
                  model_profile={"profile_id": "pinned-model-profile"})
    field = result["raw_inputs"]
    whole_trace = field["reads"]
    labels = {row["label"] for row in whole_trace}
    assert {row["label"] for row in model_rows.values()} <= labels

    for name in memory.MODEL_COMPONENTS:
        model_name = name.removeprefix("navy.")
        component = result["value"]["navy"][model_name]
        component_reads = component["raw_inputs"]["reads"]
        assert component_reads == [model_rows[name]]
        assert "helper_reads" not in component["raw_inputs"]
        assert "wholefield_trace_slice" not in component["raw_inputs"]
        assert len(component_reads) == 1
        # The full ordered slice remains available once at field scope, while
        # no component contains the other models' reads.
        assert all(row["label"] == model_rows[name]["label"] for row in component_reads)
    json.dumps(result)


def test_unsupported_or_unrequested_fields_do_not_read_quality_values(discipline_unknown):
    image, _observer, target, permission = _environment()
    assert memory.read_fields(image, BASE, target, ("F02.other",),
                              permission=permission) == {}
    assert image.reads == []
    bad = memory.read_fields(image, BASE, target, (memory.FIELD_ID, memory.FIELD_ID),
                             permission=permission)
    assert bad[memory.FIELD_ID]["status"] == "unknown"
    assert image.reads == []

