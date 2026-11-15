"""Boundary tests for province trade-power modifier input projection."""
from __future__ import annotations

import struct

import pytest

from bridge.information import foreign_quality_memory
from bridge.information import modifier_storage
from bridge.information import province_identity_memory as identity
from bridge.information import province_trade_power_inputs_memory as memory


BASE = 0x140000000
MANAGER = 0x300000000
RECORD = 0x200000000
PROVINCE_ID = 183


class FakeMemory:
    def __init__(self) -> None:
        self.bytes: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.fail_labels: set[str] = set()
        self.short_labels: set[str] = set()
        self.mutate_after: dict[str, tuple[int, bytes]] = {}

    def write(self, address: int, value: bytes) -> None:
        for offset, byte in enumerate(value):
            self.bytes[address + offset] = byte

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if label in self.fail_labels:
            raise OSError(f"fixture_read_failure:{label}")
        try:
            result = bytes(self.bytes[address + offset] for offset in range(size))
        except KeyError as exc:
            raise OSError(f"fixture_unmapped:{label}") from exc
        mutation = self.mutate_after.pop(label, None)
        if mutation is not None:
            self.write(*mutation)
        if label in self.short_labels:
            return result[:-1]
        return result


def province_binding(
    province_id: int = PROVINCE_ID,
    record: int = RECORD,
) -> dict[str, object]:
    return {
        "province_id": province_id,
        "record_id": province_id,
        "record_pointer": hex(record),
        "id_address": hex(record + identity.PROVINCE_ID_OFFSET),
        "id_raw_hex": struct.pack("<i", province_id).hex()
        if type(province_id) is int and -(1 << 31) <= province_id < (1 << 31)
        else "00000000",
    }


def setup_memory(
    *,
    indexes: tuple[int, ...] = (15, 16),
    manager: int = MANAGER,
    processor_by_index: dict[int, int] | None = None,
    key_by_index: dict[int, str] | None = None,
    pointer_by_index: dict[int, int] | None = None,
) -> tuple[FakeMemory, dict[str, object]]:
    result = FakeMemory()
    result.write(BASE + memory.MODIFIER_PROCESSOR_GLOBAL_RVA,
                 manager.to_bytes(8, "little", signed=False))
    processor_by_index = processor_by_index or {}
    key_by_index = key_by_index or {}
    pointer_by_index = pointer_by_index or {}
    for index in indexes:
        expected_key = memory._DESCRIPTORS[index]["key"]
        key = key_by_index.get(index, expected_key)
        key_pointer = pointer_by_index.get(index, 0x350000000 + index * 0x1000)
        descriptor = bytearray(memory.MODIFIER_DESCRIPTOR_SIZE)
        descriptor[:8] = key_pointer.to_bytes(8, "little", signed=False)
        descriptor[0x10:0x18] = len(key.encode("ascii")).to_bytes(8, "little")
        descriptor[0x18:0x20] = (len(key.encode("ascii")) + 8).to_bytes(8, "little")
        descriptor[0x40:0x48] = processor_by_index.get(index, 0).to_bytes(8, "little")
        descriptor_address = manager + index * memory.MODIFIER_PROCESSOR_STRIDE
        result.write(descriptor_address, bytes(descriptor))
        result.write(key_pointer, key.encode("ascii") + b"\0")
    return result, province_binding()


def install_storage_stub(monkeypatch, values: dict[int, int] | None = None):
    values = values or {}
    calls: list[dict[str, object]] = []

    def read_raw_modifier_object(trace, modifier_object, modifier_id, unit, *, name,
                                 forbidden_pointers=()):
        calls.append({
            "modifier_object": modifier_object,
            "modifier_id": modifier_id,
            "unit": unit,
            "name": name,
            "forbidden_pointers": tuple(forbidden_pointers),
        })
        raw_value = values.get(modifier_object, 0)
        return {
            "status": "known",
            "value": raw_value,
            "raw": raw_value,
            "unit": unit,
            "scale": 1000,
            "raw_inputs": {"mode": "stubbed_storage", "modifier_id": modifier_id},
        }

    monkeypatch.setattr(modifier_storage, "read_raw_modifier_object",
                        read_raw_modifier_object)
    return calls


def read_inputs(reader: FakeMemory, fields: tuple[str, ...], binding=None):
    return memory.read_fields(reader, BASE,
                              province_binding() if binding is None else binding,
                              fields)


@pytest.mark.parametrize("raw_value", [0, 12500, -9200, -(1 << 31)])
def test_signed_numeric_result_is_projected_from_storage_raw(monkeypatch, raw_value: int):
    reader, binding = setup_memory(indexes=(15,))
    object_address = RECORD + 0x998
    calls = install_storage_stub(monkeypatch, {object_address: raw_value})

    field = memory.read_fields(
        reader, BASE, binding, (memory.FIELD_PROVINCE_TRADE_POWER_VALUE,)
    )[memory.FIELD_PROVINCE_TRADE_POWER_VALUE]

    assert field["status"] == "known"
    assert field["value"] == {"raw": raw_value, "scale": 1000, "unit": "trade_power"}
    assert field["basis"] == "native_province_numeric_modifier_processor_absent"
    assert field["period"] == "current"
    assert field["complete"] is False
    assert field["raw_inputs"]["storage_component"]["raw_inputs"]["mode"] == "stubbed_storage"
    assert len(calls) == 1


def test_index16_descriptor_is_deduplicated_and_containers_are_independent(monkeypatch):
    reader, binding = setup_memory(indexes=(16,))
    main = RECORD + 0x998
    further = RECORD + 0x2438
    calls = install_storage_stub(monkeypatch, {main: 7300, further: -2250})

    result = memory.read_fields(
        reader, BASE, binding,
        (memory.FIELD_PROVINCE_TRADE_POWER_MODIFIER,
         memory.FIELD_PROVINCE_TRADE_POWER_FURTHER_MODIFIER),
    )

    assert result[memory.FIELD_PROVINCE_TRADE_POWER_MODIFIER]["value"] == {
        "raw": 7300, "scale": 1000, "unit": "ratio",
    }
    assert result[memory.FIELD_PROVINCE_TRADE_POWER_FURTHER_MODIFIER]["value"] == {
        "raw": -2250, "scale": 1000, "unit": "ratio",
    }
    assert len(calls) == 2
    assert {call["modifier_object"] for call in calls} == {main, further}
    assert {call["modifier_id"] for call in calls} == {16}
    assert {call["unit"] for call in calls} == {"ratio"}
    desc_reads = [entry for entry in reader.reads if entry[2].endswith("descriptor_96")]
    assert desc_reads == [(
        MANAGER + 16 * memory.MODIFIER_PROCESSOR_STRIDE,
        memory.MODIFIER_DESCRIPTOR_SIZE,
        "province_trade_power_inputs.index_16.descriptor_96",
    )]
    for call in calls:
        assert RECORD in call["forbidden_pointers"]
        assert call["modifier_object"] in call["forbidden_pointers"]
        assert MANAGER in call["forbidden_pointers"]
        assert MANAGER + 16 * memory.MODIFIER_PROCESSOR_STRIDE in call["forbidden_pointers"]
        assert (MANAGER + 16 * memory.MODIFIER_PROCESSOR_STRIDE
                + memory.MODIFIER_PROCESSOR_OFFSET) in call["forbidden_pointers"]


def test_index15_and_index16_use_their_own_keys_ids_and_units(monkeypatch):
    reader, binding = setup_memory()
    calls = install_storage_stub(monkeypatch)

    memory.read_fields(
        reader, BASE, binding,
        (memory.FIELD_PROVINCE_TRADE_POWER_VALUE,
         memory.FIELD_PROVINCE_TRADE_POWER_MODIFIER),
    )

    assert {(call["modifier_id"], call["unit"]) for call in calls} == {
        (15, "trade_power"), (16, "ratio"),
    }
    assert len([entry for entry in reader.reads if entry[2].endswith("descriptor_96")]) == 2


def test_non_null_processor_is_unknown_and_never_reads_object_storage(monkeypatch):
    reader, binding = setup_memory(indexes=(16,), processor_by_index={16: 0x360000000})
    calls = install_storage_stub(monkeypatch)

    field = memory.read_fields(
        reader, BASE, binding, (memory.FIELD_PROVINCE_TRADE_POWER_MODIFIER,)
    )[memory.FIELD_PROVINCE_TRADE_POWER_MODIFIER]

    assert field["status"] == "unknown"
    assert field["reason"] == "MODIFIER_PROCESSOR_NON_NULL"
    assert calls == []
    assert not any("modifier_storage" in label for _, _, label in reader.reads)


def test_descriptor_name_mismatch_is_unknown_before_storage(monkeypatch):
    wrong = "province_trade_power_bad_name"
    reader, binding = setup_memory(indexes=(15,), key_by_index={15: wrong})
    calls = install_storage_stub(monkeypatch)

    field = memory.read_fields(
        reader, BASE, binding, (memory.FIELD_PROVINCE_TRADE_POWER_VALUE,)
    )[memory.FIELD_PROVINCE_TRADE_POWER_VALUE]

    assert field["status"] == "unknown"
    assert field["reason"] == "DESCRIPTOR_NAME_MISMATCH"
    assert calls == []


def test_bad_heap_name_pointer_is_unknown_without_storage(monkeypatch):
    reader, binding = setup_memory(indexes=(15,), pointer_by_index={15: 0})
    calls = install_storage_stub(monkeypatch)

    field = memory.read_fields(
        reader, BASE, binding, (memory.FIELD_PROVINCE_TRADE_POWER_VALUE,)
    )[memory.FIELD_PROVINCE_TRADE_POWER_VALUE]

    assert field["status"] == "unknown"
    assert field["reason"] == "DESCRIPTOR_NAME_POINTER_INVALID"
    assert calls == []


def test_manager_pointer_drift_retracts_the_read_value(monkeypatch):
    reader, binding = setup_memory(indexes=(15,))
    reader.mutate_after["province_trade_power_inputs.manager_global"] = (
        BASE + memory.MODIFIER_PROCESSOR_GLOBAL_RVA,
        (MANAGER + 0x1000).to_bytes(8, "little"),
    )
    calls = install_storage_stub(monkeypatch)

    field = memory.read_fields(
        reader, BASE, binding, (memory.FIELD_PROVINCE_TRADE_POWER_VALUE,)
    )[memory.FIELD_PROVINCE_TRADE_POWER_VALUE]

    assert calls
    assert field["status"] == "unknown"
    assert field["reason"] == "MODIFIER_PROCESSOR_MANAGER_CHANGED"


@pytest.mark.parametrize(
    ("mutation_offset", "replacement", "reason"),
    [
        (0, b"\x01", "MODIFIER_DESCRIPTOR_KEY_CHANGED"),
        (memory.MODIFIER_PROCESSOR_OFFSET, b"\x01", "MODIFIER_PROCESSOR_CHANGED"),
    ],
)
def test_descriptor_name_or_processor_drift_retracts_value(
    monkeypatch, mutation_offset: int, replacement: bytes, reason: str,
):
    reader, binding = setup_memory(indexes=(16,))
    descriptor_address = MANAGER + 16 * memory.MODIFIER_PROCESSOR_STRIDE
    changed = bytearray(memory.MODIFIER_DESCRIPTOR_SIZE)
    # Use the seeded original descriptor, then change one byte after its first read.
    original = bytes(reader.bytes[descriptor_address + i]
                     for i in range(memory.MODIFIER_DESCRIPTOR_SIZE))
    changed[:] = original
    changed[mutation_offset:mutation_offset + len(replacement)] = replacement
    reader.mutate_after["province_trade_power_inputs.index_16.descriptor_96"] = (
        descriptor_address, bytes(changed),
    )
    calls = install_storage_stub(monkeypatch)

    field = memory.read_fields(
        reader, BASE, binding, (memory.FIELD_PROVINCE_TRADE_POWER_MODIFIER,)
    )[memory.FIELD_PROVINCE_TRADE_POWER_MODIFIER]

    assert calls
    assert field["status"] == "unknown"
    assert field["reason"] == reason


def test_storage_unknown_is_preserved_as_unknown(monkeypatch):
    reader, binding = setup_memory(indexes=(15,))

    def unavailable(*args, **kwargs):
        return {"status": "unknown", "reason": "MODIFIER_VALUES_POINTER_INVALID",
                "raw_inputs": {"mode": "failed"}}

    monkeypatch.setattr(modifier_storage, "read_raw_modifier_object", unavailable)
    field = memory.read_fields(
        reader, BASE, binding, (memory.FIELD_PROVINCE_TRADE_POWER_VALUE,)
    )[memory.FIELD_PROVINCE_TRADE_POWER_VALUE]

    assert field["status"] == "unknown"
    assert field["reason"] == "MODIFIER_VALUES_POINTER_INVALID"
    assert field["raw_inputs"]["storage_component"]["raw_inputs"]["mode"] == "failed"


def test_invalid_canonical_binding_is_unknown_without_reads(monkeypatch):
    reader, binding = setup_memory(indexes=(15,))
    binding["record_id"] = PROVINCE_ID + 1
    calls = install_storage_stub(monkeypatch)

    field = memory.read_fields(
        reader, BASE, binding, (memory.FIELD_PROVINCE_TRADE_POWER_VALUE,)
    )[memory.FIELD_PROVINCE_TRADE_POWER_VALUE]

    assert field["status"] == "unknown"
    assert field["raw_inputs"]["validation_errors"]
    assert reader.reads == []
    assert calls == []


def test_unsupported_and_duplicate_fields_do_not_read_memory(monkeypatch):
    reader, binding = setup_memory()
    calls = install_storage_stub(monkeypatch)

    unsupported = read_inputs(reader, ("G02.not_supported",), binding)
    assert unsupported["G02.not_supported"]["status"] == "unknown"
    assert reader.reads == []
    duplicate = read_inputs(
        reader,
        (memory.FIELD_PROVINCE_TRADE_POWER_VALUE,
         memory.FIELD_PROVINCE_TRADE_POWER_VALUE),
        binding,
    )
    assert duplicate[memory.FIELD_PROVINCE_TRADE_POWER_VALUE]["reason"] == \
        "duplicate_field_requested"
    assert reader.reads == []
    assert calls == []


def test_old_trade_power_field_delegates_unchanged(monkeypatch):
    reader, binding = setup_memory(indexes=())
    sentinel = {"status": "known", "value": {"raw": 10, "scale": 1000,
                                                "unit": "trade_power"}}
    calls: list[tuple[object, ...]] = []

    def delegated(*args):
        calls.append(args)
        return {memory.FIELD_PROVINCE_TRADE_POWER: sentinel}

    monkeypatch.setattr(memory._trade_power, "read_fields", delegated)
    result = memory.read_fields(
        reader, BASE, binding, (memory.FIELD_PROVINCE_TRADE_POWER,)
    )

    assert result[memory.FIELD_PROVINCE_TRADE_POWER] is sentinel
    assert len(calls) == 1
    assert calls[0] == (reader, BASE, binding, (memory.FIELD_PROVINCE_TRADE_POWER,))
    assert reader.reads == []


def test_mixed_old_and_new_fields_keep_independent_readers(monkeypatch):
    reader, binding = setup_memory(indexes=(15,))
    install_storage_stub(monkeypatch)
    legacy = {"status": "known", "value": {"raw": 8, "scale": 1000,
                                               "unit": "trade_power"}}
    monkeypatch.setattr(
        memory._trade_power, "read_fields",
        lambda *args: {memory.FIELD_PROVINCE_TRADE_POWER: legacy},
    )

    result = memory.read_fields(
        reader, BASE, binding,
        (memory.FIELD_PROVINCE_TRADE_POWER,
         memory.FIELD_PROVINCE_TRADE_POWER_VALUE),
    )

    assert result[memory.FIELD_PROVINCE_TRADE_POWER] is legacy
    assert result[memory.FIELD_PROVINCE_TRADE_POWER_VALUE]["status"] == "known"
