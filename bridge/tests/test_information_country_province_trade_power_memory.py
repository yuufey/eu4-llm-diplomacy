"""Boundary tests for the passive country modifier-17 reader."""
from __future__ import annotations

import struct

import pytest

from bridge.information import country_province_trade_power_memory as memory


BASE = 0x140000000
COUNTRY = 0x200000000
MANAGER = 0x300000000
NAME_POINTER = 0x350000000
TAG = "FRA"
FIELD = memory.FIELD_COUNTRY_GLOBAL_PROVINCE_TRADE_POWER_MODIFIER


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


def setup_memory(
    *,
    cache_state: int = 0,
    manager: int = MANAGER,
    processor: int = 0,
    key: str = memory.MODIFIER_KEY,
    name_pointer: int = NAME_POINTER,
) -> tuple[FakeMemory, dict[str, object]]:
    reader = FakeMemory()
    reader.write(COUNTRY + memory.CACHE_STATE_OFFSET, struct.pack("<i", cache_state))
    reader.write(BASE + memory.MODIFIER_PROCESSOR_GLOBAL_RVA,
                 manager.to_bytes(8, "little"))
    descriptor = bytearray(memory.MODIFIER_DESCRIPTOR_SIZE)
    encoded = key.encode("ascii")
    descriptor[:8] = name_pointer.to_bytes(8, "little")
    descriptor[0x10:0x18] = len(encoded).to_bytes(8, "little")
    descriptor[0x18:0x20] = (len(encoded) + 8).to_bytes(8, "little")
    descriptor[memory.MODIFIER_PROCESSOR_OFFSET:
               memory.MODIFIER_PROCESSOR_OFFSET + 8] = processor.to_bytes(8, "little")
    descriptor_address = manager + memory.MODIFIER_ID * memory.MODIFIER_PROCESSOR_STRIDE
    reader.write(descriptor_address, bytes(descriptor))
    reader.write(name_pointer, encoded + b"\0")
    binding = {"tag": TAG, "country_pointer": hex(COUNTRY),
               "fullref": "0x0100000000000001", "fullref_raw_hex": "0100000000000001"}
    return reader, binding


def install_binding(monkeypatch, *, fail_validation: bool = False):
    retained = {
        "tag": TAG,
        "country_pointer": hex(COUNTRY),
        "fullref": "0x0100000000000001",
        "fullref_raw_hex": "0100000000000001",
    }
    calls: list[tuple[object, ...]] = []

    def parse_target(base, binding):
        calls.append(("parse", base, binding))
        return BASE, COUNTRY, dict(retained)

    def validate_target(limiter, base, country, target):
        calls.append(("validate", base, country, dict(target)))
        if fail_validation:
            raise ValueError("canonical_fullref_or_pointer_mismatch")
        return {"binding": dict(target), "fullref_resolution": {"status": "known"}}

    monkeypatch.setattr(memory._country_binding, "_parse_target", parse_target)
    monkeypatch.setattr(memory._country_binding, "_validate_target_binding", validate_target)
    return calls


def install_storage_stub(monkeypatch, raw_value: int = 0):
    calls: list[dict[str, object]] = []

    def read_raw_modifier(trace, country, modifier_id, unit, *, name,
                          forbidden_pointers=()):
        calls.append({
            "trace": trace,
            "country": country,
            "modifier_id": modifier_id,
            "unit": unit,
            "name": name,
            "forbidden_pointers": tuple(forbidden_pointers),
        })
        return {
            "status": "known",
            "value": raw_value,
            "raw": raw_value,
            "unit": unit,
            "scale": 1000,
            "raw_inputs": {"mode": "stubbed_shared_storage"},
        }

    monkeypatch.setattr(memory, "read_raw_modifier", read_raw_modifier)
    return calls


def read_field(reader: FakeMemory, binding: dict[str, object]):
    return memory.read_fields(reader, BASE, binding, (FIELD,))[FIELD]


@pytest.mark.parametrize("raw_value", [0, 1800, -750, -(1 << 31), (1 << 31) - 1])
@pytest.mark.parametrize("cache_state", [0, 2])
def test_null_processor_returns_signed_current_ratio(
    monkeypatch, raw_value: int, cache_state: int,
):
    reader, binding = setup_memory(cache_state=cache_state)
    binding_calls = install_binding(monkeypatch)
    storage_calls = install_storage_stub(monkeypatch, raw_value)

    field = read_field(reader, binding)

    assert field["status"] == "known"
    assert field["value"] == {
        "country": TAG, "raw": raw_value, "scale": 1000, "unit": "ratio",
    }
    assert field["basis"] == "native_country_province_trade_power_modifier_processor_absent"
    assert field["period"] == "current"
    assert field["complete"] is False
    assert len(binding_calls) == 2
    assert len(storage_calls) == 1
    assert storage_calls[0]["country"] == COUNTRY
    assert storage_calls[0]["modifier_id"] == 17
    assert storage_calls[0]["unit"] == "ratio"
    assert storage_calls[0]["name"] == "global_prov_trade_power_modifier"
    assert COUNTRY + memory.MODIFIER_OBJECT_OFFSET in storage_calls[0]["forbidden_pointers"]
    assert field["raw_inputs"]["cache_state_before"] == cache_state
    assert field["raw_inputs"]["cache_state_after"] == cache_state


@pytest.mark.parametrize(
    ("cache_state", "reason"),
    [
        (1, "COUNTRY_CACHE_STATE_CALCULATING"),
        (3, "COUNTRY_CACHE_STATE_UNSUPPORTED"),
        (-1, "COUNTRY_CACHE_STATE_UNSUPPORTED"),
    ],
)
def test_only_conservative_cache_states_proceed(monkeypatch, cache_state: int, reason: str):
    reader, binding = setup_memory(cache_state=cache_state)
    install_binding(monkeypatch)
    storage_calls = install_storage_stub(monkeypatch)

    field = read_field(reader, binding)

    assert field["status"] == "unknown"
    assert field["reason"] == reason
    assert storage_calls == []
    assert not any(label.endswith("processor_manager_global") for _, _, label in reader.reads)


def test_canonical_binding_revalidation_failure_stops_before_country_reads(monkeypatch):
    reader, binding = setup_memory()
    binding_calls = install_binding(monkeypatch, fail_validation=True)
    storage_calls = install_storage_stub(monkeypatch)

    field = read_field(reader, binding)

    assert field["status"] == "unknown"
    assert field["reason"] == "COUNTRY_BINDING_UNVERIFIED"
    assert [call[0] for call in binding_calls] == ["parse", "validate"]
    assert reader.reads == []
    assert storage_calls == []


def test_non_null_processor_is_unknown_without_storage_reads(monkeypatch):
    reader, binding = setup_memory(processor=0x360000000)
    install_binding(monkeypatch)
    storage_calls = install_storage_stub(monkeypatch)

    field = read_field(reader, binding)

    assert field["status"] == "unknown"
    assert field["reason"] == "COUNTRY_MODIFIER_PROCESSOR_PRESENT"
    assert storage_calls == []
    assert not any("modifier_storage" in label for _, _, label in reader.reads)


def test_modifier_key_must_match_exact_script_name(monkeypatch):
    reader, binding = setup_memory(key="global_prov_trade_power_modifieX")
    install_binding(monkeypatch)
    storage_calls = install_storage_stub(monkeypatch)

    field = read_field(reader, binding)

    assert field["status"] == "unknown"
    assert field["reason"] == "COUNTRY_MODIFIER_KEY_MISMATCH"
    assert storage_calls == []


def test_bad_modifier_key_pointer_is_unknown(monkeypatch):
    reader, binding = setup_memory(name_pointer=0)
    install_binding(monkeypatch)
    storage_calls = install_storage_stub(monkeypatch)

    field = read_field(reader, binding)

    assert field["status"] == "unknown"
    assert field["reason"] == "COUNTRY_MODIFIER_DESCRIPTOR_UNVERIFIED"
    assert storage_calls == []


def test_manager_pointer_drift_retracts_value(monkeypatch):
    reader, binding = setup_memory()
    reader.mutate_after[
        "country_province_trade_power.processor_manager_global"
    ] = (BASE + memory.MODIFIER_PROCESSOR_GLOBAL_RVA,
         (MANAGER + 0x1000).to_bytes(8, "little"))
    install_binding(monkeypatch)
    storage_calls = install_storage_stub(monkeypatch, 500)

    field = read_field(reader, binding)

    assert field["status"] == "unknown"
    assert field["reason"] == "COUNTRY_MODIFIER_MANAGER_CHANGED"
    assert storage_calls


@pytest.mark.parametrize(
    ("offset", "replacement", "reason"),
    [
        (0, b"\x01", "COUNTRY_MODIFIER_DESCRIPTOR_CHANGED"),
        (memory.MODIFIER_PROCESSOR_OFFSET, b"\x01",
         "COUNTRY_MODIFIER_PROCESSOR_CHANGED"),
    ],
)
def test_descriptor_header_or_processor_drift_retracts_value(
    monkeypatch, offset: int, replacement: bytes, reason: str,
):
    reader, binding = setup_memory()
    descriptor_address = MANAGER + memory.MODIFIER_ID * memory.MODIFIER_PROCESSOR_STRIDE
    original = bytes(reader.bytes[descriptor_address + i]
                     for i in range(memory.MODIFIER_DESCRIPTOR_SIZE))
    changed = bytearray(original)
    changed[offset:offset + len(replacement)] = replacement
    reader.mutate_after[
        "country_province_trade_power.index_17.descriptor_96"
    ] = (descriptor_address, bytes(changed))
    install_binding(monkeypatch)
    install_storage_stub(monkeypatch, 500)

    field = read_field(reader, binding)

    assert field["status"] == "unknown"
    assert field["reason"] == reason


def test_key_payload_drift_retracts_value(monkeypatch):
    reader, binding = setup_memory()
    changed = b"global_prov_trade_power_modifieX\0"
    reader.mutate_after[
        "province_trade_power_inputs.country_index_17.key_bytes"
    ] = (NAME_POINTER, changed)
    install_binding(monkeypatch)
    install_storage_stub(monkeypatch, 500)

    field = read_field(reader, binding)

    assert field["status"] == "unknown"
    assert field["reason"] == "COUNTRY_MODIFIER_KEY_CHANGED"


def test_cache_state_change_during_storage_retracts_value(monkeypatch):
    reader, binding = setup_memory(cache_state=0)
    reader.mutate_after["country_province_trade_power.cache_state_before_i32"] = (
        COUNTRY + memory.CACHE_STATE_OFFSET, struct.pack("<i", 2),
    )
    install_binding(monkeypatch)
    install_storage_stub(monkeypatch, -1)

    field = read_field(reader, binding)

    assert field["status"] == "unknown"
    assert field["reason"] == "COUNTRY_CACHE_STATE_CHANGED"


def test_storage_unknown_stays_unknown_after_stability_checks(monkeypatch):
    reader, binding = setup_memory()
    install_binding(monkeypatch)
    calls: list[tuple[object, ...]] = []

    def unavailable(*args, **kwargs):
        calls.append(args)
        return {"status": "unknown", "reason": "MODIFIER_VALUES_POINTER_INVALID",
                "raw_inputs": {"mode": "shared_core_failure"}}

    monkeypatch.setattr(memory, "read_raw_modifier", unavailable)
    field = read_field(reader, binding)

    assert field["status"] == "unknown"
    assert field["reason"] == "COUNTRY_MODIFIER_STORAGE_UNAVAILABLE"
    assert field["raw_inputs"]["modifier_storage_component"]["reason"] == \
        "MODIFIER_VALUES_POINTER_INVALID"
    assert len(calls) == 1


def test_unsupported_and_duplicate_fields_do_not_read_memory(monkeypatch):
    reader, binding = setup_memory()
    install_binding(monkeypatch)
    storage_calls = install_storage_stub(monkeypatch)

    unsupported = memory.read_fields(reader, BASE, binding, ("G02.unrelated",))
    assert unsupported["G02.unrelated"]["reason"] == "UNSUPPORTED_FIELD"
    duplicate = memory.read_fields(reader, BASE, binding, (FIELD, FIELD))
    assert duplicate[FIELD]["reason"] == "DUPLICATE_FIELD_REQUESTED"
    assert reader.reads == []
    assert storage_calls == []
