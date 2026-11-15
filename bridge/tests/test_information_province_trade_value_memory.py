from __future__ import annotations

import struct

import pytest

from bridge.information import foreign_quality_memory as quality
from bridge.information import province_trade_value_memory as memory_module


BASE = 0x140000000
RECORD = 0x60000000
OWNER = 0x61000000
OBSERVER = 0x62000000
RESOURCE_DEFINITION = 0x63000000
WORLD = 0x64000000
MARKET = 0x65000000
PRICES = 0x66000000
MANAGER = 0x67000000
PROVINCE_VALUES = 0x68000000
OWNER_VALUES = 0x69000000
RESOURCE_KEY = 0x6A000000
DESCRIPTOR_KEYS = 0x6B000000
PROVINCE_ID = 227
GOODS_INDEX = 3

DESCRIPTORS = {
    20: "trade_goods_size",
    21: "trade_goods_size_modifier",
    101: "trade_value",
    112: "trade_value_modifier",
    184: "global_trade_goods_size_modifier",
    491: "global_trade_goods_size",
}
PROVINCE_COMPONENTS = {20: 100, 21: 200, 101: 25, 112: 50}
OWNER_COMPONENTS = {184: 75, 491: 300}


def _qword(value: int) -> bytes:
    return struct.pack("<Q", value)


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


def _i32(value: int) -> bytes:
    return struct.pack("<i", value)


def _fullref(slot: int, tag: str, generation: int = 1) -> int:
    return ((generation & 0xFF) << 56) | (slot << 32) | int.from_bytes(
        tag.encode("ascii") + b"\0", "little")


class Memory:
    def __init__(self):
        self.data: dict[int, int] = {}
        self.calls: list[tuple[int, int, str]] = []
        self.short_address: int | None = None
        self.drift_on_stability: int | None = None

    def put(self, address: int, raw: bytes) -> None:
        self.data.update({address + index: byte for index, byte in enumerate(raw)})

    def read(self, address: int, size: int, label: str) -> bytes:
        self.calls.append((address, size, label))
        try:
            raw = bytearray(self.data[address + index] for index in range(size))
        except KeyError as exc:
            raise OSError(f"unmapped:{address:x}+{size:x}") from exc
        if (self.drift_on_stability == address and ".stability." in label
                and raw):
            raw[0] ^= 1
        if self.short_address == address:
            return bytes(raw[:-1])
        return bytes(raw)


def _install_resource(memory: Memory, *, icon_index: int = GOODS_INDEX,
                      key: str = "copper") -> None:
    memory.put(RECORD + 0x458, _qword(RESOURCE_DEFINITION))
    key_raw = key.encode("ascii")
    header = bytearray(32)
    # This key exercises the real inline String32 path in province_resource_memory.
    header[:len(key_raw) + 1] = key_raw + b"\0"
    header[0x10:0x18] = _qword(len(key_raw))
    header[0x18:0x20] = _qword(15)
    memory.put(RESOURCE_DEFINITION + 0x18, bytes(header))
    memory.put(RESOURCE_DEFINITION + 0x78, _i32(icon_index))


def _install_descriptor(memory: Memory, index: int, key: str, *, processor: int = 0,
                        key_override: str | None = None) -> int:
    descriptor = MANAGER + index * 0x60
    encoded = (key if key_override is None else key_override).encode("ascii")
    key_pointer = DESCRIPTOR_KEYS + index * 0x1000
    header = bytearray(32)
    header[:8] = _qword(key_pointer)
    header[0x10:0x18] = _qword(len(encoded))
    header[0x18:0x20] = _qword(max(16, len(encoded)))
    raw = bytearray(0x60)
    raw[:32] = header
    raw[0x40:0x48] = _qword(processor)
    memory.put(descriptor, bytes(raw))
    memory.put(key_pointer, encoded + b"\0")
    return descriptor


def _install_modifier_object(memory: Memory, object_address: int, values_address: int,
                             values: dict[int, int], *, mode: str = "dense",
                             sparse_entries: list[tuple[int, int]] | None = None) -> None:
    if mode == "dense":
        memory.put(object_address + quality.MODIFIER_DENSE_FLAG_OFFSET, b"\x01")
        memory.put(object_address + quality.MODIFIER_VALUES_POINTER_OFFSET,
                   _qword(values_address))
        memory.put(object_address + quality.MODIFIER_SPARSE_COUNT_OFFSET, _u32(0))
        for modifier_id, value in values.items():
            memory.put(values_address + modifier_id * 8 + 4, _i32(value))
        return

    assert mode == "sparse"
    entries = sparse_entries if sparse_entries is not None else list(values.items())
    memory.put(object_address + quality.MODIFIER_DENSE_FLAG_OFFSET, b"\x00")
    memory.put(object_address + quality.MODIFIER_VALUES_POINTER_OFFSET,
               _qword(values_address if entries else 0))
    memory.put(object_address + quality.MODIFIER_SPARSE_COUNT_OFFSET, _u32(len(entries)))
    if entries:
        memory.put(values_address, b"".join(
            struct.pack("<ii", modifier_id, value) for modifier_id, value in entries))


def environment(*, cache_state: int = 0, icon_index: int = GOODS_INDEX,
                scan_world: int = WORLD, owner_ref: int | None = None,
                descriptor_overrides: dict[int, str] | None = None,
                processors: dict[int, int] | None = None,
                province_mode: str = "dense", owner_mode: str = "dense",
                province_values: dict[int, int] | None = None,
                owner_values: dict[int, int] | None = None,
                province_sparse_entries: list[tuple[int, int]] | None = None,
                owner_sparse_entries: list[tuple[int, int]] | None = None):
    memory = Memory()
    province_binding = {
        "province_id": PROVINCE_ID,
        "record_id": PROVINCE_ID,
        "record_pointer": hex(RECORD),
        "id_address": hex(RECORD + 0x20),
        "id_raw_hex": _i32(PROVINCE_ID).hex(),
    }
    province_scan = {"status": "observed", "world": {"pointer": hex(scan_world)}}
    observer_binding = {
        "tag": "FRA", "slot": 122, "country_pointer": hex(OBSERVER),
        "fullref": hex(_fullref(122, "FRA")),
        "fullref_raw_hex": _qword(_fullref(122, "FRA")).hex(),
    }
    owner_binding = {
        "tag": "ENG", "slot": 17, "country_pointer": hex(OWNER),
        "fullref": hex(_fullref(17, "ENG")),
        "fullref_raw_hex": _qword(_fullref(17, "ENG")).hex(),
    }
    canonical_owner_ref = _fullref(17, "ENG") if owner_ref is None else owner_ref

    memory.put(RECORD + 0x468, _qword(canonical_owner_ref))
    memory.put(OWNER + 0x28C8, _i32(cache_state))
    _install_resource(memory, icon_index=icon_index)
    memory.put(BASE + 0x233FE58, _qword(WORLD))
    memory.put(WORLD + 0x25D0, _qword(MARKET))
    memory.put(MARKET + 8, _qword(PRICES))
    selected_price = PRICES + GOODS_INDEX * 0x38 + 4
    if 0 <= icon_index < 1024:
        selected_price = PRICES + icon_index * 0x38 + 4
        memory.put(selected_price, _i32(2500))
    memory.put(BASE + 0x2358060, _qword(MANAGER))
    for index, key in DESCRIPTORS.items():
        _install_descriptor(memory, index, key,
            processor=(processors or {}).get(index, 0),
            key_override=(descriptor_overrides or {}).get(index))

    province_object = RECORD + 0x998
    owner_object = OWNER + quality.COUNTRY_MODIFIER_OBJECT_OFFSET
    _install_modifier_object(memory, province_object, PROVINCE_VALUES,
        PROVINCE_COMPONENTS if province_values is None else province_values,
        mode=province_mode, sparse_entries=province_sparse_entries)
    _install_modifier_object(memory, owner_object, OWNER_VALUES,
        OWNER_COMPONENTS if owner_values is None else owner_values,
        mode=owner_mode, sparse_entries=owner_sparse_entries)
    addresses = {
        "owner_ref": RECORD + 0x468,
        "resource_pointer": RECORD + 0x458,
        "resource_header": RESOURCE_DEFINITION + 0x18,
        "resource_icon": RESOURCE_DEFINITION + 0x78,
        "world": BASE + 0x233FE58,
        "market": WORLD + 0x25D0,
        "prices_pointer": MARKET + 8,
        "price": selected_price,
        "manager": BASE + 0x2358060,
        "descriptor_20": MANAGER + 20 * 0x60,
        "descriptor_20_processor": MANAGER + 20 * 0x60 + 0x40,
        "province_object": province_object,
        "province_storage_20": PROVINCE_VALUES + 20 * 8 + 4,
        "owner_storage_491": OWNER_VALUES + 491 * 8 + 4,
    }
    return memory, province_binding, province_scan, observer_binding, owner_binding, addresses


def _install_parent_binding_mock(monkeypatch):
    calls = []

    def validate(limiter, base, target_pointer, retained):
        calls.append((base, target_pointer, dict(retained)))
        return {"binding": dict(retained), "fullref_resolution": {"status": "known"}}

    # The parent capture validates the actual country database binding. This
    # unit leaf test isolates the upstream validator while keeping real target
    # parsing, String32 decoding, and modifier storage reads.
    monkeypatch.setattr(memory_module._country, "_validate_target_binding", validate)
    return calls


def _read(monkeypatch, env):
    memory, province_binding, province_scan, observer_binding, owner_binding, _ = env
    calls = _install_parent_binding_mock(monkeypatch)
    result = memory_module.read_fields(memory, BASE, province_binding, province_scan,
                                       observer_binding, owner_binding)[memory_module.FIELD]
    return result, calls


@pytest.mark.parametrize("cache_state", [0, 2])
def test_dense_components_use_real_resource_descriptor_and_modifier_storage_helpers(
        monkeypatch, cache_state):
    env = environment(cache_state=cache_state)
    result, parent_calls = _read(monkeypatch, env)
    memory = env[0]

    assert result["status"] == "known"
    assert result["basis"] == memory_module.BASIS
    assert result["period"] == "current"
    assert result["complete"] is False
    value = result["value"]
    assert value["province_id"] == PROVINCE_ID
    assert value["owner"] == "ENG"
    assert value["resource"] == {"localization_key": "copper", "icon_index": GOODS_INDEX}
    assert value["inputs"] == {
        "province_goods_base_raw": 100,
        "owner_goods_base_raw": 300,
        "province_goods_modifier_raw": 200,
        "owner_goods_modifier_raw": 75,
        "goods_price_raw": 2500,
        "province_value_add_raw": 25,
        "province_value_modifier_raw": 50,
    }
    assert value["extra_arguments_zero"] is True
    assert value["description_absent"] is True
    assert value["current_only"] is True
    assert value["individual_monthly_contribution_claimed"] is False
    assert len(parent_calls) == 1
    assert parent_calls[0][1] == OWNER
    assert parent_calls[0][2]["tag"] == "ENG"

    labels = [label for _, _, label in memory.calls]
    assert any("province_resource.String32_header" in label for label in labels)
    assert any("province_value20.key_bytes" in label for label in labels)
    assert any("modifier_storage.trade_goods_size.dense_flag_u8" in label for label in labels)
    assert any("modifier_storage.global_trade_goods_size.dense_value_i32" in label
               for label in labels)
    assert all("processor" not in label for label in labels)
    private = result["raw_inputs"]
    assert private["resource"]["raw_inputs"]["string32_storage"] == "inline"
    assert private["descriptors"]["20"]["key"]["key"] == "trade_goods_size"
    assert private["components"]["20"]["raw_inputs"]["mode"] == "dense"
    assert private["components"]["491"]["raw_inputs"]["mode"] == "dense"
    assert private["budget"]["bytes_requested"] <= memory_module.MAX_BYTES
    assert private["budget"]["calls"] <= memory_module.MAX_CALLS


def test_sparse_storage_uses_first_matching_entry_and_missing_id_as_zero(monkeypatch):
    env = environment(
        province_mode="sparse", owner_mode="sparse",
        province_sparse_entries=[(20, 57), (20, 99)],
        owner_sparse_entries=[(491, -12), (491, 88)],
    )
    result, _ = _read(monkeypatch, env)

    assert result["status"] == "known"
    assert result["value"]["inputs"]["province_goods_base_raw"] == 57
    assert result["value"]["inputs"]["province_goods_modifier_raw"] == 0
    assert result["value"]["inputs"]["owner_goods_base_raw"] == -12
    assert result["value"]["inputs"]["owner_goods_modifier_raw"] == 0
    province_component = result["raw_inputs"]["components"]["20"]["raw_inputs"]
    assert province_component["first_match_index"] == 0
    owner_component = result["raw_inputs"]["components"]["491"]["raw_inputs"]
    assert owner_component["first_match_index"] == 0
    missing_component = result["raw_inputs"]["components"]["21"]["raw_inputs"]
    assert missing_component["first_match_index"] is None
    assert missing_component["modifier_raw"] == 0


@pytest.mark.parametrize("cache_state", [1, 3, -1])
def test_owner_cache_state_outside_zero_or_two_stops_before_resource_reads(monkeypatch, cache_state):
    env = environment(cache_state=cache_state)
    result, _ = _read(monkeypatch, env)
    labels = [label for _, _, label in env[0].calls]

    assert result["status"] == "unknown"
    assert result["reason"] == "PROVINCE_VALUE_OWNER_CACHE_UNSUPPORTED"
    assert not any("province_resource" in label for label in labels)
    assert not any("modifier_storage" in label for label in labels)


def test_owner_full_reference_must_equal_the_parsed_owner_binding(monkeypatch):
    wrong_ref = _fullref(18, "ENG")
    env = environment(owner_ref=wrong_ref)
    result, _ = _read(monkeypatch, env)

    assert result["status"] == "unknown"
    assert result["reason"] == "PROVINCE_VALUE_OWNER_REFERENCE_MISMATCH"
    assert not any("province_resource" in label for _, _, label in env[0].calls)


@pytest.mark.parametrize("icon_index", [-1, 1024])
def test_goods_index_outside_supported_table_is_unknown_before_price_read(monkeypatch, icon_index):
    env = environment(icon_index=icon_index)
    result, _ = _read(monkeypatch, env)

    assert result["status"] == "unknown"
    assert result["reason"] == "PROVINCE_VALUE_GOODS_INDEX_UNSUPPORTED"
    assert not any("selected_goods_price" in label for _, _, label in env[0].calls)


def test_world_global_must_match_supplied_canonical_province_scan(monkeypatch):
    env = environment(scan_world=0x64001000)
    result, _ = _read(monkeypatch, env)

    assert result["status"] == "unknown"
    assert result["reason"] == "PROVINCE_VALUE_WORLD_MISMATCH"
    assert not any("goods_price_container" in label for _, _, label in env[0].calls)


def test_wrong_modifier_descriptor_name_fails_closed_before_storage_walk(monkeypatch):
    env = environment(descriptor_overrides={20: "trade_goods_size_bad"})
    result, _ = _read(monkeypatch, env)
    labels = [label for _, _, label in env[0].calls]

    assert result["status"] == "unknown"
    assert result["reason"] == "PROVINCE_VALUE_UNVERIFIED"
    assert result["error_type"] == "_Failure"
    assert not any("modifier_storage" in label for label in labels)


def test_nonnull_processor_is_rejected_without_executing_or_reading_it(monkeypatch):
    env = environment(processors={101: 0x6C000000})
    result, _ = _read(monkeypatch, env)
    labels = [label for _, _, label in env[0].calls]

    assert result["status"] == "unknown"
    assert result["reason"] == "PROVINCE_VALUE_PROCESSOR_PRESENT"
    assert not any("modifier_storage" in label for label in labels)
    assert not any("processor" in label for label in labels)


@pytest.mark.parametrize("drift_key", [
    "price", "province_storage_20", "owner_ref", "descriptor_20", "resource_header",
])
def test_changed_price_storage_reference_or_string_header_is_retracted(monkeypatch, drift_key):
    env = environment()
    memory, addresses = env[0], env[5]
    memory.drift_on_stability = addresses[drift_key]
    result, _ = _read(monkeypatch, env)

    assert result["status"] == "unknown"
    assert result["reason"] == "PROVINCE_VALUE_INPUT_CHANGED"
    assert any("stability." in label for _, _, label in memory.calls)


def test_short_price_read_fails_closed(monkeypatch):
    env = environment()
    env[0].short_address = env[5]["price"]
    result, _ = _read(monkeypatch, env)

    assert result["status"] == "unknown"
    assert result["reason"] == "PROVINCE_VALUE_UNVERIFIED"
    assert result["error_type"] == "_Failure"
    assert any(address == env[5]["price"] for address, _, _ in env[0].calls)


def test_leaf_budget_failure_is_stopped_by_resource_helper(monkeypatch):
    env = environment()
    monkeypatch.setattr(memory_module, "MAX_BYTES", 16)
    result, _ = _read(monkeypatch, env)

    assert result["status"] == "unknown"
    assert result["reason"] == "PROVINCE_VALUE_RESOURCE_UNVERIFIED"
    assert result["raw_inputs"]["budget"]["bytes_requested"] <= 16
    assert len(env[0].calls) <= 2
    assert not any("selected_goods_price" in label for _, _, label in env[0].calls)
    assert not any("modifier_storage" in label for _, _, label in env[0].calls)
