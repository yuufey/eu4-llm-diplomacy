"""Fake-memory contract tests for the uncatalogued province-goods leaf."""
from __future__ import annotations

import struct

import pytest

from bridge.information import foreign_quality_memory as foreign
from bridge.information import province_goods_sources_memory as goods


BASE = 0x140000000
RECORD = 0x100000000
PROVINCE_ID = 183
COMPONENT_VALUES = 0x200000000
AGGREGATE_VALUES = 0x210000000
SOURCE_KEY_BYTES = 0x220000000


class FakeMemory:
    def __init__(self) -> None:
        self.bytes: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.fail_addresses: set[int] = set()
        self.short_addresses: set[int] = set()
        self.drift: tuple[int, bytes] | None = None
        self.drift_applied = False

    def write(self, address: int, value: bytes) -> None:
        self.bytes.update({address + index: byte for index, byte in enumerate(value)})

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if (self.drift is not None and not self.drift_applied
                and address == self.drift[0] and label.endswith(".verify")):
            self.write(address, self.drift[1])
            self.drift_applied = True
        if address in self.fail_addresses:
            raise OSError(f"fixture_read_failure:{label}")
        try:
            result = bytes(self.bytes[address + index] for index in range(size))
        except KeyError as exc:
            raise OSError(f"fixture_unmapped:{label}") from exc
        if address in self.short_addresses:
            return result[:-1]
        return result


def province_binding(province_id: int = PROVINCE_ID, record: int = RECORD) -> dict[str, object]:
    return {
        "province_id": province_id,
        "record_id": province_id,
        "record_pointer": hex(record),
        "id_address": hex(record + 0x20),
        "id_raw_hex": struct.pack("<i", province_id).hex(),
    }


def _inline_string32(payload: bytes, *, length: int | None = None,
                     capacity: int | None = None) -> bytes:
    string_length = len(payload) - 1 if length is None else length
    string_capacity = string_length if capacity is None else capacity
    header = bytearray(goods.STRING32_SIZE)
    header[:min(len(payload), 16)] = payload[:16]
    header[goods.STRING32_LENGTH_OFFSET:goods.STRING32_LENGTH_OFFSET + 8] = struct.pack(
        "<Q", string_length
    )
    header[goods.STRING32_CAPACITY_OFFSET:goods.STRING32_CAPACITY_OFFSET + 8] = struct.pack(
        "<Q", string_capacity
    )
    return bytes(header)


def _heap_string32(pointer: int, *, length: int, capacity: int) -> bytes:
    header = bytearray(goods.STRING32_SIZE)
    header[:8] = struct.pack("<Q", pointer)
    header[goods.STRING32_LENGTH_OFFSET:goods.STRING32_LENGTH_OFFSET + 8] = struct.pack(
        "<Q", length
    )
    header[goods.STRING32_CAPACITY_OFFSET:goods.STRING32_CAPACITY_OFFSET + 8] = struct.pack(
        "<Q", capacity
    )
    return bytes(header)


def _write_modifier(
    memory: FakeMemory,
    object_address: int,
    values_address: int,
    *,
    dense: bool,
    raw: int = 0,
    entries: list[tuple[int, int]] | None = None,
) -> None:
    memory.write(object_address + foreign.MODIFIER_DENSE_FLAG_OFFSET,
                 bytes([1 if dense else 0]))
    memory.write(object_address + foreign.MODIFIER_VALUES_POINTER_OFFSET,
                 struct.pack("<Q", values_address))
    if dense:
        memory.write(object_address + foreign.MODIFIER_SPARSE_COUNT_OFFSET,
                     struct.pack("<I", 0))
        memory.write(values_address + goods.MODIFIER_INDEX * 8 + 4, struct.pack("<i", raw))
    else:
        sparse = entries or []
        memory.write(object_address + foreign.MODIFIER_SPARSE_COUNT_OFFSET,
                     struct.pack("<I", len(sparse)))
        if sparse:
            memory.write(values_address, b"".join(
                struct.pack("<ii", modifier_id, value) for modifier_id, value in sparse
            ))


def setup_candidate(
    *,
    state: int = goods.CACHE_READY_STATE,
    scale_input: int = 100_000,
    component_raw: int = 700,
    aggregate_raw: int = 1_250,
    component_dense: bool = True,
    aggregate_dense: bool = True,
    component_entries: list[tuple[int, int]] | None = None,
    aggregate_entries: list[tuple[int, int]] | None = None,
    source_key: str = "native_goods_source",
    source_header: bytes | None = None,
    source_payload: bytes | None = None,
) -> FakeMemory:
    memory = FakeMemory()
    memory.write(RECORD + goods.PROVINCE_CACHE_CONTAINER_OFFSET, struct.pack("<I", state))
    memory.write(RECORD + goods.PROVINCE_SCALE_INPUT_OFFSET, struct.pack("<i", scale_input))
    component_address = RECORD + goods.PROVINCE_CACHED_COMPONENT_OFFSET
    aggregate_address = RECORD + goods.PROVINCE_AGGREGATE_MODIFIER_OFFSET
    _write_modifier(memory, component_address, COMPONENT_VALUES,
                    dense=component_dense, raw=component_raw, entries=component_entries)
    _write_modifier(memory, aggregate_address, AGGREGATE_VALUES,
                    dense=aggregate_dense, raw=aggregate_raw, entries=aggregate_entries)

    if source_header is None:
        encoded = source_key.encode("ascii") + b"\0"
        length = len(encoded) - 1
        if length <= 15:
            source_header = _inline_string32(encoded)
        else:
            source_header = _heap_string32(
                SOURCE_KEY_BYTES, length=length, capacity=max(16, length)
            )
            if source_payload is None:
                source_payload = encoded
    memory.write(component_address + goods.SOURCE_KEY_STRING32_OFFSET, source_header)
    if source_payload is not None:
        pointer = int.from_bytes(source_header[:8], "little")
        memory.write(pointer, source_payload)
    return memory


def read_leaf(memory: FakeMemory, binding: dict[str, object] | None = None):
    return goods.read_fields(
        memory, BASE, binding if binding is not None else province_binding(),
        (goods.FIELD_GOODS_SOURCE,),
    )[goods.FIELD_GOODS_SOURCE]


def test_dense_objects_return_cached_component_and_signed_residual_only() -> None:
    memory = setup_candidate(source_key="inline_goods_key")

    result = read_leaf(memory)

    assert result["status"] == "known"
    assert result["complete"] is False
    assert result["basis"] == goods.BASIS
    assert result["period"] == "current"
    assert result["value"] == {
        "province_id": PROVINCE_ID,
        "modifier_index": 21,
        "modifier_key": "trade_goods_size_modifier",
        "source_key": "inline_goods_key",
        "aggregate_raw": 1_250,
        "cached_component_raw": 700,
        "residual_raw": 550,
        "province_scale_input_raw": 100_000,
        "scale": 1000,
        "current_only": True,
        "full_source_coverage": False,
    }
    assert all("pointer" not in key and "address" not in key
               for key in result["value"])
    assert result["raw_inputs"]["cached_component_storage"]["raw"] == 700
    assert result["raw_inputs"]["aggregate_storage"]["raw"] == 1_250
    assert result["raw_inputs"]["full_source_coverage"] is False
    assert result["raw_inputs"]["read_budget"]["bytes_requested"] <= 128 * 1024
    assert result["raw_inputs"]["recheck_result"] == "all_used_bytes_match"
    assert any(label.endswith(".verify") for _, _, label in memory.reads)
    assert "OTHER_PROVINCE_MODIFIER_CALLBACKS_AND_FULL_SOURCE_COVERAGE_NOT_READ" in result["gaps"]


def test_heap_string32_key_is_copied_as_text_without_exposing_its_pointer() -> None:
    memory = setup_candidate(source_key="long_native_goods_definition_key")

    result = read_leaf(memory)

    assert result["status"] == "known"
    assert result["value"]["source_key"] == "long_native_goods_definition_key"
    assert SOURCE_KEY_BYTES not in result["value"].values()
    assert result["raw_inputs"]["source_key_string32"]["storage"] == "heap"
    assert result["raw_inputs"]["source_key_string32"]["pointer"] == hex(SOURCE_KEY_BYTES)


def test_sparse_modifier_objects_preserve_negative_i32_and_wrap_residual() -> None:
    memory = setup_candidate(
        component_dense=False,
        aggregate_dense=False,
        component_entries=[(7, 15), (21, -(1 << 31)), (21, 99)],
        aggregate_entries=[(3, -2), (21, (1 << 31) - 1)],
        source_key="sparse_component_key_name",
    )

    result = read_leaf(memory)

    assert result["status"] == "known"
    assert result["value"]["cached_component_raw"] == -(1 << 31)
    assert result["value"]["aggregate_raw"] == (1 << 31) - 1
    assert result["value"]["residual_raw"] == -1
    component = result["raw_inputs"]["cached_component_storage"]["raw_inputs"]
    assert component["mode"] == "sparse"
    assert component["first_match_index"] == 1
    assert result["raw_inputs"]["aggregate_storage"]["raw_inputs"]["mode"] == "sparse"


def test_non_ready_state_reads_only_the_four_byte_state_and_its_recheck() -> None:
    memory = setup_candidate(state=1)

    result = read_leaf(memory)

    state_address = RECORD + goods.PROVINCE_CACHE_CONTAINER_OFFSET
    assert result["status"] == "unknown"
    assert result["reason"] == "province_modifier_cache_not_ready"
    assert memory.reads == [
        (state_address, 4, "province_goods_sources.cache_state_u32"),
        (state_address, 4, "province_goods_sources.cache_state_u32.verify"),
    ]


@pytest.mark.parametrize("scale_input", [0, -1, -(1 << 31)])
def test_nonpositive_scale_input_is_unknown_without_modifier_reads(scale_input: int) -> None:
    memory = setup_candidate(scale_input=scale_input)

    result = read_leaf(memory)

    allowed = {
        RECORD + goods.PROVINCE_CACHE_CONTAINER_OFFSET,
        RECORD + goods.PROVINCE_SCALE_INPUT_OFFSET,
    }
    assert result["status"] == "unknown"
    assert result["reason"] == "province_scale_input_not_positive"
    assert {address for address, _, _ in memory.reads} == allowed
    assert all(size == 4 for _, size, _ in memory.reads)
    assert len(memory.reads) == 4


@pytest.mark.parametrize(
    ("header", "payload", "reason"),
    [
        (_inline_string32(b"\0", length=0, capacity=0), None, "source_key_empty"),
        (_inline_string32(b"\xff\0", length=1, capacity=1), None, "source_key_not_ascii"),
        (_inline_string32(b"A\0B\0", length=3, capacity=3), None, "source_key_embedded_nul"),
        (_inline_string32(b"ABX", length=2, capacity=2), None, "source_key_terminator_invalid"),
        (_inline_string32(b"ABC\0", length=3, capacity=2), None, "source_key_capacity_invalid"),
        (_heap_string32(SOURCE_KEY_BYTES, length=256, capacity=256), b"x" * 257,
         "source_key_length_out_of_range"),
        (_heap_string32(SOURCE_KEY_BYTES, length=1, capacity=(1 << 20) + 1), b"A\0",
         "source_key_capacity_invalid"),
        (_heap_string32(0, length=1, capacity=16), b"A\0", "SOURCE_KEY_POINTER_INVALID"),
        (_heap_string32(SOURCE_KEY_BYTES, length=1, capacity=16), b"AX",
         "source_key_terminator_invalid"),
    ],
)
def test_malformed_or_empty_string32_fails_closed(
    header: bytes,
    payload: bytes | None,
    reason: str,
) -> None:
    memory = setup_candidate(source_header=header, source_payload=payload)

    result = read_leaf(memory)

    assert result["status"] == "unknown"
    assert result["complete"] is False
    assert result["reason"] == reason
    assert "value" not in result
    assert not any("province_goods_sources.cached_component.dense_value" in label
                   for _, _, label in memory.reads)


def test_heap_string32_pointer_alias_to_leaf_objects_is_rejected_before_payload_read() -> None:
    component_address = RECORD + goods.PROVINCE_CACHED_COMPONENT_OFFSET
    memory = setup_candidate(
        source_header=_heap_string32(component_address, length=1, capacity=16),
        source_payload=None,
    )

    result = read_leaf(memory)

    assert result["status"] == "unknown"
    assert result["reason"] == "source_key_pointer_alias"
    assert not any(label.endswith("source_key_bytes") for _, _, label in memory.reads)
    assert all("pointer" not in key and "address" not in key
               for key in result.get("value", {}))


def test_noncanonical_binding_and_unsupported_field_do_not_read() -> None:
    memory = FakeMemory()
    bad_binding = province_binding()
    bad_binding["id_raw_hex"] = "b8000000"

    invalid_binding = goods.read_fields(
        memory, BASE, bad_binding, (goods.FIELD_GOODS_SOURCE,)
    )[goods.FIELD_GOODS_SOURCE]
    unsupported = goods.read_fields(memory, BASE, province_binding(), ("G02.other",))
    malformed_list = goods.read_fields(memory, BASE, province_binding(), "not-a-list")

    assert invalid_binding["status"] == "unknown"
    assert invalid_binding["reason"] == "province_id_raw_mismatch"
    assert unsupported["G02.other"]["reason"] == "unsupported_field"
    assert malformed_list == {}
    assert memory.reads == []


def test_cached_component_drift_is_unknown_after_used_bytes_are_rechecked() -> None:
    memory = setup_candidate(component_raw=77)
    component_value_address = COMPONENT_VALUES + goods.MODIFIER_INDEX * 8 + 4
    memory.drift = (component_value_address, struct.pack("<i", 78))

    result = read_leaf(memory)

    assert result["status"] == "unknown"
    assert result["reason"] == "leaf_input_changed_during_recheck"
    assert result["raw_inputs"]["recheck_result"] == "changed"
    assert "value" not in result
    assert memory.drift_applied


def test_sparse_read_budget_includes_rechecks_and_rejects_oversized_capture() -> None:
    entries = [(1000 + index, index) for index in range(foreign.MAX_SPARSE_ENTRIES)]
    entries[-1] = (goods.MODIFIER_INDEX, 42)
    memory = setup_candidate(
        component_dense=False,
        component_entries=entries,
        source_key="budget_test_heap_definition_key",
    )

    result = read_leaf(memory)

    budget = result["raw_inputs"]["read_budget"]
    assert result["status"] == "unknown"
    assert result["reason"] == "read_budget_exceeded"
    assert budget["budget_rejected"] is True
    assert budget["bytes_requested"] <= 128 * 1024
    assert budget["calls"] <= 4096
    assert budget["primary_bytes_requested"] <= 64 * 1024
    assert budget["verification_bytes_requested"] <= budget["primary_bytes_requested"]
    assert not any("province_goods_sources.aggregate" in label
                   for _, _, label in memory.reads)
    assert max((size for _, size, _ in memory.reads), default=0) <= 16 * 1024
