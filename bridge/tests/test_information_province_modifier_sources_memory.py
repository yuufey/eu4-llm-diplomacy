"""Bounded fake-memory tests for the reconstructed province modifier sources."""
from __future__ import annotations

import struct

import pytest

from bridge.information import foreign_quality_memory as foreign
from bridge.information import province_modifier_sources_memory as sources
from bridge.information import province_modifiers_memory as kind_reader


BASE = 0x140000000
RECORD = 0x100000000
PROVINCE_ID = 183
AGGREGATE_VALUES = 0x210000000
CACHE_VALUES = 0x220000000
DESCRIPTOR_MANAGER = 0x230000000
DESCRIPTOR_KEY = 0x231000000
STATIC_MANAGER = 0x232000000
DEFINITIONS = 0x240000000
DIRECT_VALUES = 0x250000000
STATE_OBJECT = 0x260000000

DESCRIPTOR_RVA = 0x2358060
STATIC_MANAGER_RVA = 0x242BCE8
DESCRIPTOR_INDEX = 21
DESCRIPTOR_STRIDE = 0x60
DIRECT_DEFINITION_OFFSETS = {
    "under_siege": 0x260,
    "blockaded": 0x330,
    "in_state": 0x310,
    "prosperity": 0x250,
}
KIND_TRUE_VTABLE = BASE + 0x8F300
KIND_FALSE_VTABLE = BASE + 0x8F320
KIND_UNKNOWN_VTABLE = BASE + 0x8F340


class FakeMemory:
    def __init__(self, *, zero_fill_unmapped: bool = False) -> None:
        self.bytes: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.fail_addresses: set[int] = set()
        self.short_addresses: set[int] = set()
        self.drift: tuple[int, bytes] | None = None
        self.drift_applied = False
        self.zero_fill_unmapped = zero_fill_unmapped

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
            if not self.zero_fill_unmapped:
                raise OSError(f"fixture_unmapped:{label}") from exc
            result = bytes(self.bytes.get(address + index, 0) for index in range(size))
        if address in self.short_addresses:
            return result[:-1]
        return result


def province_binding(province_id: int = PROVINCE_ID,
                     record: int = RECORD) -> dict[str, object]:
    return {
        "province_id": province_id,
        "record_id": province_id,
        "record_pointer": hex(record),
        "id_address": hex(record + 0x20),
        "id_raw_hex": struct.pack("<i", province_id).hex(),
    }


def _string32(payload: str, *, heap_address: int) -> tuple[bytes, bytes | None]:
    encoded = payload.encode("ascii") + b"\0"
    length = len(encoded) - 1
    header = bytearray(0x20)
    if length <= 15:
        header[:length + 1] = encoded
        capacity = length
        heap = None
    else:
        header[:8] = struct.pack("<Q", heap_address)
        capacity = max(length, 16)
        heap = encoded
    header[0x10:0x18] = struct.pack("<Q", length)
    header[0x18:0x20] = struct.pack("<Q", capacity)
    return bytes(header), heap


def _write_string32(memory: FakeMemory, address: int, payload: str,
                    *, heap_address: int) -> None:
    header, heap = _string32(payload, heap_address=heap_address)
    memory.write(address, header)
    if heap is not None:
        memory.write(heap_address, heap)


def _write_modifier(memory: FakeMemory, object_address: int, values_address: int,
                    *, raw: int, dense: bool = True,
                    sparse_count: int = 0) -> None:
    memory.write(object_address + foreign.MODIFIER_DENSE_FLAG_OFFSET,
                 bytes([1 if dense else 0]))
    memory.write(object_address + foreign.MODIFIER_VALUES_POINTER_OFFSET,
                 struct.pack("<Q", values_address))
    memory.write(object_address + foreign.MODIFIER_SPARSE_COUNT_OFFSET,
                 struct.pack("<I", sparse_count))
    if dense:
        memory.write(values_address + 21 * 8 + 4, struct.pack("<i", raw))


def setup_candidate(
    *,
    state: int = 2,
    aggregate_raw: int = 0,
    components: dict[int, tuple[str, int]] | None = None,
    direct_values: dict[str, int] | None = None,
    kinds: dict[str, str] | None = None,
    descriptor_key: str = "trade_goods_size_modifier",
    descriptor_processor: int = 0,
    siege_pointer: int = 0,
    state_pointer: int = 0,
    state_level: int = 0,
    blockaded: bool = False,
    zero_fill_unmapped: bool = False,
) -> FakeMemory:
    memory = FakeMemory(zero_fill_unmapped=zero_fill_unmapped)
    memory.write(RECORD + 0x988, struct.pack("<I", state))
    _write_modifier(memory, RECORD + 0x998, AGGREGATE_VALUES,
                    raw=aggregate_raw)

    rows = components or {}
    for index, offset in enumerate(sources.CACHE_COMPONENT_OFFSETS):
        key, raw = rows.get(index, ("", 0))
        obj = RECORD + 0x988 + offset
        _write_string32(memory, obj + 0x158, key,
                        heap_address=CACHE_VALUES + 0x800000 + index * 0x1000)
        _write_modifier(memory, obj, CACHE_VALUES + index * 0x1000,
                        raw=raw)

    descriptor = DESCRIPTOR_MANAGER + DESCRIPTOR_INDEX * DESCRIPTOR_STRIDE
    memory.write(BASE + DESCRIPTOR_RVA, struct.pack("<Q", DESCRIPTOR_MANAGER))
    memory.write(descriptor, bytes(DESCRIPTOR_STRIDE))
    _write_string32(memory, descriptor, descriptor_key,
                    heap_address=DESCRIPTOR_KEY)
    memory.write(descriptor + 0x40, struct.pack("<Q", descriptor_processor))

    memory.write(BASE + STATIC_MANAGER_RVA, struct.pack("<Q", STATIC_MANAGER))
    value_by_key = direct_values or {}
    kind_by_key = kinds or {}
    for index, (key, offset) in enumerate(DIRECT_DEFINITION_OFFSETS.items()):
        definition = DEFINITIONS + index * 0x10000
        memory.write(STATIC_MANAGER + offset, struct.pack("<Q", definition))
        _write_string32(memory, definition + 0x158, key,
                        heap_address=DEFINITIONS + 0x800000 + index * 0x1000)
        _write_modifier(memory, definition, DIRECT_VALUES + index * 0x1000,
                        raw=value_by_key.get(key, 0))
        kind = kind_by_key.get(key, "true")
        if key in ("under_siege", "in_state", "prosperity"):
            vtable = {
                "true": KIND_TRUE_VTABLE,
                "false": KIND_FALSE_VTABLE,
                "unknown": KIND_UNKNOWN_VTABLE,
            }[kind]
            memory.write(definition, struct.pack("<Q", vtable))
            method_by_kind = {
                "true": BASE + kind_reader.SUPPORTED_TRUE_METHOD_RVA,
                "false": BASE + kind_reader.SUPPORTED_FALSE_METHOD_RVA,
                "unknown": BASE + 0x8F480,
            }
            method = method_by_kind[kind]
            memory.write(vtable + 0x90, struct.pack("<Q", method))
            if kind == "true":
                memory.write(method, kind_reader.SUPPORTED_TRUE_METHOD_BYTES)
            elif kind == "false":
                memory.write(method, kind_reader.SUPPORTED_FALSE_METHOD_BYTES)

    memory.write(RECORD + 0x388, struct.pack("<Q", siege_pointer))
    memory.write(RECORD + 0x2E0, struct.pack("<Q", state_pointer))
    memory.write(RECORD + 0x958, bytes([0x40 if blockaded else 0]))
    if state_pointer:
        memory.write(state_pointer + 0x18, struct.pack("<i", state_level))
    return memory


def read_leaf(memory: FakeMemory, binding: dict[str, object] | None = None):
    return sources.read_fields(
        memory, BASE, binding if binding is not None else province_binding(),
        (sources.FIELD,),
    )[sources.FIELD]


def _value(result: dict[str, object]) -> dict[str, object]:
    value = result.get("value")
    assert isinstance(value, dict)
    return value


def _direct(value: dict[str, object], key: str) -> dict[str, object]:
    rows = value["direct_sources"]
    assert isinstance(rows, list)
    return next(row for row in rows if row["source_key"] == key)


def test_native_sample_reconstructs_cached_and_under_siege_terms() -> None:
    memory = setup_candidate(
        aggregate_raw=-258,
        components={
            0: ("devastation", -18),
            1: ("bonus_from_merchant_republics", 10),
        },
        direct_values={"under_siege": -250},
        siege_pointer=0x270000000,
    )

    result = read_leaf(memory)

    assert result["status"] == "known"
    value = _value(result)
    assert value["aggregate_raw"] == -258
    assert value["cached_sum_raw"] == -8
    assert value["direct_sum_raw"] == -250
    assert value["residual_raw"] == 0
    assert value["current_only"] is True
    assert value["full_source_coverage"] is False
    assert value["last_refresh_execution_observed"] is False
    assert value["descriptor_qualified"] is True
    assert len(value["cached_components"]) == 23
    assert len(value["direct_sources"]) == 4
    assert _direct(value, "under_siege")["applied_raw"] == -250


def test_other_cache_source_is_available_without_devastation() -> None:
    memory = setup_candidate(
        aggregate_raw=7,
        components={3: ("another_modifier", 7)},
    )

    result = read_leaf(memory)

    assert result["status"] == "known"
    value = _value(result)
    assert value["cached_sum_raw"] == 7
    assert value["cached_components"][3] == {
        "status": "known", "source_key": "another_modifier", "raw": 7, "scale": 1000,
    }


def test_empty_cache_key_does_not_discard_nonzero_raw_value() -> None:
    memory = setup_candidate(aggregate_raw=13, components={0: ("", 13)})

    result = read_leaf(memory)

    value = _value(result)
    assert value["cached_components"][0] == {
        "status": "known", "source_key": None, "raw": 13, "scale": 1000,
    }
    assert value["cached_sum_raw"] == 13
    assert value["residual_raw"] == 0


def test_heap_empty_cache_key_still_rejects_values_pointer_alias() -> None:
    memory = setup_candidate(
        aggregate_raw=27,
        components={0: ("", 23), 1: ("sibling", 4)},
    )
    first_object = RECORD + 0x988 + sources.CACHE_COMPONENT_OFFSETS[0]
    heap_address = CACHE_VALUES
    header = bytearray(0x20)
    header[:8] = struct.pack("<Q", heap_address)
    header[0x10:0x18] = struct.pack("<Q", 0)
    header[0x18:0x20] = struct.pack("<Q", 16)
    memory.write(first_object + 0x158, bytes(header))
    memory.write(heap_address, b"\0")

    result = read_leaf(memory)

    assert result["status"] == "known"
    value = _value(result)
    assert value["cached_components"][0]["status"] == "unknown"
    assert value["cached_components"][1] == {
        "status": "known", "source_key": "sibling", "raw": 4, "scale": 1000,
    }
    assert value["cached_sum_raw"] is None
    assert value["direct_sum_raw"] == 0
    assert value["residual_raw"] is None


def test_bad_cache_key_is_local_and_withholds_only_the_cache_sum() -> None:
    memory = setup_candidate(aggregate_raw=4, components={1: ("sibling", 4)})
    first_object = RECORD + 0x988 + sources.CACHE_COMPONENT_OFFSETS[0]
    malformed = bytearray(0x20)
    malformed[:2] = b"\xff\0"
    malformed[0x10:0x18] = struct.pack("<Q", 1)
    malformed[0x18:0x20] = struct.pack("<Q", 1)
    memory.write(first_object + 0x158, bytes(malformed))

    result = read_leaf(memory)

    assert result["status"] == "known"
    value = _value(result)
    assert value["cached_components"][0]["status"] == "unknown"
    assert value["cached_components"][1]["status"] == "known"
    assert value["cached_sum_raw"] is None
    assert value["direct_sum_raw"] == 0
    assert value["residual_raw"] is None


def test_unknown_kind_withholds_only_the_active_direct_child() -> None:
    memory = setup_candidate(
        aggregate_raw=0,
        kinds={"under_siege": "unknown"},
        direct_values={"under_siege": -250},
        siege_pointer=0x270000000,
    )

    result = read_leaf(memory)

    assert result["status"] == "known"
    value = _value(result)
    assert _direct(value, "under_siege")["status"] == "unknown"
    assert _direct(value, "under_siege")["enabled"] is None
    assert _direct(value, "under_siege")["applied_raw"] is None
    assert all(_direct(value, key)["status"] == "known"
               for key in ("blockaded", "in_state", "prosperity"))
    assert value["direct_sum_raw"] is None
    assert value["residual_raw"] is None


def test_prosperity_threshold_pass_keeps_unmodeled_conditions_unknown() -> None:
    memory = setup_candidate(
        aggregate_raw=0,
        state_pointer=STATE_OBJECT,
        state_level=100_000,
        direct_values={"prosperity": 25},
    )

    result = read_leaf(memory)

    assert result["status"] == "known"
    value = _value(result)
    prosperity = _direct(value, "prosperity")
    assert prosperity["status"] == "unknown"
    assert prosperity["definition_raw"] == 25
    assert prosperity["enabled"] is None
    assert prosperity["applied_raw"] is None
    assert value["direct_sum_raw"] is None


def test_false_siege_precondition_yields_zero_even_for_unknown_kind() -> None:
    memory = setup_candidate(
        aggregate_raw=0,
        kinds={"under_siege": "unknown"},
        direct_values={"under_siege": -250},
        siege_pointer=0,
    )

    result = read_leaf(memory)

    value = _value(result)
    siege = _direct(value, "under_siege")
    assert siege["status"] == "known"
    assert siege["enabled"] is False
    assert siege["applied_raw"] == 0


def test_non_null_descriptor_processor_rejects_the_whole_leaf() -> None:
    memory = setup_candidate(aggregate_raw=0, descriptor_processor=0x270000000)

    result = read_leaf(memory)

    assert result["status"] == "unknown"
    assert result["reason"] == "MODIFIER_PROCESSOR_PRESENT"
    assert "value" not in result


def test_state_one_reads_only_state_and_recheck() -> None:
    memory = setup_candidate(state=1)

    result = read_leaf(memory)

    assert result["status"] == "unknown"
    assert result["reason"] == "PROVINCE_MODIFIER_CACHE_NOT_READY"
    assert memory.reads == [
        (RECORD + 0x988, 4, "province_sources.cache_state"),
        (RECORD + 0x988, 4, "province_sources.cache_state.verify"),
    ]


def test_drift_in_any_used_byte_retracts_the_entire_leaf() -> None:
    memory = setup_candidate(aggregate_raw=13)
    aggregate_value = AGGREGATE_VALUES + 21 * 8 + 4
    memory.drift = (aggregate_value, struct.pack("<i", 14))

    result = read_leaf(memory)

    assert result["status"] == "unknown"
    assert result["reason"] == "leaf_input_changed_during_recheck"
    assert result["raw_inputs"]["recheck_result"] == "changed"
    assert "value" not in result
    assert memory.drift_applied


def test_budget_rejection_stays_bounded_and_withdraws_the_leaf() -> None:
    memory = setup_candidate(zero_fill_unmapped=True)
    first = RECORD + 0x988 + sources.CACHE_COMPONENT_OFFSETS[0]
    _write_modifier(memory, first, CACHE_VALUES, raw=0, dense=False,
                    sparse_count=8192)

    result = read_leaf(memory)

    assert result["status"] == "unknown"
    assert result["reason"] == "PROVINCE_SOURCES_READ_BUDGET"
    budget = result["raw_inputs"]["budget"]
    assert budget["budget_rejected"] is True
    assert budget["bytes_requested"] <= 128 * 1024
    assert budget["calls"] <= 4096
    assert max((size for _, size, _ in memory.reads), default=0) <= 16 * 1024


def test_bad_binding_and_unsupported_field_are_zero_read() -> None:
    memory = FakeMemory()
    binding = province_binding()
    binding["id_raw_hex"] = "b8000000"

    bad_binding = sources.read_fields(memory, BASE, binding, (sources.FIELD,))
    unsupported = sources.read_fields(memory, BASE, province_binding(), ("G02.other",))
    malformed = sources.read_fields(memory, BASE, province_binding(), "not-a-list")

    assert bad_binding[sources.FIELD]["status"] == "unknown"
    assert bad_binding[sources.FIELD]["reason"] == "province_id_raw_mismatch"
    assert unsupported["G02.other"]["reason"] == "UNSUPPORTED_FIELD"
    assert malformed == {}
    assert memory.reads == []
