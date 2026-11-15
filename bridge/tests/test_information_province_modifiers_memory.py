"""Synthetic boundary tests for the internal province modifier reader."""
from __future__ import annotations

import struct

import pytest

from bridge.information import province_modifiers_memory as memory


BASE = 0x140000000
RECORD = 0x100000000
PRIMARY_MANAGER = 0x200000000
SECONDARY_MANAGER = 0x200010000
PRIMARY_BUCKETS = 0x200020000
SECONDARY_BUCKETS = 0x200030000
PRIMARY_NODES = 0x200040000
SECONDARY_NODES = 0x200080000
DEFINITIONS = 0x200100000
SENTINEL = 0x200500000
VECTOR = 0x200600000
SECONDARY_ARRAY = 0x200700000
VTABLE_RVA = 0x1D18300
PROVINCE_ID = 183


class FakeMemory:
    def __init__(self) -> None:
        self.bytes: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.short_labels: set[str] = set()
        self.fail_labels: set[str] = set()
        self.mutate_on_read: dict[str, tuple[int, bytes]] = {}

    def write(self, address: int, value: bytes) -> None:
        for offset, byte in enumerate(value):
            self.bytes[address + offset] = byte

    def u32(self, address: int, value: int, *, signed: bool = False) -> None:
        self.write(address, int(value).to_bytes(4, "little", signed=signed))

    def u64(self, address: int, value: int) -> None:
        self.write(address, int(value).to_bytes(8, "little"))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if label in self.fail_labels:
            raise OSError("fixture_failure")
        mutation = self.mutate_on_read.pop(label, None)
        if mutation is not None:
            self.write(*mutation)
        try:
            value = bytes(self.bytes[address + offset] for offset in range(size))
        except KeyError as exc:
            raise OSError("fixture_unmapped") from exc
        if label in self.short_labels:
            return value[:-1]
        return value


def province_binding(province_id: int = PROVINCE_ID) -> dict[str, object]:
    return {
        "province_id": province_id,
        "record_id": province_id,
        "record_pointer": hex(RECORD),
        "id_address": hex(RECORD + 0x20),
        "id_raw_hex": struct.pack("<i", province_id).hex(),
    }


def _hash_key(key: str) -> int:
    value = 0
    for byte in key.encode("ascii"):
        value = ((value + byte) * 61) & 0xFFFFFFFF
    return value


def setup_world(
    *,
    primary_keys: tuple[str, ...] = (),
    secondary_keys: tuple[str, ...] = (),
    kind: bool = True,
    primary_active: tuple[str, ...] = (),
    secondary_active: tuple[str, ...] = (),
    sentinel_kind: bool | None = None,
    cycle_primary: bool = False,
    chain_cap_primary: bool = False,
    unaligned_primary: bool = False,
    secondary_count: int | None = None,
) -> tuple[FakeMemory, dict[str, int]]:
    """Build a compact synthetic image with independent manager/list regions."""
    result = FakeMemory()
    definition_by_key: dict[str, int] = {}
    cursor = DEFINITIONS

    true_method = BASE + memory.SUPPORTED_TRUE_METHOD_RVA
    false_method = BASE + memory.SUPPORTED_FALSE_METHOD_RVA
    selected_method = true_method if kind else false_method
    result.u64(BASE + VTABLE_RVA + memory.DEFINITION_KIND_SLOT_OFFSET, selected_method)
    result.write(true_method, memory.SUPPORTED_TRUE_METHOD_BYTES)
    result.write(false_method, memory.SUPPORTED_FALSE_METHOD_BYTES)

    all_keys = tuple(dict.fromkeys((*primary_keys, *secondary_keys)))
    for key in all_keys:
        definition = cursor
        cursor += 0x1000
        definition_by_key[key] = definition
        result.write(definition, (BASE + VTABLE_RVA).to_bytes(8, "little"))
        key_string32 = bytearray(memory.DEFINITION_KEY_STRING32_WIDTH)
        encoded = key.encode("ascii")
        if len(encoded) <= 15:
            capacity = 15
            key_string32[:16] = encoded.ljust(16, b"\0")
        else:
            capacity = max(16, len(encoded))
            string_pointer = cursor
            cursor += 0x1000
            key_string32[:8] = string_pointer.to_bytes(8, "little")
            result.write(string_pointer, encoded + b"\0")
        length_offset = memory.DEFINITION_KEY_LENGTH_RELATIVE_OFFSET
        capacity_offset = memory.DEFINITION_KEY_CAPACITY_RELATIVE_OFFSET
        key_string32[length_offset:length_offset + 8] = len(encoded).to_bytes(8, "little")
        key_string32[capacity_offset:capacity_offset + 8] = capacity.to_bytes(8, "little")
        result.write(definition + memory.DEFINITION_KEY_OFFSET, bytes(key_string32))

    def add_manager(name: str, keys: tuple[str, ...], manager: int,
                    buckets: int, nodes_base: int, definition_offset: int) -> None:
        global_rva = (memory.PRIMARY_MANAGER_GLOBAL_RVA if name == "primary"
                      else memory.SECONDARY_MANAGER_GLOBAL_RVA)
        result.u64(BASE + global_rva, manager)
        result.write(manager, bytes(memory.MANAGER_HEADER_WIDTH))
        result.u32(manager + memory.MANAGER_BUCKET_COUNT_OFFSET, 1)
        result.u64(manager + memory.MANAGER_BUCKETS_POINTER_OFFSET, buckets)
        node_count = len(keys)
        for index, key in enumerate(keys):
            node = nodes_base + index * 0x100
            result.u64(node + definition_offset, definition_by_key[key])
            next_node = nodes_base + (index + 1) * 0x100 if index + 1 < node_count else 0
            result.u64(node + memory.HASH_NODE_NEXT_OFFSET, next_node)
        head = nodes_base if node_count else 0
        result.u64(buckets, head)
        if cycle_primary and name == "primary" and node_count:
            result.u64(nodes_base + (node_count - 1) * 0x100 + memory.HASH_NODE_NEXT_OFFSET,
                       nodes_base)
        if chain_cap_primary and name == "primary" and node_count:
            # A cap fixture has one more reachable node than the allowed limit.
            result.u64(nodes_base + (node_count - 1) * 0x100 + memory.HASH_NODE_NEXT_OFFSET,
                       nodes_base + node_count * 0x100)
            final = nodes_base + node_count * 0x100
            result.u64(final + definition_offset, definition_by_key[keys[-1]])
            result.u64(final + memory.HASH_NODE_NEXT_OFFSET, 0)

    add_manager("primary", primary_keys, PRIMARY_MANAGER, PRIMARY_BUCKETS,
                PRIMARY_NODES, memory.HASH_NODE_DEFINITION_OFFSET)
    add_manager("secondary", secondary_keys, SECONDARY_MANAGER, SECONDARY_BUCKETS,
                SECONDARY_NODES, memory.HASH_NODE_DEFINITION_OFFSET)

    sentinel_vtable = BASE + VTABLE_RVA
    result.u64(SENTINEL, sentinel_vtable)
    result.u64(BASE + memory.PRIMARY_UNMATCHED_SENTINEL_GLOBAL_RVA, SENTINEL)
    if sentinel_kind is not None:
        method = true_method if sentinel_kind else false_method
        result.u64(sentinel_vtable + memory.DEFINITION_KIND_SLOT_OFFSET, method)

    if primary_active:
        begin = VECTOR + (1 if unaligned_primary else 0)
        for index, key in enumerate(primary_active):
            instance = 0x200800000 + index * 0x100
            result.u64(begin + index * 8, instance)
            result.u64(instance + memory.INSTANCE_DEFINITION_OFFSET, definition_by_key[key])
        end = begin + len(primary_active) * 8
    else:
        begin = end = 0
    result.u64(RECORD + memory.PROVINCE_PRIMARY_BEGIN_OFFSET, begin)
    result.u64(RECORD + memory.PROVINCE_PRIMARY_END_OFFSET, end)

    if secondary_active:
        array_pointer = SECONDARY_ARRAY
        for index, key in enumerate(secondary_active):
            result.u64(array_pointer + index * 8, definition_by_key[key])
        count = len(secondary_active)
    else:
        array_pointer = 0
        count = 0
    if secondary_count is not None:
        count = secondary_count
    result.write(RECORD + memory.PROVINCE_SECONDARY_ARRAY_OFFSET, bytes(0x10))
    result.u64(RECORD + memory.PROVINCE_SECONDARY_ARRAY_OFFSET, array_pointer)
    result.u32(RECORD + memory.PROVINCE_SECONDARY_COUNT_OFFSET, count, signed=True)

    return result, definition_by_key


def test_primary_true_reads_instance_definition_and_knows_positive_membership() -> None:
    reader, definitions = setup_world(
        primary_keys=("tagus_estuary_modifier",),
        primary_active=("tagus_estuary_modifier",),
        kind=True,
    )

    result = memory.read_predicates(reader, BASE, province_binding(), ["tagus_estuary_modifier"])

    predicate = result["predicates"]["tagus_estuary_modifier"]
    assert result["status"] == "known"
    assert result["complete"] is False
    assert predicate["status"] == "known" and predicate["value"] is True
    assert predicate["raw_inputs"]["primary_kind"]["method_rva"] == hex(memory.SUPPORTED_TRUE_METHOD_RVA)
    assert predicate["raw_inputs"]["selected_container"]["entries"][0]["definition_pointer"] == definitions["tagus_estuary_modifier"]


def test_primary_true_complete_empty_vector_is_known_false() -> None:
    reader, _ = setup_world(primary_keys=("river_estuary_modifier",), kind=True)

    predicate = memory.read_predicates(
        reader, BASE, province_binding(), ["river_estuary_modifier"]
    )["predicates"]["river_estuary_modifier"]

    assert predicate["status"] == "known"
    assert predicate["value"] is False
    assert predicate["raw_inputs"]["selected_container"]["count"] == 0


def test_primary_false_falls_back_to_secondary_pointer_array() -> None:
    reader, definitions = setup_world(
        primary_keys=("river_estuary_modifier",),
        secondary_keys=("river_estuary_modifier",),
        secondary_active=("river_estuary_modifier",),
        kind=False,
    )

    predicate = memory.read_predicates(
        reader, BASE, province_binding(), ["river_estuary_modifier"]
    )["predicates"]["river_estuary_modifier"]

    assert predicate["status"] == "known" and predicate["value"] is True
    assert predicate["raw_inputs"]["selected_container"]["container"] == "secondary_definition_pointer_array"
    assert predicate["raw_inputs"]["selected_container"]["entries"][0]["definition_pointer"] == definitions["river_estuary_modifier"]


def test_secondary_missing_definition_is_unknown_not_false() -> None:
    reader, _ = setup_world(primary_keys=("known_other",), kind=False)

    predicate = memory.read_predicates(
        reader, BASE, province_binding(), ["absent_estuary_modifier"]
    )["predicates"]["absent_estuary_modifier"]

    assert predicate["status"] == "unknown"
    assert predicate["reason"] == "secondary_definition_missing"


def test_unmatched_primary_uses_sentinel_kind_then_secondary_fallback() -> None:
    reader, definitions = setup_world(
        secondary_keys=("seine_estuary_modifier",),
        secondary_active=("seine_estuary_modifier",),
        sentinel_kind=False,
    )

    predicate = memory.read_predicates(
        reader, BASE, province_binding(), ["seine_estuary_modifier"]
    )["predicates"]["seine_estuary_modifier"]

    assert predicate["status"] == "known" and predicate["value"] is True
    assert predicate["raw_inputs"]["primary_resolution"] == "unmatched_sentinel"
    assert predicate["raw_inputs"]["primary_kind"]["value"] is False
    assert predicate["raw_inputs"]["selected_container"]["entries"][0]["definition_pointer"] == definitions["seine_estuary_modifier"]


def test_same_named_secondary_definition_cannot_shadow_true_primary() -> None:
    reader, definitions = setup_world(
        primary_keys=("douro_estuary_modifier",),
        secondary_keys=("douro_estuary_modifier",),
        secondary_active=("douro_estuary_modifier",),
        kind=True,
    )

    predicate = memory.read_predicates(
        reader, BASE, province_binding(), ["douro_estuary_modifier"]
    )["predicates"]["douro_estuary_modifier"]

    assert predicate["status"] == "known" and predicate["value"] is False
    assert predicate["raw_inputs"]["selected_container"]["container"] == "primary_instance_vector"
    assert predicate["raw_inputs"]["selected_container"]["matched"] is False
    assert predicate["raw_inputs"]["primary_definition"]["pointer"] == hex(definitions["douro_estuary_modifier"])
    assert not any("secondary.manager_global" in label for _, _, label in reader.reads)


@pytest.mark.parametrize(
    ("key", "expected_storage"),
    [("short_key", "inline"), ("long_river_estuary_modifier", "heap")],
)
def test_definition_key_supports_inline_and_heap_string32(key: str, expected_storage: str) -> None:
    reader, _ = setup_world(primary_keys=(key,), primary_active=(key,), kind=True)

    predicate = memory.read_predicates(reader, BASE, province_binding(), [key])["predicates"][key]

    assert predicate["status"] == "known" and predicate["value"] is True
    assert predicate["raw_inputs"]["primary_definition"]["key_storage"] == expected_storage


def test_definition_key_reads_only_the_vtable_and_string32_ranges() -> None:
    key = "short_key"
    reader, definitions = setup_world(primary_keys=(key,), kind=True)

    predicate = memory.read_predicates(reader, BASE, province_binding(), [key])["predicates"][key]

    assert predicate["status"] == "known" and predicate["value"] is False
    definition = definitions[key]
    reads = [(address, size, label) for address, size, label in reader.reads
             if label in {"modifier.definition_vtable", "modifier.definition_key_string32"}]
    assert reads == [
        (definition, memory.DEFINITION_VTABLE_WIDTH, "modifier.definition_vtable"),
        (definition + memory.DEFINITION_KEY_OFFSET, memory.DEFINITION_KEY_STRING32_WIDTH,
         "modifier.definition_key_string32"),
    ]
    assert all(size != 0x178 for _, size, _ in reader.reads)
    candidate = predicate["raw_inputs"]["primary_lookup"]["candidates"][0]
    assert candidate["vtable_raw_hex"] == (BASE + VTABLE_RVA).to_bytes(8, "little").hex()
    assert candidate["key_string32_raw_hex"] == bytes(reader.bytes[
        definition + memory.DEFINITION_KEY_OFFSET + offset
    ] for offset in range(memory.DEFINITION_KEY_STRING32_WIDTH)).hex()


@pytest.mark.parametrize("label", [
    "modifier.definition_vtable",
    "modifier.definition_key_string32",
])
def test_short_definition_key_reads_remain_unknown(label: str) -> None:
    reader, _ = setup_world(primary_keys=("short_key",), kind=True)
    reader.short_labels.add(label)

    predicate = memory.read_predicates(
        reader, BASE, province_binding(), ["short_key"]
    )["predicates"]["short_key"]

    assert predicate["status"] == "unknown"
    assert predicate["reason"] == "short_read"


def test_bucket_collision_walks_chain_and_resolves_exact_key() -> None:
    reader, _ = setup_world(
        primary_keys=("first_key", "second_key"),
        primary_active=("second_key",),
        kind=True,
    )

    predicate = memory.read_predicates(reader, BASE, province_binding(), ["second_key"])["predicates"]["second_key"]

    assert predicate["status"] == "known" and predicate["value"] is True
    assert predicate["raw_inputs"]["primary_lookup"]["bucket_count"] == 1
    assert predicate["raw_inputs"]["primary_lookup"]["nodes_examined"] == 2


def test_bucket_cycle_is_unknown_even_when_requested_key_was_seen() -> None:
    reader, _ = setup_world(
        primary_keys=("cycle_key", "other_key"),
        kind=True,
        cycle_primary=True,
    )

    predicate = memory.read_predicates(reader, BASE, province_binding(), ["cycle_key"])["predicates"]["cycle_key"]

    assert predicate["status"] == "unknown"
    assert predicate["reason"] == "primary_chain_cycle_detected"


def test_bucket_chain_bound_is_enforced() -> None:
    keys = tuple(f"modifier_{index}" for index in range(memory.MAX_CHAIN_NODES))
    reader, _ = setup_world(primary_keys=keys, kind=True, chain_cap_primary=True)

    predicate = memory.read_predicates(reader, BASE, province_binding(), ["not_in_chain"])["predicates"]["not_in_chain"]

    assert predicate["status"] == "unknown"
    assert predicate["reason"] == "primary_chain_limit_exceeded"


def test_negative_secondary_count_is_unknown() -> None:
    reader, _ = setup_world(
        primary_keys=("modifier_type_false",),
        secondary_keys=("modifier_type_false",),
        kind=False,
        secondary_count=-1,
    )

    predicate = memory.read_predicates(reader, BASE, province_binding(), ["modifier_type_false"])["predicates"]["modifier_type_false"]

    assert predicate["status"] == "unknown"
    assert predicate["reason"] == "province_secondary_array_negative_count"


def test_unaligned_primary_vector_is_unknown() -> None:
    reader, _ = setup_world(
        primary_keys=("misaligned_key",),
        primary_active=("misaligned_key",),
        kind=True,
        unaligned_primary=True,
    )

    predicate = memory.read_predicates(reader, BASE, province_binding(), ["misaligned_key"])["predicates"]["misaligned_key"]

    assert predicate["status"] == "unknown"
    assert "unaligned" in predicate["reason"]


def test_short_read_of_primary_bucket_is_unknown_not_false() -> None:
    reader, _ = setup_world(primary_keys=("short_read_key",), kind=True)
    reader.short_labels.add("primary.bucket_head[0]")

    predicate = memory.read_predicates(reader, BASE, province_binding(), ["short_read_key"])["predicates"]["short_read_key"]

    assert predicate["status"] == "unknown"
    assert predicate["reason"] == "short_read"


def test_unknown_kind_method_is_unknown_and_never_invoked() -> None:
    reader, _ = setup_world(primary_keys=("unknown_method_key",), kind=True)
    reader.u64(BASE + VTABLE_RVA + memory.DEFINITION_KIND_SLOT_OFFSET, BASE + 0x8F460)

    predicate = memory.read_predicates(reader, BASE, province_binding(), ["unknown_method_key"])["predicates"]["unknown_method_key"]

    assert predicate["status"] == "unknown"
    assert predicate["reason"] == "modifier_definition_kind_method_unsupported"
    assert not any(address == BASE + 0x8F460 for address, _, _ in reader.reads)


def test_invalid_binding_key_list_and_budget_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    reader, _ = setup_world(primary_keys=("valid_key",), kind=True)
    invalid_binding = memory.read_predicates(reader, BASE, province_binding(0x10000), ["valid_key"])
    assert invalid_binding["predicates"]["valid_key"]["status"] == "unknown"
    assert reader.reads == []

    invalid_keys = memory.read_predicates(reader, BASE, province_binding(), ["bad key"])
    assert invalid_keys["reason"] == "modifier_key_invalid"
    assert reader.reads == []

    monkeypatch.setattr(memory, "MAX_READ_BYTES", 16)
    over_budget = memory.read_predicates(reader, BASE, province_binding(), ["valid_key"])
    assert over_budget["predicates"]["valid_key"]["status"] == "unknown"
    assert over_budget["predicates"]["valid_key"]["reason"] == "read_budget_exceeded"


def test_callable_reader_is_supported() -> None:
    reader, _ = setup_world(primary_keys=("callable_key",), primary_active=("callable_key",))

    result = memory.read_predicates(reader.read, BASE, province_binding(), ["callable_key"])

    assert result["predicates"]["callable_key"]["status"] == "known"
    assert result["predicates"]["callable_key"]["value"] is True


@pytest.mark.parametrize("drift", ["global", "header"])
def test_manager_global_or_header_drift_retracts_predicate(drift: str) -> None:
    reader, _ = setup_world(primary_keys=("stable_key",), primary_active=("stable_key",))
    if drift == "global":
        reader.mutate_on_read["primary.manager_global_recheck"] = (
            BASE + memory.PRIMARY_MANAGER_GLOBAL_RVA,
            (PRIMARY_MANAGER + 0x1000).to_bytes(8, "little"),
        )
    else:
        reader.mutate_on_read["primary.manager_header_recheck"] = (
            PRIMARY_MANAGER + memory.MANAGER_BUCKET_COUNT_OFFSET,
            (2).to_bytes(4, "little"),
        )

    predicate = memory.read_predicates(reader, BASE, province_binding(), ["stable_key"])["predicates"]["stable_key"]

    assert predicate["status"] == "unknown"
    assert predicate["reason"].startswith("leaf_context_changed:primary:")
