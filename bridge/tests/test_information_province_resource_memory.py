from __future__ import annotations

import struct

import pytest

from bridge.information.province_resource_memory import (
    FIELD_RESOURCE,
    RESOURCE_ICON_INDEX_OFFSET,
    RESOURCE_KEY_OFFSET,
    RESOURCE_POINTER_OFFSET,
    STRING32_SIZE,
    read_fields,
)


BASE = 0x140000000
RECORD = 0x100000000
DEFINITION = 0x200000000
HEAP = 0x300000000
PROVINCE_ID = 183


class FakeMemory:
    def __init__(self) -> None:
        self.bytes: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.fail_labels: set[str] = set()
        self.short_labels: set[str] = set()

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
        if label in self.short_labels:
            return result[:-1]
        return result


def province_binding(province_id: int = PROVINCE_ID, record: int = RECORD) -> dict:
    return {
        "province_id": province_id,
        "record_id": province_id,
        "record_pointer": hex(record),
        "id_address": hex(record + 0x20),
        "id_raw_hex": struct.pack("<i", province_id).hex(),
    }


def string32_inline(key: bytes, capacity: int = 15, *, terminator: int = 0) -> bytes:
    header = bytearray(STRING32_SIZE)
    if key:
        header[:len(key)] = key
        header[len(key)] = terminator
    struct.pack_into("<Q", header, 0x10, len(key))
    struct.pack_into("<Q", header, 0x18, capacity)
    return bytes(header)


def string32_heap(pointer: int, key: bytes, capacity: int | None = None) -> bytes:
    header = bytearray(STRING32_SIZE)
    struct.pack_into("<Q", header, 0, pointer)
    struct.pack_into("<Q", header, 0x10, len(key))
    struct.pack_into("<Q", header, 0x18, len(key) if capacity is None else capacity)
    return bytes(header)


def setup(key: bytes = b"grain", icon: int = 0, *, heap: bool = False,
          capacity: int | None = None, terminator: int = 0) -> FakeMemory:
    memory = FakeMemory()
    memory.write(RECORD + RESOURCE_POINTER_OFFSET, struct.pack("<Q", DEFINITION))
    if heap:
        memory.write(DEFINITION + RESOURCE_KEY_OFFSET,
                     string32_heap(HEAP, key, capacity))
        memory.write(HEAP, key + bytes((terminator,)))
    else:
        memory.write(DEFINITION + RESOURCE_KEY_OFFSET,
                     string32_inline(key, 15 if capacity is None else capacity,
                                     terminator=terminator))
    memory.write(DEFINITION + RESOURCE_ICON_INDEX_OFFSET, struct.pack("<i", icon))
    return memory


def leaf(memory: FakeMemory, binding: dict | None = None) -> dict:
    return read_fields(memory, BASE, province_binding() if binding is None else binding,
                       (FIELD_RESOURCE,))[FIELD_RESOURCE]


def test_inline_localization_key_and_negative_icon_index_are_raw_inputs_only() -> None:
    memory = setup(b"grain", -1)
    result = leaf(memory)
    assert result["status"] == "known"
    assert result["value"] == {"localization_key": "grain", "icon_index": -1}
    assert result["complete"] is False
    assert result["raw_inputs"]["string32_storage"] == "inline"
    assert result["raw_inputs"]["localization_key_raw_hex"] == b"grain".hex()
    assert result["raw_inputs"]["icon_index_raw_hex"] == "ffffffff"
    assert [row[2] for row in memory.reads] == [
        "province_resource.definition_pointer",
        "province_resource.String32_header",
        "province_resource.icon_index",
    ]


@pytest.mark.parametrize("icon", [-(1 << 31), (1 << 31) - 1])
def test_heap_key_and_signed_i32_icon_boundaries(icon: int) -> None:
    key = b"trade_goods_major"
    memory = setup(key, icon, heap=True, capacity=64)
    result = leaf(memory)
    assert result["status"] == "known"
    assert result["value"] == {"localization_key": key.decode("ascii"), "icon_index": icon}
    assert result["raw_inputs"]["string32_storage"] == "heap"
    assert result["raw_inputs"]["string32_heap_pointer"] == hex(HEAP)
    assert result["raw_inputs"]["string32_heap_payload_raw_hex"] == (key + b"\0").hex()


def test_maximum_key_length_is_bounded_and_accepted() -> None:
    key = b"A" * 128
    memory = setup(key, 4, heap=True, capacity=128)
    result = leaf(memory)
    assert result["status"] == "known"
    assert result["value"]["localization_key"] == key.decode("ascii")


def test_unsupported_field_is_unknown_without_reads() -> None:
    memory = FakeMemory()
    result = read_fields(memory, BASE, province_binding(), ("G02.owner",))
    assert result["G02.owner"]["status"] == "unknown"
    assert result["G02.owner"]["reason"] == "unsupported_field"
    assert "value" not in result["G02.owner"]
    assert memory.reads == []


def test_mixed_fields_reads_only_the_supported_resource_field() -> None:
    memory = setup(b"grain", 2)
    result = read_fields(memory, BASE, province_binding(), ("G02.owner", FIELD_RESOURCE))
    assert result["G02.owner"]["reason"] == "unsupported_field"
    assert result[FIELD_RESOURCE]["value"] == {"localization_key": "grain", "icon_index": 2}
    assert all(row[2].startswith("province_resource.") for row in memory.reads)


@pytest.mark.parametrize("binding", [
    {"province_id": PROVINCE_ID, "record_id": PROVINCE_ID + 1,
     "record_pointer": hex(RECORD), "id_address": hex(RECORD + 0x20),
     "id_raw_hex": struct.pack("<i", PROVINCE_ID).hex()},
    province_binding(0x10000),
    province_binding(True),
])
def test_bad_binding_and_unsupported_province_id_issue_no_reads(binding: dict) -> None:
    memory = FakeMemory()
    result = read_fields(memory, BASE, binding, (FIELD_RESOURCE,))[FIELD_RESOURCE]
    assert result["status"] == "unknown"
    assert memory.reads == []


@pytest.mark.parametrize("pointer,reason", [
    (0, "resource_definition_pointer_null"),
    (DEFINITION + 1, "resource_definition_pointer_unaligned"),
    (RECORD + 0x100, "resource_definition_aliases_province_record"),
    (0x7FFFFFFFFFF8, "resource_definition_extent_out_of_user_bounds"),
])
def test_null_unaligned_alias_and_out_of_user_definition_pointer(pointer: int, reason: str) -> None:
    memory = FakeMemory()
    memory.write(RECORD + RESOURCE_POINTER_OFFSET, struct.pack("<Q", pointer))
    result = leaf(memory)
    assert result["status"] == "unknown"
    assert result["reason"] == reason
    assert len(memory.reads) == 1


@pytest.mark.parametrize("key,reason", [
    (b"", "resource_key_length_out_of_range"),
    (b"bad key", "resource_localization_key_ascii_grammar_invalid"),
    (b"bad/key", "resource_localization_key_ascii_grammar_invalid"),
    (b"cafe\xe9", "resource_localization_key_ascii_grammar_invalid"),
    (b"nul\0key", "resource_string32_embedded_nul"),
])
def test_empty_embedded_nul_non_ascii_and_invalid_key_grammar(key: bytes, reason: str) -> None:
    memory = setup(key, 3)
    result = leaf(memory)
    assert result["status"] == "unknown"
    assert result["reason"] == reason


@pytest.mark.parametrize("capacity,heap,key,reason", [
    (4, False, b"grain", "resource_string32_capacity_invalid"),
    (129, True, b"grain", "resource_string32_capacity_invalid"),
    (15, False, b"A" * 16, "resource_string32_capacity_invalid"),
    (16, True, b"A" * 17, "resource_string32_capacity_invalid"),
])
def test_invalid_capacity_and_inline_heap_boundaries(capacity: int, heap: bool,
                                                     key: bytes, reason: str) -> None:
    memory = setup(key, 3, heap=heap, capacity=capacity)
    result = leaf(memory)
    assert result["status"] == "unknown"
    assert result["reason"] == reason


def test_string32_missing_terminator_and_heap_header_alias_are_rejected() -> None:
    no_nul = setup(b"grain", 1, terminator=ord("x"))
    result = leaf(no_nul)
    assert result["status"] == "unknown"
    assert result["reason"] == "resource_string32_terminator_invalid"

    alias = FakeMemory()
    alias.write(RECORD + RESOURCE_POINTER_OFFSET, struct.pack("<Q", DEFINITION))
    alias.write(DEFINITION + RESOURCE_KEY_OFFSET,
                string32_heap(DEFINITION + RESOURCE_KEY_OFFSET, b"grain", 32))
    result = leaf(alias)
    assert result["status"] == "unknown"
    assert result["reason"] == "resource_string32_heap_alias"
    assert len(alias.reads) == 2


@pytest.mark.parametrize("failure_label,short", [
    ("province_resource.definition_pointer", False),
    ("province_resource.definition_pointer", True),
    ("province_resource.String32_header", False),
    ("province_resource.String32_header", True),
    ("province_resource.icon_index", False),
    ("province_resource.icon_index", True),
])
def test_reader_exception_and_short_read_fail_closed(failure_label: str, short: bool) -> None:
    memory = setup(b"grain", 1)
    if short:
        memory.short_labels.add(failure_label)
    else:
        memory.fail_labels.add(failure_label)
    result = leaf(memory)
    assert result["status"] == "unknown"
    assert "read_failed" in result["reason"]
    assert result["raw_inputs"]["read_failures"][-1]["label"] == failure_label


@pytest.mark.parametrize("fields", [(), (FIELD_RESOURCE, FIELD_RESOURCE)])
def test_empty_and_duplicate_field_requests_issue_no_reads(fields: tuple[str, ...]) -> None:
    memory = FakeMemory()
    result = read_fields(memory, BASE, province_binding(), fields)
    assert memory.reads == []
    if fields:
        assert result[FIELD_RESOURCE]["reason"] == "duplicate_field_requested"
    else:
        assert result == {}
