from __future__ import annotations

import struct

import pytest

from bridge.information.province_identity_memory import (
    CULTURE_NAME_OFFSET,
    CULTURE_POINTER_OFFSET,
    FIELD_CULTURE,
    FIELD_RELIGION,
    MAX_FIELDS,
    RELIGION_ICON_FRAME_OFFSET,
    RELIGION_NAME_OFFSET,
    RELIGION_POINTER_OFFSET,
    STRING32_SIZE,
    read_fields,
)


BASE = 0x140000000
RECORD = 0x100000000
FIELD_OBJECT = 0x200000000
RELIGION_OBJECT = 0x300000000
HEAP = 0x400000000
PROVINCE_ID = 183
UTF_ESCAPE_NAME = bytes.fromhex("10295911494e105965")  # 天主教


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


def put_definition_pointer(memory: FakeMemory, field: str, pointer: int) -> None:
    offset = CULTURE_POINTER_OFFSET if field == FIELD_CULTURE else RELIGION_POINTER_OFFSET
    memory.write(RECORD + offset, struct.pack("<Q", pointer))


def string32_inline(name: bytes, capacity: int = 15) -> bytes:
    assert 0 < len(name) <= 15
    header = bytearray(STRING32_SIZE)
    header[:len(name) + 1] = name + b"\0"
    struct.pack_into("<Q", header, 0x10, len(name))
    struct.pack_into("<Q", header, 0x18, capacity)
    return bytes(header)


def string32_heap(heap_pointer: int, name: bytes, capacity: int = 64) -> bytes:
    header = bytearray(STRING32_SIZE)
    struct.pack_into("<Q", header, 0, heap_pointer)
    struct.pack_into("<Q", header, 0x10, len(name))
    struct.pack_into("<Q", header, 0x18, capacity)
    return bytes(header)


def setup_culture_inline(name: bytes = UTF_ESCAPE_NAME,
                         *, memory: FakeMemory | None = None) -> FakeMemory:
    memory = memory or FakeMemory()
    put_definition_pointer(memory, FIELD_CULTURE, FIELD_OBJECT)
    memory.write(FIELD_OBJECT + CULTURE_NAME_OFFSET, string32_inline(name))
    return memory


def setup_religion_inline(name: bytes = b"animism",
                          frame: int = -7,
                          *, memory: FakeMemory | None = None) -> FakeMemory:
    memory = memory or FakeMemory()
    put_definition_pointer(memory, FIELD_RELIGION, RELIGION_OBJECT)
    memory.write(RELIGION_OBJECT + RELIGION_NAME_OFFSET, string32_inline(name))
    memory.write(
        RELIGION_OBJECT + RELIGION_ICON_FRAME_OFFSET,
        struct.pack("<i", frame),
    )
    return memory


def test_inline_eu4_escape_culture_and_religion_frame_are_known() -> None:
    memory = setup_culture_inline()
    setup_religion_inline(memory=memory)

    result = read_fields(
        memory,
        BASE,
        province_binding(),
        [FIELD_CULTURE, FIELD_RELIGION],
    )

    assert result[FIELD_CULTURE]["status"] == "known"
    assert result[FIELD_CULTURE]["complete"] is False
    assert result[FIELD_CULTURE]["value"]["name"] == {
        "text": "天主教",
        "raw_hex": UTF_ESCAPE_NAME.hex(),
        "encoding": "eu4_escape",
    }
    assert result[FIELD_RELIGION]["status"] == "known"
    assert result[FIELD_RELIGION]["value"]["name"]["text"] == "animism"
    assert result[FIELD_RELIGION]["value"]["icon_frame_request"] == -7
    assert result[FIELD_RELIGION]["raw_inputs"]["icon_frame_request_raw_hex"] == struct.pack("<i", -7).hex()
    assert not any("culture.icon" in label for _, _, label in memory.reads)
    assert result[FIELD_CULTURE]["basis"] == result[FIELD_RELIGION]["basis"]


def test_heap_name_is_bounded_and_keeps_pointer_payload_raw() -> None:
    memory = FakeMemory()
    put_definition_pointer(memory, FIELD_CULTURE, FIELD_OBJECT)
    memory.write(FIELD_OBJECT + CULTURE_NAME_OFFSET, string32_heap(HEAP, b"Zulu"))
    memory.write(HEAP, b"Zulu\0")

    result = read_fields(memory, BASE, province_binding(), (FIELD_CULTURE,))
    leaf = result[FIELD_CULTURE]

    assert leaf["status"] == "known"
    assert leaf["value"]["name"] == {
        "text": "Zulu",
        "raw_hex": b"Zulu".hex(),
        "encoding": "eu4_escape",
    }
    assert leaf["raw_inputs"]["string32_storage"] == "heap"
    assert leaf["raw_inputs"]["string32_heap_pointer"] == hex(HEAP)
    assert leaf["raw_inputs"]["string32_heap_payload_raw_hex"] == b"Zulu\0".hex()


def test_unsupported_field_and_empty_request_issue_no_reads() -> None:
    memory = FakeMemory()

    unsupported = read_fields(memory, BASE, province_binding(), ("G02.owner",))
    assert unsupported["G02.owner"]["status"] == "unknown"
    assert unsupported["G02.owner"]["reason"] == "unsupported_field"
    assert read_fields(memory, BASE, province_binding(), ()) == {}
    assert memory.reads == []


def test_duplicate_and_oversized_field_lists_fail_without_reads() -> None:
    memory = FakeMemory()

    duplicate = read_fields(memory, BASE, province_binding(), (FIELD_CULTURE, FIELD_CULTURE))
    assert duplicate[FIELD_CULTURE]["reason"] == "duplicate_field_requested"
    assert read_fields(memory, BASE, province_binding(), ["x"] * (MAX_FIELDS + 1)) == {}
    assert read_fields(memory, BASE, province_binding(), "G02.culture") == {}
    assert memory.reads == []


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda binding: binding.update(record_id=184), "province_record_id_mismatch"),
        (lambda binding: binding.update(id_address=hex(RECORD + 0x24)), "province_id_address_mismatch"),
        (lambda binding: binding.update(id_raw_hex="b8000000"), "province_id_raw_mismatch"),
        (lambda binding: binding.update(record_pointer="0x1"), "record_pointer_out_of_user_bounds"),
        (lambda binding: binding.update(record_pointer="0x100000001"), "record_pointer_unaligned"),
    ],
)
def test_invalid_canonical_binding_returns_unknown_without_reading(mutate, reason: str) -> None:
    memory = FakeMemory()
    binding = province_binding()
    mutate(binding)

    leaf = read_fields(memory, BASE, binding, (FIELD_CULTURE,))[FIELD_CULTURE]

    assert leaf["status"] == "unknown"
    assert leaf["reason"] == reason
    assert memory.reads == []


def test_null_definition_pointer_is_unknown_and_preserves_pointer_bytes() -> None:
    memory = FakeMemory()
    memory.write(RECORD + CULTURE_POINTER_OFFSET, b"\0" * 8)

    leaf = read_fields(memory, BASE, province_binding(), (FIELD_CULTURE,))[FIELD_CULTURE]

    assert leaf["status"] == "unknown"
    assert leaf["reason"] == "culture_definition_pointer_null"
    assert leaf["raw_inputs"]["definition_pointer_raw_hex"] == "00" * 8
    assert len(memory.reads) == 1


@pytest.mark.parametrize(
    ("name", "capacity", "expected_reason"),
    [
        (b"", 15, "culture_name_empty"),
        (b"123456789012345", 15, None),
        (b"1234567890123456", 15, "culture_string32_capacity_below_length"),
        (b"long", 3, "culture_string32_capacity_below_length"),
    ],
)
def test_inline_length_and_capacity_boundaries(name: bytes, capacity: int,
                                                expected_reason: str | None) -> None:
    memory = FakeMemory()
    put_definition_pointer(memory, FIELD_CULTURE, FIELD_OBJECT)
    header = bytearray(STRING32_SIZE)
    inline = name + b"\0"
    header[:min(len(inline), 16)] = inline[:16]
    struct.pack_into("<Q", header, 0x10, len(name))
    struct.pack_into("<Q", header, 0x18, capacity)
    memory.write(FIELD_OBJECT + CULTURE_NAME_OFFSET, bytes(header))

    leaf = read_fields(memory, BASE, province_binding(), (FIELD_CULTURE,))[FIELD_CULTURE]

    if expected_reason is None:
        assert leaf["status"] == "known"
        assert leaf["value"]["name"]["text"] == "123456789012345"
    else:
        assert leaf["status"] == "unknown"
        assert leaf["reason"] == expected_reason
    assert leaf["raw_inputs"]["string32_header_raw_hex"] == bytes(header).hex()


def test_empty_heap_invalid_capacity_and_heap_header_alias_are_unknown() -> None:
    cases = (
        (string32_heap(HEAP, b"A", capacity=129), None, "culture_string32_capacity_out_of_bound"),
        (string32_heap(HEAP, b"AB", capacity=16), b"AB\0", None),
        (string32_heap(FIELD_OBJECT + CULTURE_NAME_OFFSET + 4, b"AB", capacity=16),
         None, "culture_string32_heap_overlaps_header"),
    )
    for header, payload, expected_reason in cases:
        memory = FakeMemory()
        put_definition_pointer(memory, FIELD_CULTURE, FIELD_OBJECT)
        memory.write(FIELD_OBJECT + CULTURE_NAME_OFFSET, header)
        heap_pointer = int.from_bytes(header[:8], "little")
        if payload is not None:
            memory.write(heap_pointer, payload)

        leaf = read_fields(memory, BASE, province_binding(), (FIELD_CULTURE,))[FIELD_CULTURE]
        if expected_reason is None:
            assert leaf["status"] == "known"
            assert leaf["value"]["name"]["text"] == "AB"
        else:
            assert leaf["status"] == "unknown"
            assert leaf["reason"] == expected_reason


def test_terminator_embedded_nul_and_malformed_escape_are_unknown() -> None:
    inputs = (
        (b"A", b"!", "culture_string32_terminator_invalid"),
        (b"A\0B", b"\0", "culture_string32_embedded_nul"),
        (b"\x10\x41", b"\0", "culture_name_decode_invalid"),
    )
    for raw, terminator, expected_reason in inputs:
        memory = FakeMemory()
        put_definition_pointer(memory, FIELD_CULTURE, FIELD_OBJECT)
        header = bytearray(STRING32_SIZE)
        header[:len(raw) + 1] = raw + terminator
        struct.pack_into("<Q", header, 0x10, len(raw))
        struct.pack_into("<Q", header, 0x18, 15)
        memory.write(FIELD_OBJECT + CULTURE_NAME_OFFSET, header)

        leaf = read_fields(memory, BASE, province_binding(), (FIELD_CULTURE,))[FIELD_CULTURE]
        assert leaf["status"] == "unknown"
        assert leaf["reason"] == expected_reason
        assert "string32_header_raw_hex" in leaf["raw_inputs"]


def test_religion_name_or_icon_failure_keeps_other_raw_inputs_but_is_unknown() -> None:
    memory = setup_religion_inline()
    memory.fail_labels.add("province_identity.religion.icon_frame_request")

    leaf = read_fields(memory, BASE, province_binding(), (FIELD_RELIGION,))[FIELD_RELIGION]

    assert leaf["status"] == "unknown"
    assert leaf["reason"] == "religion_icon_frame_request_read_failed"
    assert "string32_header_raw_hex" in leaf["raw_inputs"]
    assert leaf["raw_inputs"]["read_failures"][0]["label"] == "province_identity.religion.icon_frame_request"
    assert "value" not in leaf


def test_short_header_and_heap_payload_read_failures_are_unknown() -> None:
    header_label = "province_identity.culture.String32_header"
    memory = setup_culture_inline()
    memory.short_labels.add(header_label)
    leaf = read_fields(memory, BASE, province_binding(), (FIELD_CULTURE,))[FIELD_CULTURE]
    assert leaf["status"] == "unknown"
    assert leaf["reason"] == "culture_string32_header_read_failed"
    assert leaf["raw_inputs"]["read_failures"][0]["label"] == header_label

    memory = FakeMemory()
    put_definition_pointer(memory, FIELD_CULTURE, FIELD_OBJECT)
    memory.write(FIELD_OBJECT + CULTURE_NAME_OFFSET, string32_heap(HEAP, b"AB"))
    memory.fail_labels.add("province_identity.culture.String32_payload")
    leaf = read_fields(memory, BASE, province_binding(), (FIELD_CULTURE,))[FIELD_CULTURE]
    assert leaf["status"] == "unknown"
    assert leaf["reason"] == "culture_string32_heap_payload_read_failed"
    assert leaf["raw_inputs"]["string32_heap_pointer"] == hex(HEAP)


def test_religion_frame_is_signed_i32_and_invalid_frame_range_is_unknown() -> None:
    memory = setup_religion_inline(frame=0x12345678)
    result = read_fields(memory, BASE, province_binding(), (FIELD_RELIGION,))[FIELD_RELIGION]
    assert result["status"] == "known"
    assert result["value"]["icon_frame_request"] == 0x12345678

    memory = setup_religion_inline()
    memory.short_labels.add("province_identity.religion.icon_frame_request")
    result = read_fields(memory, BASE, province_binding(), (FIELD_RELIGION,))[FIELD_RELIGION]
    assert result["status"] == "unknown"
    assert result["reason"] == "religion_icon_frame_request_read_failed"


def test_module_base_invalid_fails_before_memory_access() -> None:
    memory = setup_culture_inline()
    leaf = read_fields(memory, 0, province_binding(), (FIELD_CULTURE,))[FIELD_CULTURE]
    assert leaf["status"] == "unknown"
    assert leaf["reason"] == "module_base_out_of_user_bounds"
    assert memory.reads == []


def test_culture_failure_does_not_discard_independent_religion_value() -> None:
    memory = setup_religion_inline(frame=4)
    put_definition_pointer(memory, FIELD_CULTURE, FIELD_OBJECT)
    memory.write(FIELD_OBJECT + CULTURE_NAME_OFFSET, string32_inline(b"\x10\x41"))

    result = read_fields(memory, BASE, province_binding(), [FIELD_CULTURE, FIELD_RELIGION])

    assert result[FIELD_CULTURE]["status"] == "unknown"
    assert result[FIELD_RELIGION]["status"] == "known"
    assert result[FIELD_RELIGION]["value"]["icon_frame_request"] == 4
