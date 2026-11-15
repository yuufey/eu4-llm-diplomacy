"""Leaf tests for the bounded native has-port province predicate."""
from __future__ import annotations

import struct

import pytest

from bridge.information.province_identity_memory import MAX_FIELDS
from bridge.information.province_port_memory import (
    FIELD_HAS_PORT,
    MAX_PROVINCE_ID,
    PROVINCE_HAS_PORT_PREDICATE_OFFSET,
    READ_LABEL,
    read_fields,
)


BASE = 0x140000000
RECORD = 0x100000000
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


def province_binding(
    province_id: int = PROVINCE_ID,
    record: int = RECORD,
) -> dict[str, object]:
    return {
        "province_id": province_id,
        "record_id": province_id,
        "record_pointer": hex(record),
        "id_address": hex(record + 0x20),
        "id_raw_hex": struct.pack("<i", province_id).hex(),
    }


def setup_port_predicate(
    raw_value: int,
    *,
    record: int = RECORD,
) -> FakeMemory:
    memory = FakeMemory()
    memory.write(
        record + PROVINCE_HAS_PORT_PREDICATE_OFFSET,
        struct.pack("<Q", raw_value),
    )
    return memory


@pytest.mark.parametrize(
    ("raw_value", "expected"),
    [
        (0, False),
        (1, True),
        (0xDEADBEEFCAFE0042, True),
    ],
)
def test_nonzero_native_scope_qword_is_the_only_boolean_predicate(
    raw_value: int,
    expected: bool,
) -> None:
    memory = setup_port_predicate(raw_value)

    leaf = read_fields(
        memory,
        BASE,
        province_binding(),
        (FIELD_HAS_PORT,),
    )[FIELD_HAS_PORT]

    assert leaf["status"] == "known"
    assert leaf["value"] is expected
    assert leaf["complete"] is False
    assert leaf["basis"] == "native_has_port_scope_predicate"
    assert leaf["raw_inputs"]["module_base"] == hex(BASE)
    assert leaf["raw_inputs"]["province_binding"]["province_id"] == PROVINCE_ID
    assert leaf["raw_inputs"]["predicate_address"] == hex(
        RECORD + PROVINCE_HAS_PORT_PREDICATE_OFFSET
    )
    assert leaf["raw_inputs"]["predicate_raw_hex"] == struct.pack("<Q", raw_value).hex()
    assert leaf["raw_inputs"]["predicate_raw_value"] == raw_value
    assert leaf["raw_inputs"]["predicate_nonzero"] is expected
    # The nonzero value is not treated as a pointer: the leaf performs one read.
    assert memory.reads == [
        (
            RECORD + PROVINCE_HAS_PORT_PREDICATE_OFFSET,
            8,
            READ_LABEL,
        )
    ]
    assert "PORT_FACILITIES_AND_ACCESS_ELIGIBILITY_NOT_READ" in leaf["gaps"]
    assert "ESTUARY_STATE_NOT_READ" in leaf["gaps"]
    assert "RENDERING_NOT_OBSERVED" in leaf["gaps"]


@pytest.mark.parametrize(
    ("province_id", "reason"),
    [
        (0, "province_id_invalid"),
        (-1, "province_id_invalid"),
        (MAX_PROVINCE_ID + 1, "province_id_out_of_supported_range"),
    ],
)
def test_out_of_scope_province_binding_is_unknown_without_read(
    province_id: int,
    reason: str,
) -> None:
    memory = setup_port_predicate(1)

    leaf = read_fields(
        memory,
        BASE,
        province_binding(province_id),
        (FIELD_HAS_PORT,),
    )[FIELD_HAS_PORT]

    assert leaf["status"] == "unknown"
    assert leaf["reason"] == reason
    assert leaf["complete"] is False
    assert "value" not in leaf
    assert memory.reads == []


def test_noncanonical_binding_is_unknown_without_read() -> None:
    memory = setup_port_predicate(1)
    binding = province_binding()
    binding["id_raw_hex"] = "b8000000"

    leaf = read_fields(memory, BASE, binding, (FIELD_HAS_PORT,))[FIELD_HAS_PORT]

    assert leaf["status"] == "unknown"
    assert leaf["reason"] == "province_id_raw_mismatch"
    assert leaf["raw_inputs"]["module_base"] == BASE
    assert memory.reads == []


@pytest.mark.parametrize("short", [False, True])
def test_read_error_or_short_qword_is_unknown_not_false(short: bool) -> None:
    memory = setup_port_predicate(0)
    if short:
        memory.short_labels.add(READ_LABEL)
    else:
        memory.fail_labels.add(READ_LABEL)

    leaf = read_fields(memory, BASE, province_binding(), (FIELD_HAS_PORT,))[FIELD_HAS_PORT]

    assert leaf["status"] == "unknown"
    assert "HAS_PORT_PREDICATE_READ_FAILED" in leaf["reason"]
    assert "value" not in leaf
    assert leaf["raw_inputs"]["predicate_address"] == hex(
        RECORD + PROVINCE_HAS_PORT_PREDICATE_OFFSET
    )
    assert len(leaf["raw_inputs"]["read_failures"]) == 1
    assert leaf["raw_inputs"]["read_failures"][0]["label"] == READ_LABEL
    assert memory.reads == [
        (RECORD + PROVINCE_HAS_PORT_PREDICATE_OFFSET, 8, READ_LABEL)
    ]


def test_bad_field_lists_unsupported_and_duplicates_do_not_read() -> None:
    memory = FakeMemory()

    assert read_fields(memory, BASE, province_binding(), ()) == {}
    assert read_fields(memory, BASE, province_binding(), FIELD_HAS_PORT) == {}
    assert read_fields(memory, BASE, province_binding(), [FIELD_HAS_PORT, None]) == {}
    assert read_fields(
        memory,
        BASE,
        province_binding(),
        [f"G02.other_{index}" for index in range(MAX_FIELDS + 1)],
    ) == {}

    unsupported = read_fields(memory, BASE, province_binding(), ("G02.owner",))
    assert unsupported["G02.owner"]["status"] == "unknown"
    assert unsupported["G02.owner"]["reason"] == "unsupported_field"

    duplicate = read_fields(
        memory,
        BASE,
        province_binding(),
        (FIELD_HAS_PORT, FIELD_HAS_PORT),
    )
    assert duplicate[FIELD_HAS_PORT]["status"] == "unknown"
    assert duplicate[FIELD_HAS_PORT]["reason"] == "duplicate_field_requested"
    assert memory.reads == []


@pytest.mark.parametrize("province_id", [1, MAX_PROVINCE_ID])
def test_supported_province_id_boundaries_and_mixed_unsupported_request(
    province_id: int,
) -> None:
    memory = setup_port_predicate(0)

    result = read_fields(
        memory,
        BASE,
        province_binding(province_id),
        ("G02.owner", FIELD_HAS_PORT),
    )

    assert result["G02.owner"]["status"] == "unknown"
    assert result["G02.owner"]["reason"] == "unsupported_field"
    assert result[FIELD_HAS_PORT]["status"] == "known"
    assert result[FIELD_HAS_PORT]["value"] is False
    assert result[FIELD_HAS_PORT]["raw_inputs"]["province_binding"]["province_id"] == province_id
    assert len(memory.reads) == 1
