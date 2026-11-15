from __future__ import annotations

import struct

import pytest

from bridge.information.province_cot_memory import (
    FIELD_CENTER_OF_TRADE,
    MAX_PROVINCE_ID,
    PROVINCE_CENTER_OF_TRADE_POINTER_OFFSET,
    read_fields,
)
from bridge.information.province_identity_memory import MAX_FIELDS


BASE = 0x140000000
RECORD = 0x100000000
COT_OBJECT = 0x200000000
DEFINITION = 0x300000000
PROVINCE_ID = 183
POINTER_LABEL = "province_cot.center_of_trade_pointer"
DEFINITION_POINTER_LABEL = "province_cot.definition_pointer"
KIND_LABEL = "province_cot.definition_kind"
LEVEL_LABEL = "province_cot.definition_level"


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


def province_binding(province_id: int = PROVINCE_ID,
                     record: int = RECORD) -> dict[str, object]:
    return {
        "province_id": province_id,
        "record_id": province_id,
        "record_pointer": hex(record),
        "id_address": hex(record + 0x20),
        "id_raw_hex": struct.pack("<i", province_id).hex(),
    }


def setup_center_of_trade(*, kind: int = 1, level: int = 1,
                          province_id: int = PROVINCE_ID,
                          record: int = RECORD,
                          cot_object: int = COT_OBJECT,
                          definition: int = DEFINITION) -> FakeMemory:
    memory = FakeMemory()
    memory.write(
        record + PROVINCE_CENTER_OF_TRADE_POINTER_OFFSET,
        struct.pack("<Q", cot_object),
    )
    memory.write(cot_object + 0x8, struct.pack("<Q", definition))
    memory.write(definition + 0x10, struct.pack("<i", kind))
    memory.write(definition + 0x14, struct.pack("<i", level))
    return memory


def test_null_center_of_trade_is_known_absent_and_short_circuits() -> None:
    memory = FakeMemory()
    memory.write(RECORD + PROVINCE_CENTER_OF_TRADE_POINTER_OFFSET, b"\0" * 8)

    leaf = read_fields(memory, BASE, province_binding(), (FIELD_CENTER_OF_TRADE,))[FIELD_CENTER_OF_TRADE]

    assert leaf["status"] == "known"
    assert leaf["complete"] is False
    assert leaf["value"] == {"present": False, "level": 0}
    assert leaf["raw_inputs"]["center_of_trade_pointer_raw_hex"] == "00" * 8
    assert leaf["raw_inputs"]["branch"] == "null_center_of_trade_pointer"
    assert [row[2] for row in memory.reads] == [POINTER_LABEL]


@pytest.mark.parametrize(
    ("kind", "level", "expected_kind"),
    [
        (1, 1, "coastal"),
        (1, 3, "coastal"),
        (1, 4, "coastal"),
        (0, 2, "inland"),
        (2, 8, "inland"),
        (-7, 17, "inland"),
        (-1, MAX_PROVINCE_ID, "inland"),
        (1, 0x7FFFFFFF, "coastal"),
    ],
)
def test_nonnull_center_of_trade_projects_type_and_unbounded_positive_mod_level(
    kind: int, level: int, expected_kind: str,
) -> None:
    memory = setup_center_of_trade(kind=kind, level=level)

    leaf = read_fields(memory, BASE, province_binding(), (FIELD_CENTER_OF_TRADE,))[FIELD_CENTER_OF_TRADE]

    assert leaf["status"] == "known"
    assert leaf["value"] == {
        "present": True,
        "level": level,
        "kind": expected_kind,
        "sprite_key": f"GFX_center_of_trade_{expected_kind}_{level}",
    }
    assert leaf["raw_inputs"]["definition_kind_raw"] == kind
    assert leaf["raw_inputs"]["definition_kind_raw_hex"] == struct.pack("<i", kind).hex()
    assert leaf["raw_inputs"]["definition_level"] == level
    assert leaf["raw_inputs"]["definition_level_raw_hex"] == struct.pack("<i", level).hex()
    assert leaf["basis"] == "province_center_of_trade_definition_type_and_level_sprite_request_only"
    assert leaf["complete"] is False


@pytest.mark.parametrize("level", [0, -1, -2147483648])
def test_nonpositive_signed_level_is_unknown_not_absent(level: int) -> None:
    memory = setup_center_of_trade(level=level)

    leaf = read_fields(memory, BASE, province_binding(), (FIELD_CENTER_OF_TRADE,))[FIELD_CENTER_OF_TRADE]

    assert leaf["status"] == "unknown"
    assert leaf["reason"] == "center_of_trade_level_not_positive"
    assert "value" not in leaf
    assert leaf["raw_inputs"]["definition_level"] == level
    assert leaf["raw_inputs"]["definition_level_raw_hex"] == struct.pack("<i", level).hex()


@pytest.mark.parametrize(
    ("object_pointer", "reason"),
    [
        (RECORD, "center_of_trade_object_overlaps_province_record"),
        (RECORD + PROVINCE_CENTER_OF_TRADE_POINTER_OFFSET, "center_of_trade_object_overlaps_province_record"),
        (0x1, "center_of_trade_pointer_out_of_user_bounds"),
        (COT_OBJECT + 1, "center_of_trade_pointer_unaligned"),
        (0x0000800000000000, "center_of_trade_pointer_out_of_user_bounds"),
    ],
)
def test_invalid_or_record_alias_object_pointer_reads_no_definition(
    object_pointer: int, reason: str,
) -> None:
    memory = FakeMemory()
    memory.write(RECORD + PROVINCE_CENTER_OF_TRADE_POINTER_OFFSET,
                 struct.pack("<Q", object_pointer))

    leaf = read_fields(memory, BASE, province_binding(), (FIELD_CENTER_OF_TRADE,))[FIELD_CENTER_OF_TRADE]

    assert leaf["status"] == "unknown"
    assert leaf["reason"] == reason
    assert len(memory.reads) == 1
    assert leaf["raw_inputs"]["center_of_trade_pointer"] == hex(object_pointer)


@pytest.mark.parametrize(
    ("definition_pointer", "reason"),
    [
        (0, "center_of_trade_definition_pointer_null"),
        (RECORD, "center_of_trade_definition_pointer_alias"),
        (COT_OBJECT, "center_of_trade_definition_pointer_alias"),
        (COT_OBJECT + 8, "center_of_trade_definition_overlaps_object"),
        (RECORD + 0x100, "center_of_trade_definition_overlaps_province_record"),
        (0x1, "center_of_trade_definition_pointer_out_of_user_bounds"),
        (DEFINITION + 1, "center_of_trade_definition_pointer_unaligned"),
    ],
)
def test_invalid_or_alias_definition_pointer_is_unknown_without_scalar_reads(
    definition_pointer: int, reason: str,
) -> None:
    memory = FakeMemory()
    memory.write(RECORD + PROVINCE_CENTER_OF_TRADE_POINTER_OFFSET, struct.pack("<Q", COT_OBJECT))
    memory.write(COT_OBJECT + 0x8, struct.pack("<Q", definition_pointer))

    leaf = read_fields(memory, BASE, province_binding(), (FIELD_CENTER_OF_TRADE,))[FIELD_CENTER_OF_TRADE]

    assert leaf["status"] == "unknown"
    assert leaf["reason"] == reason
    assert leaf["raw_inputs"]["definition_pointer_raw_hex"] == struct.pack("<Q", definition_pointer).hex()
    assert [row[2] for row in memory.reads] == [POINTER_LABEL, DEFINITION_POINTER_LABEL]


@pytest.mark.parametrize(
    ("label", "expected_reason"),
    [
        (POINTER_LABEL, "center_of_trade_pointer_read_failed"),
        (DEFINITION_POINTER_LABEL, "center_of_trade_definition_pointer_read_failed"),
        (KIND_LABEL, "center_of_trade_definition_scalar_read_failed"),
        (LEVEL_LABEL, "center_of_trade_definition_scalar_read_failed"),
    ],
)
@pytest.mark.parametrize("short", [False, True])
def test_failed_or_short_reads_are_unknown_with_exact_failure_row(
    label: str, expected_reason: str, short: bool,
) -> None:
    memory = setup_center_of_trade()
    if short:
        memory.short_labels.add(label)
    else:
        memory.fail_labels.add(label)

    leaf = read_fields(memory, BASE, province_binding(), (FIELD_CENTER_OF_TRADE,))[FIELD_CENTER_OF_TRADE]

    assert leaf["status"] == "unknown"
    assert leaf["reason"] == expected_reason
    assert any(row["label"] == label for row in leaf["raw_inputs"]["read_failures"])


def test_input_scope_unsupported_duplicate_and_invalid_request_do_not_read() -> None:
    memory = FakeMemory()

    unsupported = read_fields(memory, BASE, province_binding(), ("G02.owner",))
    assert unsupported["G02.owner"]["status"] == "unknown"
    assert unsupported["G02.owner"]["reason"] == "unsupported_field"
    assert read_fields(memory, BASE, province_binding(), ()) == {}
    assert read_fields(memory, BASE, province_binding(), (FIELD_CENTER_OF_TRADE,) * (MAX_FIELDS + 1)) == {}
    assert read_fields(memory, BASE, province_binding(), FIELD_CENTER_OF_TRADE) == {}
    duplicate = read_fields(memory, BASE, province_binding(), (FIELD_CENTER_OF_TRADE,) * 2)
    assert duplicate[FIELD_CENTER_OF_TRADE]["reason"] == "duplicate_field_requested"
    assert memory.reads == []


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda b: b.update(record_id=184), "province_record_id_mismatch"),
        (lambda b: b.update(id_address=hex(RECORD + 0x24)), "province_id_address_mismatch"),
        (lambda b: b.update(id_raw_hex="b8000000"), "province_id_raw_mismatch"),
        (lambda b: b.update(record_pointer="0x1"), "record_pointer_out_of_user_bounds"),
        (lambda b: b.update(province_id=65536, record_id=65536, id_raw_hex=struct.pack("<i", 65536).hex()),
         "province_id_out_of_supported_range"),
    ],
)
def test_invalid_canonical_binding_fails_before_any_memory_read(mutate, reason: str) -> None:
    memory = FakeMemory()
    binding = province_binding()
    mutate(binding)

    leaf = read_fields(memory, BASE, binding, (FIELD_CENTER_OF_TRADE,))[FIELD_CENTER_OF_TRADE]

    assert leaf["status"] == "unknown"
    assert leaf["reason"] == reason
    assert memory.reads == []


def test_supported_province_id_boundaries_and_read_object_protocol() -> None:
    for province_id in (1, MAX_PROVINCE_ID):
        memory = setup_center_of_trade(province_id=province_id)
        leaf = read_fields(memory.read, BASE, province_binding(province_id), (FIELD_CENTER_OF_TRADE,))[FIELD_CENTER_OF_TRADE]
        assert leaf["status"] == "known"
        assert leaf["raw_inputs"]["province_binding"]["province_id"] == province_id

