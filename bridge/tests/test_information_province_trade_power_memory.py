"""Boundary tests for the internal province trade-power cache reader."""
from __future__ import annotations

import struct

import pytest

from bridge.information import province_trade_power_memory as memory
from bridge.information import province_identity_memory as identity


BASE = 0x140000000
MANAGER = 0x300000000
BEGIN = 0x200000000
PROVINCE_ID = 183
RECORD = BEGIN + PROVINCE_ID * memory.PROVINCE_RECORD_STRIDE


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
    raw_value: int = 0,
    *,
    province_id: int = PROVINCE_ID,
    record: int = RECORD,
    begin: int = BEGIN,
    count: int | None = None,
    end: int | None = None,
    manager: int = MANAGER,
    id_echo: int | None = None,
) -> tuple[FakeMemory, dict[str, object]]:
    result = FakeMemory()
    if count is None:
        count = province_id + 1
    if end is None:
        end = begin + count * memory.PROVINCE_RECORD_STRIDE
    result.write(
        BASE + memory.TRADE_POWER_MANAGER_GLOBAL_RVA,
        manager.to_bytes(8, "little", signed=False),
    )
    header = begin.to_bytes(8, "little", signed=False) + end.to_bytes(8, "little", signed=False)
    result.write(manager + memory.MANAGER_HEADER_OFFSET, header)
    target = begin + province_id * memory.PROVINCE_RECORD_STRIDE
    echo = province_id if id_echo is None else id_echo
    result.write(target + memory.PROVINCE_ID_OFFSET, struct.pack("<i", echo))
    result.write(target + memory.PROVINCE_TRADE_POWER_OFFSET, struct.pack("<i", raw_value))
    return result, province_binding(province_id, record)


def read_power(reader: FakeMemory, binding: dict[str, object] | None = None):
    return memory.read_fields(
        reader,
        BASE,
        province_binding() if binding is None else binding,
        (memory.FIELD_PROVINCE_TRADE_POWER,),
    )[memory.FIELD_PROVINCE_TRADE_POWER]


@pytest.mark.parametrize("raw_value", [0, 184700, -9250, -(1 << 31)])
def test_signed_current_cache_value_is_preserved(raw_value: int) -> None:
    reader, binding = setup_memory(raw_value)

    field = memory.read_fields(
        reader, BASE, binding, (memory.FIELD_PROVINCE_TRADE_POWER,)
    )[memory.FIELD_PROVINCE_TRADE_POWER]

    assert field["status"] == "known"
    assert field["complete"] is False
    assert field["value"] == {"raw": raw_value, "scale": 1000, "unit": "trade_power"}
    assert field["basis"] == "native_province_trade_power_trigger_cache"
    assert field["period"] == "current"
    assert field["raw_inputs"]["trade_power_raw_hex"] == struct.pack("<i", raw_value).hex()


def test_canonical_alias_echo_and_exact_read_budget_are_recorded() -> None:
    reader, binding = setup_memory(4200)

    field = memory.read_fields(
        reader, BASE, binding, (memory.FIELD_PROVINCE_TRADE_POWER,)
    )[memory.FIELD_PROVINCE_TRADE_POWER]

    trace = field["raw_inputs"]
    assert field["status"] == "known"
    assert trace["canonical_record_address"] == hex(RECORD)
    assert trace["canonical_binding_echo"] == binding
    assert trace["manager_record_address"] == hex(RECORD)
    assert trace["record_id_echo"] == PROVINCE_ID
    assert trace["record_id_echo_raw_hex"] == struct.pack("<i", PROVINCE_ID).hex()
    assert trace["trade_power_raw_hex"] == struct.pack("<i", 4200).hex()
    assert trace["manager_header_raw_hex"] == trace["manager_header_recheck_raw_hex"]
    assert trace["manager_global_raw_hex"] == trace["manager_global_recheck_raw_hex"]
    assert trace["read_budget"] == {
        "bytes_requested": 56,
        "calls": 6,
        "max_bytes": 128,
        "max_calls": 16,
    }
    assert [(size, label) for _, size, label in reader.reads] == [
        (8, memory.READ_MANAGER_GLOBAL),
        (16, memory.READ_MANAGER_HEADER),
        (4, memory.READ_PROVINCE_ID),
        (4, memory.READ_TRADE_POWER),
        (8, memory.READ_MANAGER_GLOBAL_RECHECK),
        (16, memory.READ_MANAGER_HEADER_RECHECK),
    ]


def test_manager_record_must_alias_the_canonical_binding_before_record_reads() -> None:
    reader, binding = setup_memory(10, record=RECORD + memory.PROVINCE_RECORD_STRIDE)

    field = read_power(reader, binding)

    assert field["status"] == "unknown"
    assert field["reason"] == "manager_record_canonical_binding_mismatch"
    assert all(label not in (memory.READ_PROVINCE_ID, memory.READ_TRADE_POWER)
               for _, _, label in reader.reads)


def test_manager_record_id_echo_is_checked_before_cache_read() -> None:
    reader, binding = setup_memory(10, id_echo=PROVINCE_ID + 1)

    field = read_power(reader, binding)

    assert field["status"] == "unknown"
    assert field["reason"] == "manager_record_id_echo_mismatch"
    assert memory.READ_PROVINCE_ID in [label for _, _, label in reader.reads]
    assert memory.READ_TRADE_POWER not in [label for _, _, label in reader.reads]


@pytest.mark.parametrize(
    ("begin", "end", "reason"),
    [
        (BEGIN, BEGIN - memory.PROVINCE_RECORD_STRIDE, "manager_span_negative"),
        (BEGIN, BEGIN + memory.PROVINCE_RECORD_STRIDE + 1,
         "manager_span_not_stride_multiple"),
        (BEGIN, BEGIN, "manager_record_count_out_of_bounds"),
    ],
)
def test_invalid_manager_spans_are_unknown_without_record_copy(
    begin: int, end: int, reason: str,
) -> None:
    reader, binding = setup_memory(begin=begin, end=end)

    field = read_power(reader, binding)

    assert field["status"] == "unknown"
    assert field["reason"] == reason
    assert memory.READ_PROVINCE_ID not in [label for _, _, label in reader.reads]
    assert memory.READ_TRADE_POWER not in [label for _, _, label in reader.reads]


@pytest.mark.parametrize(
    ("count", "province_id", "reason"),
    [
        (memory.MAX_MANAGER_RECORDS + 1, 1, "manager_record_count_out_of_bounds"),
        (PROVINCE_ID, PROVINCE_ID, "province_id_out_of_manager_count"),
    ],
)
def test_manager_count_and_province_index_bounds_are_enforced(
    count: int, province_id: int, reason: str,
) -> None:
    reader, binding = setup_memory(count=count, province_id=province_id)

    field = read_power(reader, binding)

    assert field["status"] == "unknown"
    assert field["reason"] == reason
    assert memory.READ_PROVINCE_ID not in [label for _, _, label in reader.reads]


@pytest.mark.parametrize("manager", [0, MANAGER + 1])
def test_invalid_manager_pointer_is_unknown_without_header_read(manager: int) -> None:
    reader, binding = setup_memory(manager=manager)

    field = read_power(reader, binding)

    assert field["status"] == "unknown"
    assert memory.READ_MANAGER_HEADER not in [label for _, _, label in reader.reads]
    assert len(reader.reads) == 1


@pytest.mark.parametrize(
    ("base", "begin", "reason_fragment"),
    [
        (identity.MAX_USER_ADDRESS - memory.TRADE_POWER_MANAGER_GLOBAL_RVA + 8,
         BEGIN, "out_of_user_bounds"),
        (BASE, identity.MAX_USER_ADDRESS - 0x1000, "out_of_user_bounds"),
    ],
)
def test_address_range_overflow_is_unknown(
    base: int, begin: int, reason_fragment: str,
) -> None:
    reader, binding = setup_memory(begin=begin)

    field = memory.read_fields(
        reader, base, binding, (memory.FIELD_PROVINCE_TRADE_POWER,)
    )[memory.FIELD_PROVINCE_TRADE_POWER]

    assert field["status"] == "unknown"
    assert reason_fragment in field["reason"]
    if base != BASE:
        assert reader.reads == []


@pytest.mark.parametrize(
    "label",
    [
        memory.READ_MANAGER_GLOBAL,
        memory.READ_MANAGER_HEADER,
        memory.READ_PROVINCE_ID,
        memory.READ_TRADE_POWER,
        memory.READ_MANAGER_GLOBAL_RECHECK,
        memory.READ_MANAGER_HEADER_RECHECK,
    ],
)
def test_short_read_at_any_required_range_stays_unknown(label: str) -> None:
    reader, binding = setup_memory(0)
    reader.short_labels.add(label)

    field = memory.read_fields(
        reader, BASE, binding, (memory.FIELD_PROVINCE_TRADE_POWER,)
    )[memory.FIELD_PROVINCE_TRADE_POWER]

    assert field["status"] == "unknown"
    assert "read_failed:" in field["reason"]
    assert "value" not in field
    assert field["raw_inputs"]["read_failures"][-1]["label"] == label


@pytest.mark.parametrize(
    "label",
    [memory.READ_MANAGER_GLOBAL, memory.READ_MANAGER_HEADER],
)
def test_manager_global_and_header_are_rechecked_for_mid_read_drift(label: str) -> None:
    reader, binding = setup_memory(1900)
    if label == memory.READ_MANAGER_GLOBAL:
        reader.mutate_after[label] = (
            BASE + memory.TRADE_POWER_MANAGER_GLOBAL_RVA,
            (MANAGER + 0x1000).to_bytes(8, "little"),
        )
        expected = "manager_global_changed_during_read"
    else:
        changed_header = BEGIN.to_bytes(8, "little") + (
            BEGIN + (PROVINCE_ID + 2) * memory.PROVINCE_RECORD_STRIDE
        ).to_bytes(8, "little")
        reader.mutate_after[label] = (
            MANAGER + memory.MANAGER_HEADER_OFFSET,
            changed_header,
        )
        expected = "manager_header_changed_during_read"

    field = read_power(reader, binding)

    assert field["status"] == "unknown"
    assert field["reason"] == expected
    assert "value" not in field


@pytest.mark.parametrize(
    ("province_id", "raw_hex", "reason"),
    [
        (0, "00000000", "province_id_invalid"),
        (-1, "ffffffff", "province_id_invalid"),
        (0x10000, "00000100", "province_id_out_of_supported_range"),
        (True, "01000000", "province_id_invalid"),
    ],
)
def test_invalid_or_out_of_scope_province_id_does_not_read(
    province_id: int, raw_hex: str, reason: str,
) -> None:
    reader, binding = setup_memory(province_id=PROVINCE_ID)
    binding["province_id"] = province_id
    binding["record_id"] = province_id
    binding["id_raw_hex"] = raw_hex
    binding["id_address"] = hex(RECORD + identity.PROVINCE_ID_OFFSET)

    field = memory.read_fields(
        reader, BASE, binding, (memory.FIELD_PROVINCE_TRADE_POWER,)
    )[memory.FIELD_PROVINCE_TRADE_POWER]

    assert field["status"] == "unknown"
    assert reason in field["reason"]
    assert reader.reads == []


def test_noncanonical_binding_id_bytes_are_unknown_without_read() -> None:
    reader, binding = setup_memory()
    binding["id_raw_hex"] = "b8000000"

    field = read_power(reader, binding)

    assert field["status"] == "unknown"
    assert field["reason"] == "province_id_raw_mismatch"
    assert reader.reads == []


@pytest.mark.parametrize(
    ("fields", "expected_status", "reason"),
    [
        ([], None, None),
        (["G02.owner"], "unknown", "unsupported_field"),
        ([memory.FIELD_PROVINCE_TRADE_POWER] * 2, "unknown", "duplicate_field_requested"),
        ([memory.FIELD_PROVINCE_TRADE_POWER, "G02.owner"], "known", None),
    ],
)
def test_empty_unsupported_and_duplicate_field_requests_are_bounded(
    fields: list[str], expected_status: str | None, reason: str | None,
) -> None:
    reader, binding = setup_memory(7)

    result = memory.read_fields(reader, BASE, binding, fields)

    if expected_status is None:
        assert result == {}
        assert reader.reads == []
        return
    if reason == "unsupported_field":
        assert result["G02.owner"]["reason"] == reason
        assert reader.reads == []
        return
    if reason == "duplicate_field_requested":
        assert result[memory.FIELD_PROVINCE_TRADE_POWER]["reason"] == reason
        assert reader.reads == []
        return
    assert result[memory.FIELD_PROVINCE_TRADE_POWER]["status"] == expected_status
    assert result["G02.owner"]["status"] == "unknown"
    assert result["G02.owner"]["reason"] == "unsupported_field"
    assert reader.reads


@pytest.mark.parametrize("fields", ["G02.province_trade_power", [None], ["x"] * (identity.MAX_FIELDS + 1)])
def test_malformed_field_container_does_not_read(fields) -> None:
    reader, binding = setup_memory(1)

    assert memory.read_fields(reader, BASE, binding, fields) == {}
    assert reader.reads == []
