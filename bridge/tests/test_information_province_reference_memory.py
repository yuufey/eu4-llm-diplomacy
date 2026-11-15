"""Offline tests for the bounded B23 province ID-to-record resolver."""
from __future__ import annotations

import pytest

from bridge.information import province_reference_memory as memory


MODULE_BASES = (0x140000000, 0x180000000)
WORLD = 0x5000000000
ARRAY_BEGIN = 0x5100000000
RECORDS = 0x5200000000


class MemoryImage:
    def __init__(self) -> None:
        self.bytes: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.short_at: int | None = None
        self.error_at: int | None = None

    def put(self, address: int, raw: bytes) -> None:
        self.bytes.update({address + offset: byte for offset, byte in enumerate(raw)})

    def put_u64(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(8, "little", signed=False))

    def put_i32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=True))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if self.error_at == address:
            raise OSError("synthetic read error")
        result = bytes(self.bytes[address + offset] for offset in range(size))
        if self.short_at == address:
            return result[:-1]
        return result


def make_image(base: int = MODULE_BASES[0], count: int = 5, *,
               begin: int = ARRAY_BEGIN, records: int = RECORDS,
               ids: dict[int, int] | None = None) -> MemoryImage:
    image = MemoryImage()
    image.put_u64(base + memory.PROVINCE_GLOBAL_RVA, WORLD)
    image.put_u64(WORLD + memory.ARRAY_BEGIN_OFFSET, begin)
    image.put_u64(WORLD + memory.ARRAY_END_OFFSET, begin + count * 8)
    image.put_u64(WORLD + memory.RECORDS_POINTER_OFFSET, records)
    for province_id, stored_id in (ids or {1: 1, count - 1: count - 1}).items():
        image.put_i32(records + province_id * memory.RECORD_STRIDE
                      + memory.RECORD_ID_OFFSET, stored_id)
    return image


@pytest.mark.parametrize("base", MODULE_BASES)
def test_resolves_first_and_last_permitted_ids_under_aslr(base: int):
    image = make_image(base=base, count=5)
    result = memory.resolve_provinces(image.read, base, [1, 4])

    assert result["status"] == "observed"
    assert result["header"]["count"] == 5
    assert result["requested"]["1"]["record_pointer"] == hex(RECORDS + memory.RECORD_STRIDE)
    assert result["requested"]["4"]["record_pointer"] == hex(RECORDS + 4 * memory.RECORD_STRIDE)
    assert result["requested"]["4"]["id_raw_hex"] == (4).to_bytes(4, "little", signed=True).hex()
    assert result["world"]["pointer"] == hex(WORLD)
    assert result["visibility"] == "unknown"
    assert result["complete"] is False
    assert result["public_export_ready"] is False
    assert result["budget"]["bytes_requested"] == sum(size for _, size, _ in image.reads)
    assert result["budget"]["calls"] == len(image.reads) == 6
    assert max(size for _, size, _ in image.reads) <= memory.MAX_SINGLE_READ_BYTES


@pytest.mark.parametrize("province_ids,reason", [
    ([0], "province_id_invalid"),
    ([True], "province_id_invalid"),
    ([5], "province_id_out_of_range:5"),
    ([1, 1], "duplicate_province_id:1"),
])
def test_rejects_zero_bool_out_of_count_and_duplicate_ids(province_ids, reason):
    image = make_image()
    result = memory.resolve_provinces(image.read, MODULE_BASES[0], province_ids)
    assert result["status"] == "unknown"
    assert result["reason"] == reason
    assert result["requested"] == {}
    assert result["visibility"] == "unknown"
    assert result["complete"] is False


def test_rejects_more_than_thirty_two_requests_before_reading():
    image = make_image()
    result = memory.resolve_provinces(image.read, MODULE_BASES[0], list(range(1, 34)))
    assert result["status"] == "unknown"
    assert result["reason"] == "province_id_count_out_of_range"
    assert image.reads == []


@pytest.mark.parametrize("count,expected_reason", [
    (1, "province_count_out_of_range"),
    (memory.MAX_PROVINCE_COUNT + 1, "province_count_out_of_range"),
])
def test_rejects_count_outside_native_bounds(count, expected_reason):
    image = make_image(count=count, ids={})
    result = memory.resolve_provinces(image.read, MODULE_BASES[0], [1])
    assert result["status"] == "unknown"
    assert result["reason"] == expected_reason


def test_rejects_misaligned_vector_bounds_and_noncanonical_bounds():
    image = make_image()
    image.put_u64(WORLD + memory.ARRAY_END_OFFSET, ARRAY_BEGIN + 5 * 8 + 1)
    result = memory.resolve_provinces(image.read, MODULE_BASES[0], [1])
    assert result["reason"] == "province_array_bounds_invalid"

    image = make_image()
    image.put_u64(WORLD + memory.ARRAY_BEGIN_OFFSET, 0x7000)
    result = memory.resolve_provinces(image.read, MODULE_BASES[0], [1])
    assert result["reason"] == "province_array_bounds_invalid"


def test_rejects_module_global_and_records_pointer_wraparound():
    image = MemoryImage()
    image.put_u64(MODULE_BASES[0] + memory.PROVINCE_GLOBAL_RVA, WORLD)
    image.put_u64(WORLD + memory.ARRAY_BEGIN_OFFSET, ARRAY_BEGIN)
    image.put_u64(WORLD + memory.ARRAY_END_OFFSET, ARRAY_BEGIN + 5 * 8)
    image.put_u64(WORLD + memory.RECORDS_POINTER_OFFSET,
                  memory.MAX_USER_ADDRESS_EXCLUSIVE - 0x1000)
    result = memory.resolve_provinces(image.read, MODULE_BASES[0], [1])
    assert result["status"] == "unknown"
    assert result["reason"] == "address_range_invalid:province_records"
    assert result["header"]["count"] == 5
    assert result["header"]["records_pointer"] == hex(
        memory.MAX_USER_ADDRESS_EXCLUSIVE - 0x1000)

    wrapped = memory.resolve_provinces(image.read,
        memory.MAX_USER_ADDRESS_EXCLUSIVE - 8, [1])
    assert wrapped["status"] == "unknown"
    assert wrapped["reason"] == "address_arithmetic_invalid:province_global"


def test_short_read_and_reader_exception_return_unknown_with_failure_trace():
    image = make_image()
    image.short_at = WORLD + memory.ARRAY_END_OFFSET
    result = memory.resolve_provinces(image.read, MODULE_BASES[0], [1])
    assert result["reason"] == "short_or_invalid_read:province_reference.array_end"
    assert result["requested"] == {}
    assert result["budget"]["reads"][-1]["status"] == "failed"

    image = make_image()
    image.error_at = RECORDS + memory.RECORD_STRIDE + memory.RECORD_ID_OFFSET
    result = memory.resolve_provinces(image.read, MODULE_BASES[0], [1])
    assert result["reason"] == "read_failed:province_reference.id[1]:OSError"
    assert result["requested"] == {}
    assert result["budget"]["reads"][-1]["error_type"] == "OSError"


def test_embedded_record_id_must_match_requested_id():
    image = make_image(ids={1: 2})
    result = memory.resolve_provinces(image.read, MODULE_BASES[0], [1])
    assert result["status"] == "unknown"
    assert result["reason"] == "province_id_record_mismatch:1"
    assert result["requested"] == {}
    assert result["world"]["pointer"] == hex(WORLD)
    assert result["header"]["count"] == 5
    assert result["budget"]["reads"][-1]["raw_hex"] == (2).to_bytes(4, "little", signed=True).hex()


def test_thirty_two_ids_stay_within_all_read_budgets():
    count = 33
    ids = {province_id: province_id for province_id in range(1, count)}
    image = make_image(base=MODULE_BASES[1], count=count, ids=ids)
    result = memory.resolve_provinces(image.read, MODULE_BASES[1], list(range(1, count)))

    assert result["status"] == "observed"
    assert len(result["requested"]) == 32
    assert result["budget"]["calls"] == len(image.reads) == 36
    assert result["budget"]["bytes_requested"] == 32 + 32 * 4
    assert result["budget"]["bytes_requested"] <= memory.MAX_TOTAL_READ_BYTES
