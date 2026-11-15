"""Literal fake-memory coverage for the private current-interest leaf."""
from __future__ import annotations

import struct

import pytest

from bridge.information import bankruptcy_interest_memory as memory


BASE = 0x140000000
COUNTRY = 0x50000000
ENTRIES = 0x60000000
MANAGER = 0x70000000
PROCESSOR = 0x71000000


class MemoryImage:
    def __init__(self) -> None:
        self.data: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.short_on: set[tuple[int, int]] = set()
        self.change_on_call: dict[tuple[int, int, int], bytes] = {}
        self._counts: dict[tuple[int, int], int] = {}

    def put(self, address: int, raw: bytes) -> None:
        self.data.update({address + offset: byte for offset, byte in enumerate(raw)})

    def put_u8(self, address: int, value: int) -> None:
        self.put(address, bytes([value]))

    def put_i32(self, address: int, value: int) -> None:
        self.put(address, struct.pack("<i", value))

    def put_u64(self, address: int, value: int) -> None:
        self.put(address, struct.pack("<Q", value))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        key = (address, size)
        call_number = self._counts.get(key, 0) + 1
        self._counts[key] = call_number
        try:
            raw = bytes(self.data[address + offset] for offset in range(size))
        except KeyError as exc:
            raise OSError("synthetic unmapped bytes") from exc
        raw = self.change_on_call.get((address, size, call_number), raw)
        if key in self.short_on:
            return raw[:-1]
        return raw


def _image(*, base_raw: int = 500, floor_raw: int = 100, cache_state: int = 0,
           dense_flag: int = 1, dense_raw: int = 200,
           sparse_entries: tuple[tuple[int, int], ...] = (),
           sparse_count: int | None = None, processor: int = 0) -> MemoryImage:
    image = MemoryImage()
    image.put_i32(BASE + 0x233E128, base_raw)
    image.put_i32(BASE + 0x233E124, floor_raw)
    image.put_i32(COUNTRY + 0x28C8, cache_state)
    image.put_u8(COUNTRY + 0x28D0 + 0x10, dense_flag)
    image.put_u64(COUNTRY + 0x28D0 + 0x58, ENTRIES)
    image.put_i32(COUNTRY + 0x28D0 + 0x64,
                  len(sparse_entries) if sparse_count is None else sparse_count)
    image.put_i32(ENTRIES + 0xF4, dense_raw)
    if sparse_entries:
        image.put(ENTRIES, b"".join(struct.pack("<Ii", key, value)
                                     for key, value in sparse_entries))
    image.put_u64(BASE + 0x2358060, MANAGER)
    image.put_u64(MANAGER + 0xB80, processor)
    return image


def _run(image: MemoryImage) -> dict:
    return memory.read_state(image, BASE, COUNTRY)


def _assert_unknown(result: dict, reason: str) -> None:
    assert result["schema"] == "information.bankruptcy_interest_memory.v1"
    assert result["status"] == "unknown"
    assert result["reason"] == reason
    assert result["publication_admitted"] is False
    assert result["visibility_evaluated"] is False
    assert "value" not in result


def _assert_child_trace(result: dict) -> None:
    rows = result["raw_inputs"]["ordered_read_trace"]
    assert rows
    assert all(set(row) == {"address", "size", "raw_hex", "status"} for row in rows)
    assert all(row["status"] == "ok" and len(bytes.fromhex(row["raw_hex"])) == row["size"]
               for row in rows)
    budget = result["raw_inputs"]["read_budget"]
    assert budget["calls"] == len(rows)
    assert budget["calls"] <= 128
    assert budget["bytes_requested"] <= 16 * 1024
    assert max(row["size"] for row in rows) <= 1024


def test_dense_null_processor_returns_signed32_sum_above_floor():
    image = _image(base_raw=500, floor_raw=100, dense_raw=200)
    result = _run(image)

    assert result["status"] == "known"
    assert result["basis"] == "native_current_interest_null_processor_branch"
    assert result["publication_admitted"] is False
    assert result["value"] == {
        "helper_return_i32": 700,
        "base_raw_i32": 500,
        "modifier_raw_i32": 200,
        "floor_raw_i32": 100,
    }
    assert result["raw_inputs"]["selected_branch"] == "dense"
    assert result["raw_inputs"]["native_function_invoked"] is False
    assert result["raw_inputs"]["processor_callback_invoked"] is False
    _assert_child_trace(result)


def test_signed32_wrap_then_signed_floor_is_preserved():
    image = _image(base_raw=2_147_483_600, floor_raw=-2_147_483_590,
                   dense_raw=100)
    result = _run(image)

    assert result["status"] == "known"
    assert result["value"]["base_raw_i32"] == 2_147_483_600
    assert result["value"]["modifier_raw_i32"] == 100
    # 2147483600 + 100 wraps to -2147483596, then the signed lower floor wins.
    assert result["value"]["helper_return_i32"] == -2_147_483_590


def test_sparse_uses_the_first_matching_key_and_keeps_signed_value():
    image = _image(base_raw=400, floor_raw=-100, dense_flag=0,
                   sparse_entries=((7, 999), (0x1E, -25), (41, 88)))
    result = _run(image)

    assert result["status"] == "known"
    assert result["value"] == {
        "helper_return_i32": 375,
        "base_raw_i32": 400,
        "modifier_raw_i32": -25,
        "floor_raw_i32": -100,
    }
    assert result["raw_inputs"]["selected_branch"] == "sparse"
    assert result["raw_inputs"]["sparse_match_count"] == 1


def test_sparse_missing_key_uses_zero_modifier():
    image = _image(base_raw=123, floor_raw=-999, dense_flag=0,
                   sparse_entries=((7, 50), (41, -9)))
    result = _run(image)

    assert result["status"] == "known"
    assert result["value"]["modifier_raw_i32"] == 0
    assert result["value"]["helper_return_i32"] == 123


def test_sparse_duplicate_key_is_rejected_as_ambiguous():
    image = _image(dense_flag=0, sparse_entries=((0x1E, 10), (0x1E, 20)))
    result = _run(image)

    _assert_unknown(result, "SPARSE_MODIFIER_KEY_DUPLICATE")


def test_state_one_is_unknown_without_tls_or_modifier_reads():
    image = _image(cache_state=1)
    result = _run(image)

    _assert_unknown(result, "CACHE_CALCULATING_STATE")
    assert len(result["raw_inputs"]["ordered_read_trace"]) == 6
    assert not any("tls" in label.lower() for _, _, label in image.reads)
    assert not any(address == COUNTRY + 0x28D0 + 0x10 for address, _, _ in image.reads)


def test_nonnull_processor_is_unknown_and_never_followed():
    image = _image(processor=PROCESSOR)
    result = _run(image)

    _assert_unknown(result, "NON_NULL_PROCESSOR_UNSUPPORTED")
    assert any(address == MANAGER + 0xB80 for address, _, _ in image.reads)
    assert not any(PROCESSOR <= address < PROCESSOR + 0x100 for address, _, _ in image.reads)


def test_sparse_count_over_limit_is_unknown():
    image = _image(dense_flag=0, sparse_count=257)
    result = _run(image)

    _assert_unknown(result, "SPARSE_COUNT_OUT_OF_BOUNDS")
    assert not any(address == ENTRIES for address, _, _ in image.reads)


def test_invalid_dense_flag_is_unknown():
    image = _image(dense_flag=2)
    result = _run(image)

    _assert_unknown(result, "DENSE_FLAG_INVALID")


def test_pointer_or_short_read_failure_is_unknown():
    invalid = _image()
    invalid.put_u64(COUNTRY + 0x28D0 + 0x58, 0x1001)
    _assert_unknown(_run(invalid), "MODIFIER_ENTRIES_POINTER_INVALID")

    short = _image()
    short.short_on.add((BASE + 0x233E128, 4))
    result = _run(short)
    assert result["status"] == "unknown"
    assert result["reason"].startswith("READ_FAILED:")
    assert "value" not in result


def test_input_drift_between_passes_withdraws_value():
    image = _image()
    image.change_on_call[(BASE + 0x233E128, 4, 2)] = struct.pack("<i", 501)
    result = _run(image)

    _assert_unknown(result, "INPUTS_CHANGED_AFTER_READ")


def test_max_sparse_table_is_chunked_within_read_budget():
    pairs = tuple((0x1000 + key, key - 100) for key in range(1, 257))
    image = _image(base_raw=250, floor_raw=-500, dense_flag=0,
                   sparse_entries=pairs)
    result = _run(image)

    assert result["status"] == "known"
    assert result["value"]["modifier_raw_i32"] == 0
    _assert_child_trace(result)
    assert result["raw_inputs"]["read_budget"]["bytes_requested"] < 16 * 1024


def test_child_budget_rejects_the_first_read_past_limit():
    class ZeroReader:
        def read(self, address: int, size: int, label: str) -> bytes:
            return bytes(size)

    trace = memory._Trace(ZeroReader())
    for index in range(16):
        trace.exact(0x50000000 + index * 0x1000, 1024, f"budget.{index}")
    with pytest.raises(memory._Unknown, match="READ_BUDGET_EXCEEDED"):
        trace.exact(0x50010000, 1, "budget.limit")
    assert trace.summary()["calls"] == 16
    assert trace.summary()["bytes_requested"] == 16 * 1024
