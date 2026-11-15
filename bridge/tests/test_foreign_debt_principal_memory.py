"""Literal fake-memory tests for the private foreign-debt principal leaf."""
from __future__ import annotations

import struct

import pytest

from bridge.information import foreign_debt_principal_memory as memory


BASE = 0x140000000
OBSERVER_SLOT = 19
TARGET_SLOT = 41
OBSERVER_POINTER = 0x50000000
TARGET_POINTER = 0x50001000
NODE_BASE = 0x60000000
RECORD_BASE = 0x70000000
NODE_STRIDE = 0x100
RECORD_STRIDE = 0x100
INT32_MIN = -(1 << 31)
INT32_MAX = (1 << 31) - 1


def _fullref(tag: str, slot: int, generation: int) -> int:
    return ((generation & 0xFFFF) << 48) | (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


class MemoryImage:
    """Sparse literal bytes with exact read logging and controlled drift."""

    def __init__(self) -> None:
        self.data: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.short_labels: set[str] = set()
        self.error_labels: set[str] = set()
        self.changed_reads: dict[str, bytes] = {}

    def put(self, address: int, raw: bytes) -> None:
        self.data.update({address + offset: value for offset, value in enumerate(raw)})

    def put_u64(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(8, "little", signed=False))

    def put_i32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=True))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if label in self.error_labels:
            raise OSError("synthetic read failure")
        try:
            raw = bytes(self.data[address + offset] for offset in range(size))
        except KeyError as exc:
            raise OSError("synthetic unmapped bytes") from exc
        if label in self.changed_reads:
            raw = self.changed_reads[label]
        if label in self.short_labels:
            return raw[:-1]
        return raw


def _binding(tag: str, slot: int, pointer: int, generation: int) -> dict[str, object]:
    fullref = _fullref(tag, slot, generation)
    return {
        "tag": tag,
        "slot": slot,
        "country_pointer": hex(pointer),
        "country_fullref_address": hex(pointer + 0x20),
        "fullref": hex(fullref),
        "fullref_raw_hex": fullref.to_bytes(8, "little").hex(),
        "table_entry_address": hex(0x61000000 + slot * 8),
        "table_entry_raw_hex": pointer.to_bytes(8, "little").hex(),
    }


def _environment(principals: tuple[int, ...] = (100, -25), *,
                 declared_count: int | None = None) -> tuple[MemoryImage, dict, dict, list[int], list[int]]:
    image = MemoryImage()
    observer = _binding("FRA", OBSERVER_SLOT, OBSERVER_POINTER, 0x1234)
    target = _binding("ENG", TARGET_SLOT, TARGET_POINTER, 0x2345)
    observer_ref = int(str(observer["fullref"]), 0)
    target_ref = int(str(target["fullref"]), 0)
    image.put_u64(OBSERVER_POINTER + 0x20, observer_ref)
    image.put_u64(TARGET_POINTER + 0x20, target_ref)

    node_pointers = [NODE_BASE + index * NODE_STRIDE for index in range(len(principals))]
    record_pointers = [RECORD_BASE + index * RECORD_STRIDE for index in range(len(principals))]
    for index, (node, record, principal) in enumerate(zip(node_pointers, record_pointers, principals)):
        following = node_pointers[index + 1] if index + 1 < len(node_pointers) else 0
        # Literal native node shape: record@+0, opaque qword@+8, next@+0x10.
        image.put(node, struct.pack("<QQQ", record, 0xA5A5A5A5A5A5A5A5, following))
        # Populate unrelated lender/interest/due-like cells with distinctive
        # values so tests can prove the reader never requests those ranges.
        record_bytes = bytearray(0x40)
        record_bytes[0x10:0x18] = observer_ref.to_bytes(8, "little")
        record_bytes[0x20:0x28] = target_ref.to_bytes(8, "little")
        record_bytes[0x2C:0x30] = principal.to_bytes(4, "little", signed=True)
        record_bytes[0x30:0x3C] = bytes.fromhex("78563412efcdab9076543210")
        image.put(record, bytes(record_bytes))

    head = node_pointers[0] if node_pointers else 0
    count = len(principals) if declared_count is None else declared_count
    image.put_u64(TARGET_POINTER + 0xDE8, head)
    image.put_i32(TARGET_POINTER + 0xDF8, count)
    return image, observer, target, node_pointers, record_pointers


def _run(image: MemoryImage, observer: dict, target: dict) -> dict:
    return memory.read_state(image, BASE, observer, target)


def _assert_unknown_without_value(result: dict) -> None:
    assert result["schema"] == "information.foreign_debt_principal_memory.v1"
    assert result["status"] == "unknown"
    assert result["complete_loan_list"] is False
    assert result["publication_admitted"] is False
    assert result["visibility"]["status"] == "unknown"
    assert "value" not in result


def _assert_budget(result: dict) -> None:
    budget = result["raw_inputs"]["read_budget"]
    assert budget["max_nodes"] == 64
    assert budget["max_bytes"] == 32 * 1024
    assert budget["max_calls"] == 384
    assert budget["max_single_read_bytes"] == 1024
    assert budget["calls"] <= budget["max_calls"]
    assert budget["bytes_requested"] <= budget["max_bytes"]
    assert max((read["size"] for read in result["raw_inputs"]["ordered_read_trace"]), default=0) <= 1024


def test_nonempty_list_returns_both_distinct_signed_principal_totals():
    image, observer, target, nodes, records = _environment((100, -25))
    result = _run(image, observer, target)

    assert result["schema"] == "information.foreign_debt_principal_memory.v1"
    assert result["status"] == "known"
    assert result["complete_loan_list"] is True
    assert result["publication_admitted"] is False
    assert result["visibility"]["status"] == "unknown"
    assert result["value"]["loan_count"] == 2
    assert result["value"]["principal_total"] == {
        "status": "known", "raw": 75, "value": 75, "unit": "ducats",
        "scale": 1, "signed_bits": 32, "overflowed": False,
        "arithmetic": "signed32_wrap_after_each_principal_add",
    }
    assert result["value"]["diplomatic_principal_total"] == {
        "status": "known", "raw": 75_000, "value": 75.0, "unit": "ducats",
        "scale": 1000, "signed_bits": 32, "overflowed": False,
        "arithmetic": "signed32_wrap_each_principal_times_1000_then_signed32_add",
    }
    labels = [label for _address, _size, label in image.reads]
    for label in (
            "binding.observer_before.fullref_echo", "binding.target_before.fullref_echo",
            "target.loan_head_before", "target.loan_count_before",
            "binding.observer_after.fullref_echo", "binding.target_after.fullref_echo",
            "target.loan_head_after", "target.loan_count_after"):
        assert labels.count(label) == 1
    for index in range(2):
        assert labels.count(f"loan.node[{index}].before") == 1
        assert labels.count(f"loan.node[{index}].after") == 1
        assert labels.count(f"loan.record_principal[{index}].before") == 1
        assert labels.count(f"loan.record_principal[{index}].after") == 1

    # Neither lender-like +0x10/+0x20 data nor neighboring interest/due cells
    # are read; only the exact four principal bytes at +0x2c are selected.
    forbidden = [(record + 0x10, record + 0x2C) for record in records]
    forbidden += [(record + 0x30, record + 0x40) for record in records]
    for address, size, _label in image.reads:
        end = address + size
        assert all(end <= start or address >= stop for start, stop in forbidden)
    assert result["raw_inputs"]["lender_identity_read"] is False
    assert result["raw_inputs"]["interest_or_due_date_read"] is False
    assert result["raw_inputs"]["atomic_snapshot"] is False
    assert len(nodes) == 2
    _assert_budget(result)


def test_empty_list_is_a_complete_known_zero_for_this_list_only():
    image, observer, target, _nodes, _records = _environment(())
    result = _run(image, observer, target)
    assert result["status"] == "known"
    assert result["complete_loan_list"] is True
    assert result["value"]["loan_count"] == 0
    assert result["value"]["principal_total"]["raw"] == 0
    assert result["value"]["diplomatic_principal_total"]["raw"] == 0
    assert not any(label.startswith("loan.node[") for _a, _s, label in image.reads)
    assert not any(label.startswith("loan.record_principal[") for _a, _s, label in image.reads)
    _assert_budget(result)


def test_negative_values_and_signed32_overflow_are_preserved_without_rejection():
    principals = (INT32_MAX, 1, -2, -3)
    image, observer, target, _nodes, _records = _environment(principals)
    result = _run(image, observer, target)

    # Independent literal expectations: the principal sum is INT32_MAX-4.
    # Its scaled sum is 500*2**32-5000, whose signed DWORD is -5000.
    # These constants check the native 32-bit behavior without reproducing
    # the reader's per-record wrap/overflow loop as the test oracle.
    assert result["status"] == "known"
    assert result["value"]["principal_total"]["raw"] == 2_147_483_643
    assert result["value"]["principal_total"]["overflowed"] is True
    assert result["value"]["diplomatic_principal_total"]["raw"] == -5_000
    assert result["value"]["diplomatic_principal_total"]["overflowed"] is True
    assert result["value"]["diplomatic_principal_total"]["value"] == -5.0
    _assert_budget(result)


@pytest.mark.parametrize(("shape", "reason"), [
    ("negative_count", "LOAN_COUNT_OUT_OF_BOUNDS"),
    ("over_count", "LOAN_COUNT_OUT_OF_BOUNDS"),
    ("nonnull_head_zero_count", "LOAN_HEAD_COUNT_MISMATCH"),
    ("null_head_positive_count", "LOAN_HEAD_COUNT_MISMATCH"),
    ("short_chain", "LOAN_CHAIN_SHORTER_THAN_COUNT"),
    ("long_chain", "LOAN_CHAIN_LONGER_THAN_COUNT"),
    ("cycle", "LOAN_NODE_CYCLE"),
    ("duplicate_record", "LOAN_RECORD_DUPLICATE"),
])
def test_count_and_linked_list_shape_errors_withdraw_all_totals(shape: str, reason: str):
    image, observer, target, nodes, records = _environment((100, 200))
    if shape == "negative_count":
        image.put_i32(TARGET_POINTER + 0xDF8, -1)
    elif shape == "over_count":
        image.put_i32(TARGET_POINTER + 0xDF8, 65)
    elif shape == "nonnull_head_zero_count":
        image.put_i32(TARGET_POINTER + 0xDF8, 0)
    elif shape == "null_head_positive_count":
        image.put_u64(TARGET_POINTER + 0xDE8, 0)
        image.put_i32(TARGET_POINTER + 0xDF8, 1)
    elif shape == "short_chain":
        image.put(TARGET_POINTER + 0xDF8, (3).to_bytes(4, "little", signed=True))
        image.put(nodes[0], struct.pack("<QQQ", records[0], 0xA5A5A5A5A5A5A5A5, 0))
    elif shape == "long_chain":
        image.put_i32(TARGET_POINTER + 0xDF8, 1)
    elif shape == "cycle":
        image.put_i32(TARGET_POINTER + 0xDF8, 2)
        image.put(nodes[0], struct.pack("<QQQ", records[0], 0xA5A5A5A5A5A5A5A5, nodes[0]))
    elif shape == "duplicate_record":
        image.put(nodes[1], struct.pack("<QQQ", records[0], 0xA5A5A5A5A5A5A5A5, 0))

    result = _run(image, observer, target)
    _assert_unknown_without_value(result)
    assert result["reason"] == reason
    _assert_budget(result)


def test_maximum_supported_node_count_is_still_within_read_budgets():
    principals = tuple((index % 5) - 2 for index in range(64))
    image, observer, target, _nodes, _records = _environment(principals)
    result = _run(image, observer, target)
    assert result["status"] == "known"
    assert result["complete_loan_list"] is True
    assert result["value"]["loan_count"] == 64
    assert result["raw_inputs"]["read_budget"]["calls"] == 2 * (4 + 2 * 64)
    _assert_budget(result)


@pytest.mark.parametrize(("drift_label", "mutated"), [
    ("binding.observer_after.fullref_echo", _fullref("FRA", OBSERVER_SLOT, 0x1235).to_bytes(8, "little")),
    ("binding.target_after.fullref_echo", _fullref("ENG", TARGET_SLOT, 0x2346).to_bytes(8, "little")),
    ("target.loan_head_after", (NODE_BASE + NODE_STRIDE).to_bytes(8, "little")),
    ("target.loan_count_after", (2).to_bytes(4, "little", signed=True)),
    ("loan.node[0].after", bytes.fromhex("000000000000007f" + "a5" * 8 + "0000000000000000")),
    ("loan.record_principal[0].after", (101).to_bytes(4, "little", signed=True)),
])
def test_any_fullref_header_node_or_principal_drift_withdraws_entire_result(
        drift_label: str, mutated: bytes):
    image, observer, target, _nodes, _records = _environment((100,))
    image.changed_reads[drift_label] = mutated
    result = _run(image, observer, target)
    _assert_unknown_without_value(result)
    assert "CHANGED_AFTER_READ" in result["reason"] or "FULLREF_ECHO_MISMATCH" in result["reason"]
    _assert_budget(result)


def test_short_read_and_reader_error_withdraw_entire_result():
    for fault in ("short", "error"):
        image, observer, target, _nodes, _records = _environment((100,))
        label = "loan.record_principal[0].before"
        if fault == "short":
            image.short_labels.add(label)
        else:
            image.error_labels.add(label)
        result = _run(image, observer, target)
        _assert_unknown_without_value(result)
        assert result["reason"] == f"READ_FAILED:{label}"
        assert result["raw_inputs"]["ordered_read_trace"][-1]["status"] == "failed"
        _assert_budget(result)


@pytest.mark.parametrize(("limit_name", "limit_value"), [
    ("MAX_READ_CALLS", 3),
    ("MAX_TOTAL_READ_BYTES", 20),
])
def test_call_or_byte_budget_exhaustion_returns_unknown_without_totals(
        monkeypatch: pytest.MonkeyPatch, limit_name: str, limit_value: int):
    image, observer, target, _nodes, _records = _environment((100,))
    monkeypatch.setattr(memory, limit_name, limit_value)
    result = _run(image, observer, target)
    _assert_unknown_without_value(result)
    assert result["reason"] == "READ_BUDGET_EXCEEDED"
    assert result["raw_inputs"]["ordered_read_trace"][-1]["status"] == "rejected"
    assert result["raw_inputs"]["read_budget"]["max_calls"] == memory.MAX_READ_CALLS
    assert result["raw_inputs"]["read_budget"]["max_bytes"] == memory.MAX_TOTAL_READ_BYTES
