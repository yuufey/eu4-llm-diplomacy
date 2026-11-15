"""Offline bounded-memory tests for country ledger candidate membership."""
from __future__ import annotations

from copy import deepcopy
import json

import pytest

from bridge.information import country_ledger_membership_memory as memory


WORLD = 0x6200000000
ARRAY = 0x6300000000
COUNTRIES = 0x6400000000
OBSERVER_SLOT = 122
TARGET_SLOT = 46


def _fullref(tag: str, slot: int, generation: int = 1) -> int:
    return ((generation & 0xFFFF) << 48) | (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


class MemoryImage:
    def __init__(self) -> None:
        self.data: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.error_at: set[int] = set()
        self.short_at: set[int] = set()

    def put(self, address: int, raw: bytes) -> None:
        self.data.update({address + offset: byte for offset, byte in enumerate(raw)})

    def put_i32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=True))

    def put_u64(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(8, "little", signed=False))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if address in self.error_at:
            raise OSError("synthetic read failure")
        try:
            raw = bytes(self.data[address + offset] for offset in range(size))
        except KeyError as exc:
            raise OSError("unmapped fake memory") from exc
        return raw[:-1] if address in self.short_at else raw


def _binding(tag: str = "ENG", slot: int = TARGET_SLOT,
             pointer: int | None = None, generation: int = 0x1234) -> dict:
    if pointer is None:
        pointer = COUNTRIES + slot * 0x1000
    fullref = _fullref(tag, slot, generation)
    return {
        "tag": tag,
        "slot": slot,
        "country_pointer": hex(pointer),
        "country_fullref_address": hex(pointer + memory.COUNTRY_FULLREF_OFFSET),
        "fullref": hex(fullref),
        "fullref_raw_hex": fullref.to_bytes(8, "little").hex(),
        "table_entry_address": hex(0x6100000000 + slot * 8),
        "table_entry_raw_hex": pointer.to_bytes(8, "little").hex(),
    }


def _environment(tags: tuple[tuple[str, int], ...] = (('FRA', OBSERVER_SLOT), ('ENG', TARGET_SLOT), ('ORL', 300)),
                 *, count_override: int | None = None) -> tuple[MemoryImage, dict, dict[int, int]]:
    image = MemoryImage()
    bindings: dict[int, int] = {}
    pointers = []
    for tag, slot in tags:
        pointer = COUNTRIES + slot * 0x1000
        bindings[slot] = pointer
        pointers.append(pointer)
        image.put_u64(pointer + memory.COUNTRY_FULLREF_OFFSET,
                      _fullref(tag, slot, 0x1200 + slot))
    target = _binding(generation=0x1200 + TARGET_SLOT)
    image.put_u64(int(target["country_pointer"], 16) + memory.COUNTRY_FULLREF_OFFSET,
                  int(target["fullref"], 16))
    image.put_u64(WORLD + memory.WORLD_COUNTRY_POINTERS_OFFSET, ARRAY if pointers else 0)
    image.put_i32(WORLD + memory.WORLD_COUNTRY_COUNT_OFFSET,
                  len(pointers) if count_override is None else count_override)
    if pointers:
        image.put(ARRAY, b"".join(pointer.to_bytes(8, "little") for pointer in pointers))
    return image, target, bindings


def _target_ref(image: MemoryImage, binding: dict, *, generation: int = 0x1200 + TARGET_SLOT) -> None:
    ptr = int(binding["country_pointer"], 16)
    image.put_u64(ptr + memory.COUNTRY_FULLREF_OFFSET,
                  _fullref(binding["tag"], binding["slot"], generation))


def test_candidate_array_membership_checks_pointer_and_live_fullref():
    image, target, _ = _environment()
    result = memory.read_membership(image, WORLD, target)
    assert result["status"] == "known" and result["member"] is True
    assert result["matching_indices"] == [1]
    assert result["target"]["fullref"] == target["fullref"]
    assert result["raw_inputs"]["target_fullref_validation"]["matches_binding"] is True
    assert memory.validate_membership(json.loads(json.dumps(result)))


def test_valid_database_binding_missing_from_active_candidate_array_is_known_false():
    image, target, _ = _environment((('FRA', OBSERVER_SLOT), ('ORL', 300)))
    result = memory.read_membership(image, WORLD, target)
    assert result["status"] == "known" and result["member"] is False
    assert result["matching_indices"] == []
    assert result["raw_inputs"]["target_fullref_validation"]["matches_binding"] is True
    assert memory.validate_membership(result)


def test_zero_candidate_count_is_known_nonmember_and_allows_null_array():
    image, target, _ = _environment((), count_override=0)
    result = memory.read_membership(image, WORLD, target)
    assert result["status"] == "known" and result["member"] is False
    assert result["world"]["candidate_array_pointer"] is None
    assert not any("array_chunk" in label for _a, _s, label in image.reads)
    assert memory.validate_membership(result)


@pytest.mark.parametrize("count", [-1, 4097])
def test_negative_or_oversize_candidate_count_is_unknown_without_array_reads(count: int):
    image, target, _ = _environment((('FRA', OBSERVER_SLOT),), count_override=count)
    result = memory.read_membership(image, WORLD, target)
    assert result["status"] == "unknown" and result["member"] is None
    assert result["reason"] == "COUNTRY_CANDIDATE_COUNT_INVALID"
    assert len(image.reads) == 2
    assert memory.validate_membership(result)


def test_candidate_count_4096_stays_within_128_calls_64k_and_1024_byte_chunks():
    image = MemoryImage()
    target = _binding()
    pointers = [0x6800000000 + index * 0x1000 for index in range(4096)]
    image.put_u64(WORLD + memory.WORLD_COUNTRY_POINTERS_OFFSET, ARRAY)
    image.put_i32(WORLD + memory.WORLD_COUNTRY_COUNT_OFFSET, len(pointers))
    image.put(ARRAY, b"".join(pointer.to_bytes(8, "little") for pointer in pointers))
    target_pointer = int(target["country_pointer"], 16)
    image.put_u64(target_pointer + memory.COUNTRY_FULLREF_OFFSET,
                  int(target["fullref"], 16))
    result = memory.read_membership(image, WORLD, target)
    assert result["status"] == "known" and result["member"] is False
    budget = result["raw_inputs"]["budget"]
    assert budget["calls"] <= 128 and budget["bytes_requested"] <= 64 * 1024
    assert max(size for _address, size, _label in image.reads) <= 1024
    assert all(size % 8 == 0 for _address, size, label in image.reads if "array_chunk" in label)
    assert memory.validate_membership(result)


@pytest.mark.parametrize("failure_kind", ["short", "error"])
def test_required_read_failures_fail_closed(failure_kind: str):
    image, target, _ = _environment()
    if failure_kind == "short":
        image.short_at.add(WORLD + memory.WORLD_COUNTRY_COUNT_OFFSET)
    else:
        image.error_at.add(ARRAY)
    result = memory.read_membership(image, WORLD, target)
    assert result["status"] == "unknown" and result["member"] is None
    assert result["reason"].startswith("READ_FAILED:")
    assert memory.validate_membership(result)


def test_target_live_fullref_mismatch_is_unknown_even_when_pointer_is_in_array():
    image, target, _ = _environment()
    _target_ref(image, target, generation=0x4321)
    result = memory.read_membership(image, WORLD, target)
    assert result["status"] == "unknown" and result["member"] is None
    assert result["reason"] == "TARGET_FULLREF_MISMATCH"
    assert result["matching_indices"] == []
    assert memory.validate_membership(result)


@pytest.mark.parametrize("field,value", [
    ("tag", "---"), ("slot", True), ("country_pointer", "0x1000"),
    ("fullref_raw_hex", "00" * 8), ("table_entry_raw_hex", "ff" * 8),
])
def test_invalid_target_binding_fails_before_any_read(field: str, value: object):
    image, target, _ = _environment()
    target[field] = value
    result = memory.read_membership(image, WORLD, target)
    assert result["status"] == "unknown" and result["member"] is None
    assert result["reason"] == (
        "TARGET_TABLE_ENTRY_RAW_MISMATCH" if field == "table_entry_raw_hex"
        else "TARGET_BINDING_INVALID")
    assert image.reads == []


def test_invalid_world_or_nonzero_count_with_null_array_is_unknown():
    image, target, _ = _environment()
    assert memory.read_membership(None, WORLD, target)["reason"] == "READER_INVALID"
    invalid = memory.read_membership(image, 1, target)
    assert invalid["reason"] == "WORLD_POINTER_INVALID"
    image.put_u64(WORLD + memory.WORLD_COUNTRY_POINTERS_OFFSET, 0)
    invalid = memory.read_membership(image, WORLD, target)
    assert invalid["reason"] == "COUNTRY_ARRAY_POINTER_INVALID"


def test_budget_rejection_is_unknown_and_recorded(monkeypatch):
    image, target, _ = _environment()
    monkeypatch.setattr(memory, "MAX_READ_CALLS", 1)
    result = memory.read_membership(image, WORLD, target)
    assert result["status"] == "unknown" and result["reason"] == "READ_BUDGET_EXCEEDED"
    assert result["raw_inputs"]["reads"][-1]["status"] == "rejected"
    assert memory.validate_membership(result)


def test_validator_rejects_forged_index_and_changed_array_trace():
    image, target, _ = _environment()
    result = memory.read_membership(image, WORLD, target)
    assert memory.validate_membership(result)
    forged_index = deepcopy(result)
    forged_index["matching_indices"] = [2]
    assert not memory.validate_membership(forged_index)
    forged_array = deepcopy(result)
    vector = next(row for row in forged_array["raw_inputs"]["reads"]
                  if "array_chunk" in row["label"])
    forged = bytearray.fromhex(vector["raw_hex"])
    forged[8:16] = (COUNTRIES + 888 * 0x1000).to_bytes(8, "little")
    vector["raw_hex"] = forged.hex()
    assert not memory.validate_membership(forged_array)


def test_validator_does_not_equate_boolean_and_integer_candidate_indices():
    image, target, _ = _environment()
    result = memory.read_membership(image, WORLD, target)
    assert result["matching_indices"] == [1]
    forged = deepcopy(result)
    forged["matching_indices"] = [True]
    assert not memory.validate_membership(forged)
