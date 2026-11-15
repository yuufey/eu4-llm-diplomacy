"""Narrow bounded tests for the current army_tradition country cache."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import military_tradition_memory as memory


MODULE_BASE = 0x100000000
COUNTRY_POINTER = 0x200000000


def _put(storage: dict[int, int], address: int, raw: bytes) -> None:
    storage.update({address + index: value for index, value in enumerate(raw)})


class _BoundedReader:
    def __init__(self, storage: dict[int, int]):
        self.storage = storage
        self.reads: list[tuple[int, int, str]] = []

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        missing = [address + index for index in range(size) if address + index not in self.storage]
        if missing:
            raise AssertionError(f"unmapped read {label}: {missing[0]:#x}")
        return bytes(self.storage[address + index] for index in range(size))


def _reader(raw: int = 0, *, bad_guard: bool = False, include_cache: bool = True) -> _BoundedReader:
    profile = memory._load_profile()
    storage: dict[int, int] = {}
    for index, guard in enumerate(profile["code_guards"]):
        expected = bytearray(bytes.fromhex(guard["hex"]))
        if bad_guard and index == 0:
            expected[0] ^= 0xFF
        _put(storage, MODULE_BASE + int(guard["rva"], 0), bytes(expected))
    if include_cache:
        _put(
            storage,
            COUNTRY_POINTER + memory.COUNTRY_OFFSET,
            int(raw).to_bytes(4, "little", signed=True),
        )
    return _BoundedReader(storage)


@pytest.mark.parametrize("raw", [-1, 0, 100000, -(2**31), 2**31 - 1])
def test_copies_signed_current_cache_without_clamp_or_recompute(raw: int) -> None:
    reader = _reader(raw)
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "observed"
    field = record["fields"]["army_tradition"]
    assert field == {
        "status": "known",
        "complete": True,
        "value": raw,
        "raw": raw,
        "raw_hex": int(raw).to_bytes(4, "little", signed=True).hex(),
        "unit": "army_tradition",
        "scale": 1000,
        "period": "current",
        "basis": memory.BASIS,
        "value_origin": memory.VALUE_ORIGIN,
    }
    assert record["module_base"] == hex(MODULE_BASE)
    assert record["country_pointer"] == hex(COUNTRY_POINTER)
    assert memory.validate_record(record) is True
    assert record["runtime_code_guard"]["status"] == "observed"
    assert record["observation"]["raw_bytes_hex"] == field["raw_hex"]
    assert sum(size for _address, size, _label in reader.reads) <= memory.READ_BUDGET_BYTES


def test_bad_guard_rejects_before_country_cache_read() -> None:
    reader = _reader(17, bad_guard=True)

    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "unknown"
    assert record["reason"] == "runtime_code_guard_failed"
    assert not any(label == "military_tradition.current_cache" for _a, _s, label in reader.reads)


def test_short_country_cache_stays_unknown_after_valid_guards() -> None:
    reader = _reader(include_cache=False)

    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "unknown"
    assert record["fields"]["army_tradition"]["status"] == "unknown"
    assert any(label == "military_tradition.current_cache" for _a, _s, label in reader.reads)
    assert record["runtime_code_guard"]["status"] == "observed"


def test_validator_recomputes_raw_provenance_and_guard() -> None:
    record = memory.read_fields(_reader(-1234), MODULE_BASE, COUNTRY_POINTER)
    assert memory.validate_record(record)

    changed = deepcopy(record)
    changed["values"]["army_tradition"] += 1
    assert not memory.validate_record(changed)

    changed = deepcopy(record)
    changed["raw_hex"]["army_tradition"] = "00000000"
    assert not memory.validate_record(changed)

    changed = deepcopy(record)
    changed["fields"]["army_tradition"]["value_origin"] = "invented"
    assert not memory.validate_record(changed)

    changed = deepcopy(record)
    changed["runtime_code_guard"]["records"]["army_tradition_getter"]["actual_hex"] = "00" * 13
    assert not memory.validate_record(changed)


def test_profile_failure_stops_before_reader_use(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = _reader()

    def reject(*_args, **_kwargs):
        raise memory.ProfileError("profile rejected")

    monkeypatch.setattr(memory, "_load_profile", reject)
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "unknown"
    assert record["reason"] == "static_contract_guard_failed"
    assert reader.reads == []


def test_retraction_removes_known_value() -> None:
    record = memory.read_fields(_reader(100000), MODULE_BASE, COUNTRY_POINTER)
    assert memory.validate_record(record)

    retracted = memory.retract_record(record, "cleanup_failed")

    assert retracted["status"] == "unknown"
    assert retracted["fields"]["army_tradition"]["status"] == "unknown"
    assert retracted["values"] is None
    assert retracted["raw_hex"] is None
    assert memory.validate_record(retracted) is False
