"""Narrow bounded tests for the signed QWORD army-professionalism cache."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import military_professionalism_memory as memory
from bridge.tests import test_information_military_quality_memory as quality_fixture


# Parent mixed-child tests use the same fake address domain as the military
# quality and morale children.  The country+0x50 bytes below are the inline
# value itself; no pointer object is installed there.
MODULE_BASE = quality_fixture.MODULE_BASE
COUNTRY_POINTER = quality_fixture.COUNTRY_POINTER
BoundedReader = quality_fixture.BoundedReader


def provide_reader(
    value: int = 655,
    *,
    bad_guard: bool = False,
    include_cache: bool = True,
) -> BoundedReader:
    """Build a bounded reader fixture for parent mixed-child tests."""

    profile = memory._load_profile()
    reader = BoundedReader()
    for index, (_name, rva, _end, raw) in enumerate(memory._profile_code_guards(profile)):
        expected = bytearray(raw)
        if bad_guard and index == 0:
            expected[0] ^= 0xFF
        reader.put(MODULE_BASE + rva, bytes(expected))
    if include_cache:
        reader.put(
            COUNTRY_POINTER + memory.COUNTRY_OFFSET,
            int(value).to_bytes(memory.VALUE_WIDTH, "little", signed=True),
        )
    return reader


@pytest.mark.parametrize(
    "value",
    [-(2**63), -(2**31) - 1, -1, 0, 655, 2**31 + 1, 2**63 - 1],
)
def test_copies_signed_inline_qword_without_clamp_or_pointer_dereference(value: int) -> None:
    reader = provide_reader(value)

    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    expected_hex = int(value).to_bytes(8, "little", signed=True).hex()
    assert record["status"] == "observed"
    assert record["module_base"] == hex(MODULE_BASE)
    assert record["country_pointer"] == hex(COUNTRY_POINTER)
    assert record["values"] == {"professionalism": value}
    assert record["raw_hex"] == {"professionalism": expected_hex}
    assert record["fields"]["professionalism"] == {
        "status": "known",
        "complete": True,
        "value": value,
        "raw": value,
        "raw_hex": expected_hex,
        "unit": "ratio",
        "scale": 32768,
        "period": "current",
        "basis": memory.BASIS,
        "value_origin": memory.VALUE_ORIGIN,
    }
    assert record["observation"]["cache_address"] == hex(COUNTRY_POINTER + 0x50)
    assert memory.validate_record(record) is True
    assert sum(size for _address, size, _label in reader.reads) <= memory.READ_BUDGET_BYTES


def test_provide_reader_fixture_uses_shared_quality_addresses() -> None:
    record = memory.read_fields(provide_reader(655), MODULE_BASE, COUNTRY_POINTER)
    assert record["status"] == "observed"
    assert memory.validate_record(record)
    assert MODULE_BASE == quality_fixture.MODULE_BASE
    assert COUNTRY_POINTER == quality_fixture.COUNTRY_POINTER


def test_bad_guard_rejects_before_inline_cache_read() -> None:
    reader = provide_reader(17, bad_guard=True)

    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "unknown"
    assert record["reason"] == "runtime_code_guard_failed"
    assert not any(
        label == "military_professionalism.current_cache"
        for _address, _size, label in reader.reads
    )


def test_short_inline_cache_stays_unknown_after_valid_guards() -> None:
    reader = provide_reader(include_cache=False)

    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "unknown"
    assert record["reason"].startswith("read_failed:")
    assert record["fields"]["professionalism"]["status"] == "unknown"
    assert any(
        label == "military_professionalism.current_cache"
        for _address, _size, label in reader.reads
    )
    assert record["runtime_code_guard"]["status"] == "observed"


def test_budget_is_reserved_before_over_budget_guard_read(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = provide_reader()

    class TinyBudget(memory._ReadBudget):
        def __init__(self, _limit: int = memory.READ_BUDGET_BYTES):
            super().__init__(100)

    monkeypatch.setattr(memory, "_ReadBudget", TinyBudget)
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "unknown"
    assert record["reason"] == "runtime_code_guard_failed"
    assert record["runtime_code_guard"]["bytes_reserved"] == 67
    assert record["observation"]["read_budget"]["bytes_reserved"] == 67
    assert not any(
        label == "military_professionalism.current_cache"
        for _address, _size, label in reader.reads
    )


def test_validator_recomputes_qword_raw_and_guard_provenance() -> None:
    record = memory.read_fields(provide_reader(-(2**31) - 1), MODULE_BASE, COUNTRY_POINTER)
    assert memory.validate_record(record)

    changed = deepcopy(record)
    changed["values"]["professionalism"] += 1
    assert memory.validate_record(changed) is False

    changed = deepcopy(record)
    changed["raw_hex"]["professionalism"] = "00" * 8
    assert memory.validate_record(changed) is False

    changed = deepcopy(record)
    changed["fields"]["professionalism"]["unit"] = "professionalism"
    assert memory.validate_record(changed) is False

    changed = deepcopy(record)
    changed["observation"]["cache_address"] = hex(COUNTRY_POINTER)
    assert memory.validate_record(changed) is False

    changed = deepcopy(record)
    changed["runtime_code_guard"]["checks"]["professionalism_getter"] = False
    assert memory.validate_record(changed) is False


def test_profile_failure_stops_before_reader_use(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = BoundedReader()

    def reject(*_args, **_kwargs):
        raise memory.ProfileError("profile rejected")

    monkeypatch.setattr(memory, "_load_profile", reject)
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "unknown"
    assert record["reason"] == "static_contract_guard_failed"
    assert reader.reads == []


def test_retraction_removes_known_value_and_cannot_validate() -> None:
    record = memory.read_fields(provide_reader(2**31 + 1), MODULE_BASE, COUNTRY_POINTER)
    assert memory.validate_record(record)

    retracted = memory.retract_record(record, "cleanup_failed")

    assert retracted["status"] == "unknown"
    assert retracted["fields"]["professionalism"]["status"] == "unknown"
    assert retracted["values"] is None
    assert retracted["raw_hex"] is None
    assert memory.validate_record(retracted) is False

