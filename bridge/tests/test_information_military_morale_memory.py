"""Narrow bounded tests for the current army/navy morale caches."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import military_morale_memory as memory
from bridge.tests import test_information_military_quality_memory as quality_fixture


# Keep the child fixture address domain aligned with the military-quality
# child so a parent adapter can combine both records without translating fake
# pointers.
MODULE_BASE = quality_fixture.MODULE_BASE
COUNTRY_POINTER = quality_fixture.COUNTRY_POINTER
BoundedReader = quality_fixture.BoundedReader


def provide_reader(
    army: int = 0,
    navy: int = 0,
    *,
    bad_guard: bool = False,
    include_army: bool = True,
    include_navy: bool = True,
) -> BoundedReader:
    """Build a bounded reader fixture for parent mixed-child tests."""
    profile = memory._load_profile()
    reader = BoundedReader()
    for index, (_name, rva, _end, raw) in enumerate(memory._profile_code_guards(profile)):
        expected = bytearray(raw)
        if bad_guard and index == 0:
            expected[0] ^= 0xFF
        reader.put(MODULE_BASE + rva, bytes(expected))
    if include_army:
        reader.i32(COUNTRY_POINTER + memory.COUNTRY_OFFSETS["army"], army)
    if include_navy:
        reader.i32(COUNTRY_POINTER + memory.COUNTRY_OFFSETS["navy"], navy)
    return reader


@pytest.mark.parametrize(
    "army,navy",
    [(-1, 0), (0, 0), (1000, -2000), (-(2**31), 2**31 - 1)],
)
def test_copies_both_signed_current_caches_without_recompute(army: int, navy: int) -> None:
    reader = provide_reader(army, navy)
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "observed"
    assert record["module_base"] == hex(MODULE_BASE)
    assert record["country_pointer"] == hex(COUNTRY_POINTER)
    assert record["values"] == {"morale": {"army": army, "navy": navy}}
    assert record["raw_hex"] == {"morale": {
        "army": int(army).to_bytes(4, "little", signed=True).hex(),
        "navy": int(navy).to_bytes(4, "little", signed=True).hex(),
    }}
    assert record["fields"]["morale"]["value"] == {"army": army, "navy": navy}
    assert record["fields"]["morale"]["raw"] == {"army": army, "navy": navy}
    assert record["fields"]["morale"]["raw_hex"] == {
        "army": int(army).to_bytes(4, "little", signed=True).hex(),
        "navy": int(navy).to_bytes(4, "little", signed=True).hex(),
    }
    assert record["fields"]["morale"]["status"] == "known"
    assert record["fields"]["morale"]["complete"] is True
    assert record["fields"]["morale"]["unit"] == "morale"
    assert record["fields"]["morale"]["scale"] == 1000
    assert record["fields"]["morale"]["basis"] == memory.BASIS
    assert record["fields"]["morale"]["value_origin"] == memory.VALUE_ORIGIN
    for key, value in (("army", army), ("navy", navy)):
        cache = record["observation"]["caches"][key]
        assert cache["cache_address"] == hex(COUNTRY_POINTER + memory.COUNTRY_OFFSETS[key])
        assert cache["raw_bytes_hex"] == record["raw_hex"]["morale"][key]
    assert memory.validate_record(record) is True
    assert record["runtime_code_guard"]["status"] == "observed"
    assert record["observation"]["raw_bytes_hex"] == record["raw_hex"]
    assert sum(size for _address, size, _label in reader.reads) <= memory.READ_BUDGET_BYTES


def test_provide_reader_fixture_uses_shared_quality_addresses() -> None:
    reader = provide_reader(1234, -5678)
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)
    assert record["status"] == "observed"
    assert memory.validate_record(record)
    assert MODULE_BASE == quality_fixture.MODULE_BASE
    assert COUNTRY_POINTER == quality_fixture.COUNTRY_POINTER


def test_bad_guard_rejects_before_either_country_cache_read() -> None:
    reader = provide_reader(17, 19, bad_guard=True)

    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "unknown"
    assert record["reason"] == "runtime_code_guard_failed"
    assert not any("current_cache" in label for _a, _s, label in reader.reads)
    assert record["values"] is None


def test_short_second_cache_withdraws_both_fields_without_partial_values() -> None:
    reader = provide_reader(11, 22, include_navy=False)

    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "unknown"
    assert record["fields"]["morale"]["status"] == "unknown"
    assert record["values"] is None
    assert record["raw_hex"] is None
    assert any(label == "military_morale.navy.current_cache" for _a, _s, label in reader.reads)


def test_validator_rejects_each_side_and_raw_or_guard_tampering() -> None:
    record = memory.read_fields(provide_reader(-1234, 5678), MODULE_BASE, COUNTRY_POINTER)
    assert memory.validate_record(record)

    for value_key in ("army", "navy"):
        changed = deepcopy(record)
        changed["values"]["morale"][value_key] += 1
        assert memory.validate_record(changed) is False

    changed = deepcopy(record)
    changed["raw_hex"]["morale"]["army"] = "00" * 4
    assert memory.validate_record(changed) is False

    changed = deepcopy(record)
    changed["observation"]["caches"]["navy"]["cache_address"] = hex(COUNTRY_POINTER)
    assert memory.validate_record(changed) is False

    changed = deepcopy(record)
    changed["runtime_code_guard"]["checks"]["army_writer_core"] = False
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


def test_retraction_removes_both_known_values() -> None:
    record = memory.read_fields(provide_reader(100000, -100000), MODULE_BASE, COUNTRY_POINTER)
    assert memory.validate_record(record)

    retracted = memory.retract_record(record, "cleanup_failed")

    assert retracted["status"] == "unknown"
    assert retracted["fields"]["morale"]["status"] == "unknown"
    assert retracted["values"] is None
    assert retracted["raw_hex"] is None
    assert memory.validate_record(retracted) is False
