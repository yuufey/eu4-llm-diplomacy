"""Bounded tests for the fixed-build average-unrest cache reader.

The reader is exercised through a sparse byte-addressed seam.  Only the
profile guards and the country ``+0x7F0`` cache slot are mapped, so an
unexpected read fails instead of producing a convenient fabricated value.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information import InformationService
from bridge.information import average_unrest_memory as memory
from bridge.tests.test_information_domestic_pressure import (
    FIELDS as LEGACY_FIELDS,
    _query as domestic_query,
    _report as domestic_report,
    _source as domestic_source,
)
from bridge.tests.test_information_religious_unity_memory import _BoundedReader, _put


MODULE_BASE = 0x100000000
COUNTRY = 0x200000000


def _profile() -> dict:
    return memory._load_profile()


def _offset(value: object) -> int:
    return int(value, 0) if isinstance(value, str) else int(value)


def _reader(raw: int = -7127) -> _BoundedReader:
    profile = _profile()
    data: dict[int, int] = {}
    for guard in profile["code_guards"]:
        _put(data, MODULE_BASE + _offset(guard["rva"]), bytes.fromhex(guard["hex"]))
    offset = _offset(profile["layout"]["country_average_unrest_offset"])
    _put(data, COUNTRY + offset, raw.to_bytes(4, "little", signed=True))
    return _BoundedReader(data)


def _with_record(session, record: dict) -> dict:
    report = domestic_report(session)
    report["field_results"]["unrest"] = deepcopy(record)
    report["values"]["unrest"] = record["raw"]
    for snapshot_name in ("before", "after"):
        report[snapshot_name]["field_results"]["unrest"] = deepcopy(record)
    return report


@pytest.mark.parametrize("raw", [-7127, -(2**31), 0, 2**31 - 1])
def test_copies_signed_cache_without_clamping_or_percent_conversion(raw: int) -> None:
    reader = _reader(raw)
    record = memory.capture(reader, MODULE_BASE, COUNTRY)

    assert record["status"] == "known"
    assert record["raw"] == raw
    assert record["raw_hex"] == raw.to_bytes(4, "little", signed=True).hex()
    assert record["unit"] == "unrest"
    assert record["scale"] == 1000
    assert memory.validate_record(record) is True
    assert reader.reads[-1] == (
        COUNTRY + _offset(_profile()["layout"]["country_average_unrest_offset"]),
        4,
        "unrest.current_cache",
    )


def test_changed_code_guard_stops_before_reading_country_cache() -> None:
    reader = _reader()
    first = _profile()["code_guards"][0]
    reader.memory[MODULE_BASE + _offset(first["rva"])] ^= 1

    result = memory.capture(reader, MODULE_BASE, COUNTRY)

    assert result["status"] == "unknown"
    assert result["reason"] == "AVERAGE_UNREST_CODE_CHANGED"
    assert not any(label == "unrest.current_cache" for _, _, label in reader.reads)


def test_invalid_profile_stops_before_reader_use(tmp_path: Path, monkeypatch) -> None:
    reader = _reader()
    bad_profile = tmp_path / "invalid-average-unrest-profile.json"
    bad_profile.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(memory, "PROFILE_FILE", bad_profile)

    result = memory.capture(reader, MODULE_BASE, COUNTRY)

    assert result["status"] == "unknown"
    assert result["reason"] == "AVERAGE_UNREST_PROFILE_MISMATCH"
    assert reader.reads == []


def test_record_rejects_modified_copy_or_missing_field_guards() -> None:
    record = memory.capture(_reader(), MODULE_BASE, COUNTRY)
    assert record["status"] == "known"

    changed = deepcopy(record)
    changed["raw"] += 1
    assert memory.validate_record(changed) is False

    changed = deepcopy(record)
    changed["raw_hex"] = "00000000"
    assert memory.validate_record(changed) is False

    changed = deepcopy(record)
    changed["observation"]["code_guard"]["checks"].popitem()
    assert memory.validate_record(changed) is False

    assert memory.validate_record({"status": "known", "raw": -7127}) is False


def test_n04_single_mixed_default_and_periodic_paths_keep_unrest_metadata(tmp_path: Path) -> None:
    record = memory.capture(_reader(), MODULE_BASE, COUNTRY)
    assert record["status"] == "known"
    source, base, _, calls = domestic_source(
        tmp_path,
        report=lambda session: _with_record(session, record),
    )

    expected = {
        "status": "known",
        "value": -7127,
        "raw": -7127,
        "raw_hex": (-7127).to_bytes(4, "little", signed=True).hex(),
        "unit": "unrest",
        "scale": 1000,
        "basis": "native_country_average_unrest_cache",
        "value_origin": "copied_native_country_average_cache",
    }
    single = source.read(domestic_query(["unrest"]), base.context())
    assert single["fields"]["unrest"] == expected
    assert calls[-1][2] == ["unrest"]

    mixed = source.read(domestic_query(["stability", "unrest"]), base.context())
    assert mixed["fields"]["stability"]["status"] == "known"
    assert mixed["fields"]["unrest"] == expected
    assert calls[-1][2] == ["stability", "unrest"]

    # The default legacy query remains the original three fields and does not
    # silently expand into the newly explicit cache reader.
    default = source.read(domestic_query(), base.context())
    assert list(default["fields"]) == LEGACY_FIELDS
    assert calls[-1][2] == LEGACY_FIELDS

    now = [1000.0]
    service = InformationService(source, tmp_path / "average-unrest.sqlite3", clock=lambda: now[0])
    try:
        queried = service.query("unrest-query", queries=[domestic_query(["unrest"])])
        assert queried["status"] == "complete"
        assert queried["items"][0]["fields"]["unrest"] == expected
        report = service.manage_report(
            "unrest-report", "create",
            config={"name": "unrest", "queries": [domestic_query(["unrest"])], "detail": "full"},
        )["report"]
        subscription = service.manage_subscription(
            "unrest-subscription", "create",
            config={
                "name": "unrest periodic", "kind": "periodic", "report_id": report["id"],
                "enabled": True,
                "schedule": {"basis": "real", "every": 1, "unit": "seconds", "missed": "coalesce"},
            },
        )["subscription"]
        now[0] += 1
        tick = service.tick()
        assert tick["results"]
        periodic = tick["results"][0]
        assert periodic["subscription_id"] == subscription["id"]
        assert periodic["items"][0]["fields"]["unrest"] == expected
    finally:
        service.close()

