"""Exercise the guarded UI-cache reader and its public N04 consumer."""
from copy import deepcopy

import pytest

from bridge.information import InformationService, overextension_memory as memory
from bridge.tests.test_information_domestic_pressure import (
    _query, _report, _source,
)
from bridge.tests.test_information_religious_unity_memory import _BoundedReader, _put


BASE, COUNTRY = 0x100000000, 0x200000000


def _reader(raw=1250):
    profile = memory._load_profile()
    data = {}
    for guard in profile["code_guards"]:
        _put(data, BASE + int(guard["rva"], 0), bytes.fromhex(guard["hex"]))
    _put(data, COUNTRY + 0xE48, raw.to_bytes(4, "little", signed=True))
    return _BoundedReader(data)


@pytest.mark.parametrize("raw", [0, 125, 1250, -1, 2**31-1])
def test_copies_signed_cache_without_clamping_or_percent_conversion(raw):
    reader = _reader(raw)
    record = memory.capture(reader, BASE, COUNTRY)
    assert record["status"] == "known"
    assert record["raw"] == raw
    assert record["raw_hex"] == raw.to_bytes(4, "little", signed=True).hex()
    assert record["unit"] == "fraction" and record["scale"] == 1000
    assert memory.validate_record(record)
    assert reader.reads[-1] == (COUNTRY + 0xE48, 4, "overextension.current_cache")


def test_changed_ui_code_rejects_before_reading_country_cache():
    reader = _reader()
    first = memory._load_profile()["code_guards"][0]
    reader.memory[BASE + int(first["rva"], 0)] ^= 1
    result = memory.capture(reader, BASE, COUNTRY)
    assert result["status"] == "unknown" and result["reason"] == "OVEREXTENSION_CODE_CHANGED"
    assert not any(label == "overextension.current_cache" for _, _, label in reader.reads)


def test_invalid_profile_stops_before_reader_use(tmp_path, monkeypatch):
    reader = _reader()
    path = tmp_path / "profile.json"
    path.write_text("{}")
    monkeypatch.setattr(memory, "PROFILE_FILE", path)
    assert memory.capture(reader, BASE, COUNTRY)["reason"] == "OVEREXTENSION_PROFILE_MISMATCH"
    assert not reader.reads


def test_record_rejects_modified_copy_or_missing_field_guards():
    record = memory.capture(_reader(), BASE, COUNTRY)
    changed = deepcopy(record)
    changed["raw"] += 1
    assert not memory.validate_record(changed)
    changed = deepcopy(record)
    changed["observation"]["code_guard"]["checks"].popitem()
    assert not memory.validate_record(changed)
    assert not memory.validate_record({"status": "known", "raw": 1250})


def _with_record(session, record):
    report = _report(session)
    report["field_results"]["overextension"] = deepcopy(record)
    report["values"]["overextension"] = record["raw"]
    for label in ("before", "after"):
        report[label]["field_results"]["overextension"] = deepcopy(record)
    return report


def test_query_mixed_and_periodic_preserve_cache_semantics(tmp_path):
    record = memory.capture(_reader(), BASE, COUNTRY)
    source, base, _, calls = _source(tmp_path, report=lambda session: _with_record(session, record))
    result = source.read(_query(["overextension"]), base.context())
    value = result["fields"]["overextension"]
    assert value == {"status": "known", "value": 1250, "raw": 1250, "raw_hex": "e2040000",
                     "unit": "fraction", "scale": 1000, "basis": "native_ui_current_cache",
                     "value_origin": "copied_native_ui_cache"}
    mixed = source.read(_query(["stability", "overextension"]), base.context())
    assert all(item["status"] == "known" for item in mixed["fields"].values())
    assert calls[-1][2] == ["stability", "overextension"]
    now = [1000.0]
    service = InformationService(source, tmp_path / "oe.sqlite3", clock=lambda: now[0])
    report = service.manage_report("oe-report", "create", config={
        "name": "oe", "queries": [_query(["overextension"])], "detail": "full"})["report"]
    subscription = service.manage_subscription("oe-sub", "create", config={
        "name": "oe", "kind": "periodic", "report_id": report["id"], "enabled": True,
        "schedule": {"basis": "real", "every": 1, "unit": "seconds", "missed": "coalesce"}})["subscription"]
    now[0] += 1
    periodic = service.tick()["results"][0]
    assert periodic["subscription_id"] == subscription["id"]
    assert periodic["items"][0]["fields"]["overextension"] == value


def test_bad_snapshot_only_retracts_overextension(tmp_path):
    record = memory.capture(_reader(), BASE, COUNTRY)
    def report(session):
        result = _with_record(session, record)
        result["after"]["field_results"]["overextension"]["observation"]["cache_raw_hex"] = "00000000"
        return result
    source, base, _, _ = _source(tmp_path, report=report)
    result = source.read(_query(["stability", "overextension"]), base.context())
    assert result["fields"]["stability"]["status"] == "known"
    assert result["fields"]["overextension"]["status"] == "unknown"
