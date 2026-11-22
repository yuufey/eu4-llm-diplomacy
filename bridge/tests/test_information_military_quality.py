from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information import military_quality_memory as military
from bridge.information import military_tradition_memory as tradition
from bridge.information.model import InformationError
from bridge.information.military_quality import NativeMilitaryQualitySource
from bridge.tests import test_information_military_quality_memory as fixture


GAME_SHA256 = military.EXPECTED_EXE_SHA256
SESSION_ID = "session-military-quality-1"
CREATION_FILETIME = 134373102720165920
GAME_DATE = 56557728
MODULE_BASE = fixture.MODULE_BASE
COUNTRY_POINTER = fixture.COUNTRY_POINTER


class _Session:
    def __init__(self, directory: Path):
        self.directory = directory
        self.creation_filetime = CREATION_FILETIME
        self.record = {
            "session_id": SESSION_ID,
            "creation_filetime": CREATION_FILETIME,
        }


class _Base:
    def __init__(self, directory: Path):
        self.session = _Session(directory)
        self.calls = 0
        self.after_context = None

    def context(self) -> dict:
        self.calls += 1
        context = {
            "status": "ready",
            "complete": True,
            "mode": "live",
            "session_id": SESSION_ID,
            "game_sha256": GAME_SHA256,
            "game_version": "1.37.4",
            "observer": "FRA",
            "game_date": GAME_DATE,
            "game_date_raw": GAME_DATE,
        }
        if self.after_context is not None and self.calls >= 3:
            context.update(deepcopy(self.after_context))
        return context


def _reader_with_guard():
    return fixture._reader(index=3, value=7)


def _child():
    record = military.read_fields(_reader_with_guard(), MODULE_BASE, COUNTRY_POINTER)
    assert record["status"] == "observed"
    assert military.validate_record(record)
    return record


def _tradition_child(value: int = -1250):
    reader = _reader_with_guard()
    profile = tradition._load_profile()
    for _name, rva, _end, raw in tradition._profile_code_guards(profile):
        reader.put(MODULE_BASE + rva, raw)
    reader.i32(COUNTRY_POINTER + tradition.COUNTRY_OFFSET, value)
    record = tradition.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)
    assert record["status"] == "observed"
    assert tradition.validate_record(record)
    return record


def _pointer_scan():
    return {
        "status": "observed",
        "requested_country": "FRA",
        "country_pointer": {"va": hex(COUNTRY_POINTER), "rva": None},
    }


def _snapshot(child: dict, tradition_child: dict | None = None):
    snapshot = {
        "status": "observed",
        "game_date": {"value": GAME_DATE, "raw_hex": "a0005f03"},
        "country_scan": _pointer_scan(),
        "values": {"administrative": 0, "diplomatic": 0, "military": 0},
        "military_quality": deepcopy(child),
    }
    if tradition_child is not None:
        snapshot["military_tradition"] = deepcopy(tradition_child)
    return snapshot


def _report(base: _Base, child: dict | None = None, tradition_child: dict | None = None):
    child = _child() if child is None else deepcopy(child)
    report = {
        "probe": "information-country-resources-runtime",
        "status": "observed",
        "read_only": True,
        "native_function_invoked": False,
        "country": "FRA",
        "target_build": {"version": "1.37.4", "expected_exe_sha256": GAME_SHA256},
        "request": {
            "installation": str(base.session.directory / "installation.json"),
            "country": "FRA",
            "include_military_quality": True,
        },
        "identity": {
            "binding_verified": True,
            "process_path_sha256": GAME_SHA256,
            "installation_session_id": SESSION_ID,
            "installation_creation_filetime": CREATION_FILETIME,
            "process_creation_filetime": CREATION_FILETIME,
        },
        "module_base": {"va": hex(MODULE_BASE), "rva": None},
        "static_contract_guard": {"status": "observed", "checks": {"profile": True}},
        "file_code_guard": {"status": "observed", "checks": {"file": True}},
        "runtime_code_guard": {"status": "observed", "checks": {"runtime": True}},
        "doublepass": {"performed": True, "consistent": True, "mismatches": []},
        "cleanup": {"handle_close": {"status": "closed", "closed": True}},
        "before": _snapshot(child, tradition_child),
        "after": _snapshot(child, tradition_child),
        "military_quality": deepcopy(child),
        "values": {"administrative": 0, "diplomatic": 0, "military": 0},
        "unit": "monarch_points",
        "scale": 1,
        "completed": True,
    }
    if tradition_child is not None:
        report["military_tradition"] = deepcopy(tradition_child)
    return report


def _source(tmp_path: Path, report=None):
    base = _Base(tmp_path)
    calls = []

    def capture(installation, country, **kwargs):
        calls.append((installation, country, kwargs))
        return deepcopy(report if report is not None else _report(base))

    return NativeMilitaryQualitySource(base, capture=capture), base, calls


def _query(fields=None):
    return {
        "topic": "N03",
        "object": {"type": "country", "country": "FRA"},
        "fields": ["military_technology"] if fields is None else fields,
        "parameters": {},
    }


def test_catalog_and_default_scope_are_explicit(tmp_path: Path):
    source, base, _ = _source(tmp_path)
    item = source.catalog()[0]
    assert item["topic_id"] == "N03"
    assert item["triggers"] == ["query", "periodic"]
    assert item["fields"]["military_technology"]["coverage"] == "available"
    assert item["fields"]["military_technology"]["complete"] is True
    assert item["fields"]["army_tradition"]["coverage"] == "available"
    assert source.validate_query(_query(), base.context())["parameters"] == {}
    with pytest.raises(InformationError) as other_country:
        source.validate_query({**_query(), "object": {"type": "country", "country": "ENG"}}, base.context())
    assert other_country.value.code == "observer_scope_mismatch"
    with pytest.raises(InformationError) as extra_field:
        source.validate_query(_query(["military_modifiers"]))
    assert extra_field.value.code == "unknown_field"


def test_known_technology_uses_real_child_validator_and_single_capture(tmp_path: Path):
    source, base, calls = _source(tmp_path)
    result = source.read(_query(), base.context())
    assert result["fields"]["military_technology"] == {
        "status": "known",
        "complete": True,
        "value": 7,
        "raw": 7,
        "raw_hex": "07000000",
        "unit": "technology_level",
        "scale": 1,
        "basis": military.BASIS,
        "period": "current",
        "value_origin": military.VALUE_ORIGIN,
    }
    assert result["complete"] is True
    assert result["source"]["name"] == "NativeMilitaryQualitySource"
    assert result["source"]["context_scope"] == "country_scope"
    assert calls == [
        (tmp_path / "installation.json", "FRA", {"include_military_quality": True})
    ]
    assert result["source"]["provenance"]["military_quality"]["field"]["raw_hex"] == "07000000"


def test_parent_and_child_tampering_never_returns_known(tmp_path: Path):
    base = _Base(tmp_path)
    report = _report(base)
    report["after"]["military_quality"]["values"]["military_technology"] += 1
    source, base, _ = _source(tmp_path, report)
    result = source.read(_query(), base.context())
    assert result["fields"]["military_technology"]["status"] == "unknown"
    assert "RECORD_INVALID" in result["fields"]["military_technology"]["reason"]

    base = _Base(tmp_path)
    report = _report(base)
    report["after"]["country_scan"]["country_pointer"]["va"] = hex(COUNTRY_POINTER + 0x10)
    source, base, _ = _source(tmp_path, report)
    result = source.read(_query(), base.context())
    assert result["fields"]["military_technology"]["status"] == "unknown"
    assert result["fields"]["military_technology"]["reason"] == "MILITARY_QUALITY_MILITARY_TECHNOLOGY_AFTER_COUNTRY_BINDING_INVALID"


def test_context_change_after_capture_retracts_known_and_capture_exception_is_checked(tmp_path: Path):
    source, base, _ = _source(tmp_path)
    base.after_context = {"game_date": GAME_DATE + 1, "game_date_raw": GAME_DATE + 1}
    result = source.read(_query(), base.context())
    assert result["fields"]["military_technology"]["status"] == "unknown"
    assert "CONTEXT_CHANGED" in result["fields"]["military_technology"]["reason"]

    base = _Base(tmp_path)
    calls = []

    def failing_capture(*args, **kwargs):
        calls.append((args, kwargs))
        raise RuntimeError("reader failed")

    source = NativeMilitaryQualitySource(base, capture=failing_capture)
    result = source.read(_query(), base.context())
    assert result["fields"]["military_technology"] == {
        "status": "unknown", "reason": "MILITARY_QUALITY_CAPTURE_FAILED:RuntimeError"
    }
    assert calls and calls[0][1] == {"include_military_quality": True}


def test_mixed_technology_and_tradition_are_independently_validated(tmp_path: Path):
    tech = _child()
    trad = _tradition_child()
    base = _Base(tmp_path)
    report = _report(base, tech, trad)
    source, base, calls = _source(tmp_path, report)
    result = source.read(_query(["military_technology", "army_tradition"]), base.context())
    assert result["fields"]["military_technology"]["status"] == "known"
    assert result["fields"]["army_tradition"] == {
        "status": "known",
        "complete": True,
        "value": -1250,
        "raw": -1250,
        "raw_hex": "1efbffff",
        "unit": "army_tradition",
        "scale": 1000,
        "basis": tradition.BASIS,
        "period": "current",
        "value_origin": tradition.VALUE_ORIGIN,
    }
    assert result["complete"] is True
    assert len(calls) == 1 and calls[0][2] == {"include_military_quality": True}

    # A broken technology child does not erase an independently valid
    # tradition child from the same guarded capture.
    base = _Base(tmp_path)
    report = _report(base, tech, trad)
    report["after"]["military_quality"]["values"]["military_technology"] += 1
    source, base, _ = _source(tmp_path, report)
    result = source.read(_query(["military_technology", "army_tradition"]), base.context())
    assert result["fields"]["military_technology"]["status"] == "unknown"
    assert result["fields"]["army_tradition"]["status"] == "known"
    assert result["complete"] is False

