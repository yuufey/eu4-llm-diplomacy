from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path

import pytest

from bridge.information import trade_income_memory as trade
from bridge.information import trade_power_memory as power
from bridge.information.model import InformationError
from bridge.information.trade_power import NativeTradePowerSource
from bridge.tests import test_information_trade_income_memory as trade_fixture


GAME_SHA256 = trade.EXPECTED_EXE_SHA256
SESSION_ID = "session-power-1"
CREATION_FILETIME = 134373102720165920
GAME_DATE = 56557728
MODULE_BASE = trade_fixture.MODULE_BASE
COUNTRY_POINTER = trade_fixture.COUNTRY_POINTER
POWER_PROFILE_SHA256 = hashlib.sha256(power.PROFILE_FILE.read_bytes()).hexdigest()


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


@pytest.fixture
def configured(monkeypatch: pytest.MonkeyPatch):
    """Use the checked-in power profile and both real child validators."""

    trade_profile = trade_fixture._profile()
    power_profile = power._load_profile(expected_sha256=POWER_PROFILE_SHA256)
    # The production pin is deliberately supplied by the neighboring low-level
    # integration task.  A pending pin during this adapter test must still use
    # the checked-in profile bytes, never a synthetic record or validator.
    if power.EXPECTED_PROFILE_SHA256 == "pending-profile":
        monkeypatch.setattr(power, "EXPECTED_PROFILE_SHA256", POWER_PROFILE_SHA256)
    monkeypatch.setattr(trade, "_active_profile", lambda: trade_profile)
    monkeypatch.setattr(power, "_active_profile", lambda: power_profile)
    return trade_profile, power_profile


def _reader_with_power_guard(power_profile):
    reader = trade_fixture._build_reader()
    for guard in power_profile["code_guards"]:
        address = MODULE_BASE + int(guard["rva"], 0)
        reader.data[(address, len(bytes.fromhex(guard["hex"])))] = bytes.fromhex(guard["hex"])
    reader.data[(trade_fixture.RUNTIME_ONE + power.RUNTIME_TOTAL_POWER_OFFSET, 4)] = trade_fixture._i32(746110)
    reader.data[(trade_fixture.RUNTIME_TWO + power.RUNTIME_TOTAL_POWER_OFFSET, 4)] = trade_fixture._i32(-42)
    return reader


def _set_power_components(reader, table: int, values: tuple[int, int, int, int, int]) -> None:
    address = table + 7 * 0xC0
    raw = bytearray(reader.data[(address, 0xC0)])
    for offset, value in zip(power.ENTRY_POWER_OFFSETS, values):
        raw[offset:offset + 4] = trade_fixture._i32(value)
    reader.data[(address, 0xC0)] = bytes(raw)


def _records(reader):
    trade_record = trade.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)
    assert trade_record["status"] == "observed"
    assert trade.validate_record(trade_record)
    power_record = power.read_fields(reader, MODULE_BASE, trade_record)
    assert power_record["status"] == "observed"
    assert power.validate_record(power_record, trade_record)
    return trade_record, power_record


def _snapshot(trade_record: dict, power_record: dict) -> dict:
    return {
        "status": "observed",
        "game_date": {"value": GAME_DATE, "raw_hex": "a0005f03"},
        "values": {"administrative": 0, "diplomatic": 0, "military": 0},
        "trade_income": deepcopy(trade_record),
        "trade_power": deepcopy(power_record),
    }


def _report(trade_record: dict, power_record: dict, base: _Base) -> dict:
    return {
        "probe": "information-country-resources-runtime",
        "status": "observed",
        "read_only": True,
        "native_function_invoked": False,
        "country": "FRA",
        "target_build": {"version": "1.37.4", "expected_exe_sha256": GAME_SHA256},
        "request": {
            "installation": str(base.session.directory / "installation.json"),
            "country": "FRA",
            "include_trade_income": True,
            "include_trade_power": True,
        },
        "identity": {
            "binding_verified": True,
            "process_path_sha256": GAME_SHA256,
            "installation_session_id": SESSION_ID,
            "installation_creation_filetime": CREATION_FILETIME,
            "process_creation_filetime": CREATION_FILETIME,
        },
        "static_contract_guard": {"status": "observed", "checks": {"profile": True}},
        "file_code_guard": {"status": "observed", "checks": {"file": True}},
        "runtime_code_guard": {"status": "observed", "checks": {"runtime": True}},
        "doublepass": {"performed": True, "consistent": True, "mismatches": []},
        "cleanup": {"handle_close": {"status": "closed", "closed": True}},
        "before": _snapshot(trade_record, power_record),
        "after": _snapshot(trade_record, power_record),
        "trade_income": deepcopy(trade_record),
        "trade_power": deepcopy(power_record),
        "completed": True,
    }


def _source(tmp_path: Path, report=None):
    base = _Base(tmp_path)
    calls = []

    def capture(installation, country, *, include_trade_income=False, include_trade_power=False):
        calls.append((installation, country, include_trade_income, include_trade_power))
        return deepcopy(report)

    return NativeTradePowerSource(base, capture=capture), base, calls


def _query(node_id: str, fields=None, parameters=None) -> dict:
    return {
        "topic": "T04",
        "object": {"type": "trade_node", "node_id": node_id},
        "fields": ["country_power", "total_power"] if fields is None else fields,
        "parameters": {} if parameters is None else parameters,
    }


def test_catalog_and_strict_scope(configured, tmp_path: Path):
    source, base, _ = _source(tmp_path)
    item = source.catalog()[0]
    assert item["topic_id"] == "T04"
    assert list(item["fields"]) == ["country_power", "total_power"]
    assert all(item["fields"][field]["coverage"] == "partial" for field in item["fields"])
    assert item["object_types"] == ["trade_node"]
    assert item["triggers"] == ["query", "periodic"]
    assert item["parameters"]["required"] == []
    assert source.validate_query(_query("alpha"), base.context())["parameters"] == {}
    for field in ("shares", "sources"):
        with pytest.raises(InformationError) as error:
            source.validate_query(_query("alpha", [field]))
        assert error.value.code == "unknown_field"
    with pytest.raises(InformationError) as wrong_object:
        source.validate_query({**_query("alpha"), "object": {"type": "country", "country": "FRA"}})
    assert wrong_object.value.code == "invalid_object"
    with pytest.raises(InformationError) as nonempty_parameters:
        source.validate_query(_query("alpha", parameters={"foo": 1}))
    assert nonempty_parameters.value.code == "invalid_parameters"


def test_known_values_use_one_capture_and_compact_real_child_provenance(configured, tmp_path: Path):
    reader = _reader_with_power_guard(configured[1])
    _set_power_components(reader, trade_fixture.TABLE_ONE, (1053, 123767, 117538, 0, 51131))
    _set_power_components(reader, trade_fixture.TABLE_TWO, (1000, 2000, 500, -100, 50))
    trade_record, power_record = _records(reader)
    base = _Base(tmp_path)
    source, base, calls = _source(tmp_path, _report(trade_record, power_record, base))
    result = source.read(_query("alpha"), base.context())
    assert result["complete"] is False
    assert calls == [(tmp_path / "installation.json", "FRA", True, True)]
    alpha = next(node for node in power_record["nodes"] if node["node_id"] == "alpha")
    assert result["fields"]["country_power"] == {
        "status": "known",
        "value": alpha["country_power_raw"],
        "raw": alpha["country_power_raw"],
        "raw_hex": alpha["country_power_raw_hex"],
        "unit": "trade_power",
        "scale": 1000,
        "period": "current",
        "basis": "native_trade_node_power_caches",
        "value_origin": "derived_from_copied_native_caches",
        "complete": False,
    }
    assert result["fields"]["total_power"]["value"] == alpha["total_power_raw"]
    assert result["fields"]["total_power"]["raw_hex"] == alpha["total_power_raw_hex"]
    assert result["fields"]["total_power"]["value_origin"] == "copied_native_cache"
    audit = result["source"]["provenance"]["trade_power"]
    assert audit["profile_sha256"] == POWER_PROFILE_SHA256
    assert audit["requested_node_id"] == "alpha"
    assert audit["node"]["node_id"] == "alpha"
    assert audit["node"]["country_power_raw"] == alpha["country_power_raw"]
    assert audit["node"]["entry_power_components_raw"] == alpha["entry_power_components_raw"]
    assert audit["node"]["entry_power_components_raw_hex"] == alpha["entry_power_components_raw_hex"]
    assert "nodes" not in audit
    assert audit["trade_income_record_canonical_sha256"]
    assert audit["record_canonical_sha256"]


def test_unknown_node_is_explicit_after_real_children_are_validated(configured, tmp_path: Path):
    reader = _reader_with_power_guard(configured[1])
    trade_record, power_record = _records(reader)
    base = _Base(tmp_path)
    source, base, calls = _source(tmp_path, _report(trade_record, power_record, base))
    result = source.read(_query("not_a_native_node"), base.context())
    assert result["fields"] == {
        "country_power": {"status": "unknown", "reason": "NODE_NOT_FOUND"},
        "total_power": {"status": "unknown", "reason": "NODE_NOT_FOUND"},
    }
    assert calls and calls[0][2:] == (True, True)


def test_parent_or_power_child_tamper_never_returns_known(configured, tmp_path: Path):
    reader = _reader_with_power_guard(configured[1])
    trade_record, power_record = _records(reader)
    base = _Base(tmp_path)
    report = _report(trade_record, power_record, base)
    report["after"]["trade_income"]["total_raw"] += 1
    source, base, _ = _source(tmp_path, report)
    result = source.read(_query("alpha"), base.context())
    assert all(item["status"] == "unknown" for item in result["fields"].values())
    assert "TRADE_INCOME" in result["fields"]["country_power"]["reason"]

    report = _report(trade_record, power_record, base)
    report["after"]["trade_power"]["nodes"][0]["total_power_raw"] += 1
    source, base, _ = _source(tmp_path, report)
    result = source.read(_query("alpha"), base.context())
    assert all(item["status"] == "unknown" for item in result["fields"].values())
    assert "TRADE_POWER" in result["fields"]["country_power"]["reason"]


def test_context_change_and_capture_exception_are_checked_after_attempt(configured, tmp_path: Path):
    reader = _reader_with_power_guard(configured[1])
    trade_record, power_record = _records(reader)
    base = _Base(tmp_path)
    report = _report(trade_record, power_record, base)
    source, base, calls = _source(tmp_path, report)
    base.after_context = {"game_date": GAME_DATE + 1, "game_date_raw": GAME_DATE + 1}
    result = source.read(_query("alpha"), base.context())
    assert all(item["status"] == "unknown" for item in result["fields"].values())
    assert "CONTEXT_CHANGED" in result["fields"]["country_power"]["reason"]
    assert calls == [(tmp_path / "installation.json", "FRA", True, True)]

    base = _Base(tmp_path)
    calls = []

    def failing_capture(*args, **kwargs):
        calls.append(kwargs)
        raise RuntimeError("reader failed")

    source = NativeTradePowerSource(base, capture=failing_capture)
    result = source.read(_query("alpha"), base.context())
    assert all(item["status"] == "unknown" for item in result["fields"].values())
    assert result["fields"]["country_power"]["reason"] == "TRADE_POWER_CAPTURE_FAILED:RuntimeError"
    assert calls == [{"include_trade_income": True, "include_trade_power": True}]


def test_polling_is_query_only_and_does_not_capture(configured, tmp_path: Path):
    source, base, calls = _source(tmp_path)
    assert source.poll_events(base.context(), {"offset": 2}) == {
        "events": [], "cursor": {"offset": 2}, "complete": True, "gaps": [],
    }
    assert calls == []
