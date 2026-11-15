from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path

import pytest

from bridge.information import home_trade_node_memory as home
from bridge.information import trade_income_memory as trade
from bridge.information.model import InformationError, canonical
from bridge.information.trade_home import NativeTradeHomeSource
from bridge.tests import test_information_trade_income_memory as trade_fixture


GAME_SHA256 = trade.EXPECTED_EXE_SHA256
TRADE_PROFILE_SHA256 = trade.EXPECTED_PROFILE_SHA256
HOME_PROFILE_SHA256 = home.EXPECTED_PROFILE_SHA256
SESSION_ID = "session-home-1"
CREATION_FILETIME = 134373102720165920
GAME_DATE = 56557728
MODULE_BASE = trade_fixture.MODULE_BASE
COUNTRY_POINTER = trade_fixture.COUNTRY_POINTER


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
    """Use real validators and pins with the existing bounded fake reader."""

    trade_profile = trade_fixture._profile()
    # Keep the old trade fixture's bounded layout, but load the checked-in
    # home profile verbatim.  It carries all five audited guards and the
    # real source-index/profile pin; the fake reader below installs those
    # exact bytes at its module base.
    home_profile = home._load_profile()
    # Replace only the trade layout with the bounded fixture layout.  The
    # checked-in pins and both real validators remain active.
    monkeypatch.setattr(trade, "_active_profile", lambda: trade_profile)
    monkeypatch.setattr(home, "_active_profile", lambda: home_profile)
    return trade_profile, home_profile


def _reader_with_home_guard(home_profile):
    reader = trade_fixture._build_reader()
    for guard in home_profile["code_guards"]:
        address = MODULE_BASE + int(guard["rva"], 0)
        reader.data[(address, len(bytes.fromhex(guard["hex"])))] = bytes.fromhex(guard["hex"])
    return reader


def _set_ad(reader, table: int, value: int) -> None:
    address = table + 7 * 0xC0
    raw = bytearray(reader.data[(address, 0xC0)])
    raw[0xAD] = value
    reader.data[(address, 0xC0)] = bytes(raw)


def _records(reader):
    trade_record = trade.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)
    assert trade_record["status"] == "observed"
    assert trade.validate_record(trade_record)
    home_record = home.read_fields(reader, MODULE_BASE, trade_record)
    assert home.validate_record(home_record, trade_record)
    return trade_record, home_record


def _snapshot(trade_record: dict, home_record: dict) -> dict:
    return {
        "status": "observed",
        "game_date": {"value": GAME_DATE, "raw_hex": "a0005f03"},
        "values": {"administrative": 0, "diplomatic": 0, "military": 0},
        "trade_income": deepcopy(trade_record),
        "home_trade_node": deepcopy(home_record),
    }


def _report(trade_record: dict, home_record: dict, base: _Base, *, include_home: bool = True) -> dict:
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
            "include_home_trade_node": include_home,
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
        "before": _snapshot(trade_record, home_record),
        "after": _snapshot(trade_record, home_record),
        "trade_income": deepcopy(trade_record),
        "home_trade_node": deepcopy(home_record),
        "completed": True,
    }


def _source(tmp_path: Path, report=None):
    base = _Base(tmp_path)
    calls = []

    def capture(installation, country, *, include_trade_income=False, include_home_trade_node=False):
        calls.append((installation, country, include_trade_income, include_home_trade_node))
        return deepcopy(report)

    return NativeTradeHomeSource(base, capture=capture), base, calls


def _query(object_: dict, fields=None, parameters=None) -> dict:
    return {
        "topic": "T02",
        "object": object_,
        "fields": ["home_node"] if fields is None else fields,
        "parameters": {} if parameters is None else parameters,
    }


def test_catalog_and_strict_country_selector(configured, tmp_path: Path):
    source, base, _ = _source(tmp_path)
    item = source.catalog()[0]
    assert item["topic_id"] == "T02"
    assert list(item["fields"]) == ["home_node"]
    assert item["fields"]["home_node"]["coverage"] == "partial"
    assert item["fields"]["home_node"]["basis"] == "native_trade_node_home_flag"
    assert item["triggers"] == ["query", "periodic"]
    assert source.validate_query(_query({"type": "country", "country": "FRA"}), base.context())["parameters"] == {}
    with pytest.raises(InformationError) as trade_node:
        source.validate_query(_query({"type": "trade_node", "node_id": "alpha"}))
    assert trade_node.value.code == "invalid_object"
    with pytest.raises(InformationError) as other_field:
        source.validate_query(_query({"type": "country", "country": "FRA"}, ["collect_node"]))
    assert other_field.value.code == "unknown_field"


def test_unique_home_uses_real_child_records_and_compact_provenance(configured, tmp_path: Path):
    reader = _reader_with_home_guard(configured[1])
    _set_ad(reader, trade_fixture.TABLE_ONE, 1)
    trade_record, home_record = _records(reader)
    base = _Base(tmp_path)
    report = _report(trade_record, home_record, base)
    source, base, capture_calls = _source(tmp_path, report)
    result = source.read(_query({"type": "country", "country": "FRA"}), base.context())
    field = result["fields"]["home_node"]
    assert field == {
        "status": "known",
        "value": "alpha",
        "unit": "trade_node",
        "scale": 1,
        "period": "current",
        "basis": "native_trade_node_home_flag",
        "value_origin": "derived_from_copied_native_flags",
        "complete": False,
        "native_home_flag_raw": 1,
        "native_home_flag_raw_hex": "01",
    }
    assert result["complete"] is False
    assert capture_calls == [(tmp_path / "installation.json", "FRA", True, True)]
    audit = result["source"]["provenance"]["home_trade_node"]
    assert audit["profile_sha256"] == HOME_PROFILE_SHA256
    assert audit["country_fullref_raw_hex"] == trade_record["country_fullref_raw_hex"]
    assert audit["country_slot"] == trade_record["country_slot"]
    assert audit["candidate_node_ids"] == ["alpha"]
    assert audit["nodes"] == [
        {"node_id": "alpha", "flag_ad": 1, "flag_ad_raw_hex": "01"},
        {"node_id": "beta", "flag_ad": 0, "flag_ad_raw_hex": "00"},
    ]
    assert "entry_raw_hex" not in audit
    assert audit["trade_income_record_canonical_sha256"] == hashlib.sha256(
        canonical(trade_record).encode("utf-8")
    ).hexdigest()


@pytest.mark.parametrize(
    "flags, expected",
    [([0, 0], "no_node_with_flag_ad"), ([1, 1], "multiple_nodes_with_flag_ad")],
)
def test_zero_or_multiple_candidates_are_real_unknown_records(configured, tmp_path: Path, flags, expected):
    reader = _reader_with_home_guard(configured[1])
    _set_ad(reader, trade_fixture.TABLE_ONE, flags[0])
    _set_ad(reader, trade_fixture.TABLE_TWO, flags[1])
    trade_record, home_record = _records(reader)
    assert home_record["reason"] == expected
    base = _Base(tmp_path)
    source, base, _ = _source(tmp_path, _report(trade_record, home_record, base))
    result = source.read(_query({"type": "country", "country": "FRA"}), base.context())
    assert result["fields"]["home_node"] == {"status": "unknown", "reason": expected}
    assert result["complete"] is False


def test_parent_or_child_validation_failure_never_returns_known(configured, tmp_path: Path):
    reader = _reader_with_home_guard(configured[1])
    _set_ad(reader, trade_fixture.TABLE_ONE, 1)
    trade_record, home_record = _records(reader)
    base = _Base(tmp_path)
    report = _report(trade_record, home_record, base)
    report["after"]["trade_income"]["total_raw"] += 1
    source, base, _ = _source(tmp_path, report)
    result = source.read(_query({"type": "country", "country": "FRA"}), base.context())
    assert result["fields"]["home_node"]["status"] == "unknown"
    assert "TRADE_HOME_TRADE_INCOME" in result["fields"]["home_node"]["reason"]

    report = _report(trade_record, home_record, base)
    report["after"]["home_trade_node"]["nodes"][0]["flag_ad_raw_hex"] = "00"
    source, base, _ = _source(tmp_path, report)
    result = source.read(_query({"type": "country", "country": "FRA"}), base.context())
    assert result["fields"]["home_node"]["status"] == "unknown"
    assert result["fields"]["home_node"]["reason"] == "TRADE_HOME_RECORD_INVALID"


def test_context_change_and_capture_exception_are_checked_after_attempt(configured, tmp_path: Path):
    reader = _reader_with_home_guard(configured[1])
    _set_ad(reader, trade_fixture.TABLE_ONE, 1)
    trade_record, home_record = _records(reader)
    base = _Base(tmp_path)
    report = _report(trade_record, home_record, base)
    source, base, _ = _source(tmp_path, report)
    base.after_context = {"game_date": GAME_DATE + 1, "game_date_raw": GAME_DATE + 1}
    result = source.read(_query({"type": "country", "country": "FRA"}), base.context())
    assert result["fields"]["home_node"]["status"] == "unknown"
    assert "CONTEXT_CHANGED" in result["fields"]["home_node"]["reason"]

    base = _Base(tmp_path)
    calls = []

    def failing_capture(*args, **kwargs):
        calls.append(kwargs)
        raise RuntimeError("reader failed")

    source = NativeTradeHomeSource(base, capture=failing_capture)
    result = source.read(_query({"type": "country", "country": "FRA"}), base.context())
    assert result["fields"]["home_node"]["status"] == "unknown"
    assert result["fields"]["home_node"]["reason"] == "TRADE_HOME_CAPTURE_FAILED:RuntimeError"
    assert calls == [{"include_trade_income": True, "include_home_trade_node": True}]


def test_polling_and_no_reference_side_effect(configured, tmp_path: Path):
    source, base, capture_calls = _source(tmp_path)
    assert source.poll_events(base.context(), {"offset": 2}) == {
        "events": [], "cursor": {"offset": 2}, "complete": True, "gaps": [],
    }
    assert capture_calls == []
