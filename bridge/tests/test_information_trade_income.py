from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import sys
import types

import pytest

from bridge.information.model import InformationError, canonical
from bridge.information.trade_income import NativeTradeIncomeSource


GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
PROFILE_SHA256 = "a" * 64
SESSION_ID = "session-trade-1"
CREATION_FILETIME = 134373102720165920
GAME_DATE = 56557728


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


def _raw_hex(value: int) -> str:
    return (value & 0xFFFFFFFF).to_bytes(4, "little", signed=False).hex()


def _node(
    node_id: str,
    cache_income_raw: int,
    *,
    eligible: bool = True,
) -> dict:
    income_raw = cache_income_raw if eligible else 0
    return {
        "node_id": node_id,
        "cache_income_raw": cache_income_raw,
        "cache_income_raw_hex": _raw_hex(cache_income_raw),
        "income_raw": income_raw,
        "income_raw_hex": _raw_hex(income_raw),
        "eligible": eligible,
        "value_origin": (
            "copied_native_cache"
            if eligible else "derived_from_copied_native_caches"
        ),
        "flags": {"predicate_rva": "0x8f440" if eligible else "0x8f450"},
        "raw_graph": {
            "definition_pointer_raw_hex": "0011223344556677",
            "predicate_rva": "0x8f440" if eligible else "0x8f450",
        },
    }


def _record(*, nodes: list[dict] | None = None, valid: bool = True) -> dict:
    nodes = nodes or [_node("champagne", 3813), _node("lubeck", 0)]
    total = 0
    for node in nodes:
        total = (total + node["income_raw"]) & 0xFFFFFFFF
        if total & 0x80000000:
            total -= 0x100000000
    return {
        "status": "observed",
        "_valid": valid,
        "profile_sha256": PROFILE_SHA256,
        "static_contract_guard": {"status": "observed", "checks": {"profile": True}},
        "runtime_code_guard": {"status": "observed", "checks": {"trade": True}},
        "country": "FRA",
        "country_fullref_raw_hex": "465241007a000001",
        "country_slot": 122,
        "graph": {
            "node_count": 3,
            "real_node_count": len(nodes),
            "placeholder_count": 3 - len(nodes),
        },
        "nodes": deepcopy(nodes),
        "total_raw": total,
        "total_raw_hex": _raw_hex(total),
        "basis": "native_trade_node_country_income_cache",
        "unit": "ducats",
        "scale": 1000,
        "period": "month",
        "value_origin": "derived_from_copied_native_caches",
    }


def _snapshot(record: dict) -> dict:
    return {
        "status": "observed",
        "game_date": {"value": GAME_DATE, "raw_hex": _raw_hex(GAME_DATE)},
        "values": {"administrative": 0, "diplomatic": 0, "military": 0},
        "trade_income": deepcopy(record),
    }


def _report(record: dict, base: _Base) -> dict:
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
        "before": _snapshot(record),
        "after": _snapshot(record),
        "trade_income": deepcopy(record),
        "completed": True,
    }


@pytest.fixture
def fake_trade_memory(monkeypatch: pytest.MonkeyPatch):
    calls: list[dict] = []
    module = types.ModuleType("bridge.information.trade_income_memory")
    module.EXPECTED_PROFILE_SHA256 = PROFILE_SHA256

    def validate_record(record):
        calls.append(record)
        return isinstance(record, dict) and record.get("_valid") is True

    module.validate_record = validate_record
    monkeypatch.setitem(sys.modules, "bridge.information.trade_income_memory", module)
    return calls


def _source(tmp_path: Path, report=None):
    base = _Base(tmp_path)
    calls: list[tuple[Path, str, bool]] = []

    def capture(installation, country, *, include_trade_income=False):
        calls.append((installation, country, include_trade_income))
        return deepcopy(report if report is not None else _report(_record(), base))

    return NativeTradeIncomeSource(base, capture=capture), base, calls


def _query(object_: dict, fields=None, parameters=None) -> dict:
    return {
        "topic": "T05",
        "object": object_,
        "fields": ["income"] if fields is None else fields,
        "parameters": {} if parameters is None else parameters,
    }


def test_catalog_and_strict_selectors(fake_trade_memory, tmp_path: Path):
    source, base, _ = _source(tmp_path)
    item = source.catalog()[0]
    assert item["topic_id"] == "T05"
    assert item["fields"]["income"]["coverage"] == "partial"
    assert item["fields"]["income"]["unit"] == "ducats"
    assert item["fields"]["income"]["scale"] == 1000
    assert item["triggers"] == ["query", "periodic"]
    assert source.validate_query(_query({"type": "country", "country": "FRA"}), base.context())["parameters"] == {}
    assert source.validate_query(_query({"type": "trade_node", "node_id": "champagne"}))
    with pytest.raises(InformationError):
        source.validate_query(_query({"type": "country", "country": "ENG"}))
    with pytest.raises(InformationError):
        source.validate_query(_query({"type": "trade_node", "node_id": "非ASCII"}))
    with pytest.raises(InformationError):
        source.validate_query(_query({"type": "country", "country": "FRA"}, parameters={"x": 1}))


def test_country_total_and_trade_node_preserve_raw_cache(fake_trade_memory, tmp_path: Path):
    source, base, capture_calls = _source(tmp_path)
    country = source.read(_query({"type": "country", "country": "FRA"}), base.context())
    assert country["fields"]["income"] == {
        "status": "known", "value": 3813, "raw": 3813,
        "raw_hex": "e50e0000", "unit": "ducats", "scale": 1000,
        "period": "month", "basis": "native_trade_node_country_income_cache",
        "value_origin": "derived_from_copied_native_caches", "complete": False,
    }
    assert country["complete"] is False
    assert capture_calls == [(tmp_path / "installation.json", "FRA", True)]
    country_audit = country["source"]["provenance"]["trade_income"]
    assert country_audit["graph_counts"] == {
        "node_count": 3, "real_node_count": 2, "placeholder_count": 1,
    }
    assert len(country_audit["nodes"]) == 2
    assert sum(item["income_raw"] for item in country_audit["nodes"]) == 3813
    assert all(
        "raw_graph" not in item
        and "entry_raw_hex" not in item
        and "definition_pointer" not in item
        and "entry_pointer" not in item
        for item in country_audit["nodes"]
    )
    assert country_audit["record_canonical_sha256"] == hashlib.sha256(
        canonical(fake_trade_memory[0]).encode("utf-8")
    ).hexdigest()

    node = source.read(_query({"type": "trade_node", "node_id": "champagne"}), base.context())
    item = node["fields"]["income"]
    assert item["status"] == "known"
    assert item["value"] == item["raw"] == 3813
    assert item["cache_income_raw"] == 3813
    assert item["eligible"] is True
    assert item["value_origin"] == "copied_native_cache"
    node_audit = node["source"]["provenance"]["trade_income"]
    assert [item["node_id"] for item in node_audit["nodes"]] == ["champagne"]
    assert all(
        "raw_graph" not in item
        and "entry_raw_hex" not in item
        and "definition_pointer" not in item
        and "entry_pointer" not in item
        for item in node_audit["nodes"]
    )
    assert node_audit["record_canonical_sha256"] == hashlib.sha256(
        canonical(fake_trade_memory[3]).encode("utf-8")
    ).hexdigest()
    # Each parent report contains top, before and after child records.
    assert len(fake_trade_memory) == 6


def test_zero_negative_and_ineligible_contribution_are_preserved(fake_trade_memory, tmp_path: Path):
    record = _record(nodes=[_node("champagne", -7), _node("lubeck", 9, eligible=False)])
    source, base, _ = _source(tmp_path, _report(record, _Base(tmp_path)))
    result = source.read(_query({"type": "trade_node", "node_id": "lubeck"}), base.context())
    item = result["fields"]["income"]
    assert item["status"] == "known"
    assert item["value"] == item["raw"] == 0
    assert item["cache_income_raw"] == 9
    assert item["eligible"] is False
    assert item["value_origin"] == "derived_from_copied_native_caches"

    total = source.read(_query({"type": "country", "country": "FRA"}), base.context())
    assert total["fields"]["income"]["value"] == -7


def test_missing_node_is_unknown_and_does_not_become_zero(fake_trade_memory, tmp_path: Path):
    source, base, _ = _source(tmp_path)
    result = source.read(_query({"type": "trade_node", "node_id": "unknown_node"}), base.context())
    assert result["fields"]["income"] == {"status": "unknown", "reason": "NODE_NOT_FOUND"}
    assert result["complete"] is False


@pytest.mark.parametrize(
    "mutation, expected",
    [
        (lambda report: report["doublepass"].update(consistent=False), "DOUBLEPASS"),
        (lambda report: report["cleanup"]["handle_close"].update(status="error", closed=False), "CLEANUP"),
        (lambda report: report["identity"].update(binding_verified=False), "IDENTITY"),
        (lambda report: report["before"]["game_date"].update(value=GAME_DATE + 1), "DATE"),
    ],
)
def test_parent_contract_failures_retract_value(fake_trade_memory, tmp_path: Path, mutation, expected):
    base = _Base(tmp_path)
    report = _report(_record(), base)
    mutation(report)
    source, base, _ = _source(tmp_path, report)
    result = source.read(_query({"type": "country", "country": "FRA"}), base.context())
    assert result["fields"]["income"]["status"] == "unknown"
    assert expected in result["fields"]["income"]["reason"]


def test_top_before_after_mismatch_and_child_validator_are_rejected(fake_trade_memory, tmp_path: Path):
    base = _Base(tmp_path)
    report = _report(_record(), base)
    report["after"]["trade_income"]["nodes"][0]["raw_graph"]["changed"] = True
    source, base, _ = _source(tmp_path, report)
    result = source.read(_query({"type": "country", "country": "FRA"}), base.context())
    assert result["fields"]["income"]["status"] == "unknown"
    assert "SNAPSHOT_MISMATCH" in result["fields"]["income"]["reason"]

    invalid = _record(valid=False)
    source, base, _ = _source(tmp_path, _report(invalid, base))
    result = source.read(_query({"type": "country", "country": "FRA"}), base.context())
    assert result["fields"]["income"]["status"] == "unknown"
    assert "RECORD_INVALID" in result["fields"]["income"]["reason"]
    audit = result["source"]["provenance"]["trade_income"]
    assert audit["reason"] == "TRADE_INCOME_RECORD_INVALID"
    assert audit["record_canonical_sha256"] is not None
    assert "nodes" not in audit
    assert len(fake_trade_memory) == 4


def test_context_change_after_capture_retracts_child(fake_trade_memory, tmp_path: Path):
    source, base, _ = _source(tmp_path)
    base.after_context = {"game_date": GAME_DATE + 1, "game_date_raw": GAME_DATE + 1}
    result = source.read(_query({"type": "country", "country": "FRA"}), base.context())
    assert result["fields"]["income"]["status"] == "unknown"
    assert "CONTEXT_CHANGED" in result["fields"]["income"]["reason"]


def test_no_mission_or_game_function_and_no_change_events(fake_trade_memory, tmp_path: Path):
    source, base, _ = _source(tmp_path)
    result = source.poll_events(base.context(), {"offset": 3})
    assert result == {
        "events": [], "cursor": {"offset": 3}, "complete": True, "gaps": [],
    }
