from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information import country_resources_memory as crm
from bridge.information import home_trade_node_memory as home
from bridge.information import trade_income_memory as trade
from bridge.tests import test_information_trade_income_memory as old_fixture


MODULE_BASE = old_fixture.MODULE_BASE
COUNTRY_POINTER = old_fixture.COUNTRY_POINTER
HANDLE = 0x7788


def _home_profile() -> dict:
    return {
        "profile_id": "home-trade-node-memory-1374",
        "game_version": home.EXPECTED_VERSION,
        "executable": {"sha256": home.EXPECTED_EXE_SHA256},
        "source_index": {
            "source_index_id": "home-node-source-001",
            "path": "work/runtime/information-trade-state-20261027-001/home-node-source-001.json",
            "sha256": "c" * 64,
        },
        "layout": {
            "entry_home_flag_offset": "0xad",
            "required_home_count": 1,
            "source_trade_profile_sha256": "b" * 64,
        },
        "code_guards": [{"name": "ad_leaf", "rva": "0x500", "hex": "aabb"}],
    }


@pytest.fixture
def configured(monkeypatch: pytest.MonkeyPatch):
    old_profile = old_fixture._profile()
    monkeypatch.setattr(trade, "EXPECTED_PROFILE_SHA256", "b" * 64)
    monkeypatch.setattr(trade, "_active_profile", lambda: old_profile)
    monkeypatch.setattr(home, "EXPECTED_PROFILE_SHA256", "h" * 64)
    monkeypatch.setattr(home, "EXPECTED_TRADE_PROFILE_SHA256", "b" * 64)
    profile = _home_profile()
    monkeypatch.setattr(home, "_active_profile", lambda: profile)
    return profile


def _reader_with_home_guard():
    reader = old_fixture._build_reader()
    reader.data[(MODULE_BASE + 0x500, 2)] = bytes.fromhex("aabb")
    return reader


def _set_ad(reader, table: int, value: int) -> None:
    address = table + 7 * 0xC0
    raw = bytearray(reader.data[(address, 0xC0)])
    raw[0xAD] = value
    reader.data[(address, 0xC0)] = bytes(raw)


def _old_record(reader):
    record = trade.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)
    assert record["status"] == "observed"
    assert trade.validate_record(record)
    return record


def test_unique_ad_derives_home_node_from_complete_old_record(configured):
    reader = _reader_with_home_guard()
    _set_ad(reader, old_fixture.TABLE_ONE, 1)
    source = _old_record(reader)

    record = home.read_fields(reader, MODULE_BASE, source)

    assert record["status"] == "observed"
    assert record["home_node"] == "alpha"
    assert record["derived_nodes"] == ["alpha"]
    assert record["nodes"][0] == {"node_id": "alpha", "flag_ad": 1, "flag_ad_raw_hex": "01"}
    assert record["nodes"][1]["flag_ad"] == 0
    assert record["basis"] == "native_trade_node_home_flag"
    assert record["value_origin"] == "derived_from_copied_native_flags"
    assert home.validate_record(record, source)
    assert [label for _address, _size, label in reader.reads if label.startswith("home_trade_node.code.")] == [
        "home_trade_node.code.ad_leaf"
    ]


def test_zero_ad_is_unknown_and_keeps_compact_candidates(configured):
    reader = _reader_with_home_guard()
    source = _old_record(reader)

    record = home.read_fields(reader, MODULE_BASE, source)

    assert record["status"] == "unknown"
    assert record["home_node"] is None
    assert record["derived_nodes"] == []
    assert record["reason"] == "no_node_with_flag_ad"
    assert record["nodes"]
    assert home.validate_record(record, source)


def test_multiple_ad_is_unknown_without_arbitrary_home(configured):
    reader = _reader_with_home_guard()
    _set_ad(reader, old_fixture.TABLE_ONE, 1)
    _set_ad(reader, old_fixture.TABLE_TWO, 1)
    source = _old_record(reader)

    record = home.read_fields(reader, MODULE_BASE, source)

    assert record["status"] == "unknown"
    assert record["home_node"] is None
    assert record["derived_nodes"] == ["alpha", "beta"]
    assert record["reason"] == "multiple_nodes_with_flag_ad"
    assert home.validate_record(record, source)


def test_old_record_validation_precedes_pending_profile_and_rpm(monkeypatch, configured):
    reader = _reader_with_home_guard()
    source = _old_record(reader)

    class BombReader:
        def __init__(self):
            self.calls = 0

        def read(self, *_args):
            self.calls += 1
            raise AssertionError("home reader must not RPM when profile is pending")

    bomb = BombReader()

    def reject_profile():
        raise home.ProfileError("profile_sha256_pending_or_invalid")

    monkeypatch.setattr(home, "_active_profile", reject_profile)
    record = home.read_fields(bomb, MODULE_BASE, source)

    assert record["status"] == "unknown"
    assert record["reason"].startswith("profile_unavailable:")
    assert bomb.calls == 0


def test_validation_rejects_source_digest_raw_ad_fullref_and_guard_tampering(configured):
    reader = _reader_with_home_guard()
    _set_ad(reader, old_fixture.TABLE_ONE, 1)
    source = _old_record(reader)
    record = home.read_fields(reader, MODULE_BASE, source)
    assert home.validate_record(record, source)

    changed = deepcopy(record)
    changed["source_trade_record_canonical_sha256"] = "0" * 64
    assert not home.validate_record(changed, source)

    changed = deepcopy(record)
    changed["nodes"][0]["flag_ad_raw_hex"] = "00"
    assert not home.validate_record(changed, source)

    changed = deepcopy(record)
    changed["country_fullref_raw_hex"] = "504f5200" + changed["country_fullref_raw_hex"][8:]
    assert not home.validate_record(changed, source)

    changed = deepcopy(record)
    changed["runtime_code_guard"]["checks"]["ad_leaf"] = False
    assert not home.validate_record(changed, source)

    changed = deepcopy(record)
    changed["module_base"] = "0x150000000"
    assert not home.validate_record(changed, source)


def test_retract_clears_home_and_derived_nodes(configured):
    reader = _reader_with_home_guard()
    _set_ad(reader, old_fixture.TABLE_ONE, 1)
    source = _old_record(reader)
    record = home.read_fields(reader, MODULE_BASE, source)
    retracted = home.retract_record(record, "cleanup_failed")

    assert retracted["status"] == "unknown"
    assert retracted["home_node"] is None
    assert retracted["derived_nodes"] is None
    assert retracted["nodes"] is None
    assert not home.validate_record(retracted, source)


def test_parent_request_requires_trade_income_and_default_is_unchanged(monkeypatch):
    report = crm._base_report(Path("C:/EU4"), "FRA")
    assert "include_home_trade_node" not in report["request"]
    assert "home_trade_node" not in report

    monkeypatch.setattr(crm, "_configure_kernel", lambda: (_ for _ in ()).throw(AssertionError("no RPM")))
    invalid = crm.capture(Path("fake-installation.json"), "FRA", include_home_trade_node=True)
    assert invalid["status"] == "invalid_request"
    assert any(
        item["error"] == "include_home_trade_node_requires_include_trade_income"
        for item in invalid["errors"]
    )


def test_parent_snapshot_and_cleanup_retract_home_top_before_after(configured, monkeypatch):
    reader = _reader_with_home_guard()
    _set_ad(reader, old_fixture.TABLE_ONE, 1)
    source = _old_record(reader)
    home_record = home.read_fields(reader, MODULE_BASE, source)
    assert home.validate_record(home_record, source)

    report = crm._base_report(
        Path("C:/EU4"),
        "FRA",
        include_trade_income=True,
        include_home_trade_node=True,
    )
    report["home_trade_node"] = home_record
    report["before"] = {
        "status": "observed",
        "values": {"administrative": 1},
        "trade_income": source,
        "home_trade_node": home_record,
    }
    report["after"] = deepcopy(report["before"])
    comparison = crm._compare_snapshot(report["before"])
    assert comparison["home_trade_node"] == home_record

    crm._retract(report)
    assert report["home_trade_node"]["home_node"] is None
    assert report["before"]["home_trade_node"]["derived_nodes"] is None
    assert report["after"]["home_trade_node"]["nodes"] is None

    class Kernel:
        def OpenProcess(self, *_args):
            return HANDLE

    monkeypatch.setattr(crm, "_static_contract_guard", lambda: {"status": "observed", "checks": {}, "unknown_conditions": []})
    monkeypatch.setattr(crm, "_active_profile", lambda: {})
    monkeypatch.setattr(crm, "_load_installation", lambda _path: {"pid": 1})
    monkeypatch.setattr(crm, "_configure_kernel", lambda: Kernel())

    def identity(report_value, *_args):
        report_value["identity"]["process_path"] = "fake-eu4.exe"
        return MODULE_BASE

    monkeypatch.setattr(crm, "_capture_identity", identity)
    monkeypatch.setattr(crm, "_file_code_guard", lambda _path: {"status": "observed"})

    def fake_pass(_reader, _module, _country, _profile, _start, *_flags):
        snapshot = {
            "status": "observed",
            "runtime_code_guard": {"status": "observed"},
            "game_pointer": None,
            "database_pointer": None,
            "game_date": {"value": 100, "raw_hex": "64000000"},
            "country_scan": None,
            "values": {"administrative": 1},
            "value_raw_hex": {"administrative": "01000000"},
            "read_log": [],
            "trade_income": source,
            "home_trade_node": home_record,
        }
        return deepcopy(snapshot)

    monkeypatch.setattr(crm, "_pass", fake_pass)
    monkeypatch.setattr(crm, "_close_process_handle", lambda _kernel, _handle: {"status": "error", "error": "close_failed"})
    captured = crm.capture(
        Path("fake-installation.json"),
        "FRA",
        include_trade_income=True,
        include_home_trade_node=True,
    )
    assert captured["status"] == "cleanup_error"
    assert captured["doublepass"]["performed"] is True
    assert captured["doublepass"]["consistent"] is True
    assert captured["home_trade_node"]["home_node"] is None
    assert captured["before"]["home_trade_node"]["derived_nodes"] is None
    assert captured["after"]["home_trade_node"]["nodes"] is None

