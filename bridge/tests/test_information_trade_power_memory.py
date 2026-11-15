from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import pytest

from bridge.information import country_resources_memory as crm
from bridge.information import home_trade_node_memory as home
from bridge.information import trade_income_memory as trade
from bridge.information import trade_power_memory as power
from bridge.tests import test_information_trade_income_memory as old_fixture


MODULE_BASE = old_fixture.MODULE_BASE
COUNTRY_POINTER = old_fixture.COUNTRY_POINTER
HANDLE = 0x7788


def _power_profile() -> dict:
    return {
        "profile_id": "trade-power-memory-1374",
        "game_version": power.EXPECTED_VERSION,
        "executable": {"sha256": power.EXPECTED_EXE_SHA256},
        "source_index": {
            "source_index_id": "trade-power-source-index-002",
            "path": "work/runtime/information-trade-state-20261027-001/trade-power-source-index-002.json",
            "sha256": "c" * 64,
        },
        "layout": {
            "runtime_total_power_offset": "0xc8",
            "entry_power_offsets": {
                "0x44": "0x44",
                "0x48": "0x48",
                "0x4c": "0x4c",
                "0x50": "0x50",
                "0x54": "0x54",
            },
            "source_trade_profile_sha256": "b" * 64,
        },
        "semantics": {
            "basis": "native_trade_node_power_caches",
            "unit": "trade_power",
            "scale": 1000,
            "period": "current",
            "country_value_origin": "derived_from_copied_native_caches",
            "total_value_origin": "copied_native_cache",
        },
        "code_guards": [{"name": "power_leaf", "rva": "0x500", "hex": "aabb"}],
    }


@pytest.fixture
def configured(monkeypatch: pytest.MonkeyPatch):
    trade_profile = old_fixture._profile()
    monkeypatch.setattr(trade, "EXPECTED_PROFILE_SHA256", "b" * 64)
    monkeypatch.setattr(trade, "_active_profile", lambda: trade_profile)
    monkeypatch.setattr(power, "EXPECTED_PROFILE_SHA256", "p" * 64)
    monkeypatch.setattr(power, "EXPECTED_TRADE_PROFILE_SHA256", "b" * 64)
    profile = _power_profile()
    monkeypatch.setattr(power, "_active_profile", lambda: profile)
    return profile


def _reader_with_power_cache(values: tuple[int, int] = (1234, -55)):
    reader = old_fixture._build_reader()
    reader.data[(MODULE_BASE + 0x500, 2)] = bytes.fromhex("aabb")
    reader.data[(old_fixture.RUNTIME_ONE + 0xC8, 4)] = old_fixture._i32(values[0])
    reader.data[(old_fixture.RUNTIME_TWO + 0xC8, 4)] = old_fixture._i32(values[1])
    return reader


def _reader_with_real_power_guards(values: tuple[int, int] = (1234, -55)):
    reader = old_fixture._build_reader()
    for item in power.PROFILE["code_guards"]:
        reader.data[(MODULE_BASE + int(item["rva"], 0), len(bytes.fromhex(item["hex"])))] = bytes.fromhex(item["hex"])
    reader.data[(old_fixture.RUNTIME_ONE + 0xC8, 4)] = old_fixture._i32(values[0])
    reader.data[(old_fixture.RUNTIME_TWO + 0xC8, 4)] = old_fixture._i32(values[1])
    return reader


def _reader_with_real_home_power_guards(values: tuple[int, int] = (1234, -55)):
    reader = _reader_with_real_power_guards(values)
    for item in home.PROFILE["code_guards"]:
        reader.data[(MODULE_BASE + int(item["rva"], 0), len(bytes.fromhex(item["hex"])))] = bytes.fromhex(item["hex"])
    return reader


def _set_components(reader, table: int, values: dict[int, int]) -> None:
    address = table + 7 * 0xC0
    raw = bytearray(reader.data[(address, 0xC0)])
    for offset, value in values.items():
        raw[offset:offset + 4] = old_fixture._i32(value)
    reader.data[(address, 0xC0)] = bytes(raw)


def _set_ad(reader, table: int, value: int) -> None:
    address = table + 7 * 0xC0
    raw = bytearray(reader.data[(address, 0xC0)])
    raw[0xAD] = value
    reader.data[(address, 0xC0)] = bytes(raw)


def _source(reader):
    record = trade.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)
    assert record["status"] == "observed"
    assert trade.validate_record(record)
    return record


def test_reads_runtime_c8_and_derives_country_power_from_entry_components(configured):
    reader = _reader_with_power_cache()
    _set_components(reader, old_fixture.TABLE_ONE, {0x44: 1000, 0x48: 1500, 0x4C: 2000, 0x50: 100, 0x54: 200})
    _set_components(reader, old_fixture.TABLE_TWO, {0x44: -1000, 0x48: 5, 0x4C: 2000, 0x50: 20, 0x54: 12})
    source = _source(reader)

    record = power.read_fields(reader, MODULE_BASE, source)

    assert record["status"] == "observed"
    assert [node["node_id"] for node in record["nodes"]] == ["alpha", "beta"]
    assert record["nodes"][0]["total_power_raw"] == 1234
    assert record["nodes"][0]["total_power_raw_hex"] == "d2040000"
    assert record["nodes"][0]["country_power_raw"] == 1600
    assert record["nodes"][0]["country_power_raw_hex"] == "40060000"
    assert record["nodes"][0]["entry_power_components_raw"] == {
        "0x44": 1000, "0x48": 1500, "0x4c": 2000, "0x50": 100, "0x54": 200,
    }
    assert record["nodes"][0]["entry_power_components_raw_hex"] == "e8030000dc050000d007000064000000c8000000"
    assert record["nodes"][1]["country_power_raw"] == -8
    assert record["nodes"][1]["total_power_raw"] == -55
    assert power.validate_record(record, source)
    assert [label for _address, _size, label in reader.reads if label.startswith("trade_power.node[")] == [
        "trade_power.node[0].runtime_total_power",
        "trade_power.node[1].runtime_total_power",
    ]


def test_pinned_profile_loads_and_real_child_validator_accepts_record(monkeypatch):
    assert power.PROFILE is not None
    assert power.EXPECTED_PROFILE_SHA256 != "pending-profile"
    trade_profile = old_fixture._profile()
    monkeypatch.setattr(trade, "_active_profile", lambda: trade_profile)
    reader = _reader_with_real_power_guards()
    source = _source(reader)
    record = power.read_fields(reader, MODULE_BASE, source)
    assert record["status"] == "observed"
    assert power.validate_record(record, source)


def test_formula_preserves_width_order_negative_cap_and_delta_wrap(configured):
    reader = _reader_with_power_cache()
    _set_components(reader, old_fixture.TABLE_ONE, {
        0x44: 2_147_483_647,
        0x48: 5,
        0x4C: 1001,
        0x50: 0,
        0x54: 0,
    })
    _set_components(reader, old_fixture.TABLE_TWO, {
        0x44: 1000,
        0x48: -5,
        0x4C: 1000,
        0x50: -1,
        0x54: 2_147_483_647,
    })
    source = _source(reader)
    record = power.read_fields(reader, MODULE_BASE, source)
    assert record["status"] == "observed"
    components = record["nodes"][0]["entry_power_components_raw"]
    assert components["0x44"] == 2_147_483_647
    assert components["0x48"] == 5
    # q64 is positive, but its low signed32 value is negative.  Native TEST
    # EDX/CMOVG therefore takes max-zero after narrowing; testing q64 first
    # would incorrectly retain a negative wrapped value.
    assert record["nodes"][0]["country_power_raw"] == 0
    # signed cap -5 plus (INT32_MAX - (-1)) wraps to 2147483643.
    assert record["nodes"][1]["country_power_raw"] == 2_147_483_643
    assert power.validate_record(record, source)


def test_negative_q64_is_narrowed_before_max_zero(configured):
    reader = _reader_with_power_cache()
    _set_components(reader, old_fixture.TABLE_ONE, {
        0x44: -2_147_483_648,
        0x48: 2_147_483_647,
        0x4C: 1001,
        0x50: 0,
        0x54: 0,
    })
    source = _source(reader)
    record = power.read_fields(reader, MODULE_BASE, source)
    assert record["status"] == "observed"
    # q64=-2149631131, q32=2145336165, so TEST/CMOVG keeps q32 positive.
    assert record["nodes"][0]["country_power_raw"] == 2_145_336_165
    assert power.validate_record(record, source)


def test_profile_failure_and_invalid_parent_are_fail_closed_without_child_rpm(monkeypatch, configured):
    reader = _reader_with_power_cache()
    source = _source(reader)

    class BombReader:
        def __init__(self):
            self.calls = 0

        def read(self, *_args):
            self.calls += 1
            raise AssertionError("trade power child must not RPM")

    bomb = BombReader()
    monkeypatch.setattr(power, "_active_profile", lambda: (_ for _ in ()).throw(power.ProfileError("pending")))
    record = power.read_fields(bomb, MODULE_BASE, source)
    assert record["status"] == "unknown"
    assert record["reason"].startswith("profile_unavailable:")
    assert bomb.calls == 0

    invalid = power.read_fields(bomb, MODULE_BASE, {"status": "unknown"})
    assert invalid["reason"] == "trade_income_record_invalid"
    assert bomb.calls == 0


def test_validation_rejects_source_raw_formula_cache_and_guard_tampering(configured):
    reader = _reader_with_power_cache()
    _set_components(reader, old_fixture.TABLE_ONE, {0x44: 1000, 0x4C: 2000})
    source = _source(reader)
    record = power.read_fields(reader, MODULE_BASE, source)
    assert power.validate_record(record, source)

    changed = deepcopy(record)
    changed["source_trade_record_canonical_sha256"] = "0" * 64
    assert not power.validate_record(changed, source)

    changed = deepcopy(record)
    changed["nodes"][0]["entry_power_components_raw"]["0x44"] += 1
    assert not power.validate_record(changed, source)

    changed = deepcopy(record)
    changed["nodes"][0]["entry_power_components_raw_hex"] = "00" * 20
    assert not power.validate_record(changed, source)

    changed = deepcopy(record)
    changed["nodes"][0]["total_power_raw"] += 1
    assert not power.validate_record(changed, source)

    changed = deepcopy(record)
    changed["nodes"][0]["country_power_raw"] += 1
    assert not power.validate_record(changed, source)

    changed = deepcopy(record)
    changed["runtime_code_guard"]["checks"]["power_leaf"] = False
    assert not power.validate_record(changed, source)

    changed = deepcopy(record)
    changed["country_fullref_raw_hex"] = "504f5200" + changed["country_fullref_raw_hex"][8:]
    assert not power.validate_record(changed, source)


def test_retract_and_parent_flags_preserve_default_and_cover_cleanup(configured, monkeypatch):
    reader = _reader_with_power_cache()
    source = _source(reader)
    record = power.read_fields(reader, MODULE_BASE, source)
    assert power.validate_record(record, source)
    retracted = power.retract_record(record, "cleanup_failed")
    assert retracted["status"] == "unknown"
    assert retracted["nodes"] is None
    assert not power.validate_record(retracted, source)

    default = crm._base_report(Path("C:/EU4"), "FRA")
    assert "include_trade_power" not in default["request"]
    assert "trade_power" not in default

    report = crm._base_report(
        Path("C:/EU4"), "FRA", include_trade_income=True, include_trade_power=True
    )
    report["trade_power"] = record
    report["before"] = {"status": "observed", "values": {"administrative": 1}, "trade_income": source, "trade_power": record}
    report["after"] = deepcopy(report["before"])
    assert crm._compare_snapshot(report["before"])["trade_power"] == record
    crm._retract(report)
    assert report["trade_power"]["nodes"] is None
    assert report["before"]["trade_power"]["nodes"] is None
    assert report["after"]["trade_power"]["nodes"] is None

    monkeypatch.setattr(crm, "_configure_kernel", lambda: (_ for _ in ()).throw(AssertionError("no RPM")))
    invalid = crm.capture(Path("fake-installation.json"), "FRA", include_trade_power=True)
    assert invalid["status"] == "invalid_request"
    assert any(item["error"] == "include_trade_power_requires_include_trade_income" for item in invalid["errors"])


def test_real_home_power_snapshot_seam_and_cleanup(monkeypatch):
    """The combined parent path keeps both children through two-pass cleanup."""
    assert home.PROFILE is not None
    assert power.PROFILE is not None
    monkeypatch.setattr(trade, "_active_profile", lambda: old_fixture._profile())

    reader = _reader_with_real_home_power_guards()
    _set_ad(reader, old_fixture.TABLE_ONE, 1)
    source = _source(reader)
    home_record = home.read_fields(reader, MODULE_BASE, source)
    power_record = power.read_fields(reader, MODULE_BASE, source)
    assert home.validate_record(home_record, source)
    assert power.validate_record(power_record, source)

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
        "trade_power": power_record,
    }

    report = crm._base_report(
        Path("C:/EU4"),
        "FRA",
        include_trade_income=True,
        include_home_trade_node=True,
        include_trade_power=True,
    )
    report["trade_income"] = source
    report["home_trade_node"] = home_record
    report["trade_power"] = power_record
    report["before"] = deepcopy(snapshot)
    report["after"] = deepcopy(snapshot)
    comparison = crm._compare_snapshot(report["before"])
    assert comparison["home_trade_node"] == home_record
    assert comparison["trade_power"] == power_record
    crm._retract(report)
    for item in (report, report["before"], report["after"]):
        assert item["home_trade_node"]["home_node"] is None
        assert item["home_trade_node"]["derived_nodes"] is None
        assert item["trade_power"]["nodes"] is None

    calls: list[tuple[object, ...]] = []

    def fake_snapshot(*args):
        calls.append(args[4:])
        return deepcopy(snapshot)

    monkeypatch.setattr(crm, "_runtime_code_guard", lambda *_args: {"status": "observed"})
    monkeypatch.setattr(crm, "_snapshot", fake_snapshot)
    reader.read_log = []
    passed = crm._pass(reader, MODULE_BASE, "FRA", {}, 0, False, True, True, True)
    assert calls == [(False, True, True, True)]
    assert passed["home_trade_node"] == home_record
    assert passed["trade_power"] == power_record

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

    def fake_pass(*_args):
        return deepcopy(snapshot)

    monkeypatch.setattr(crm, "_pass", fake_pass)
    monkeypatch.setattr(crm, "_close_process_handle", lambda _kernel, _handle: {"status": "error", "error": "close_failed"})
    captured = crm.capture(
        Path("fake-installation.json"),
        "FRA",
        include_trade_income=True,
        include_home_trade_node=True,
        include_trade_power=True,
    )
    assert captured["status"] == "cleanup_error"
    assert captured["doublepass"]["performed"] is True
    assert captured["doublepass"]["consistent"] is True
    for item in (captured, captured["before"], captured["after"]):
        assert item["home_trade_node"]["home_node"] is None
        assert item["home_trade_node"]["derived_nodes"] is None
        assert item["trade_power"]["nodes"] is None
