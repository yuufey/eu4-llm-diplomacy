"""Offline tests for the optional trade-power-sum parent capture extension."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
from types import ModuleType

import pytest

import bridge.information as information_package
from bridge.information import country_resources_memory as crm
from bridge.information import trade_income_memory, trade_power_memory


MODULE_BASE = 0x140000000
GAME_POINTER = 0x200000
DATABASE_POINTER = 0x300000
COUNTRY_POINTER = 0x500000
HANDLE = 0x1234
TRADE_RECORD = {"status": "observed", "country": "FRA", "nodes": []}
POWER_RECORD = {"status": "observed", "country": "FRA", "nodes": []}
SUM_RECORD = {"status": "observed", "raw_sum": 37, "value": 37}
COUNTRY_SCAN = {
    "status": "observed",
    "country": "FRA",
    "country_pointer": {"va": hex(COUNTRY_POINTER)},
}


def _sum_module(monkeypatch: pytest.MonkeyPatch, reader=None):
    calls = {"reads": [], "retracts": []}
    module = ModuleType("bridge.information.trade_power_sum_capture")

    def read_fields(*args):
        calls["reads"].append(args)
        if reader is not None:
            return reader(*args)
        args[0].read_log.append({"label": "trade_power_sum.test_raw", "status": "observed"})
        return deepcopy(SUM_RECORD)

    def retract_record(record, reason):
        calls["retracts"].append((deepcopy(record), reason))
        result = deepcopy(record) if isinstance(record, dict) else {}
        result.update(status="unknown", reason=reason, value=None)
        return result

    module.read_fields = read_fields
    module.retract_record = retract_record
    module.validate_record = lambda *_args: True
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setattr(information_package, "trade_power_sum_capture", module, raising=False)
    return module, calls


def _fake_snapshot(*, trade_power_sum=None):
    result = {
        "status": "observed",
        "runtime_code_guard": {"status": "observed"},
        "game_pointer": {"value": hex(GAME_POINTER)},
        "database_pointer": {"value": hex(DATABASE_POINTER)},
        "game_date": {"value": 123, "raw_hex": "7b000000"},
        "country_scan": deepcopy(COUNTRY_SCAN),
        "values": {"administrative": 1, "diplomatic": 2, "military": 3},
        "value_raw_hex": {"administrative": "01000000", "diplomatic": "02000000", "military": "03000000"},
        "read_log": [],
        "trade_income": deepcopy(TRADE_RECORD),
        "trade_power": deepcopy(POWER_RECORD),
    }
    if trade_power_sum is not None:
        result["trade_power_sum"] = deepcopy(trade_power_sum)
    return result


class _Reader:
    def __init__(self):
        self.read_log = []

    def qword(self, address, label):
        value = GAME_POINTER if label == "globals.game_pointer" else DATABASE_POINTER
        raw = value.to_bytes(8, "little")
        self.read_log.append({"address": address, "label": label, "status": "observed", "raw_hex": raw.hex()})
        return value, raw

    def read(self, address, size, label):
        if label == "game.game_date":
            value = 123
            raw = value.to_bytes(size, "little", signed=True)
        else:
            raw = bytes([1]) * size
        self.read_log.append({"address": address, "label": label, "status": "observed", "raw_hex": raw.hex()})
        return raw


def _install_snapshot_stubs(monkeypatch: pytest.MonkeyPatch, sum_reader=None):
    module, calls = _sum_module(monkeypatch, sum_reader)
    monkeypatch.setattr(
        crm,
        "_profile_layout",
        lambda _profile: {
            "game_rva": 0x1000,
            "database_rva": 0x2000,
            "game_date_offset": 0x40,
            "power_offsets": {"administrative": 0x10, "diplomatic": 0x14, "military": 0x18},
            "component_width": 4,
        },
    )
    monkeypatch.setattr(crm, "_country_identity", lambda *_args: deepcopy(COUNTRY_SCAN))
    monkeypatch.setattr(trade_income_memory, "read_fields", lambda *_args: deepcopy(TRADE_RECORD))
    monkeypatch.setattr(trade_power_memory, "read_fields", lambda *_args: deepcopy(POWER_RECORD))
    return module, calls


def _install_capture_stubs(monkeypatch: pytest.MonkeyPatch, snapshots):
    class Kernel:
        def OpenProcess(self, *_args):
            return HANDLE

    calls = []
    iterator = iter(snapshots)

    def fake_pass(*args, **kwargs):
        calls.append((args, kwargs))
        return deepcopy(next(iterator))

    monkeypatch.setattr(crm, "_static_contract_guard", lambda: {"status": "observed"})
    monkeypatch.setattr(crm, "_active_profile", lambda: {})
    monkeypatch.setattr(crm, "_load_installation", lambda _path: {"pid": 10})
    monkeypatch.setattr(crm, "_configure_kernel", lambda: Kernel())

    def identity(report, *_args):
        report["identity"].update({
            "process_path": "C:/EU4/eu4.exe",
            "process_path_sha256": crm.EXPECTED_EXE_SHA256,
            "installation_creation_filetime": 99,
            "process_creation_filetime": 99,
            "installation_session_id": "session",
            "binding_verified": True,
        })
        return MODULE_BASE

    monkeypatch.setattr(crm, "_capture_identity", identity)
    monkeypatch.setattr(crm, "_file_code_guard", lambda _path: {"status": "observed"})
    monkeypatch.setattr(crm, "_pass", fake_pass)
    monkeypatch.setattr(crm, "_close_process_handle", lambda *_args: {"status": "closed", "closed": True})
    return calls


def test_default_shape_is_unchanged_and_opt_in_requires_both_parent_records(monkeypatch):
    default = crm._base_report(Path("C:/EU4"), "FRA")
    assert "include_trade_power_sum" not in default["request"]
    assert "trade_power_sum" not in default

    _sum_module(monkeypatch)
    monkeypatch.setattr(crm, "_configure_kernel", lambda: (_ for _ in ()).throw(AssertionError("invalid request reached process")))
    monkeypatch.setattr(crm, "_close_process_handle", lambda *_args: {"status": "closed", "closed": True})
    without_income = crm.capture(Path("fake.json"), "FRA", include_trade_power_sum=True)
    assert without_income["status"] == "invalid_request"
    assert "include_trade_power_sum_requires_include_trade_income" in {e["error"] for e in without_income["errors"]}

    without_power = crm.capture(
        Path("fake.json"), "FRA", include_trade_income=True, include_trade_power_sum=True
    )
    assert without_power["status"] == "invalid_request"
    assert "include_trade_power_sum_requires_include_trade_power" in {e["error"] for e in without_power["errors"]}

    non_bool = crm.capture(Path("fake.json"), "FRA", include_trade_power_sum=1)
    assert non_bool["status"] == "invalid_request"
    assert "include_trade_power_sum_must_be_bool" in {e["error"] for e in non_bool["errors"]}


def test_snapshot_passes_existing_trade_records_and_country_scan_to_one_child(monkeypatch):
    seen = []

    def reader(*args):
        seen.append(args)
        args[0].read_log.append({"label": "trade_power_sum.child_raw", "status": "observed"})
        return deepcopy(SUM_RECORD)

    _module, _calls = _install_snapshot_stubs(monkeypatch, reader)
    rpm = _Reader()
    snapshot = crm._snapshot(
        rpm,
        MODULE_BASE,
        "FRA",
        {},
        include_trade_income=True,
        include_trade_power=True,
        include_trade_power_sum=True,
    )
    assert snapshot["status"] == "observed"
    assert snapshot["trade_income"] == TRADE_RECORD
    assert snapshot["trade_power"] == POWER_RECORD
    assert snapshot["trade_power_sum"] == SUM_RECORD
    assert len(seen) == 1
    assert seen[0][0] is rpm
    assert seen[0][1] == MODULE_BASE
    assert seen[0][2] == TRADE_RECORD
    assert seen[0][3] == COUNTRY_SCAN
    assert any(row["label"] == "trade_power_sum.child_raw" for row in rpm.read_log)


def test_snapshot_child_failure_is_local_and_retracts_only_sum(monkeypatch):
    def fail(*_args):
        raise ValueError("bounded child read failed")

    _module, calls = _install_snapshot_stubs(monkeypatch, fail)
    snapshot = crm._snapshot(
        _Reader(), MODULE_BASE, "FRA", {},
        include_trade_income=True, include_trade_power=True, include_trade_power_sum=True,
    )
    assert snapshot["status"] == "observed"
    assert snapshot["trade_income"] == TRADE_RECORD
    assert snapshot["trade_power"] == POWER_RECORD
    assert snapshot["trade_power_sum"]["status"] == "unknown"
    assert "trade_power_sum_reader_failed:ValueError" in snapshot["trade_power_sum"]["reason"]
    assert len(calls["retracts"]) == 1


def test_pass_preserves_legacy_snapshot_seam_and_includes_sum_reads_when_enabled(monkeypatch):
    monkeypatch.setattr(crm, "_runtime_code_guard", lambda *_args: {"status": "observed"})
    calls = []

    def fake_snapshot(*args, **kwargs):
        calls.append((args, kwargs))
        reader.read_log.append({"label": "trade_power_sum.pass_raw", "status": "observed"})
        sum_record = SUM_RECORD if kwargs.get("include_trade_power_sum") is True else None
        return _fake_snapshot(trade_power_sum=sum_record)

    monkeypatch.setattr(crm, "_snapshot", fake_snapshot)
    reader = _Reader()
    reader.read_log.append({"label": "before_start", "status": "observed"})
    legacy = crm._pass(reader, MODULE_BASE, "FRA", {}, 1, False, True, False, True)
    assert calls[-1][0][4:] == (False, True, False, True)
    assert calls[-1][1] == {}
    assert "trade_power_sum" not in crm._compare_snapshot(legacy)

    reader.read_log = [{"label": "before_start", "status": "observed"}]
    enabled = crm._pass(
        reader, MODULE_BASE, "FRA", {}, 1,
        False, True, False, True, include_trade_power_sum=True,
    )
    assert calls[-1][1]["include_trade_power_sum"] is True
    assert enabled["trade_power_sum"] == SUM_RECORD
    assert enabled["read_log"] == [{"label": "trade_power_sum.pass_raw", "status": "observed"}]
    assert crm._compare_snapshot(enabled)["trade_power_sum"] == SUM_RECORD


def test_pass_runtime_guard_failure_retracts_requested_sum_child(monkeypatch):
    _module, calls = _sum_module(monkeypatch)
    monkeypatch.setattr(crm, "_runtime_code_guard", lambda *_args: {"status": "unknown"})
    result = crm._pass(
        _Reader(), MODULE_BASE, "FRA", {}, 0,
        False, True, False, True, include_trade_power_sum=True,
    )
    assert result["status"] == "unknown"
    assert result["trade_power_sum"]["status"] == "unknown"
    assert calls["retracts"][-1][1] == "runtime_code_guard_failed"


def test_capture_opt_in_top_copy_and_default_pass_call_shape(monkeypatch):
    snapshot = _fake_snapshot(trade_power_sum=SUM_RECORD)
    calls = _install_capture_stubs(monkeypatch, [snapshot, snapshot])
    report = crm.capture(
        Path("fake-installation.json"), "FRA",
        include_trade_income=True,
        include_trade_power=True,
        include_trade_power_sum=True,
    )
    assert report["status"] == "observed"
    assert report["completed"] is True
    assert report["request"]["include_trade_power_sum"] is True
    assert report["trade_power_sum"] == report["after"]["trade_power_sum"] == SUM_RECORD
    assert report["before"]["trade_power_sum"] == SUM_RECORD
    assert report["doublepass"]["consistent"] is True
    assert all(kwargs["include_trade_power_sum"] is True for _args, kwargs in calls)

    default_calls = _install_capture_stubs(monkeypatch, [_fake_snapshot(), _fake_snapshot()])
    default = crm.capture(Path("fake-installation.json"), "FRA")
    assert default["status"] == "observed"
    assert "trade_power_sum" not in default
    assert all("include_trade_power_sum" not in kwargs for _args, kwargs in default_calls)


def test_snapshot_drift_retracts_top_and_both_child_passes(monkeypatch):
    _module, retracts = _sum_module(monkeypatch)
    first = _fake_snapshot(trade_power_sum={"status": "observed", "raw_sum": 37})
    second = _fake_snapshot(trade_power_sum={"status": "observed", "raw_sum": 38})
    calls = _install_capture_stubs(monkeypatch, [first, second])
    report = crm.capture(
        Path("fake-installation.json"), "FRA",
        include_trade_income=True,
        include_trade_power=True,
        include_trade_power_sum=True,
    )
    assert report["status"] == "doublepass_mismatch"
    assert report["doublepass"]["consistent"] is False
    assert any(path.endswith("trade_power_sum.raw_sum") for path in report["doublepass"]["mismatches"])
    assert report["trade_power_sum"]["status"] == "unknown"
    assert report["before"]["trade_power_sum"]["status"] == "unknown"
    assert report["after"]["trade_power_sum"]["status"] == "unknown"
    assert len(retracts["retracts"]) == 3
    assert all(kwargs["include_trade_power_sum"] is True for _args, kwargs in calls)
