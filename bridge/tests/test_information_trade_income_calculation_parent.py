"""Offline parent wiring tests for the optional trade-income calculator child."""
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
NODE_ID = "champagne"
TRADE_RECORD = {"status": "observed", "country": "FRA", "nodes": [{"node_id": NODE_ID}]}
POWER_RECORD = {"status": "observed", "country": "FRA", "nodes": [{"node_id": NODE_ID}]}
SUM_RECORD = {"status": "observed", "raw_sum": 37, "value": 37}
CALC_RECORD = {"status": "known", "node_id": NODE_ID, "raw": 15}
COUNTRY_SCAN = {
    "status": "observed",
    "country": "FRA",
    "country_pointer": {"va": hex(COUNTRY_POINTER)},
}


def _calculation_module(monkeypatch: pytest.MonkeyPatch, reader=None):
    calls = {"reads": [], "retracts": []}
    module = ModuleType("bridge.information.trade_income_calculation_capture")

    def read_fields(rpm, base, trade_income, country_scan, trade_power_sum, *, node_id):
        calls["reads"].append((rpm, base, trade_income, country_scan, trade_power_sum, node_id))
        if reader is not None:
            return reader(rpm, base, trade_income, country_scan, trade_power_sum, node_id=node_id)
        rpm.read_log.append({"label": "trade_income_calculation.test_raw", "status": "observed"})
        return {**deepcopy(CALC_RECORD), "node_id": node_id}

    def retract_record(record, reason):
        calls["retracts"].append((deepcopy(record), reason))
        result = deepcopy(record) if isinstance(record, dict) else {}
        result.update(status="unknown", reason=reason, value=None)
        return result

    module.read_fields = read_fields
    module.retract_record = retract_record
    module.validate_record = lambda *_args: True
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setattr(information_package, "trade_income_calculation_capture", module, raising=False)
    return module, calls


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
            raw = (123).to_bytes(size, "little", signed=True)
        else:
            raw = bytes([1]) * size
        self.read_log.append({"address": address, "label": label, "status": "observed", "raw_hex": raw.hex()})
        return raw


def _install_snapshot_stubs(monkeypatch: pytest.MonkeyPatch):
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


def _snapshot_for_capture(calculation=None):
    return {
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
        "trade_power_sum": deepcopy(SUM_RECORD),
        "trade_income_calculation": deepcopy(calculation or CALC_RECORD),
    }


def _install_capture_stubs(monkeypatch: pytest.MonkeyPatch, snapshots):
    class Kernel:
        def __init__(self):
            self.open_calls = []

        def OpenProcess(self, *args):
            self.open_calls.append(args)
            return HANDLE

    kernel = Kernel()
    pass_calls = []
    iterator = iter(snapshots)

    monkeypatch.setattr(crm, "_static_contract_guard", lambda: {"status": "observed"})
    monkeypatch.setattr(crm, "_active_profile", lambda: {})
    monkeypatch.setattr(crm, "_load_installation", lambda _path: {"pid": 10})
    monkeypatch.setattr(crm, "_configure_kernel", lambda: kernel)

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

    def fake_pass(*args, **kwargs):
        pass_calls.append((args, kwargs))
        return deepcopy(next(iterator))

    monkeypatch.setattr(crm, "_pass", fake_pass)
    close_calls = []

    def close(_kernel, handle):
        close_calls.append(handle)
        return {"status": "closed", "closed": True}

    monkeypatch.setattr(crm, "_close_process_handle", close)
    return kernel, pass_calls, close_calls


def test_default_shape_and_pass_seam_remain_unchanged(monkeypatch):
    report = crm._base_report(Path("C:/EU4"), "FRA")
    assert "trade_income_node_id" not in report["request"]
    assert "trade_income_calculation" not in report

    _install_snapshot_stubs(monkeypatch)
    monkeypatch.setitem(sys.modules, "bridge.information.trade_income_calculation_capture", None)
    default_snapshot = crm._snapshot(_Reader(), MODULE_BASE, "FRA", {})
    assert default_snapshot["status"] == "observed"
    assert "trade_income_calculation" not in default_snapshot

    calls = []
    monkeypatch.setattr(crm, "_runtime_code_guard", lambda *_args: {"status": "observed"})

    def fake_snapshot(*args, **kwargs):
        calls.append((args, kwargs))
        return _snapshot_for_capture()

    monkeypatch.setattr(crm, "_snapshot", fake_snapshot)
    result = crm._pass(_Reader(), MODULE_BASE, "FRA", {}, 0)
    assert result["status"] == "observed"
    assert len(calls[0][0]) == 4
    assert calls[0][1] == {}
    assert "trade_income_calculation" not in crm._compare_snapshot({"status": "observed"})


def test_snapshot_runs_calculation_after_sum_on_the_same_reader(monkeypatch):
    _install_snapshot_stubs(monkeypatch)
    _sum_module(monkeypatch)
    module, calls = _calculation_module(monkeypatch)
    rpm = _Reader()
    snapshot = crm._snapshot(
        rpm,
        MODULE_BASE,
        "FRA",
        {},
        include_trade_income=True,
        include_trade_power=True,
        include_trade_power_sum=True,
        trade_income_node_id=NODE_ID,
    )
    assert snapshot["status"] == "observed"
    assert snapshot["trade_income"] == TRADE_RECORD
    assert snapshot["trade_power"] == POWER_RECORD
    assert snapshot["trade_power_sum"] == SUM_RECORD
    assert snapshot["trade_income_calculation"] == CALC_RECORD
    assert len(calls["reads"]) == 1
    seen_reader, base, trade, scan, power_sum, node_id = calls["reads"][0]
    assert seen_reader is rpm
    assert (base, trade, scan, power_sum, node_id) == (
        MODULE_BASE, TRADE_RECORD, COUNTRY_SCAN, SUM_RECORD, NODE_ID
    )
    labels = [row["label"] for row in rpm.read_log]
    assert labels.index("trade_power_sum.test_raw") < labels.index("trade_income_calculation.test_raw")


def test_snapshot_child_exception_is_local_and_parent_records_survive(monkeypatch):
    _install_snapshot_stubs(monkeypatch)
    _sum_module(monkeypatch)

    def fail(*_args, **_kwargs):
        raise ValueError("calculation child failed")

    _module, calls = _calculation_module(monkeypatch, fail)
    snapshot = crm._snapshot(
        _Reader(), MODULE_BASE, "FRA", {},
        include_trade_income=True,
        include_trade_power=True,
        include_trade_power_sum=True,
        trade_income_node_id=NODE_ID,
    )
    assert snapshot["status"] == "observed"
    assert snapshot["trade_income"] == TRADE_RECORD
    assert snapshot["trade_power"] == POWER_RECORD
    assert snapshot["trade_power_sum"] == SUM_RECORD
    assert snapshot["trade_income_calculation"]["status"] == "unknown"
    assert "trade_income_calculation_reader_failed:ValueError" in snapshot["trade_income_calculation"]["reason"]
    assert calls["retracts"][-1][1].startswith("trade_income_calculation_reader_failed:ValueError")


@pytest.mark.parametrize("selector", ["a" * 129, "invalid/key", True, "Null"])
def test_invalid_selector_is_rejected_before_process_open(monkeypatch, selector):
    _module, _calls = _calculation_module(monkeypatch)
    opens = []
    monkeypatch.setattr(crm, "_configure_kernel", lambda: opens.append("called"))
    monkeypatch.setattr(crm, "_close_process_handle", lambda *_args: {"status": "closed", "closed": True})
    report = crm.capture(Path("fake-installation.json"), "FRA", trade_income_node_id=selector)
    assert report["status"] == "invalid_request"
    assert "trade_income_node_id_invalid" in {row["error"] for row in report["errors"]}
    assert opens == []


@pytest.mark.parametrize(
    "options,expected_error",
    [
        (
            {"include_trade_income": True, "include_trade_power": True},
            "trade_income_node_id_requires_include_trade_power_sum",
        ),
        (
            {"include_trade_income": True, "include_trade_power_sum": True},
            "include_trade_power_sum_requires_include_trade_power",
        ),
        (
            {"include_trade_power": True, "include_trade_power_sum": True},
            "include_trade_power_requires_include_trade_income",
        ),
    ],
)
def test_selector_requires_income_power_and_sum_before_process_open(monkeypatch, options, expected_error):
    _module, _calls = _calculation_module(monkeypatch)
    opens = []
    monkeypatch.setattr(crm, "_configure_kernel", lambda: opens.append("called"))
    monkeypatch.setattr(crm, "_close_process_handle", lambda *_args: {"status": "closed", "closed": True})
    report = crm.capture(
        Path("fake-installation.json"), "FRA",
        **options,
        trade_income_node_id=NODE_ID,
    )
    assert report["status"] == "invalid_request"
    assert expected_error in {row["error"] for row in report["errors"]}
    assert opens == []


@pytest.mark.parametrize("failure", ["runtime_guard", "snapshot"])
def test_pass_failures_retract_requested_child(failure, monkeypatch):
    _sum_module(monkeypatch)
    _module, calls = _calculation_module(monkeypatch)
    if failure == "runtime_guard":
        monkeypatch.setattr(crm, "_runtime_code_guard", lambda *_args: {"status": "unknown"})
    else:
        monkeypatch.setattr(crm, "_runtime_code_guard", lambda *_args: {"status": "observed"})
        monkeypatch.setattr(crm, "_snapshot", lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("snapshot failed")))
    result = crm._pass(
        _Reader(), MODULE_BASE, "FRA", {}, 0,
        include_trade_income=True,
        include_trade_power=True,
        include_trade_power_sum=True,
        trade_income_node_id=NODE_ID,
    )
    assert result["status"] == "unknown"
    assert result["trade_income_calculation"]["status"] == "unknown"
    assert calls["retracts"][-1][1] == (
        "runtime_code_guard_failed" if failure == "runtime_guard"
        else "snapshot_failed:ValueError:snapshot failed"
    )


def test_capture_copies_child_and_uses_one_handle_for_both_passes(monkeypatch):
    _module, _calls = _calculation_module(monkeypatch)
    parent_pass = crm._pass
    kernel, _pass_calls, close_calls = _install_capture_stubs(monkeypatch, [])
    monkeypatch.setattr(crm, "_runtime_code_guard", lambda *_args: {"status": "observed"})
    snapshot_calls = []

    def snapshot(*args, **kwargs):
        snapshot_calls.append((args, kwargs))
        return _snapshot_for_capture()

    monkeypatch.setattr(crm, "_snapshot", snapshot)
    monkeypatch.setattr(crm, "_pass", parent_pass)
    report = crm.capture(
        Path("fake-installation.json"), "FRA",
        include_trade_income=True,
        include_trade_power=True,
        include_trade_power_sum=True,
        trade_income_node_id=NODE_ID,
    )
    assert report["status"] == "observed" and report["completed"] is True
    assert report["request"]["trade_income_node_id"] == NODE_ID
    assert report["trade_income_calculation"] == CALC_RECORD
    assert len(kernel.open_calls) == 1 and close_calls == [HANDLE]
    assert len(snapshot_calls) == 2
    assert snapshot_calls[0][0][0] is snapshot_calls[1][0][0]
    for _args, kwargs in snapshot_calls:
        assert kwargs["trade_income_node_id"] == NODE_ID
        assert kwargs["include_trade_power_sum"] is True


def test_child_drift_makes_capture_fail_and_retracts_top_and_both_passes(monkeypatch):
    module, calls = _calculation_module(monkeypatch)
    first = _snapshot_for_capture({**CALC_RECORD, "raw": 15})
    second = _snapshot_for_capture({**CALC_RECORD, "raw": 16})
    kernel, pass_calls, close_calls = _install_capture_stubs(monkeypatch, [first, second])
    # Parent-level siblings are intentionally present so global retraction covers the nested child only.
    monkeypatch.setattr(trade_income_memory, "retract_record", lambda record, reason: {"status": "unknown", "reason": reason})
    monkeypatch.setattr(trade_power_memory, "retract_record", lambda record, reason: {"status": "unknown", "reason": reason})
    _sum, _sum_calls = _sum_module(monkeypatch)
    report = crm.capture(
        Path("fake-installation.json"), "FRA",
        include_trade_income=True,
        include_trade_power=True,
        include_trade_power_sum=True,
        trade_income_node_id=NODE_ID,
    )
    assert report["status"] == "doublepass_mismatch"
    assert report["doublepass"]["consistent"] is False
    assert report["trade_income_calculation"]["status"] == "unknown"
    assert report["before"]["trade_income_calculation"]["status"] == "unknown"
    assert report["after"]["trade_income_calculation"]["status"] == "unknown"
    assert len(kernel.open_calls) == 1 and close_calls == [HANDLE]
    assert len(pass_calls) == 2
    assert len(calls["retracts"]) >= 3
    assert all(reason == "observation_retracted" for _record, reason in calls["retracts"][-3:])
