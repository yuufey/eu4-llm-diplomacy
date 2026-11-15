"""Offline qualification of the internal province trade-power reader."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from bridge.information import province_trade_power as reader_module
from bridge.information.province_trade_power_memory import FIELD_PROVINCE_TRADE_POWER as FIELD
from bridge.tests import test_information_province_state as g02_fixtures


PROVINCE_ID = 183
BASIS = "native_province_trade_power_trigger_cache"


def _gate():
    return {
        "status": "known",
        "admitted": True,
        "observer_nonplayer_role": {"observer": "FRA", "verified": True},
    }


def _discovery():
    return {"status": "known", "value": True}


def _leaf_field(*, raw=1250, status="known", value=None, reason="LEAF_VALUE_UNAVAILABLE",
                complete=False, basis=BASIS, period="current"):
    result = {
        "status": status,
        "complete": complete,
        "basis": basis,
        "period": period,
        "raw_inputs": {"record_address": "0x123456789abcdef0", "raw_hex": "e2040000"},
        "gaps": ["PRIVATE_CAPTURE_GAP"],
    }
    if status == "known":
        result["value"] = deepcopy(value if value is not None else {
            "raw": raw, "scale": 1000, "unit": "trade_power",
        })
    else:
        result["reason"] = reason
    return result


def _capture_report(context, *, province_id=PROVINCE_ID, leaf=None, before_date=None,
                    after_date=None, access=None, cleanup=None, backend_changes=None,
                    target_changes=None, outer_changes=None):
    field = deepcopy(leaf if leaf is not None else _leaf_field())
    target = {
        "province_id": province_id,
        "admission_by_pass": {"pass1": _gate(), "pass2": _gate()},
        "discovery_by_pass": {"pass1": _discovery(), "pass2": _discovery()},
        "fields": {FIELD: field},
        "field_consistency": {FIELD: {
            "status": "stable" if field.get("status") == "known" else "unknown",
        }},
    }
    target.update(deepcopy(target_changes or {}))
    backend = {
        "status": "observed",
        "consistency": {"status": "stable", "shared_mismatch_paths": []},
        "observer": {"tag": "FRA"},
        "targets": [target],
    }
    backend.update(deepcopy(backend_changes or {}))
    raw_reads = [{
        "status": "observed",
        "address": "0x123456789abcdef0",
        "size": 4,
        "label": "province_trade_power.cache_i32",
        "raw_hex": "e2040000",
    }]
    inner_access = {
        "read_only": True,
        "native_function_invoked": False,
        "writes": False,
        "UI_control": False,
        "date_advance": False,
        "save_or_reload": False,
        "limit_bytes": 524288,
        "calls": len(raw_reads),
        "bytes_requested": sum(row["size"] for row in raw_reads),
    }
    inner_access.update(deepcopy(access or {}))
    inner_cleanup = {"status": "closed", "closed": True, "success": True}
    inner_cleanup.update(deepcopy(cleanup or {}))
    report = {
        "schema": "information.province_trade_power_capture.v1",
        "observer": "FRA",
        "object": {"type": "province", "province_id": province_id},
        "capture": {
            "schema": "information.province_trade_power_observer_snapshot.v1",
            "status": "observed",
            "completed": True,
            "request": {
                "country": "FRA",
                "observer": "FRA",
                "session_id": context["session_id"],
                "creation_filetime": g02_fixtures.CREATION,
            },
            "access": inner_access,
            "raw_reads": raw_reads,
            "cleanup": inner_cleanup,
            "observation": {
                "stable": True,
                "context_before": {"game_date": (
                    context["game_date"] if before_date is None else before_date)},
                "context_after": {"game_date": (
                    context["game_date"] if after_date is None else after_date)},
                "backend": backend,
            },
        },
    }
    report.update(deepcopy(outer_changes or {}))
    return report


def _make_reader(tmp_path, monkeypatch, *, report=None, validator_result=True,
                 capture_error=None, after_capture=None, context=None,
                 capture_override=True, expose_validator=True):
    base_context = deepcopy(context or g02_fixtures.make_context())
    base = g02_fixtures.Base(tmp_path, base_context)
    source_report = deepcopy(report if report is not None else _capture_report(base_context))
    calls = {"capture": [], "module_capture": [], "validate": []}

    def injected_capture(installation, *, province_id, observer):
        calls["capture"].append((installation, province_id, observer))
        if after_capture is not None:
            after_capture(base)
        if capture_error is not None:
            raise capture_error
        return deepcopy(source_report)

    def module_capture(installation, *, province_id, observer):
        calls["module_capture"].append((installation, province_id, observer))
        return deepcopy(source_report)

    def validate_capture(report_arg, context_arg, creation, province_id):
        calls["validate"].append((deepcopy(report_arg), deepcopy(context_arg), creation, province_id))
        return validator_result

    module = SimpleNamespace(capture=module_capture)
    if expose_validator:
        module.validate_capture = validate_capture
    monkeypatch.setattr(reader_module, "import_module", lambda _name, _package: module)
    capture = injected_capture if capture_override else None
    reader = reader_module.NativeProvinceTradePowerReader(base, capture=capture)
    return reader, base, calls


@pytest.mark.parametrize("raw", [0, -2147483648, 2147483647])
def test_signed_i32_is_projected_only_after_capture_validator_accepts(tmp_path, monkeypatch, raw):
    context = g02_fixtures.make_context()
    report = _capture_report(context, leaf=_leaf_field(raw=raw))
    reader, _base, calls = _make_reader(tmp_path, monkeypatch, report=report)

    result = reader.read(PROVINCE_ID, context)

    assert result["schema"] == reader_module.SCHEMA
    assert result["status"] == "known"
    assert result["province_id"] == PROVINCE_ID
    assert result["value"] == {"raw": raw, "scale": 1000, "unit": "trade_power"}
    assert result["period"] == "current"
    assert result["basis"] == BASIS
    assert result["partial"] is True and result["complete"] is False
    assert result["acquisition_delta_evaluated"] is False
    assert result["cache_refresh_timing_verified"] is False
    assert result["source"]["name"] == "NativeProvinceTradePowerReader"
    assert result["source"]["mode"] == "live"
    assert result["source"]["status"] == "observed"
    assert result["source"]["observer"] == "FRA"
    assert result["source"]["session_id"] == context["session_id"]
    provenance = result["source"]["provenance"]
    assert provenance["observer"] == "FRA"
    assert provenance["province_id"] == PROVINCE_ID
    assert provenance["read_only"] is True
    assert provenance["native_function_invoked"] is False
    assert len(provenance["capture_report_sha256"]) == 64
    assert len(calls["validate"]) == 1
    assert calls["validate"][0][1:] == (context, g02_fixtures.CREATION, PROVINCE_ID)
    assert "raw_inputs" not in repr(result)
    assert "raw_reads" not in repr(result)
    assert "0x123456789abcdef0" not in repr(result)


def test_unknown_leaf_uses_fixed_reason_and_does_not_copy_reader_detail(tmp_path, monkeypatch):
    context = g02_fixtures.make_context()
    report = _capture_report(context, leaf=_leaf_field(
        status="unknown", reason="read_failed:0x123456789abcdef0",
    ))
    reader, _base, calls = _make_reader(tmp_path, monkeypatch, report=report)

    result = reader.read(PROVINCE_ID, context)

    assert result["status"] == "unknown"
    assert result["reason"] == "PROVINCE_TRADE_POWER_VALUE_UNKNOWN"
    assert "value" not in result
    assert "0x123456789abcdef0" not in repr(result)
    assert len(calls["validate"]) == 1


def test_default_module_capture_is_used_and_still_strictly_validated(tmp_path, monkeypatch):
    context = g02_fixtures.make_context()
    reader, _base, calls = _make_reader(tmp_path, monkeypatch, capture_override=False)

    result = reader.read(PROVINCE_ID, context)

    assert result["status"] == "known"
    assert calls["capture"] == []
    assert len(calls["module_capture"]) == 1
    assert len(calls["validate"]) == 1


def test_admission_or_discovery_gate_failure_withholds_trade_power(tmp_path, monkeypatch):
    context = g02_fixtures.make_context()
    report = _capture_report(context)
    report["capture"]["observation"]["backend"]["targets"][0][
        "discovery_by_pass"]["pass2"] = {"status": "known", "value": False}
    reader, _base, _calls = _make_reader(tmp_path, monkeypatch, report=report)

    result = reader.read(PROVINCE_ID, context)

    assert result["status"] == "unknown"
    assert result["reason"] == "PROVINCE_TRADE_POWER_ADMISSION_OR_DISCOVERY_UNVERIFIED"
    assert "value" not in result


@pytest.mark.parametrize("bad_value", [
    {"raw": True, "scale": 1000, "unit": "trade_power"},
    {"raw": 1 << 31, "scale": 1000, "unit": "trade_power"},
    {"raw": -(1 << 31) - 1, "scale": 1000, "unit": "trade_power"},
    {"raw": 1, "scale": 100, "unit": "trade_power"},
    {"raw": 1, "scale": 1000, "unit": "ducats"},
    {"raw": 1, "scale": 1000, "unit": "trade_power", "address": "0x1234"},
])
def test_malformed_signed_value_never_becomes_known(tmp_path, monkeypatch, bad_value):
    context = g02_fixtures.make_context()
    report = _capture_report(context, leaf=_leaf_field(value=bad_value))
    reader, _base, _calls = _make_reader(tmp_path, monkeypatch, report=report)

    result = reader.read(PROVINCE_ID, context)

    assert result["status"] == "unknown"
    assert result["reason"] == "PROVINCE_TRADE_POWER_FIELD_INVALID"
    assert "value" not in result
    assert "0x1234" not in repr(result)


def test_leaf_completeness_basis_and_period_are_required(tmp_path, monkeypatch):
    context = g02_fixtures.make_context()
    report = _capture_report(context, leaf=_leaf_field(complete=True))
    reader, _base, _calls = _make_reader(tmp_path, monkeypatch, report=report)

    result = reader.read(PROVINCE_ID, context)

    assert result["status"] == "unknown"
    assert result["reason"] == "PROVINCE_TRADE_POWER_FIELD_INVALID"
    assert "value" not in result


def test_strict_capture_validator_failure_withholds_signed_leaf(tmp_path, monkeypatch):
    context = g02_fixtures.make_context()
    reader, _base, calls = _make_reader(
        tmp_path, monkeypatch, validator_result=False,
    )

    result = reader.read(PROVINCE_ID, context)

    assert result["status"] == "unknown"
    assert result["reason"] == "PROVINCE_TRADE_POWER_CAPTURE_INVALID"
    assert "value" not in result
    assert len(calls["validate"]) == 1


def test_module_validator_is_mandatory_even_when_capture_is_injected(tmp_path, monkeypatch):
    context = g02_fixtures.make_context()
    reader, _base, calls = _make_reader(
        tmp_path, monkeypatch, expose_validator=False, capture_override=True,
    )

    result = reader.read(PROVINCE_ID, context)

    assert result["status"] == "unavailable"
    assert result["reason"] == "PROVINCE_TRADE_POWER_CAPTURE_UNAVAILABLE"
    assert calls["capture"] == []
    assert calls["validate"] == []


@pytest.mark.parametrize("province_id", [True, 0, -1, 65536])
def test_invalid_province_id_is_rejected_before_capture(tmp_path, monkeypatch, province_id):
    reader, _base, calls = _make_reader(tmp_path, monkeypatch)

    result = reader.read(province_id)

    assert result["status"] == "unknown"
    assert result["reason"] == "PROVINCE_TRADE_POWER_INVALID_PROVINCE_ID"
    assert type(result["province_id"]) is int
    assert calls["capture"] == []
    assert calls["validate"] == []


def test_stale_supplied_context_is_rejected_before_capture(tmp_path, monkeypatch):
    context = g02_fixtures.make_context()
    reader, _base, calls = _make_reader(tmp_path, monkeypatch)
    stale = deepcopy(context)
    stale["game_date"] += 24

    result = reader.read(PROVINCE_ID, stale)

    assert result["status"] == "unavailable"
    assert result["reason"] == "PROVINCE_TRADE_POWER_CONTEXT_STALE"
    assert calls["capture"] == []


def test_context_date_mismatch_inside_capture_is_unknown(tmp_path, monkeypatch):
    context = g02_fixtures.make_context()
    report = _capture_report(context, after_date=context["game_date"] + 24)
    reader, _base, calls = _make_reader(tmp_path, monkeypatch, report=report)

    result = reader.read(PROVINCE_ID, context)

    assert result["status"] == "unknown"
    assert result["reason"] == "PROVINCE_TRADE_POWER_CAPTURE_DATE_MISMATCH"
    assert len(calls["validate"]) == 1
    assert "value" not in result


@pytest.mark.parametrize("bad_access", [
    {"read_only": False},
    {"native_function_invoked": True},
])
def test_access_envelope_must_remain_read_only(tmp_path, monkeypatch, bad_access):
    context = g02_fixtures.make_context()
    report = _capture_report(context, access=bad_access)
    reader, _base, _calls = _make_reader(tmp_path, monkeypatch, report=report)

    result = reader.read(PROVINCE_ID, context)

    assert result["status"] == "unknown"
    assert result["reason"] == "PROVINCE_TRADE_POWER_CAPTURE_UNVERIFIED"
    assert "value" not in result


def test_capture_cleanup_must_be_closed_successfully(tmp_path, monkeypatch):
    context = g02_fixtures.make_context()
    report = _capture_report(context, cleanup={"status": "open", "closed": False})
    reader, _base, _calls = _make_reader(tmp_path, monkeypatch, report=report)

    result = reader.read(PROVINCE_ID, context)

    assert result["status"] == "unknown"
    assert result["reason"] == "PROVINCE_TRADE_POWER_CAPTURE_CLEANUP_UNVERIFIED"
    assert "value" not in result


def test_backend_must_bind_fra_and_the_requested_discovered_province(tmp_path, monkeypatch):
    context = g02_fixtures.make_context()
    report = _capture_report(context, target_changes={"province_id": PROVINCE_ID + 1})
    reader, _base, _calls = _make_reader(tmp_path, monkeypatch, report=report)

    result = reader.read(PROVINCE_ID, context)

    assert result["status"] == "unknown"
    assert result["reason"] == "PROVINCE_TRADE_POWER_TARGET_PROVINCE_MISMATCH"
    assert "value" not in result


def test_context_drift_during_capture_withdraws_the_annotation(tmp_path, monkeypatch):
    context = g02_fixtures.make_context()

    def drift(base):
        base.current["game_date"] += 24

    reader, _base, calls = _make_reader(tmp_path, monkeypatch, after_capture=drift)

    result = reader.read(PROVINCE_ID, context)

    assert result["status"] == "unavailable"
    assert result["reason"] == "PROVINCE_TRADE_POWER_CONTEXT_CHANGED_DURING_CAPTURE"
    assert len(calls["capture"]) == 1
    assert calls["validate"] == []
    assert "value" not in result


def test_session_creation_drift_during_capture_withdraws_the_annotation(tmp_path, monkeypatch):
    context = g02_fixtures.make_context()

    def drift(base):
        base.session.record["creation_filetime"] += 1

    reader, _base, calls = _make_reader(tmp_path, monkeypatch, after_capture=drift)

    result = reader.read(PROVINCE_ID, context)

    assert result["status"] == "unavailable"
    assert result["reason"] == "PROVINCE_TRADE_POWER_SESSION_CHANGED_DURING_CAPTURE"
    assert len(calls["capture"]) == 1
    assert calls["validate"] == []
    assert "value" not in result


def test_capture_exception_maps_to_fixed_unknown_reason(tmp_path, monkeypatch):
    reader, _base, calls = _make_reader(
        tmp_path, monkeypatch,
        capture_error=RuntimeError("private reader error at 0x123456789abcdef0"),
    )

    result = reader.read(PROVINCE_ID)

    assert result["status"] == "unknown"
    assert result["reason"] == "PROVINCE_TRADE_POWER_CAPTURE_FAILED"
    assert "RuntimeError" not in repr(result)
    assert "0x123456789abcdef0" not in repr(result)
    assert calls["validate"] == []
