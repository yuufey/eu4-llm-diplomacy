"""Strict public qualification for the native province has-port predicate."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information import province_port_capture as capture_module
from bridge.information import province_port_memory as port_memory
from bridge.information import province_ports as ports_module
from bridge.information.province_ports import BASIS, FIELD, NativeProvincePortSource
from bridge.tests import test_information_province_state as g02_fixtures


PROVINCE_ID = 183
RAW_FIELD = port_memory.FIELD_HAS_PORT
GAME_DATE = g02_fixtures.make_context()["game_date"]


def _field_raw(value=True, **extra):
    return {
        "status": "known",
        "complete": False,
        "value": value,
        "basis": BASIS,
        "raw_inputs": {"predicate_raw_value": int(value), "private_marker": "RAW_PRIVATE"},
        "gaps": ["PRIVATE_CAPTURE_GAP"],
        **deepcopy(extra),
    }


def _pass_gate(*, admitted=True, discovered=True):
    return {
        "admission": {
            "status": "known",
            "admitted": admitted,
            "observer_nonplayer_role": {"observer": "FRA", "verified": True},
        },
        "discovery": {"status": "known", "value": discovered},
    }


def _capture_report(province_id=PROVINCE_ID, *, has_port=True, raw_field=None,
                    observer="FRA", backend_observer="FRA", admitted=True,
                    discovered=True, field_consistency="stable"):
    first = _pass_gate(admitted=admitted, discovered=discovered)
    second = _pass_gate(admitted=admitted, discovered=discovered)
    field = deepcopy(raw_field if raw_field is not None else _field_raw(has_port))
    target = {
        "province_id": province_id,
        "admission_by_pass": {
            "pass1": first["admission"],
            "pass2": second["admission"],
        },
        "discovery_by_pass": {
            "pass1": first["discovery"],
            "pass2": second["discovery"],
        },
        "fields": {RAW_FIELD: field},
        "field_consistency": {RAW_FIELD: {"status": field_consistency}},
    }
    return {
        "schema": capture_module.SCHEMA,
        "observer": observer,
        "object": {"type": "province", "province_id": province_id},
        "capture": {
            "schema": capture_module.INNER_SCHEMA,
            "status": "observed",
            "completed": True,
            "observation": {
                "stable": True,
                "context_before": {"game_date": GAME_DATE},
                "context_after": {"game_date": GAME_DATE},
                "backend": {
                    "status": "observed",
                    "consistency": {"status": "stable"},
                    "observer": {"tag": backend_observer},
                    "targets": [target],
                },
            },
        },
    }


def _query(province_id=PROVINCE_ID):
    return {
        "topic": "G04",
        "object": {"type": "province", "province_id": province_id},
        "fields": [FIELD],
        "parameters": {},
    }


def _make_source(tmp_path, monkeypatch, *, report=None, valid=True,
                 capture_error=None, after_capture=None):
    base = g02_fixtures.Base(tmp_path, g02_fixtures.make_context())
    actual_report = deepcopy(report if report is not None else _capture_report())
    captures = []
    validations = []

    def capture(installation, *, province_id, observer):
        captures.append((installation, province_id, observer))
        if after_capture is not None:
            after_capture(base)
        if capture_error is not None:
            raise capture_error
        return deepcopy(actual_report)

    def validate_capture(report_arg, context_arg, creation, province_id):
        validations.append((deepcopy(report_arg), deepcopy(context_arg), creation, province_id))
        return valid

    validator_module = SimpleNamespace(validate_capture=validate_capture)
    monkeypatch.setattr(ports_module, "import_module", lambda _name, _package: validator_module)
    source = NativeProvincePortSource(base, capture=capture)
    return source, base, actual_report, captures, validations


def test_verified_true_and_false_project_without_private_predicate_inputs(tmp_path, monkeypatch):
    for index, has_port in enumerate((True, False)):
        case_dir = tmp_path / f"case-{index}"
        case_dir.mkdir()
        report = _capture_report(has_port=has_port)
        source, base, _report, captures, validations = _make_source(
            case_dir, monkeypatch, report=report,
        )

        result = source.read(_query(), base.context())

        field = result["fields"][FIELD]
        assert field["status"] == "known"
        assert field["value"] == {"province_id": PROVINCE_ID, "has_port": has_port}
        assert field["basis"] == BASIS
        assert field["period"] == "current"
        assert field["partial"] is True
        assert field["complete"] is False
        assert "unit" not in field
        assert result["source"]["context_scope"] == "visible_scope"
        assert result["source"]["provenance"]["native_function_invoked"] is False
        assert "RAW_PRIVATE" not in repr(result)
        assert "predicate_raw_value" not in repr(result)
        assert captures == [(case_dir / "installation.json", PROVINCE_ID, "FRA")]
        assert validations[0][1]["observer"] == "FRA"
        assert validations[0][2:] == (g02_fixtures.CREATION, PROVINCE_ID)


@pytest.mark.parametrize(("case", "raw_field", "expected_reason"), [
    ("missing", None, "PROVINCE_PORT_FIELD_MISSING"),
    ("unknown", {"status": "unknown", "reason": "FIELD_READER_FAILED",
                  "raw_inputs": {"private_marker": "RAW_PRIVATE"}}, "FIELD_READER_FAILED"),
    ("integer-zero", _field_raw(0), "PROVINCE_PORT_FIELD_INVALID"),
    ("bad-unit", _field_raw(True, unit="trade_power"), "PROVINCE_PORT_FIELD_INVALID"),
    ("bad-basis", _field_raw(True, basis="province_center_of_trade"), "PROVINCE_PORT_FIELD_INVALID"),
])
def test_missing_unknown_or_malformed_leaf_never_becomes_false(
    tmp_path, monkeypatch, case, raw_field, expected_reason,
):
    report = _capture_report(raw_field=raw_field)
    if case == "missing":
        report["capture"]["observation"]["backend"]["targets"][0]["fields"] = {}
    source, base, _report, _captures, _validations = _make_source(
        tmp_path, monkeypatch, report=report,
    )

    result = source.read(_query(), base.context())

    field = result["fields"][FIELD]
    assert field["status"] == "unknown"
    assert field["reason"] == expected_reason
    assert "value" not in field
    assert "raw_inputs" not in field
    assert "RAW_PRIVATE" not in repr(result)


@pytest.mark.parametrize(("case", "mutate", "expected_reason"), [
    ("outer-province", lambda report: report["object"].update(province_id=184),
     "PROVINCE_PORT_CAPTURE_OBJECT_MISMATCH"),
    ("observer", lambda report: report.update(observer="ENG"),
     "PROVINCE_PORT_CAPTURE_OBSERVER_MISMATCH"),
    ("backend-observer", lambda report: report["capture"]["observation"]["backend"]["observer"].update(tag="ENG"),
     "PROVINCE_PORT_BACKEND_OBSERVER_MISMATCH"),
    ("admission", lambda report: report["capture"]["observation"]["backend"]["targets"][0][
        "admission_by_pass"]["pass2"].update(admitted=False),
     "PROVINCE_PORT_ADMISSION_OR_DISCOVERY_UNVERIFIED"),
    ("discovery", lambda report: report["capture"]["observation"]["backend"]["targets"][0][
        "discovery_by_pass"]["pass1"].update(value=False),
     "PROVINCE_PORT_ADMISSION_OR_DISCOVERY_UNVERIFIED"),
])
def test_identity_admission_and_discovery_gates_fail_closed(
    tmp_path, monkeypatch, case, mutate, expected_reason,
):
    report = _capture_report()
    mutate(report)
    source, base, _report, _captures, _validations = _make_source(
        tmp_path, monkeypatch, report=report,
    )

    result = source.read(_query(), base.context())

    field = result["fields"][FIELD]
    assert field["status"] == "unknown"
    assert field["reason"] == expected_reason
    assert "value" not in field


def test_capture_read_error_and_live_context_drift_do_not_project_a_port(tmp_path, monkeypatch):
    read_dir = tmp_path / "capture-error"
    read_dir.mkdir()
    source, base, _report, captures, validations = _make_source(
        read_dir, monkeypatch, capture_error=OSError("bounded capture failed"),
    )
    failed = source.read(_query(), base.context())["fields"][FIELD]
    assert failed["status"] == "unknown"
    assert failed["reason"] == "PROVINCE_PORT_CAPTURE_FAILED:OSError"
    assert "value" not in failed
    assert validations == []

    drift_dir = tmp_path / "context-drift"
    drift_dir.mkdir()

    def drift_context(base_source):
        base_source.current["game_date"] += 1

    source, base, _report, drift_captures, drift_validations = _make_source(
        drift_dir, monkeypatch, after_capture=drift_context,
    )
    drifted = source.read(_query(), base.context())["fields"][FIELD]
    assert drifted["status"] == "unavailable"
    assert drifted["reason"] == "PROVINCE_PORT_CONTEXT_CHANGED_DURING_CAPTURE"
    assert "value" not in drifted
    assert len(captures) == 1
    assert drift_validations == []
    assert drift_captures == [(drift_dir / "installation.json", PROVINCE_ID, "FRA")]


@pytest.mark.parametrize('observer_tag', ['FRA', 'TUR'])
def test_capture_uses_profiled_owner_and_existing_generic_g02_double_pass(monkeypatch, observer_tag):
    calls = {}

    def fake_read_two_pass(reader, base, province_id, *, observer, fields, read_fields, observer_scoped):
        assert observer_scoped is True
        calls["two_pass"] = (reader, base, province_id, observer, fields, read_fields)
        return {"status": "observed", "consistency": {"status": "stable"}}

    def fake_observe(reader, base, country, profile, *, backend_reader):
        return {"stable": True, "backend": backend_reader(reader, base, country)}

    def fake_capture_common(installation, country, *, observer, schema, profile_sha256,
                            load_profile, observe, allow_observer_target, observer_scoped):
        assert observer_scoped is True
        calls["capture_common"] = {
            "installation": installation,
            "country": country,
            "observer": observer,
            "schema": schema,
            "profile_sha256": profile_sha256,
            "load_profile": load_profile,
            "allow_observer_target": allow_observer_target,
        }
        return {
            "schema": schema,
            "status": "observed",
            "completed": True,
            "observation": observe(object(), 0x140000000, country, {"profile_id": "test"}),
        }

    monkeypatch.setattr(capture_module._province, "read_two_pass", fake_read_two_pass)
    monkeypatch.setattr(capture_module._owner, "_observe", fake_observe)
    monkeypatch.setattr(capture_module._owner, "_capture_common", fake_capture_common)

    report = capture_module.capture(Path("installation.json"), PROVINCE_ID, observer=observer_tag)

    assert report["schema"] == capture_module.SCHEMA
    assert report["observer"] == observer_tag
    assert report["object"] == {"type": "province", "province_id": PROVINCE_ID}
    assert report["capture"]["observation"]["stable"] is True
    two_pass = calls["two_pass"]
    assert two_pass[2:5] == (PROVINCE_ID, observer_tag, (RAW_FIELD,))
    assert two_pass[5] is port_memory.read_fields
    capture_args = calls["capture_common"]
    assert capture_args["country"] == capture_args["observer"] == observer_tag
    assert capture_args["schema"] == capture_module.INNER_SCHEMA
    assert capture_args["profile_sha256"] == capture_module.PROFILE_SHA256
    assert callable(capture_args["load_profile"])
    assert capture_args["allow_observer_target"] is True


def test_profile_manifest_is_frozen_and_dependencies_match():
    profile = capture_module._load_profile()
    assert profile["profile_id"] == "province-port-memory-1374"
    assert profile["profile_version"] == 1
    assert profile["game_version"] == "1.37.4"


def test_g04_composite_query_routes_ports_as_a_partial_field(tmp_path, monkeypatch):
    base = g02_fixtures.Base(tmp_path, g02_fixtures.make_context())
    report = _capture_report(has_port=True)
    captures = []

    def capture(installation, *, province_id, observer):
        captures.append((installation, province_id, observer))
        return deepcopy(report)

    validator_module = SimpleNamespace(validate_capture=lambda *_args: True)
    monkeypatch.setattr(ports_module, "import_module", lambda _name, _package: validator_module)
    adapter = NativeProvincePortSource(base, capture=capture)
    composite = CompositeSource(base, [adapter])
    service = InformationService(composite, tmp_path / "province-ports.sqlite3")
    try:
        topic = next(item for item in composite.catalog() if item["topic_id"] == "G04")
        assert topic["fields"][FIELD]["coverage"] == "partial"
        assert topic["fields"][FIELD]["basis"] == BASIS
        result = service.query("province-port-composite-query", queries=[_query()])
        field = result["items"][0]["fields"][FIELD]
        assert field["status"] == "known"
        assert field["value"] == {"province_id": PROVINCE_ID, "has_port": True}
        assert result["items"][0]["query"]["topic"] == "G04"
        assert captures == [(tmp_path / "installation.json", PROVINCE_ID, "FRA")]
    finally:
        service.close()
