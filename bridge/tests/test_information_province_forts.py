"""Strict public qualification for the native province fort-level input."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information import province_fort_capture as capture_module
from bridge.information import province_fort_memory as fort_memory
from bridge.information import province_forts as forts_module
from bridge.information.province_forts import BASIS, FIELD, NativeProvinceFortSource
from bridge.information.straits import StaticStraitsSource
from bridge.tests import test_information_province_state as g02_fixtures


PROVINCE_ID = 183
RAW_FIELD = fort_memory.FIELD_FORT_LEVEL
GAME_DATE = g02_fixtures.make_context()["game_date"]


def _field_raw(value=2, **extra):
    return {
        "status": "known",
        "complete": False,
        "value": value,
        "basis": BASIS,
        "raw_inputs": {"fort_level_raw": deepcopy(value), "private_marker": "RAW_PRIVATE"},
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


def _capture_report(province_id=PROVINCE_ID, *, fort_level=2, raw_field=None,
                    observer="FRA", backend_observer="FRA", admitted=True,
                    discovered=True, field_consistency="stable"):
    first = _pass_gate(admitted=admitted, discovered=discovered)
    second = _pass_gate(admitted=admitted, discovered=discovered)
    field = deepcopy(raw_field if raw_field is not None else _field_raw(fort_level))
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


def _query(province_id=PROVINCE_ID, *, fields=None):
    return {
        "topic": "G03",
        "object": {"type": "province", "province_id": province_id},
        "fields": list(fields if fields is not None else [FIELD]),
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
    monkeypatch.setattr(forts_module, "import_module", lambda _name, _package: validator_module)
    source = NativeProvinceFortSource(base, capture=capture)
    return source, base, actual_report, captures, validations


def test_signed_i32_values_project_without_private_inputs_or_clamping(tmp_path, monkeypatch):
    for index, fort_level in enumerate((0, -1, -(1 << 31), (1 << 31) - 1)):
        case_dir = tmp_path / f"case-{index}"
        case_dir.mkdir()
        report = _capture_report(fort_level=fort_level)
        source, base, _report, captures, validations = _make_source(
            case_dir, monkeypatch, report=report,
        )

        result = source.read(_query(), base.context())

        field = result["fields"][FIELD]
        assert field["status"] == "known"
        assert field["value"] == {"province_id": PROVINCE_ID, "fort_level": fort_level}
        assert field["basis"] == BASIS
        assert field["period"] == "current"
        assert field["partial"] is True
        assert field["complete"] is False
        assert "unit" not in field
        assert result["source"]["context_scope"] == "visible_scope"
        assert result["source"]["provenance"]["native_function_invoked"] is False
        assert "RAW_PRIVATE" not in repr(result)
        assert "fort_level_raw" not in repr(result)
        assert captures == [(case_dir / "installation.json", PROVINCE_ID, "FRA")]
        assert validations[0][1]["observer"] == "FRA"
        assert validations[0][2:] == (g02_fixtures.CREATION, PROVINCE_ID)


@pytest.mark.parametrize(("case", "raw_field", "expected_reason"), [
    ("missing", None, "PROVINCE_FORT_FIELD_MISSING"),
    ("unknown", {"status": "unknown", "reason": "FIELD_READER_FAILED",
                  "raw_inputs": {"private_marker": "RAW_PRIVATE"}}, "FIELD_READER_FAILED"),
    ("bool-is-not-an-int", _field_raw(True), "PROVINCE_FORT_FIELD_INVALID"),
    ("float-is-not-an-int", _field_raw(2.0), "PROVINCE_FORT_FIELD_INVALID"),
    ("high-out-of-range", _field_raw(1 << 31), "PROVINCE_FORT_FIELD_INVALID"),
    ("low-out-of-range", _field_raw(-(1 << 31) - 1), "PROVINCE_FORT_FIELD_INVALID"),
    ("bad-unit", _field_raw(2, unit="fort_count"), "PROVINCE_FORT_FIELD_INVALID"),
    ("bad-basis", _field_raw(2, basis="province_fort_state"), "PROVINCE_FORT_FIELD_INVALID"),
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
     "PROVINCE_FORT_CAPTURE_OBJECT_MISMATCH"),
    ("observer", lambda report: report.update(observer="ENG"),
     "PROVINCE_FORT_CAPTURE_OBSERVER_MISMATCH"),
    ("backend-observer", lambda report: report["capture"]["observation"]["backend"]["observer"].update(tag="ENG"),
     "PROVINCE_FORT_BACKEND_OBSERVER_MISMATCH"),
    ("admission", lambda report: report["capture"]["observation"]["backend"]["targets"][0][
        "admission_by_pass"]["pass2"].update(admitted=False),
     "PROVINCE_FORT_ADMISSION_OR_DISCOVERY_UNVERIFIED"),
    ("discovery", lambda report: report["capture"]["observation"]["backend"]["targets"][0][
        "discovery_by_pass"]["pass1"].update(value=False),
     "PROVINCE_FORT_ADMISSION_OR_DISCOVERY_UNVERIFIED"),
    ("field-changed", lambda report: report["capture"]["observation"]["backend"]["targets"][0][
        "field_consistency"][RAW_FIELD].update(status="changed"),
     "PROVINCE_FORT_FIELD_CHANGED_BETWEEN_PASSES"),
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


def test_capture_read_error_and_live_context_drift_do_not_project_a_fort_level(tmp_path, monkeypatch):
    read_dir = tmp_path / "capture-error"
    read_dir.mkdir()
    source, base, _report, captures, validations = _make_source(
        read_dir, monkeypatch, capture_error=OSError("bounded capture failed"),
    )
    failed = source.read(_query(), base.context())["fields"][FIELD]
    assert failed["status"] == "unknown"
    assert failed["reason"] == "PROVINCE_FORT_CAPTURE_FAILED:OSError"
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
    assert drifted["reason"] == "PROVINCE_FORT_CONTEXT_CHANGED_DURING_CAPTURE"
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
    assert two_pass[5] is fort_memory.read_fields
    capture_args = calls["capture_common"]
    assert capture_args["country"] == capture_args["observer"] == observer_tag
    assert capture_args["schema"] == capture_module.INNER_SCHEMA
    assert capture_args["profile_sha256"] == capture_module.PROFILE_SHA256
    assert callable(capture_args["load_profile"])
    assert capture_args["allow_observer_target"] is True


def test_profile_manifest_is_frozen_and_dependencies_match():
    profile = capture_module._load_profile()
    assert profile["profile_id"] == "province-fort-memory-1374"
    assert profile["profile_version"] == 1
    assert profile["game_version"] == "1.37.4"


def test_g03_composite_merges_disjoint_fort_and_straits_fields_and_keeps_pair_unknown(
    tmp_path, monkeypatch,
):
    base = g02_fixtures.Base(tmp_path, g02_fixtures.make_context())
    report = _capture_report(fort_level=-3)
    captures = []

    def capture(installation, *, province_id, observer):
        captures.append((installation, province_id, observer))
        return deepcopy(report)

    validator_module = SimpleNamespace(validate_capture=lambda *_args: True)
    monkeypatch.setattr(forts_module, "import_module", lambda _name, _package: validator_module)
    adapter = NativeProvinceFortSource(base, capture=capture)
    index = SimpleNamespace(
        context=lambda: {
            "status": "ready", "mode": "static", "context_scope": "static_rules",
            "game_version": "1.37.4", "definitions_sha256": "a" * 64,
            "config_sha256": "b" * 64,
        },
        lookup=lambda _province_id: {"status": "known", "value": [{
            "from_province": 183, "to_province": 184, "through_province": None,
            "source_lines": [2],
        }]},
    )
    static = StaticStraitsSource(index=index)
    composite = CompositeSource(base, [static, adapter])
    service = InformationService(composite, tmp_path / "province-forts.sqlite3")
    try:
        topic = next(item for item in composite.catalog() if item["topic_id"] == "G03")
        assert set(topic["fields"]) >= {FIELD, "straits"}
        assert topic["fields"][FIELD]["coverage"] == "partial"
        assert topic["fields"][FIELD]["basis"] == BASIS
        result = service.query(
            "province-fort-composite-query",
            queries=[_query(fields=[FIELD, "straits"])],
        )
        item = result["items"][0]
        assert item["fields"][FIELD]["status"] == "known"
        assert item["fields"][FIELD]["value"] == {"province_id": PROVINCE_ID, "fort_level": -3}
        assert item["fields"]["straits"]["status"] == "known"
        assert item["query"]["topic"] == "G03"

        pair_query = {
            "topic": "G03",
            "object": {"type": "country_pair", "actor": "FRA", "recipient": "ENG"},
            "fields": [FIELD, "straits"],
            "parameters": {},
        }
        pair = service.query("province-fort-pair-query", queries=[pair_query])
        assert pair["items"][0]["fields"][FIELD]["status"] == "unknown"
        assert pair["items"][0]["fields"][FIELD]["reason"] == "FORT_COUNTRY_PAIR_NOT_IMPLEMENTED"
        assert pair["items"][0]["fields"]["straits"]["status"] == "unknown"
        assert pair["items"][0]["fields"]["straits"]["reason"] == "COUNTRY_PAIR_STRAITS_NOT_IMPLEMENTED"
        assert captures == [(tmp_path / "installation.json", PROVINCE_ID, "FRA")]
    finally:
        service.close()


def test_g03_fort_routes_through_query_report_and_periodic_collection(tmp_path, monkeypatch):
    base = g02_fixtures.Base(tmp_path, g02_fixtures.make_context())
    report = _capture_report(fort_level=4)
    captures = []

    def capture(installation, *, province_id, observer):
        captures.append((installation, province_id, observer))
        return deepcopy(report)

    validator_module = SimpleNamespace(validate_capture=lambda *_args: True)
    monkeypatch.setattr(forts_module, "import_module", lambda _name, _package: validator_module)
    adapter = NativeProvinceFortSource(base, capture=capture)
    now = [10]
    service = InformationService(adapter, tmp_path / "province-fort-triggers.sqlite3",
                                 clock=lambda: now[0])
    try:
        direct = service.query("fort-direct-query", queries=[_query()])
        assert direct["items"][0]["fields"][FIELD]["value"] == {
            "province_id": PROVINCE_ID, "fort_level": 4,
        }

        saved = service.manage_report(
            "fort-report-create",
            "create",
            config={"name": "fort level", "queries": [_query()]},
        )["report"]
        via_report = service.query("fort-report-query", report_id=saved["id"])
        assert via_report["items"][0]["fields"][FIELD]["status"] == "known"

        service.manage_subscription(
            "fort-periodic-create",
            "create",
            config={
                "kind": "periodic",
                "report_id": saved["id"],
                "schedule": {"basis": "real", "every": 1, "unit": "seconds"},
            },
        )
        now[0] = 11
        tick = service.tick()
        assert tick["state"] == "processed"
        assert len(tick["results"]) == 1
        assert tick["results"][0]["items"][0]["fields"][FIELD]["value"] == {
            "province_id": PROVINCE_ID, "fort_level": 4,
        }
        assert captures == [(tmp_path / "installation.json", PROVINCE_ID, "FRA")] * 3
    finally:
        service.close()
