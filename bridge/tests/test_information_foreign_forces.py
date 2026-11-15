"""Public F02 soldier/ship statistic projection tests.

Reports here are synthetic public-shape fixtures.  The fake validator only
checks adapter orchestration; it is not evidence of strict native raw replay.
"""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from bridge.information import InformationService
from bridge.information.catalog import list_topics
from bridge.information.composite import CompositeSource
from bridge.information import foreign_technology as source_module
from bridge.information.foreign_technology import NativeForeignTechnologySource
from bridge.information.model import InformationError
from bridge.information.tools import InformationTools
from bridge.tests.test_information_foreign_technology_capture import make_valid_capture


TARGET = "ENG"
ARMY_ID = "F02.visible_army"
NAVY_ID = "F02.visible_navy"
VISIBILITY_ID = "F02.military_resource_visibility"
ARMY_BASIS = "native_diplomacy_soldier_statistic"
NAVY_BASIS = "native_diplomacy_ship_statistic"
STATS_BASIS = "native_country_military_stats_visibility_permission"


class Base:
    event_types = ()

    def __init__(self, directory, context, creation):
        self.current = deepcopy(context)
        self.current.update(status="ready", mode="live", complete=True)
        self.session = SimpleNamespace(
            directory=directory,
            creation_filetime=creation,
            record={"session_id": self.current["session_id"],
                    "creation_filetime": creation},
        )

    def context(self):
        return deepcopy(self.current)

    def catalog(self):
        return list_topics()

    def read(self, query, context):
        return {"fields": {field: {"status": "unsupported", "reason": "PRIMARY_UNUSED"}
                           for field in query["fields"]},
                "complete": False,
                "source": {"name": "fixture_primary", "mode": "live"}}


def query(fields):
    return {"topic": "F02", "object": {"type": "country", "country": TARGET},
            "fields": list(fields), "parameters": {}}


def _view_gate(admitted=True, status="known"):
    role = {"verified": True,
            "basis": "copied_native_controller_array_not_UI_current_country"}
    return {"status": status, "admitted": admitted,
            "observer_nonplayer_role": deepcopy(role)}


def _admission(admitted=True):
    gate = _view_gate(admitted)
    return {"pass1": deepcopy(gate), "pass2": deepcopy(gate)}


def _permission(admitted=True, mode="public_options"):
    return {"status": "known", "value": {
        "admitted": admitted, "mode": mode, "basis": STATS_BASIS},
        "raw_inputs": {"address": "0xprivate-permission"}}


def force_report(*, view_admitted=True, stats_admitted=True,
                 army_status="known", navy_status="known",
                 army_value=2239, army_raw=None, army_count=51,
                 navy_value=8, navy_raw=None, valid=True,
                 army_consistency=None, navy_consistency=None):
    if army_raw is None:
        army_raw = army_value
    if navy_raw is None:
        navy_raw = navy_value

    def force_field(status, value, raw, unit, basis, **extra):
        field = {"status": status, "complete": False, "partial": True,
                 "basis": basis, "unit": unit, "scale": 1,
                 "raw_inputs": {"record_pointer_private": "0xprivate-record",
                                "display_input_raw": 2239000}}
        if status == "known":
            field.update(value=value, raw=raw)
            field.update(extra)
        else:
            field["reason"] = "FIXTURE_FIELD_UNKNOWN"
        return field

    fields = {
        ARMY_ID: force_field(army_status, army_value, army_raw, "soldiers",
                             ARMY_BASIS, record_count=army_count),
        NAVY_ID: force_field(navy_status, navy_value, navy_raw, "ships", NAVY_BASIS),
        VISIBILITY_ID: _permission(stats_admitted),
    }
    consistency = {
        ARMY_ID: {"status": army_consistency or
                  ("stable" if army_status == "known" else army_status)},
        NAVY_ID: {"status": navy_consistency or
                  ("stable" if navy_status == "known" else navy_status)},
        VISIBILITY_ID: {"status": "stable"},
    }
    return {"valid": valid, "country": TARGET, "observer": "FRA",
            "observation": {"backend": {"targets": [{
                "tag": TARGET, "admission_by_pass": _admission(view_admitted),
                "fields": fields, "field_consistency": consistency,
            }]}}}


def manpower_report(*, view_admitted=True, stats_admitted=True,
                    stats_mode="public_options", valid=True):
    return {"valid": valid, "country": TARGET, "observer": "FRA",
        "observation": {"backend": {"targets": [{
            "tag": TARGET,
            "admission_by_pass": _admission(view_admitted),
            "fields": {VISIBILITY_ID: _permission(stats_admitted, stats_mode)},
        }]}}}


def technology_report(*, view_admitted=True, valid=True):
    return {"valid": valid, "country": TARGET, "observer": "FRA",
        "observation": {"backend": {"targets": [{
            "tag": TARGET, "admission_by_pass": _admission(view_admitted),
            "technology": {"value": 18, "raw_hex": "12000000"},
        }]}}}


class FakeCaptureModule:
    def __init__(self, report, context, creation):
        self.report = deepcopy(report)
        self.context = context
        self.creation = creation
        self.validator_calls = 0
        self.capture_calls = []

    def capture(self, installation, *, country, observer):
        self.capture_calls.append((installation, country, observer))
        return deepcopy(self.report)

    def validate_capture(self, report, context, creation, country):
        self.validator_calls += 1
        return (isinstance(report, dict) and report.get("valid") is True
                and report.get("country") == country and report.get("observer") == "FRA"
                and context.get("observer") == "FRA" and creation == self.creation)


def setup_source(tmp_path, monkeypatch, *, forces=None, manpower=None, technology=None,
                 inject_technology=True):
    _, context, creation, _ = make_valid_capture(physical_tag="POR")
    base = Base(tmp_path, context, creation)
    reports = {
        "technology": technology_report() if technology is None else deepcopy(technology),
        "manpower": manpower_report() if manpower is None else deepcopy(manpower),
        "forces": force_report() if forces is None else deepcopy(forces),
    }
    modules = {name: FakeCaptureModule(report, context, creation)
               for name, report in reports.items()}
    paths = {".foreign_technology_capture": "technology",
             ".foreign_manpower_capture": "manpower",
             ".foreign_forces_capture": "forces"}

    def fake_import(name, package):
        assert package == "bridge.information"
        return modules[paths[name]]

    monkeypatch.setattr(source_module, "import_module", fake_import)
    adapter = NativeForeignTechnologySource(
        base,
        capture=modules["technology"].capture if inject_technology else None,
        manpower_capture=modules["manpower"].capture,
        forces_capture=modules["forces"].capture,
    )
    calls = []
    for name, module in modules.items():
        original = module.capture

        def wrapped(installation, *, country, observer, _name=name, _capture=original):
            calls.append((_name, installation, country, observer))
            return _capture(installation, country=country, observer=observer)

        module.capture = wrapped
        if name == "technology" and inject_technology:
            adapter.capture = wrapped
        elif name == "manpower":
            adapter.manpower_capture = wrapped
        elif name == "forces":
            adapter.forces_capture = wrapped
    return adapter, base, calls, modules


def test_army_and_navy_statistics_use_one_capture_and_expose_only_scalars(tmp_path, monkeypatch):
    adapter, base, calls, modules = setup_source(tmp_path, monkeypatch)
    result = adapter.read(query(["visible_army", "visible_navy"]), base.context())

    army = result["fields"]["visible_army"]
    navy = result["fields"]["visible_navy"]
    assert army == {"status": "known", "value": 2239, "raw": 2239,
        "unit": "soldiers", "scale": 1, "period": "current",
        "basis": ARMY_BASIS, "complete": False, "partial": True,
        "record_count": 51}
    assert navy == {"status": "known", "value": 8, "raw": 8,
        "unit": "ships", "scale": 1, "period": "current",
        "basis": NAVY_BASIS, "complete": False, "partial": True}
    assert army["record_count"] != army["value"]
    assert calls == [("forces", tmp_path / "installation.json", TARGET, "FRA")]
    assert modules["forces"].validator_calls == 1
    assert result["source"]["projection_version"] == 4
    assert set(result["source"]["provenance"]["capture_report_sha256_by_source"]) == {"forces"}
    text = repr(result)
    for private in ("raw_inputs", "record_pointer_private", "display_input_raw",
                    "0xprivate-record", "0xprivate-permission"):
        assert private not in text
    assert result["source"]["provenance"]["observer"] == "FRA"
    assert result["source"]["provenance"]["actual_UI_observed"] is False


def test_negative_signed_stat_is_preserved_and_not_scaled_or_clamped(tmp_path, monkeypatch):
    adapter, base, _, _ = setup_source(
        tmp_path, monkeypatch, forces=force_report(army_value=-9, army_count=0))
    field = adapter.read(query(["visible_army"]), base.context())["fields"]["visible_army"]
    assert field["status"] == "known"
    assert field["value"] == field["raw"] == -9
    assert field["unit"] == "soldiers" and field["scale"] == 1
    assert field["record_count"] == 0


def test_force_capture_invisible_gate_never_exports_even_fixture_values(tmp_path, monkeypatch):
    report = force_report(view_admitted=False, army_value=2239, navy_value=8)
    adapter, base, _, _ = setup_source(tmp_path, monkeypatch, forces=report)
    result = adapter.read(query(["visible_army", "visible_navy"]), base.context())
    for name in ("visible_army", "visible_navy"):
        assert result["fields"][name]["status"] == "invisible"
        assert "value" not in result["fields"][name] and "raw" not in result["fields"][name]


def test_stats_denial_hides_force_values_and_unknown_permission_retracts(tmp_path, monkeypatch):
    denied, base, _, _ = setup_source(
        tmp_path / "denied", monkeypatch,
        forces=force_report(stats_admitted=False, army_status="invisible",
                            navy_status="invisible"))
    denied_result = denied.read(query(["visible_army", "visible_navy"]), base.context())
    assert all(denied_result["fields"][name]["status"] == "invisible"
               for name in ("visible_army", "visible_navy"))
    assert all("value" not in denied_result["fields"][name]
               for name in ("visible_army", "visible_navy"))

    unknown_report = force_report()
    unknown_report["observation"]["backend"]["targets"][0]["fields"][VISIBILITY_ID] = {
        "status": "unknown", "reason": "PERMISSION_UNAVAILABLE",
        "raw_inputs": {"address": "0xprivate"}}
    unknown, unknown_base, _, _ = setup_source(
        tmp_path / "unknown", monkeypatch, forces=unknown_report)
    unknown_result = unknown.read(query(["visible_army"]), unknown_base.context())
    assert unknown_result["fields"]["visible_army"] == {
        "status": "unknown", "reason": "PERMISSION_UNAVAILABLE"}


@pytest.mark.parametrize("bad_report,bad_field", [
    (force_report(army_value=True), "visible_army"),
    (force_report(army_value=12, army_raw=13), "visible_army"),
    (force_report(army_count=True), "visible_army"),
    (force_report(navy_value=False), "visible_navy"),
])
def test_malformed_scalar_retracts_only_affected_force_field(
        tmp_path, monkeypatch, bad_report, bad_field):
    adapter, base, _, _ = setup_source(tmp_path, monkeypatch, forces=bad_report)
    result = adapter.read(query(["visible_army", "visible_navy"]), base.context())
    other_field = "visible_navy" if bad_field == "visible_army" else "visible_army"
    assert result["fields"][bad_field]["status"] == "unknown"
    assert "value" not in result["fields"][bad_field]
    assert result["fields"][other_field]["status"] == "known"


def test_field_consistency_is_independent_between_army_and_navy(tmp_path, monkeypatch):
    report = force_report(army_consistency="changed")
    adapter, base, _, _ = setup_source(tmp_path, monkeypatch, forces=report)
    result = adapter.read(query(["visible_army", "visible_navy"]), base.context())
    assert result["fields"]["visible_army"]["status"] == "unknown"
    assert result["fields"]["visible_army"]["reason"] == "FOREIGN_FORCE_FIELD_UNKNOWN"
    assert result["fields"]["visible_navy"]["status"] == "known"


def test_visibility_only_uses_manpower_capture_and_exposes_shared_gate_for_army_navy(
        tmp_path, monkeypatch):
    adapter, base, calls, modules = setup_source(tmp_path, monkeypatch)
    result = adapter.read(query(["visibility"]), base.context())
    assert [call[0] for call in calls] == ["manpower"]
    assert modules["manpower"].validator_calls == 1
    assert modules["forces"].validator_calls == 0
    visibility = result["fields"]["visibility"]
    assert visibility["status"] == "known"
    for category in ("army", "navy"):
        gate = visibility["value"][category]
        assert gate["country_view"]["admitted"] is True
        assert gate["military_stats_permission"]["admitted"] is True
        assert gate["effective_admitted"] == {"status": "known", "value": True}
        assert gate["country_view"]["actual_UI_observed"] is False


def test_force_and_visibility_share_one_capture_and_hash_source(tmp_path, monkeypatch):
    force = force_report(view_admitted=True, stats_admitted=True)
    adapter, base, calls, modules = setup_source(
        tmp_path, monkeypatch, forces=force)
    result = adapter.read(query(["visible_army", "visible_navy", "visibility"]),
                          base.context())
    assert [call[0] for call in calls] == ["forces"]
    assert modules["forces"].validator_calls == 1
    assert modules["manpower"].validator_calls == 0
    assert result["fields"]["visible_army"]["status"] == "known"
    assert result["fields"]["visible_navy"]["status"] == "known"
    assert result["fields"]["visibility"]["status"] == "known"
    assert set(result["source"]["provenance"][
        "capture_report_sha256_by_source"]) == {"forces"}


def test_explicit_manpower_and_forces_capture_both_and_all_five_use_three_sources(
        tmp_path, monkeypatch):
    adapter, base, calls, modules = setup_source(tmp_path, monkeypatch)
    result = adapter.read(query(["military_technology", "manpower", "visibility",
                                 "visible_army", "visible_navy"]), base.context())
    assert [call[0] for call in calls] == ["technology", "manpower", "forces"]
    assert all(module.validator_calls == 1 for module in modules.values())
    assert set(result["source"]["provenance"][
        "capture_report_sha256_by_source"]) == {"technology", "manpower", "forces"}


def test_one_capture_validation_failure_does_not_erase_other_capture(tmp_path, monkeypatch):
    force = force_report(valid=False)
    tech = technology_report(valid=True)
    adapter, base, calls, modules = setup_source(
        tmp_path, monkeypatch, forces=force, technology=tech)
    result = adapter.read(query(["military_technology", "visible_army"]), base.context())
    assert [call[0] for call in calls] == ["technology", "forces"]
    assert result["fields"]["military_technology"]["status"] == "known"
    assert result["fields"]["visible_army"]["status"] == "unknown"
    assert result["source"]["provenance"]["capture_failures"]["forces"] == "CAPTURE_INVALID"
    assert modules["technology"].validator_calls == modules["forces"].validator_calls == 1


def test_force_request_does_not_reuse_legacy_technology_capture_override(
        tmp_path, monkeypatch):
    _, context, creation, _ = make_valid_capture(physical_tag="POR")
    base = Base(tmp_path, context, creation)
    calls = []

    def legacy_capture(installation, *, country, observer):
        calls.append((installation, country, observer))
        return technology_report()

    adapter = NativeForeignTechnologySource(base, capture=legacy_capture)
    result = adapter.read(query(["visible_army"]), base.context())
    assert result["fields"]["visible_army"] == {
        "status": "unknown", "reason": "FOREIGN_FORCES_CAPTURE_OVERRIDE_NOT_PROVIDED"}
    assert calls == []


def test_service_query_and_saved_report_keep_force_projection_identical(tmp_path, monkeypatch):
    adapter, base, _, _ = setup_source(tmp_path, monkeypatch)
    source = CompositeSource(base, [adapter])
    service = InformationService(source, tmp_path / "information.sqlite3")
    tools = InformationTools(service)
    try:
        catalog = next(item for item in source.catalog() if item["topic_id"] == "F02")
        assert catalog["fields"]["visible_army"]["coverage"] == "partial"
        assert catalog["fields"]["visible_army"]["unit"] == "soldiers"
        assert catalog["fields"]["visible_navy"]["unit"] == "ships"
        request = {"request_id": "forces-query", "queries": [query(["visible_army", "visible_navy"])],
                   "view": "full"}
        direct = tools.call("information_query", request)
        report = tools.call("information_manage_report", {
            "request_id": "forces-report", "operation": "create",
            "config": {"name": "foreign forces", "detail": "raw",
                       "queries": [query(["visible_army", "visible_navy"])]}})["report"]
        rendered = tools.call("information_query", {
            "request_id": "forces-render", "report_id": report["id"], "view": "full"})
        assert direct["items"][0]["fields"] == rendered["items"][0]["fields"]
        assert direct["items"][0]["fields"]["visible_army"]["value"] == 2239
        assert direct["complete"] is False
    finally:
        service.close()


@pytest.mark.parametrize("bad_query", [
    {"topic": "F02", "object": {"type": "country", "country": "FRA"},
     "fields": ["visible_army"], "parameters": {}},
    {"topic": "F02", "object": {"type": "country", "country": "ENG"},
     "fields": ["unrecognized_quality"], "parameters": {}},
    {"topic": "F02", "object": {"type": "country", "country": "ENG"},
     "fields": ["visible_army", "visible_army"], "parameters": {}},
])
def test_invalid_force_queries_fail_before_any_capture(tmp_path, monkeypatch, bad_query):
    adapter, base, calls, _ = setup_source(tmp_path, monkeypatch)
    with pytest.raises(InformationError):
        adapter.read(bad_query, base.context())
    assert calls == []

