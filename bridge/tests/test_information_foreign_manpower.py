"""Public F02 manpower projection and compatibility tests."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import foreign_technology as source_module
from bridge.information.foreign_technology import NativeForeignTechnologySource
from bridge.information.model import InformationError
from bridge.tests.test_information_foreign_technology_capture import make_valid_capture


TARGET = "ENG"
MANPOWER_ID = "F02.manpower"
VISIBILITY_ID = "F02.military_resource_visibility"


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


class FakeCaptureModule:
    def __init__(self, prefix):
        self.prefix = prefix
        self.validator_calls = 0

    def validate_capture(self, report, context, creation, country):
        self.validator_calls += 1
        return (isinstance(report, dict) and report.get("valid") is True
                and report.get("country") == country
                and context.get("observer") == "FRA" and type(creation) is int)


def _view_gate(admitted=True):
    role = {"verified": True, "basis": "copied_native_controller_array_not_UI_current_country"}
    return {"status": "known", "admitted": admitted,
            "observer_nonplayer_role": deepcopy(role)}


def technology_report(*, admitted=True, value=18, valid=True):
    gate = _view_gate(admitted)
    return {"valid": valid, "country": TARGET,
        "observation": {"backend": {"targets": [{
            "tag": TARGET,
            "admission_by_pass": {"pass1": deepcopy(gate), "pass2": deepcopy(gate)},
            "technology": {"value": value,
                           "raw_hex": (value & 0xffffffff).to_bytes(4, "little").hex()},
        }]}}}


def manpower_value():
    components = [
        {"count": 2, "definition_cost": {"status": "known", "raw": 10},
         "contribution_raw": 20},
        {"count": 0, "definition_cost": {"status": "not_applicable"},
         "contribution_raw": 0},
        {"count": 3, "definition_cost": {"status": "known", "raw": -2},
         "contribution_raw": -6},
    ]
    return {"reserve_raw": 100, "components": components,
            "recruited_total_raw": 14, "total_raw": 114}


def manpower_report(*, view_admitted=True, stats_admitted=True, mode="public_options",
                    field_status="known", valid=True):
    view = _view_gate(view_admitted)
    value = manpower_value()
    field = {"status": field_status, "raw_inputs": {"address": "0x12345678"}}
    if field_status == "known":
        field["value"] = value
    elif field_status == "invisible":
        field["reason"] = "COUNTRY_VIEW_NOT_ADMITTED"
    else:
        field["reason"] = "TEST_FIELD_UNKNOWN"
    permission = {"status": "known", "value": {
        "admitted": stats_admitted, "mode": mode,
        "basis": "native_country_military_stats_visibility_permission"},
        "raw_inputs": {"address": "0x87654321"}}
    return {"valid": valid, "country": TARGET,
        "observation": {"backend": {"targets": [{
            "tag": TARGET,
            "admission_by_pass": {"pass1": deepcopy(view), "pass2": deepcopy(view)},
            "fields": {MANPOWER_ID: field, VISIBILITY_ID: permission},
            "field_consistency": {MANPOWER_ID: {"status": "stable"}},
        }]}}}


def setup_source(tmp_path, monkeypatch, *, tech=None, manpower=None,
                 tech_valid=True, manpower_valid=True, inject_legacy=False):
    _, context, creation, _ = make_valid_capture()
    base = Base(tmp_path, context, creation)
    tech_module = FakeCaptureModule("technology")
    manpower_module = FakeCaptureModule("manpower")
    selected_tech = technology_report(valid=tech_valid) if tech is None else deepcopy(tech)
    selected_manpower = manpower_report(valid=manpower_valid) if manpower is None else deepcopy(manpower)
    calls = []

    def tech_capture(installation, *, country, observer):
        calls.append(("technology", installation, country, observer))
        return deepcopy(selected_tech)

    def manpower_capture(installation, *, country, observer):
        calls.append(("manpower", installation, country, observer))
        return deepcopy(selected_manpower)

    def fake_import(name, package):
        assert package == "bridge.information"
        if name == ".foreign_technology_capture":
            tech_module.capture = tech_capture
            return tech_module
        if name == ".foreign_manpower_capture":
            manpower_module.capture = manpower_capture
            return manpower_module
        raise AssertionError(f"unexpected capture module {name}")

    monkeypatch.setattr(source_module, "import_module", fake_import)
    if inject_legacy:
        adapter = NativeForeignTechnologySource(base, capture=tech_capture)
    else:
        adapter = NativeForeignTechnologySource(base, capture=tech_capture,
                                                manpower_capture=manpower_capture)
    return adapter, base, calls, tech_module, manpower_module


def query(fields):
    return {"topic": "F02", "object": {"type": "country", "country": TARGET},
            "fields": list(fields), "parameters": {}}


def test_manpower_only_uses_its_capture_and_exports_only_public_values(tmp_path, monkeypatch):
    adapter, base, calls, _, manpower_module = setup_source(tmp_path, monkeypatch)
    result = adapter.read(query(["manpower"]), base.context())
    field = result["fields"]["manpower"]
    assert field["status"] == "known"
    assert field["unit"] == "native_manpower_statistic" and field["scale"] == 1
    assert field["complete"] is False and field["partial"] is True
    assert field["value"] == manpower_value()
    assert [entry[0] for entry in calls] == ["manpower"]
    assert manpower_module.validator_calls == 1
    assert set(result["source"]["provenance"]["capture_report_sha256_by_source"]) == {"manpower"}
    rendered = repr(result)
    for private in ("raw_inputs", "0x12345678", "0x87654321", "country_pointer"):
        assert private not in rendered


def test_combined_captures_are_separately_validated_and_visibility_combines_both_gates(
        tmp_path, monkeypatch):
    adapter, base, calls, tech_module, manpower_module = setup_source(tmp_path, monkeypatch)
    result = adapter.read(query(["military_technology", "manpower", "visibility"]), base.context())
    assert [entry[0] for entry in calls] == ["technology", "manpower"]
    assert tech_module.validator_calls == manpower_module.validator_calls == 1
    assert result["fields"]["military_technology"]["value"] == 18
    assert result["fields"]["manpower"]["value"]["total_raw"] == 114
    visibility = result["fields"]["visibility"]
    assert visibility["status"] == "known"
    assert visibility["value"]["military_technology"]["admitted"] is True
    assert visibility["value"]["manpower"]["military_stats_permission"] == {
        "status": "known", "admitted": True, "mode": "public_options",
        "basis": "native_country_military_stats_visibility_permission"}
    assert visibility["value"]["manpower"]["effective_admitted"] == {
        "status": "known", "value": True}
    for key in ("army", "navy"):
        assert visibility["value"][key]["country_view"]["admitted"] is True
        assert visibility["value"][key]["military_stats_permission"]["admitted"] is True
        assert visibility["value"][key]["effective_admitted"] == {
            "status": "known", "value": True}
    assert visibility["value"]["military_quality"]["status"] == "unknown"
    pins = result["source"]["provenance"]["capture_report_sha256_by_source"]
    assert set(pins) == {"technology", "manpower"}
    assert result["source"]["provenance"]["capture_report_sha256"] == pins["technology"]


def test_denied_military_stats_hides_manpower_but_keeps_permission_evidence(
        tmp_path, monkeypatch):
    report = manpower_report(stats_admitted=False, field_status="invisible")
    adapter, base, _, _, _ = setup_source(tmp_path, monkeypatch, manpower=report)
    result = adapter.read(query(["manpower", "visibility"]), base.context())
    assert result["fields"]["manpower"]["status"] == "invisible"
    assert "value" not in result["fields"]["manpower"]
    gates = result["fields"]["visibility"]["value"]["manpower"]
    assert gates["country_view"]["admitted"] is True
    assert gates["military_stats_permission"]["admitted"] is False
    assert gates["effective_admitted"] == {"status": "known", "value": False}


def test_outer_country_view_denial_does_not_export_manpower_or_claim_stats_result(
        tmp_path, monkeypatch):
    report = manpower_report(view_admitted=False, stats_admitted=True,
                             field_status="invisible")
    adapter, base, _, _, _ = setup_source(tmp_path, monkeypatch, manpower=report)
    result = adapter.read(query(["manpower", "visibility"]), base.context())
    assert result["fields"]["manpower"]["status"] == "invisible"
    gates = result["fields"]["visibility"]["value"]["manpower"]
    assert gates["country_view"]["admitted"] is False
    assert gates["military_stats_permission"]["status"] == "unknown"
    assert gates["effective_admitted"] == {
        "status": "known", "value": False,
        "reason": "COUNTRY_VIEW_PREDICATE_REJECTED_FOR_OBSERVER"}


def test_one_capture_failure_does_not_erase_the_other_field(tmp_path, monkeypatch):
    adapter, base, _, _, _ = setup_source(tmp_path, monkeypatch, tech_valid=False)
    result = adapter.read(query(["military_technology", "manpower", "visibility"]), base.context())
    assert result["fields"]["military_technology"]["status"] == "unknown"
    assert result["fields"]["manpower"]["status"] == "known"
    assert result["fields"]["visibility"]["value"]["manpower"]["effective_admitted"]["value"] is True


def test_inconsistent_country_view_snapshots_make_only_combined_visibility_unknown(
        tmp_path, monkeypatch):
    report = manpower_report(view_admitted=False, stats_admitted=True,
                             field_status="invisible")
    adapter, base, _, _, _ = setup_source(tmp_path, monkeypatch, manpower=report)
    result = adapter.read(query(["military_technology", "manpower", "visibility"]), base.context())
    assert result["fields"]["military_technology"]["status"] == "known"
    assert result["fields"]["manpower"]["status"] == "invisible"
    assert result["fields"]["visibility"] == {
        "status": "unknown", "reason": "COUNTRY_VIEW_CAPTURE_DISAGREEMENT",
        "basis": "combined_country_view_and_military_stats_permission"}


def test_changed_outer_context_revokes_all_fields_after_first_capture(tmp_path, monkeypatch):
    adapter, base, calls, _, _ = setup_source(tmp_path, monkeypatch)
    original = base.context
    changed = {"done": False}

    def mutate_after_capture():
        context = original()
        if calls and not changed["done"]:
            base.current["game_date"] += 1
            changed["done"] = True
        return context

    base.context = mutate_after_capture
    result = adapter.read(query(["military_technology", "manpower", "visibility"]), original())
    assert all(field["status"] == "unknown" for field in result["fields"].values())
    assert len(calls) == 1


def test_legacy_capture_override_does_not_trigger_unmocked_manpower_capture(tmp_path, monkeypatch):
    adapter, base, calls, _, _ = setup_source(tmp_path, monkeypatch, inject_legacy=True)
    result = adapter.read(query(["military_technology", "visibility"]), base.context())
    assert [entry[0] for entry in calls] == ["technology"]
    assert result["fields"]["military_technology"]["status"] == "known"
    assert result["fields"]["visibility"]["value"]["manpower"]["military_stats_permission"]["status"] == "unknown"


@pytest.mark.parametrize("field", ["unrecognized_quality", "bad"])
def test_unsupported_field_is_rejected_before_capture(tmp_path, monkeypatch, field):
    adapter, base, calls, _, _ = setup_source(tmp_path, monkeypatch)
    with pytest.raises(InformationError):
        adapter.read(query([field]), base.context())
    assert calls == []

