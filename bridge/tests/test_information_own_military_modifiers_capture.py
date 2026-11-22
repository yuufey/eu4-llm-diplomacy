"""Offline tests for the isolated FRA aggregate-modifier capture wrapper."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information import foreign_quality_capture
from bridge.information import own_military_modifiers_capture as capture
from bridge.tests import test_information_foreign_quality as quality_fixture


CREATION = 123456789012345678
SESSION = "own-modifier-wrapper-session"


def _report() -> dict:
    """Promote the existing synthetic quality report to wrapper packet shape."""
    report = quality_fixture.quality_report()
    observation = report["observation"]
    observation["stable"] = True
    backend = observation["backend"]
    backend.update(status="observed", consistency={"status": "stable"})
    target = backend["targets"][0]
    target["tag"] = "FRA"
    return {
        "schema": capture.SCHEMA,
        "status": "observed",
        "completed": True,
        "request": {"country": "FRA", "observer": "FRA",
                    "creation_filetime": CREATION, "session_id": SESSION},
        "profile_sha256": capture.PROFILE_SHA256,
        "identity": {"binding_verified": True,
                     "process_creation_filetime": CREATION},
        "identity_after": {"binding_verified": True,
                           "process_creation_filetime": CREATION},
        "module_base": "0x180000000",
        "observation": observation,
        "cleanup": {"status": "closed", "closed": True, "success": True},
        "raw_reads": [],
        "access": {"read_only": True, "native_function_invoked": False,
                   "writes": False, "UI_control": False, "date_advance": False,
                   "save_or_reload": False, "limit_bytes": 512 * 1024,
                   "calls": 0, "bytes_requested": 0},
        "errors": [],
    }


def _component(report: dict, group: str, key: str) -> dict:
    return (report["observation"]["backend"]["targets"][0]["fields"]
            [foreign_quality_capture.QUALITY_FIELD]["value"][group][key])


def test_projection_selects_only_three_components_and_strips_private_inputs():
    report = _report()
    field = capture.project_field(report)

    assert field["status"] == "known"
    assert field["unit"] == "military_modifier_map"
    assert field["scale"] == 1 and field["period"] == "current"
    assert field["complete"] is False and field["partial"] is True
    assert field["key_subset"] == [
        "army.siege_ability", "army.defensiveness", "navy.ship_durability"]
    assert set(field["value"]) == {"army", "navy"}
    assert set(field["value"]["army"]) == {"siege_ability", "defensiveness"}
    assert set(field["value"]["navy"]) == {"ship_durability"}
    for group in field["value"].values():
        for item in group.values():
            assert item["status"] == "known"
            assert item["unit"] == "ratio_modifier" and item["scale"] == 1000
            assert type(item["raw"]) is int
            assert item["value"] == item["raw"] / 1000
    assert "raw_inputs" not in repr(field)
    assert "private" not in repr(field)


def test_twelve_known_components_do_not_imply_selected_components_known():
    report = _report()
    for group, key in (("army", "siege_ability"),
                       ("army", "defensiveness"),
                       ("navy", "ship_durability")):
        _component(report, group, key).update(
            status="unknown", reason="SELECTED_COMPONENT_PENDING")
        _component(report, group, key).pop("raw", None)
        _component(report, group, key).pop("value", None)
    field = capture.project_field(report)
    assert field == {"status": "unknown",
                     "reason": "SELECTED_MILITARY_MODIFIERS_UNKNOWN"}


def test_mixed_selected_components_keep_unknown_reason_and_negative_raw():
    report = _report()
    _component(report, "army", "siege_ability").update(
        status="unknown", reason="SIEGE_NOT_CAPTURED")
    _component(report, "army", "siege_ability").pop("raw", None)
    _component(report, "army", "siege_ability").pop("value", None)
    defensiveness = _component(report, "army", "defensiveness")
    # The source record carries the native integer in ``value``; the shared
    # quality projection normalizes it to -0.07 for this public wrapper.
    defensiveness.update(raw=-70, value=-70)
    ship = _component(report, "navy", "ship_durability")
    ship.update(status="unknown", reason="SHIP_NOT_CAPTURED")
    ship.pop("raw", None)
    ship.pop("value", None)

    field = capture.project_field(report)
    assert field["status"] == "known"
    assert field["value"]["army"]["siege_ability"] == {
        "status": "unknown", "reason": "SIEGE_NOT_CAPTURED"}
    assert field["value"]["army"]["defensiveness"] == {
        "status": "known", "value": -0.07, "raw": -70,
        "unit": "ratio_modifier", "scale": 1000}
    assert field["value"]["navy"]["ship_durability"] == {
        "status": "unknown", "reason": "SHIP_NOT_CAPTURED"}


@pytest.mark.parametrize("tamper", ["unit", "scale", "raw_type", "value"])
def test_invalid_selected_leaf_is_retracted_without_leaking_it(tamper):
    report = _report()
    item = _component(report, "army", "siege_ability")
    if tamper == "unit":
        item["unit"] = "ratio"
    elif tamper == "scale":
        item["scale"] = True
    elif tamper == "raw_type":
        item["raw"] = "1000"
    else:
        item["value"] = 2.0
    field = capture.project_field(report)
    assert field["status"] == "known"  # the other two selected leaves remain known
    expected_reason = ("QUALITY_COMPONENT_RAW_INVALID" if tamper == "raw_type"
                       else "QUALITY_COMPONENT_INVALID")
    assert field["value"]["army"]["siege_ability"] == {
        "status": "unknown", "reason": expected_reason}
    assert "raw_inputs" not in repr(field)


def test_invisible_or_wrong_target_never_exports_values():
    report = _report()
    target = report["observation"]["backend"]["targets"][0]
    for phase in ("pass1", "pass2"):
        target["admission_by_pass"][phase]["admitted"] = False
    invisible = capture.project_field(report)
    assert invisible["status"] == "invisible" and "value" not in invisible

    report = _report()
    report["observation"]["backend"]["targets"][0]["tag"] = "ENG"
    assert capture.project_field(report) == {
        "status": "unknown",
        "reason": "OWN_MILITARY_MODIFIERS_CAPTURE_NOT_VALIDATED"}


@pytest.mark.parametrize("change", [
    lambda report: report.update(schema="information.foreign_quality_capture.v2"),
    lambda report: report.update(status="unknown"),
    lambda report: report["observation"].update(stable=False),
    lambda report: report.update(profile_sha256="0" * 64),
])
def test_projection_rejects_unvalidated_packet(change):
    report = _report()
    change(report)
    assert capture.project_field(report)["status"] == "unknown"


def test_capture_uses_configured_observer_and_passes_self_target_flag(monkeypatch, tmp_path):
    calls = []

    def fake_common(*args, **kwargs):
        calls.append((args, kwargs))
        return {"status": "observed"}

    monkeypatch.setattr(capture._owner, "_capture_common", fake_common)
    assert capture.capture(tmp_path / "installation.json", observer='TUR') == {"status": "observed"}
    assert calls[0][0][1] == "TUR"
    assert calls[0][1]['observer_scoped'] is True
    assert calls[0][1]["allow_observer_target"] is True
    assert calls[0][1]["schema"] == capture.SCHEMA
    assert calls[0][1]["load_profile"] is capture._quality_capture._load_profile
    assert calls[0][1]["observe"].func is capture._quality_capture._observe
    assert calls[0][1]["observe"].keywords == {'observer': 'TUR'}
    assert len(calls) == 1


def test_validate_uses_strict_access_and_self_target(monkeypatch):
    calls = []

    def fake_validate(*args, **kwargs):
        calls.append((args, kwargs))
        return True

    monkeypatch.setattr(capture._owner, "_validate_capture_common", fake_validate)
    report = _report()
    context = {"observer": "FRA", "session_id": SESSION}
    assert capture.validate_capture(report, context, CREATION) is True
    assert calls[0][0][3] == "FRA"
    assert calls[0][1]["allow_observer_target"] is True
    assert calls[0][1]["require_access"] is True
    assert calls[0][1]["schema"] == capture.SCHEMA
    assert capture.validate_capture({"schema": "wrong"}, context, CREATION) is False
    assert len(calls) == 1


def test_legacy_foreign_quality_self_capture_still_rejects_before_openprocess(tmp_path):
    old = foreign_quality_capture.capture(
        Path(tmp_path) / "does-not-exist-installation.json", "FRA")
    assert old["status"] == "unknown"
    assert old["completed"] is False
    assert old["errors"][0]["reason"] == "FOREIGN_TECH_REQUEST_SCOPE"

    # The old validator must not accept this independent self-target schema.
    assert not foreign_quality_capture.validate_capture(
        _report(), {"observer": "FRA", "session_id": SESSION}, CREATION, "FRA")

