"""Offline tests for the bounded N03 military-modifier source."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import own_military_modifiers as modifiers_module
from bridge.information.catalog import InformationError
from bridge.information.catalog import list_topics
from bridge.information.own_military_modifiers import NativeOwnMilitaryModifiersSource


GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
CREATION = 134380633247930565
PROFILE_SHA = "b" * 64


def make_context(**overrides):
    context = {
        "status": "ready",
        "mode": "live",
        "complete": True,
        "observer": "FRA",
        "session_id": "own-military-modifiers-test-session",
        "game_version": "1.37.4",
        "game_sha256": GAME_SHA,
        "game_date": 56569464,
        "physical_client_country": "POR",
    }
    context.update(overrides)
    return context


class FakeBase:
    event_types = ()

    def __init__(self, directory: Path, context: dict):
        self.current = deepcopy(context)
        self.context_calls = 0
        self.catalog_calls = 0
        self.session = SimpleNamespace(
            directory=directory,
            creation_filetime=CREATION,
            record={
                "session_id": context["session_id"],
                "creation_filetime": CREATION,
            },
        )

    def context(self):
        self.context_calls += 1
        return deepcopy(self.current)

    def catalog(self):
        self.catalog_calls += 1
        return list_topics()

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": deepcopy(cursor or {}),
                "complete": True, "gaps": []}


def make_query(*, country="FRA", fields=None, parameters=None):
    return {
        "topic": "N03",
        "object": {"type": "country", "country": country},
        "fields": list(fields if fields is not None else ("military_modifiers",)),
        "parameters": deepcopy(parameters if parameters is not None else {}),
    }


def _item_known(raw):
    return {
        "status": "known",
        "value": raw / 1000,
        "raw": raw,
        "unit": "ratio_modifier",
        "scale": 1000,
    }


def _projection(*, siege=None, defense=None, durability=None, status="known", reason=None):
    if status != "known":
        return {"status": status, "reason": reason or "NO_SELECTED_MODIFIER_KNOWN"}
    projected = {
        "status": status,
        "unit": "military_modifier_map",
        "scale": 1,
        "period": "current",
        "complete": False,
        "partial": True,
        "basis": "native_selected_military_modifier_cache",
        "value_origin": "derived_from_copied_native_aggregate_modifiers",
        "key_subset": ["army.siege_ability", "army.defensiveness", "navy.ship_durability"],
    }
    if status == "known":
        projected["value"] = {
            "army": {
                "siege_ability": siege if siege is not None else _item_known(225),
                "defensiveness": defense if defense is not None else {
                    "status": "unknown", "reason": "PROCESSOR_CONTRACT_UNSUPPORTED",
                },
            },
            "navy": {
                "ship_durability": durability if durability is not None else {
                    "status": "invisible", "reason": "NATIVE_PERMISSION_DENIED",
                },
            },
        }
    return projected


def make_source(tmp_path, monkeypatch, *, projection=None, validation=True,
                after_capture=None, capture_error=None, profile_sha=PROFILE_SHA,
                context=None):
    base = FakeBase(tmp_path, context or make_context())
    report = {
        "capture_fixture": "synthetic-own-military-modifiers",
        "private_pointer": "0x12345678",
        "raw_inputs": {"copied_value": "private"},
    }
    calls = {"capture": [], "validate": [], "project": []}

    def capture(installation, *, observer):
        calls["capture"].append((installation, observer))
        if after_capture is not None:
            after_capture(base)
        if capture_error is not None:
            raise capture_error
        return deepcopy(report)

    def validate_capture(report_arg, context_arg, creation):
        calls["validate"].append((deepcopy(report_arg), deepcopy(context_arg), creation))
        return validation

    projected = deepcopy(projection if projection is not None else _projection())

    def project_field(report_arg):
        calls["project"].append(deepcopy(report_arg))
        return deepcopy(projected)

    module = SimpleNamespace(
        PROFILE_SHA256=profile_sha,
        validate_capture=validate_capture,
        project_field=project_field,
    )
    monkeypatch.setattr(
        modifiers_module, "import_module", lambda _name, _package: module,
    )
    source = NativeOwnMilitaryModifiersSource(base, capture=capture)
    return source, base, report, calls


def test_catalog_declares_only_partial_military_modifier_map(tmp_path):
    source = NativeOwnMilitaryModifiersSource(FakeBase(tmp_path, make_context()))
    topic = source.catalog()[0]

    assert topic["topic_id"] == "N03"
    assert set(topic["fields"]) == {"military_modifiers"}
    field = topic["fields"]["military_modifiers"]
    assert field["coverage"] == "partial"
    assert field["complete"] is False
    assert field["unit"] == "military_modifier_map"
    assert field["scale"] == 1
    assert field["period"] == "current"
    assert topic["observer_scope"] == []
    assert field["supported_object_types"] == ["country"]
    assert topic["triggers"] == ["query", "periodic"]
    assert topic["parameters"]["additionalProperties"] is False


def test_known_partial_map_keeps_item_unknown_reasons_and_never_leaks_capture(
        tmp_path, monkeypatch):
    source, base, report, calls = make_source(tmp_path, monkeypatch)

    result = source.read(make_query(), base.context())

    field = result["fields"]["military_modifiers"]
    assert field["status"] == "known"
    assert field["value"] == {
        "army": {
            "siege_ability": _item_known(225),
            "defensiveness": {
                "status": "unknown", "reason": "PROCESSOR_CONTRACT_UNSUPPORTED",
            },
        },
        "navy": {
            "ship_durability": {
                "status": "invisible", "reason": "NATIVE_PERMISSION_DENIED",
            },
        },
    }
    assert field["unit"] == "military_modifier_map"
    assert field["scale"] == 1
    assert field["period"] == "current"
    assert field["complete"] is False and field["partial"] is True
    assert result["complete"] is False
    assert calls["capture"] == [(tmp_path / "installation.json", "FRA")]
    assert len(calls["validate"]) == len(calls["project"]) == 1
    assert calls["validate"][0][2] == CREATION
    assert base.catalog_calls == 0
    provenance = result["source"]["provenance"]
    assert provenance["profile_sha256"] == PROFILE_SHA
    assert len(provenance["capture_report_sha256"]) == 64
    assert provenance["observer"] == "FRA"
    for private in ("capture_fixture", "raw_inputs", "private_pointer", "0x12345678"):
        assert private not in repr(result)
    assert report["capture_fixture"] not in repr(result)


@pytest.mark.parametrize("status", ["unknown", "invisible"])
def test_all_unavailable_components_remain_top_level_unknown_or_invisible(
        tmp_path, monkeypatch, status):
    source, base, _, _ = make_source(
        tmp_path, monkeypatch,
        projection=_projection(status=status, reason="NO_SELECTED_MODIFIER_KNOWN"),
    )

    result = source.read(make_query(), base.context())

    field = result["fields"]["military_modifiers"]
    assert field["status"] == status
    assert field["reason"] == "NO_SELECTED_MODIFIER_KNOWN"
    assert "value" not in field


@pytest.mark.parametrize("query", [
    make_query(country="ENG"),
    make_query(parameters={"include_all": True}),
])
def test_foreign_country_or_nonempty_parameters_are_rejected_without_capture(
        tmp_path, monkeypatch, query):
    source, base, _, calls = make_source(tmp_path, monkeypatch)

    with pytest.raises(InformationError):
        source.read(query, base.context())

    assert calls["capture"] == []


def test_capture_exception_still_rechecks_context_and_retracts_on_date_change(
        tmp_path, monkeypatch):
    def change_date(base):
        base.current["game_date"] += 24

    source, base, _, calls = make_source(
        tmp_path, monkeypatch, after_capture=change_date,
        capture_error=RuntimeError("synthetic capture error"),
    )

    result = source.read(make_query(), base.context())

    field = result["fields"]["military_modifiers"]
    assert field["status"] == "unavailable"
    assert field["reason"] == "OWN_MILITARY_MODIFIERS_CONTEXT_CHANGED_DURING_CAPTURE"
    assert calls["validate"] == calls["project"] == []
    assert base.context_calls >= 3


def test_session_change_during_capture_retracts_values(tmp_path, monkeypatch):
    def change_session(base):
        base.session.creation_filetime += 1
        base.session.record["creation_filetime"] += 1

    source, base, _, calls = make_source(
        tmp_path, monkeypatch, after_capture=change_session,
    )

    result = source.read(make_query(), base.context())

    field = result["fields"]["military_modifiers"]
    assert field["status"] == "unavailable"
    assert field["reason"] == "OWN_MILITARY_MODIFIERS_SESSION_CHANGED_DURING_CAPTURE"
    assert calls["validate"] == calls["project"] == []


@pytest.mark.parametrize("projection", [
    _projection(siege={"status": "known", "value": 0.226, "raw": 225,
                       "unit": "ratio_modifier", "scale": 1000}),
    _projection(siege={"status": "known", "value": 0.225, "raw": True,
                       "unit": "ratio_modifier", "scale": 1000}),
    _projection(siege={"status": "unknown", "reason": "POINTER_0x1234"}),
    _projection(defense={"status": "known", "value": 0.07, "raw": 70,
                         "unit": "ratio_modifier", "scale": 1000,
                         "private_pointer": "0x1234"}),
    _projection(siege={"status": "unknown", "reason": "NO_SIEGE"},
                defense={"status": "unknown", "reason": "NO_DEFENSE"},
                durability={"status": "unsupported", "reason": "SOURCE_NOT_CLOSED"}),
])
def test_malformed_or_empty_known_projection_is_sanitized_to_unknown(
        tmp_path, monkeypatch, projection):
    source, base, _, _ = make_source(tmp_path, monkeypatch, projection=projection)

    result = source.read(make_query(), base.context())

    field = result["fields"]["military_modifiers"]
    assert field["status"] == "unknown"
    assert field["reason"] == "OWN_MILITARY_MODIFIERS_CAPTURE_SHAPE_INVALID"
    assert "value" not in field
    assert "0x1234" not in repr(result)


def test_capture_failure_without_identity_drift_is_specific_unknown(tmp_path, monkeypatch):
    source, base, _, calls = make_source(
        tmp_path, monkeypatch, capture_error=OSError("synthetic read failure"),
    )

    result = source.read(make_query(), base.context())

    field = result["fields"]["military_modifiers"]
    assert field["status"] == "unknown"
    assert field["reason"] == "OWN_MILITARY_MODIFIERS_CAPTURE_FAILED"
    assert calls["validate"] == calls["project"] == []
    assert base.context_calls >= 3


def test_context_observer_mismatch_is_unavailable_without_capture(tmp_path, monkeypatch):
    source, base, _, calls = make_source(tmp_path, monkeypatch)
    invalid_context = base.context()
    invalid_context["observer"] = "ENG"

    with pytest.raises(InformationError):
        source.read(make_query(), invalid_context)
    assert calls["capture"] == []


def test_validator_and_profile_sha_are_required(tmp_path, monkeypatch):
    source, base, _, calls = make_source(tmp_path, monkeypatch, validation=1)
    result = source.read(make_query(), base.context())

    assert result["fields"]["military_modifiers"]["status"] == "unknown"
    assert result["fields"]["military_modifiers"]["reason"] == (
        "OWN_MILITARY_MODIFIERS_CAPTURE_NOT_VALIDATED")
    assert calls["project"] == []

    source, base, _, calls = make_source(
        tmp_path, monkeypatch, profile_sha="not-a-profile-hash",
    )
    result = source.read(make_query(), base.context())
    assert result["fields"]["military_modifiers"]["status"] == "unknown"
    assert result["fields"]["military_modifiers"]["reason"] == (
        "OWN_MILITARY_MODIFIERS_CAPTURE_SHAPE_INVALID")
    assert len(calls["project"]) == 1

