"""Focused tests for the live G01 permanent-claims adapter."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import province_interests_live as interests_module
from bridge.information import province_permanent_claims as permanent_module
from bridge.information.catalog import list_topics
from bridge.information.composite import CompositeSource
from bridge.information.province_interests_live import NativeProvinceInterestsSource
from bridge.information.province_permanent_claims import NativeProvincePermanentClaimsSource


GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
CREATION = 134380633247930565
PROFILE_SHA = "a" * 64
PROVINCE_ID = 186


def make_context(**overrides):
    context = {
        "status": "ready",
        "mode": "live",
        "complete": True,
        "observer": "FRA",
        "session_id": "province-permanent-claim-test-session",
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
        self.session = SimpleNamespace(
            directory=directory,
            creation_filetime=CREATION,
            record={
                "session_id": context["session_id"],
                "creation_filetime": CREATION,
            },
        )

    def context(self):
        return deepcopy(self.current)

    def catalog(self):
        return list_topics()

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": deepcopy(cursor or {}),
                "complete": True, "gaps": []}


def make_query(*, fields=None, obj=None):
    return {
        "topic": "G01",
        "object": obj or {"type": "province", "province_id": PROVINCE_ID},
        "fields": list(fields if fields is not None else ("permanent_claims",)),
        "parameters": {},
    }


def _projection(tags):
    return {"permanent_claims": {"status": "known", "value": list(tags)}}


def make_source(tmp_path, monkeypatch, *, tags=("BUR", "FRA"),
                validation=True, projection=None, after_capture=None,
                capture_error=None, context=None):
    base = FakeBase(tmp_path, context or make_context())
    report = {"capture_fixture": "permanent-claim"}
    calls = {"capture": [], "validate": [], "project": []}

    def capture(installation, *, province_id, observer):
        calls["capture"].append((installation, province_id, observer))
        if after_capture is not None:
            after_capture(base)
        if capture_error is not None:
            raise capture_error
        return deepcopy(report)

    def validate_capture(report_arg, context_arg, creation, province_id):
        calls["validate"].append((deepcopy(report_arg), deepcopy(context_arg),
                                  creation, province_id))
        return validation

    projected = deepcopy(projection if projection is not None else _projection(tags))

    def project_fields(report_arg):
        calls["project"].append(deepcopy(report_arg))
        return deepcopy(projected)

    module = SimpleNamespace(
        PROFILE_SHA256=PROFILE_SHA,
        validate_capture=validate_capture,
        project_fields=project_fields,
    )
    monkeypatch.setattr(permanent_module, "import_module",
                        lambda _name, _package: module)
    source = NativeProvincePermanentClaimsSource(base, capture=capture)
    return source, base, report, calls


def test_catalog_declares_only_partial_permanent_claims_for_provinces(tmp_path):
    source = NativeProvincePermanentClaimsSource(
        FakeBase(tmp_path, make_context()))
    topic = source.catalog()[0]

    assert topic["topic_id"] == "G01"
    assert set(topic["fields"]) == {"permanent_claims"}
    field = topic["fields"]["permanent_claims"]
    assert field["coverage"] == "partial"
    assert field["complete"] is False
    assert field["unit"] == "country_tag"
    assert field["scale"] == 1
    assert field["period"] == "current"
    assert field["basis"] == (
        "native_permanent_claim_predicate_after_positive_actor_discovery")
    assert field["value_origin"] == (
        "derived_from_copied_native_claim_and_history_records")
    assert field["supported_object_types"] == ["province"]
    assert topic["triggers"] == ["query", "periodic"]


@pytest.mark.parametrize("tags", [("BUR", "FRA"), ()])
def test_known_positive_and_known_empty_are_distinct_and_sanitized(
        tmp_path, monkeypatch, tags):
    source, base, report, calls = make_source(tmp_path, monkeypatch, tags=tags)
    result = source.read(make_query(), base.context())

    field = result["fields"]["permanent_claims"]
    assert field["status"] == "known"
    assert field["value"] == sorted(tags)
    assert field["unit"] == "country_tag"
    assert field["scale"] == 1
    assert field["period"] == "current"
    assert field["complete"] is False
    assert result["complete"] is False
    assert calls["capture"] == [
        (tmp_path / "installation.json", PROVINCE_ID, "FRA")
    ]
    assert len(calls["validate"]) == len(calls["project"]) == 1
    provenance = result["source"]["provenance"]
    assert len(provenance["capture_report_sha256"]) == 64
    assert provenance["profile_sha256"] == PROFILE_SHA
    assert provenance["actual_UI_observed"] is False
    assert provenance["full_province_visibility_complete"] is False
    for private in ("capture_fixture", "raw_inputs", "raw_reads", "private_pointer"):
        assert private not in repr(result)


def test_country_reverse_is_unknown_without_capture(tmp_path, monkeypatch):
    source, base, _, calls = make_source(tmp_path, monkeypatch)
    query = make_query(obj={"type": "country", "country": "FRA"})

    result = source.read(query, base.context())

    field = result["fields"]["permanent_claims"]
    assert field["status"] == "unknown"
    assert field["reason"] == "COUNTRY_REVERSE_ENUMERATION_NOT_IMPLEMENTED"
    assert calls == {"capture": [], "validate": [], "project": []}


def test_bad_context_is_unavailable_without_capture(tmp_path, monkeypatch):
    source, base, _, calls = make_source(tmp_path, monkeypatch)
    bad_context = base.context()
    bad_context["observer"] = "ENG"

    result = source.read(make_query(), bad_context)

    assert result["fields"]["permanent_claims"]["status"] == "unavailable"
    assert calls == {"capture": [], "validate": [], "project": []}


def test_capture_exception_still_rechecks_context_and_retracts_on_drift(
        tmp_path, monkeypatch):
    def mutate(base):
        base.current["game_date"] += 24

    source, base, _, calls = make_source(
        tmp_path, monkeypatch, after_capture=mutate,
        capture_error=RuntimeError("synthetic capture failure"))

    result = source.read(make_query(), base.context())

    field = result["fields"]["permanent_claims"]
    assert field["status"] == "unavailable"
    assert field["reason"] == (
        "PROVINCE_PERMANENT_CLAIMS_CONTEXT_CHANGED_DURING_CAPTURE")
    assert len(calls["capture"]) == 1
    assert calls["validate"] == calls["project"] == []


def test_session_change_during_capture_retracts_values(tmp_path, monkeypatch):
    def mutate(base):
        base.session.creation_filetime += 1
        base.session.record["creation_filetime"] += 1

    source, base, _, calls = make_source(
        tmp_path, monkeypatch, after_capture=mutate)

    result = source.read(make_query(), base.context())

    field = result["fields"]["permanent_claims"]
    assert field["status"] == "unavailable"
    assert field["reason"] == (
        "PROVINCE_PERMANENT_CLAIMS_SESSION_CHANGED_DURING_CAPTURE")
    assert len(calls["capture"]) == 1
    assert calls["validate"] == calls["project"] == []


def test_validator_must_return_literal_true(tmp_path, monkeypatch):
    source, base, _, calls = make_source(tmp_path, monkeypatch, validation=1)

    result = source.read(make_query(), base.context())

    field = result["fields"]["permanent_claims"]
    assert field["status"] == "unknown"
    assert field["reason"] == "PROVINCE_PERMANENT_CLAIMS_CAPTURE_NOT_VALIDATED"
    assert len(calls["validate"]) == 1
    assert calls["project"] == []


@pytest.mark.parametrize("projection", [
    None,
    {"wrong_field": {"status": "known", "value": ["FRA"]}},
    {"permanent_claims": {"status": "known", "value": ["0x123456"]}},
    {"permanent_claims": {"status": "unknown", "reason": "PTR_0x1234"}},
])
def test_bad_projection_shape_is_unknown_and_never_leaks_raw_values(
        tmp_path, monkeypatch, projection):
    if projection is None:
        projection = []
    source, base, _, calls = make_source(
        tmp_path, monkeypatch, projection=projection)

    result = source.read(make_query(), base.context())

    field = result["fields"]["permanent_claims"]
    assert field["status"] == "unknown"
    assert field["reason"] == "PROVINCE_PERMANENT_CLAIMS_CAPTURE_SHAPE_INVALID"
    assert len(calls["validate"]) == len(calls["project"]) == 1
    assert "0x123456" not in repr(result)
    assert "PTR_0x1234" not in repr(result)


def test_composite_routes_cores_claims_and_permanent_claims_to_separate_owners(
        tmp_path, monkeypatch):
    base = FakeBase(tmp_path, make_context())
    old_calls = []

    old_report = {"old_fixture": True}
    old_module = SimpleNamespace(
        PROFILE_SHA256="b" * 64,
        validate_capture=lambda *_args: True,
        project_fields=lambda _report: {
            "cores": {"status": "known", "value": ["FRA"]},
            "claims": {"status": "known", "value": ["BUR"]},
        },
    )
    monkeypatch.setattr(interests_module, "import_module",
                        lambda _name, _package: old_module)
    old = NativeProvinceInterestsSource(
        base,
        capture=lambda installation, *, province_id, observer: (
            old_calls.append((installation, province_id, observer)) or deepcopy(old_report)
        ),
    )

    new_source, _, _, new_test_calls = make_source(tmp_path, monkeypatch, tags=("SAV",))
    composite = CompositeSource(base, [old, new_source])
    common = {"type": "province", "province_id": PROVINCE_ID}

    cores = composite.read(make_query(fields=["cores"], obj=common), base.context())
    claims = composite.read(make_query(fields=["claims"], obj=common), base.context())
    permanent = composite.read(
        make_query(fields=["permanent_claims"], obj=common), base.context())

    assert cores["fields"]["cores"]["value"] == ["FRA"]
    assert claims["fields"]["claims"]["value"] == ["BUR"]
    assert permanent["fields"]["permanent_claims"]["value"] == ["SAV"]
    assert old_calls == [(tmp_path / "installation.json", PROVINCE_ID, "FRA")] * 2
    assert len(new_test_calls["capture"]) == 1

