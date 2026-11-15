"""Offline tests for the bounded N05 relations capacity source."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information.catalog import InformationError
from bridge.information import relations_capacity as relations_module
from bridge.information.relations_capacity import NativeRelationsCapacitySource


GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
CREATION = 134380633247930565
PROFILE_SHA = "c" * 64


def make_context(**overrides):
    context = {
        "status": "ready",
        "mode": "live",
        "complete": True,
        "observer": "FRA",
        "session_id": "relations-capacity-test-session",
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
        raise AssertionError("the adapter must not read the base catalog")

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": deepcopy(cursor or {}),
                "complete": True, "gaps": []}


def make_query(*, country="FRA", fields=None, parameters=None):
    return {
        "topic": "N05",
        "object": {"type": "country", "country": country},
        "fields": list(fields if fields is not None else ("relations_count",)),
        "parameters": deepcopy(parameters if parameters is not None else {}),
    }


def _known(value):
    return {
        "status": "known",
        "value": value,
        "raw": value,
        "raw_hex": (value & 0xffffffff).to_bytes(4, "little").hex(),
        "unit": "diplomatic_relation",
        "scale": 1,
        "period": "current",
        "partial": True,
        "complete": False,
        "basis": "native_diplomatic_relation_trigger_arithmetic",
        "value_origin": "derived_from_copied_native_modifier_and_relation_caches",
    }


def make_source(tmp_path, monkeypatch, *, projected=None, validation=True,
                after_capture=None, capture_error=None, profile_sha=PROFILE_SHA):
    base = FakeBase(tmp_path, make_context())
    report = {
        "capture_fixture": "synthetic-relations-capacity",
        "raw_inputs": {"private_pointer": "0x12345678"},
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

    result = deepcopy(projected if projected is not None else {
        "relations_count": _known(3),
        "relations_limit": {
            "status": "unknown",
            "reason": "RELATION_LIMIT_PROCESSOR_NOT_SUPPORTED",
        },
    })

    def project_fields(report_arg):
        calls["project"].append(deepcopy(report_arg))
        return deepcopy(result)

    module = SimpleNamespace(
        PROFILE_SHA256=profile_sha,
        validate_capture=validate_capture,
        project_fields=project_fields,
    )
    monkeypatch.setattr(
        relations_module, "import_module", lambda _name, _package: module,
    )
    source = NativeRelationsCapacitySource(base, capture=capture)
    return source, base, report, calls


def test_catalog_declares_only_two_partial_relation_fields(tmp_path):
    source = NativeRelationsCapacitySource(FakeBase(tmp_path, make_context()))
    topic = source.catalog()[0]

    assert topic["topic_id"] == "N05"
    assert set(topic["fields"]) == {"relations_count", "relations_limit"}
    for field in topic["fields"].values():
        assert field["coverage"] == "partial"
        assert field["complete"] is False
        assert field["unit"] == "diplomatic_relation"
        assert field["scale"] == 1
        assert field["period"] == "current"
        assert field["supported_countries"] == ["FRA"]
        assert field["supported_object_types"] == ["country"]
    assert topic["triggers"] == ["query", "periodic"]
    assert topic["parameters"]["additionalProperties"] is False


def test_single_selected_field_uses_known_count_and_preserves_limit_reason(
        tmp_path, monkeypatch):
    source, base, report, calls = make_source(tmp_path, monkeypatch)

    result = source.read(make_query(fields=["relations_count"]), base.context())

    field = result["fields"]["relations_count"]
    assert list(result["fields"]) == ["relations_count"]
    assert field["status"] == "known"
    assert field["value"] == field["raw"] == 3
    assert field["raw_hex"] == "03000000"
    assert field["unit"] == "diplomatic_relation"
    assert field["scale"] == 1
    assert field["period"] == "current"
    assert field["complete"] is False and field["partial"] is True
    assert calls["capture"] == [(tmp_path / "installation.json", "FRA")]
    assert len(calls["validate"]) == len(calls["project"]) == 1
    assert calls["validate"][0][2] == CREATION
    assert base.catalog_calls == 0
    provenance = result["source"]["provenance"]
    assert provenance["profile_sha256"] == PROFILE_SHA
    assert len(provenance["capture_report_sha256"]) == 64
    assert report["capture_fixture"] not in repr(result)
    assert "raw_inputs" not in repr(result) and "0x12345678" not in repr(result)


def test_two_selected_fields_return_only_requested_whitelisted_values(
        tmp_path, monkeypatch):
    projection = {
        "relations_count": _known(5),
        "relations_limit": _known(-2),
    }
    source, base, _, _ = make_source(tmp_path, monkeypatch, projected=projection)

    result = source.read(
        make_query(fields=["relations_limit", "relations_count"]), base.context(),
    )

    assert list(result["fields"]) == ["relations_limit", "relations_count"]
    assert result["fields"]["relations_limit"]["value"] == -2
    assert result["fields"]["relations_limit"]["raw_hex"] == "feffffff"
    assert result["fields"]["relations_count"]["value"] == 5


@pytest.mark.parametrize(("status", "reason"), [
    ("unknown", "RELATIONS_LIMIT_PROCESSOR_NOT_SUPPORTED"),
    ("invisible", "RELATIONS_LIMIT_NOT_VISIBLE"),
])
def test_unknown_and_invisible_reasons_need_no_known_value_metadata(
        tmp_path, monkeypatch, status, reason):
    projection = {
        "relations_count": {"status": status, "reason": reason},
        "relations_limit": {"status": "unknown", "reason": "LIMIT_SOURCE_UNKNOWN"},
    }
    source, base, _, _ = make_source(tmp_path, monkeypatch, projected=projection)

    result = source.read(make_query(fields=["relations_count"]), base.context())

    field = result["fields"]["relations_count"]
    assert field["status"] == status
    assert field["reason"] == reason
    assert "value" not in field
    assert field["unit"] == "diplomatic_relation"


@pytest.mark.parametrize("query", [
    make_query(country="ENG"),
    make_query(parameters={"include_foreign": True}),
])
def test_foreign_country_and_nonempty_parameters_are_rejected(
        tmp_path, monkeypatch, query):
    source, base, _, calls = make_source(tmp_path, monkeypatch)

    with pytest.raises(InformationError):
        source.read(query, base.context())

    assert calls["capture"] == []


def test_capture_exception_still_checks_context_drift(tmp_path, monkeypatch):
    def change_date(base):
        base.current["game_date"] += 24

    source, base, _, calls = make_source(
        tmp_path, monkeypatch, after_capture=change_date,
        capture_error=RuntimeError("synthetic failure"),
    )

    result = source.read(make_query(), base.context())

    field = result["fields"]["relations_count"]
    assert field["status"] == "unavailable"
    assert field["reason"] == "RELATIONS_CAPACITY_CONTEXT_CHANGED_DURING_CAPTURE"
    assert calls["validate"] == calls["project"] == []
    assert base.context_calls >= 3


def test_session_drift_after_capture_retracts_values(tmp_path, monkeypatch):
    def change_session(base):
        base.session.creation_filetime += 1
        base.session.record["creation_filetime"] += 1

    source, base, _, calls = make_source(tmp_path, monkeypatch, after_capture=change_session)

    result = source.read(make_query(fields=["relations_limit"]), base.context())

    field = result["fields"]["relations_limit"]
    assert field["status"] == "unavailable"
    assert field["reason"] == "RELATIONS_CAPACITY_SESSION_CHANGED_DURING_CAPTURE"
    assert calls["validate"] == calls["project"] == []


def test_capture_failure_without_drift_has_a_specific_unknown_reason(tmp_path, monkeypatch):
    source, base, _, calls = make_source(
        tmp_path, monkeypatch, capture_error=OSError("synthetic read failure"),
    )

    result = source.read(make_query(), base.context())

    assert result["fields"]["relations_count"]["status"] == "unknown"
    assert result["fields"]["relations_count"]["reason"] == (
        "RELATIONS_CAPACITY_CAPTURE_FAILED")
    assert calls["validate"] == calls["project"] == []
    assert base.context_calls >= 3


@pytest.mark.parametrize("bad_field", [
    {**_known(3), "raw_hex": "0300000A"},
    {**_known(3), "raw_hex": "03ff"},
    {**_known(3), "raw": True, "value": True, "raw_hex": "01000000"},
    {**_known(3), "scale": True},
    {**_known(3), "value": 4},
    {**_known(3), "private_pointer": "0x12345678"},
])
def test_invalid_known_encoding_and_types_are_unknown_without_leaks(
        tmp_path, monkeypatch, bad_field):
    source, base, _, _ = make_source(
        tmp_path, monkeypatch,
        projected={
            "relations_count": bad_field,
            "relations_limit": {"status": "unknown", "reason": "LIMIT_UNKNOWN"},
        },
    )

    result = source.read(make_query(), base.context())

    field = result["fields"]["relations_count"]
    assert field["status"] == "unknown"
    assert field["reason"] == "RELATIONS_CAPACITY_CAPTURE_SHAPE_INVALID"
    assert "value" not in field
    assert "0x12345678" not in repr(result)


def test_nonrequested_malformed_field_is_not_published(tmp_path, monkeypatch):
    source, base, _, _ = make_source(
        tmp_path, monkeypatch,
        projected={
            "relations_count": _known(7),
            "relations_limit": {"status": "known", "value": True},
        },
    )

    result = source.read(make_query(fields=["relations_count"]), base.context())

    assert list(result["fields"]) == ["relations_count"]
    assert result["fields"]["relations_count"]["status"] == "known"
    assert result["fields"]["relations_count"]["value"] == 7


def test_validator_and_profile_sha_are_required(tmp_path, monkeypatch):
    source, base, _, calls = make_source(tmp_path, monkeypatch, validation=1)
    result = source.read(make_query(), base.context())
    assert result["fields"]["relations_count"]["status"] == "unknown"
    assert result["fields"]["relations_count"]["reason"] == (
        "RELATIONS_CAPACITY_CAPTURE_NOT_VALIDATED")
    assert calls["project"] == []

    source, base, _, calls = make_source(
        tmp_path, monkeypatch, profile_sha="invalid-profile-sha",
    )
    result = source.read(make_query(), base.context())
    assert result["fields"]["relations_count"]["status"] == "unknown"
    assert result["fields"]["relations_count"]["reason"] == (
        "RELATIONS_CAPACITY_CAPTURE_SHAPE_INVALID")
    assert len(calls["project"]) == 1


def test_shared_reference_selector_is_preserved_without_changing_capacity(tmp_path, monkeypatch):
    source, base, _, calls = make_source(tmp_path, monkeypatch)
    query = make_query(parameters={"reference_recipient": "PAP"})
    assert source.validate_query(query)["parameters"] == {"reference_recipient": "PAP"}
    result = source.read(query, base.context())
    assert result["fields"]["relations_count"]["value"] == 3
    assert len(calls["capture"]) == 1


@pytest.mark.parametrize("recipient", ["FRA", "france", 1, True])
def test_invalid_shared_reference_is_rejected_before_capture(tmp_path, monkeypatch, recipient):
    source, _, _, calls = make_source(tmp_path, monkeypatch)
    with pytest.raises(InformationError):
        source.validate_query(make_query(parameters={"reference_recipient": recipient}))
    assert not calls["capture"]

