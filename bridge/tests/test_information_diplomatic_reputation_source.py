"""Offline boundary tests for the N06 diplomatic-reputation source."""
from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from bridge.information import InformationService
from bridge.information import diplomatic_reputation as reputation_module
from bridge.information import scalar_capture_source as scalar_module
from bridge.information.catalog import InformationError
from bridge.tests import test_information_relations_capacity as capacity_fixture


FIELD = "diplomatic_reputation"
TOPIC = "N06"
PROFILE_SHA = "d" * 64
PRIVATE_ADDRESS = "0xdeadbeef"


def make_query(*, country="FRA", fields=None, parameters=None):
    return {
        "topic": TOPIC,
        "object": {"type": "country", "country": country},
        "fields": list(fields if fields is not None else (FIELD,)),
        "parameters": deepcopy(parameters if parameters is not None else {}),
    }


def _known(value: int) -> dict:
    return {
        "status": "known",
        "value": value,
        "raw": value,
        "raw_hex": value.to_bytes(4, "little", signed=True).hex(),
        "unit": "diplomatic_reputation",
        "scale": 1000,
        "period": "current",
        "partial": True,
        "complete": False,
        "basis": reputation_module.NativeDiplomaticReputationSource.BASIS,
        "value_origin": reputation_module.NativeDiplomaticReputationSource.VALUE_ORIGIN,
    }


def make_source(tmp_path, monkeypatch, *, projected=None, validation=True,
                after_capture=None, capture_error=None, profile_sha=PROFILE_SHA):
    base = capacity_fixture.FakeBase(tmp_path, capacity_fixture.make_context())
    report = {
        "capture_fixture": "synthetic-diplomatic-reputation",
        "raw_inputs": {"private_address": PRIVATE_ADDRESS},
    }
    calls = {"capture": [], "validate": [], "project": []}
    projection = deepcopy(projected if projected is not None else {FIELD: _known(-1250)})

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

    def project_fields(report_arg):
        calls["project"].append(deepcopy(report_arg))
        return deepcopy(projection)

    module = SimpleNamespace(
        PROFILE_SHA256=profile_sha,
        validate_capture=validate_capture,
        project_fields=project_fields,
    )
    monkeypatch.setattr(scalar_module, "import_module", lambda _name: module)
    source = reputation_module.NativeDiplomaticReputationSource(base, capture=capture)
    return source, base, report, calls


def test_catalog_and_query_are_fra_only_and_select_only_the_new_field(tmp_path, monkeypatch):
    source, base, _, calls = make_source(tmp_path, monkeypatch)
    topic = source.catalog()[0]
    assert topic["topic_id"] == TOPIC
    assert list(topic["fields"]) == [FIELD]
    assert topic["observer_scope"] == ["FRA"]
    assert topic["triggers"] == ["query", "periodic"]

    query = make_query()
    normalized = source.validate_query(query, base.context())
    assert normalized["fields"] == [FIELD]
    assert normalized["parameters"] == {}
    with pytest.raises(InformationError):
        source.validate_query(make_query(country="ENG"), base.context())
    with pytest.raises(InformationError):
        source.validate_query(make_query(fields=[FIELD, "relations_count"]), base.context())
    with pytest.raises(InformationError):
        source.validate_query(make_query(fields=["relations_count"]), base.context())
    assert calls["capture"] == []


def test_optional_reference_recipient_is_accepted_but_fra_reference_is_rejected(
        tmp_path, monkeypatch):
    source, base, _, calls = make_source(tmp_path, monkeypatch)

    omitted = make_query()
    omitted.pop("parameters")
    assert source.validate_query(omitted)["parameters"] == {}

    reference = make_query(parameters={"reference_recipient": "PAP"})
    assert source.validate_query(reference)["parameters"] == {
        "reference_recipient": "PAP",
    }
    result = source.read(reference, base.context())
    assert result["fields"][FIELD]["status"] == "known"
    assert calls["capture"] == [(base.session.directory / "installation.json", "FRA")]

    with pytest.raises(InformationError):
        source.validate_query(make_query(parameters={"reference_recipient": "FRA"}))
    assert len(calls["capture"]) == 1


def test_stale_context_is_rejected_before_capture(tmp_path, monkeypatch):
    source, base, _, calls = make_source(tmp_path, monkeypatch)
    stale = base.context()
    base.current["game_date"] += 24

    result = source.read(make_query(), stale)

    field = result["fields"][FIELD]
    assert field["status"] == "stale"
    assert field["reason"] == "NATIVE_SCALAR_CONTEXT_STALE"
    assert calls["capture"] == []


def test_capture_exception_still_rechecks_context_and_session(tmp_path, monkeypatch):
    def change_date(base):
        base.current["game_date"] += 24

    source, base, _, calls = make_source(
        tmp_path, monkeypatch, after_capture=change_date,
        capture_error=RuntimeError("synthetic capture failure"),
    )
    result = source.read(make_query(), base.context())
    field = result["fields"][FIELD]
    assert field["status"] == "stale"
    assert field["reason"] == "NATIVE_SCALAR_CONTEXT_CHANGED_DURING_CAPTURE"
    assert base.context_calls >= 3
    assert calls["validate"] == calls["project"] == []

    def change_session(base):
        base.session.creation_filetime += 1
        base.session.record["creation_filetime"] += 1

    source, base, _, calls = make_source(
        tmp_path, monkeypatch, after_capture=change_session,
        capture_error=RuntimeError("synthetic capture failure"),
    )
    result = source.read(make_query(), base.context())
    field = result["fields"][FIELD]
    assert field["status"] == "stale"
    assert field["reason"] == "NATIVE_SCALAR_CONTEXT_CHANGED_DURING_CAPTURE"
    assert base.context_calls >= 3
    assert calls["validate"] == calls["project"] == []


def test_capture_failure_without_drift_has_unknown_reason_after_guard_checks(
        tmp_path, monkeypatch):
    source, base, _, calls = make_source(
        tmp_path, monkeypatch, capture_error=OSError("synthetic capture failure"),
    )
    result = source.read(make_query(), base.context())
    field = result["fields"][FIELD]
    assert field["status"] == "unknown"
    assert field["reason"] == "NATIVE_SCALAR_CAPTURE_FAILED"
    assert base.context_calls >= 3
    assert calls["validate"] == calls["project"] == []


def test_capture_validator_must_return_exact_true(tmp_path, monkeypatch):
    source, base, _, calls = make_source(tmp_path, monkeypatch, validation=1)

    result = source.read(make_query(), base.context())

    field = result["fields"][FIELD]
    assert field["status"] == "unknown"
    assert field["reason"] == "NATIVE_SCALAR_CAPTURE_NOT_VALIDATED"
    assert len(calls["validate"]) == 1
    assert calls["project"] == []


def test_valid_known_projection_and_unknown_reason_are_preserved(tmp_path, monkeypatch):
    source, base, report, calls = make_source(tmp_path, monkeypatch)
    result = source.read(make_query(), base.context())
    field = result["fields"][FIELD]

    assert field == _known(-1250)
    assert calls["validate"][0][2] == capacity_fixture.CREATION
    assert len(calls["project"]) == 1
    assert len(result["source"]["provenance"]["capture_report_sha256"]) == 64
    assert result["source"]["provenance"]["profile_sha256"] == PROFILE_SHA
    assert report["capture_fixture"] not in repr(result)
    assert PRIVATE_ADDRESS not in repr(result)

    source, base, _, _ = make_source(
        tmp_path, monkeypatch,
        projected={FIELD: {"status": "unknown", "reason": "CACHE_INPUT_UNKNOWN"}},
    )
    result = source.read(make_query(), base.context())
    field = result["fields"][FIELD]
    assert field["status"] == "unknown"
    assert field["reason"] == "CACHE_INPUT_UNKNOWN"
    assert "value" not in field
    assert field["unit"] == "diplomatic_reputation"
    assert field["scale"] == 1000


@pytest.mark.parametrize("mutation", [
    "raw_mismatch", "hex_mismatch", "scale", "bool_value", "bool_raw", "extra_address",
])
def test_malformed_known_projection_is_rejected_without_address_leak(
        tmp_path, monkeypatch, mutation):
    item = _known(1250)
    if mutation == "raw_mismatch":
        item["raw"] = 1251
    elif mutation == "hex_mismatch":
        item["raw_hex"] = "e3040000"
    elif mutation == "scale":
        item["scale"] = True
    elif mutation == "bool_value":
        item["value"] = True
    elif mutation == "bool_raw":
        item["raw"] = True
    elif mutation == "extra_address":
        item["address"] = PRIVATE_ADDRESS

    source, base, _, _ = make_source(tmp_path, monkeypatch, projected={FIELD: item})
    result = source.read(make_query(), base.context())

    field = result["fields"][FIELD]
    assert field["status"] == "unknown"
    assert field["reason"] == "NATIVE_SCALAR_CAPTURE_SHAPE_INVALID"
    assert "value" not in field
    assert PRIVATE_ADDRESS not in repr(result)


class FakeClock:
    def __init__(self, now=1000.0):
        self.now = float(now)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += float(seconds)


def test_query_report_periodic_share_projection_and_cancel_stops_future_reads(
        tmp_path, monkeypatch):
    source, base, _, calls = make_source(tmp_path, monkeypatch)
    clock = FakeClock()
    service = InformationService(source, tmp_path / "diplomatic-reputation.sqlite3",
                                  clock=clock)
    query = make_query()
    try:
        direct_field = source.read(query, base.context())["fields"][FIELD]

        manual = service.query("reputation-manual-query", queries=[query])
        assert manual["items"][0]["fields"][FIELD] == direct_field

        report = service.manage_report(
            "reputation-report-create", "create",
            config={"name": "reputation", "queries": [query], "detail": "full"},
        )["report"]
        report_result = service.query("reputation-report-query", report_id=report["id"])
        assert report_result["items"][0]["fields"][FIELD] == direct_field

        subscription = service.manage_subscription(
            "reputation-periodic-create", "create",
            config={
                "name": "reputation periodic",
                "kind": "periodic",
                "report_id": report["id"],
                "schedule": {"basis": "real", "every": 5, "unit": "seconds"},
            },
        )["subscription"]
        assert service.tick()["results"] == []
        clock.advance(5)
        periodic = service.tick()["results"]
        assert len(periodic) == 1
        assert periodic[0]["trigger"] == "periodic"
        assert periodic[0]["items"][0]["fields"][FIELD] == direct_field
        assert len(calls["capture"]) == 4

        cancelled = service.manage_subscription(
            "reputation-periodic-cancel", "cancel",
            subscription_id=subscription["id"],
            expected_version=subscription["version"],
        )["subscription"]
        assert cancelled["state"] == "cancelled"
        clock.advance(5)
        assert service.tick()["results"] == []
        assert len(calls["capture"]) == 4
    finally:
        service.close()

