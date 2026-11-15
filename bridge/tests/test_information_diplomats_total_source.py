"""Offline boundary tests for the N05 native diplomats-total source."""
from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from bridge.information import InformationService
from bridge.information import diplomats_total as diplomats_module
from bridge.information import scalar_capture_source as scalar_module
from bridge.information.catalog import InformationError
from bridge.tests import test_information_relations_capacity as capacity_fixture


FIELD = "diplomats_total"
TOPIC = "N05"
PROFILE_SHA = "e" * 64
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
        "unit": "diplomats",
        "scale": 1000,
        "period": "current",
        "partial": True,
        "complete": False,
        "basis": diplomats_module.NativeDiplomatsTotalSource.BASIS,
        "value_origin": diplomats_module.NativeDiplomatsTotalSource.VALUE_ORIGIN,
    }


def make_source(tmp_path, monkeypatch, *, projected=None, validation=True,
                after_capture=None, capture_error=None, profile_sha=PROFILE_SHA):
    base = capacity_fixture.FakeBase(tmp_path, capacity_fixture.make_context())
    report = {
        "capture_fixture": "synthetic-diplomats-total",
        "raw_inputs": {"private_address": PRIVATE_ADDRESS},
    }
    calls = {"capture": [], "validate": [], "project": []}
    projection = deepcopy(projected if projected is not None else {FIELD: _known(2500)})

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
    source = diplomats_module.NativeDiplomatsTotalSource(base, capture=capture)
    return source, base, report, calls


def test_catalog_and_query_are_fra_only_and_select_only_diplomats_total(
        tmp_path, monkeypatch):
    source, base, _, calls = make_source(tmp_path, monkeypatch)
    topic = source.catalog()[0]
    assert topic["topic_id"] == TOPIC
    assert list(topic["fields"]) == [FIELD]
    assert topic["observer_scope"] == ["FRA"]
    assert topic["triggers"] == ["query", "periodic"]

    normalized = source.validate_query(make_query(), base.context())
    assert normalized["fields"] == [FIELD]
    assert normalized["parameters"] == {}
    with pytest.raises(InformationError):
        source.validate_query(make_query(country="ENG"), base.context())
    with pytest.raises(InformationError):
        source.validate_query(make_query(fields=[FIELD, "diplomats_available"]), base.context())
    with pytest.raises(InformationError):
        source.validate_query(make_query(fields=["diplomats_available"]), base.context())
    assert calls["capture"] == []


def test_optional_reference_recipient_is_accepted_without_affecting_total(
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
    field = result["fields"][FIELD]
    assert field["status"] == "known"
    assert field["value"] == field["raw"] == 2500
    assert field["unit"] == "diplomats" and field["scale"] == 1000
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
    field = source.read(make_query(), base.context())["fields"][FIELD]
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
    field = source.read(make_query(), base.context())["fields"][FIELD]
    assert field["status"] == "stale"
    assert field["reason"] == "NATIVE_SCALAR_CONTEXT_CHANGED_DURING_CAPTURE"
    assert base.context_calls >= 3
    assert calls["validate"] == calls["project"] == []


def test_capture_validator_must_return_exact_true(tmp_path, monkeypatch):
    source, base, _, calls = make_source(tmp_path, monkeypatch, validation=1)

    field = source.read(make_query(), base.context())["fields"][FIELD]
    assert field["status"] == "unknown"
    assert field["reason"] == "NATIVE_SCALAR_CAPTURE_NOT_VALIDATED"
    assert len(calls["validate"]) == 1
    assert calls["project"] == []


def test_valid_known_and_unknown_projections_preserve_fixed_point_contract(
        tmp_path, monkeypatch):
    source, base, report, calls = make_source(tmp_path, monkeypatch)
    result = source.read(make_query(), base.context())
    field = result["fields"][FIELD]
    assert field == _known(2500)
    assert field["value"] == field["raw"] == 2500  # keep 2.5 diplomats raw; do not round
    assert field["unit"] == "diplomats" and field["scale"] == 1000
    assert calls["validate"][0][2] == capacity_fixture.CREATION
    assert len(calls["project"]) == 1
    assert len(result["source"]["provenance"]["capture_report_sha256"]) == 64
    assert result["source"]["provenance"]["profile_sha256"] == PROFILE_SHA
    assert report["capture_fixture"] not in repr(result)
    assert PRIVATE_ADDRESS not in repr(result)

    source, base, _, _ = make_source(
        tmp_path, monkeypatch,
        projected={FIELD: {"status": "unknown", "reason": "PROCESSOR_STATE_UNKNOWN"}},
    )
    field = source.read(make_query(), base.context())["fields"][FIELD]
    assert field["status"] == "unknown"
    assert field["reason"] == "PROCESSOR_STATE_UNKNOWN"
    assert "value" not in field
    assert field["unit"] == "diplomats" and field["scale"] == 1000


@pytest.mark.parametrize("mutation", [
    "raw_mismatch", "hex_mismatch", "scale", "bool_value", "bool_raw", "extra_address",
])
def test_malformed_known_projection_is_rejected_without_address_leak(
        tmp_path, monkeypatch, mutation):
    item = _known(2500)
    if mutation == "raw_mismatch":
        item["raw"] = 2501
    elif mutation == "hex_mismatch":
        item["raw_hex"] = "c5090000"
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


def test_query_report_two_periodics_share_projection_and_cancel_stops_future_reads(
        tmp_path, monkeypatch):
    source, base, _, calls = make_source(tmp_path, monkeypatch)
    clock = FakeClock()
    service = InformationService(source, tmp_path / "diplomats-total.sqlite3", clock=clock)
    query = make_query()
    try:
        direct_field = source.read(query, base.context())["fields"][FIELD]
        manual = service.query("diplomats-manual-query", queries=[query])
        assert manual["items"][0]["fields"][FIELD] == direct_field

        report = service.manage_report(
            "diplomats-report-create", "create",
            config={"name": "diplomats total", "queries": [query], "detail": "full"},
        )["report"]
        report_result = service.query("diplomats-report-query", report_id=report["id"])
        assert report_result["items"][0]["fields"][FIELD] == direct_field

        def create_periodic(request_id, name, every):
            return service.manage_subscription(
                request_id, "create",
                config={
                    "name": name,
                    "kind": "periodic",
                    "report_id": report["id"],
                    "schedule": {"basis": "real", "every": every, "unit": "seconds"},
                },
            )["subscription"]

        periodic_two = create_periodic("diplomats-periodic-two", "two seconds", 2)
        periodic_five = create_periodic("diplomats-periodic-five", "five seconds", 5)
        assert service.tick()["results"] == []

        clock.advance(2)
        first_tick = service.tick()["results"]
        assert len(first_tick) == 1
        assert first_tick[0]["subscription_id"] == periodic_two["id"]
        assert first_tick[0]["trigger"] == "periodic"
        assert first_tick[0]["items"][0]["fields"][FIELD] == direct_field

        cancelled_two = service.manage_subscription(
            "diplomats-cancel-two", "cancel", subscription_id=periodic_two["id"],
            expected_version=periodic_two["version"],
        )["subscription"]
        assert cancelled_two["state"] == "cancelled"

        clock.advance(3)
        second_tick = service.tick()["results"]
        assert len(second_tick) == 1
        assert second_tick[0]["subscription_id"] == periodic_five["id"]
        assert second_tick[0]["trigger"] == "periodic"
        assert second_tick[0]["items"][0]["fields"][FIELD] == direct_field

        cancelled_five = service.manage_subscription(
            "diplomats-cancel-five", "cancel", subscription_id=periodic_five["id"],
            expected_version=periodic_five["version"],
        )["subscription"]
        assert cancelled_five["state"] == "cancelled"
        assert len(calls["capture"]) == 5
        clock.advance(5)
        assert service.tick()["results"] == []
        assert len(calls["capture"]) == 5
    finally:
        service.close()

