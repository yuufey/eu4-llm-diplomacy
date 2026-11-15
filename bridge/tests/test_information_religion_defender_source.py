"""Offline projection and service-routing tests for S02.defender."""
from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.model import InformationError
from bridge.information.religion_defender import (
    BASIS,
    FIELD,
    NativeReligionDefenderSource,
)
from bridge.information.religion_information import NativeReligionInformationSource
from bridge.information.tools import InformationTools
from bridge.tests import test_information_capture_runtime as runtime_fixture
from bridge.tests import test_information_country_faith as faith_fixture
from bridge.tests import test_information_religion_information as religion_fixture
import bridge.information.religion_defender as defender_module


PROFILE_SHA256 = "e" * 64
CAPTURE_SHA256_LENGTH = 64
PRIVATE_POINTER = "0x123456789abcdef0"
KNOWN_TIER = {
    "status": "known",
    "level": 3,
    "same_faith_country_count": 17,
    "range_from": 0,
    "range_to_exclusive": None,
}


def _defender_report(target="ENG", *, holder="FRA", is_member=None,
                     field_status="known", field_complete=False,
                     field_basis=BASIS, pass2_status="known", admitted=True,
                     item_target=None, reason="SAFE_FIXTURE_REASON", tier=None):
    if is_member is None:
        is_member = holder == target
    field = {
        "status": field_status,
        "complete": field_complete,
        "basis": field_basis,
        "value": {
            "defender_country": holder,
            "is_target_defender": is_member,
            "tier": deepcopy(KNOWN_TIER if tier is None else tier),
        },
        "raw_inputs": {"country_pointer": PRIVATE_POINTER},
    }
    if field_status in ("unknown", "invisible"):
        field["reason"] = reason
    return {
        "schema": "information.religion_defender_capture.v1",
        "status": "observed",
        "completed": True,
        "observation": {
            "backend": {
                "observer": {"tag": "FRA", "private_pointer": "0x2233445566778899"},
                "targets": [{
                    "tag": item_target if item_target is not None else target,
                    "fullref": PRIVATE_POINTER,
                    "admission_by_pass": {
                        "pass1": {"status": "known", "admitted": admitted},
                        "pass2": {"status": pass2_status, "admitted": admitted},
                    },
                    "fields": {"S02.defender": field},
                }],
            },
        },
        "raw_reads": [{"label": "private.trace", "address": PRIVATE_POINTER}],
    }


def _defender_query(target="ENG", fields=None, parameters=None):
    return faith_fixture.make_query(
        target,
        fields=fields if fields is not None else [FIELD],
        parameters=parameters if parameters is not None else {},
    )


def _make_defender_source(base, monkeypatch, *, target="ENG", report=None,
                          valid=True, capture_error=None, after_capture=None):
    report = deepcopy(report if report is not None else _defender_report(target))
    calls = []
    validations = []

    def capture(installation, *, country, observer):
        calls.append((installation, country, observer))
        if after_capture is not None:
            after_capture(base)
        if capture_error is not None:
            raise capture_error
        return deepcopy(report)

    def validate_capture(actual_report, actual_context, creation, actual_target):
        validations.append((deepcopy(actual_report), deepcopy(actual_context), creation, actual_target))
        return valid

    validator_module = SimpleNamespace(
        validate_capture=validate_capture,
        PROFILE_SHA256=PROFILE_SHA256,
    )
    monkeypatch.setattr(
        defender_module,
        "import_module",
        lambda _name, _package: validator_module,
    )
    source = NativeReligionDefenderSource(base, capture=capture)
    return source, report, calls, validations


def _make_source(tmp_path, monkeypatch, *, target="ENG", **kwargs):
    base = faith_fixture.Base(tmp_path, faith_fixture.make_context())
    source, report, calls, validations = _make_defender_source(
        base, monkeypatch, target=target, **kwargs,
    )
    return source, base, report, calls, validations


@pytest.mark.parametrize(("target", "holder", "member"), [
    ("FRA", "FRA", True),
    ("ENG", "FRA", False),
])
def test_known_defender_projects_exact_public_value_and_catalog_metadata(
        tmp_path, monkeypatch, target, holder, member):
    source, base, report, calls, validations = _make_source(
        tmp_path / target,
        monkeypatch,
        target=target,
        report=_defender_report(target, holder=holder, is_member=member),
    )

    topic = source.catalog()[0]
    spec = topic["fields"][FIELD]
    assert topic["topic_id"] == "S02"
    assert spec["coverage"] == "partial"
    assert spec["complete"] is False
    assert spec["unit"] == "country_and_membership"
    assert spec["scale"] == 1
    assert spec["period"] == "current"
    assert spec["basis"] == BASIS == "bounded_native_religion_defender_country_reference"
    assert spec["triggers"] == ["query", "periodic"]
    assert topic["context_scope"] == topic["visibility"] == "visible_scope"
    assert topic["observer_scope"] == ["FRA"]
    assert source.event_types == ()

    result = source.read(_defender_query(target), base.context())
    field = result["fields"][FIELD]
    assert field == {
        "status": "known",
        "period": "current",
        "unit": "country_and_membership",
        "scale": 1,
        "partial": True,
        "complete": False,
        "basis": BASIS,
        "value_origin": "copied_native_religion_state_and_verified_country_reference",
        "value": {"defender_country": holder, "is_target_defender": member,
                  "tier": KNOWN_TIER},
    }
    assert set(field["value"]) == {"defender_country", "is_target_defender", "tier"}
    assert result["complete"] is False
    assert result["source"]["context_scope"] == "visible_scope"
    assert result["source"]["provenance"]["observer"] == "FRA"
    assert result["source"]["provenance"]["target"] == target
    assert len(result["source"]["provenance"]["capture_report_sha256"]) == CAPTURE_SHA256_LENGTH
    assert result["source"]["provenance"]["profile_sha256"] == PROFILE_SHA256
    assert PRIVATE_POINTER not in repr(result)
    assert calls == [(base.session.directory / "installation.json", target, "FRA")]
    assert len(validations) == 1
    assert validations[0][1]["observer"] == "FRA"
    assert validations[0][2] == faith_fixture.CREATION
    assert validations[0][3] == target


@pytest.mark.parametrize(("report", "expected_status", "expected_reason"), [
    (_defender_report("ENG", field_status="unknown"), "unknown", "SAFE_FIXTURE_REASON"),
    (_defender_report("ENG", field_status="invisible"), "invisible", "SAFE_FIXTURE_REASON"),
    (_defender_report("ENG", pass2_status="unknown"), "unknown",
     "RELIGION_DEFENDER_VIEW_ADMISSION_UNKNOWN"),
    (_defender_report("ENG", admitted=False), "invisible", "RELIGION_DEFENDER_NOT_ADMITTED"),
])
def test_unknown_invisible_and_admission_gates_never_publish_value(
        tmp_path, monkeypatch, report, expected_status, expected_reason):
    source, base, _, _, _ = _make_source(tmp_path, monkeypatch, report=report)

    result = source.read(_defender_query("ENG"), base.context())
    field = result["fields"][FIELD]
    assert field["status"] == expected_status
    assert field["reason"] == expected_reason
    assert "value" not in field
    assert PRIVATE_POINTER not in repr(result)


@pytest.mark.parametrize("mutation", [
    "extra_value_key",
    "pointer_like_tag",
    "non_bool_membership",
    "membership_mismatch",
    "wrong_target_tag",
    "bad_basis",
    "complete_true",
    "validator_false",
])
def test_bad_public_values_target_and_backend_contract_fail_closed(
        tmp_path, monkeypatch, mutation):
    report = _defender_report("ENG")
    valid = True
    item = report["observation"]["backend"]["targets"][0]
    field = item["fields"]["S02.defender"]
    if mutation == "extra_value_key":
        field["value"]["pointer"] = PRIVATE_POINTER
    elif mutation == "pointer_like_tag":
        field["value"]["defender_country"] = PRIVATE_POINTER
    elif mutation == "non_bool_membership":
        field["value"]["is_target_defender"] = 0
    elif mutation == "membership_mismatch":
        field["value"]["defender_country"] = "FRA"
        field["value"]["is_target_defender"] = True
    elif mutation == "wrong_target_tag":
        item["tag"] = "POR"
    elif mutation == "bad_basis":
        field["basis"] = "another_basis"
    elif mutation == "complete_true":
        field["complete"] = True
    elif mutation == "validator_false":
        valid = False
    source, base, _, _, _ = _make_source(
        tmp_path / mutation, monkeypatch, report=report, valid=valid,
    )

    result = source.read(_defender_query("ENG"), base.context())
    field_result = result["fields"][FIELD]
    assert field_result["status"] == "unknown"
    assert field_result["reason"] == "RELIGION_DEFENDER_CAPTURE_INVALID"
    assert "value" not in field_result
    assert PRIVATE_POINTER not in repr(result)


@pytest.mark.parametrize(("change", "expected_reason"), [
    ("date", "RELIGION_DEFENDER_CONTEXT_CHANGED_DURING_CAPTURE"),
    ("session", "RELIGION_DEFENDER_SESSION_CHANGED_DURING_CAPTURE"),
])
def test_capture_exception_after_context_or_session_drift_retracts_result(
        tmp_path, monkeypatch, change, expected_reason):
    def drift(base):
        if change == "date":
            base.current["game_date"] += 1
        else:
            base.session.creation_filetime += 1
            base.session.record["creation_filetime"] += 1

    source, base, _, calls, _ = _make_source(
        tmp_path / change,
        monkeypatch,
        capture_error=RuntimeError("fixture capture failed"),
        after_capture=drift,
    )

    result = source.read(_defender_query("ENG"), base.context())
    field = result["fields"][FIELD]
    assert field["status"] == "unavailable"
    assert field["reason"] == expected_reason
    assert "value" not in field
    assert len(calls) == 1


@pytest.mark.parametrize("query", [
    {"topic": "S02", "object": {"type": "country", "country": "bad"},
     "fields": [FIELD]},
    {"topic": "S02", "object": {"type": "country", "country": "ENG", "pointer": 1},
     "fields": [FIELD]},
    {"topic": "S02", "object": {"type": "country", "country": "ENG"},
     "fields": [FIELD, FIELD]},
    {"topic": "S02", "object": {"type": "country", "country": "ENG"},
     "fields": ["faith"]},
    {"topic": "S02", "object": {"type": "country", "country": "ENG"},
     "fields": [FIELD], "parameters": {"detail": "full"}},
    {"topic": "S02", "object": {"type": "country", "country": "ENG"},
     "fields": [FIELD], "unexpected": True},
])
def test_invalid_queries_are_rejected_before_capture(tmp_path, monkeypatch, query):
    source, base, _, calls, _ = _make_source(tmp_path, monkeypatch)
    with pytest.raises(InformationError):
        source.read(query, base.context())
    assert calls == []


def test_wrong_observer_and_stale_input_context_fail_before_capture(tmp_path, monkeypatch):
    source, base, _, calls, _ = _make_source(tmp_path, monkeypatch)
    wrong_observer = base.context()
    wrong_observer["observer"] = "POR"
    with pytest.raises(InformationError, match="FRA"):
        source.read(_defender_query("ENG"), wrong_observer)

    stale = base.context()
    stale["game_date"] += 1
    field = source.read(_defender_query("ENG"), stale)["fields"][FIELD]
    assert field["status"] == "unavailable"
    assert field["reason"] == "RELIGION_DEFENDER_CONTEXT_STALE"
    assert calls == []


def test_composite_owner_routes_religion_fields_and_defender_query_report_periodic(
        tmp_path, monkeypatch):
    info_source, base, identity_calls, _, faith_calls, group_calls = religion_fixture._make_source(
        tmp_path / "combined",
        monkeypatch,
        target="ENG",
        definitions=religion_fixture.DefinitionIndex(),
    )
    defender_source, _, defender_calls, _ = _make_defender_source(
        base,
        monkeypatch,
        target="ENG",
        report=_defender_report("ENG", holder="FRA", is_member=False),
    )
    source = CompositeSource(base, [info_source, defender_source])
    now = [100]
    service = InformationService(source, tmp_path / "defender-composite.sqlite3",
                                 clock=lambda: now[0])
    tools = InformationTools(service)
    query = faith_fixture.make_query(
        "ENG", fields=["faith", "religion_group", "mechanics", FIELD])
    try:
        catalog = next(item for item in service.source.catalog() if item["topic_id"] == "S02")
        assert catalog["source"] == "CompositeSource"
        for name in ("faith", "religion_group", "mechanics", FIELD):
            assert catalog["fields"][name]["coverage"] == "partial"
            assert catalog["fields"][name]["complete"] is False
            assert catalog["fields"][name]["triggers"] == ["query", "periodic"]
        defender_owners = [owner for owner, entry in source._routes["S02"]
                           if FIELD in entry["fields"]]
        religion_owners = [owner for owner, entry in source._routes["S02"]
                           if "mechanics" in entry["fields"]]
        assert defender_owners == [defender_source]
        assert religion_owners == [info_source]

        direct = tools.call("information_query", {
            "view": "full",
            "request_id": "defender-composite-query", "queries": [query],
        })
        direct_fields = direct["items"][0]["fields"]
        assert set(direct_fields) == {"faith", "religion_group", "mechanics", FIELD}
        assert direct_fields[FIELD]["status"] == "known"
        assert direct_fields[FIELD]["value"] == {
            "defender_country": "FRA", "is_target_defender": False,
            "tier": KNOWN_TIER,
        }
        assert direct["complete"] is False

        report = tools.call("information_manage_report", {
            "request_id": "defender-composite-report-create",
            "operation": "create",
            "config": {"name": "religion and defender", "detail": "raw",
                       "queries": [query]},
        })["report"]
        rendered = tools.call("information_query", {
            "view": "full",
            "request_id": "defender-composite-report-query", "report_id": report["id"],
        })
        assert rendered["items"][0]["fields"] == direct_fields

        subscription = tools.call("information_manage_subscription", {
            "request_id": "defender-composite-subscription-create",
            "operation": "create",
            "config": {
                "name": "defender partial periodic",
                "enabled": True,
                "kind": "periodic",
                "report_id": report["id"],
                "schedule": {"basis": "real", "unit": "seconds", "every": 1,
                             "missed": "coalesce"},
            },
        })["subscription"]
        now[0] = 102
        tick = tools.call("information_tick", {"view": "full"})
        assert tick["state"] == "processed"
        assert len(tick["results"]) == 1
        assert tick["results"][0]["status"] == "partial"
        assert tick["results"][0]["items"][0]["fields"] == direct_fields
        assert len(identity_calls) == len(faith_calls) == len(group_calls) == 3
        assert len(defender_calls) == 3

        tools.call("information_manage_subscription", {
            "request_id": "defender-composite-subscription-cancel",
            "operation": "cancel",
            "subscription_id": subscription["id"],
            "expected_version": subscription["version"],
        })
        now[0] = 104
        tools.call("information_tick", {"view": "full"})
        assert len(identity_calls) == len(faith_calls) == len(group_calls) == 3
        assert len(defender_calls) == 3
    finally:
        service.close()


def test_live_factory_registers_defender_as_its_only_s02_field_owner(
        tmp_path, monkeypatch):
    runtime_harness = runtime_fixture.wiring.__wrapped__(monkeypatch)
    import bridge.information.trade_collection as trade_collection_module
    from tools.serve_information import _build_runtime

    monkeypatch.setattr(trade_collection_module, "NativeTradeCollectionSource",
                        runtime_fixture._Adapter)
    service, journal = _build_runtime(runtime_fixture._live_args(tmp_path))
    try:
        composed = service.source.primary
        adapters = composed.adapters
        defender_sources = [adapter for adapter in adapters
                            if isinstance(adapter, NativeReligionDefenderSource)]
        religion_sources = [adapter for adapter in adapters
                            if isinstance(adapter, NativeReligionInformationSource)]
        assert len(defender_sources) == 1
        assert len(religion_sources) == 1
        assert FIELD not in religion_sources[0].catalog()[0]["fields"]
        assert defender_sources[0].base_source is composed.primary
        assert religion_sources[0].base_source is composed.primary
    finally:
        service.close()
        for ingestor in runtime_harness.ingestors:
            ingestor.close()
        if journal is not None:
            journal.close()
