"""Offline source, DTO admission, and service-routing tests for S02.papacy."""
from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.model import InformationError
from bridge.information.papacy import BASIS, FIELD, NativePapacySource
from bridge.information.religion_defender import FIELD as DEFENDER_FIELD
from bridge.information.religion_information import NativeReligionInformationSource
from bridge.information.tools import InformationTools
from bridge.information import papacy as papacy_module
from bridge.tests import test_information_capture_runtime as runtime_fixture
from bridge.tests import test_information_country_faith as faith_fixture
from bridge.tests import test_information_religion_defender_source as defender_fixture
from bridge.tests import test_information_religion_information as religion_fixture
from bridge.information.papacy_values import number_value
from tools.serve_information import _build_runtime


PROFILE_SHA256 = "a" * 64
PRIVATE_POINTER = "0x123456789abcdef0"
PAPACY_NA = {"status": "not_applicable", "reason": "PAPACY_NOT_USED"}
CONTROLLER_UNKNOWN = {
    "status": "unknown",
    "reason": "PAPACY_CONTROLLER_UNRESOLVED",
}


def _papacy_value(target="ENG", *, uses_papacy=True, influence=225,
                  treasury=2701, controller="PAP", controller_status="known"):
    if not uses_papacy:
        return {
            "uses_papacy": False,
            "papal_influence": dict(PAPACY_NA),
            "curia_treasury": dict(PAPACY_NA),
            "controller": dict(PAPACY_NA),
        }
    if controller_status == "unknown":
        controller_dto = dict(CONTROLLER_UNKNOWN)
    else:
        controller_dto = {
            "status": "known",
            "country": controller,
            "is_target_controller": controller == target,
        }
    return {
        "uses_papacy": True,
        "papal_influence": number_value("papal_influence", influence.to_bytes(4, "little", signed=True)),
        "curia_treasury": number_value("curia_treasury", treasury.to_bytes(4, "little", signed=True)),
        "controller": controller_dto,
    }


def _papacy_report(target="ENG", *, value=None, field_status="known",
                   field_basis=BASIS, complete=False, admission_status="known",
                   admitted=True, item_target=None, reason="SAFE_FIXTURE_REASON"):
    field = {
        "status": field_status,
        "complete": complete,
        "basis": field_basis,
        "raw_inputs": {"target_pointer": PRIVATE_POINTER, "nested": {"address": PRIVATE_POINTER}},
    }
    if field_status == "known":
        field["value"] = deepcopy(value if value is not None else _papacy_value(target))
    if field_status in ("unknown", "invisible"):
        field["reason"] = reason
    return {
        "schema": "information.papacy_capture.v1",
        "status": "observed",
        "completed": True,
        "observation": {
            "backend": {
                "observer": {"tag": "FRA", "private_pointer": PRIVATE_POINTER},
                "targets": [{
                    "tag": item_target if item_target is not None else target,
                    "fullref": PRIVATE_POINTER,
                    "admission_by_pass": {
                        "pass1": {"status": "known", "admitted": admitted},
                        "pass2": {"status": admission_status, "admitted": admitted},
                    },
                    "fields": {"S02.papacy": field},
                }],
            },
        },
        "raw_reads": [{"label": "private.papacy", "address": PRIVATE_POINTER}],
    }


def _query(target="ENG", fields=None, parameters=None):
    return faith_fixture.make_query(
        target,
        fields=fields if fields is not None else [FIELD],
        parameters=parameters if parameters is not None else {},
    )


def _make_source(tmp_path, monkeypatch, *, target="ENG", report=None,
                 valid=True, capture_error=None, after_capture=None):
    base = faith_fixture.Base(tmp_path, faith_fixture.make_context())
    report = deepcopy(report if report is not None else _papacy_report(target))
    captures = []
    validations = []

    def capture(installation, *, country, observer):
        captures.append((installation, country, observer))
        if after_capture is not None:
            after_capture(base)
        if capture_error is not None:
            raise capture_error
        return deepcopy(report)

    def validate_capture(actual_report, actual_context, creation, actual_target):
        validations.append((deepcopy(actual_report), deepcopy(actual_context), creation, actual_target))
        return valid

    module = SimpleNamespace(
        capture=capture,
        validate_capture=validate_capture,
        PROFILE_SHA256=PROFILE_SHA256,
    )
    monkeypatch.setattr(papacy_module, "import_module", lambda _name, _package: module)
    return NativePapacySource(base), base, report, captures, validations


@pytest.mark.parametrize(("target", "is_controller"), [
    ("FRA", False),
    ("ENG", False),
    ("PAP", True),
])
def test_known_country_projection_preserves_scalars_and_controller_membership(
        tmp_path, monkeypatch, target, is_controller):
    source, base, _, captures, validations = _make_source(
        tmp_path / target, monkeypatch, target=target,
        report=_papacy_report(target, value=_papacy_value(target)),
    )
    topic = source.catalog()[0]
    spec = topic["fields"][FIELD]
    assert topic["topic_id"] == "S02"
    assert spec["coverage"] == "partial" and spec["complete"] is False
    assert spec["unit"] == "papacy_summary" and spec["scale"] == 1
    assert spec["period"] == "current" and spec["basis"] == BASIS
    assert spec["triggers"] == ["query", "periodic"]
    assert spec["supported_observers"] == ["FRA"]

    result = source.read(_query(target), base.context())
    field = result["fields"][FIELD]
    assert field == {
        "status": "known",
        "period": "current",
        "unit": "papacy_summary",
        "scale": 1,
        "partial": True,
        "complete": False,
        "basis": BASIS,
        "value_origin": "copied_native_papacy_state",
        "value": {
            "uses_papacy": True,
            "papal_influence": number_value("papal_influence", (225).to_bytes(4, "little", signed=True)),
            "curia_treasury": number_value("curia_treasury", (2701).to_bytes(4, "little", signed=True)),
            "controller": {
                "status": "known", "country": "PAP",
                "is_target_controller": is_controller,
            },
        },
    }
    assert result["complete"] is False
    assert result["source"]["context_scope"] == "visible_scope"
    provenance = result["source"]["provenance"]
    assert provenance["observer"] == "FRA" and provenance["target"] == target
    assert len(provenance["capture_report_sha256"]) == 64
    assert provenance["profile_sha256"] == PROFILE_SHA256
    assert PRIVATE_POINTER not in repr(result)
    assert captures == [(base.session.directory / "installation.json", target, "FRA")]
    assert len(validations) == 1
    assert validations[0][1]["observer"] == "FRA"
    assert validations[0][2:] == (faith_fixture.CREATION, target)


def test_non_papacy_target_has_three_exact_not_applicable_children(tmp_path, monkeypatch):
    value = _papacy_value("TUR", uses_papacy=False)
    source, base, _, _, _ = _make_source(
        tmp_path, monkeypatch, target="TUR", report=_papacy_report("TUR", value=value),
    )

    result = source.read(_query("TUR"), base.context())
    public = result["fields"][FIELD]["value"]
    assert public == {
        "uses_papacy": False,
        "papal_influence": PAPACY_NA,
        "curia_treasury": PAPACY_NA,
        "controller": PAPACY_NA,
    }
    assert all(set(public[name]) == {"status", "reason"}
               for name in ("papal_influence", "curia_treasury", "controller"))


def test_unresolved_controller_keeps_known_numeric_siblings(tmp_path, monkeypatch):
    value = _papacy_value("ENG", controller_status="unknown")
    source, base, _, _, _ = _make_source(
        tmp_path, monkeypatch, report=_papacy_report("ENG", value=value),
    )

    field = source.read(_query("ENG"), base.context())["fields"][FIELD]
    assert field["status"] == "known"
    assert field["value"]["papal_influence"]["value"] == 225
    assert field["value"]["curia_treasury"]["value"] == 2701
    assert field["value"]["controller"] == CONTROLLER_UNKNOWN
    assert PRIVATE_POINTER not in repr(field)


@pytest.mark.parametrize(("report", "status", "reason"), [
    (_papacy_report("ENG", admission_status="unknown"), "unknown", "PAPACY_VIEW_ADMISSION_UNKNOWN"),
    (_papacy_report("ENG", admitted=False), "invisible", "PAPACY_NOT_ADMITTED"),
    (_papacy_report("ENG", field_status="unknown", reason="SAFE_BACKEND_REASON"), "unknown", "SAFE_BACKEND_REASON"),
    (_papacy_report("ENG", field_status="invisible", reason="SAFE_BACKEND_REASON"), "invisible", "SAFE_BACKEND_REASON"),
    (_papacy_report("ENG", field_status="unknown", reason=PRIVATE_POINTER), "unknown", "PAPACY_BACKEND_UNKNOWN"),
])
def test_admission_and_backend_visibility_gates_never_publish_value(
        tmp_path, monkeypatch, report, status, reason):
    source, base, _, _, _ = _make_source(tmp_path, monkeypatch, report=report)

    field = source.read(_query("ENG"), base.context())["fields"][FIELD]
    assert field["status"] == status
    assert field["reason"] == reason
    assert "value" not in field
    assert PRIVATE_POINTER not in repr(field)


@pytest.mark.parametrize("mutation", [
    "extra_value_key", "bad_raw_hex", "wrong_scalar_unit", "controller_pointer",
    "membership_mismatch", "wrong_target", "bad_basis", "complete_true", "validator_false",
])
def test_tampered_value_or_capture_contract_fails_closed(tmp_path, monkeypatch, mutation):
    report = _papacy_report("ENG")
    valid = True
    target_item = report["observation"]["backend"]["targets"][0]
    field = target_item["fields"]["S02.papacy"]
    value = field["value"]
    if mutation == "extra_value_key":
        value["private_pointer"] = PRIVATE_POINTER
    elif mutation == "bad_raw_hex":
        value["papal_influence"]["raw_hex"] = "00000000"
    elif mutation == "wrong_scalar_unit":
        value["curia_treasury"]["unit"] = "papal_influence"
    elif mutation == "controller_pointer":
        value["controller"] = {
            "status": "known", "country": PRIVATE_POINTER,
            "is_target_controller": False,
        }
    elif mutation == "membership_mismatch":
        value["controller"]["country"] = "FRA"
        value["controller"]["is_target_controller"] = True
    elif mutation == "wrong_target":
        target_item["tag"] = "POR"
    elif mutation == "bad_basis":
        field["basis"] = "another_basis"
    elif mutation == "complete_true":
        field["complete"] = True
    elif mutation == "validator_false":
        valid = False
    source, base, _, _, _ = _make_source(
        tmp_path / mutation, monkeypatch, report=report, valid=valid,
    )

    field_result = source.read(_query("ENG"), base.context())["fields"][FIELD]
    assert field_result["status"] == "unknown"
    assert field_result["reason"] == "PAPACY_CAPTURE_INVALID"
    assert "value" not in field_result
    assert PRIVATE_POINTER not in repr(field_result)


@pytest.mark.parametrize(("change", "expected_reason"), [
    ("date", "PAPACY_CONTEXT_CHANGED_DURING_CAPTURE"),
    ("session", "PAPACY_SESSION_CHANGED_DURING_CAPTURE"),
])
def test_context_or_session_change_during_capture_retracts_value(
        tmp_path, monkeypatch, change, expected_reason):
    def drift(base):
        if change == "date":
            base.current["game_date"] += 1
        else:
            base.session.creation_filetime += 1
            base.session.record["creation_filetime"] += 1

    source, base, _, captures, _ = _make_source(
        tmp_path / change, monkeypatch, after_capture=drift,
    )

    field = source.read(_query("ENG"), base.context())["fields"][FIELD]
    assert field["status"] == "unavailable"
    assert field["reason"] == expected_reason
    assert "value" not in field
    assert len(captures) == 1


def test_capture_exception_and_stale_input_context_are_fail_closed(tmp_path, monkeypatch):
    source, base, _, captures, _ = _make_source(
        tmp_path, monkeypatch, capture_error=RuntimeError("fixture capture failure"),
    )
    field = source.read(_query("ENG"), base.context())["fields"][FIELD]
    assert field["status"] == "unknown"
    assert field["reason"] == "PAPACY_CAPTURE_FAILED:RuntimeError"
    assert "value" not in field
    assert len(captures) == 1

    stale = base.context()
    stale["game_date"] += 1
    stale_field = source.read(_query("ENG"), stale)["fields"][FIELD]
    assert stale_field["status"] == "unavailable"
    assert stale_field["reason"] == "PAPACY_CONTEXT_STALE"
    assert len(captures) == 1


@pytest.mark.parametrize("query", [
    {"topic": "S02", "object": {"type": "country", "country": "bad"}, "fields": [FIELD]},
    {"topic": "S02", "object": {"type": "country", "country": "ENG"}, "fields": ["faith"]},
    {"topic": "S02", "object": {"type": "country", "country": "ENG"}, "fields": [FIELD, FIELD]},
    {"topic": "S02", "object": {"type": "country", "country": "ENG"}, "fields": [FIELD], "parameters": {"detail": "full"}},
    {"topic": "S02", "object": {"type": "country", "country": "ENG"}, "fields": [FIELD], "extra": True},
])
def test_invalid_queries_and_observer_scope_are_rejected_before_capture(
        tmp_path, monkeypatch, query):
    source, base, _, captures, _ = _make_source(tmp_path, monkeypatch)
    with pytest.raises(InformationError):
        source.read(query, base.context())
    wrong_observer = base.context()
    wrong_observer["observer"] = "POR"
    with pytest.raises(InformationError):
        source.read(_query("ENG"), wrong_observer)
    assert captures == []


def test_composite_routes_religion_defender_and_papacy_for_query_report_periodic(
        tmp_path, monkeypatch):
    info_source, base, identity_calls, _, faith_calls, group_calls = religion_fixture._make_source(
        tmp_path / "mixed", monkeypatch, target="ENG",
        definitions=religion_fixture.DefinitionIndex(),
    )
    defender_source, _, defender_calls, _ = defender_fixture._make_defender_source(
        base, monkeypatch, target="ENG",
        report=defender_fixture._defender_report("ENG", holder="FRA", is_member=False),
    )
    papacy_source, _, _, papacy_calls, _ = _make_source(
        tmp_path / "papacy", monkeypatch, target="ENG",
        report=_papacy_report("ENG", value=_papacy_value("ENG")),
    )
    source = CompositeSource(base, [info_source, defender_source, papacy_source])
    now = [100]
    service = InformationService(source, tmp_path / "papacy-composite.sqlite3", clock=lambda: now[0])
    tools = InformationTools(service)
    fields = ["faith", "religion_group", "mechanics", DEFENDER_FIELD, FIELD]
    query = faith_fixture.make_query("ENG", fields=fields)
    try:
        catalog = next(item for item in source.catalog() if item["topic_id"] == "S02")
        assert catalog["source"] == "CompositeSource"
        assert catalog["fields"][FIELD]["coverage"] == "partial"
        assert catalog["fields"][FIELD]["triggers"] == ["query", "periodic"]
        papacy_owners = [owner for owner, entry in source._routes["S02"] if FIELD in entry["fields"]]
        defender_owners = [owner for owner, entry in source._routes["S02"] if DEFENDER_FIELD in entry["fields"]]
        assert papacy_owners == [papacy_source]
        assert defender_owners == [defender_source]

        direct = tools.call("information_query", {
            "view": "full",
            "request_id": "papacy-composite-query", "queries": [query],
        })
        direct_fields = direct["items"][0]["fields"]
        assert set(direct_fields) == set(fields)
        assert direct_fields[FIELD]["status"] == "known"
        assert direct_fields[FIELD]["value"]["controller"]["country"] == "PAP"
        assert direct_fields[DEFENDER_FIELD]["status"] == "known"
        assert direct["complete"] is False

        report = tools.call("information_manage_report", {
            "request_id": "papacy-composite-report-create",
            "operation": "create",
            "config": {"name": "religion defender and papacy", "detail": "raw", "queries": [query]},
        })["report"]
        rendered = tools.call("information_query", {
            "view": "full",
            "request_id": "papacy-composite-report-query", "report_id": report["id"],
        })
        assert rendered["items"][0]["fields"] == direct_fields

        subscription = tools.call("information_manage_subscription", {
            "request_id": "papacy-composite-subscription-create",
            "operation": "create",
            "config": {
                "name": "papacy partial periodic", "enabled": True, "kind": "periodic",
                "report_id": report["id"],
                "schedule": {"basis": "real", "unit": "seconds", "every": 1, "missed": "coalesce"},
            },
        })["subscription"]
        now[0] = 102
        tick = tools.call("information_tick", {"view": "full"})
        assert tick["state"] == "processed"
        assert len(tick["results"]) == 1
        assert tick["results"][0]["status"] == "partial"
        assert tick["results"][0]["items"][0]["fields"] == direct_fields
        assert len(identity_calls) == len(faith_calls) == len(group_calls) == 3
        assert len(defender_calls) == len(papacy_calls) == 3

        tools.call("information_manage_subscription", {
            "request_id": "papacy-composite-subscription-cancel",
            "operation": "cancel", "subscription_id": subscription["id"],
            "expected_version": subscription["version"],
        })
        now[0] = 104
        tools.call("information_tick", {"view": "full"})
        assert len(identity_calls) == len(faith_calls) == len(group_calls) == 3
        assert len(defender_calls) == len(papacy_calls) == 3
    finally:
        service.close()


def test_factory_registers_one_papacy_field_owner(tmp_path, monkeypatch):
    runtime_harness = runtime_fixture.wiring.__wrapped__(monkeypatch)
    import bridge.information.trade_collection as trade_collection_module

    monkeypatch.setattr(
        trade_collection_module,
        "NativeTradeCollectionSource",
        runtime_fixture._Adapter,
    )
    service, journal = _build_runtime(runtime_fixture._live_args(tmp_path))
    try:
        composed = service.source.primary
        owners = [adapter for adapter in composed.adapters if isinstance(adapter, NativePapacySource)]
        assert len(owners) == 1
        assert owners[0].base_source is composed.primary
        assert set(owners[0].catalog()[0]["fields"]) == {FIELD}
    finally:
        service.close()
        for ingestor in runtime_harness.ingestors:
            ingestor.close()
        if journal is not None:
            journal.close()
