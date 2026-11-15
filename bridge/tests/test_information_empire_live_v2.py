"""Offline source-boundary tests for the S01 reform-ID extension.

The injected capture backend keeps these tests independent from the native
reader.  They exercise the adapter's validation, field isolation, context
checks, projection whitelist, and normal information-service scheduling.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import empire_live as empire_live_module
from bridge.information.catalog import get_topic, list_topics
from bridge.information.composite import CompositeSource
from bridge.information.empire_live_v2 import FIELDS, NativeEmpireReformsSource
from bridge.information.model import InformationError
from bridge.information.service import InformationService
from bridge.information.tools import InformationTools


GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
DLL_SHA = "f1c0a589a9922bae5c395b564b3419748f5d6d789d565d5d78b0f86ab8358138"
CREATION = 134380633247930565
CAPTURE_PROFILE_SHA = "b" * 64
TAGS = ["TRI", "BOH", "SAX", "BRA", "KOL", "MAI", "PAL"]
REFORMS = ["centralization_reform", "imperial_authority_reform"]
SECRET = "private pointer 0xdeadbeef raw_inputs"


def make_context(**overrides):
    context = {
        "status": "ready", "mode": "live", "complete": True,
        "observer": "FRA", "session_id": "empire-v2-test-session",
        "game_version": "1.37.4", "game_sha256": GAME_SHA,
        "dll_sha256": DLL_SHA, "game_date": 56556984,
        "world_generation": 42, "physical_client_country": "POR",
    }
    context.update(overrides)
    return context


class FakeBase:
    event_types = ()

    def __init__(self, directory: Path, context: dict | None = None):
        self.current = deepcopy(context if context is not None else make_context())
        session_dir = directory / "session"
        session_dir.mkdir(parents=True, exist_ok=True)
        self.session = SimpleNamespace(
            directory=session_dir,
            creation_filetime=CREATION,
            record={"session_id": self.current["session_id"],
                    "creation_filetime": CREATION},
        )

    def context(self):
        return deepcopy(self.current)

    def catalog(self):
        return list_topics()

    def read(self, query, context):
        return {
            "fields": {name: {"status": "unsupported", "reason": "PRIMARY_UNUSED"}
                       for name in query["fields"]},
            "complete": False,
            "source": {"name": "fake_primary", "mode": "live"},
        }

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": deepcopy(cursor or {}),
                "complete": True, "gaps": []}


def make_query(*, obj=None, fields=None):
    return {
        "topic": "S01",
        "object": deepcopy(obj if obj is not None else {"type": "country", "country": "FRA"}),
        "fields": list(fields if fields is not None else FIELDS),
        "parameters": {},
    }


def make_report():
    return {
        "schema": "information.empire_capture.v2",
        "observer": "FRA",
        "object": {"kind": "global_hre"},
        "capture": {"private": SECRET},
    }


def make_projection(*, emperor="HAB", electors=None, reforms=None):
    return {
        "emperor": {"status": "known", "value": emperor,
                    "raw_inputs": {"country_pointer": "0x1111222233334444"}},
        "electors": {"status": "known", "value": list(TAGS if electors is None else electors),
                     "raw_inputs": {"node_pointer": "0x5555666677778888"}},
        "reforms": {"status": "known", "value": list(REFORMS if reforms is None else reforms),
                    "raw_inputs": {"reform_table": "0x9999"}},
    }


def make_source(tmp_path, monkeypatch, *, projection=None, validation=True,
                validation_error=None, capture_error=None, projection_error=None,
                after_capture=None, after_validation=None, context=None):
    base = FakeBase(tmp_path, context)
    report = make_report()
    projected = deepcopy(projection if projection is not None else make_projection())
    captures, validations, projections, import_names = [], [], [], []

    def capture(installation, *, observer):
        captures.append((installation, observer))
        if after_capture is not None:
            after_capture(base)
        if capture_error is not None:
            raise capture_error
        return deepcopy(report)

    def validate_capture(report_arg, context_arg, creation):
        validations.append((deepcopy(report_arg), deepcopy(context_arg), creation))
        if validation_error is not None:
            raise validation_error
        if after_validation is not None:
            after_validation(base)
        return validation is True

    def project_fields(report_arg):
        projections.append(deepcopy(report_arg))
        if projection_error is not None:
            raise projection_error
        return deepcopy(projected)

    backend = SimpleNamespace(
        capture=capture,
        validate_capture=validate_capture,
        project_fields=project_fields,
        PROFILE_SHA256=CAPTURE_PROFILE_SHA,
    )

    def import_module(name, package):
        import_names.append((name, package))
        if name != ".empire_capture_v2":
            raise AssertionError(f"unexpected capture module: {name}")
        return backend

    monkeypatch.setattr(empire_live_module, "import_module", import_module)
    source = NativeEmpireReformsSource(base, capture=capture)
    return source, base, report, captures, validations, projections, import_names


def private_leaks(result):
    text = repr(result)
    return [token for token in ("raw_inputs", "raw_reads", "0x1111222233334444",
                                 "0x5555666677778888", "0x9999", "0xdeadbeef")
            if token in text]


def test_catalog_adds_only_partial_current_reform_ids_and_keeps_full_union(tmp_path, monkeypatch):
    source, base, *_ = make_source(tmp_path, monkeypatch)
    owned = source.catalog()[0]

    assert owned["topic_id"] == "S01"
    assert set(owned["fields"]) == set(FIELDS)
    assert set(owned["object_types"]) == {"country", "session"}
    assert owned["triggers"] == ["query", "periodic"]
    assert owned["observer_roles"] == []
    assert all(meta["coverage"] == "partial" for meta in owned["fields"].values())

    expected_fields = {row["topic_id"]: set(row["fields"]) for row in base.catalog()}
    catalog = CompositeSource(base, [source]).catalog()
    assert len(catalog) == len(expected_fields)
    assert {row["topic_id"]: set(row["fields"]) for row in catalog} == expected_fields
    topic = next(row for row in catalog if row["topic_id"] == "S01")
    fields = topic["fields"]
    assert set(fields) == set(get_topic("S01")["fields"])
    assert {name for name, meta in fields.items() if meta["coverage"] == "partial"} == set(FIELDS)
    for name in FIELDS:
        assert fields[name]["coverage"] == "partial"
        assert fields[name]["unit"] == ("reform_id" if name == "reforms" else "country_tag")
        assert fields[name]["scale"] == 1
        assert fields[name]["period"] == "current"
        assert fields[name]["complete"] is False
    assert all(meta["coverage"] == "planned" for name, meta in fields.items()
               if name not in FIELDS)


def test_country_and_session_selectors_share_one_validated_global_projection(tmp_path, monkeypatch):
    source, base, report, captures, validations, projections, import_names = make_source(
        tmp_path, monkeypatch)
    country = source.read(make_query(obj={"type": "country", "country": "HAB"}), base.context())
    session = source.read(make_query(obj={"type": "session"}), base.context())

    assert country["fields"] == session["fields"]
    assert country["fields"]["emperor"]["value"] == "HAB"
    assert country["fields"]["electors"]["value"] == sorted(TAGS)
    assert country["fields"]["reforms"]["value"] == REFORMS
    assert country["fields"]["reforms"]["order"] == "native_record_order"
    assert all(country["fields"][name]["complete"] is False
               and country["fields"][name]["period"] == "current" for name in FIELDS)
    assert [call[1] for call in captures] == ["FRA", "FRA"]
    assert all(row[0]["schema"] == report["schema"] and row[2] == CREATION
               for row in validations)
    assert len(projections) == 2 and all(row == report for row in projections)
    assert all(name == ".empire_capture_v2" for name, _ in import_names)
    assert not private_leaks(country)
    assert country["source"]["provenance"]["actual_UI_observed"] is False
    assert country["source"]["provenance"]["atomic_snapshot"] is False


def test_known_empty_reform_list_is_distinct_from_unknown(tmp_path, monkeypatch):
    source, base, *_ = make_source(tmp_path, monkeypatch,
                                  projection=make_projection(reforms=[]))
    result = source.read(make_query(fields=["emperor", "electors", "reforms"]), base.context())
    reforms = result["fields"]["reforms"]
    assert reforms["status"] == "known" and reforms["value"] == []
    assert reforms["unit"] == "reform_id" and reforms["scale"] == 1
    assert reforms["complete"] is False
    assert result["complete"] is False


def test_leading_underscore_and_maximum_length_reform_ids_keep_native_order(tmp_path, monkeypatch):
    identifiers = ["_first", "x" * 128, "_" + "z" * 127]
    source, base, *_ = make_source(tmp_path, monkeypatch,
                                  projection=make_projection(reforms=identifiers))
    result = source.read(make_query(fields=["reforms"]), base.context())
    assert result["fields"]["reforms"]["status"] == "known"
    assert result["fields"]["reforms"]["value"] == identifiers
    assert [len(value) for value in result["fields"]["reforms"]["value"]] == [6, 128, 128]


@pytest.mark.parametrize("values", [
    ["centralization_reform", "centralization_reform"],
    ["bad value"],
    ["x" * 129],
    [True],
    ["reform"] * 4097,
])
def test_invalid_reform_ids_only_make_reforms_unknown(tmp_path, monkeypatch, values):
    source, base, *_ = make_source(tmp_path, monkeypatch,
                                  projection=make_projection(reforms=values))
    result = source.read(make_query(), base.context())
    assert result["fields"]["emperor"]["status"] == "known"
    assert result["fields"]["electors"]["status"] == "known"
    assert result["fields"]["reforms"]["status"] == "unknown"
    assert result["fields"]["reforms"]["reason"] == "EMPIRE_REFORM_IDENTIFIERS_INVALID"
    assert "value" not in result["fields"]["reforms"]
    assert not private_leaks(result)


def test_unknown_reforms_do_not_retract_known_legacy_fields_or_leak_bad_value(tmp_path, monkeypatch):
    projection = make_projection()
    projection["reforms"] = {"status": "unknown", "reason": "REFORMS_NOT_STABLE",
                              "value": [SECRET], "raw_inputs": {"ptr": "0x9999"}}
    source, base, *_ = make_source(tmp_path, monkeypatch, projection=projection)
    result = source.read(make_query(), base.context())
    assert result["fields"]["emperor"]["status"] == "known"
    assert result["fields"]["electors"]["status"] == "known"
    assert result["fields"]["reforms"]["status"] == "unknown"
    assert result["fields"]["reforms"]["reason"] == "REFORMS_NOT_STABLE"
    assert not private_leaks(result)


@pytest.mark.parametrize("projection", [
    {"emperor": {"status": "known", "value": "HAB"},
     "electors": {"status": "known", "value": []}},
    {**make_projection(), "extra": SECRET},
])
def test_invalid_projection_shape_retracts_all_fields_without_private_payload(
        tmp_path, monkeypatch, projection):
    source, base, *_ = make_source(tmp_path, monkeypatch, projection=projection)
    result = source.read(make_query(), base.context())
    assert all(result["fields"][name]["status"] == "unknown" for name in FIELDS)
    assert all(result["fields"][name]["reason"] == "EMPIRE_CAPTURE_SHAPE_INVALID"
               and "value" not in result["fields"][name] for name in FIELDS)
    assert not private_leaks(result)


@pytest.mark.parametrize("validation,raises,expected_reason", [
    (False, None, "EMPIRE_CAPTURE_NOT_VALIDATED"),
    (1, None, "EMPIRE_CAPTURE_NOT_VALIDATED"),
    (True, RuntimeError(SECRET), "EMPIRE_CAPTURE_SHAPE_INVALID"),
])
def test_capture_validation_must_be_literal_true_and_exceptions_are_private(
        tmp_path, monkeypatch, validation, raises, expected_reason):
    source, base, _, captures, validations, projections, _ = make_source(
        tmp_path, monkeypatch, validation=validation, validation_error=raises)
    result = source.read(make_query(), base.context())
    assert all(result["fields"][name]["status"] == "unknown"
               and result["fields"][name]["reason"] == expected_reason
               and "value" not in result["fields"][name] for name in FIELDS)
    assert len(captures) == len(validations) == 1 and projections == []
    assert not private_leaks(result) and SECRET not in repr(result)


def test_bad_selector_or_session_binding_stops_before_capture(tmp_path, monkeypatch):
    source, base, _, captures, validations, projections, _ = make_source(tmp_path, monkeypatch)
    with pytest.raises(InformationError):
        source.read(make_query(obj={"type": "country", "country": "fra"}), base.context())
    assert captures == validations == projections == []

    mismatch = source.read(make_query(obj={"type": "session", "session_id": "other"}),
                          base.context())
    assert all(mismatch["fields"][name]["status"] == "unavailable"
               and mismatch["fields"][name]["reason"] == "EMPIRE_SELECTOR_SESSION_MISMATCH"
               for name in FIELDS)
    assert captures == validations == projections == []

    base.session.record["session_id"] = "wrong-record"
    invalid_binding = source.read(make_query(), base.context())
    assert all(invalid_binding["fields"][name]["status"] == "unavailable"
               and invalid_binding["fields"][name]["reason"] == "EMPIRE_SESSION_RECORD_MISMATCH"
               for name in FIELDS)
    assert captures == validations == projections == []


@pytest.mark.parametrize("changed_key", ["game_date", "world_generation", "physical_client_country"])
def test_context_drift_after_capture_retracts_all_three_fields(
        tmp_path, monkeypatch, changed_key):
    def mutate(base):
        if changed_key == "physical_client_country":
            base.current[changed_key] = "ENG"
        elif changed_key == "game_date":
            base.current[changed_key] += 1
        else:
            base.current[changed_key] += 1

    source, base, _, captures, validations, projections, _ = make_source(
        tmp_path, monkeypatch, after_capture=mutate)
    result = source.read(make_query(), base.context())
    assert all(result["fields"][name]["status"] == "unavailable"
               and result["fields"][name]["reason"] == "EMPIRE_CONTEXT_CHANGED_DURING_CAPTURE"
               and "value" not in result["fields"][name] for name in FIELDS)
    assert len(captures) == 1 and validations == projections == []


def test_context_drift_during_final_validation_retracts_all_three_fields(tmp_path, monkeypatch):
    def mutate(base):
        base.current["world_generation"] += 1

    source, base, _, captures, validations, projections, _ = make_source(
        tmp_path, monkeypatch, after_validation=mutate)
    result = source.read(make_query(), base.context())
    assert all(result["fields"][name]["status"] == "unavailable"
               and result["fields"][name]["reason"] == "EMPIRE_CONTEXT_CHANGED_DURING_VALIDATION"
               and "value" not in result["fields"][name] for name in FIELDS)
    assert len(captures) == len(validations) == len(projections) == 1
    assert not private_leaks(result)


def test_capture_and_projection_exceptions_are_sanitized(tmp_path, monkeypatch):
    source, base, _, captures, validations, projections, _ = make_source(
        tmp_path, monkeypatch, capture_error=RuntimeError(SECRET))
    result = source.read(make_query(), base.context())
    assert all(result["fields"][name]["reason"] == "EMPIRE_CAPTURE_FAILED"
               for name in FIELDS)
    assert SECRET not in repr(result) and len(captures) == 1
    assert validations == projections == []

    source, base, _, captures, validations, projections, _ = make_source(
        tmp_path, monkeypatch, projection_error=RuntimeError(SECRET))
    result = source.read(make_query(), base.context())
    assert all(result["fields"][name]["reason"] == "EMPIRE_CAPTURE_SHAPE_INVALID"
               for name in FIELDS)
    assert SECRET not in repr(result) and len(captures) == 1
    assert len(validations) == len(projections) == 1


def test_unsupported_only_query_does_not_capture(tmp_path, monkeypatch):
    source, base, _, captures, validations, projections, _ = make_source(tmp_path, monkeypatch)
    unsupported = next(name for name in get_topic("S01")["fields"] if name not in FIELDS)
    result = source.read(make_query(fields=[unsupported]), base.context())
    assert result["fields"][unsupported]["status"] == "unsupported"
    assert captures == validations == projections == []


def test_query_report_two_and_five_second_periodics_share_source_and_cancel_independently(
        tmp_path, monkeypatch):
    source, base, _, captures, validations, projections, _ = make_source(tmp_path, monkeypatch)
    now = [100.0]
    service = InformationService(
        CompositeSource(base, [source]), tmp_path / "empire-live-v2-service.sqlite3",
        clock=lambda: now[0],
    )
    tools = InformationTools(service)
    fields = [*FIELDS]
    direct_query = make_query(obj={"type": "country", "country": "HAB"}, fields=fields)
    report_query = make_query(obj={"type": "session"}, fields=fields)
    try:
        direct = tools.call("information_query", {
            "view": "full",
            "request_id": "empire-v2-direct", "queries": [direct_query],
        })
        report = tools.call("information_manage_report", {
            "request_id": "empire-v2-report-create", "operation": "create",
            "config": {"name": "global HRE v2", "detail": "raw", "queries": [report_query]},
        })["report"]
        rendered = tools.call("information_query", {
            "view": "full",
            "request_id": "empire-v2-report-query", "report_id": report["id"],
        })
        direct_fields = direct["items"][0]["fields"]
        assert direct_fields == rendered["items"][0]["fields"]
        assert direct_fields["reforms"]["value"] == REFORMS
        assert direct_fields["reforms"]["unit"] == "reform_id"
        assert direct_fields["reforms"]["complete"] is False
        assert direct["complete"] is rendered["complete"] is False
        assert not private_leaks(direct["items"][0])

        subscriptions = {}
        for seconds in (2, 5):
            response = tools.call("information_manage_subscription", {
                "request_id": f"empire-v2-subscribe-{seconds}", "operation": "create",
                "config": {
                    "name": f"global HRE every {seconds}s", "enabled": True,
                    "kind": "periodic", "report_id": report["id"],
                    "schedule": {"basis": "real", "unit": "seconds",
                                 "every": seconds, "missed": "coalesce"},
                },
            })
            subscriptions[seconds] = response["subscription"]["id"]

        now[0] = 102.0
        tick2 = tools.call("information_tick", {"view": "full"})
        assert len(tick2["results"]) == 1
        assert tick2["results"][0]["items"][0]["fields"] == direct_fields

        tools.call("information_manage_subscription", {
            "request_id": "empire-v2-cancel-2s", "operation": "cancel",
            "subscription_id": subscriptions[2], "expected_version": 1,
        })
        states = {row["id"]: row["state"] for row in tools.call(
            "information_manage_subscription", {
                "request_id": "empire-v2-list-after-cancel", "operation": "list",
            })["subscriptions"]}
        assert states[subscriptions[2]] == "cancelled"
        assert states[subscriptions[5]] == "active"

        now[0] = 105.0
        tick5 = tools.call("information_tick", {"view": "full"})
        assert len(tick5["results"]) == 1
        assert tick5["results"][0]["items"][0]["fields"] == direct_fields
        tools.call("information_manage_subscription", {
            "request_id": "empire-v2-cancel-5s", "operation": "cancel",
            "subscription_id": subscriptions[5], "expected_version": 1,
        })
        now[0] = 110.0
        assert tools.call("information_tick", {"view": "full"})["results"] == []
        assert len(captures) == len(validations) == len(projections) == 4
        assert all(row[1] == "FRA" for row in captures)
    finally:
        service.close()

