"""Contract tests for the live global-HRE source adapter.

The capture backend is injected so these tests exercise routing, validation,
projection, context checks, and service scheduling without touching a game.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import empire_live as empire_live_module
from bridge.information.catalog import get_topic, list_topics
from bridge.information.composite import CompositeSource
from bridge.information.empire_live import NativeEmpireSource
from bridge.information.model import InformationError
from bridge.information.service import InformationService
from bridge.information.tools import InformationTools


GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
DLL_SHA = "f1c0a589a9922bae5c395b564b3419748f5d6d789d565d5d78b0f86ab8358138"
CREATION = 134380633247930565
PROFILE_SHA = "a" * 64
FIELDS = ("emperor", "electors")
_DEFAULT_VALIDATION = object()


def make_context(**overrides):
    context = {
        "status": "ready",
        "mode": "live",
        "complete": True,
        "observer": "FRA",
        "session_id": "empire-live-test-session",
        "game_version": "1.37.4",
        "game_sha256": GAME_SHA,
        "dll_sha256": DLL_SHA,
        "game_date": 56556984,
        "world_generation": 42,
        "physical_client_country": "POR",
    }
    context.update(overrides)
    return context


class FakeBase:
    event_types = ()

    def __init__(self, directory: Path, context: dict):
        self.current = deepcopy(context)
        session_dir = directory / "session"
        session_dir.mkdir(parents=True, exist_ok=True)
        self.session = SimpleNamespace(
            directory=session_dir,
            creation_filetime=CREATION,
            record={"session_id": context["session_id"],
                    "creation_filetime": CREATION},
        )

    def context(self):
        return deepcopy(self.current)

    def catalog(self):
        return list_topics()

    def read(self, query, context):
        return {
            "fields": {
                field: {"status": "unsupported", "reason": "PRIMARY_UNUSED"}
                for field in query["fields"]
            },
            "complete": False,
            "source": {"name": "fake_primary", "mode": "live"},
        }

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": deepcopy(cursor or {}),
                "complete": True, "gaps": []}


def make_query(*, obj=None, fields=None):
    return {
        "topic": "S01",
        "object": deepcopy(obj or {"type": "country", "country": "FRA"}),
        "fields": list(fields if fields is not None else FIELDS),
        "parameters": {},
    }


def make_report():
    return {
        "schema": "information.empire_capture.v1",
        "observer": "FRA",
        "raw_inputs": {"hre_pointer": "0x123456789abcdef0"},
        "raw_reads": [{"address": "0x0fedcba987654321", "bytes": "private"}],
    }


def make_projection():
    return {
        "emperor": {
            "status": "known", "value": "HAB",
            "raw_inputs": {"country_pointer": "0x1111222233334444"},
        },
        "electors": {
            "status": "known", "value": ["TRI", "BOH", "SAX", "BRA", "KOL", "MAI", "PAL"],
            "raw_inputs": {"node_pointer": "0x5555666677778888"},
        },
    }


def make_source(tmp_path, monkeypatch, *, report=None, projection=None,
                validation_result=_DEFAULT_VALIDATION, after_capture=None,
                capture_error=None, projection_error=None, context=None):
    base = FakeBase(tmp_path, context or make_context())
    captured = deepcopy(report if report is not None else make_report())
    projected = deepcopy(projection if projection is not None else make_projection())
    captures = []
    validations = []
    projections = []
    calls = []

    def capture(installation, *, observer):
        captures.append((installation, observer))
        if after_capture is not None:
            after_capture(base)
        if capture_error is not None:
            raise capture_error
        return deepcopy(captured)

    def validate_capture(report_arg, context_arg, creation):
        calls.append("validate")
        validations.append((deepcopy(report_arg), deepcopy(context_arg), creation))
        valid = (
            isinstance(report_arg, dict)
            and report_arg.get("schema") == "information.empire_capture.v1"
            and report_arg.get("observer") == "FRA"
            and isinstance(context_arg, dict)
            and context_arg.get("observer") == "FRA"
            and context_arg.get("session_id") == base.current.get("session_id")
            and creation == CREATION
        )
        if validation_result is _DEFAULT_VALIDATION:
            return valid
        if isinstance(validation_result, Exception):
            raise validation_result
        return validation_result

    def project_fields(report_arg):
        calls.append("project")
        projections.append(deepcopy(report_arg))
        if projection_error is not None:
            raise projection_error
        return deepcopy(projected)

    backend = SimpleNamespace(
        capture=lambda installation, *, observer: capture(installation, observer=observer),
        validate_capture=validate_capture,
        project_fields=project_fields,
        PROFILE_SHA256=PROFILE_SHA,
    )
    monkeypatch.setattr(empire_live_module, "import_module",
                        lambda _name, _package: backend)
    source = NativeEmpireSource(base, capture=backend.capture)
    return source, base, captured, captures, validations, projections, calls


def test_catalog_merges_only_live_emperor_and_electors_as_partial(tmp_path, monkeypatch):
    source, base, *_ = make_source(tmp_path, monkeypatch)
    owned = source.catalog()[0]
    assert owned["topic_id"] == "S01"
    assert set(owned["fields"]) == set(FIELDS)
    assert set(owned["object_types"]) == {"country", "session"}
    assert owned["observer_roles"] == []
    assert owned["triggers"] == ["query", "periodic"]
    assert all(field["coverage"] == "partial" and field["complete"] is False
               and field["period"] == "current" for field in owned["fields"].values())

    expected_fields = {topic["topic_id"]: set(topic["fields"]) for topic in base.catalog()}
    catalog = CompositeSource(base, [source]).catalog()
    assert len(catalog) == len(expected_fields)
    assert {topic["topic_id"]: set(topic["fields"]) for topic in catalog} == expected_fields
    s01 = next(topic for topic in catalog if topic["topic_id"] == "S01")
    assert set(s01["fields"]) == set(get_topic("S01")["fields"])
    assert {name for name, field in s01["fields"].items()
            if field["coverage"] == "partial"} == set(FIELDS)
    assert all(field["coverage"] == "planned" for name, field in s01["fields"].items()
               if name not in FIELDS)


def test_country_and_session_selectors_read_the_same_global_record_through_validator(
        tmp_path, monkeypatch):
    source, base, report, captures, validations, projections, calls = make_source(
        tmp_path, monkeypatch)
    country = source.read(make_query(obj={"type": "country", "country": "HAB"}),
                          base.context())
    session = source.read(make_query(obj={"type": "session",
                                          "session_id": base.current["session_id"]}),
                          base.context())

    assert country["fields"] == session["fields"]
    assert country["fields"]["emperor"]["value"] == "HAB"
    assert country["fields"]["electors"]["value"] == [
        "BOH", "BRA", "KOL", "MAI", "PAL", "SAX", "TRI"]
    assert country["complete"] is session["complete"] is False
    for result in (country, session):
        for name in FIELDS:
            field = result["fields"][name]
            assert field["status"] == "known"
            assert field["complete"] is False and field["period"] == "current"
            assert field["unit"] == "country_tag" and field["scale"] == 1
        provenance = result["source"]["provenance"]
        assert provenance["country_selector_semantics"] == "global_empire_record_not_membership"
        assert provenance["read_only"] is True
        assert provenance["native_function_invoked"] is False
        assert provenance["actual_UI_observed"] is False
        assert provenance["atomic_snapshot"] is False
        assert len(provenance["capture_report_sha256"]) == 64
        assert provenance["profile_sha256"] == PROFILE_SHA

    expected_installation = base.session.directory / "installation.json"
    assert captures == [(expected_installation, "FRA")] * 2
    assert len(validations) == len(projections) == 2
    assert calls == ["validate", "project", "validate", "project"]
    assert validations[0][0] == report and projections[0] == report
    public = repr((country, session))
    for private in ("raw_inputs", "raw_reads", "0x123456789abcdef0",
                    "0x0fedcba987654321", "0x1111222233334444",
                    "0x5555666677778888"):
        assert private not in public


def test_known_empty_electors_and_unknown_emperor_remain_field_independent(
        tmp_path, monkeypatch):
    projection = {
        "emperor": {"status": "unknown", "reason": "MISSING_EMPEROR",
                    "value": "BAD", "raw_inputs": {"ptr": "0xaaaa"}},
        "electors": {"status": "known", "value": [],
                     "raw_inputs": {"ptr": "0xbbbb"}},
    }
    source, base, *_ = make_source(tmp_path, monkeypatch, projection=projection)
    result = source.read(make_query(), base.context())
    assert result["fields"]["emperor"]["status"] == "unknown"
    assert "value" not in result["fields"]["emperor"]
    assert result["fields"]["electors"]["status"] == "known"
    assert result["fields"]["electors"]["value"] == []
    assert "0xaaaa" not in repr(result) and "0xbbbb" not in repr(result)


def test_planned_s01_fields_stay_unsupported_without_capture(tmp_path, monkeypatch):
    source, base, _, captures, validations, projections, _ = make_source(
        tmp_path, monkeypatch)
    result = source.read(make_query(fields=["reforms", "empire_status"]), base.context())
    assert {name: value["status"] for name, value in result["fields"].items()} == {
        "reforms": "unsupported", "empire_status": "unsupported"}
    assert captures == validations == projections == []


@pytest.mark.parametrize("validation_result", [False, 1, None])
def test_capture_validator_must_return_literal_true(
        tmp_path, monkeypatch, validation_result):
    source, base, _, captures, validations, projections, calls = make_source(
        tmp_path, monkeypatch, validation_result=validation_result)
    result = source.read(make_query(), base.context())
    assert all(result["fields"][name]["status"] == "unknown" for name in FIELDS)
    assert all(result["fields"][name]["reason"] == "EMPIRE_CAPTURE_NOT_VALIDATED"
               and "value" not in result["fields"][name] for name in FIELDS)
    assert len(captures) == len(validations) == 1
    assert projections == [] and calls == ["validate"]


@pytest.mark.parametrize("projection", [
    {"emperor": {"status": "known", "value": "HAB"},
     "electors": {"status": "known", "value": []}, "extra": "0xdeadbeef"},
    {"emperor": {"status": "known", "value": "0xdeadbeef"},
     "electors": {"status": "known", "value": []}},
    {"emperor": {"status": "known", "value": "HAB"},
     "electors": {"status": "known", "value": ["BOH", "BOH"]}},
    {"emperor": {"status": "known", "value": "HAB"},
     "electors": {"status": "known", "value": [True]}},
])
def test_invalid_projection_is_retracted_without_leaking_private_values(
        tmp_path, monkeypatch, projection):
    source, base, _, captures, validations, projections, _ = make_source(
        tmp_path, monkeypatch, projection=projection)
    result = source.read(make_query(), base.context())
    for name in FIELDS:
        assert result["fields"][name]["status"] == "unknown"
        assert result["fields"][name]["reason"] == "EMPIRE_CAPTURE_SHAPE_INVALID"
        assert "value" not in result["fields"][name]
    assert len(captures) == len(validations) == len(projections) == 1
    for private in ("raw_inputs", "raw_reads", "0x123456789abcdef0",
                    "0xdeadbeef", "0x5555666677778888"):
        assert private not in repr(result)


def test_capture_and_projection_exceptions_do_not_leak_messages_or_pointers(
        tmp_path, monkeypatch):
    secret = "secret pointer 0xdeadbeef"
    source, base, _, captures, validations, projections, _ = make_source(
        tmp_path, monkeypatch, capture_error=RuntimeError(secret))
    result = source.read(make_query(), base.context())
    assert all(result["fields"][name]["reason"] == "EMPIRE_CAPTURE_FAILED"
               for name in FIELDS)
    assert secret not in repr(result)
    assert len(captures) == 1 and validations == projections == []

    source, base, _, captures, validations, projections, calls = make_source(
        tmp_path, monkeypatch, projection_error=RuntimeError(secret))
    result = source.read(make_query(), base.context())
    assert all(result["fields"][name]["reason"] == "EMPIRE_CAPTURE_SHAPE_INVALID"
               for name in FIELDS)
    assert secret not in repr(result)
    assert len(captures) == len(validations) == len(projections) == 1
    assert calls == ["validate", "project"]


@pytest.mark.parametrize("obj", [
    {"type": "country", "country": "fra"},
    {"type": "session", "session_id": 3},
    {"type": "province", "province_id": 1},
])
def test_invalid_selectors_are_rejected_before_capture(tmp_path, monkeypatch, obj):
    source, base, _, captures, validations, projections, _ = make_source(
        tmp_path, monkeypatch)
    with pytest.raises(InformationError):
        source.read(make_query(obj=obj), base.context())
    assert captures == validations == projections == []


def test_session_selector_mismatch_and_stale_supplied_context_do_not_capture(
        tmp_path, monkeypatch):
    source, base, _, captures, validations, projections, _ = make_source(
        tmp_path, monkeypatch)
    mismatched = source.read(make_query(obj={"type": "session", "session_id": "other"}),
                             base.context())
    assert all(mismatched["fields"][name]["status"] == "unavailable"
               and mismatched["fields"][name]["reason"] == "EMPIRE_SELECTOR_SESSION_MISMATCH"
               for name in FIELDS)

    stale = base.context()
    stale["world_generation"] += 1
    result = source.read(make_query(), stale)
    assert all(result["fields"][name]["status"] == "unavailable"
               and result["fields"][name]["reason"] == "EMPIRE_CONTEXT_STALE"
               for name in FIELDS)
    assert captures == validations == projections == []


@pytest.mark.parametrize("changed_key", [
    "game_date", "dll_sha256", "world_generation", "physical_client_country",
])
def test_context_drift_after_capture_retracts_all_supported_fields(
        tmp_path, monkeypatch, changed_key):
    def mutate(base):
        if changed_key == "game_date":
            base.current[changed_key] += 1
        elif changed_key == "physical_client_country":
            base.current[changed_key] = "ENG"
        else:
            base.current[changed_key] = "f" * 64 if changed_key == "dll_sha256" else 43

    source, base, _, captures, validations, projections, _ = make_source(
        tmp_path, monkeypatch, after_capture=mutate)
    result = source.read(make_query(), base.context())
    assert all(result["fields"][name]["status"] == "unavailable"
               and result["fields"][name]["reason"] == "EMPIRE_CONTEXT_CHANGED_DURING_CAPTURE"
               and "value" not in result["fields"][name] for name in FIELDS)
    assert len(captures) == 1 and validations == projections == []


def test_session_record_id_creation_and_path_are_bound_across_capture(
        tmp_path, monkeypatch):
    source, base, _, captures, validations, projections, _ = make_source(
        tmp_path, monkeypatch)
    base.session.record["session_id"] = "another-session"
    result = source.read(make_query(), base.context())
    assert all(result["fields"][name]["status"] == "unavailable"
               and result["fields"][name]["reason"] == "EMPIRE_SESSION_RECORD_MISMATCH"
               for name in FIELDS)
    assert captures == validations == projections == []

    def change_creation(fake):
        fake.session.creation_filetime += 1
        fake.session.record["creation_filetime"] += 1

    source, base, _, captures, validations, projections, _ = make_source(
        tmp_path, monkeypatch, after_capture=change_creation)
    result = source.read(make_query(), base.context())
    assert all(result["fields"][name]["status"] == "unavailable"
               and result["fields"][name]["reason"] == "EMPIRE_SESSION_CHANGED_DURING_CAPTURE"
               for name in FIELDS)
    assert len(captures) == 1 and validations == projections == []

    def change_path(fake):
        fake.session.directory = fake.session.directory / "replacement"

    source, base, _, captures, validations, projections, _ = make_source(
        tmp_path, monkeypatch, after_capture=change_path)
    result = source.read(make_query(), base.context())
    assert all(result["fields"][name]["status"] == "unavailable"
               and result["fields"][name]["reason"] == "EMPIRE_SESSION_CHANGED_DURING_CAPTURE"
               for name in FIELDS)
    assert len(captures) == 1 and validations == projections == []


def test_poll_events_is_empty_and_does_not_capture(tmp_path, monkeypatch):
    source, _, _, captures, validations, projections, _ = make_source(
        tmp_path, monkeypatch)
    cursor = {"epoch": 3, "opaque": "unchanged"}
    result = source.poll_events(make_context(), cursor)
    assert result == {"events": [], "cursor": cursor, "complete": True, "gaps": []}
    assert captures == validations == projections == []


def test_query_report_two_and_five_second_periodics_share_and_cancel_independently(
        tmp_path, monkeypatch):
    source, base, _, captures, validations, projections, _ = make_source(
        tmp_path, monkeypatch)
    now = [100.0]
    service = InformationService(
        CompositeSource(base, [source]), tmp_path / "empire-live-service.sqlite3",
        clock=lambda: now[0],
    )
    tools = InformationTools(service)
    direct_query = make_query(obj={"type": "country", "country": "HAB"})
    report_query = make_query(obj={"type": "session"})
    try:
        direct = tools.call("information_query", {
            "view": "full",
            "request_id": "empire-live-direct", "queries": [direct_query],
        })
        report = tools.call("information_manage_report", {
            "request_id": "empire-live-report-create", "operation": "create",
            "config": {"name": "global HRE", "detail": "raw", "queries": [report_query]},
        })["report"]
        rendered = tools.call("information_query", {
            "view": "full",
            "request_id": "empire-live-report-query", "report_id": report["id"],
        })
        direct_fields = direct["items"][0]["fields"]
        assert direct_fields == rendered["items"][0]["fields"]
        assert direct_fields["emperor"]["value"] == "HAB"
        assert direct_fields["electors"]["value"] == [
            "BOH", "BRA", "KOL", "MAI", "PAL", "SAX", "TRI"]
        assert all(direct_fields[name]["complete"] is False for name in FIELDS)
        assert direct["complete"] is rendered["complete"] is False
        assert direct["items"][0]["source"]["provenance"]["actual_UI_observed"] is False
        for private in ("raw_inputs", "raw_reads", "0x123456789abcdef0",
                        "0x1111222233334444", "0x5555666677778888"):
            assert private not in repr(direct["items"][0])

        subscriptions = {}
        for seconds in (2, 5):
            response = tools.call("information_manage_subscription", {
                "request_id": f"empire-live-subscribe-{seconds}",
                "operation": "create",
                "config": {
                    "name": f"HRE every {seconds}s", "enabled": True,
                    "kind": "periodic", "report_id": report["id"],
                    "schedule": {"basis": "real", "unit": "seconds",
                                 "every": seconds, "missed": "coalesce"},
                },
            })
            subscriptions[seconds] = response["subscription"]["id"]

        now[0] = 102.0
        two_second_tick = tools.call("information_tick", {"view": "full"})
        assert two_second_tick["state"] == "processed"
        assert len(two_second_tick["results"]) == 1
        assert two_second_tick["results"][0]["items"][0]["fields"] == direct_fields
        assert two_second_tick["results"][0]["status"] == "partial"

        tools.call("information_manage_subscription", {
            "request_id": "empire-live-cancel-2s", "operation": "cancel",
            "subscription_id": subscriptions[2], "expected_version": 1,
        })
        listed = tools.call("information_manage_subscription", {
            "request_id": "empire-live-subscriptions-after-cancel",
            "operation": "list",
        })["subscriptions"]
        states = {row["id"]: row["state"] for row in listed}
        assert states[subscriptions[2]] == "cancelled"
        assert states[subscriptions[5]] == "active"

        now[0] = 105.0
        five_second_tick = tools.call("information_tick", {"view": "full"})
        assert len(five_second_tick["results"]) == 1
        assert five_second_tick["results"][0]["items"][0]["fields"] == direct_fields
        assert five_second_tick["results"][0]["status"] == "partial"

        tools.call("information_manage_subscription", {
            "request_id": "empire-live-cancel-5s", "operation": "cancel",
            "subscription_id": subscriptions[5], "expected_version": 1,
        })
        now[0] = 110.0
        cancelled_tick = tools.call("information_tick", {"view": "full"})
        assert cancelled_tick["results"] == []
        assert len(captures) == len(validations) == len(projections) == 4
        assert all(call[1] == "FRA" for call in captures)
    finally:
        service.close()
