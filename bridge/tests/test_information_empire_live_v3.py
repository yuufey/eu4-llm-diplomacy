"""Tests for the isolated current passed-reform owner (no game process)."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import empire_live as empire_live_module
from bridge.information.catalog import get_topic, list_topics
from bridge.information.composite import CompositeSource
from bridge.information.empire_live import NativeEmpireSource
from bridge.information.empire_live_v3 import NativeEmpirePassedReformsSource
from bridge.information.service import InformationService
from bridge.information.tools import InformationTools


GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
DLL_SHA = "f1c0a589a9922bae5c395b564b3419748f5d6d789d565d5d78b0f86ab8358138"
CREATION = 134380633247930565
PROFILE_SHA = "c" * 64
REFORMS = ["centralization", "hereditary_monarchy"]


def make_context(**overrides):
    result = {
        "status": "ready", "mode": "live", "complete": True, "observer": "FRA",
        "session_id": "empire-v3-test-session", "game_version": "1.37.4",
        "game_sha256": GAME_SHA, "dll_sha256": DLL_SHA, "game_date": 56556984,
        "world_generation": 57, "physical_client_country": "POR",
    }
    result.update(overrides)
    return result


class FakeBase:
    event_types = ()

    def __init__(self, tmp_path, context=None):
        self.current = deepcopy(context or make_context())
        session_dir = tmp_path / "session"
        session_dir.mkdir(parents=True, exist_ok=True)
        self.session = SimpleNamespace(
            directory=session_dir, creation_filetime=CREATION,
            record={"session_id": self.current["session_id"],
                    "creation_filetime": CREATION},
        )

    def context(self):
        return deepcopy(self.current)

    def catalog(self):
        return list_topics()

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": deepcopy(cursor or {}),
                "complete": True, "gaps": []}


def make_projection(reforms=REFORMS):
    return {
        "emperor": {"status": "known", "value": "HAB",
                     "raw_inputs": {"country_pointer": "0x1111222233334444"}},
        "electors": {"status": "known", "value": ["BOH", "TRI"],
                      "raw_inputs": {"node_pointer": "0x5555666677778888"}},
        "reforms": {"status": "known", "value": deepcopy(reforms),
                    "raw_inputs": {"table_pointer": "0x9999aaaabbbbcccc"},
                    "unexpected_private_payload": {"fullref": "0xdeadbeef"}},
    }


def make_source(tmp_path, monkeypatch, *, projection=None, validation=True,
                capture_error=None, after_capture=None, context=None):
    base = FakeBase(tmp_path, context)
    report = {"schema": "information.empire_capture.v3",
              "observer": "FRA", "raw_reads": [{"address": "0xabcdef"}]}
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
        if isinstance(validation, Exception):
            raise validation
        return validation

    def project_fields(report_arg):
        calls["project"].append(deepcopy(report_arg))
        return deepcopy(projection if projection is not None else make_projection())

    backend = SimpleNamespace(capture=capture, validate_capture=validate_capture,
                              project_fields=project_fields, PROFILE_SHA256=PROFILE_SHA)
    monkeypatch.setattr(empire_live_module, "import_module",
                        lambda _name, _package: backend)
    return NativeEmpirePassedReformsSource(base, capture=capture), base, calls


def make_query(obj=None, fields=None):
    return {"topic": "S01", "object": deepcopy(obj or {"type": "country", "country": "HAB"}),
            "fields": list(fields if fields is not None else ["reforms"]), "parameters": {}}


def test_catalog_owns_only_reforms_and_composes_with_legacy_fields(tmp_path, monkeypatch):
    source, base, _ = make_source(tmp_path, monkeypatch)
    legacy = NativeEmpireSource(base)
    owned = source.catalog()[0]
    assert set(owned["fields"]) == {"reforms"}
    metadata = owned["fields"]["reforms"]
    assert metadata["coverage"] == "partial"
    assert metadata["unit"] == "reform_id" and metadata["period"] == "current"
    assert metadata["complete"] is False
    assert "ACTUAL_UI_DRAW_NOT_OBSERVED" in metadata["gaps"]

    expected_fields = {topic["topic_id"]: set(topic["fields"]) for topic in base.catalog()}
    catalog = CompositeSource(base, [legacy, source]).catalog()
    assert len(catalog) == len(expected_fields)
    assert {topic["topic_id"]: set(topic["fields"]) for topic in catalog} == expected_fields
    s01 = next(t for t in catalog if t["topic_id"] == "S01")
    assert set(s01["fields"]) == set(get_topic("S01")["fields"])
    assert {name for name in ("emperor", "electors", "reforms")
            if s01["fields"][name]["coverage"] == "partial"} == {
                "emperor", "electors", "reforms"}
    assert all(s01["fields"][name]["coverage"] == "planned"
               for name in s01["fields"] if name not in {"emperor", "electors", "reforms"})


def test_country_and_session_selectors_publish_only_current_reform_ids(tmp_path, monkeypatch):
    source, base, calls = make_source(tmp_path, monkeypatch)
    country = source.read(make_query({"type": "country", "country": "HAB"}), base.context())
    session = source.read(make_query({"type": "session"}), base.context())
    assert country["fields"] == session["fields"]
    field = country["fields"]["reforms"]
    assert field["status"] == "known" and field["value"] == REFORMS
    assert field["unit"] == "reform_id" and field["period"] == "current"
    assert field["complete"] is False
    provenance = country["source"]["provenance"]
    assert provenance["actual_UI_observed"] is False
    assert provenance["complete_observer_visibility_evaluated"] is False
    assert provenance["active_effects_evaluated"] is False
    assert provenance["enactment_conditions_evaluated"] is False
    assert provenance["native_function_invoked"] is False
    assert provenance["read_only"] is True
    assert len(calls["capture"]) == len(calls["validate"]) == len(calls["project"]) == 2
    public = repr(country)
    for private in ("raw_inputs", "raw_reads", "0xabcdef", "0x9999aaaabbbbcccc",
                    "0xdeadbeef"):
        assert private not in public


def test_known_empty_passed_reform_list_remains_known_empty(tmp_path, monkeypatch):
    source, base, _ = make_source(tmp_path, monkeypatch, projection=make_projection([]))
    result = source.read(make_query(), base.context())
    assert result["fields"]["reforms"]["status"] == "known"
    assert result["fields"]["reforms"]["value"] == []
    assert result["fields"]["reforms"]["complete"] is False


@pytest.mark.parametrize("bad_ids", [
    ["duplicate", "duplicate"], ["bad id"], ["x" * 129], [1],
])
def test_malformed_or_duplicate_ids_are_not_published(tmp_path, monkeypatch, bad_ids):
    source, base, _ = make_source(tmp_path, monkeypatch, projection=make_projection(bad_ids))
    result = source.read(make_query(), base.context())
    assert result["fields"]["reforms"]["status"] == "unknown"
    assert result["fields"]["reforms"]["reason"] == "EMPIRE_REFORM_IDENTIFIERS_INVALID"


def test_validator_failure_isolated_from_legacy_emperor_and_elector_fields(tmp_path, monkeypatch):
    base = FakeBase(tmp_path)
    old_report = {"schema": "information.empire_capture.v1", "observer": "FRA"}
    new_report = {"schema": "information.empire_capture.v3", "observer": "FRA"}
    old_projection = {
        "emperor": {"status": "known", "value": "HAB"},
        "electors": {"status": "known", "value": ["BOH"]},
    }
    old_backend = SimpleNamespace(
        capture=lambda installation, *, observer: deepcopy(old_report),
        validate_capture=lambda report, context, creation: True,
        project_fields=lambda report: deepcopy(old_projection), PROFILE_SHA256="a" * 64,
    )
    new_backend = SimpleNamespace(
        capture=lambda installation, *, observer: deepcopy(new_report),
        validate_capture=lambda report, context, creation: False,
        project_fields=lambda report: pytest.fail("unvalidated V3 report must not be projected"),
        PROFILE_SHA256=PROFILE_SHA,
    )
    monkeypatch.setattr(empire_live_module, "import_module",
                        lambda name, package: old_backend if name == ".empire_capture" else new_backend)
    old = NativeEmpireSource(base, capture=old_backend.capture)
    new = NativeEmpirePassedReformsSource(base, capture=new_backend.capture)
    composed = CompositeSource(base, [old, new])
    query = make_query({"type": "session"}, ["emperor", "electors", "reforms"])
    result = composed.read(query, base.context())
    assert result["fields"]["emperor"]["status"] == "known"
    assert result["fields"]["electors"]["status"] == "known"
    assert result["fields"]["reforms"]["status"] == "unknown"
    assert result["fields"]["reforms"]["reason"] == "EMPIRE_CAPTURE_NOT_VALIDATED"


@pytest.mark.parametrize("mode,expected", [
    ("capture", "EMPIRE_CAPTURE_FAILED"),
    ("validator_exception", "EMPIRE_CAPTURE_SHAPE_INVALID"),
    ("context_drift", "EMPIRE_CONTEXT_CHANGED_DURING_CAPTURE"),
])
def test_capture_or_context_failure_is_closed_and_field_scoped(tmp_path, monkeypatch, mode, expected):
    drift = (lambda base: base.current.update(game_date=base.current["game_date"] + 1)) \
        if mode == "context_drift" else None
    source, base, _ = make_source(
        tmp_path, monkeypatch,
        capture_error=RuntimeError("private details") if mode == "capture" else None,
        validation=RuntimeError("replay details") if mode == "validator_exception" else True,
        after_capture=drift,
    )
    result = source.read(make_query(), base.context())
    field = result["fields"]["reforms"]
    assert field["status"] in {"unknown", "unavailable"}
    assert field["reason"] == expected
    assert "private details" not in repr(result) and "replay details" not in repr(result)


def test_report_and_independent_two_and_five_second_periodics_share_v3_results(tmp_path, monkeypatch):
    source, base, calls = make_source(tmp_path, monkeypatch, projection=make_projection([]))
    now = [100.0]
    service = InformationService(CompositeSource(base, [source]),
                                tmp_path / "empire-v3.sqlite3", clock=lambda: now[0])
    tools = InformationTools(service)
    query = make_query({"type": "session"})
    try:
        direct = tools.call("information_query", {
            "view": "full",
            "request_id": "v3-direct", "queries": [query]})
        report = tools.call("information_manage_report", {
            "request_id": "v3-report-create", "operation": "create",
            "config": {"name": "passed reforms", "detail": "raw", "queries": [query]},
        })["report"]
        rendered = tools.call("information_query", {
            "view": "full",
            "request_id": "v3-report-read", "report_id": report["id"]})
        public = direct["items"][0]["fields"]
        assert public == rendered["items"][0]["fields"]
        assert public["reforms"]["status"] == "known" and public["reforms"]["value"] == []

        subscriptions = {}
        for seconds in (2, 5):
            response = tools.call("information_manage_subscription", {
                "request_id": f"v3-sub-{seconds}", "operation": "create",
                "config": {"name": f"v3 {seconds}s", "enabled": True,
                           "kind": "periodic", "report_id": report["id"],
                           "schedule": {"basis": "real", "unit": "seconds",
                                        "every": seconds, "missed": "coalesce"}},
            })
            subscriptions[seconds] = response["subscription"]["id"]
        now[0] = 102.0
        tick2 = tools.call("information_tick", {"view": "full"})
        assert len(tick2["results"]) == 1
        assert tick2["results"][0]["items"][0]["fields"] == public
        tools.call("information_manage_subscription", {
            "request_id": "v3-cancel-2", "operation": "cancel",
            "subscription_id": subscriptions[2], "expected_version": 1})
        now[0] = 105.0
        tick5 = tools.call("information_tick", {"view": "full"})
        assert len(tick5["results"]) == 1
        assert tick5["results"][0]["items"][0]["fields"] == public
        tools.call("information_manage_subscription", {
            "request_id": "v3-cancel-5", "operation": "cancel",
            "subscription_id": subscriptions[5], "expected_version": 1})
        assert len(calls["capture"]) == 4
    finally:
        service.close()
