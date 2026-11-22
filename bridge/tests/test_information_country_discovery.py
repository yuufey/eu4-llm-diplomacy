"""Offline contract tests for the bounded live C02 country source."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information.catalog import get_topic, list_topics
from bridge.information.composite import CompositeSource
from bridge.information.country_discovery import (
    FIELD, NativeCountryDiscoverySource,
)
from bridge.information.model import InformationError
from bridge.information.service import InformationService
from bridge.information.tools import InformationTools


GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
DLL_SHA = "f1c0a589a9922bae5c395b564b3419748f5d6d789d565d5d78b0f86ab8358138"
CREATION = 134380633247930565
PROFILE_SHA = "a" * 64
ALL_C02_FIELDS = tuple(get_topic("C02")["fields"])
DEFAULT_TAGS = ["ENG", "FRA", "POR"]


def make_context(**overrides):
    context = {
        "status": "ready",
        "mode": "live",
        "complete": True,
        "observer": "FRA",
        "session_id": "country-discovery-test-session",
        "game_version": "1.37.4",
        "game_sha256": GAME_SHA,
        "dll_sha256": DLL_SHA,
        "game_date": 56556984,
        "world_generation": 7,
        "physical_client_country": "POR",
    }
    context.update(overrides)
    return context


def make_projection(tags=None, **overrides):
    tags = list(DEFAULT_TAGS if tags is None else tags)
    field = {
        "status": "known",
        "value": tags,
        "candidate_count": 1380,
        "existing_candidate_count": 320,
        "domain_complete": False,
        "country_existence_filter_applied": True,
    }
    field.update(overrides)
    return {FIELD: field}


class FakeBase:
    event_types = ()

    def __init__(self, directory: Path, context=None):
        self.current = deepcopy(context or make_context())
        self.session = SimpleNamespace(
            directory=directory,
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


class FakeCapture:
    PROFILE_SHA256 = PROFILE_SHA

    def __init__(self, *, projection=None, validation=True, report=None,
                 capture_error=None, validation_error=None, projection_error=None,
                 on_capture=None, on_validate=None):
        self.projection = deepcopy(projection if projection is not None else make_projection())
        self.validation = validation
        self.report = deepcopy(report if report is not None else {
            "schema": "information.country_discovery_capture.v1",
            "observer": "FRA",
            "private": {"country_pointer": "0x123456789abcdef0"},
        })
        self.capture_error = capture_error
        self.validation_error = validation_error
        self.projection_error = projection_error
        self.on_capture = on_capture
        self.on_validate = on_validate
        self.captures = []
        self.validations = []
        self.projections = []

    def capture(self, installation, *, observer="FRA"):
        self.captures.append((installation, observer))
        if self.on_capture:
            self.on_capture()
        if self.capture_error:
            raise self.capture_error
        return deepcopy(self.report)

    def validate_capture(self, report, context, creation):
        self.validations.append((deepcopy(report), deepcopy(context), creation))
        if self.on_validate:
            self.on_validate()
        if self.validation_error:
            raise self.validation_error
        return self.validation

    def project_fields(self, report):
        self.projections.append(deepcopy(report))
        if self.projection_error:
            raise self.projection_error
        return deepcopy(self.projection)


def make_query(*, obj=None, fields=None, parameters=None):
    return {
        "topic": "C02",
        "object": deepcopy(obj or {"type": "session"}),
        "fields": list(fields if fields is not None else [FIELD]),
        "parameters": deepcopy(parameters or {}),
    }


def make_source(tmp_path, *, context=None, backend=None):
    base = FakeBase(tmp_path, context)
    backend = backend or FakeCapture()
    return NativeCountryDiscoverySource(base, capture=backend), base, backend


def test_catalog_owns_only_partial_country_tag_field(tmp_path):
    source, base, _ = make_source(tmp_path)
    topic = source.catalog()[0]
    assert topic["topic_id"] == "C02"
    assert set(topic["fields"]) == {FIELD}
    assert topic["triggers"] == ["query", "periodic"]
    assert "change" not in topic["triggers"]
    field = topic["fields"][FIELD]
    assert field["coverage"] == "partial"
    assert field["complete"] is False
    assert field["period"] == "current"
    assert field["unit"] == "country_tag"
    assert field["supported_object_types"] == ["session", "country"]
    assert "ORDINARY_COUNTRY_CANDIDATE_DOMAIN_IS_BOUNDED" in field["gaps"]

    expected_fields = {item["topic_id"]: set(item["fields"]) for item in base.catalog()}
    merged = CompositeSource(base, [source]).catalog()
    assert len(merged) == len(expected_fields)
    assert {item["topic_id"]: set(item["fields"]) for item in merged} == expected_fields
    c02 = next(item for item in merged if item["topic_id"] == "C02")
    assert set(c02["fields"]) == set(ALL_C02_FIELDS)
    assert {name for name, item in c02["fields"].items()
            if item["coverage"] == "partial"} == {FIELD}
    assert all(item["coverage"] == "planned" for name, item in c02["fields"].items()
               if name != FIELD)


def test_known_empty_existing_set_is_distinct_from_unknown(tmp_path):
    known_source, known_base, backend = make_source(
        tmp_path / "known", backend=FakeCapture(projection=make_projection(
            [], candidate_count=1380, existing_candidate_count=0)))
    known = known_source.read(make_query(), known_base.context())
    item = known["fields"][FIELD]
    assert item["status"] == "known" and item["value"] == []
    assert item["candidate_count"] == 1380
    assert item["existing_candidate_count"] == 0
    assert item["country_existence_filter_applied"] is True
    assert item["domain_complete"] is False
    assert item["complete"] is False

    unknown_source, unknown_base, unknown_backend = make_source(
        tmp_path / "unknown", backend=FakeCapture(validation=False))
    unknown = unknown_source.read(make_query(), unknown_base.context())
    item = unknown["fields"][FIELD]
    assert item["status"] == "unknown"
    assert item["reason"] == "C02_CAPTURE_NOT_VALIDATED"
    assert "value" not in item
    assert unknown_backend.projections == []
    assert len(backend.captures) == 1
    assert len(unknown_backend.captures) == 1


def test_known_tags_are_sorted_sanitized_and_may_include_observer(tmp_path):
    source, base, backend = make_source(tmp_path)
    result = source.read(make_query(), base.context())
    field = result["fields"][FIELD]
    assert field == {
        "status": "known", "value": DEFAULT_TAGS, "unit": "country_tag", "scale": 1,
        "period": "current", "complete": False,
        "basis": "native_exists_and_knows_country_for_resolved_ordinary_refs",
        "candidate_count": 1380, "existing_candidate_count": 320,
        "country_existence_filter_applied": True, "domain_complete": False,
    }
    assert result["source"]["complete"] is False
    provenance = result["source"]["provenance"]
    assert provenance["observer"] == "FRA"
    assert provenance["actual_UI_observed"] is False
    assert provenance["domain_complete"] is False
    assert len(provenance["capture_report_sha256"]) == 64
    assert provenance["profile_sha256"] == PROFILE_SHA
    assert backend.captures == [(base.session.directory / "installation.json", "FRA")]
    for private in ("private", "country_pointer", "0x123456789abcdef0", "raw_reads"):
        assert private not in repr(result)


@pytest.mark.parametrize("projection", [
    make_projection(["FRA", "FRA"]),
    make_projection(["FRA", "ENG", "POR"]),
    make_projection(["ENG", "fr1", "POR"]),
    make_projection(["ENG"], candidate_count=0, existing_candidate_count=0),
    make_projection(["ENG", "FRA"], candidate_count=True),
    make_projection(["ENG", "FRA"], existing_candidate_count=True),
    make_projection(["ENG", "FRA"], existing_candidate_count=1),
    make_projection(["ENG", "FRA"], existing_candidate_count=1381),
    make_projection(["ENG", "FRA"], candidate_count=4097),
    make_projection(["ENG", "FRA"], domain_complete=True),
    make_projection(["ENG", "FRA"], country_existence_filter_applied=False),
    {FIELD: {key: value for key, value in make_projection()[FIELD].items()
             if key != "country_existence_filter_applied"}},
    {FIELD: {"status": "unknown", "reason": "PRIVATE_UNKNOWN"}},
    {FIELD: {**make_projection()[FIELD], "private_pointer": "0xdeadbeef"}},
])
def test_malformed_or_private_projection_is_retracted(tmp_path, projection):
    source, base, backend = make_source(
        tmp_path, backend=FakeCapture(projection=projection))
    result = source.read(make_query(), base.context())
    item = result["fields"][FIELD]
    assert item["status"] == "unknown"
    assert item["reason"] == "C02_CAPTURE_SHAPE_INVALID"
    assert "value" not in item
    assert "0xdeadbeef" not in repr(result)
    assert len(backend.captures) == len(backend.validations) == len(backend.projections) == 1


@pytest.mark.parametrize("foreign_tag", ["ENG", "POR"])
def test_foreign_country_selector_is_denied_and_configured_country_is_sampled(tmp_path, foreign_tag):
    source, base, backend = make_source(tmp_path)
    foreign = source.read(make_query(obj={"type": "country", "country": foreign_tag}),
                          base.context())
    assert foreign["fields"][FIELD]["status"] == "not_applicable"
    assert foreign["fields"][FIELD]["reason"] == "C02_OBSERVER_DISCOVERY_VIEW_ONLY"

    base.current["observer"] = "ENG"
    configured = source.read(make_query(), base.context())
    assert configured["fields"][FIELD]["status"] == "known"
    assert backend.captures[0][1] == 'ENG'


def test_physical_client_tag_does_not_determine_nonplayer_admission(tmp_path):
    source, base, backend = make_source(tmp_path)
    base.current["physical_client_country"] = "FRA"
    result = source.read(make_query(), base.context())
    assert result["fields"][FIELD]["status"] == "known"
    assert len(backend.validations) == 1


def test_session_selector_and_stale_context_do_not_capture(tmp_path):
    source, base, backend = make_source(tmp_path)
    mismatched = source.read(
        make_query(obj={"type": "session", "session_id": "other"}), base.context())
    assert mismatched["fields"][FIELD]["status"] == "unavailable"
    assert mismatched["fields"][FIELD]["reason"] == "C02_SELECTOR_SESSION_MISMATCH"

    stale = base.context()
    stale["world_generation"] += 1
    result = source.read(make_query(), stale)
    assert result["fields"][FIELD]["status"] == "unavailable"
    assert result["fields"][FIELD]["reason"] == "C02_CONTEXT_STALE"
    assert backend.captures == backend.validations == backend.projections == []


@pytest.mark.parametrize("bad_query", [
    {"topic": "C02", "object": {"type": "country", "country": "fra"},
     "fields": [FIELD], "parameters": {}},
    {"topic": "C02", "object": {"type": "session", "session_id": True},
     "fields": [FIELD], "parameters": {}},
    {"topic": "C02", "object": {"type": "session"},
     "fields": [FIELD, FIELD], "parameters": {}},
    {"topic": "C02", "object": {"type": "session"},
     "fields": [FIELD], "parameters": {"limit": 2}},
    {"topic": "C02", "object": {"type": "province", "province_id": 1},
     "fields": [FIELD], "parameters": {}},
])
def test_invalid_query_shapes_fail_before_capture(tmp_path, bad_query):
    source, base, backend = make_source(tmp_path)
    with pytest.raises(InformationError):
        source.read(bad_query, base.context())
    assert backend.captures == backend.validations == backend.projections == []


def test_planned_only_and_mixed_fields_capture_only_once(tmp_path):
    source, base, backend = make_source(tmp_path)
    planned = next(name for name in ALL_C02_FIELDS if name != FIELD)
    result = source.read(make_query(fields=[planned]), base.context())
    assert result["fields"][planned]["status"] == "unsupported"
    assert backend.captures == backend.validations == backend.projections == []

    mixed = source.read(make_query(fields=[FIELD, planned]), base.context())
    assert mixed["fields"][FIELD]["status"] == "known"
    assert mixed["fields"][planned]["status"] == "unsupported"
    assert len(backend.captures) == len(backend.validations) == len(backend.projections) == 1


@pytest.mark.parametrize("failure", ["capture", "validate", "project"])
def test_capture_validation_and_projection_failures_are_safe(tmp_path, failure):
    secret = "private address 0xdeadbeef"
    kwargs = {
        "capture_error": RuntimeError(secret) if failure == "capture" else None,
        "validation_error": RuntimeError(secret) if failure == "validate" else None,
        "projection_error": RuntimeError(secret) if failure == "project" else None,
    }
    source, base, backend = make_source(tmp_path, backend=FakeCapture(**kwargs))
    result = source.read(make_query(), base.context())
    item = result["fields"][FIELD]
    assert item["status"] == "unknown"
    assert item["reason"] == {
        "capture": "C02_CAPTURE_FAILED",
        "validate": "C02_CAPTURE_SHAPE_INVALID",
        "project": "C02_CAPTURE_SHAPE_INVALID",
    }[failure]
    assert "value" not in item and secret not in repr(result)


def test_context_and_session_drift_retract_values(tmp_path):
    source, base, backend = make_source(tmp_path)
    backend.on_capture = lambda: base.current.update(game_date=base.current["game_date"] + 1)
    result = source.read(make_query(), base.context())
    assert result["fields"][FIELD]["status"] == "unavailable"
    assert result["fields"][FIELD]["reason"] == "C02_CONTEXT_CHANGED_DURING_CAPTURE"
    assert backend.validations == backend.projections == []

    backend.on_capture = None
    backend.on_validate = lambda: base.current.update(world_generation=8)
    result = source.read(make_query(), base.context())
    assert result["fields"][FIELD]["status"] == "unavailable"
    assert result["fields"][FIELD]["reason"] == "C02_CONTEXT_CHANGED_DURING_VALIDATION"
    assert "value" not in result["fields"][FIELD]


def test_session_record_identity_is_required(tmp_path):
    source, base, backend = make_source(tmp_path)
    base.session.record["session_id"] = "another-session"
    result = source.read(make_query(), base.context())
    assert result["fields"][FIELD]["status"] == "unavailable"
    assert result["fields"][FIELD]["reason"] == "C02_SESSION_RECORD_MISMATCH"
    assert backend.captures == backend.validations == backend.projections == []


class FakeClock:
    def __init__(self, now=100.0):
        self.now = float(now)

    def __call__(self):
        return self.now


def test_tools_manual_report_two_periods_and_independent_cancellation(tmp_path):
    source, base, backend = make_source(tmp_path / "session")
    service = InformationService(
        CompositeSource(base, [source]), tmp_path / "service.sqlite3", clock=FakeClock())
    tools = InformationTools(service)
    query = make_query()
    clock = service.clock
    try:
        direct = tools.call("information_query", {
            "view": "full",
            "request_id": "country-discovery-direct", "queries": [query],
        })
        created = tools.call("information_manage_report", {
            "request_id": "country-discovery-report-create", "operation": "create",
            "config": {"name": "FRA country discovery", "detail": "raw", "queries": [query]},
        })["report"]
        replay = tools.call("information_query", {
            "view": "full",
            "request_id": "country-discovery-report-run", "report_id": created["id"],
        })
        direct_field = direct["items"][0]["fields"][FIELD]
        assert direct_field == replay["items"][0]["fields"][FIELD]
        assert direct_field["value"] == DEFAULT_TAGS
        assert direct["items"][0]["complete"] is False

        subscriptions = {}
        for seconds in (2, 5):
            subscriptions[seconds] = tools.call("information_manage_subscription", {
                "request_id": f"country-discovery-subscribe-{seconds}", "operation": "create",
                "config": {
                    "name": f"C02 country discovery every {seconds}s", "enabled": True,
                    "kind": "periodic", "report_id": created["id"],
                    "schedule": {"basis": "real", "unit": "seconds",
                                 "every": seconds, "missed": "coalesce"},
                },
            })["subscription"]["id"]

        clock.now = 102.0
        tick2 = tools.call("information_tick", {"view": "full"})
        assert len(tick2["results"]) == 1
        assert tick2["results"][0]["items"][0]["fields"][FIELD] == direct_field

        tools.call("information_manage_subscription", {
            "request_id": "country-discovery-cancel-2s", "operation": "cancel",
            "subscription_id": subscriptions[2], "expected_version": 1,
        })
        clock.now = 105.0
        tick5 = tools.call("information_tick", {"view": "full"})
        assert len(tick5["results"]) == 1
        assert tick5["results"][0]["items"][0]["fields"][FIELD] == direct_field
        tools.call("information_manage_subscription", {
            "request_id": "country-discovery-cancel-5s", "operation": "cancel",
            "subscription_id": subscriptions[5], "expected_version": 1,
        })
        clock.now = 110.0
        assert tools.call("information_tick", {"view": "full"})["results"] == []
        assert len(backend.captures) == 4
        assert len(backend.validations) == len(backend.projections) == 4
    finally:
        service.close()


def test_change_subscription_is_rejected_by_c02_trigger_contract(tmp_path):
    source, base, backend = make_source(tmp_path / "change")
    service = InformationService(CompositeSource(base, [source]), tmp_path / "change.sqlite3")
    tools = InformationTools(service)
    try:
        report = tools.call("information_manage_report", {
            "request_id": "country-discovery-change-report", "operation": "create",
            "config": {"name": "C02", "detail": "raw", "queries": [make_query()]},
        })["report"]
        with pytest.raises(InformationError, match="does not support change"):
            tools.call("information_manage_subscription", {
                "request_id": "country-discovery-change-create", "operation": "create",
                "config": {
                    "name": "unsupported change", "enabled": True,
                    "kind": "change", "report_id": report["id"],
                    "schedule": {"basis": "real", "unit": "seconds",
                                 "every": 1, "missed": "coalesce"},
                },
            })
        assert backend.captures == backend.validations == backend.projections == []
    finally:
        service.close()
