"""Public S02 faith projection tests using a stub capture validator.

These tests exercise the public DTO and shared query/report/scheduler routes.
They do not validate the country-faith raw RPM trace; that is covered by the
capture module's own validator tests.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import InformationService
from bridge.information.catalog import list_topics
from bridge.information.composite import CompositeSource
from bridge.information.country_faith import NativeCountryFaithSource
from bridge.information.model import InformationError, canonical
from bridge.information.tools import InformationTools
import bridge.information.country_faith as faith_module


GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
CREATION = 134376782534496994


def make_context(*, physical_country="POR"):
    return {
        "status": "ready",
        "mode": "live",
        "complete": True,
        "observer": "FRA",
        "session_id": "faith-public-session",
        "game_version": "1.37.4",
        "game_sha256": GAME_SHA,
        "game_date": 56564448,
        "physical_client_country": physical_country,
    }


def make_report(target="ENG", *, gate_status="known", admitted=True,
                field_status="known", name_text="天主教", raw_hex=None,
                icon=3, reason=None):
    if raw_hex is None:
        raw_hex = (
            "10295911494e105965" if name_text == "天主教"
            else name_text.encode("ascii").hex()
        )
    faith_field = {
        "status": field_status,
        "value": {
            "primary_religion_name": {
                "text": name_text,
                "raw_hex": raw_hex,
                "encoding": "eu4_escape",
            },
            "icon_frame_request": icon,
            "unapproved_extra": "must not escape",
        },
        "raw_inputs": {
            "country_pointer": "0x123456789abcdef0",
            "native_bytes": "636174686f6c6963",
        },
    }
    if reason is not None:
        faith_field["reason"] = reason
    return {
        "schema": "information.country_faith_capture.v1",
        "status": "observed",
        "completed": True,
        "observation": {
            "backend": {
                "observer": {"tag": "FRA", "private_pointer": "0x2233445566778899"},
                "targets": [{
                    "tag": target,
                    "fullref": "0x123456789abcdef0",
                    "admission_by_pass": {
                        "pass1": {"status": gate_status, "admitted": admitted},
                        "pass2": {"status": gate_status, "admitted": admitted},
                    },
                    "fields": {"S02.faith": faith_field},
                }],
            },
        },
        "raw_reads": [{"label": "private.trace", "address": "0x123456789abcdef0"}],
    }


class Base:
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
        self.on_capture = None

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
            "source": {"name": "fixture_primary", "mode": "live"},
        }


def make_query(target="ENG", fields=None, parameters=None):
    return {
        "topic": "S02",
        "object": {"type": "country", "country": target},
        "fields": fields if fields is not None else ["faith"],
        "parameters": parameters if parameters is not None else {},
    }


def make_source(tmp_path, monkeypatch, *, target="ENG", report=None,
                valid=True, after_capture=None):
    context = make_context()
    base = Base(tmp_path, context)
    if after_capture is not None:
        base.on_capture = after_capture
    report = deepcopy(report if report is not None else make_report(target))
    captures = []
    validations = []

    def capture(installation, *, country, observer):
        captures.append((installation, country, observer))
        if base.on_capture is not None:
            base.on_capture(base)
        return deepcopy(report)

    def validate_capture(actual_report, actual_context, creation, actual_target):
        validations.append((deepcopy(actual_report), deepcopy(actual_context), creation, actual_target))
        return valid

    validator_module = SimpleNamespace(validate_capture=validate_capture)
    monkeypatch.setattr(faith_module, "import_module", lambda _name, _package: validator_module)
    source = NativeCountryFaithSource(base, capture=capture)
    return source, base, report, captures, validations


@pytest.mark.parametrize("target", ["ENG", "FRA"])
def test_known_value_is_a_whitelisted_projection_for_foreign_or_observer_country(
        tmp_path, monkeypatch, target):
    """Fake validator is projection scaffolding, not raw-trace validation."""
    report = make_report(target, name_text="church_of_england", icon=7)
    source, base, _, captures, validations = make_source(
        tmp_path, monkeypatch, target=target, report=report
    )
    result = source.read(make_query(target), base.context())

    assert result["fields"]["faith"]["status"] == "known"
    field = result["fields"]["faith"]
    assert field["value"] == {
        "primary_religion_name": {
            "text": "church_of_england",
            "raw_hex": "6368757263685f6f665f656e676c616e64",
            "encoding": "eu4_escape",
        },
        "icon_frame_request": 7,
    }
    assert set(field["value"]) == {"primary_religion_name", "icon_frame_request"}
    assert field["partial"] is True and field["complete"] is False
    assert result["complete"] is False
    assert result["source"]["provenance"]["observer"] == "FRA"
    assert result["source"]["provenance"]["target"] == target
    assert result["source"]["provenance"]["actual_UI_observed"] is False
    assert result["source"]["provenance"]["capture_report_sha256"]
    assert captures == [(tmp_path / "installation.json", target, "FRA")]
    assert len(validations) == 1
    assert validations[0][1]["observer"] == "FRA"
    assert validations[0][2:] == (CREATION, target)
    public = repr(result)
    for private in ("raw_inputs", "raw_reads", "country_pointer", "private_pointer", "native_bytes"):
        assert private not in public


def test_invisible_target_never_exports_backend_value(tmp_path, monkeypatch):
    report = make_report("ENG", admitted=False, name_text="catholic", icon=3)
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)
    result = source.read(make_query("ENG"), base.context())
    field = result["fields"]["faith"]
    assert field["status"] == "invisible"
    assert "value" not in field
    assert "raw_inputs" not in repr(result)
    assert field["partial"] is True and field["complete"] is False


def test_display_name_accepts_the_128_byte_limit(tmp_path, monkeypatch):
    text = "a" * 128
    source, base, _, _, _ = make_source(
        tmp_path, monkeypatch, report=make_report("ENG", name_text=text)
    )
    field = source.read(make_query("ENG"), base.context())["fields"]["faith"]
    assert field["status"] == "known"
    assert field["value"]["primary_religion_name"] == {
        "text": text,
        "raw_hex": "61" * 128,
        "encoding": "eu4_escape",
    }


def test_unknown_preserves_bounded_safe_reason_and_no_backend_trace(tmp_path, monkeypatch):
    reason = "FAITH_NATIVE_CACHE_UNRESOLVED_" + "A" * 180
    report = make_report("ENG", field_status="unknown", reason=reason)
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)
    field = source.read(make_query("ENG"), base.context())["fields"]["faith"]
    assert field["status"] == "unknown"
    assert field["reason"] == reason[:128]
    assert len(field["reason"]) <= 128
    assert "value" not in field
    assert "raw_reads" not in repr(field)


@pytest.mark.parametrize("name,icon", [
    ({"text": "not catholic", "raw_hex": "10295911494e105965", "encoding": "eu4_escape"}, 1),
    ({"text": "x", "raw_hex": "0", "encoding": "eu4_escape"}, 1),
    ({"text": "x", "raw_hex": "zz", "encoding": "eu4_escape"}, 1),
    ({"text": "x", "raw_hex": "00", "encoding": "eu4_escape"}, 1),
    ({"text": "x", "raw_hex": "61" * 129, "encoding": "eu4_escape"}, 1),
    ({"text": "x", "raw_hex": "61", "encoding": "utf8"}, 1),
    ({"text": "x", "raw_hex": "61"}, 1),
    ({"text": "catholic", "raw_hex": "636174686f6c6963", "encoding": "eu4_escape"}, True),
    ({"text": "catholic", "raw_hex": "636174686f6c6963", "encoding": "eu4_escape"}, -1),
    ({"text": "catholic", "raw_hex": "636174686f6c6963", "encoding": "eu4_escape"}, 1 << 32),
])
def test_invalid_display_name_or_u32_icon_request_is_unknown_without_value(
        tmp_path, monkeypatch, name, icon):
    report = make_report("ENG", icon=icon)
    report["observation"]["backend"]["targets"][0]["fields"]["S02.faith"]["value"][
        "primary_religion_name"
    ] = name
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)
    field = source.read(make_query("ENG"), base.context())["fields"]["faith"]
    assert field["status"] == "unknown"
    assert field["reason"] == "COUNTRY_FAITH_FIELD_INVALID"
    assert "value" not in field


def test_unknown_admission_and_pointer_like_reason_are_safely_retracted(tmp_path, monkeypatch):
    report = make_report("ENG", gate_status="unknown", admitted=None)
    report["observation"]["backend"]["targets"][0]["admission_by_pass"]["pass2"]["reason"] = (
        "NATIVE_GATE_UNKNOWN:0x123456789abcdef0"
    )
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, report=report)
    field = source.read(make_query("ENG"), base.context())["fields"]["faith"]
    assert field["status"] == "unknown"
    assert field["reason"] == "COUNTRY_FAITH_VIEW_ADMISSION_UNKNOWN"
    assert "value" not in field
    assert "0x123456789abcdef0" not in repr(field)


@pytest.mark.parametrize("query", [
    {"topic": "S02", "object": {"type": "country", "country": "bad"}, "fields": ["faith"]},
    {"topic": "S02", "object": {"type": "country", "country": "ENG", "pointer": 7}, "fields": ["faith"]},
    {"topic": "S02", "object": {"type": "country", "country": "ENG"}, "fields": ["faith", "faith"]},
    {"topic": "S02", "object": {"type": "country", "country": "ENG"}, "fields": ["religion_group"]},
    {"topic": "S02", "object": {"type": "country", "country": "ENG"}, "fields": ["faith"], "parameters": {"detail": "full"}},
    {"topic": "S02", "object": {"type": "country", "country": "ENG"}, "fields": ["faith"], "unexpected": 1},
])
def test_query_rejects_unbounded_objects_fields_and_parameters(tmp_path, monkeypatch, query):
    source, base, _, captures, _ = make_source(tmp_path, monkeypatch)
    with pytest.raises(InformationError):
        source.read(query, base.context())
    assert captures == []


def test_observer_mismatch_and_stale_pre_capture_context_do_not_capture(tmp_path, monkeypatch):
    source, base, _, captures, _ = make_source(tmp_path, monkeypatch)
    wrong_observer = base.context()
    wrong_observer["observer"] = "POR"
    wrong = source.read(make_query("ENG"), wrong_observer)["fields"]["faith"]
    assert wrong["reason"] == "COUNTRY_FAITH_CONTEXT_STALE"
    stale = base.context()
    stale["game_date"] += 1
    result = source.read(make_query("ENG"), stale)
    assert result["fields"]["faith"]["status"] == "unavailable"
    assert result["fields"]["faith"]["reason"] == "COUNTRY_FAITH_CONTEXT_STALE"
    assert captures == []


@pytest.mark.parametrize("mutation,expected", [
    ("context", "COUNTRY_FAITH_CONTEXT_CHANGED_DURING_CAPTURE"),
    ("session", "COUNTRY_FAITH_SESSION_CHANGED_DURING_CAPTURE"),
])
def test_post_capture_context_and_session_revalidation_retracts_value(
        tmp_path, monkeypatch, mutation, expected):
    def mutate(base):
        if mutation == "context":
            base.current["game_date"] += 1
        else:
            base.session.creation_filetime += 1
            base.session.record["creation_filetime"] += 1

    source, base, _, captures, _ = make_source(
        tmp_path, monkeypatch, after_capture=mutate
    )
    result = source.read(make_query("ENG"), base.context())
    field = result["fields"]["faith"]
    assert field["status"] == "unavailable"
    assert field["reason"] == expected
    assert "value" not in field
    assert len(captures) == 1


def test_capture_validator_must_return_true_before_projection(tmp_path, monkeypatch):
    source, base, _, _, _ = make_source(tmp_path, monkeypatch, valid=False)
    field = source.read(make_query("ENG"), base.context())["fields"]["faith"]
    assert field["status"] == "unknown"
    assert field["reason"] == "COUNTRY_FAITH_CAPTURE_INVALID"
    assert "value" not in field


def test_query_report_and_periodic_routes_share_the_same_partial_projection(tmp_path, monkeypatch):
    report = make_report("ENG", name_text="reformed", icon=4)
    context = make_context()
    base = Base(tmp_path, context)
    captured = []

    def capture(_installation, *, country, observer):
        captured.append((country, observer))
        return deepcopy(report)

    validator_module = SimpleNamespace(validate_capture=lambda *_args: True)
    monkeypatch.setattr(faith_module, "import_module", lambda _name, _package: validator_module)
    faith = NativeCountryFaithSource(base, capture=capture)
    now = [100]
    service = InformationService(
        CompositeSource(base, [faith]),
        tmp_path / "faith-information.sqlite3",
        clock=lambda: now[0],
    )
    tools = InformationTools(service)
    query = make_query("ENG")
    try:
        topic = next(item for item in service.source.catalog() if item["topic_id"] == "S02")
        assert topic["fields"]["faith"]["coverage"] == "partial"
        assert topic["fields"]["faith"]["complete"] is False
        assert topic["triggers"] == ["query", "periodic"]

        direct = tools.call("information_query", {
            "view": "full",
            "request_id": "faith-public-query", "queries": [query],
        })
        saved = tools.call("information_manage_report", {
            "request_id": "faith-public-report", "operation": "create",
            "config": {"name": "faith partial", "detail": "raw", "queries": [query]},
        })["report"]
        rendered = tools.call("information_query", {
            "view": "full",
            "request_id": "faith-public-report-query", "report_id": saved["id"],
        })
        assert direct["items"][0]["fields"] == rendered["items"][0]["fields"]
        assert direct["items"][0]["fields"]["faith"]["value"] == {
            "primary_religion_name": {
                "text": "reformed",
                "raw_hex": "7265666f726d6564",
                "encoding": "eu4_escape",
            },
            "icon_frame_request": 4,
        }
        assert direct["complete"] is False

        tools.call("information_manage_subscription", {
            "request_id": "faith-public-subscription-create",
            "operation": "create",
            "config": {
                "name": "faith periodic",
                "enabled": True,
                "kind": "periodic",
                "report_id": saved["id"],
                "schedule": {
                    "basis": "real", "unit": "seconds", "every": 1,
                    "missed": "coalesce",
                },
            },
        })
        now[0] = 102
        tick = tools.call("information_tick", {"view": "full"})
        assert tick["state"] == "processed"
        assert len(tick["results"]) == 1
        periodic = tick["results"][0]
        assert periodic["items"][0]["fields"] == direct["items"][0]["fields"]
        assert periodic["status"] == "partial"
        assert captured == [("ENG", "FRA")] * 3
    finally:
        service.close()
