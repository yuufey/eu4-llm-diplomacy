"""Offline public-source tests for S02.religion_group."""
from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.country_faith import NativeCountryFaithSource
from bridge.information.model import InformationError
from bridge.information.religion_group import NativeReligionGroupSource
from bridge.information.tools import InformationTools
from bridge.tests import test_information_country_faith as faith_fixture
from bridge.tests import test_information_capture_runtime as runtime_fixture
from tools.serve_information import _build_runtime
import bridge.information.country_faith as faith_module
import bridge.information.religion_group as religion_group_module


PROFILE_SHA256 = "d" * 64


def _group_report(target="ENG", *, admitted=True, gate_status="known",
                  field_status="known", text="christian", raw_hex=None,
                  reason=None):
    if raw_hex is None:
        raw_hex = text.encode("ascii").hex() if text else ""
    group_field = {
        "status": field_status,
        "complete": False,
        "value": {"religion_group_name": {
            "text": text, "raw_hex": raw_hex, "encoding": "eu4_escape",
        }},
        "raw_inputs": {"private_pointer": "0x123456789abcdef0"},
    }
    if reason is not None:
        group_field["reason"] = reason
    return {
        "schema": "information.religion_group_capture.v1",
        "status": "observed",
        "completed": True,
        "observation": {"backend": {
            "observer": {"tag": "FRA", "private_pointer": "0x2233445566778899"},
            "targets": [{
                "tag": target,
                "fullref": "0x123456789abcdef0",
                "admission_by_pass": {
                    "pass1": {"status": gate_status, "admitted": admitted},
                    "pass2": {"status": gate_status, "admitted": admitted},
                },
                "fields": {"S02.religion_group": group_field},
            }],
        }},
        "raw_reads": [{"label": "private.trace", "address": "0x123456789abcdef0"}],
    }


def _group_query(target="ENG", fields=None, parameters=None):
    return faith_fixture.make_query(
        target, fields=fields if fields is not None else ["religion_group"],
        parameters=parameters if parameters is not None else {},
    )


def _make_group_source(base, monkeypatch, *, target="ENG", report=None,
                       valid=True, validator_raises=False, capture_error=None,
                       after_capture=None):
    report = deepcopy(report if report is not None else _group_report(target))
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
        if validator_raises:
            raise ValueError("fixture profile pin mismatch")
        return valid

    validator_module = SimpleNamespace(
        validate_capture=validate_capture,
        PROFILE_SHA256=PROFILE_SHA256,
    )
    monkeypatch.setattr(
        religion_group_module, "import_module",
        lambda _name, _package: validator_module,
    )
    source = NativeReligionGroupSource(base, capture=capture)
    return source, report, calls, validations


def _make_source(tmp_path, monkeypatch, **kwargs):
    base = faith_fixture.Base(tmp_path, faith_fixture.make_context())
    source, report, calls, validations = _make_group_source(base, monkeypatch, **kwargs)
    return source, base, report, calls, validations


def test_catalog_and_fra_observer_allow_fra_or_other_country_target(tmp_path, monkeypatch):
    for target in ("FRA", "ENG"):
        source, base, report, calls, validations = _make_source(
            tmp_path / target, monkeypatch, target=target,
            report=_group_report(target, text="christian"),
        )
        topic = source.catalog()[0]
        assert topic["topic_id"] == "S02"
        assert topic["fields"]["religion_group"]["coverage"] == "partial"
        assert topic["fields"]["religion_group"]["complete"] is False
        assert topic["triggers"] == ["query", "periodic"]
        assert topic["context_scope"] == "visible_scope"
        assert topic["visibility"] == "visible_scope"
        assert topic["observer_scope"] == []

        result = source.read(_group_query(target), base.context())
        field = result["fields"]["religion_group"]
        assert field["status"] == "known"
        assert field["value"] == {"religion_group_name": {
            "text": "christian", "raw_hex": "63687269737469616e", "encoding": "eu4_escape",
        }}
        assert field["partial"] is True and field["complete"] is False
        assert result["complete"] is False
        assert result["source"]["context_scope"] == "visible_scope"
        assert result["source"]["provenance"]["observer"] == "FRA"
        assert result["source"]["provenance"]["target"] == target
        assert result["source"]["provenance"]["actual_UI_observed"] is False
        assert len(result["source"]["provenance"]["capture_report_sha256"]) == 64
        assert result["source"]["provenance"]["profile_sha256"] == PROFILE_SHA256
        assert calls == [(tmp_path / target / "installation.json", target, "FRA")]
        assert validations[0][1]["observer"] == "FRA"
        assert validations[0][2:] == (faith_fixture.CREATION, target)
        assert report["observation"]["backend"]["observer"]["tag"] == "FRA"
        assert base.context()["physical_client_country"] == "POR"
        public = repr(result)
        for private in ("raw_inputs", "raw_reads", "private_pointer", "0x123456789abcdef0"):
            assert private not in public


def test_invisible_target_does_not_export_group_name(tmp_path, monkeypatch):
    source, base, _, _, _ = _make_source(
        tmp_path, monkeypatch,
        report=_group_report("ENG", admitted=False, text="secret_group"),
    )
    result = source.read(_group_query("ENG"), base.context())
    field = result["fields"]["religion_group"]
    assert field["status"] == "invisible"
    assert field["reason"] == "RELIGION_GROUP_NOT_ADMITTED_FOR_OBSERVER"
    assert "value" not in field
    assert "secret_group" not in repr(result)


@pytest.mark.parametrize("mutation", [
    "private", "garbled", "hex_mismatch", "empty", "nul",
])
def test_private_or_malformed_group_name_is_unknown_without_value(tmp_path, monkeypatch, mutation):
    report = _group_report("ENG", text="catholic")
    name = report["observation"]["backend"]["targets"][0]["fields"][
        "S02.religion_group"]["value"]["religion_group_name"]
    if mutation == "private":
        name["private_pointer"] = "0x123456789abcdef0"
    elif mutation == "garbled":
        name["raw_hex"] = "zz"
    elif mutation == "hex_mismatch":
        name["text"] = "protestant"
    elif mutation == "empty":
        name["text"] = ""
        name["raw_hex"] = ""
    else:
        name["text"] = "a"
        name["raw_hex"] = "6100"
    source, base, _, _, _ = _make_source(tmp_path, monkeypatch, report=report)

    field = source.read(_group_query("ENG"), base.context())["fields"]["religion_group"]
    assert field["status"] == "unknown"
    assert field["reason"] == "RELIGION_GROUP_CAPTURE_INVALID"
    assert "value" not in field


@pytest.mark.parametrize("validation_failure", ["false", "raises"])
def test_capture_validator_pin_failure_is_unknown_without_value(
        tmp_path, monkeypatch, validation_failure):
    source, base, _, _, _ = _make_source(
        tmp_path, monkeypatch, valid=validation_failure != "false",
        validator_raises=validation_failure == "raises",
    )
    field = source.read(_group_query("ENG"), base.context())["fields"]["religion_group"]
    assert field["status"] == "unknown"
    assert field["reason"] == "RELIGION_GROUP_CAPTURE_INVALID"
    assert "value" not in field


def test_backend_unknown_does_not_leak_value_or_pointer_reason(tmp_path, monkeypatch):
    report = _group_report("ENG", field_status="unknown", text="private_group",
                           reason="NATIVE_POINTER:0x123456789abcdef0")
    source, base, _, _, _ = _make_source(tmp_path, monkeypatch, report=report)
    field = source.read(_group_query("ENG"), base.context())["fields"]["religion_group"]
    assert field["status"] == "unknown"
    assert field["reason"] == "RELIGION_GROUP_BACKEND_UNKNOWN"
    assert "value" not in field
    assert "0x123456789abcdef0" not in repr(field)


@pytest.mark.parametrize(("mutation", "expected"), [
    ("context", "RELIGION_GROUP_CONTEXT_CHANGED_DURING_CAPTURE"),
    ("session", "RELIGION_GROUP_SESSION_CHANGED_DURING_CAPTURE"),
])
def test_context_or_session_change_after_thrown_capture_retracts_result(
        tmp_path, monkeypatch, mutation, expected):
    def change_then_throw(base):
        if mutation == "context":
            base.current["game_date"] += 1
        else:
            base.session.creation_filetime += 1
            base.session.record["creation_filetime"] += 1

    source, base, _, calls, _ = _make_source(
        tmp_path, monkeypatch, capture_error=RuntimeError("offline fixture"),
        after_capture=change_then_throw,
    )
    result = source.read(_group_query("ENG"), base.context())
    field = result["fields"]["religion_group"]
    assert field["status"] == "unavailable"
    assert field["reason"] == expected
    assert "value" not in field
    assert len(calls) == 1


def test_thrown_capture_without_context_change_is_unknown(tmp_path, monkeypatch):
    source, base, _, _, _ = _make_source(
        tmp_path, monkeypatch, capture_error=RuntimeError("offline fixture"),
    )
    field = source.read(_group_query("ENG"), base.context())["fields"]["religion_group"]
    assert field["status"] == "unknown"
    assert field["reason"] == "RELIGION_GROUP_CAPTURE_FAILED:RuntimeError"
    assert "value" not in field


@pytest.mark.parametrize("query", [
    {"topic": "S02", "object": {"type": "country", "country": "bad"},
     "fields": ["religion_group"]},
    {"topic": "S02", "object": {"type": "country", "country": "ENG", "pointer": 1},
     "fields": ["religion_group"]},
    {"topic": "S02", "object": {"type": "country", "country": "ENG"},
     "fields": ["religion_group", "religion_group"]},
    {"topic": "S02", "object": {"type": "country", "country": "ENG"},
     "fields": ["faith"]},
    {"topic": "S02", "object": {"type": "country", "country": "ENG"},
     "fields": ["religion_group"], "parameters": {"detail": "full"}},
    {"topic": "S02", "object": {"type": "country", "country": "ENG"},
     "fields": ["religion_group"], "unexpected": True},
])
def test_invalid_fields_objects_and_parameters_are_rejected_before_capture(tmp_path, monkeypatch, query):
    source, base, _, calls, _ = _make_source(tmp_path, monkeypatch)
    with pytest.raises(InformationError):
        source.read(query, base.context())
    assert calls == []


def test_observer_mismatch_and_stale_pre_capture_context_are_unavailable(
        tmp_path, monkeypatch):
    source, base, _, calls, _ = _make_source(tmp_path, monkeypatch)
    wrong_observer = base.context()
    wrong_observer["observer"] = "POR"
    wrong = source.read(_group_query("ENG"), wrong_observer)["fields"]["religion_group"]
    assert wrong["reason"] == "RELIGION_GROUP_CONTEXT_STALE"

    stale = base.context()
    stale["game_date"] += 1
    field = source.read(_group_query("ENG"), stale)["fields"]["religion_group"]
    assert field["status"] == "unavailable"
    assert field["reason"] == "RELIGION_GROUP_CONTEXT_STALE"
    assert calls == []


def test_composite_service_routes_faith_and_group_query_report_periodic_then_cancel(
        tmp_path, monkeypatch):
    base = faith_fixture.Base(tmp_path, faith_fixture.make_context())
    faith_report = faith_fixture.make_report("ENG", name_text="reformed", icon=4)
    group_report = _group_report("ENG", text="christian")
    faith_calls = []
    group_calls = []

    def faith_capture(_installation, *, country, observer):
        faith_calls.append((country, observer))
        return deepcopy(faith_report)

    def group_capture(_installation, *, country, observer):
        group_calls.append((country, observer))
        return deepcopy(group_report)

    monkeypatch.setattr(faith_module, "import_module", lambda *_args: SimpleNamespace(
        validate_capture=lambda *_args: True))
    validator_module = SimpleNamespace(validate_capture=lambda *_args: True,
                                        PROFILE_SHA256=PROFILE_SHA256)
    monkeypatch.setattr(religion_group_module, "import_module", lambda *_args: validator_module)
    faith = NativeCountryFaithSource(base, capture=faith_capture)
    group = NativeReligionGroupSource(base, capture=group_capture)
    source = CompositeSource(base, [faith, group])
    now = [100]
    service = InformationService(source, tmp_path / "religion-group-service.sqlite3",
                                 clock=lambda: now[0])
    tools = InformationTools(service)
    query = faith_fixture.make_query("ENG", fields=["faith", "religion_group"])
    try:
        catalog = next(item for item in service.source.catalog() if item["topic_id"] == "S02")
        assert set(catalog["fields"]) >= {"faith", "religion_group"}
        assert catalog["fields"]["religion_group"]["coverage"] == "partial"
        assert catalog["fields"]["religion_group"]["complete"] is False

        direct = tools.call("information_query", {
            "view": "full",
            "request_id": "religion-group-composite-query", "queries": [query],
        })
        direct_fields = direct["items"][0]["fields"]
        assert direct_fields["faith"]["status"] == "known"
        assert direct_fields["religion_group"]["status"] == "known"
        assert direct_fields["religion_group"]["value"]["religion_group_name"]["text"] == "christian"
        assert direct["complete"] is False

        report = tools.call("information_manage_report", {
            "request_id": "religion-group-composite-report-create",
            "operation": "create",
            "config": {"name": "faith and religion group", "detail": "raw",
                       "queries": [query]},
        })["report"]
        rendered = tools.call("information_query", {
            "view": "full",
            "request_id": "religion-group-composite-report-query", "report_id": report["id"],
        })
        assert rendered["items"][0]["fields"] == direct_fields

        subscription = tools.call("information_manage_subscription", {
            "request_id": "religion-group-composite-subscription-create",
            "operation": "create",
            "config": {
                "name": "religion group partial periodic",
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
        assert faith_calls == [("ENG", "FRA")] * 3
        assert group_calls == [("ENG", "FRA")] * 3

        tools.call("information_manage_subscription", {
            "request_id": "religion-group-composite-subscription-cancel",
            "operation": "cancel", "subscription_id": subscription["id"],
            "expected_version": subscription["version"],
        })
        now[0] = 104
        tools.call("information_tick", {"view": "full"})
        assert faith_calls == [("ENG", "FRA")] * 3
        assert group_calls == [("ENG", "FRA")] * 3
    finally:
        service.close()


def test_live_factory_registers_religion_information_with_legacy_children(tmp_path, monkeypatch):
    harness = runtime_fixture.wiring.__wrapped__(monkeypatch)
    import bridge.information.trade_collection as trade_collection_module
    monkeypatch.setattr(trade_collection_module, "NativeTradeCollectionSource",
                        runtime_fixture._Adapter)
    service, journal = _build_runtime(runtime_fixture._live_args(tmp_path))
    try:
        from bridge.information.religion_information import NativeReligionInformationSource

        composed = service.source.primary  # the mocked battle wrapper contains CompositeSource
        adapters = composed.adapters
        religion_sources = [adapter for adapter in adapters
                            if isinstance(adapter, NativeReligionInformationSource)]
        assert len(religion_sources) == 1
        religion = religion_sources[0]
        assert not any(isinstance(adapter, (NativeCountryFaithSource,
                                            NativeReligionGroupSource))
                       for adapter in adapters)
        assert isinstance(religion.faith_source, NativeCountryFaithSource)
        assert isinstance(religion.group_source, NativeReligionGroupSource)
        assert religion.base_source is composed.primary
        assert religion.faith_source.base_source is composed.primary
        assert religion.group_source.base_source is composed.primary
    finally:
        service.close()
        for ingestor in harness.ingestors:
            ingestor.close()
        if journal is not None:
            journal.close()
