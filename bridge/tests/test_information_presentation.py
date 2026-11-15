"""Brief presentation preserves business facts and a complete-result lookup."""
from contextlib import closing
from copy import deepcopy

import pytest

from bridge.information.presentation import present_result, present_concise
from bridge.information.service import InformationService
from bridge.information.tools import InformationTools
from bridge.tests.test_information_service import (
    EventAwareSource, FakeClock, FakeOutput, _event, report_config, subscription_config,
)


@pytest.mark.parametrize('value', [None, 'legacy text', {'display_composition': {'status': 'known'}}])
def test_incomplete_battle_composition_cannot_break_brief_business_fields(value):
    original = {'result_id': 'result-old-battle', 'detail': 'brief',
                'items': [{'topic': 'B04', 'fields': {'details': {'status': 'known', 'value': value}}}]}
    before = deepcopy(original)
    result = present_result(original)
    assert result['items'][0]['fields'] == original['items'][0]['fields']
    assert original == before
    if isinstance(value, dict):
        assert result['items'][0]['presentation']['battle_text']['status'] == 'unknown'


def _annotate(sample):
    sample["source"] = {
        "name": "fixture", "gaps": ["SOURCE_LIMITATION"],
        "provenance": {"capture": "byte evidence" * 1000},
    }
    for field in sample["fields"].values():
        field["provenance"] = {"capture": "field evidence"}
    return sample


class ProvenanceSource(EventAwareSource):
    def read(self, query, context):
        return _annotate(super().read(query, context))

    def read_event(self, query, context, event):
        return _annotate(super().read_event(query, context, event))


@pytest.mark.parametrize(('field_name', 'legacy_value'), [
    ('ally', 'SAV'),
    ('willingness', -12),
    ('reasons', [{'value': -12, 'text': 'recorded reason'}]),
    ('land_promise_available', False),
])
def test_d04_mixed_legacy_and_current_fields_keep_each_field_value(field_name, legacy_value):
    values = {
        'ally': [{'country': 'SAV', 'side': 'attacker', 'automatic': False}],
        'willingness': {'SAV': {'score': 20, 'threshold': 1}},
        'reasons': {'SAV': [{'value': 20, 'text': 'promised land'}]},
        'land_promise_available': {'SAV': True},
    }
    fields = {name: {'status': 'known', 'value': deepcopy(value),
                     'source_path': 'participants.candidates'} for name, value in values.items()}
    fields[field_name] = {'status': 'known', 'value': deepcopy(legacy_value)}
    original = {'result_id': 'mixed-d04', 'items': [{'topic': 'D04', 'fields': fields}]}
    before = deepcopy(original)
    expected = {**values, field_name: legacy_value}
    assert present_concise(original)['items'] == [expected]
    assert original == before


def test_brief_preserves_values_units_unknowns_events_and_source_limitations():
    original = {
        "result_id": "result-brief-fixture", "detail": "brief", "complete": False,
        "event": {"payload": {"raw_text": "完整原始战报", "provenance": {"business": True}}},
        "items": [{
            "query": {"topic": "fixture"},
            "fields": {
                "amount": {"status": "known", "value": {"raw": 7000, "provenance": "business value"},
                           "unit": "ducats", "scale": 1000, "complete": False, "period": "month",
                           "unknown_conditions": ["CACHE_FRESHNESS_UNKNOWN"], "provenance": {"capture": "bytes"}},
                "missing": {"status": "unknown", "reason": "NOT_VISIBLE", "gaps": ["VISIBILITY"],
                            "provenance": {"capture": "bytes"}},
            },
            "source": {"name": "composite", "sources": [{"fields": ["amount"], "source": {
                "name": "native", "complete": False, "gaps": ["SOURCE_LIMITATION"],
                "provenance": {"capture": "bytes"},
            }}]},
        }],
    }
    before = deepcopy(original)
    brief = present_result(original)
    assert original == before
    assert brief["event"] == original["event"]
    for name, value in original["items"][0]["fields"].items():
        expected = deepcopy(value)
        expected.pop("provenance")
        assert brief["items"][0]["fields"][name] == expected
    source = brief["items"][0]["source"]["sources"][0]["source"]
    assert source == {"name": "native", "complete": False, "gaps": ["SOURCE_LIMITATION"]}
    assert brief["presentation"]["full_result"] == {
        "tool": "information_get_result", "arguments": {"result_id": original["result_id"]},
    }
    assert present_result(brief) == brief


@pytest.mark.parametrize("detail", ["raw", "full"])
def test_existing_raw_and_full_presentations_preserve_complete_payload(detail):
    result = {"detail": detail, "result_id": "result-fixture", "items": [
        {"source": {"provenance": {"capture": "bytes"}}},
    ]}
    assert present_result(result) == result


def test_public_brief_query_list_and_restart_keep_full_result_access(tmp_path):
    source = ProvenanceSource()
    database = tmp_path / "information.sqlite3"
    with closing(InformationService(source, database)) as service:
        tools = InformationTools(service)
        report = tools.call("information_manage_report", {
            "request_id": "brief-create", "operation": "create", "config": report_config(detail="brief"),
        })["report"]
        arguments = {"request_id": "brief-query", "report_id": report["id"]}
        brief = tools.call("information_query", arguments)
        assert "source" not in brief["items"][0]
        full = tools.call("information_get_result", {"result_id": brief["result_id"], "view": "full"})
        assert full["items"][0]["source"]["provenance"]["capture"]
        assert "presentation" not in full
        assert present_concise(full) == brief
        assert tools.call("information_query", arguments) == brief
        assert len(source.read_calls) == 1
        assert tools.call("information_list_results", {})["results"] == [brief]
    with closing(InformationService(source, database)) as service:
        restored = InformationTools(service).call("information_get_result", {"result_id": full["result_id"], "view": "full"})
        assert restored == full


@pytest.mark.parametrize("kind", ["periodic", "event"])
def test_brief_subscription_tick_and_external_delivery_keep_full_storage(tmp_path, kind):
    source, output, clock = ProvenanceSource(), FakeOutput(), FakeClock()
    with closing(InformationService(source, tmp_path / "information.sqlite3", output=output, clock=clock)) as service:
        tools = InformationTools(service)
        report = tools.call("information_manage_report", {
            "request_id": "brief-create", "operation": "create", "config": report_config(detail="brief"),
        })["report"]
        options = {"kind": kind}
        if kind == "event":
            options["event"] = {"types": ["battle"]}
        tools.call("information_manage_subscription", {
            "request_id": "brief-subscribe", "operation": "create",
            "config": subscription_config(report["id"], **options),
        })
        if kind == "periodic":
            clock.advance(10)
        else:
            event = _event(source, "battle-brief")
            event["payload"] = {"value": {"raw_text": "完整原始战报", "provenance": "business"}, "zero": 0}
            source.event_pages = [{"events": [event], "cursor": {"position": 1}, "complete": True, "gaps": []}]
        brief = tools.call("information_tick", {})["results"][0]
        assert "source" not in brief["items"][0]
        assert "source" not in output.delivered[0]["items"][0]
        full = service.get_result(brief["result_id"])
        assert full["items"][0]["source"]["provenance"]["capture"]
        assert brief == present_concise(full)
        if kind == "event":
            assert brief["event"]["payload"] == {"value": {"raw_text": "完整原始战报"}, "zero": 0}
