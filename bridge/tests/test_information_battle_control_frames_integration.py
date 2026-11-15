"""Recorded data through the public query/report/event path, without game access."""
from __future__ import annotations

import pytest

from bridge.information import InformationService
from bridge.information.tools import InformationTools
from bridge.tests.test_information_battle_display import (
    GAME_SHA256, LAND_FIXTURE, NAVAL_FIXTURE, _load,
)
from bridge.tests.test_information_battles import battle_topic_query, event_id, make_source


def _check_display(display, count):
    assert display["status"] == "known"
    value = display["value"]
    assert value["full_display_complete"] is False
    assert value["runtime_popup_verified"] is False
    frames = [control for control in value["controls"] if "native_frame_requests" in control]
    assert len(frames) == count
    for control in frames:
        side = control['side_binding']
        assert side['status'] == 'known'
        assert side['value']['combat_side_index'] == (0 if control['template_key'].startswith('OUR') else 1)
        requests = control["native_frame_requests"]
        assert requests["status"] == "known"
        assert requests["native_call_observed"] is False
        assert requests["runtime_widget_state_verified"] is False
        assert len(requests["requests"]) == len(control["inputs"])
        assert [row["pair_index"] for row in requests["requests"]] == [
            row["pair_index"] for row in control["inputs"]
        ]
        asset = control["declared_frame_asset"]
        assert asset["widget_type"] == "iconType"
        assert asset["active_runtime_definition_verified"] is False
        assert asset["actual_widget_state_verified"] is False
        if control["value_kind"] == "numeric_or_frame":
            assert asset["sprite_type"] == "GFX_stars_small"
            assert asset["declared_frame_count"] == 13
            for request in requests["requests"]:
                converted = request["parsed"]["bits_u32"]
                assert request["virtual_setter_request"]["vtable_offset"] == "0xa8"
                assert request["virtual_setter_request"]["arg_u32"] == (converted + 1) & 0xffffffff
        else:
            assert asset["sprite_type"] == "GFX_leader_types"
            assert asset["declared_frame_count"] == 7
        # A computed icon/frame request is still not a final text string.
        assert control["display_text"]["status"] == "unsupported"
    return frames


@pytest.mark.parametrize(
    ("name", "observer", "message", "count"),
    [(LAND_FIXTURE, "FRA", "3", 10), (NAVAL_FIXTURE, "KEL", "8", 8)],
)
def test_recorded_frame_requests_match_query_report_and_event(tmp_path, name, observer, message, count):
    fixture, _decoded, _display = _load(name)
    source, _primary, fixture, _db, _payload = make_source(
        tmp_path, fixture=fixture, observer=observer, message_ids=(message,),
    )
    service = InformationService(source, tmp_path / "service.sqlite3")
    tools = InformationTools(service)
    query = battle_topic_query("B04", ["details", "raw_text"], selected_event=event_id(fixture, message))
    try:
        topic = next(topic for topic in source.catalog() if topic["topic_id"] == "B04")
        assert topic["fields"]["details"]["frame_requests_revision"] == 1
        direct = service.query("frames-query", queries=[query])["items"][0]
        assert direct["source"]["projection_version"] == 30
        assert direct["source"]["name"] == "IBOW.v4"
        assert direct["source"]["mode"] == "recorded"
        display = direct["fields"]["details"]["value"]["display"]
        _check_display(display, count)
        assert direct["fields"]["raw_text"]["status"] == "unknown"
        report = tools.call("information_manage_report", {
            "request_id": "frames-report", "operation": "create",
            "config": {"name": "recorded frame conversion", "detail": "raw", "queries": [query]},
        })["report"]
        rendered = tools.call("information_query", {
            "view": "full",
            "request_id": "frames-report-query", "report_id": report["id"],
        })
        assert rendered["items"][0]["fields"]["details"] == direct["fields"]["details"]
        tools.call("information_manage_subscription", {
            "request_id": "frames-subscription", "operation": "create",
            "config": {"name": "recorded frames event", "kind": "event", "report_id": report["id"],
                       "enabled": True,
                       "binding": {"session_id": fixture["provenance"]["session_id"], "observer": observer,
                                   "game_version": "1.37.4", "game_sha256": GAME_SHA256},
                       "event": {"types": ["battle_observation"]}},
        })
        tick = tools.call("information_tick", {"view": "full"})
        assert len(tick["results"]) == 1
        delivered = tick["results"][0]["items"][0]
        assert delivered["source"]["projection_version"] == 30
        assert delivered["fields"]["details"] == direct["fields"]["details"]
        assert delivered["fields"]["raw_text"] == direct["fields"]["raw_text"]
        assert tick["results"][0]["complete"] is False
        assert tools.call("information_tick", {"view": "full"})["results"] == []
    finally:
        service.close()
