"""A derived name line reaches existing APIs without becoming native text."""
from bridge.information import InformationService
from bridge.information.tools import InformationTools
from bridge.tests.test_information_battle_display_context_integration import (
    GAME_SHA256, _v7_fixture,
)
from bridge.tests.test_information_battles import battle_topic_query, event_id, make_source


def test_same_event_candidate_reaches_query_report_and_event_without_native_line1(tmp_path):
    fixture, _v6, _v7 = _v7_fixture()
    source, _primary, _stored, _database, _payload = make_source(
        tmp_path, fixture=fixture, observer="FRA", message_ids=("159",))
    selected = event_id(fixture, "159")
    query = battle_topic_query("B04", ["details", "raw_text"], selected_event=selected)
    direct = source.read(query, source.context())
    candidate = direct["fields"]["details"]["value"]["display_context"]["body_candidate"]
    assert candidate["status"] == "known"
    assert candidate["decoded"]["value"] == "BATTLE_OF_PARIS"
    assert candidate["input_source"] == "title_helper_candidate"
    assert candidate["native_name_handoff_verified"] is False
    assert candidate["native_formatter_invoked"] is False
    assert candidate["native_line1_verified"] is False
    assert candidate["complete"] is candidate["full_display_complete"] is False
    assert direct["fields"]["raw_text"]["status"] == "unknown"
    assert direct["source"]["projection_version"] == 30
    service = InformationService(source, tmp_path / "information.sqlite3")
    tools = InformationTools(service)
    try:
        item = service.query("body-candidate-query", queries=[query])["items"][0]
        assert item["fields"]["details"]["value"]["display_context"]["body_candidate"] == candidate
        report = tools.call("information_manage_report", {
            "request_id": "body-candidate-report", "operation": "create",
            "config": {"name": "derived name line", "detail": "full",
                       "queries": [battle_topic_query("B04", ["details", "raw_text"])]},
        })["report"]
        subscription = tools.call("information_manage_subscription", {
            "request_id": "body-candidate-event", "operation": "create",
            "config": {"name": "derived name line event", "kind": "event",
                       "report_id": report["id"], "enabled": True,
                       "binding": {"session_id": fixture["provenance"]["session_id"],
                                   "observer": "FRA", "game_version": "1.37.4",
                                   "game_sha256": GAME_SHA256},
                       "event": {"types": ["battle_observation"]}},
        })["subscription"]
        assert subscription["state"] == "active"
        delivered = tools.call("information_tick", {"view": "full"})["results"]
        assert len(delivered) == 1
        event = delivered[0]
        assert event["event"]["event_id"] == selected
        assert event["items"][0]["fields"]["details"]["value"]["display_context"]["body_candidate"] == candidate
        assert event["items"][0]["fields"]["raw_text"] == item["fields"]["raw_text"]
        assert event["complete"] is False
    finally:
        service.close()
