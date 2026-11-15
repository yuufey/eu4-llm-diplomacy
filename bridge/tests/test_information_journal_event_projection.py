"""C04 delivers the same durable request snapshot as its event envelope."""
from contextlib import closing
from copy import deepcopy

import pytest

from bridge.information import InformationService
from bridge.information.tools import InformationTools
from bridge.tests.test_information_country_modifier_events import make_source


QUERY = {
    "topic": "C04", "object": {"type": "session"},
    "fields": ["event_id", "event_type", "event_objects", "event_payload"],
    "parameters": {"event_type": "diplomatic_request_result"},
}


def test_c04_request_result_delivers_frozen_fields_without_a_request_selector(tmp_path, monkeypatch):
    session, journal, source = make_source(tmp_path)
    request_id = "c04-request-result"
    journal.register(request_id, {
        "action_id": "offer_alliance", "actor": "FRA", "recipient": "SAV",
        "phase": "initiate", "parameters": {},
    })
    for state in ("queued", "consumed", "constructed"):
        journal.transition(request_id, state)
    claim = journal.claim_submission(request_id, submission_id="fixture-submission")
    journal.mark_submitted(request_id, claim.claim_token, {"event": "native_submission", "submitted": True})
    journal.mark_executed(request_id, {"alliance_after": True, "native_state": 2}, event_id="fixture-execution")

    def no_fresh_request(*args, **kwargs):
        pytest.fail("event projection must use the frozen request snapshot")

    monkeypatch.setattr(source.diplomacy_tools, "get_diplomatic_result", no_fresh_request)
    database = tmp_path / "information.sqlite3"
    try:
        with closing(InformationService(source, database)) as service:
            tools = InformationTools(service)
            report = tools.call("information_manage_report", {
                "request_id": "c04-result-report", "operation": "create",
                "config": {"name": "Diplomatic results", "detail": "full", "queries": [QUERY]},
            })["report"]
            tools.call("information_manage_subscription", {
                "request_id": "c04-result-subscription", "operation": "create",
                "config": {"name": "Diplomatic results", "kind": "event", "report_id": report["id"],
                           "enabled": True, "event": {"types": ["diplomatic_request_result"],
                                                      "actors": ["FRA"], "recipients": ["SAV"]}},
            })
            delivered = tools.call("information_tick", {})["results"]
            assert len(delivered) == 1
            full = tools.call("information_get_result", {"result_id": delivered[0]["result_id"], "view": "full"})
            fields = full["items"][0]["fields"]
            assert all(field["status"] == "known" for field in fields.values())
            assert fields["event_id"]["value"] == full["event"]["event_id"]
            assert fields["event_payload"]["value"] == full["event"]["payload"]
            assert fields["event_payload"]["value"]["request"]["game_outcome"] == "executed"
            assert delivered[0]["items"][0]["event_payload"]["request"]["game_outcome"] == "executed"
            assert tools.call("information_tick", {})["results"] == []

        session.game_date += 24
        monkeypatch.setattr(journal, "lookup_request", no_fresh_request)
        replay = source.replay_event(deepcopy(QUERY), source.context(), full["event"])
        assert replay["fields"] == fields
        assert replay["source"]["projection"] == "event_snapshot"
        for selector in ({"request_id": request_id}, {"request_id": "different-request"},
                         {"event_type": "evidence"}, {"case": "unrelated-case"}):
            selected_query = deepcopy(QUERY)
            selected_query["parameters"].update(selector)
            selected = source.replay_event(selected_query, source.context(), full["event"])
            expected_status = "known" if selector == {"request_id": request_id} else "unavailable"
            assert all(field["status"] == expected_status for field in selected["fields"].values())
        with closing(InformationService(source, database)) as reopened:
            tools = InformationTools(reopened)
            assert tools.call("information_get_result", {"result_id": full["result_id"], "view": "full"}) == full
    finally:
        journal.close()
