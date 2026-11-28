"""Offline delivery of archived native responses through normal query entry points."""
from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge.tests.legacy_france_adapter import FixedFranceDiplomacyTools as DiplomacyTools, FixedFranceObserverSession as ObserverSession
from bridge.diplomacy_journal import DurableJournal
from bridge.information import InformationService
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools


class ArchivedSession(ObserverSession):
    observer = "FRA"

    def __init__(self, directory, fixture):
        record = {
            "experiment_id": "native-result-information",
            "session_id": fixture["source"]["session_id"],
            "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
            "dll_sha256": fixture["source"]["dll_sha256"],
        }
        installation = directory / "installation.json"
        installation.write_text(json.dumps(record), encoding="utf-8")
        super().__init__(installation, directory / "unused-game.exe")
        self.read_count = 0

    def health(self):
        return {"status": "ready", "date_raw": 56554848, "complete": True, "reasons": []}

    def read_native_alliance_inbound_offers(self):
        return []

    def _native_alliance_inbound_context(self, proposal_id):
        assert proposal_id == "a" * 32
        return {"actor": "ENG", "recipient": "FRA", "session_id": self.session_id,
                "action_id": "peace_offer", "family": "peace", "native_proposal_id": 1}

    def read_native_peace_inbound_response(self, *args):
        self.read_count += 1
        return super().read_native_peace_inbound_response(*args)


@pytest.fixture(params=["reject", "accept"])
def archived_backend(tmp_path, request):
    filename = {"reject": "peace_inbound_r44b_real_reject.json",
                "accept": "peace_inbound_r44d_real_accept.json"}[request.param]
    fixture = json.loads((Path(__file__).parent / "fixtures" / filename).read_text(encoding="utf-8"))
    events = [item["event"] for item in fixture["events"]]
    submission = next(item for item in events if item["event"] == "native_peace_inbound_submission_result")
    session = ArchivedSession(tmp_path, fixture)
    journal = DurableJournal(tmp_path / "journal.sqlite3", session.experiment_id, session.session_id)
    request_id = submission["request_id"]
    journal.register(request_id, {"action_id": "peace_offer", "actor": "ENG", "recipient": "FRA",
                                 "phase": request.param, "parameters": {"proposal_id": "a" * 32}})
    for status in ("queued", "consumed", "constructed"):
        journal.transition(request_id, status)
    claim = journal.claim_submission(request_id)
    receipt = ObserverSession._public_native_inbound_submission_receipt(
        submission, request_id, "ENG", request.param, submission["date_raw"], "peace_offer")
    journal.mark_submitted(request_id, claim.claim_token, receipt)
    (tmp_path / "control-probe.jsonl").write_text(
        "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
    backend = DiplomacyTools(journal, session)
    try:
        yield backend, request_id, request.param + "ed"
    finally:
        journal.close()


def result_query(request_id):
    return {"topic": "A05", "object": {"type": "country_pair", "actor": "ENG", "recipient": "FRA"},
            "fields": ["status", "game_outcome", "result", "evidence"],
            "parameters": {"request_id": request_id}}


def test_archived_native_response_delivered_once_and_replayed_without_live_reads(tmp_path, archived_backend, monkeypatch):
    backend, request_id, expected = archived_backend
    source = DiplomacySource(backend)
    database = tmp_path / "information.sqlite3"
    with closing(InformationService(source, database)) as service:
        tools = InformationTools(service)
        event_query = result_query(request_id)
        event_query["parameters"] = {}
        report = tools.call("information_manage_report", {
            "request_id": "report-create", "operation": "create",
            "config": {"name": "archived response", "queries": [event_query], "detail": "full"},
        })["report"]
        tools.call("information_manage_subscription", {
            "request_id": "subscription-create", "operation": "create", "config": {
                "name": "archived response delivery", "kind": "event", "report_id": report["id"], "enabled": True,
                "event": {"types": ["diplomatic_request_result"], "actors": ["ENG"], "recipients": ["FRA"]},
            },
        })
        first = tools.call("information_tick", {"view": "full"})
        assert len(first["results"]) == 1
        delivered = first["results"][0]
        fields = delivered["items"][0]["fields"]
        assert fields["status"]["value"] == expected
        assert fields["game_outcome"]["value"] == expected
        assert fields["result"]["value"]["native_outcome"] == expected
        assert any(item["type"] == "native_response" for item in fields["evidence"]["value"])
        assert delivered["items"][0]["source"]["projection"] == "event_snapshot"
        assert delivered["event"]["game_date"] is None
        assert delivered["event"]["source"]["date_semantics"] == "response_time_unknown"
        assert tools.call("information_tick", {"view": "full"})["results"] == []
        assert backend.session.read_count == 1
        result_id = delivered["result_id"]
    with closing(InformationService(source, database)) as reopened:
        assert reopened.get_result(result_id)["items"] == delivered["items"]
    monkeypatch.setattr(backend, "get_diplomatic_result", lambda *_: pytest.fail("replay performed a native read"))
    snapshot = source.replay_event(result_query(request_id), source.context(), delivered["event"])
    assert snapshot["fields"] == fields
    wrong = deepcopy(result_query(request_id))
    wrong["parameters"]["request_id"] = "another-request"
    assert not source.replay_event(wrong, source.context(), delivered["event"])["complete"]


def test_result_query_rejects_a_different_country_pair(archived_backend):
    backend, request_id, _ = archived_backend
    source = DiplomacySource(backend)
    query = result_query(request_id)
    query["object"]["actor"] = "SAV"
    result = source.read(query, source.context())
    assert result["fields"]["status"]["reason"] == "REQUEST_OBSERVER_SCOPE_MISMATCH"
    assert backend.session.read_count == 0


def test_consumed_response_retried_after_journal_failure(archived_backend, monkeypatch):
    backend, request_id, expected = archived_backend
    source = DiplomacySource(backend)
    method_name = "mark_accepted" if expected == "accepted" else "mark_rejected"
    original = getattr(backend.journal, method_name)

    def fail_persistence(*args, **kwargs):
        raise OSError("injected journal failure")

    monkeypatch.setattr(backend.journal, method_name, fail_persistence)
    failed = source.read(result_query(request_id), source.context())
    assert not failed["complete"]
    assert failed["fields"]["status"]["reason"] == "NATIVE_RESULT_REFRESH_FAILED"
    assert backend.journal.lookup_request(request_id).status == "submitted"
    monkeypatch.setattr(backend.journal, method_name, original)
    recovered = source.read(result_query(request_id), source.context())
    assert recovered["fields"]["status"]["value"] == expected
    assert backend.session.read_count == 1
    assert not backend._pending_native_responses


def test_event_snapshot_keeps_earlier_status_after_journal_changes(archived_backend):
    backend, request_id, expected = archived_backend
    source = DiplomacySource(backend)
    context = source.context()
    earlier = source._journal_event(backend.journal.lookup_request(request_id), context, [])
    assert source.read(result_query(request_id), context)["fields"]["status"]["value"] == expected
    assert source.read_event(result_query(request_id), context, earlier)["fields"]["status"]["value"] == "submitted"


def test_poll_failure_reports_gap_then_retries_without_consuming_response_twice(archived_backend, monkeypatch):
    backend, request_id, expected = archived_backend
    source = DiplomacySource(backend)
    context = source.context()
    method_name = "mark_accepted" if expected == "accepted" else "mark_rejected"
    original = getattr(backend.journal, method_name)

    def fail_persistence(*args, **kwargs):
        raise OSError("injected journal failure")

    monkeypatch.setattr(backend.journal, method_name, fail_persistence)
    first = source.poll_events(context, None)
    assert not first["complete"]
    assert "NATIVE_RESULT_REFRESH_FAILED:" + request_id in first["gaps"]
    monkeypatch.setattr(backend.journal, method_name, original)
    recovered = source.poll_events(context, first["cursor"])
    results = [event for event in recovered["events"] if event["event_type"] == "diplomatic_request_result"]
    assert recovered["complete"]
    assert len(results) == 1
    assert results[0]["payload"]["request"]["status"] == expected
    assert results[0]["sequence"] > first["cursor"]["sequence"]
    assert source.poll_events(context, recovered["cursor"])["events"] == []
    assert backend.session.read_count == 1


@pytest.mark.parametrize("change", ["unready", "foreign_session", "foreign_observer", "unsubmitted"])
def test_native_refresh_skips_ineligible_records(archived_backend, change):
    backend, request_id, _ = archived_backend
    source = DiplomacySource(backend)
    context = source.context()
    record = backend.journal.lookup_request(request_id)
    if change == "unready":
        context["status"] = "unready"
    elif change == "foreign_session":
        context["session_id"] = "other-session"
    elif change == "foreign_observer":
        context["observer"] = "POR"
    else:
        backend.journal.register("unsubmitted-request", record.payload)
        record = backend.journal.lookup_request("unsubmitted-request")
    assert source._refresh_native_record(record, context) == record
    assert backend.session.read_count == 0
