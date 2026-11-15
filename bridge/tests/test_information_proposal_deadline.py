"""Native pending deadlines keep their threshold and occurrence dates distinct."""
from contextlib import closing
import pytest

from bridge import proposal_expiry
from bridge.diplomacy import DiplomacyTools
from bridge.diplomacy_journal import DurableJournal
from bridge.information import InformationService
from bridge.information.catalog import get_topic
from bridge.information.presentation import present_concise, present_result
from bridge.information.sources import DiplomacySource, _field_result
from bridge.information.tools import InformationTools
from bridge.tests.test_information_proposal_expiry import NOW, SESSION, expired, offer, session


@pytest.mark.parametrize("damage", [
    {"created2c": None}, {"created2c": True}, {"created2c": 0},
    {"created2c": "5"}, {"date2c": True}, {"date2c": NOW - 97},
    {"created2c": 2**31 - 72, "date2c": 2**31 - 72},
    {"proposal3c": 0}, {"proposal3c": True}, {"token3c": True},
    {"token3c": 18}, {"pending_source": "unverified"},
    {"event": "native_call_to_arms_observed"},
])
def test_unverified_dates_or_pending_identity_keep_deadline_unknown(damage):
    raw = dict(offer(), **damage)
    projected = proposal_expiry.project_deadline(raw, enabled=True)
    assert projected["status"] == "unknown"
    assert "value" not in projected


def test_threshold_is_strict_and_never_fills_the_original_occurrence_date(tmp_path):
    observed = session(tmp_path, [offer(), expired()])
    events = observed.read_native_inbound_events()
    deadline = events[0]["payload"]["deadline"]
    assert deadline["status"] == "known"
    assert deadline["value"] == NOW - 24
    assert deadline["pending_created_game_date"] == NOW - 96
    assert deadline["expiry_comparison"] == "current_game_date > value"
    assert events[0]["date_raw"] is None
    assert events[1]["date_raw"] == NOW
    assert events[1]["payload"]["deadline"] == deadline
    assert events[1]["payload"]["parameters"]["proposal_lifecycle"]["game_date_raw"] > deadline["value"]


def test_deadline_requires_the_pinned_expiry_capability(tmp_path):
    observed = session(tmp_path, [offer()], enabled=False)
    deadline = observed.read_native_inbound_offers()[0]["deadline"]
    assert deadline["status"] == "unknown"
    assert deadline["reason"] == "PROPOSAL_EXPIRY_RULE_NOT_VERIFIED"


def test_saved_pending_keeps_the_original_threshold(tmp_path):
    raw = offer()
    raw.update(event="native_diplomacy_inbound_pending_restored",
               pending_source="native_saved_pending_queue", new_entry=False,
               call_redirected=False, saved_queue_restored=True,
               native_queue_membership_verified=True, extra60=0)
    observed = session(tmp_path, [raw])
    public = observed.read_native_inbound_offers()[0]
    assert public["source"] == "saved_native_pending"
    assert public["deadline"]["value"] == NOW - 24
    assert "date_raw" not in public


def test_maximum_threshold_does_not_overflow():
    raw = offer()
    raw.update(created2c=2**31 - 73, date2c=2**31 - 73)
    assert proposal_expiry.project_deadline(raw, enabled=True)["value"] == 2**31 - 1


@pytest.mark.parametrize("detail", ["full", "brief"])
def test_query_event_full_read_dedup_and_reopen_keep_deadline(tmp_path, detail):
    observed = session(tmp_path, [offer(), expired()])
    query = {"topic": "A04", "object": {"type": "session"},
             "fields": ["proposal_id", "deadline", "proposal_status", "parameters"], "parameters": {}}
    with closing(DurableJournal(tmp_path / "journal.sqlite3", observed.experiment_id, SESSION)) as journal:
        source = DiplomacySource(DiplomacyTools(journal, observed))
        database = tmp_path / "information.sqlite3"
        with closing(InformationService(source, database)) as service:
            tools = InformationTools(service)
            result = tools.call("information_query", {
                "request_id": "deadline-query", "queries": [query], "view": "full"})
            deadline = result["items"][0]["fields"]["deadline"]
            assert deadline["status"] == "known" and deadline["value"] == NOW - 24
            report = tools.call("information_manage_report", {
                "request_id": "deadline-report", "operation": "create",
                "config": {"name": "proposal deadline", "detail": detail, "queries": [query]},
            })["report"]
            subscription = tools.call("information_manage_subscription", {
                "request_id": "deadline-subscribe", "operation": "create", "config": {
                    "name": "proposal deadline", "kind": "event", "enabled": True,
                    "report_id": report["id"], "event": {"types": ["diplomatic_proposal"]},
                },
            })["subscription"]
            delivered = tools.call("information_tick", {})["results"]
            assert len(delivered) == 2
            for item in delivered:
                full = tools.call("information_get_result", {
                    "result_id": item["result_id"], "view": "full"})
                assert full["items"][0]["fields"]["deadline"] == deadline
                report_view = present_result(full) if detail == "brief" else full
                assert present_concise(report_view) == item
            assert tools.call("information_tick", {})["results"] == []
            tools.call("information_manage_subscription", {
                "request_id": "deadline-cancel", "operation": "cancel",
                "subscription_id": subscription["id"], "expected_version": subscription["version"],
            })
        with closing(InformationService(source, database)) as reopened:
            assert InformationTools(reopened).call("information_get_result", {
                "result_id": full["result_id"], "view": "full"}) == full


def test_deadline_is_discoverable_with_an_explicit_expiry_comparison():
    field = get_topic("A04")["fields"]["deadline"]
    assert field["coverage"] == "partial"
    assert field["expiry_comparison"] == "current_game_date > value"
    assert field["event_occurrence_date_derived"] is False


@pytest.mark.parametrize("payload", [
    {}, {"deadline": proposal_expiry.project_deadline({}, enabled=False)},
    {"deadline": {}}, {"deadline": "unverified"},
])
def test_legacy_or_unverified_deadline_is_unknown_at_the_field_boundary(payload):
    fields, complete = _field_result(["deadline"], payload, get_topic("A04"))
    assert fields["deadline"]["status"] == "unknown"
    assert "value" not in fields["deadline"]
    assert complete is False
