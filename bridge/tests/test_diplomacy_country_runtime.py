from __future__ import annotations

import json

import pytest

from bridge.diplomacy import DiplomacyTools, ObserverSession
from bridge.diplomacy_control import DiplomacyControl, DiplomacyPermissionError
from bridge.diplomacy_journal import DurableJournal
from bridge.country_control_runtime import CAPABILITY as COUNTRY_CONTROL_CAPABILITY


class NativeSubmissionStub:
    """Small ready-session stub for the normal submit/receipt path."""

    controlled_country = "K00"

    def __init__(self):
        self.submit_calls = []
        self._health_calls = 0

    def health(self):
        self._health_calls += 1
        return {
            "status": "ready", "state_id": f"state-{self._health_calls}",
            "date_raw": 42, "reasons": [], "complete": True,
        }

    def installation_capabilities(self):
        return frozenset({"native_offer_submission"})

    def alliance_objects(self, actor, recipient):
        return {"status": "observed", "items": [], "complete": False,
                "reason_code": "QUEUE_LIFECYCLE_NOT_RECOVERED"}

    def inspect_alliance(self, action_id, actor, recipient, phase):
        return {
            "display_predicate": True,
            "common_action_gate": True,
            "validity_called": True,
            "native_validity": True,
            "initiation_gate": True,
            "score_applicable": True,
            "score_available": True,
            "native_total_raw": 64,
            "acceptance_threshold_raw": 1,
            "reason_count": 0,
            "reason_items": [],
            "reason_items_truncated": False,
            "ui_selection_checked": True,
            "native_visibility": True,
            "ui_enabled_gate_checked": True,
            "tooltip_gate": True,
            "full_rules_complete": True,
            "date_raw": 42,
        }

    def submit_offer_alliance(self, request_id, actor, recipient, phase, date_raw):
        self.submit_calls.append((request_id, actor, recipient, phase, date_raw))
        return {
            "status": "submitted",
            "receipt": {
                "event": "native_alliance_submission_result",
                "request_id": request_id,
                "action_id": "offer_alliance",
                "actor": actor,
                "recipient": recipient,
                "phase": phase,
                "date_raw": date_raw,
                "submitted": True,
                "native_queue_verified": True,
                "transport_ring_receipt": True,
                "native_sequence": 11,
                "native_origin": 1,
                "native_flags": 0,
            },
        }


def _inbound_event():
    return {
        "event": "native_alliance_inbound_offer",
        "session_id": "session-k00",
        "proposal_id": 17,
        "action_id": "offer_alliance",
        "phase": "initiate",
        "actor": "SAV",
        "mirror": "SAV",
        "recipient": "K00",
        "date28": 56459880,
        "date2c": 56459880,
        "envoy30": 1,
        "state34": 0,
        "variant38": 1,
        "proposal3c": 2,
        "token3c": 3,
        "created2c": 4,
        "queue_before_count": 0,
        "queue_after_count": 1,
        "queue_readable": True,
        "list_integrity": True,
        "new_entry": True,
        "payload_readable": True,
        "decision_country": "K00",
        "decision_country_verified": True,
        "pending_source": "native_executor_pending_block",
        "source_verified": True,
        "call_redirected": True,
        "business_result": "pending_observed",
    }


def test_non_fra_country_executes_to_native_stub_and_binds_receipt():
    session = NativeSubmissionStub()
    with DurableJournal(":memory:", "experiment-k00", "session-k00") as journal:
        tools = DiplomacyTools(journal, session)
        tools.control = DiplomacyControl("agent-k00", "K00")
        tools.controlled_country = "K00"

        result = tools.execute_diplomatic_action(
            "offer-k00-1", "offer_alliance", "K00", "ENG")

        assert result["status"] == "submitted"
        assert result["submitted"] is True
        assert session.submit_calls == [
            ("offer-k00-1", "K00", "ENG", "initiate", 42)]
        record = journal.get_request("offer-k00-1")
        assert record.principal == "agent-k00"
        assert record.decision_country == "K00"
        assert record.native_receipt["actor"] == "K00"
        assert record.native_receipt["recipient"] == "ENG"
        assert tools.list_diplomatic_actions()["actor"] == "K00"
        with pytest.raises(DiplomacyPermissionError,
                           match="DIPLOMACY_COUNTRY_NOT_AUTHORIZED"):
            tools.list_diplomatic_actions(actor="FRA", recipient="ENG")
        response_inspection = tools.inspect_diplomatic_action(
            "offer_alliance", "SAV", "K00", "accept",
            {"proposal_id": "a" * 32})
        assert response_inspection["action_id"] == "offer_alliance"
        with pytest.raises(DiplomacyPermissionError,
                           match="DIPLOMACY_COUNTRY_NOT_AUTHORIZED"):
            tools.inspect_diplomatic_action(
                "offer_alliance", "SAV", "ENG", "accept",
                {"proposal_id": "a" * 32})

        with pytest.raises(DiplomacyPermissionError,
                           match="DIPLOMACY_COUNTRY_NOT_AUTHORIZED"):
            tools.execute_diplomatic_action(
                "offer-foreign-1", "offer_alliance", "FRA", "ENG")
        assert len(session.submit_calls) == 1
        assert [record.request_id for record in journal.list_requests()] == [
            "offer-k00-1"]

        another_agent = DiplomacyTools(journal, session)
        another_agent.control = DiplomacyControl("agent-other", "K00")
        with pytest.raises(DiplomacyPermissionError,
                           match="DIPLOMACY_REQUEST_NOT_OWNED"):
            another_agent.get_diplomatic_result("offer-k00-1")
        wrong_country = DiplomacyTools(journal, session)
        wrong_country.control = DiplomacyControl("agent-k00", "ENG")
        with pytest.raises(DiplomacyPermissionError,
                           match="DIPLOMACY_COUNTRY_NOT_AUTHORIZED"):
            wrong_country.get_diplomatic_result("offer-k00-1")


def test_dynamic_inbound_direction_and_country_validators_accept_alphanumeric_tags():
    event = _inbound_event()
    assert ObserverSession._valid_native_inbound_offer_event(
        event, "session-k00", controlled_country="K00")
    public = ObserverSession._public_native_inbound_offer(
        "public-k00-1", event, controlled_country="K00")
    assert public["actor"] == "SAV"
    assert public["recipient"] == "K00"
    assert public["decision_country"] == "K00"

    wrong_recipient = dict(event, recipient="FRA")
    assert not ObserverSession._valid_native_inbound_offer_event(
        wrong_recipient, "session-k00", controlled_country="K00")
    DiplomacyTools._validate(
        "offer_alliance", "SAV", "K00", "accept",
        {"proposal_id": "a" * 32}, controlled_country="K00")

    assert DiplomacyTools._native_offer_scope(
        "offer_alliance", "K00", "initiate", controlled_country="K00")
    assert not DiplomacyTools._native_offer_scope(
        "offer_alliance", "FRA", "initiate", controlled_country="K00")
    receipt = {
        "event": "native_alliance_submission_result",
        "request_id": "offer-k00-1", "session_id": "session-k00",
        "action_id": "offer_alliance", "actor": "K00", "recipient": "ENG",
        "phase": "initiate", "date_raw": 42, "submitted": True,
        "native_queue_verified": True, "transport_ring_receipt": True,
        "native_sequence": 11, "native_origin": 1, "native_flags": 0,
    }
    assert ObserverSession._valid_native_submission_result(
        receipt, "offer-k00-1", "session-k00", "K00", "ENG",
        "initiate", 42)


@pytest.mark.parametrize(
    "ack, expected",
    [
        ({"version": 65,
          "native_country_control_configuration": True,
          "native_country_control_protocol": "EU4CONTROL1",
          "native_country_control_ack": "native_controlled_countries_set",
          "native_country_control_request": "controlled-countries.req",
          "caps": [COUNTRY_CONTROL_CAPABILITY]}, True),
        # A copied capability-list entry is not proof of the control channel.
        ({"version": 65, "caps": [COUNTRY_CONTROL_CAPABILITY]}, False),
        ({"version": 65,
          "native_country_control_protocol": "EU4CONTROL1",
          "native_country_control_ack": "native_controlled_countries_set",
          "native_country_control_request": "controlled-countries.req"}, False),
        ({"version": 65,
          "native_country_control_configuration": True,
          "native_country_control_ack": "native_controlled_countries_set",
          "native_country_control_request": "controlled-countries.req"}, False),
        ({"version": 65,
          "native_country_control_configuration": True,
          "native_country_control_protocol": "EU4CONTROL1",
          "native_country_control_request": "controlled-countries.req"}, False),
        ({"version": 64,
          "native_country_control_configuration": True,
          "native_country_control_protocol": "EU4CONTROL1",
          "native_country_control_ack": "native_controlled_countries_set",
          "native_country_control_request": "controlled-countries.req",
          "caps": [COUNTRY_CONTROL_CAPABILITY]}, False),
        ({"version": True,
          "native_country_control_configuration": True,
          "native_country_control_protocol": "EU4CONTROL1",
          "native_country_control_ack": "native_controlled_countries_set",
          "native_country_control_request": "controlled-countries.req"}, False),
        ({"version": 65,
          "native_country_control_configuration": "true",
          "native_country_control_protocol": "EU4CONTROL1",
          "native_country_control_ack": "native_controlled_countries_set",
          "native_country_control_request": "controlled-countries.req"}, False),
        ({"version": 65,
          "native_country_control_configuration": True,
          "native_country_control_protocol": "other",
          "native_country_control_ack": "native_controlled_countries_set",
          "native_country_control_request": "controlled-countries.req"}, False),
        ({"version": 65,
          "native_country_control_configuration": True,
          "native_country_control_protocol": "EU4CONTROL1",
          "native_country_control_ack": "other",
          "native_country_control_request": "controlled-countries.req"}, False),
        ({"version": 65,
          "native_country_control_configuration": True,
          "native_country_control_protocol": "EU4CONTROL1",
          "native_country_control_ack": "native_controlled_countries_set",
          "native_country_control_request": "other.req"}, False),
        ({"version": 65,
          "native_country_control_configuration": True,
          "native_country_control_protocol": "EU4CONTROL1",
          "native_country_control_ack": "native_controlled_countries_set"}, False),
    ],
)
def test_installation_ack_grants_country_control_only_for_complete_v65_identity(
        tmp_path, ack, expected):
    session_id = "session-control-ack"
    installation = tmp_path / "installation.json"
    installation.write_text(json.dumps({
        "experiment_id": "experiment-control-ack", "session_id": session_id,
    }), encoding="utf-8")
    log = tmp_path / "control-probe.jsonl"
    event = {
        "event": "diplomacy_observer_installed",
        "session_id": session_id,
        **ack,
    }
    log.write_text(json.dumps(event) + "\n", encoding="utf-8")

    capabilities = ObserverSession(installation, tmp_path / "eu4.exe").installation_capabilities()

    assert (COUNTRY_CONTROL_CAPABILITY in capabilities) is expected
