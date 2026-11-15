"""Narrow A04 fresh-pending tests over the existing read-only inspector."""

from __future__ import annotations

from copy import deepcopy
from contextlib import closing
import json
from pathlib import Path

import pytest

from bridge.diplomacy import ObserverSession
from bridge.information import InformationError, InformationService
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools


ROOT = Path(__file__).resolve().parents[2]
ACTIVE_FIXTURE = ROOT / "bridge" / "tests" / "fixtures" / (
    "military_access_r32_inbound_inspections.json"
)
INACTIVE_FIXTURE = ROOT / "bridge" / "tests" / "fixtures" / (
    "military_access_r32_inbound_pending_inactive.json"
)
GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
PUBLIC_ID = "a" * 32


def _fixture_event(path: Path, index: int = 0) -> dict:
    fixture = json.loads(path.read_text(encoding="utf-8"))
    event = fixture["events"][index]["event"]
    assert ObserverSession._valid_native_inbound_inspection(
        event, event["query_id"], event["session_id"], event["actor"],
        event["phase"], event["native_proposal_id"], event["date_raw"],
        "ask_military_access",
    )
    return event


class FakeSession:
    observer = "FRA"

    def __init__(self, event: dict, public_id: str):
        self.session_id = event["session_id"]
        self.current_date = event["date_raw"]
        self.record = {
            "session_id": self.session_id,
            "game_sha256": GAME_SHA256,
            "game_version": "1.37.4",
        }
        self.event = deepcopy(event)
        self.public_id = public_id
        self.health_calls = 0
        self.offer_calls = 0

    def health(self) -> dict:
        self.health_calls += 1
        return {
            "status": "ready", "date_raw": self.current_date,
            "game_sha256": GAME_SHA256, "game_version": "1.37.4",
            "observer": "FRA", "session_id": self.session_id,
            "complete": True, "reasons": [],
        }

    def read_native_alliance_inbound_offers(self) -> list[dict]:
        self.offer_calls += 1
        return [{
            "proposal_id": self.public_id,
            "action_id": "ask_military_access",
            "actor": self.event["actor"], "recipient": "FRA",
            "phase": "initiate", "observer_status": "observed_pending",
            "parameters": {"family": "military_access"},
        }]


class FakeTools:
    def __init__(self, event: dict, public_id: str = PUBLIC_ID):
        self.session = FakeSession(event, public_id)
        self.journal = None
        self.inspect_calls: list[tuple] = []
        self.drift_after_inspect = False
        self.envelope = self._envelope(event, public_id)

    def _envelope(self, event: dict, public_id: str) -> dict:
        native = ObserverSession._public_native_inbound_inspection(
            event, event["date_raw"], "ask_military_access"
        )
        observed = {
            "proposal_id": public_id,
            "action_id": "ask_military_access",
            "actor": event["actor"], "recipient": "FRA",
            "phase": "initiate", "currently_pending": native["pending_active"],
        }
        health = self.session.health()
        return {
            "action_id": "ask_military_access", "actor": event["actor"],
            "recipient": "FRA", "phase": "accept",
            "decision_country": "FRA",
            "decision_country_verified": native["decision_country_verified"],
            "parameters": {
                "requested": {"proposal_id": public_id, "phase": "initiate"},
                "actual": {"proposal_id": public_id, "phase": "initiate",
                            "decision_country": "FRA"},
            },
            "session": health,
            "native_inbound_inspection": native,
            "observed_inbound_proposal": observed,
        }

    def inspect_diplomatic_action(self, action_id, actor, recipient,
                                  phase="initiate", parameters=None):
        self.inspect_calls.append((action_id, actor, recipient, phase, deepcopy(parameters)))
        result = deepcopy(self.envelope)
        if self.drift_after_inspect:
            self.session.current_date += self.drift_after_inspect
        return result

    def submit_native_inbound_response(self, *args, **kwargs):
        pytest.fail("fresh_pending must never submit an inbound response")

    def execute_diplomatic_action(self, *args, **kwargs):
        pytest.fail("fresh_pending must never execute a diplomatic action")


def _source(event: dict, public_id: str = PUBLIC_ID) -> tuple[DiplomacySource, FakeTools]:
    tools = FakeTools(event, public_id)
    return DiplomacySource(tools), tools


def _query(fields=("proposal_status",), *, public_id=PUBLIC_ID, parameters=None,
           actor="SAV") -> dict:
    return {
        "topic": "A04",
        "object": {"type": "country_pair", "actor": actor, "recipient": "FRA"},
        "fields": list(fields),
        "parameters": ({"fresh_pending": True, "proposal_id": public_id,
                        "phase": "initiate"}
                       if parameters is None else parameters),
    }


def test_a04_catalog_and_default_observation_remain_partial_without_inspection():
    event = _fixture_event(ACTIVE_FIXTURE)
    source, tools = _source(event)
    topic = next(item for item in source.catalog() if item["topic_id"] == "A04")
    assert topic["fields"]["proposal_status"]["coverage"] == "partial"
    assert topic["fields"]["proposal_status"]["complete"] is False
    assert "proposal_status" in topic["fields"]

    context = source.context()
    result = source.read(_query(parameters={}), context)
    status = result["fields"]["proposal_status"]
    assert status["status"] == "known"
    assert status["value"] == "observed_pending"
    assert status["period"] == "observed"
    assert status["partial"] is True
    assert status["currently_pending"] == {
        "status": "unknown", "reason": "OBSERVATION_IS_NOT_CURRENT_PENDING_PROOF"
    }
    assert tools.inspect_calls == []


def test_fresh_active_returns_pending_and_inspects_exactly_once_without_execution():
    event = _fixture_event(ACTIVE_FIXTURE)
    source, tools = _source(event)
    context = source.context()
    result = source.read(_query(), context)
    status = result["fields"]["proposal_status"]

    assert status["status"] == "known"
    assert status["value"] == "pending"
    assert status["currently_pending"] == {"status": "known", "value": True, "period": "current"}
    assert len(tools.inspect_calls) == 1
    assert tools.inspect_calls[0] == (
        "ask_military_access", event["actor"], "FRA", "accept",
        {"proposal_id": PUBLIC_ID},
    )
    assert result["source"]["provenance"]["inspection_attempted"] is True
    assert result["source"]["provenance"]["response_executed"] is False


def test_fresh_inactive_is_known_only_with_pending_not_active_reason():
    event = _fixture_event(INACTIVE_FIXTURE)
    source, tools = _source(event)
    result = source.read(_query(actor=event["actor"]), source.context())
    status = result["fields"]["proposal_status"]

    assert status["status"] == "known"
    assert status["value"] == "inactive"
    assert status["currently_pending"] == {"status": "known", "value": False, "period": "current"}
    assert result["source"]["provenance"]["native_status_proof"]["native_validity"] is False
    assert len(tools.inspect_calls) == 1


def test_legality_or_native_validity_false_does_not_turn_active_pending_inactive():
    event = _fixture_event(ACTIVE_FIXTURE)
    source, tools = _source(event)
    tools.envelope["native_inbound_inspection"]["native_validity"] = False
    result = source.read(_query(), source.context())
    status = result["fields"]["proposal_status"]
    assert status["status"] == "known"
    assert status["value"] == "pending"


@pytest.mark.parametrize("mutation", [
    lambda envelope: envelope["native_inbound_inspection"].pop("reason"),
    lambda envelope: envelope["native_inbound_inspection"].update(pending_active="true"),
    lambda envelope: envelope["native_inbound_inspection"].update(
        decision_country_verified="true"),
    lambda envelope: envelope["native_inbound_inspection"].update(reason="BAD REASON"),
])
def test_missing_or_bad_native_reason_and_flags_stay_unknown(mutation):
    event = _fixture_event(INACTIVE_FIXTURE)
    source, tools = _source(event)
    mutation(tools.envelope)
    result = source.read(_query(actor=event["actor"]), source.context())
    assert result["fields"]["proposal_status"]["status"] == "unknown"
    assert "value" not in result["fields"]["proposal_status"]


@pytest.mark.parametrize("mutation", [
    lambda envelope: envelope.update(action_id="offer_alliance"),
    lambda envelope: envelope["parameters"]["actual"].update(proposal_id="b" * 32),
    lambda envelope: envelope["observed_inbound_proposal"].update(actor="GEN"),
    lambda envelope: envelope["session"].update(date_raw=0),
])
def test_action_party_date_or_requested_id_confusion_never_falls_back_to_observed(mutation):
    event = _fixture_event(ACTIVE_FIXTURE)
    source, tools = _source(event)
    mutation(tools.envelope)
    result = source.read(_query(), source.context())
    status = result["fields"]["proposal_status"]
    assert status["status"] == "unknown"
    assert "value" not in status


def test_missing_native_block_is_unknown_and_never_leaks_native_identity():
    event = _fixture_event(ACTIVE_FIXTURE)
    source, tools = _source(event)
    tools.envelope.pop("native_inbound_inspection")
    missing = source.read(_query(), source.context())
    assert missing["fields"]["proposal_status"]["status"] == "unknown"

    source, tools = _source(event, public_id="c" * 32)
    result = source.read(_query(public_id="c" * 32), source.context())
    encoded = json.dumps(result, sort_keys=True)
    assert "native_proposal_id" not in encoded
    assert event["query_id"] not in encoded
    assert "token3c" not in encoded
    assert tools.inspect_calls


@pytest.mark.parametrize('elapsed', [1, 24, 72])
def test_normal_time_advance_after_inspection_keeps_observed_pending_status(elapsed):
    event = _fixture_event(ACTIVE_FIXTURE)
    source, tools = _source(event)
    tools.drift_after_inspect = elapsed
    result = source.read(_query(), source.context())
    status = result["fields"]["proposal_status"]
    assert status["status"] == "known"
    assert status["value"] == "pending"
    assert status["observation_game_date"] == event['date_raw']
    assert len(tools.inspect_calls) == 1


def test_inspection_keeps_native_observation_when_query_and_health_dates_differ():
    event = _fixture_event(ACTIVE_FIXTURE)
    source, tools = _source(event)
    context = source.context()
    tools.session.current_date += 24
    tools.envelope['session']['date_raw'] += 24
    tools.envelope['native_inbound_inspection']['date_raw'] += 48
    result = source.read(_query(), context)
    status = result["fields"]["proposal_status"]
    assert status["status"] == "known"
    assert status["value"] == "pending"
    assert status["observation_game_date"] == event['date_raw'] + 48
    assert len(tools.inspect_calls) == 1


def test_session_change_during_inspection_withdraws_result():
    event = _fixture_event(ACTIVE_FIXTURE)
    source, tools = _source(event)
    inspect = tools.inspect_diplomatic_action

    def changed_session(*args, **kwargs):
        result = inspect(*args, **kwargs)
        tools.session.session_id = 'another-session'
        return result

    tools.inspect_diplomatic_action = changed_session
    result = source.read(_query(), source.context())
    status = result["fields"]["proposal_status"]
    assert status["status"] == "unavailable"
    assert status["reason"] == "INBOUND_CURRENT_CONTEXT_CHANGED"
    assert len(tools.inspect_calls) == 1


def test_normal_query_keeps_pending_information_while_game_time_advances(tmp_path):
    source, tools = _source(_fixture_event(ACTIVE_FIXTURE))
    tools.drift_after_inspect = 24
    with closing(InformationService(source, tmp_path / 'information.sqlite3')) as service:
        result = InformationTools(service).call('information_query', {
            'request_id': 'running-pending-query',
            'queries': [_query(('proposal_status', 'currently_pending'))],
        })
        assert result['items'][0]['proposal_status'] == 'pending'
        assert result['items'][0]['currently_pending'] is True
        assert len(tools.inspect_calls) == 1


def test_fresh_pending_requires_opaque_proposal_id_and_initiate_phase():
    event = _fixture_event(ACTIVE_FIXTURE)
    source, tools = _source(event)
    with pytest.raises(InformationError) as missing:
        source.read(_query(parameters={"fresh_pending": True, "phase": "initiate"}), source.context())
    assert missing.value.code == "invalid_parameters"
    with pytest.raises(InformationError) as phase:
        source.read(_query(parameters={"fresh_pending": True, "proposal_id": PUBLIC_ID,
                                       "phase": "accept"}), source.context())
    assert phase.value.code == "invalid_parameters"
    assert tools.inspect_calls == []


def test_non_fresh_fields_do_not_trigger_inspection():
    event = _fixture_event(ACTIVE_FIXTURE)
    source, tools = _source(event)
    result = source.read(
        _query(("proposal_id", "action_id"),
               parameters={"fresh_pending": True, "proposal_id": PUBLIC_ID,
                           "phase": "initiate"}),
        source.context(),
    )
    assert result["fields"]["proposal_id"]["status"] == "known"
    assert result["fields"]["action_id"]["status"] == "known"
    assert tools.inspect_calls == []

