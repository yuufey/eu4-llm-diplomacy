"""MCP recall authorization, durable ownership and native consequences."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from bridge import diplomat_recall
from bridge.diplomacy import DiplomacyTools
from bridge.diplomacy_control import DiplomacyControl
from bridge.diplomacy_journal import DurableJournal
from bridge.game_tools import GameTools
from bridge.information.model import InformationError
from bridge.tests.test_game_tools import FakeInformationService


@pytest.fixture
def recall_session(tmp_path):
    (tmp_path / "control-probe.jsonl").touch()
    return SimpleNamespace(
        directory=tmp_path,
        session_id="test-recall-session",
        managed_countries=("TUR", "ENG"),
        health=lambda: {"status": "ready"},
        _installation_ack=lambda: {"native_diplomat_recall_by_id": True,
                                   "native_diplomat_recall_protocol": "EU4RECALL1"},
    )


def game_tools(session, journal, principal="test-operator", country="TUR"):
    diplomacy = DiplomacyTools(journal, session)
    diplomacy.control = DiplomacyControl(principal, country)
    return GameTools(FakeInformationService(diplomacy))


def test_mcp_tool_only_appears_for_supported_and_authorized_binding(recall_session):
    with DurableJournal(":memory:", experiment_id="test", session_id=recall_session.session_id) as journal:
        names = lambda tools: {item["name"] for item in tools.definitions()}
        assert "recall_diplomat" in names(game_tools(recall_session, journal))
        assert "recall_diplomat" not in names(game_tools(recall_session, journal, country=None))
        assert "recall_diplomat" not in names(game_tools(recall_session, journal, country="FRA"))
        recall_session._installation_ack = lambda: {}
        assert "recall_diplomat" not in names(game_tools(recall_session, journal))


@pytest.mark.parametrize("country", ["TUR", "ENG"])
def test_mcp_uses_bound_country_only_and_replays_no_native_request(
        recall_session, monkeypatch, country):
    published = []

    def publish(request, line):
        protocol, session, revision, expires, actor, diplomat_id = line.rstrip("\n").split("\t")
        assert protocol == "EU4RECALL1" and session == recall_session.session_id
        assert int(expires) > 116444736000000000 + int(revision) // 100
        assert (actor, diplomat_id) == (country, "2")
        published.append(line)
        base = {"session_id": session, "revision": int(revision), "actor": actor, "diplomat_id": 2}
        queued = dict(base, event=diplomat_recall.RESULT_EVENT, status="queued")
        executed = dict(base, event=diplomat_recall.CONSEQUENCE_EVENT, status="executed",
                        state="returning", date_raw=56456976)
        with (request.parent / "control-probe.jsonl").open("a", encoding="utf-8") as log:
            for event in (dict(executed, actor="FRA"), dict(executed, diplomat_id=3), queued, executed):
                log.write(json.dumps(event) + "\n")

    monkeypatch.setattr(diplomat_recall, "_publish", publish)
    with DurableJournal(":memory:", experiment_id="test", session_id=recall_session.session_id) as journal:
        tools = game_tools(recall_session, journal, country=country)
        args = {"request_id": "recall-1", "diplomat_id": 2}
        for invalid in (dict(args, actor="FRA"), dict(args, diplomat_id=True), dict(args, diplomat_id=-1)):
            with pytest.raises(InformationError, match="arguments") as error:
                tools.call("recall_diplomat", invalid)
            assert error.value.code == "invalid_parameters"
        assert not published

        result = tools.call("recall_diplomat", args)
        assert result["status"] == "executed" and result["submitted"] is True
        assert result["result"] == {"actor": country, "diplomat_id": 2,
                                    "state": "returning", "game_date_raw": 56456976}
        assert tools.call("recall_diplomat", args) == result
        assert tools.call("recall_diplomat", dict(args, diplomat_id=3))["status"] == "conflict"
        peer = game_tools(recall_session, journal, principal="different-owner", country=country)
        for tool, payload in (("recall_diplomat", args),
                              ("get_diplomatic_result", {"request_id": args["request_id"]})):
            with pytest.raises(InformationError) as error:
                peer.call(tool, payload)
            assert error.value.code == "permission_denied"
        assert len(published) == 1


def test_queued_command_with_unconfirmed_consequence_is_not_executed(recall_session, monkeypatch):
    def publish(request, line):
        _, session, revision, _, actor, diplomat_id = line.rstrip("\n").split("\t")
        fields = {"session_id": session, "revision": int(revision),
                  "actor": actor, "diplomat_id": int(diplomat_id)}
        with (request.parent / "control-probe.jsonl").open("a", encoding="utf-8") as log:
            log.write(json.dumps(dict(fields, event=diplomat_recall.RESULT_EVENT, status="queued")) + "\n")
            log.write(json.dumps(dict(fields, event=diplomat_recall.CONSEQUENCE_EVENT,
                                      status="unconfirmed")) + "\n")

    monkeypatch.setattr(diplomat_recall, "_publish", publish)
    with DurableJournal(":memory:", experiment_id="test", session_id=recall_session.session_id) as journal:
        tools = game_tools(recall_session, journal)
        result = tools.call("recall_diplomat", {"request_id": "unconfirmed", "diplomat_id": 2})
        assert result["status"] == "expired" and result["game_outcome"] == "unknown"
        assert result["result"]["reason"] == "RECALL_UNCONFIRMED"
