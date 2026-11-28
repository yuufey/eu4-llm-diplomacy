"""Country assignments govern decision roles before an execution is reached."""
from dataclasses import FrozenInstanceError
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from bridge.diplomacy_control import DiplomacyControl, DiplomacyPermissionError
from bridge.game_tools import GameTools
from bridge.information.collection_lock import CollectionLock
from bridge.information.model import InformationError
from tools.serve_information import build_parser


@pytest.mark.parametrize("country", ["ENG", "SAV", "POR", "FRA", "K00"])
def test_operator_can_assign_any_valid_country(country):
    control = DiplomacyControl("agent-1", country)
    assert control.authorize("offer_alliance", country, "BUR") == country
    with pytest.raises(DiplomacyPermissionError):
        control.authorize("offer_alliance", "BUR", country)
    with pytest.raises(FrozenInstanceError):
        control.controlled_country = "BUR"


@pytest.mark.parametrize("phase", ["accept", "reject"])
def test_inbound_authority_belongs_to_the_country_answering(phase):
    control = DiplomacyControl("english-agent", "ENG")
    assert control.authorize("offer_alliance", "FRA", "ENG", phase) == "ENG"
    with pytest.raises(DiplomacyPermissionError):
        control.authorize("offer_alliance", "ENG", "FRA", phase)


def test_read_only_connection_and_invalid_assignments():
    with pytest.raises(DiplomacyPermissionError):
        DiplomacyControl("reader", None).authorize("offer_alliance", "FRA", "ENG")
    for country in ("", "eng", "ENG;", 1):
        with pytest.raises(ValueError):
            DiplomacyControl("agent", country)


def test_results_require_the_assigned_country_and_recorded_principal():
    control = DiplomacyControl("english-agent", "ENG")
    record = SimpleNamespace(payload={"action_id": "offer_alliance", "actor": "ENG",
                                     "recipient": "FRA", "phase": "initiate"},
                             principal="english-agent", decision_country="ENG")
    control.authorize_record(record)
    record.principal = "another-agent"
    with pytest.raises(DiplomacyPermissionError):
        control.authorize_record(record)
    record.principal = None
    record.decision_country = None
    control.authorize_record(record)
    record.payload["actor"] = "SAV"
    with pytest.raises(DiplomacyPermissionError):
        control.authorize_record(record)


def test_direct_use_requires_explicit_control_not_physical_player():
    from bridge.diplomacy import DiplomacyTools

    session = SimpleNamespace(record={"preflight_player_tag": "FRA"})
    journal = Mock()
    api = DiplomacyTools(journal, session)
    assert api._controlled_country() is None
    with pytest.raises(DiplomacyPermissionError, match="DIPLOMACY_CONTROL_CONTEXT_MISSING"):
        api.inspect_diplomatic_action("offer_alliance", "FRA", "SAV")
    with pytest.raises(DiplomacyPermissionError, match="DIPLOMACY_CONTROL_CONTEXT_MISSING"):
        api.execute_diplomatic_action("direct-1", "offer_alliance", "FRA", "SAV")
    journal.register.assert_not_called()
    session.controlled_country = "ENG"
    assert api._authorize("offer_alliance", "ENG", "FRA") == "ENG"
    assert api._authorize("offer_alliance", "FRA", "ENG", "accept") == "ENG"
    api._inspect_diplomatic_action = Mock(return_value={"phase": "initiate"})
    assert api.inspect_diplomatic_action("offer_alliance", "ENG", "FRA")["phase"] == "initiate"
    api._inspect_diplomatic_action.assert_called_once()
    with pytest.raises(DiplomacyPermissionError, match="DIPLOMACY_COUNTRY_NOT_AUTHORIZED"):
        api.execute_diplomatic_action("direct-2", "offer_alliance", "FRA", "ENG")
    journal.register.assert_not_called()

    record = SimpleNamespace(payload={"action_id": "offer_alliance", "actor": "ENG",
                                      "recipient": "FRA", "phase": "initiate"},
                             principal=None, decision_country="ENG")
    api._authorize_record(record)
    record.principal = "another-agent"
    with pytest.raises(DiplomacyPermissionError, match="DIPLOMACY_REQUEST_NOT_OWNED"):
        api._authorize_record(record)
    record.principal = None
    record.decision_country = "FRA"
    with pytest.raises(DiplomacyPermissionError, match="DIPLOMACY_REQUEST_COUNTRY_MISMATCH"):
        api._authorize_record(record)

    api.control = DiplomacyControl("reader", None)
    assert api._controlled_country() is None
    with pytest.raises(DiplomacyPermissionError):
        api.execute_diplomatic_action("direct-3", "offer_alliance", "ENG", "FRA")
    journal.register.assert_not_called()


def test_unbound_direct_caller_can_still_read_the_action_catalog():
    from bridge.diplomacy import DiplomacyTools

    api = DiplomacyTools(None)
    assert api._controlled_country() is None
    assert api.list_diplomatic_actions()["actions"]


def test_observer_session_accepts_only_explicit_decision_country(tmp_path):
    from bridge.diplomacy import ObserverSession

    installation = tmp_path / "installation.json"
    installation.write_text(json.dumps({"experiment_id": "direct", "session_id": "1-1",
                                         "preflight_player_tag": "FRA"}), encoding="utf-8")
    assert ObserverSession(installation, tmp_path / "game.exe")._controlled_country() is None
    assert ObserverSession(installation, tmp_path / "game.exe", controlled_country="ENG")._controlled_country() == "ENG"
    with pytest.raises(ValueError, match="INVALID_CONTROLLED_COUNTRY"):
        ObserverSession(installation, tmp_path / "game.exe", controlled_country="eng")
    unbound = ObserverSession(installation, tmp_path / "game.exe")
    unbound.controlled_country = "ENG|BAD"
    assert unbound._controlled_country() is None


def test_unified_entry_rejects_wrong_country_before_calling_the_backend():
    calls = []
    api = SimpleNamespace(execute_diplomatic_action=lambda **arguments: calls.append(arguments))
    service = SimpleNamespace(diplomacy_tools=api, diplomacy_control=DiplomacyControl("agent", "ENG"),
                              collection_lock=CollectionLock(":memory:"), _closed=False)
    tools = GameTools(service)
    arguments = {"request_id": "controlled-001", "action_id": "offer_alliance",
                 "actor": "FRA", "recipient": "ENG"}
    with pytest.raises(InformationError) as error:
        tools.call("execute_diplomatic_action", arguments)
    assert error.value.code == "permission_denied"
    assert calls == []
    arguments.update(actor="ENG", recipient="SAV")
    tools.call("execute_diplomatic_action", arguments)
    assert calls == [arguments]
    assert "ENG" in tools.instructions


def test_control_assignment_is_not_a_model_tool_argument():
    service = SimpleNamespace(diplomacy_tools=object(), diplomacy_control=DiplomacyControl("agent", "ENG"))
    with pytest.raises(InformationError) as error:
        GameTools(service).call("execute_diplomatic_action", {
            "request_id": "attempted-override", "action_id": "offer_alliance",
            "actor": "FRA", "recipient": "ENG", "controlled_country": "FRA"})
    assert error.value.code == "invalid_parameters"


def test_cli_exposes_trusted_control_assignment():
    args = build_parser().parse_args(["--controlled-country", "ENG", "--owner", "eng-agent"])
    assert args.controlled_country == "ENG"
    assert args.owner == "eng-agent"


def test_inbound_expiry_follows_the_configured_recipient():
    from bridge import proposal_expiry
    from bridge.tests.test_information_proposal_expiry import expired, SESSION

    event = expired()
    recipient = int(event["source"]["recipient20"], 16)
    event["source"]["recipient20"] = hex((recipient & ~0xFFFFFF) | int.from_bytes(b"ENG", "little"))
    assert proposal_expiry.is_expiry_observation(event, SESSION, controlled_country="ENG")
    result = proposal_expiry.validate_expiry(event, SESSION, controlled_country="ENG")
    assert result["recipient"] == "ENG"
    assert proposal_expiry.validate_expiry(event, SESSION, controlled_country="FRA") is None


def test_invalid_managed_scope_is_rejected_before_opening_the_game():
    from tools.serve_information import _build_runtime

    args = build_parser().parse_args([
        "--operator-session", "missing-installation.json", "--controlled-country", "ENG",
        "--managed-countries", "FRA"])
    with pytest.raises(ValueError, match="CONTROLLED_COUNTRY_OUTSIDE_MANAGED_COUNTRIES"):
        _build_runtime(args)
