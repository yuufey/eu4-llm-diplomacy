from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from bridge.information.foreign_debt_disclosure import read_scope, validate_scope


GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
SESSION_ID = "30524-1dd6929aa5b7ead"
CREATION_FILETIME = 134379191563681453
GAME_DATE = 56556984


def inspection_shape(*, recipient="ENG", date_raw=GAME_DATE,
                     native_visibility=True, visibility_status=None):
    """Mirror the archived native inspection's relevant and surrounding shape."""
    if visibility_status is None:
        visibility_status = "visible" if native_visibility else "hidden"
    return {
        "contract_version": 1,
        "action_id": "trade_favors_for_gold",
        "native_identifier": "TRADE_FAVORS_FOR_GOLD_DESC2",
        "actor": "FRA",
        "recipient": recipient,
        "phase": "initiate",
        "decision_country": None,
        "decision_country_verified": False,
        "requested_decision_country": "FRA",
        "interface_support": {
            "query": "partial_native_rules",
            "execute": "native_favor_gold_submission",
            "complete": False,
        },
        "session": {
            "status": "ready",
            "state_id": "b933e2b08bf308a588c6df4d420531c3ec3b5d359eef2cd7da52788c64e2d6e0",
            "date_raw": date_raw,
            "reasons": [],
            "complete": True,
        },
        "visibility": {"status": visibility_status, "complete": True},
        "legality": {"status": "unavailable", "reasons": [], "complete": True},
        "authorization": {"status": "unavailable", "reasons": [], "complete": True},
        "parameters": {"requested": {}, "actual": {}, "candidates": None, "complete": True},
        "costs": {"status": "unknown", "items": [], "complete": False},
        "acceptance": {
            "applicability": "applicable", "complete": False,
            "details_available": False, "items": [], "items_truncated": False,
            "native_total": None, "predicted_response": "unknown",
            "prediction_available": False, "reason_count": 0,
            "scale_verified": False, "unit": "unknown",
        },
        "resources": {"complete": False, "items": []},
        "native_diagnostic": {"complete": False, "reasons": []},
        "native_rule_components": {
            "ui_action_selection": True,
            "ui_enabled_gate_verified": True,
            "common_action_gate": False,
            "initiation_gate": False,
            "specific_validity_query_called": True,
            "executor_validity": False,
            "complete": True,
            "ui_selection_checked": True,
            "native_visibility": native_visibility,
            "ui_enabled_gate_checked": True,
            "tooltip_gate": False,
            "full_rules_complete": True,
        },
        "favor_trade": {
            "amount": {
                "available": True, "payer": "ENG", "raw": 50131,
                "receiver": "FRA", "scale": 1000, "unit": "ducats",
                "value": 50.131,
            },
            "complete": True,
            "favors": {"available": True, "raw": 10, "unit": "favors"},
            "kind": "gold",
            "source": "native_rule",
        },
    }


class FakeSession:
    def __init__(self, *, controlled_countries=None):
        self.session_id = SESSION_ID
        self.creation_filetime = CREATION_FILETIME
        self.controlled_country = "FRA"
        self.record = {
            "session_id": SESSION_ID,
            "creation_filetime": CREATION_FILETIME,
            "game_sha256": GAME_SHA256,
        }
        if controlled_countries is not None:
            self.record["controlled_countries"] = controlled_countries


class FakeTools:
    def __init__(self, session, response=None, *, before_return=None, error=None):
        self.session = session
        self.response = response if response is not None else inspection_shape()
        self.before_return = before_return
        self.error = error
        self.calls = []

    def inspect_diplomatic_action(self, *args):
        self.calls.append(args)
        if self.before_return is not None:
            self.before_return()
        if self.error is not None:
            raise self.error
        return self.response


class FakeBaseSource:
    def __init__(self, session, tools):
        self.session = session
        self.diplomacy_tools = tools


def valid_context():
    return {
        "status": "ready",
        "complete": True,
        "mode": "live",
        "session_id": SESSION_ID,
        "game_sha256": GAME_SHA256,
        "game_version": "1.37.4",
        "observer": "FRA",
        "game_date": GAME_DATE,
    }


def make_source(*, controlled_countries=None, response=None, before_return=None,
                error=None, tools_session=None):
    session = FakeSession(controlled_countries=controlled_countries)
    tools = FakeTools(tools_session or session, response,
                      before_return=before_return, error=error)
    return session, tools, FakeBaseSource(session, tools)


def test_visible_selector_is_known_even_when_legality_is_unavailable_and_reasons_empty():
    session, tools, source = make_source()
    context = valid_context()
    # Caller-supplied control hints are not the host authorization source.
    context["controlled_countries"] = ["FRA", "ENG"]

    result = read_scope(source, context, "ENG")

    assert set(result) == {
        "schema", "scope", "status", "admitted", "reason", "observer", "target",
        "game_date", "session_id", "creation_filetime", "native_inspection_calls",
        "actual_UI_render_observed", "raw_inputs",
    }
    assert result["schema"] == "information.foreign_debt_disclosure.v1"
    assert result["scope"] == "native_ai_accept_principal_amount"
    assert result["observer"] == "FRA"
    assert result["target"] == "ENG"
    assert result["game_date"] == GAME_DATE
    assert result["session_id"] == SESSION_ID
    assert result["creation_filetime"] == CREATION_FILETIME
    assert result["status"] == "known"
    assert result["admitted"] is True
    assert result["native_inspection_calls"] == 1
    assert result["actual_UI_render_observed"] is False
    assert result["raw_inputs"]["operation"]["read_only"] is True
    assert result["raw_inputs"]["debt_amount_source"] == "not_evaluated_by_helper"
    assert result["raw_inputs"]["inspection"]["legality"]["status"] == "unavailable"
    assert result["raw_inputs"]["inspection"]["legality"]["reasons"] == []
    assert tools.calls == [("trade_favors_for_gold", "FRA", "ENG", "initiate", {})]
    assert source.session is session
    assert validate_scope(result)


@pytest.mark.parametrize(
    ("target", "expected_reason"),
    [("FRA", "TARGET_CONTROLLED_BY_HOST")],
)
def test_controlled_target_is_refused_without_inspection(target, expected_reason):
    _, tools, source = make_source()

    result = read_scope(source, valid_context(), target)

    assert result["status"] == "known"
    assert result["admitted"] is False
    assert result["reason"] == expected_reason
    assert result["native_inspection_calls"] == 0
    assert tools.calls == []
    assert validate_scope(result)


def test_observer_and_target_use_bound_tags_not_historical_tags():
    inspection = inspection_shape(recipient="FRA")
    inspection["actor"] = "POR"
    session, tools, source = make_source(controlled_countries=["POR"], response=inspection)
    context = valid_context() | {"observer": "POR"}
    result = read_scope(source, context, "FRA")
    assert result["observer"] == "POR" and result["status"] == "known"
    assert result["admitted"] is True and validate_scope(result)
    assert tools.calls == [("trade_favors_for_gold", "POR", "FRA", "initiate", {})]
    forged = deepcopy(result)
    forged["raw_inputs"]["inspection"]["actor"] = "FRA"
    assert not validate_scope(forged)


def test_legacy_fallback_uses_session_controlled_country():
    inspection = inspection_shape(recipient="FRA")
    inspection["actor"] = "ENG"
    session, tools, source = make_source(response=inspection)
    session.controlled_country = "ENG"
    result = read_scope(source, valid_context() | {"observer": "ENG"}, "FRA")
    assert result["status"] == "known" and validate_scope(result)
    assert tools.calls == [("trade_favors_for_gold", "ENG", "FRA", "initiate", {})]


def test_missing_host_control_authority_fails_closed():
    session, tools, source = make_source()
    del session.controlled_country
    result = read_scope(source, valid_context(), "ENG")
    assert result["status"] == "unknown"
    assert result["reason"] == "CONTROLLED_COUNTRY_AUTHORITY_UNAVAILABLE"
    assert tools.calls == [] and validate_scope(result)


def test_invalid_target_and_invalid_controlled_policy_are_unknown_without_inspection():
    _, tools, source = make_source()
    invalid_target = read_scope(source, valid_context(), "eng")
    assert invalid_target["status"] == "unknown"
    assert invalid_target["native_inspection_calls"] == 0
    assert tools.calls == []
    assert validate_scope(invalid_target)

    _, tools, source = make_source(controlled_countries="FRA")
    invalid_policy = read_scope(source, valid_context(), "ENG")
    assert invalid_policy["status"] == "unknown"
    assert invalid_policy["reason"] == "CONTROLLED_COUNTRIES_NOT_LIST"
    assert invalid_policy["native_inspection_calls"] == 0
    assert tools.calls == []
    assert validate_scope(invalid_policy)


def test_missing_inspection_tool_is_unknown_without_call():
    session = FakeSession()
    tools = SimpleNamespace(session=session)
    source = FakeBaseSource(session, tools)

    result = read_scope(source, valid_context(), "ENG")

    assert result["status"] == "unknown"
    assert result["reason"] == "INSPECTION_TOOL_UNAVAILABLE"
    assert result["native_inspection_calls"] == 0
    assert validate_scope(result)


def test_wrong_tools_session_is_rejected_before_call():
    session = FakeSession()
    other_session = FakeSession()
    tools = FakeTools(other_session)
    source = FakeBaseSource(session, tools)

    result = read_scope(source, valid_context(), "ENG")

    assert result["status"] == "unknown"
    assert result["reason"] == "DIPLOMACY_TOOLS_SESSION_MISMATCH"
    assert tools.calls == []
    assert validate_scope(result)


@pytest.mark.parametrize(
    ("changed", "expected_reason"),
    [
        ({"session_id": "stale-session"}, "CONTEXT_BINDING_INVALID"),
        ({"game_date": GAME_DATE + 1}, "INSPECTION_SESSION_DATE_MISMATCH"),
        ({"game_version": "1.37.3"}, "CONTEXT_BINDING_INVALID"),
    ],
)
def test_context_or_inspection_date_mismatch_is_unknown(changed, expected_reason):
    _, tools, source = make_source()
    context = {**valid_context(), **changed}

    result = read_scope(source, context, "ENG")

    assert result["status"] == "unknown"
    assert result["reason"] == expected_reason
    assert validate_scope(result)
    if expected_reason == "CONTEXT_BINDING_INVALID":
        assert tools.calls == []
    else:
        assert len(tools.calls) == 1


def test_wrong_recipient_and_inconsistent_visibility_are_unknown_after_one_call():
    wrong_target = inspection_shape(recipient="SWE")
    _, tools, source = make_source(response=wrong_target)
    result = read_scope(source, valid_context(), "ENG")
    assert result["status"] == "unknown"
    assert result["reason"] == "INSPECTION_ACTION_BINDING_MISMATCH"
    assert len(tools.calls) == 1
    assert validate_scope(result)

    mismatch = inspection_shape(native_visibility=True, visibility_status="hidden")
    _, tools, source = make_source(response=mismatch)
    result = read_scope(source, valid_context(), "ENG")
    assert result["status"] == "unknown"
    assert result["reason"] == "VISIBILITY_PROJECTION_MISMATCH"
    assert len(tools.calls) == 1
    assert validate_scope(result)


def test_inspection_date_mismatch_is_unknown_after_one_call():
    _, tools, source = make_source(response=inspection_shape(date_raw=GAME_DATE + 24))

    result = read_scope(source, valid_context(), "ENG")

    assert result["status"] == "unknown"
    assert result["reason"] == "INSPECTION_SESSION_DATE_MISMATCH"
    assert len(tools.calls) == 1
    assert validate_scope(result)


def test_controlled_country_policy_drift_during_query_is_unknown_after_one_call():
    session = FakeSession(controlled_countries=["FRA"])
    tools = FakeTools(session, before_return=lambda: session.record["controlled_countries"].append("ENG"))
    source = FakeBaseSource(session, tools)

    result = read_scope(source, valid_context(), "ENG")

    assert result["status"] == "unknown"
    assert result["reason"] == "SOURCE_BINDING_DRIFTED"
    assert result["native_inspection_calls"] == 1
    assert len(tools.calls) == 1
    assert validate_scope(result)


def test_inspection_exception_is_unknown_and_never_retried():
    _, tools, source = make_source(error=RuntimeError("transient"))

    result = read_scope(source, valid_context(), "ENG")

    assert result["status"] == "unknown"
    assert result["reason"] == "INSPECTION_CALL_FAILED"
    assert result["native_inspection_calls"] == 1
    assert result["raw_inputs"]["inspection_error"] == "RuntimeError"
    assert len(tools.calls) == 1
    assert validate_scope(result)


def test_hidden_selector_is_known_but_not_admitted():
    _, tools, source = make_source(
        response=inspection_shape(native_visibility=False, visibility_status="hidden")
    )

    result = read_scope(source, valid_context(), "ENG")

    assert result["status"] == "known"
    assert result["admitted"] is False
    assert result["reason"] == "NATIVE_SELECTOR_HIDDEN"
    assert len(tools.calls) == 1
    assert validate_scope(result)


def test_validate_scope_rejects_top_level_and_raw_evidence_tampering():
    _, _, source = make_source()
    original = read_scope(source, valid_context(), "ENG")
    assert validate_scope(original)

    changed_admission = deepcopy(original)
    changed_admission["admitted"] = False
    assert not validate_scope(changed_admission)

    changed_target = deepcopy(original)
    changed_target["target"] = "SWE"
    assert not validate_scope(changed_target)

    changed_top_date = deepcopy(original)
    changed_top_date["game_date"] += 24
    assert not validate_scope(changed_top_date)

    changed_date = deepcopy(original)
    changed_date["raw_inputs"]["identity_before"]["context"]["game_date"]["value"] += 24
    assert not validate_scope(changed_date)

    stripped_proof = deepcopy(original)
    stripped_proof["raw_inputs"] = {}
    assert not validate_scope(stripped_proof)
