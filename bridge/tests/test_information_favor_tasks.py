"""Focused tests for the selected-pair R05 Curry task projection."""

from __future__ import annotations

from bridge.information.catalog import catalog
from bridge.information.sources import DiplomacySource


EXE_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


def _query(obj, fields=("favor_tasks",), parameters=None):
    return {
        "topic": "R05",
        "object": obj,
        "fields": list(fields),
        "parameters": {} if parameters is None else parameters,
    }


class _Session:
    session_id = "favor-task-session"
    observer = "FRA"
    record = {"game_sha256": EXE_SHA, "dll_sha256": "d" * 64}

    def __init__(self, *, date=56560000):
        self.date = date
        self.health_calls = 0

    def health(self):
        self.health_calls += 1
        return {
            "status": "ready",
            "date_raw": self.date,
            "complete": True,
            "reasons": [],
        }


class _Tools:
    def __init__(self, *, active=False, family="curry_favors", verified=True,
                 relationship_complete=True, relationship_active=None,
                 session=None):
        self.session = session or _Session()
        self.active = active
        self.family = family
        self.verified = verified
        self.relationship_complete = relationship_complete
        self.relationship_active = active if relationship_active is None else relationship_active
        self.inspect_calls = []

    def inspect_diplomatic_action(self, action_id, actor, recipient, phase="initiate",
                                  parameters=None):
        self.inspect_calls.append((action_id, actor, recipient, phase, parameters))
        if action_id not in {"curry_favors", "stop_curry_favors"}:
            return {
                "action_id": action_id,
                "actor": actor,
                "recipient": recipient,
                "phase": phase,
                "native_favor_trade": {
                    "recipient_trust_raw": 50,
                    "favors_available_raw": 23466,
                },
                "session": {"status": "ready", "date_raw": self.session.date},
            }
        return {
            "action_id": action_id,
            "actor": actor,
            "recipient": recipient,
            "phase": phase,
            "family": self.family,
            "task_active": self.active,
            "task_state_verified": self.verified,
            "relationship_state": {
                "task_active": self.relationship_active,
                "complete": self.relationship_complete,
            },
            "submitted": False,
            "session": {"status": "ready", "date_raw": self.session.date},
        }


def _source(tools=None):
    session = tools.session if tools is not None else _Session()
    tools = tools or _Tools(session=session)
    return DiplomacySource(tools), session, tools


def test_catalog_marks_pair_task_partial_and_accepts_country_for_explicit_unavailable():
    r05 = next(item for item in catalog() if item["topic_id"] == "R05")
    assert r05["object_types"] == ["country_pair", "country"]
    task = r05["fields"]["favor_tasks"]
    assert task["coverage"] == "partial"
    assert task["unit"] == "task_state"
    assert task["scale"] == 1
    assert task["direction"] == "actor_to_recipient"
    assert task["source"] == "DiplomacyTools.inspect_diplomatic_action"


def test_task_only_defaults_to_stop_curry_and_preserves_active_false():
    source, session, tools = _source(_Tools(active=False))
    context = source.context()
    result = source.read(_query({"type": "country_pair", "actor": "FRA", "recipient": "SAV"}), context)

    assert len(tools.inspect_calls) == 1
    assert tools.inspect_calls[0] == ("stop_curry_favors", "FRA", "SAV", "initiate", {})
    field = result["fields"]["favor_tasks"]
    assert field["status"] == "known"
    assert field["value"]["actor"] == "FRA"
    assert field["value"]["recipient"] == "SAV"
    assert field["value"]["direction"] == "actor_to_recipient"
    assert field["value"]["task_active"] is False
    assert field["value"]["task_state_verified"] is True
    assert field["complete"] is False
    assert result["complete"] is False
    assert result["source"]["provenance"]["favor_tasks"]["network_enumeration"] == "unavailable"
    assert session.health_calls >= 2


def test_explicit_curry_action_reports_active_pair_without_second_query():
    source, _session, tools = _source(_Tools(active=True))
    result = source.read(
        _query(
            {"type": "country_pair", "actor": "FRA", "recipient": "SAV"},
            parameters={"action_id": "curry_favors"},
        ),
        source.context(),
    )
    assert len(tools.inspect_calls) == 1
    assert tools.inspect_calls[0][0] == "curry_favors"
    assert result["fields"]["favor_tasks"]["status"] == "known"
    assert result["fields"]["favor_tasks"]["value"]["task_active"] is True


def test_mixed_exchange_query_does_not_append_a_curry_query():
    source, _session, tools = _source(_Tools(active=True))
    result = source.read(
        _query(
            {"type": "country_pair", "actor": "FRA", "recipient": "SAV"},
            fields=("trust", "favor_tasks"),
            parameters={"action_id": "trade_favors_for_trust", "kind": "trust"},
        ),
        source.context(),
    )
    assert len(tools.inspect_calls) == 1
    assert tools.inspect_calls[0][0] == "trade_favors_for_trust"
    assert result["fields"]["trust"] == {"status": "known", "value": 50}
    assert result["fields"]["favor_tasks"] == {
        "status": "unknown",
        "reason": "FAVOR_TASKS_REQUIRES_CURRY_INSPECTION",
    }


def test_mixed_unselected_balance_query_defaults_to_trust_and_explains_task_gap():
    source, _session, tools = _source(_Tools(active=True))
    result = source.read(
        _query(
            {"type": "country_pair", "actor": "FRA", "recipient": "SAV"},
            fields=("trust", "favors_available", "favor_tasks"),
        ),
        source.context(),
    )

    assert tools.inspect_calls == [
        ("trade_favors_for_trust", "FRA", "SAV", "initiate", {})]
    assert result["fields"]["trust"] == {"status": "known", "value": 50}
    assert result["fields"]["favors_available"] == {
        "status": "known", "value": 23466}
    assert result["fields"]["favor_tasks"] == {
        "status": "unknown",
        "reason": "FAVOR_TASKS_REQUIRES_CURRY_INSPECTION",
    }


def test_invalid_curry_payload_is_unknown_and_never_false():
    source, _session, _tools = _source(_Tools(family="native_alliance_inspection"))
    result = source.read(
        _query({"type": "country_pair", "actor": "FRA", "recipient": "SAV"}),
        source.context(),
    )
    assert result["fields"]["favor_tasks"]["status"] == "unknown"
    assert result["fields"]["favor_tasks"]["reason"] == "FAVOR_TASKS_IDENTITY_UNVERIFIED"

    source, _session, _tools = _source(_Tools(verified=False))
    result = source.read(
        _query({"type": "country_pair", "actor": "FRA", "recipient": "SAV"}),
        source.context(),
    )
    assert result["fields"]["favor_tasks"]["status"] == "unknown"
    assert result["fields"]["favor_tasks"]["reason"] == "FAVOR_TASKS_STATE_NOT_VERIFIED"


def test_relationship_active_requires_exact_bool_and_matches_top_level():
    source, _session, _tools = _source(
        _Tools(active=True, relationship_active=1)
    )
    result = source.read(
        _query({"type": "country_pair", "actor": "FRA", "recipient": "SAV"}),
        source.context(),
    )
    assert result["fields"]["favor_tasks"] == {
        "status": "unknown",
        "reason": "FAVOR_TASKS_RELATIONSHIP_ACTIVE_NOT_EXACT_BOOL",
    }

    source, _session, _tools = _source(
        _Tools(active=True, relationship_active=False)
    )
    result = source.read(
        _query({"type": "country_pair", "actor": "FRA", "recipient": "SAV"}),
        source.context(),
    )
    assert result["fields"]["favor_tasks"] == {
        "status": "unknown",
        "reason": "FAVOR_TASKS_RELATIONSHIP_ACTIVE_MISMATCH",
    }


def test_native_date_raw_must_be_present_integer_and_not_bool():
    for invalid_date in (None, True, "56560000"):
        source, _session, _tools = _source(
            _Tools(active=True, session=_Session(date=invalid_date))
        )
        result = source.read(
            _query({"type": "country_pair", "actor": "FRA", "recipient": "SAV"}),
            source.context(),
        )
        assert result["fields"]["favor_tasks"] == {
            "status": "unknown",
            "reason": "FAVOR_TASKS_NATIVE_DATE_INVALID",
        }


def test_country_object_is_explicitly_unavailable_without_inspection():
    source, _session, tools = _source(_Tools(active=True))
    result = source.read(
        _query({"type": "country", "country": "FRA"}),
        source.context(),
    )
    assert result["fields"]["favor_tasks"] == {
        "status": "unavailable",
        "reason": "FAVOR_TASKS_COUNTRY_NETWORK_UNAVAILABLE",
    }
    assert tools.inspect_calls == []


def test_context_change_after_inspection_withdraws_task_known_value():
    session = _Session(date=56560000)
    tools = _Tools(active=True, session=session)
    source = DiplomacySource(tools)
    context = source.context()
    original_health = session.health

    def changing_health():
        value = original_health()
        if session.health_calls >= 2:
            value["date_raw"] = 56560001
        return value

    session.health = changing_health
    result = source.read(
        _query({"type": "country_pair", "actor": "FRA", "recipient": "SAV"}),
        context,
    )
    assert result["fields"]["favor_tasks"] == {
        "status": "unknown",
        "reason": "FAVOR_TASKS_CONTEXT_CHANGED_DURING_QUERY",
    }

