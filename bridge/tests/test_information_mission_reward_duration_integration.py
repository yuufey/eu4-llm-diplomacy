"""M04 duration is a static Source projection, not a live expiry reading."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import InformationService
from bridge.information.catalog import list_topics
from bridge.information.composite import CompositeSource
from bridge.information.model import InformationError, canonical
from bridge.information.missions import FIELDS, MissionInformationSource
from bridge.tests.test_information_mission_targets_source import (
    Definitions, State, block, scalar,
)


class _Primary:
    event_types = ()

    def __init__(self, state: State):
        self.state = state

    def context(self):
        return deepcopy(self.state.current)

    def catalog(self):
        return list_topics()

    def read(self, query, context):
        raise AssertionError(f"M04 should route to MissionInformationSource: {query!r}")

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": deepcopy(cursor or {}), "complete": True, "gaps": []}


def _query(fields=("duration",), **parameters):
    return {
        "topic": "M04",
        "object": {"type": "country", "country": "FRA"},
        "fields": list(fields),
        "parameters": parameters,
    }


def _command(name: str, *children, line: int = 10):
    return block(name, list(children), line)


def _put_effect(definitions: Definitions, task_id: str, *commands):
    for root in definitions.values.values():
        for item in root["tasks"]:
            if item["task_id"] == task_id:
                item["effect"] = block("effect", list(commands), 9)
                return
    raise AssertionError(f"task fixture missing: {task_id}")


def _live_source(*, scheduling=False):
    state, definitions = State(), Definitions()
    primary = _Primary(state)
    source = MissionInformationSource(
        primary, definitions, state.capture, scheduling=scheduling,
    )
    return source, primary, state, definitions


def _duration_result(sample):
    field = sample["fields"]["duration"]
    assert field["complete"] is False
    assert field["value"]["complete"] is False
    value = field["value"]
    assert value["evaluated"] is False
    assert value["applied"] == "unknown"
    assert value["start_time"] == "unknown"
    assert value["expiry_time"] == "unknown"
    return field


def test_source_uses_loaded_root_and_task_membership_for_duration():
    source, primary, _state, definitions = _live_source()
    _put_effect(
        definitions,
        "task_owned",
        _command("add_country_modifier", scalar("duration", "30", 11)),
    )
    # This is a defined task but absent from the captured loaded-task vector.
    _put_effect(
        definitions,
        "not_loaded",
        _command("add_country_modifier", scalar("duration", "999", 12)),
    )

    result = source.read(_query(root_id="root_main"), primary.context())
    field = _duration_result(result)

    assert field["status"] == "known"
    assert field["value"]["task_count"] == 2
    assert {row["task_id"] for row in field["value"]["rules"]} == {
        "task_owned", "task_core",
    }
    owned = next(row for row in field["value"]["rules"] if row["task_id"] == "task_owned")
    assert owned["status"] == "known"
    assert [rule["command"] for rule in owned["rules"]] == ["add_country_modifier"]
    term = owned["rules"][0]["terms"][0]
    assert (term["raw_integer"], term["unit"]) == (30, "days")

    not_loaded = source.read(_query(task_id="not_loaded"), primary.context())
    assert not_loaded["fields"]["duration"]["status"] == "unknown"
    assert not_loaded["fields"]["duration"]["reason"] == "TASK_NOT_IN_CAPTURED_LOADED_TASKS"
    assert "value" not in not_loaded["fields"]["duration"]


def test_known_duration_keeps_mixed_raw_unknown_terms_and_command_units():
    source, primary, _state, definitions = _live_source()
    _put_effect(
        definitions,
        "task_owned",
        _command("add_country_modifier", scalar("duration", "30", 11)),
        _command("add_trade_modifier", scalar("duration", "12", 12)),
        _command("add_claim", scalar("who", "ENG", 13)),
    )

    result = source.read(_query(task_id="task_owned"), primary.context())
    field = _duration_result(result)
    assert field["status"] == "known"
    task = field["value"]["rules"][0]
    assert task["task_id"] == "task_owned"
    rules = {row["command"]: row for row in task["rules"]}
    assert set(rules) == {"add_country_modifier", "add_trade_modifier", "add_claim"}
    known_term = rules["add_country_modifier"]["terms"][0]
    assert (known_term["status"], known_term["raw_integer"], known_term["unit"]) == (
        "known", 30, "days",
    )
    unknown_term = rules["add_trade_modifier"]["terms"][0]
    assert unknown_term["status"] == "unknown"
    assert unknown_term["reason"] == "UNIT_NOT_ESTABLISHED_BY_CWT"
    assert rules["add_claim"]["terms"][0]["reason"] == "CWT_DURATION_NOT_DECLARED"
    assert field["provenance"]["runtime_conditions_evaluated"] is False
    assert field["provenance"]["actual_reward_status"] == "unknown"


def test_actor_mismatch_and_definition_drift_withhold_duration():
    source, primary, _state, definitions = _live_source()
    _put_effect(
        definitions,
        "task_owned",
        _command("add_country_modifier", scalar("duration", "30", 11)),
    )
    mismatched_context = primary.context()
    mismatched_context["observer"] = "ENG"
    with pytest.raises(InformationError) as error:
        source.read(_query(task_id="task_owned"), mismatched_context)
    assert error.value.code == "observer_scope_mismatch"

    definitions.mutate_after_first_context = True
    stale = source.read(_query(task_id="task_owned"), primary.context())
    assert stale["fields"]["duration"]["status"] == "stale"
    assert stale["fields"]["duration"]["reason"] == "MISSION_DEFINITIONS_CHANGED_DURING_COLLECTION"
    assert "value" not in stale["fields"]["duration"]


def test_composite_catalog_keeps_six_m04_fields_and_periodic_uses_same_source(tmp_path):
    state, definitions = State(), Definitions()
    _put_effect(
        definitions,
        "task_owned",
        _command("add_country_modifier", scalar("duration", "30", 11)),
    )
    primary = _Primary(state)
    adapter = MissionInformationSource(primary, definitions, state.capture, scheduling=True)
    source = CompositeSource(primary, [adapter])
    topic = next(row for row in source.catalog() if row["topic_id"] == "M04")

    assert set(topic["fields"]) == {
        "rewards", "unlocks", "claims", "casus_belli", "trade_modifiers", "duration",
    }
    assert topic["fields"]["duration"]["coverage"] == "partial"
    assert topic["fields"]["unlocks"]["coverage"] == "partial"
    assert "periodic" in topic["triggers"]
    assert set(FIELDS["M04"]) == {
        "rewards", "claims", "casus_belli", "trade_modifiers", "duration", "unlocks",
    }

    clock = [100.0]
    service = InformationService(source, tmp_path / "mission-duration-periodic.sqlite3",
                                 clock=lambda: clock[0])
    try:
        query = _query(task_id="task_owned")
        manual = service.query("duration-manual", queries=[query])
        manual_field = _duration_result(manual["items"][0])
        report = service.manage_report(
            "duration-report", "create",
            config={"name": "mission duration", "queries": [query], "detail": "full"},
        )["report"]
        subscription = service.manage_subscription(
            "duration-subscription", "create",
            config={
                "name": "mission duration periodic", "kind": "periodic",
                "report_id": report["id"], "enabled": True,
                "schedule": {"basis": "real", "every": 1, "unit": "seconds",
                             "missed": "coalesce"},
            },
        )["subscription"]
        clock[0] += 1.0
        tick = service.tick()
        assert len(tick["results"]) == 1
        periodic = tick["results"][0]
        assert periodic["subscription_id"] == subscription["id"]
        periodic_field = _duration_result(periodic["items"][0])
        # The manual response is reread from SQLite while tick returns its
        # just-created object. Compare their wire-JSON representation so
        # integer provenance-map keys receive the same JSON string encoding.
        assert periodic_field["status"] == manual_field["status"] == "known"
        assert canonical(periodic_field) == canonical(manual_field)
        assert periodic_field == manual_field
        assert state.calls == 2
    finally:
        service.close()
