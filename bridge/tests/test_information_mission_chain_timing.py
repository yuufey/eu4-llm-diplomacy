"""Consumer tests for the selected M05 reward-timing projection."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information.catalog import get_topic
from bridge.information.mission_chain_timing import FIELD, MissionChainTimingSource
from bridge.information.mission_reward_duration import SCHEMA as DURATION_SCHEMA
from bridge.information.model import InformationError
from bridge.tests import test_information_mission_reward_duration_integration as fixture


def _query(*, root_id="root_main", task_id="task_owned", country="FRA",
           parameters=None):
    return {
        "topic": "M05",
        "object": {"type": "country", "country": country},
        "fields": [FIELD],
        "parameters": (deepcopy(parameters) if parameters is not None else {
            "root_id": root_id, "task_id": task_id,
        }),
    }


def _source_with_known_duration(*, task_id="task_owned"):
    missions, primary, state, definitions = fixture._live_source()
    fixture._put_effect(
        definitions, task_id,
        fixture._command("add_country_modifier", fixture.scalar("duration", "7300", 11)),
    )
    return MissionChainTimingSource(missions), missions, primary, state, definitions


def test_known_timing_binds_exact_loaded_task_and_preserves_m04_metadata():
    source, missions, primary, state, definitions = _source_with_known_duration()
    calls = []
    original_read = missions.read

    def counted_read(query, context=None):
        calls.append(deepcopy(query))
        return original_read(query, context)

    missions.read = counted_read
    result = source.read(_query(), primary.context())
    field = result["fields"][FIELD]
    value = field["value"]

    assert len(calls) == 1
    assert calls[0]["topic"] == "M04" and calls[0]["fields"] == ["duration"]
    assert calls[0]["parameters"] == {"root_id": "root_main", "task_id": "task_owned"}
    assert field["status"] == "known" and field["complete"] is False
    assert value["candidate"] == {
        "root_id": "root_main", "task_id": "task_owned", "country": "FRA",
    }
    assert value["conditions_evaluated"] is False
    assert value["effects_executed"] is False
    assert value["candidate_feasibility"] == "unknown"
    assert value["applied"] == value["start_time"] == value["expiry_time"] == "unknown"
    assert value["complete"] is False
    timing = value["declared_timing"]
    assert timing["field"] == "duration"
    row = timing["rules"][0]
    assert (row["root_id"], row["task_id"], row["status"]) == (
        "root_main", "task_owned", "known",
    )
    assert row["rules"][0]["terms"][0]["raw_integer"] == 7300
    provenance = result["source"]["provenance"]
    assert provenance["task_membership_source"] == "captured_loaded_task_objects"
    assert provenance["task_membership_status"] == "known"
    assert "state" in provenance and "definitions" in provenance
    projection = provenance["reward_timing_projection"]
    assert projection["source_topic"] == "M04" and projection["source_field"] == "duration"
    assert projection["duration_schema"] == DURATION_SCHEMA
    assert projection["duration_provenance"]
    assert projection["selector"] == {"root_id": "root_main", "task_id": "task_owned"}

    topics = {topic["topic_id"]: topic for topic in source.catalog()}
    topic = topics["M05"]
    assert topic["title"] == get_topic("M05")["title"]
    m04 = next(item for item in missions.catalog() if item["topic_id"] == "M04")
    for key in ("context_scope", "visibility", "observer_roles", "object_types",
                "triggers", "supported_versions"):
        if key in m04:
            assert topic[key] == m04[key]
    assert set(topic["fields"]) == {FIELD}
    assert topic["fields"][FIELD]["coverage"] == "partial"
    assert topic["parameters"]["required"] == ["root_id", "task_id"]


def test_required_selectors_and_country_scope_are_validated_by_m04_source():
    source, missions, primary, state, _definitions = _source_with_known_duration()
    context = primary.context()
    before_calls = state.calls

    for parameters in (
        {"task_id": "task_owned"},
        {"root_id": "root_main"},
        {"root_id": "root_main", "task_id": "bad/task"},
    ):
        with pytest.raises(InformationError):
            source.validate_query(_query(parameters=parameters), context)

    with pytest.raises(InformationError) as caught:
        source.read(_query(country="ENG"), context)
    assert caught.value.code == "observer_scope_mismatch"
    assert state.calls == before_calls


def test_wrong_root_task_pair_and_task_without_duration_stay_unknown():
    source, _missions, primary, state, _definitions = _source_with_known_duration()

    wrong_pair = source.read(
        _query(root_id="root_main", task_id="task_region"), primary.context(),
    )["fields"][FIELD]
    assert wrong_pair["status"] == "unknown"
    assert wrong_pair["reason"] == "TASK_NOT_IN_CAPTURED_LOADED_TASKS"
    assert "value" not in wrong_pair

    no_duration = source.read(
        _query(root_id="root_main", task_id="task_core"), primary.context(),
    )["fields"][FIELD]
    assert no_duration["status"] == "unknown"
    assert no_duration["reason"] == "NO_DURATION_RULE_MATCH"
    assert "value" not in no_duration
    assert state.calls == 2


def test_live_static_root_without_verified_loaded_task_membership_is_unknown():
    source, _missions, primary, state, _definitions = _source_with_known_duration()
    state.sample.pop("loaded_tasks")

    result = source.read(_query(), primary.context())
    field = result["fields"][FIELD]
    provenance = result["source"]["provenance"]

    assert provenance["task_membership_source"] == "current_definitions_for_captured_roots"
    assert field["status"] == "unknown"
    assert field["reason"] == "LOADED_TASK_MEMBERSHIP_REQUIRED_FOR_REWARD_TIMING"
    assert "value" not in field
    assert state.calls == 1


def test_definition_change_during_m04_read_preserves_stale_refusal():
    source, _missions, primary, state, definitions = _source_with_known_duration()
    definitions.mutate_after_first_context = True

    result = source.read(_query(), primary.context())
    field = result["fields"][FIELD]

    assert field["status"] == "stale"
    assert field["reason"] == "MISSION_DEFINITIONS_CHANGED_DURING_COLLECTION"
    assert "value" not in field
    assert state.calls == 1


def test_known_duration_with_mismatched_rule_identity_is_withheld():
    source, missions, primary, state, _definitions = _source_with_known_duration()
    original_read = missions.read

    def mismatched_read(query, context=None):
        result = original_read(query, context)
        result["fields"]["duration"]["value"]["rules"][0]["task_id"] = "task_core"
        return result

    missions.read = mismatched_read
    field = source.read(_query(), primary.context())["fields"][FIELD]

    assert field["status"] == "unknown"
    assert field["reason"] == "MISSION_DURATION_TASK_BINDING_UNVERIFIED"
    assert "value" not in field
    assert state.calls == 1


def test_mixed_known_and_unknown_duration_terms_are_preserved():
    missions, primary, _state, definitions = fixture._live_source()
    fixture._put_effect(
        definitions, "task_owned",
        fixture._command("add_country_modifier", fixture.scalar("duration", "30", 11)),
        fixture._command("add_trade_modifier", fixture.scalar("duration", "12", 12)),
        fixture._command("add_claim", fixture.scalar("who", "ENG", 13)),
    )
    adapter = MissionChainTimingSource(missions)

    field = adapter.read(_query(), primary.context())["fields"][FIELD]

    assert field["status"] == "known"
    timing = field["value"]["declared_timing"]
    row = timing["rules"][0]
    rules = {item["command"]: item for item in row["rules"]}
    assert rules["add_country_modifier"]["terms"][0]["status"] == "known"
    assert rules["add_trade_modifier"]["terms"][0]["reason"] == "UNIT_NOT_ESTABLISHED_BY_CWT"
    assert rules["add_claim"]["terms"][0]["reason"] == "CWT_DURATION_NOT_DECLARED"
    unknown_row = {**row, "status": "unknown", "reason": {"code": "PARTIAL_TASK_ROW"}}
    assert adapter._selected_duration_matches(
        {**timing, "rules": [unknown_row]}, "root_main", "task_owned",
    ) is True
