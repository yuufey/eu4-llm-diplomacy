"""M05 relates the existing M02/M03 projections without a second capture."""
from copy import deepcopy

import pytest

from bridge.information.composite import CompositeSource
from bridge.information.mission_chain_targets import MissionChainTargetsSource
from bridge.information.mission_chain_timing import MissionChainTimingSource
from bridge.information.model import InformationError
from bridge.tests import test_information_mission_reward_duration_integration as fixture


def setup_source():
    missions, primary, state, definitions = fixture._live_source()
    dependencies = {"task_owned": [], "task_core": ["task_owned"], "task_region": ["task_core"]}
    state.sample["loaded_prerequisites"] = {
        "status": "known", "tasks": [
            {"root_id": root["root_id"], "task_id": task, "required_task_ids": dependencies[task]}
            for root in state.sample["loaded_tasks"]["roots"] for task in root["task_ids"]],
    }
    fixture._put_effect(definitions, "task_core",
        fixture._command("add_country_modifier", fixture.scalar("duration", "30", 11)))
    return MissionChainTargetsSource(missions), missions, primary, state, definitions


def query(fields=("linked_targets", "basis"), **params):
    return {"topic": "M05", "object": {"type": "country", "country": "FRA"},
            "fields": list(fields), "parameters": params or {"root_id": "root_main", "task_id": "task_core"}}


def test_one_capture_is_reused_by_both_public_projectors(monkeypatch):
    source, _missions, primary, state, _definitions = setup_source()
    captured = []

    def project(prerequisites, targets, selector):
        captured.append(deepcopy((prerequisites, targets, selector)))
        return {field: {"status": "known", "value": field, "complete": False}
                for field in ("linked_targets", "basis")}

    monkeypatch.setattr("bridge.information.mission_chain_graph.project_chain", project)
    result = source.read(query(), primary.context())
    assert state.calls == 1 and len(captured) == 1
    prerequisites, targets, selector = captured[0]
    assert prerequisites["value_origin"] == "captured_loaded_required_missions"
    assert {(row["root_id"], row["task_id"]) for row in prerequisites["value"]} == {
        ("root_main", "task_owned"), ("root_main", "task_core"), ("root_extra", "task_region")}
    assert set(targets) == {"provinces", "regions", "countries", "ownership", "control", "cores", "subjects"}
    assert selector == query()["parameters"]
    proof = result["source"]["provenance"]
    assert proof["single_captured_state"] is True
    assert proof["prerequisites"]["provenance"]["state"] == proof["targets"]["provenance"]["state"]
    assert result["complete"] is False


def test_mixed_timing_and_targets_route_through_the_same_m05_parameters():
    source, missions, primary, state, _definitions = setup_source()
    combined = CompositeSource(primary, [missions, MissionChainTimingSource(missions), source])
    request = query(("linked_targets", "reward_timing", "basis"))
    normalized = combined.validate_query(request)
    result = combined.read(normalized, primary.context())
    assert set(result["fields"]) == set(request["fields"])
    assert all(value["status"] == "known" for value in result["fields"].values())
    assert state.calls == 2  # one timing capture, one shared chain capture
    assert result["fields"]["reward_timing"]["value"]["candidate_feasibility"] == "unknown"
    topic = next(row for row in combined.catalog() if row["topic_id"] == "M05")
    assert topic["fields"]["costs"]["coverage"] == "planned"
    assert topic["parameters"]["required"] == ["root_id", "task_id"]
    assert all(topic["fields"][field]["coverage"] == "partial" for field in request["fields"])


def test_definition_change_between_components_withdraws_the_join(monkeypatch):
    source, _missions, primary, state, definitions = setup_source()
    definitions.mutate_after_first_context = True
    monkeypatch.setattr("bridge.information.mission_chain_graph.project_chain",
                        lambda *args: pytest.fail("changed input must not reach graph projector"))
    result = source.read(query(), primary.context())
    assert state.calls == 1
    for field in result["fields"].values():
        assert field["status"] == "unknown"
        assert field["reason"] == "MISSION_CHAIN_INPUTS_UNVERIFIED_OR_CHANGED"
        assert "value" not in field


def test_static_prerequisite_fallback_cannot_become_loaded_chain():
    source, _missions, primary, state, _definitions = setup_source()
    del state.sample["loaded_prerequisites"]
    result = source.read(query(), primary.context())
    assert state.calls == 1
    assert result["fields"]["linked_targets"]["status"] == "unknown"


def test_required_pair_country_and_fields_are_checked_before_capture():
    source, _missions, primary, state, _definitions = setup_source()
    for params in ({"task_id": "task_core"}, {"root_id": "root_main"},
                   {"root_id": "root_main", "task_id": "bad/task"}):
        with pytest.raises(InformationError):
            source.read(dict(query(), parameters=params), primary.context())
    with pytest.raises(InformationError) as error:
        source.read(dict(query(), object={"type": "country", "country": "ENG"}), primary.context())
    assert error.value.code == "observer_scope_mismatch"
    for fields in ([], ["costs"], ["basis", "basis"], [False]):
        with pytest.raises(InformationError):
            source.validate_query(dict(query(), fields=fields), primary.context())
    assert state.calls == 0


def test_wrong_snapshot_identity_is_unavailable_and_not_a_graph():
    source, _missions, primary, state, _definitions = setup_source()
    state.sample["session_id"] = "old-session"
    result = source.read(query(), primary.context())
    assert state.calls == 1
    assert all(field["status"] == "unavailable" and field["reason"] == "mission_context_changed"
               for field in result["fields"].values())


def test_unready_context_and_uncaptured_membership_do_not_grant_a_chain():
    source, _missions, primary, state, _definitions = setup_source()
    context = dict(primary.context(), status="unavailable")
    assert all(field["status"] == "unavailable" for field in source.read(query(), context)["fields"].values())
    assert state.calls == 0
    del state.sample["loaded_tasks"]
    assert all(field["status"] == "unknown" for field in source.read(query(), primary.context())["fields"].values())


def test_catalog_advertises_query_and_repeatable_sampling_without_event_claim():
    source, missions, _primary, _state, _definitions = setup_source()
    missions.scheduling = True
    topic = source.catalog()[0]
    assert topic["triggers"] == ["query", "periodic"]
    assert set(topic["fields"]) == {"linked_targets", "basis"}
    assert topic["parameters"] == MissionChainTimingSource(missions).catalog()[0]["parameters"]
