"""Mission membership, completion facts and unevaluated rule boundaries."""
from copy import deepcopy

import pytest

from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.mission_definitions import MissionDefinitionError
from bridge.information.missions import MissionInformationSource
from bridge.tests.test_information_composite import topic


class State:
    event_types = ()

    def __init__(self):
        self.current = {"status": "ready", "mode": "live", "observer": "FRA", "game_version": "1.37.4",
                        "session_id": "mission-session", "game_date": 24, "game_day": 1}
        self.calls = 0
        self.sample = {"complete": True, "country": "FRA", "mode": "live", "session_id": "mission-session",
                       "game_date": 24, "state_kind": "captured_country_mission_slots",
                       "mission_slots": [{"slot": 1, "roots": ["loaded"]}],
                       "completed_missions": {"status": "known", "task_ids": ["first"]}}

    def context(self):
        return deepcopy(self.current)

    def catalog(self):
        from bridge.information.catalog import list_topics
        return list_topics()

    def read(self, query, context):
        raise AssertionError("Mission topic must route to adapter")

    def capture(self, country):
        self.calls += 1
        assert country == "FRA"
        return deepcopy(self.sample)

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": {}, "complete": True, "gaps": []}


class Definitions:
    def __init__(self):
        self.ready = True
        self.values = {
            "loaded": {"root_id": "loaded", "slot": 1, "potential": {"tag": "FRA"},
                       "potential_on_load": {"has_dlc": "Domination"}, "source": {"sha256": "abc"},
                       "tasks": [{"task_id": "first", "required_missions": [], "trigger": {"stability": 1},
                                  "effect": {"if": {"limit": {"tag": "FRA"}, "claims": [1]}}},
                                 {"task_id": "second", "required_missions": ["first"], "trigger": {"owns": 1},
                                  "effect": {"treasury": 10}}]},
            "other": {"root_id": "other", "slot": 1, "tasks": [{"task_id": "must_not_guess"}]}}

    def context(self):
        return {"status": "ready" if self.ready else "unready", "game_version": "1.37.4",
                "definitions_sha256": "definitions"}

    def root(self, root_id):
        if root_id not in self.values:
            raise MissionDefinitionError("UNKNOWN_ROOT_ID", root_id)
        return deepcopy(self.values[root_id])

    def roots(self, ids):
        return [self.root(root_id) for root_id in ids]


def query(topic, fields, **parameters):
    return {"topic": topic, "object": {"type": "country", "country": "FRA"},
            "fields": fields, "parameters": parameters}


def service(tmp_path):
    state, definitions = State(), Definitions()
    adapter = MissionInformationSource(state, definitions, state.capture)
    return InformationService(CompositeSource(state, [adapter]), tmp_path / "info.db"), state, definitions


def test_only_captured_roots_supply_tasks_and_rules_do_not_imply_effects(tmp_path):
    api, state, definitions = service(tmp_path)
    try:
        result = api.query("missions", queries=[query("M01", ["task_id", "branches"]),
                            query("M04", ["rewards"]), query("M02", ["completion_status", "currently_completable"])])
        assert result["status"] == "partial"
        assert [task["task_id"] for task in result["items"][0]["fields"]["task_id"]["value"]] == ["first", "second"]
        rewards = result["items"][1]["fields"]["rewards"]["value"]
        assert rewards["evaluated"] is False and rewards["applied"] == "unknown"
        assert rewards["tasks"][0]["effect"]["if"]["limit"] == {"tag": "FRA"}
        assert result["items"][2]["fields"]["currently_completable"] == {
            'status':'unknown','reason':'LOADED_TASK_MEMBERSHIP_REQUIRED'}
        assert state.calls == 3
    finally:
        api.close()


def test_unavailable_definitions_preserve_captured_membership_and_completion(tmp_path):
    api, state, definitions = service(tmp_path)
    definitions.ready = False
    try:
        result = api.query("unavailable", queries=[query("M01", ["task_id", "branches"]),
                                                   query("M02", ["completion_status"])])
        assert result["items"][0]["fields"]["branches"]["status"] == "known"
        assert result["items"][0]["fields"]["task_id"]["reason"] == "MISSION_DEFINITIONS_UNAVAILABLE"
        assert result["items"][1]["fields"]["completion_status"]["value"]["completed_task_ids"] == ["first"]
    finally:
        api.close()


def test_missing_definition_and_unloaded_selector_are_not_guessed(tmp_path):
    api, state, definitions = service(tmp_path)
    state.sample["mission_slots"][0]["roots"].append("missing")
    try:
        result = api.query("missing", queries=[query("M01", ["task_id", "branches"])])
        assert result["items"][0]["fields"]["task_id"]["reason"] == "LOADED_ROOT_DEFINITION_MISSING"
        assert result["items"][0]["fields"]["branches"]["value"]["slots"][0]["roots"] == ["loaded", "missing"]
        result = api.query("unloaded", queries=[query("M01", ["task_id"], root_id="other")])
        assert result["items"][0]["fields"]["task_id"]["reason"] == "ROOT_NOT_IN_CAPTURED_MISSION_SLOTS"
    finally:
        api.close()


def test_task_filter_completion_and_raw_prerequisites(tmp_path):
    api, state, definitions = service(tmp_path)
    try:
        result = api.query("task", queries=[query("M02", ["prerequisites", "unlock_conditions", "completion_status"], task_id="second")])
        fields = result["items"][0]["fields"]
        assert fields["prerequisites"]["value"][0]["declared_rules"] == ["first"]
        assert fields["unlock_conditions"]["value"]["evaluated"] is False
        assert fields["completion_status"]["value"]["selected_task"] == {"task_id": "second", "completed": False}
        unknown = api.query("unknown-task", queries=[query("M02", ["completion_status"], task_id="not_loaded")])
        assert unknown["items"][0]["fields"]["completion_status"]["reason"] == "TASK_NOT_IN_CAPTURED_MISSION_ROOTS"
    finally:
        api.close()


@pytest.mark.parametrize("mutation", [
    {"session_id": "another"}, {"game_date": 0}, {"country": "ENG"}, {"mode": "recorded"},
    {"complete": False}, {"mission_slots": [{"slot": 1, "roots": [None]}]},
])
def test_malformed_or_changed_state_fails_without_turning_it_into_empty(tmp_path, mutation):
    api, state, definitions = service(tmp_path)
    state.sample.update(mutation)
    try:
        result = api.query("invalid", queries=[query("M01", ["branches"])])
        assert result["status"] == "failed"
        assert result["items"][0]["fields"]["branches"]["status"] == "unavailable"
    finally:
        api.close()


def test_foreign_scope_is_rejected_before_memory_reader(tmp_path):
    api, state, definitions = service(tmp_path)
    try:
        foreign = query("M01", ["branches"])
        foreign["object"]["country"] = "ENG"
        result = api.query("foreign", queries=[foreign])
        assert result["items"][0]["fields"]["branches"]["reason"] == "observer_scope_mismatch"
        assert state.calls == 0
    finally:
        api.close()


def test_definition_change_during_read_invalidates_rules_but_preserves_state(tmp_path):
    api, state, definitions = service(tmp_path)
    original = definitions.roots
    def changed(ids):
        roots = original(ids)
        definitions.ready = False
        return roots
    definitions.roots = changed
    try:
        result = api.query("changed", queries=[query("M01", ["task_id", "branches"])])
        fields = result["items"][0]["fields"]
        assert fields["task_id"]["status"] == "stale"
        assert fields["branches"]["status"] == "known"
    finally:
        api.close()
