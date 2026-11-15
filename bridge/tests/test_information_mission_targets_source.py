"""Mission target rules are scoped to loaded tasks and retain old topic behavior."""

from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information.mission_definitions import MissionDefinitionError
from bridge.information.missions import FIELDS, MissionInformationSource


def scalar(key: str, value: str, line: int, operator: str = "=") -> dict:
    return {
        "key": key,
        "line": line,
        "end_line": line,
        "value": value,
        "children": [],
        "ast_semantics": "structural",
        "kind": "scalar",
        "assignment": operator,
        "operator": operator,
        "raw_key": key,
        "raw_value": value,
    }


def block(key: str, children: list[dict], line: int = 1, operator: str = "=") -> dict:
    return {
        "key": key,
        "line": line,
        "end_line": max([line, *(child["end_line"] for child in children)]),
        "value": None,
        "children": children,
        "ast_semantics": "structural",
        "kind": "block",
        "assignment": operator,
        "operator": operator,
        "raw_key": key,
        "raw_value": "{",
    }


def task(task_id: str, *trigger_nodes: dict, effect=None) -> dict:
    trigger = block("trigger", list(trigger_nodes), 1)
    return {
        "task_id": task_id,
        "required_missions": [],
        "trigger": trigger,
        "effect": deepcopy(effect or {"treasury": 10}),
        "source": {
            "path": "missions/example.txt",
            "sha256": "a" * 64,
            "source_kind": "base_game",
            "line": 1,
            "end_line": trigger["end_line"],
            "encoding": {"name": "utf-8-sig"},
        },
    }


class State:
    def __init__(self):
        self.current = {
            "status": "ready", "mode": "live", "observer": "FRA",
            "game_version": "1.37.4", "session_id": "mission-target-session",
            "game_date": 56556984, "game_day": 2356541,
        }
        self.sample = {
            "complete": True, "country": "FRA", "mode": "live",
            "session_id": "mission-target-session", "game_date": 56556984,
            "state_kind": "captured_country_mission_slots",
            "mission_slots": [{"slot": 1, "roots": ["root_main", "root_extra"]}],
            "completed_missions": {"status": "known", "task_ids": ["task_owned"]},
            "loaded_tasks": {"status": "known", "roots": [
                {"root_id": "root_main", "task_ids": ["task_owned", "task_core"]},
                {"root_id": "root_extra", "task_ids": ["task_region"]},
            ]},
            "provenance": {"fixture": "independent_loaded_task_set"},
        }
        self.calls = 0

    def context(self):
        return deepcopy(self.current)

    def capture(self, country):
        self.calls += 1
        assert country == "FRA"
        return deepcopy(self.sample)


class Definitions:
    def __init__(self):
        self.values = {
            "root_main": {
                "root_id": "root_main", "slot": 1, "tasks": [
                    task("task_owned", scalar("owns", "183", 2),
                         scalar("controlled_by", "FRA", 3), effect={"treasury": 10}),
                    task("task_core", scalar("owns_core_province", "186", 5),
                         effect={"add_prestige": 5}),
                    task("not_loaded", scalar("owns", "999", 7)),
                ],
                "source": {"path": "missions/example.txt", "sha256": "b" * 64,
                           "line": 1, "end_line": 8},
            },
            "root_extra": {
                "root_id": "root_extra", "slot": 1,
                "tasks": [task("task_region", scalar("region", "france_region", 9))],
                "source": {"path": "missions/example.txt", "sha256": "c" * 64,
                           "line": 9, "end_line": 10},
            },
        }
        self.sha = "definitions-v1"
        self.mutate_after_first_context = False
        self.context_calls = 0

    def context(self):
        self.context_calls += 1
        digest = self.sha
        if self.mutate_after_first_context and self.context_calls >= 2:
            digest = "definitions-changed-during-read"
        return {"status": "ready", "game_version": "1.37.4",
                "configuration_sha256": "config-v1", "definitions_sha256": digest,
                "reasons": [], "script_parser": {"status": "ready", "name": "fake"}}

    def roots(self, ids):
        missing = [root_id for root_id in ids if root_id not in self.values]
        if missing:
            raise MissionDefinitionError("UNKNOWN_ROOT_ID", missing[0])
        return [deepcopy(self.values[root_id]) for root_id in ids]

    def root(self, root_id):
        if root_id not in self.values:
            raise MissionDefinitionError("UNKNOWN_ROOT_ID", root_id)
        return deepcopy(self.values[root_id])


def query(topic: str, fields: list[str], **parameters) -> dict:
    return {"topic": topic, "object": {"type": "country", "country": "FRA"},
            "fields": fields, "parameters": parameters}


def make_source():
    state, definitions = State(), Definitions()
    source = MissionInformationSource(state, definitions, state.capture, scheduling=False)
    return source, state, definitions


def target_rows(field_result: dict) -> list[dict]:
    assert field_result["status"] == "known"
    assert field_result["complete"] is False
    assert field_result["value"]["evaluated"] is False
    assert field_result["value"]["scope_targets_resolved"] is False
    return field_result["value"]["rules"]


def set_task_encoding(definitions: Definitions, task_id: str, encoding: dict) -> None:
    for root in definitions.values.values():
        for item in root["tasks"]:
            if item["task_id"] == task_id:
                item["source"]["encoding"] = deepcopy(encoding)
                return
    raise AssertionError(f"fixture task not found: {task_id}")


def test_catalog_and_m03_use_only_captured_loaded_root_and_task_membership():
    source, state, _definitions = make_source()
    catalog = {row["topic_id"]: row for row in source.catalog()}
    assert set(catalog["M03"]["fields"]) == set(FIELDS["M03"])
    assert all(catalog["M03"]["fields"][field]["coverage"] == "partial" for field in FIELDS["M03"])
    assert catalog["M03"]["fields"]["provinces"]["runtime_conditions_evaluated"] is False
    assert catalog["M03"]["fields"]["provinces"]["scope_targets_resolved"] is False

    result = source.read(query("M03", ["provinces", "countries", "cores"]), state.context())
    assert [row["literal_value"] for row in target_rows(result["fields"]["provinces"])] == [183, 186]
    assert [row["task_id"] for row in target_rows(result["fields"]["provinces"])] == ["task_owned", "task_core"]
    assert [row["literal_value"] for row in target_rows(result["fields"]["countries"])] == ["FRA"]
    assert [row["literal_value"] for row in target_rows(result["fields"]["cores"])] == [186]
    assert "not_loaded" not in {row["task_id"] for row in target_rows(result["fields"]["provinces"])}
    assert result["source"]["provenance"]["task_membership_source"] == "captured_loaded_task_objects"
    assert result["source"]["provenance"]["target_rule_projection"]["runtime_conditions_evaluated"] is False
    assert state.calls == 1


def test_partial_target_projector_result_preserves_known_rules_and_gap(monkeypatch):
    from bridge.information import mission_target_rules_v2

    source, state, _definitions = make_source()
    partial = {
        "status": "partial", "complete": False,
        "value": {"evaluated": False, "scope_targets_resolved": False,
                  "full_target_set_resolved": False,
                  "rules": [{"command_key": "owns", "literal_value": 183}]},
        "gaps": [{"reason": "DYNAMIC_SCOPE_SYMBOL_UNRESOLVED", "field": "provinces"}],
    }
    calls = []

    def partial_projector(tasks, field, *, scope_index=None, _prepared=None):
        # This is the source's v2 projector boundary. Patching the v1 leaf
        # with a two-argument callable rejects v2's internal classifier hooks
        # before the source can exercise its partial-result normalization.
        calls.append((deepcopy(tasks), field, scope_index, _prepared))
        return deepcopy(partial)

    monkeypatch.setattr(mission_target_rules_v2, "project_target_rules", partial_projector)

    result = source.read(query("M03", ["provinces"]), state.context())
    field = result["fields"]["provinces"]
    assert field["status"] == "known"
    assert field["complete"] is False
    assert field["value"] == partial["value"]
    assert field["gaps"] == partial["gaps"]
    assert len(calls) == 1
    assert calls[0][1] == "provinces" and calls[0][2] is None
    assert isinstance(calls[0][3], mission_target_rules_v2.PreparedScopeProjection)
    assert {task["task_id"] for task in calls[0][0]} == {"task_owned", "task_core", "task_region"}
    assert state.calls == 1


def test_source_accepts_preserved_windows_1252_slot_and_keeps_literal_rule():
    source, state, definitions = make_source()
    encoding = {
        "name": "windows-1252",
        "structural_only": True,
        "c1_byte_slots_preserved": ["8d"],
    }
    set_task_encoding(definitions, "task_owned", encoding)

    result = source.read(query("M03", ["provinces"], task_id="task_owned"), state.context())
    field = result["fields"]["provinces"]
    assert field["status"] == "known"
    assert field["complete"] is False
    assert [(row["command_key"], row["literal_value"])
            for row in target_rows(field)] == [("owns", 183)]
    assert field["value"]["tasks"][0]["source"]["encoding"] == encoding


@pytest.mark.parametrize("encoding", [
    {"name": "windows-1252", "structural_only": True,
     "c1_byte_slots_preserved": ["82"]},
    {"name": "windows-1252", "structural_only": True,
     "c1_byte_slots_preserved": ["81", "81"]},
    {"name": "windows-1252", "structural_only": True,
     "other_byte_slots": ["8d"]},
], ids=["illegal-slot", "duplicate-slot", "unapproved-list"])
def test_source_rejects_invalid_encoding_slot_lists_without_rule_value(encoding):
    source, state, definitions = make_source()
    set_task_encoding(definitions, "task_owned", encoding)

    result = source.read(query("M03", ["provinces"], task_id="task_owned"), state.context())
    field = result["fields"]["provinces"]
    assert field["status"] == "unknown"
    assert field["reason"] == "TARGET_REFERENCES_UNRESOLVED"
    assert "value" not in field
    assert field["tasks"][0]["status"] == "unknown"
    assert field["tasks"][0]["reason"] == "TASK_SOURCE_ENCODING_OVERSIZE"


def test_m03_root_and_task_selectors_are_intersections_with_loaded_membership():
    source, state, _definitions = make_source()
    root_selected = source.read(query("M03", ["provinces"], root_id="root_main"), state.context())
    assert {row["task_id"] for row in target_rows(root_selected["fields"]["provinces"])} == {
        "task_owned", "task_core",
    }
    task_selected = source.read(query("M03", ["provinces"], task_id="task_core"), state.context())
    assert [(row["task_id"], row["literal_value"]) for row in target_rows(task_selected["fields"]["provinces"])] == [
        ("task_core", 186),
    ]
    not_captured_root = source.read(
        query("M03", ["provinces"], root_id="not_captured_root"), state.context())
    assert not_captured_root["fields"]["provinces"]["status"] == "unknown"
    assert not_captured_root["fields"]["provinces"]["reason"] == "ROOT_NOT_IN_CAPTURED_MISSION_SLOTS"
    assert "value" not in not_captured_root["fields"]["provinces"]
    not_loaded = source.read(query("M03", ["provinces"], task_id="not_loaded"), state.context())
    assert not_loaded["fields"]["provinces"]["status"] == "unknown"
    assert not_loaded["fields"]["provinces"]["reason"] == "TASK_NOT_IN_CAPTURED_LOADED_TASKS"
    assert "value" not in not_loaded["fields"]["provinces"]


def test_failed_or_incomplete_loaded_membership_never_becomes_empty_targets():
    source, state, _definitions = make_source()
    state.sample["loaded_tasks"] = {"status": "unknown", "reason": "TASK_CAPTURE_UNVERIFIED"}
    failed = source.read(query("M03", ["provinces"]), state.context())
    assert failed["fields"]["provinces"] == {"status": "unknown", "reason": "TASK_CAPTURE_UNVERIFIED"}
    assert "value" not in failed["fields"]["provinces"]

    source, state, _definitions = make_source()
    state.sample["loaded_tasks"]["roots"] = [{"root_id": "root_main", "task_ids": ["task_owned"]}]
    incomplete = source.read(query("M03", ["provinces"]), state.context())
    assert incomplete["fields"]["provinces"]["status"] == "unknown"
    assert incomplete["fields"]["provinces"]["reason"] == "LOADED_TASK_ROOTS_INCOMPLETE"
    assert "value" not in incomplete["fields"]["provinces"]


def test_loaded_task_without_current_definition_and_definition_drift_are_gaps():
    source, state, definitions = make_source()
    state.sample["loaded_tasks"]["roots"][0]["task_ids"].append("captured_but_missing")
    missing = source.read(query("M03", ["provinces"]), state.context())
    assert missing["fields"]["provinces"]["status"] == "unknown"
    assert missing["fields"]["provinces"]["reason"] == "LOADED_TASK_DEFINITION_MISSING"
    assert "value" not in missing["fields"]["provinces"]

    source, state, definitions = make_source()
    definitions.mutate_after_first_context = True
    stale = source.read(query("M03", ["provinces"]), state.context())
    assert stale["fields"]["provinces"]["status"] == "stale"
    assert "value" not in stale["fields"]["provinces"]


def test_m01_m02_and_m04_keep_their_existing_membership_and_raw_rule_shapes():
    source, state, _definitions = make_source()
    m01 = source.read(query("M01", ["task_id", "branches"]), state.context())
    assert [entry["task_id"] for entry in m01["fields"]["task_id"]["value"]] == [
        "task_owned", "task_core", "task_region",
    ]
    assert m01["fields"]["branches"]["status"] == "known"

    m02 = source.read(query("M02", ["completion_status"]), state.context())
    assert m02["fields"]["completion_status"]["value"]["completed_task_ids"] == ["task_owned"]

    m04 = source.read(query("M04", ["rewards"]), state.context())
    assert m04["fields"]["rewards"]["status"] == "known"
    assert m04["fields"]["rewards"]["value"]["evaluated"] is False
    assert m04["fields"]["rewards"]["value"]["tasks"][0]["effect"] == {"treasury": 10}
