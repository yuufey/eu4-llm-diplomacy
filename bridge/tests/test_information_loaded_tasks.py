"""Captured child objects determine membership independently of current files."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.missions import MissionInformationSource, NativeMissionReader
from bridge.tests.test_information_missions import Definitions, State, query


def make_service(tmp_path, ids=("first", "runtime_only")):
    state, definitions = State(), Definitions()
    state.sample["loaded_tasks"] = {"status": "known", "roots": [
        {"root_id": "loaded", "task_ids": list(ids)}]}
    adapter = MissionInformationSource(state, definitions, state.capture)
    api = InformationService(CompositeSource(state, [adapter]), tmp_path / "info.db")
    return api, state, definitions


def test_loaded_ids_are_not_replaced_by_current_file_membership(tmp_path):
    api, state, definitions = make_service(tmp_path)
    try:
        result = api.query("actual", queries=[query("M01", ["task_id"]), query("M04", ["rewards"])])
        field = result["items"][0]["fields"]["task_id"]
        assert [entry["task_id"] for entry in field["value"]] == ["first", "runtime_only"]
        assert field["membership_source"] == "captured_loaded_task_objects"
        assert all(entry["branch_visibility"] == "unknown" for entry in field["value"])
        compare = result["items"][0]["source"]["provenance"]["task_definition_comparison"]
        assert compare["loaded_without_current_definition"] == [{"root_id": "loaded", "task_id": "runtime_only"}]
        assert compare["current_definition_not_loaded"] == [{"root_id": "loaded", "task_id": "second"}]
        assert result["items"][1]["fields"]["rewards"]["reason"] == "LOADED_TASK_DEFINITION_MISSING"
    finally:
        api.close()


def test_runtime_membership_and_selected_completion_survive_missing_definitions(tmp_path):
    api, state, definitions = make_service(tmp_path)
    definitions.ready = False
    try:
        result = api.query("no-files", queries=[query("M01", ["task_id", "branches"]),
            query("M02", ["completion_status"], task_id="runtime_only"), query("M04", ["rewards"])])
        assert result["items"][0]["complete"] is True
        assert result["items"][1]["fields"]["completion_status"]["value"]["selected_task"] == {
            "task_id": "runtime_only", "completed": False}
        assert result["items"][2]["fields"]["rewards"]["reason"] == "MISSION_DEFINITIONS_UNAVAILABLE"
    finally:
        api.close()


def test_unloaded_static_task_cannot_be_selected(tmp_path):
    api, state, definitions = make_service(tmp_path)
    try:
        result = api.query("not-loaded", queries=[query("M02", ["completion_status", "prerequisites"], task_id="second")])
        assert all(field["reason"] == "TASK_NOT_IN_CAPTURED_LOADED_TASKS"
                   for field in result["items"][0]["fields"].values())
    finally:
        api.close()


def test_unknown_task_capture_preserves_roots_but_does_not_fall_back_to_static_ids(tmp_path):
    api, state, definitions = make_service(tmp_path)
    state.sample["loaded_tasks"] = {"status": "unknown", "reason": "TASK_VTABLE_MISMATCH"}
    try:
        result = api.query("unknown", queries=[query("M01", ["task_id", "branches"]),
            query("M02", ["completion_status"]), query("M02", ["completion_status"], task_id="first")])
        fields = result["items"][0]["fields"]
        assert fields["task_id"]["reason"] == "TASK_VTABLE_MISMATCH"
        assert fields["branches"]["status"] == "known"
        assert result["items"][1]["fields"]["completion_status"]["status"] == "known"
        assert result["items"][2]["fields"]["completion_status"]["reason"] == "TASK_VTABLE_MISMATCH"
    finally:
        api.close()


def test_empty_loaded_vector_is_not_populated_from_definition_file(tmp_path):
    api, state, definitions = make_service(tmp_path, ())
    try:
        result = api.query("empty", queries=[query("M01", ["task_id"]), query("M02", ["prerequisites"])])
        assert result["items"][0]["fields"]["task_id"]["value"] == []
        assert result["items"][1]["fields"]["prerequisites"]["value"] == []
    finally:
        api.close()


@pytest.mark.parametrize("roots,reason", [
    ([], "LOADED_TASK_ROOTS_INCOMPLETE"),
    ([{"root_id": "other", "task_ids": ["first"]}], "LOADED_TASKS_INVALID"),
    ([{"root_id": "loaded", "task_ids": ["first", "first"]}], "LOADED_TASKS_INVALID"),
    ([{"root_id": "loaded", "task_ids": ["first"]}, {"root_id": "loaded", "task_ids": ["second"]}], "LOADED_TASK_ROOT_CONFLICT"),
])
def test_partial_or_conflicting_runtime_membership_remains_unknown(tmp_path, roots, reason):
    api, state, definitions = make_service(tmp_path)
    state.sample["loaded_tasks"]["roots"] = deepcopy(roots)
    try:
        result = api.query("invalid", queries=[query("M01", ["task_id", "branches"])])
        assert result["items"][0]["fields"]["task_id"]["reason"] == reason
        assert result["items"][0]["fields"]["branches"]["status"] == "known"
    finally:
        api.close()


def test_definition_change_invalidates_rules_but_not_captured_task_ids(tmp_path):
    api, state, definitions = make_service(tmp_path, ("first",))
    original = definitions.roots

    def read_then_change(ids):
        result = original(ids)
        definitions.ready = False
        return result

    definitions.roots = read_then_change
    try:
        result = api.query("changed", queries=[query("M01", ["task_id"])])
        assert result["items"][0]["fields"]["task_id"]["status"] == "known"
        definitions.ready = True
        result = api.query("rules-changed", queries=[query("M04", ["rewards"])])
        assert result["items"][0]["fields"]["rewards"]["status"] == "stale"
    finally:
        api.close()


def retained_capture():
    fixture = json.loads((Path(__file__).parent / "fixtures/information_loaded_tasks_live_1374.json").read_text(encoding="utf-8"))
    assert fixture["provenance"]["mode"] == "recorded"
    return fixture["native_capture"], fixture["original_context"]


def test_retained_native_children_are_not_derived_from_a_definition_index():
    raw, context = retained_capture()
    state = NativeMissionReader.normalize(raw, context)
    assert state["loaded_tasks"]["status"] == "known"
    assert len(state["loaded_tasks"]["roots"]) == 18
    assert sum(len(root["task_ids"]) for root in state["loaded_tasks"]["roots"]) == 61
    assert state["loaded_tasks"]["roots"][0]["task_ids"] == [
        "fra_liberate_norm", "fra_burg_succession", "fra_border_empire"]
    assert state["provenance"]["loaded_tasks_same_doublepass"] is True
    assert state["provenance"]["branch_visibility_evaluated"] is False
    assert state["provenance"]["task_reader"]["profile_sha256"] == "3f855893f34a2203c4f77f885e2d68ebcf4e4d76ca33d8eea3ba9a6e9c648fd6"


@pytest.mark.parametrize("change", ["static", "file", "runtime", "task_doublepass",
                                    "root_identity", "vector", "task_id", "count", "task_record"])
def test_task_verification_failure_preserves_captured_roots_and_completion(change):
    raw, context = retained_capture()
    if change in {"static", "file", "runtime"}:
        raw[f"task_{change}_contract_guard" if change == "static" else f"task_{change}_code_guard"]["status"] = "unknown"
    elif change == "task_doublepass":
        raw["doublepass"]["task_consistent"] = False
    elif change == "root_identity":
        raw["loaded_tasks"]["roots"][0]["root_id"] = "another_root"
    elif change == "vector":
        raw["loaded_tasks"]["roots"][0]["vector"] = None
    elif change == "task_id":
        raw["loaded_tasks"]["roots"][0]["task_ids"][0] = "another_task"
    elif change == "count":
        raw["loaded_tasks"]["total_task_count"] = 60
    else:
        raw["loaded_tasks"]["roots"][0]["tasks"][0]["task_id"] = None
    state = NativeMissionReader.normalize(raw, context)
    assert state["loaded_tasks"]["status"] == "unknown"
    assert len(state["mission_slots"]) == 5
    assert sum(len(slot["roots"]) for slot in state["mission_slots"]) == 18
    assert state["completed_missions"] == {"status": "known", "task_ids": []}


def test_failed_handle_cleanup_rejects_the_whole_native_snapshot():
    raw, context = retained_capture()
    raw["cleanup"]["handle_close"]["closed"] = False
    with pytest.raises(Exception) as error:
        NativeMissionReader.normalize(raw, context)
    assert error.value.code == "mission_snapshot_incomplete"


@pytest.mark.parametrize('section', [
    'identity', 'request', 'static_contract_guard', 'doublepass', 'before',
    'file_code_guard', 'runtime_code_guard', 'cleanup', 'handle_close',
    'missions', 'mission_contract',
])
def test_null_audit_sections_report_incomplete_instead_of_raising_attribute_error(section):
    raw, context = retained_capture()
    if section == 'handle_close':
        raw['cleanup']['handle_close'] = None
    elif section in {'missions', 'mission_contract'}:
        raw['before'][section] = None
    else:
        raw[section] = None
    with pytest.raises(Exception) as error:
        NativeMissionReader.normalize(raw, context)
    assert error.value.code == 'mission_snapshot_incomplete'
