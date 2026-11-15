"""Runtime-loaded mission prerequisites stay distinct from disk rules."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.mission_loaded_prerequisites import (
    normalize_prerequisites,
    project_prerequisites,
)
from bridge.information.mission_prerequisite_profile import PROFILE_SHA256
from bridge.information.missions import MissionInformationSource, NativeMissionReader
from bridge.tests.test_information_missions import Definitions, State, query


def _required_rules(*task_ids):
    if not task_ids:
        return []
    return [{
        "key": "required_missions",
        "kind": "block",
        "assignment": "=",
        "value": None,
        "children": [{"key": task_id, "kind": "bare", "assignment": None,
                      "value": None, "children": []} for task_id in task_ids],
    }]


def _service(tmp_path, *, loaded_ids=("first", "second"), native_ids=None,
             roots=("loaded",)):
    state, definitions = State(), Definitions()
    state.sample["mission_slots"] = [{"slot": 1, "roots": list(roots)}]
    state.sample["loaded_tasks"] = {
        "status": "known",
        "roots": [
            {"root_id": "loaded", "task_ids": list(loaded_ids)}
            if root == "loaded" else {"root_id": root, "task_ids": ["must_not_guess"]}
            for root in roots
        ],
    }
    ids_by_root = {"loaded": list(loaded_ids)}
    ids_by_root.update({root: ["must_not_guess"] for root in roots if root != "loaded"})
    native_ids = native_ids or {}
    state.sample["loaded_prerequisites"] = {
        "status": "known",
        "profile_sha256": PROFILE_SHA256,
        "tasks": [
            {"root_id": root, "task_id": task_id,
             "required_task_ids": list(native_ids.get((root, task_id), ())) }
            for root in roots for task_id in ids_by_root[root]
        ],
    }
    # The fixture's string shorthand is useful in older tests. Here use the
    # supported literal AST so the declared-rule comparison is meaningful.
    definitions.values["loaded"]["tasks"][0]["required_missions"] = _required_rules()
    definitions.values["loaded"]["tasks"][1]["required_missions"] = _required_rules("first")
    adapter = MissionInformationSource(state, definitions, state.capture)
    api = InformationService(CompositeSource(state, [adapter]), tmp_path / "info.db")
    return api, state, definitions


def _project(api, request_id="prerequisites", **parameters):
    result = api.query(request_id, queries=[query("M02", ["prerequisites"], **parameters)])
    return result["items"][0]["fields"]["prerequisites"]


def test_loaded_rules_are_returned_when_they_disagree_with_disk_and_completion_is_not_eligibility(tmp_path):
    api, state, definitions = _service(
        tmp_path,
        native_ids={("loaded", "first"): ["first", "runtime_only"]},
    )
    try:
        field = _project(api)
        assert field["status"] == "known"
        first, second = field["value"]

        assert first["value_origin"] == "captured_loaded_required_missions"
        assert first["required_task_ids"] == ["first", "runtime_only"]
        assert first["declared_rules_match_loaded_ids"] is False
        assert first["evaluation"]["status"] == "unknown"
        assert first["evaluation"]["reason"] == "CANONICAL_PREREQUISITE_DEFINITION_LOOKUP_NOT_CAPTURED"
        assert first["evaluation"]["satisfied"] is None
        # "first" is present in the completion capture, but that alone does
        # not establish the native canonical prerequisite lookup result.
        assert "first" in state.sample["completed_missions"]["task_ids"]
        assert first["evaluation"]["native_function_called"] is False

        assert second["required_task_ids"] == []
        assert second["declared_rules_match_loaded_ids"] is False
        assert second["evaluation"]["status"] == "known"
        assert second["evaluation"]["satisfied"] is True
        assert second["evaluation"]["scope"] == "loaded_required_missions_only"
        assert field["complete"] is False
        assert field["task_trigger_evaluated"] is False
        assert field["branch_visibility_evaluated"] is False
    finally:
        api.close()


def test_live_prerequisites_are_available_without_static_definitions(tmp_path):
    api, state, definitions = _service(
        tmp_path,
        native_ids={("loaded", "first"): ["runtime_only"]},
    )
    definitions.ready = False
    try:
        field = _project(api)
        assert field["status"] == "known"
        assert [(entry["task_id"], entry["required_task_ids"]) for entry in field["value"]] == [
            ("first", ["runtime_only"]), ("second", []),
        ]
        assert field["value"][0]["declared_rules"] is None
        assert field["value"][0]["declared_rules_match_loaded_ids"] is None
        assert field["complete"] is False
    finally:
        api.close()


def test_explicitly_unknown_native_capture_does_not_fall_back_to_disk_rules(tmp_path):
    api, state, definitions = _service(tmp_path)
    state.sample["loaded_prerequisites"] = {
        "status": "unknown", "reason": "PREREQUISITE_DOUBLEPASS_MISMATCH",
    }
    try:
        field = _project(api)
        assert field == {"status": "unknown", "reason": "PREREQUISITE_DOUBLEPASS_MISMATCH"}
    finally:
        api.close()


def test_legacy_reader_without_prerequisite_capture_keeps_disk_rule_evaluation(tmp_path):
    state, definitions = State(), Definitions()
    definitions.values["loaded"]["tasks"][1]["required_missions"] = _required_rules("first")
    adapter = MissionInformationSource(state, definitions, state.capture)
    api = InformationService(CompositeSource(state, [adapter]), tmp_path / "legacy.db")
    try:
        field = _project(api, "legacy-prerequisites", task_id="second")
        assert field["status"] == "known"
        entry = field["value"][0]
        assert entry["task_id"] == "second"
        assert entry["declared_rules"] == _required_rules("first")
        assert entry["evaluation"]["status"] == "known"
        assert entry["evaluation"]["satisfied"] is True
        assert "value_origin" not in entry
    finally:
        api.close()


def test_root_and_task_selectors_are_limited_to_captured_loaded_membership(tmp_path):
    api, state, definitions = _service(  # "second" exists on disk but is not loaded.
        tmp_path, loaded_ids=("first",),
    )
    try:
        field = _project(api, "selected-root", root_id="loaded")
        assert field["status"] == "known"
        assert [(entry["root_id"], entry["task_id"]) for entry in field["value"]] == [
            ("loaded", "first"),
        ]

        result = api.query("unloaded-static-task", queries=[
            query("M02", ["prerequisites"], root_id="loaded", task_id="second")
        ])
        field = result["items"][0]["fields"]["prerequisites"]
        assert field["reason"] == "TASK_NOT_IN_CAPTURED_LOADED_TASKS"
    finally:
        api.close()


def _record(root_id, task_id, required_ids=()):
    required_ids = list(required_ids)
    return {"root_id": root_id, "task_id": task_id,
            "required_task_ids": required_ids, "vector": {"count": len(required_ids)}}


def _normalizer_report(records):
    return {
        "request": {"include_prerequisites": True},
        "doublepass": {"prerequisite_consistent": True},
        "prerequisite_profile_sha256": PROFILE_SHA256,
        "cleanup": {"handle_close": {"closed": True}},
        "loaded_prerequisites": {"status": "observed", "complete": True, "tasks": records},
    }


@pytest.mark.parametrize(("mutation", "reason"), [
    ("missing_pair", "LOADED_PREREQUISITE_TASKS_INCOMPLETE"),
    ("invalid_id", "LOADED_PREREQUISITE_VECTOR_INVALID"),
    ("duplicate_record", "LOADED_PREREQUISITE_TASK_MISMATCH"),
])
def test_normalizer_rejects_incomplete_or_malformed_captured_pairs(mutation, reason):
    loaded = {"status": "known", "roots": [{"root_id": "loaded", "task_ids": ["first", "second"]}]}
    records = [_record("loaded", "first", ["runtime_only"]), _record("loaded", "second")]
    if mutation == "missing_pair":
        records.pop()
    elif mutation == "invalid_id":
        records[0]["required_task_ids"] = ["bad task"]
        records[0]["vector"]["count"] = 1
    else:
        records[1] = deepcopy(records[0])
    result = normalize_prerequisites(_normalizer_report(records), loaded)
    assert result == {"status": "unknown", "reason": reason}


@pytest.mark.parametrize("corruption", ["request", "doublepass", "profile", "cleanup", "capture_status"])
def test_normalizer_rejects_capture_without_its_request_guards_or_cleanup(corruption):
    loaded = {"status": "known", "roots": [{"root_id": "loaded", "task_ids": ["first"]}]}
    report = _normalizer_report([_record("loaded", "first")])
    if corruption == "request":
        report["request"]["include_prerequisites"] = False
    elif corruption == "doublepass":
        report["doublepass"]["prerequisite_consistent"] = False
    elif corruption == "profile":
        report["prerequisite_profile_sha256"] = "0" * 64
    elif corruption == "cleanup":
        report["cleanup"]["handle_close"]["closed"] = False
    else:
        report["loaded_prerequisites"]["status"] = "unknown"
    result = normalize_prerequisites(report, loaded)
    assert result == {"status": "unknown", "reason": "LOADED_PREREQUISITES_NOT_VERIFIED"}


def test_projector_rejects_duplicate_known_records_and_missing_selected_pair():
    loaded = [{"root_id": "loaded", "task_id": "first"}]
    state = {"loaded_prerequisites": {"status": "known", "tasks": [
        {"root_id": "loaded", "task_id": "first", "required_task_ids": []},
        {"root_id": "loaded", "task_id": "first", "required_task_ids": []},
    ]}}
    assert project_prerequisites(state, loaded, [], "1.37.4") == {
        "status": "unknown", "reason": "LOADED_PREREQUISITES_INVALID",
    }

    # A single valid record for the selected task would correctly project as
    # known. Clear the records so this assertion actually exercises a missing
    # selected pair after the duplicate-record rejection above.
    state["loaded_prerequisites"]["tasks"].clear()
    assert project_prerequisites(state, loaded, [], "1.37.4") == {
        "status": "unknown", "reason": "LOADED_PREREQUISITE_TASKS_INCOMPLETE",
    }


def test_projector_keeps_unsupported_game_version_unknown():
    state = {"loaded_prerequisites": {"status": "known", "tasks": []}}
    assert project_prerequisites(state, [], [], "1.37.5") == {
        "status": "unknown", "reason": "PREREQUISITE_SEMANTICS_VERSION_UNSUPPORTED",
    }


@pytest.mark.parametrize("bad_count", [True, "1"])
def test_normalizer_rejects_non_integer_native_vector_counts(bad_count):
    loaded = {"status": "known", "roots": [{"root_id": "loaded", "task_ids": ["first"]}]}
    record = _record("loaded", "first", ["runtime_only"])
    record["vector"]["count"] = bad_count
    result = normalize_prerequisites(_normalizer_report([record]), loaded)
    assert result == {"status": "unknown", "reason": "LOADED_PREREQUISITE_VECTOR_INVALID"}


def _recorded_native_capture():
    fixture = Path(__file__).parent / "fixtures/information_loaded_tasks_live_1374.json"
    recorded = json.loads(fixture.read_text(encoding="utf-8"))
    report = deepcopy(recorded["native_capture"])
    context = deepcopy(recorded["original_context"])
    report["request"]["include_prerequisites"] = True
    report["doublepass"]["prerequisite_consistent"] = True
    report["prerequisite_profile_sha256"] = PROFILE_SHA256
    report["loaded_prerequisites"] = {
        "status": "observed", "complete": True,
        "tasks": [
            _record(root["root_id"], task_id)
            for root in report["loaded_tasks"]["roots"]
            for task_id in root["task_ids"]
        ],
    }
    return report, context


def test_recorded_native_fixture_normalizes_prerequisite_capture_and_keeps_guard_provenance():
    report, context = _recorded_native_capture()
    state = NativeMissionReader.normalize(report, context)
    assert state["loaded_prerequisites"]["status"] == "known"
    assert len(state["loaded_prerequisites"]["tasks"]) == 61
    assert state["provenance"]["loaded_prerequisites_same_doublepass"] is True
    assert state["provenance"]["prerequisite_profile_sha256"] == PROFILE_SHA256

    bad_pass = deepcopy(report)
    bad_pass["doublepass"]["prerequisite_consistent"] = False
    normalized = NativeMissionReader.normalize(bad_pass, context)
    assert normalized["loaded_prerequisites"]["reason"] == "LOADED_PREREQUISITES_NOT_VERIFIED"

    bad_profile = deepcopy(report)
    bad_profile["prerequisite_profile_sha256"] = "0" * 64
    normalized = NativeMissionReader.normalize(bad_profile, context)
    assert normalized["loaded_prerequisites"]["reason"] == "LOADED_PREREQUISITES_NOT_VERIFIED"
