"""Native mission condition evidence stays bounded and distinct from disk rules."""

import pytest

from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.catalog import get_topic
from bridge.information.mission_condition_profile import PROFILE_SHA256
from bridge.information.mission_condition_source import normalize_conditions
from bridge.information.missions import MissionInformationSource
from bridge.tests.test_information_missions import Definitions, State, query


def test_condition_progress_remains_planned():
    assert get_topic("M02")["fields"]["condition_progress"]["coverage"] == "planned"


def _condition_row(*, root_id="loaded", task_id="second", task_completed=False,
                   required=(True,)):
    required_rows = [
        {"task_id": task, "completed": completed}
        for task, completed in zip(("first", "extra"), required)
    ]
    return {
        "root_id": root_id,
        "task_id": task_id,
        "task_completed": task_completed,
        "prerequisites_satisfied": all(item["completed"] for item in required_rows),
        "required": required_rows,
    }


def _declared_required_rules(*task_ids):
    if not task_ids:
        return []
    return [{
        "key": "required_missions", "kind": "block", "assignment": "=",
        "value": None,
        "children": [{"key": task_id, "kind": "bare", "assignment": None,
                      "value": None, "children": []} for task_id in task_ids],
    }]


def _condition_report(rows, *, required_ids=("first",)):
    return {
        "request": {"include_conditions": True},
        "doublepass": {"condition_consistent": True},
        "condition_profile_sha256": PROFILE_SHA256,
        "cleanup": {"handle_close": {"closed": True}},
        "mission_conditions": {"status": "observed", "complete": True, "tasks": rows},
    }, {
        "status": "known",
        "tasks": [{"root_id": "loaded", "task_id": "second",
                    "required_task_ids": list(required_ids)}],
    }


def test_normalizer_preserves_verified_required_completion_booleans():
    report, prerequisites = _condition_report(
        [_condition_row(required=(True, False))], required_ids=("first", "extra"),
    )

    normalized = normalize_conditions(report, prerequisites)

    assert normalized["status"] == "known"
    assert normalized["canonical_pointer_keys_verified"] is True
    assert normalized["tasks"] == [{
        "root_id": "loaded", "task_id": "second", "task_completed": False,
        "prerequisites_satisfied": False,
        "required": [
            {"task_id": "first", "completed": True},
            {"task_id": "extra", "completed": False},
        ],
    }]


@pytest.mark.parametrize("corruption", ["request", "doublepass", "profile", "cleanup"])
def test_normalizer_rejects_condition_capture_without_guard_evidence(corruption):
    report, prerequisites = _condition_report([_condition_row()])
    if corruption == "request":
        report["request"]["include_conditions"] = False
    elif corruption == "doublepass":
        report["doublepass"]["condition_consistent"] = False
    elif corruption == "profile":
        report["condition_profile_sha256"] = "0" * 64
    else:
        report["cleanup"]["handle_close"]["closed"] = False

    assert normalize_conditions(report, prerequisites) == {
        "status": "unknown", "reason": "MISSION_CONDITIONS_NOT_VERIFIED",
    }


@pytest.mark.parametrize(("corruption", "reason"), [
    ("missing_task", "MISSION_CONDITION_TASKS_INCOMPLETE"),
    ("wrong_pair", "MISSION_CONDITION_TASK_MISMATCH"),
    ("wrong_required_order", "MISSION_CONDITION_RECORD_INVALID"),
    ("wrong_required_count", "MISSION_CONDITION_RECORD_INVALID"),
    ("task_completed_type", "MISSION_CONDITION_RECORD_INVALID"),
    ("prerequisite_bool_type", "MISSION_CONDITION_RECORD_INVALID"),
    ("required_bool_type", "MISSION_CONDITION_RECORD_INVALID"),
    ("inconsistent_prerequisite_result", "MISSION_CONDITION_RECORD_INVALID"),
])
def test_normalizer_rejects_mismatched_pairs_required_ids_and_non_boolean_results(corruption, reason):
    row = _condition_row(required=(True, False))
    report, prerequisites = _condition_report([row], required_ids=("first", "extra"))
    if corruption == "missing_task":
        report["mission_conditions"]["tasks"] = []
    elif corruption == "wrong_pair":
        row["task_id"] = "first"
    elif corruption == "wrong_required_order":
        row["required"].reverse()
    elif corruption == "wrong_required_count":
        row["required"].pop()
    elif corruption == "task_completed_type":
        row["task_completed"] = 1
    elif corruption == "prerequisite_bool_type":
        row["prerequisites_satisfied"] = 1
    elif corruption == "required_bool_type":
        row["required"][0]["completed"] = 1
    else:
        row["prerequisites_satisfied"] = True

    assert normalize_conditions(report, prerequisites) == {"status": "unknown", "reason": reason}


def _service(tmp_path, *, condition_rows=None, condition_status="known",
             completed_task_ids=("first",), definitions_ready=True):
    state, definitions = State(), Definitions()
    state.sample["loaded_tasks"] = {
        "status": "known",
        "roots": [{"root_id": "loaded", "task_ids": ["first", "second"]}],
    }
    state.sample["loaded_prerequisites"] = {
        "status": "known",
        "tasks": [
            {"root_id": "loaded", "task_id": "first", "required_task_ids": []},
            {"root_id": "loaded", "task_id": "second", "required_task_ids": ["first"]},
        ],
    }
    state.sample["completed_missions"] = {
        "status": "known", "task_ids": list(completed_task_ids),
    }
    if condition_status is not None:
        state.sample["mission_conditions"] = (
            {"status": "known", "canonical_pointer_keys_verified": True,
             "tasks": condition_rows or []}
            if condition_status == "known"
            else {"status": condition_status, "reason": "CONDITION_CAPTURE_UNVERIFIED"}
        )
    definitions.ready = definitions_ready
    adapter = MissionInformationSource(state, definitions, state.capture)
    api = InformationService(CompositeSource(state, [adapter]), tmp_path / "info.db")
    return api, state, definitions


def _item_m02(api, request_id="condition-query", *, task_id="second"):
    result = api.query(request_id, queries=[query(
        "M02", ["prerequisites", "completion_status", "currently_completable"],
        task_id=task_id,
    )])
    return result["items"][0]


def _read_m02(api, request_id="condition-query", *, task_id="second"):
    return _item_m02(api, request_id, task_id=task_id)["fields"]


@pytest.mark.parametrize("required_completed", [True, False])
def test_loaded_nonempty_prerequisites_use_verified_pointer_key_completion(
        tmp_path, required_completed):
    row = _condition_row(required=(required_completed,))
    api, state, definitions = _service(
        tmp_path, condition_rows=[row], definitions_ready=False,
    )
    try:
        item = _item_m02(api)
        fields = item["fields"]
        prerequisites = fields["prerequisites"]
        assert prerequisites["status"] == "known"
        evaluation = prerequisites["value"][0]["evaluation"]
        assert evaluation["status"] == "known"
        assert evaluation["satisfied"] is required_completed
        assert evaluation["canonical_pointer_keys_verified"] is True
        assert evaluation["required_definitions"] == [
            {"task_id": "first", "completed": required_completed},
        ]
        assert prerequisites["value"][0]["declared_rules"] is None

        # The runtime condition and loaded prerequisite data survive even when
        # the current disk definition index is unavailable.
        assert fields["currently_completable"]["status"] == "known"
        assert definitions.ready is False
    finally:
        api.close()


@pytest.mark.parametrize(("task_completed", "required_completed", "completed_ids", "expected_status", "reason"), [
    (True, True, ("first", "second"), "known", "TASK_ALREADY_COMPLETED"),
    (False, False, ("first",), "known", "REQUIRED_MISSIONS_NOT_COMPLETED"),
    (False, True, ("first",), "unknown", "TASK_TRIGGER_NOT_EVALUATED"),
])
def test_current_eligibility_reports_only_false_short_circuits_and_mixes_m02_facts(
        tmp_path, task_completed, required_completed, completed_ids, expected_status, reason):
    row = _condition_row(task_completed=task_completed, required=(required_completed,))
    api, state, _definitions = _service(
        tmp_path, condition_rows=[row], completed_task_ids=completed_ids,
        definitions_ready=False,
    )
    try:
        item = _item_m02(api)
        fields = item["fields"]

        assert fields["completion_status"]["status"] == "known"
        selected_completion = fields["completion_status"]["value"]["selected_task"]["completed"]
        assert selected_completion is ("second" in completed_ids)
        assert fields["prerequisites"]["value"][0]["evaluation"]["satisfied"] is required_completed

        current = fields["currently_completable"]
        assert current["status"] == "known"
        assert item["complete"] is False
        projected = current["value"]["tasks"][0]
        assert projected["status"] == expected_status
        assert projected["reason"] == reason
        if expected_status == "known":
            assert projected["currently_completable"] is False
        else:
            assert projected["currently_completable"] is None
            assert projected["checks"]["task_trigger"] == {
                "status": "unknown", "reason": "TASK_TRIGGER_NOT_EVALUATED",
            }
        assert current["complete"] is False
        assert current["task_trigger_evaluated"] is False
        assert current["branch_visibility_evaluated"] is False
    finally:
        api.close()


def test_missing_or_explicitly_unknown_conditions_do_not_use_completion_names_as_a_substitute(tmp_path):
    # The completion list and current disk rules make the prerequisite look
    # satisfied by name, but no canonical native condition result was captured.
    api, _state, definitions = _service(
        tmp_path, condition_status="unknown", completed_task_ids=("first", "second"),
    )
    definitions.values["loaded"]["tasks"][1]["required_missions"] = _declared_required_rules("first")
    try:
        fields = _read_m02(api, "explicitly-unknown")
        native_evaluation = fields["prerequisites"]["value"][0]["evaluation"]
        assert native_evaluation["status"] == "unknown"
        assert native_evaluation["satisfied"] is None
        assert native_evaluation["reason"] == "CANONICAL_PREREQUISITE_DEFINITION_LOOKUP_NOT_CAPTURED"
        assert fields["prerequisites"]["value"][0]["declared_rule_evaluation"]["satisfied"] is True
        assert fields["completion_status"]["value"]["selected_task"]["completed"] is True
        assert fields["currently_completable"] == {
            "status": "unknown", "reason": "CONDITION_CAPTURE_UNVERIFIED",
        }
    finally:
        api.close()

    api, _state, _definitions = _service(
        tmp_path, condition_status=None, completed_task_ids=("first", "second"),
    )
    try:
        fields = _read_m02(api, "legacy-without-condition-capture")
        assert fields["currently_completable"] == {
            "status": "unknown", "reason": "NATIVE_MISSION_CONDITIONS_NOT_CAPTURED",
        }
    finally:
        api.close()


def test_current_eligibility_task_selector_rejects_unloaded_static_tasks(tmp_path):
    row = _condition_row()
    api, _state, _definitions = _service(tmp_path, condition_rows=[row])
    try:
        result = api.query("unloaded-current-task", queries=[query(
            "M02", ["currently_completable"], root_id="loaded", task_id="not_loaded",
        )])
        assert result["items"][0]["fields"]["currently_completable"] == {
            "status": "unknown", "reason": "TASK_NOT_IN_CAPTURED_LOADED_TASKS",
        }

        outside_loaded_slots = api.query("unloaded-current-root", queries=[query(
            "M02", ["currently_completable"], root_id="other",
        )])
        assert outside_loaded_slots["items"][0]["fields"]["currently_completable"] == {
            "status": "unknown", "reason": "ROOT_NOT_IN_CAPTURED_MISSION_SLOTS",
        }
    finally:
        api.close()
