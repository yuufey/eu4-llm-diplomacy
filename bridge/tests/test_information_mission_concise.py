"""Compact mission projections keep game facts and drop parser evidence."""

from copy import deepcopy

from bridge.information.mission_concise import project_mission_fields


def known(value):
    return {"status": "known", "value": value, "complete": False}


def _assert_no_technical_metadata(value):
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = str(key).lower()
            assert not any(word in lowered for word in
                           ("token", "index", "path", "source", "line", "sha", "raw", "verify"))
            assert lowered != "count" and not lowered.endswith(("_count", "_counts"))
            _assert_no_technical_metadata(child)
    elif isinstance(value, list):
        for child in value:
            _assert_no_technical_metadata(child)


def test_m01_uses_localized_name_and_task_identity_without_mutating_input():
    fields = {
        "task_id": known([{"root_id": "french_missions_1", "task_id": "fra_liberate_norm",
                            "branch_visibility": "unknown"}]),
        "name": known({"entries": [{"root_id": "french_missions_1", "task_id": "fra_liberate_norm",
                                     "text": "解放诺曼底", "raw_template_hex": "deadbeef"}]}),
        "description": {"status": "unknown", "reason": "not captured"},
        "branches": known({"slots": [{"slot": 1, "roots": ["french_missions_1"]}]}),
    }
    before = deepcopy(fields)

    result = project_mission_fields("M01", fields)

    assert result == {"tasks": [{"root_id": "french_missions_1",
                                  "task_id": "fra_liberate_norm", "name": "解放诺曼底"}],
                      "branches": {"slots": [{"slot": 1, "roots": ["french_missions_1"]}]}}
    assert fields == before


def test_m02_keeps_task_state_and_province_owner_condition_without_ast_details():
    fields = {
        "completion_status": known({"completed_task_ids": ["fra_appease_the_princes"],
                                    "selected_task": {"task_id": "fra_liberate_norm", "completed": False}}),
        "currently_completable": known({"tasks": [{"task_id": "fra_liberate_norm", "status": "known",
                                                    "currently_completable": False,
                                                    "checks": {"task_trigger": {"satisfied": False}}}]}),
        "prerequisites": known([{"task_id": "fra_liberate_norm",
                                  "required_task_ids": ["fra_appease_the_princes"],
                                  "evaluation": {"status": "known", "satisfied": False,
                                                 "required_task_ids": ["fra_appease_the_princes"],
                                                 "missing_task_ids": ["fra_appease_the_princes"]}}]),
        "condition_progress": known({"tasks": [{"root_id": "french_missions_1",
            "task_id": "fra_liberate_norm", "trigger": {
            "kind": "and", "token": 26353, "evaluation": {"status": "known", "satisfied": False},
            "children": [{"kind": "geographic", "token": 44, "members": [
                {"province_id": 167, "tree": {"kind": "leaf", "token": 1,
                 "condition_name": "country_or_non_sovereign_subject_holds",
                 "evaluation": {"status": "known", "satisfied": False},
                 "metric": {"province_id": 167, "comparison_country": "ROOT",
                            "actual_country": "ENG", "source": "memory"}}},
            ]}]}}]}),
    }

    result = project_mission_fields("M02", fields)
    task = result["tasks"][0]

    assert len(result["tasks"]) == 1
    assert task["root_id"] == "french_missions_1"
    assert task["completed"] is False
    assert task["currently_completable"] is False
    assert task["prerequisites"] == {"required_task_ids": ["fra_appease_the_princes"],
                                     "missing_task_ids": ["fra_appease_the_princes"],
                                     "satisfied": False}
    assert task["conditions"] == [{"condition_name": "country_or_non_sovereign_subject_holds",
                                   "satisfied": False,
                                   "metric": {"province_id": 167, "comparison_country": "ROOT",
                                              "actual_country": "ENG"}}]
    assert result["completed_task_ids"] == ["fra_appease_the_princes"]
    _assert_no_technical_metadata(result)


def test_m03_reports_static_area_members_and_unevaluated_ownership_condition():
    fields = {
        "regions": known({"rules": [{"task_id": "fra_liberate_norm", "kind": "scope_head_reference",
                                      "path": "trigger.children[0]",
                                      "static_scope": {"kind": "area", "name": "normandy_area",
                                                       "members": [167, 168, 1879, 4385],
                                                       "source": {"files": []}}}]}),
        "ownership": known({"rules": [{"task_id": "fra_liberate_norm",
                                        "kind": "symbolic_condition_reference",
                                        "command_key": "country_or_non_sovereign_subject_holds",
                                        "path": "trigger.children[0]"}]}),
    }

    result = project_mission_fields("M03", fields)
    task = result["tasks"][0]

    assert task["targets"] == [{"kind": "area", "identifier": "normandy_area",
                                 "province_ids": [167, 168, 1879, 4385],
                                 "basis": "static_definition"}]
    assert task["conditions"] == [{"condition_name": "country_or_non_sovereign_subject_holds",
                                   "satisfied": None}]
    _assert_no_technical_metadata(result)


def test_m04_keeps_claim_area_and_conditional_context_without_claiming_reward():
    fields = {"claims": known({"applied": "unknown", "rules": [{
        "root_id": "french_missions_1", "task_id": "fra_liberate_norm", "status": "known",
        "rules": [{"command": "add_permanent_claim", "path": [2, 1],
                   "raw_node": {"key": "add_permanent_claim", "value": "ROOT"},
                   "parent_scope": [{"key": "effect", "kind": "block"},
                                    {"key": "brittany_area", "kind": "control"}],
                   "condition_context": [{"key": "brittany_area", "kind": "control"},
                                          {"key": "limit", "kind": "condition"}],
                   "context_status": "unresolved", "conditional": None,
                   "declared_area_candidates": {"status": "known", "kind": "area",
                       "identifier": "brittany_area", "candidate_province_ids": [169, 170],
                       "applied": "unknown", "current_limit_evaluation": {
                           "status": "unknown", "provinces": [
                               {"province_id": 169, "satisfies_limit": None,
                                "reason": "REWARD_LIMIT_INPUT_UNAVAILABLE"}]}}}],
    }]}), "rewards": known({"evaluated": False, "applied": "unknown", "tasks": []})}

    result = project_mission_fields("M04", fields)
    claim = result["tasks"][0]["claims"][0]

    assert claim["claim_type"] == "permanent"
    assert claim["target"] == {"kind": "area", "identifier": "brittany_area",
                               "province_ids": [169, 170], "basis": "declared_static_target"}
    assert claim["condition_tree"] == {
        "contexts": [{"scope": "brittany_area", "kind": "control"},
                     {"scope": "limit", "kind": "condition"}],
        "evaluated": False,
    }
    assert claim["conditional"] is True
    assert claim["condition_status"] == "unresolved"
    assert claim["limit_evaluation"] == {"status": None,
                                         "provinces": [{"province_id": 169,
                                                        "satisfies_limit": None}]}
    assert claim["granted"] is None
    assert result["rewards"] == {"evaluated": False, "applied": "unknown", "tasks": []}
    _assert_no_technical_metadata(result)
    no_claims = project_mission_fields("M04", {"rewards": known({"tasks": []})})
    assert "tasks" not in no_claims and "claims" not in no_claims


def test_unknown_mission_facts_remain_null_and_other_topics_are_ignored():
    result = project_mission_fields("M02", {
        "currently_completable": {"status": "unknown", "reason": "reader unavailable"},
        "condition_progress": {"status": "unavailable"},
    })
    assert result == {"tasks": None, "completed_task_ids": None}
    assert project_mission_fields("N01", {"treasury": known(20)}) is None
