from __future__ import annotations

import json

import pytest

from bridge.information.mission_reward_rules import (
    MAX_DEPTH,
    MAX_OUTPUT_BYTES,
    MAX_RAW_NODE_BYTES,
    MAX_TASKS,
    project_reward_rules,
)


SOURCE_SHA = "a" * 64


def node(
    key: str,
    children: list[dict] | None = None,
    *,
    value: object = None,
    line: int = 1,
    end_line: int | None = None,
    raw_script: str | None = None,
) -> dict:
    actual_children = children or []
    result = {
        "key": key,
        "line": line,
        "end_line": end_line if end_line is not None else line,
        "value": value,
        "children": actual_children,
        "ast_semantics": "structural",
        "kind": "block" if actual_children else "scalar",
        "assignment": "=",
        "raw_key": key,
        "raw_value": "{" if actual_children else ("" if value is None else str(value)),
    }
    if raw_script is not None:
        result["raw_script"] = raw_script
    return result


def task(effect: object, *, root_id: str = "root_a", task_id: str = "task_a") -> dict:
    return {
        "root_id": root_id,
        "task_id": task_id,
        "effect": effect,
        "source": {
            "path": "missions/fixture.txt",
            "absolute_path": "C:/EU4/missions/fixture.txt",
            "source_kind": "basegame",
            "source": "basegame",
            "sha256": SOURCE_SHA,
            "size": 1024,
            "line": 1,
            "end_line": 50,
            "encoding": {"name": "utf-8-sig", "structural_only": False},
        },
    }


def rules_for(result: dict) -> list[dict]:
    return result["value"]["rules"][0]["rules"]


def test_projects_commands_and_condition_context() -> None:
    effect = node(
        "effect",
        [
            node(
                "if",
                [
                    node(
                        "limit",
                        [node("add_claim", value="CONDITION_ONLY", line=12)],
                        line=11,
                    ),
                    node("add_claim", value="ROOT", line=13),
                ],
                line=10,
            ),
            node(
                "else_if",
                [
                    node(
                        "limit",
                        [node("add_permanent_claim", value="CONDITION_ONLY", line=21)],
                        line=20,
                    ),
                    node("add_permanent_claim", value="PERM", line=22),
                ],
                line=19,
            ),
            node("else", [node("add_claim", value="ELSE", line=24)], line=23),
            node("add_casus_belli", value="cb_conquest", line=25),
            node("add_trade_modifier", [node("who", value="FRA", line=31)], line=30),
            node("scripted_effect", [node("add_claim", value="HIDDEN", line=40)], line=39),
        ],
        line=8,
    )

    claims = project_reward_rules([task(effect)], "claims")
    assert claims["status"] == "known"
    assert claims["complete"] is False
    assert claims["value"]["semantics"] == "declared_literal_effect_rules"
    assert claims["value"]["evaluated"] is False
    assert claims["value"]["applied"] == "unknown"
    assert claims["value"]["scope_targets_resolved"] is False
    assert claims["value"]["scripted_effects_expanded"] is False
    claim_rules = rules_for(claims)
    assert [item["command"] for item in claim_rules] == [
        "add_claim",
        "add_permanent_claim",
        "add_claim",
    ]
    first = claim_rules[0]
    assert first["path"] == [0, 1]
    assert first["path_text"] == "effect.children[0].children[1]"
    assert [item["key"] for item in first["condition_context"]] == ["if", "limit"]
    assert [item["key"] for item in first["parent_scope"]] == ["effect", "if"]
    assert [item["path"] for item in first["context_refs"]] == [[0], [0, 0]]
    assert first["context_status"] == "unresolved"
    assert first["raw_node"]["key"] == "add_claim"
    assert first["source"]["path"] == "missions/fixture.txt"
    assert first["source"]["sha256"] == SOURCE_SHA
    assert first["source"]["line"] == 13
    assert first["source"]["end_line"] == 13
    task_result = claims["value"]["rules"][0]
    assert [item["key"] for item in task_result["context_table"]] == [
        "if",
        "limit",
        "else_if",
        "limit",
        "else",
    ]
    assert task_result["context_table"][1]["raw_node"]["key"] == "limit"
    assert task_result["context_table"][3]["raw_node"]["children"][0]["key"] == (
        "add_permanent_claim"
    )

    casus_belli = project_reward_rules([task(effect)], "casus_belli")
    assert [item["command"] for item in rules_for(casus_belli)] == ["add_casus_belli"]

    trade_modifiers = project_reward_rules([task(effect)], "trade_modifiers")
    trade_rules = rules_for(trade_modifiers)
    assert [item["command"] for item in trade_rules] == ["add_trade_modifier"]
    assert trade_rules[0]["raw_node"]["children"][0]["key"] == "who"


def test_empty_literal_inventory_is_known_but_incomplete() -> None:
    result = project_reward_rules(
        [task(node("effect", [node("add_stability", value=1)]))],
        "claims",
    )
    assert result["status"] == "known"
    assert result["complete"] is False
    assert result["value"]["rules"][0]["status"] == "known"
    assert result["value"]["rules"][0]["literal_inventory"] == "empty"
    assert result["value"]["rules"][0]["rules"] == []
    assert result["value"]["literal_rule_count"] == 0


def test_trigger_condition_commands_are_context_only() -> None:
    effect = node(
        "effect",
        [
            node(
                "if",
                [
                    node("trigger", [node("add_claim", value="CONDITION_ONLY", line=3)], line=2),
                    node("add_claim", value="REWARD_RULE", line=4),
                ],
                line=1,
            )
        ],
    )
    result = project_reward_rules([task(effect)], "claims")

    assert result["status"] == "known"
    rules = rules_for(result)
    assert [item["command"] for item in rules] == ["add_claim"]
    assert rules[0]["raw_node"]["value"] == "REWARD_RULE"
    assert [item["key"] for item in result["value"]["rules"][0]["context_table"]] == [
        "if",
        "trigger",
    ]
    assert result["value"]["rules"][0]["context_table"][1]["raw_node"]["key"] == "trigger"


def test_unknown_wrapper_marks_literal_occurrence_context_unresolved() -> None:
    effect = node(
        "effect",
        [node("unknown_wrapper", [node("add_claim", value="FRA", line=4)], line=3)],
    )
    result = project_reward_rules([task(effect)], "claims")

    assert result["status"] == "known"
    rule = rules_for(result)[0]
    assert rule["command"] == "add_claim"
    assert rule["context_status"] == "unresolved"
    assert rule["context_refs"][0]["path"] == [0]
    context = result["value"]["rules"][0]["context_table"][0]
    assert context["kind"] == "unknown_scope"
    assert context["key"] == "unknown_wrapper"


def test_bad_ast_is_unknown_without_erasing_valid_tasks() -> None:
    valid = task(node("effect", [node("add_claim", value="FRA")]), task_id="valid")
    empty = task(node("effect", [node("add_stability", value=1)]), task_id="empty")
    bad_effect = {"key": "effect", "line": 1, "end_line": 1}
    bad = task(bad_effect, task_id="bad")
    result = project_reward_rules([valid, bad, empty], "claims")

    assert result["status"] == "partial"
    assert result["value"]["known_task_count"] == 2
    assert result["value"]["unknown_task_count"] == 1
    assert result["value"]["rules"][0]["status"] == "known"
    assert result["value"]["rules"][0]["rules"][0]["command"] == "add_claim"
    assert result["value"]["rules"][1]["status"] == "unknown"
    assert result["value"]["rules"][1]["reason"]["code"] == "AST_CHILDREN_MISSING"
    assert result["value"]["rules"][2]["status"] == "known"
    assert result["provenance"]["unknown_reasons"] == {"AST_CHILDREN_MISSING": 1}


def test_partial_task_keeps_prior_effect_root_rules() -> None:
    good_root = node("effect", [node("add_claim", value="FRA", line=2)])
    bad_root = {"key": "effect", "line": 3, "end_line": 3}
    result = project_reward_rules([task([good_root, bad_root])], "claims")

    assert result["status"] == "partial"
    assert result["value"]["known_task_count"] == 0
    assert result["value"]["unknown_task_count"] == 1
    task_result = result["value"]["rules"][0]
    assert task_result["status"] == "unknown"
    assert task_result["reason"]["code"] == "AST_CHILDREN_MISSING"
    assert [item["command"] for item in task_result["rules"]] == ["add_claim"]


def test_missing_effect_or_source_is_unknown() -> None:
    missing_effect = task(None, task_id="missing_effect")
    missing_effect["effect"] = None
    missing_source = task(node("effect", []), task_id="missing_source")
    del missing_source["source"]
    result = project_reward_rules([missing_effect, missing_source], "claims")

    assert result["status"] == "unknown"
    reasons = [item["reason"]["code"] for item in result["value"]["rules"]]
    assert reasons == ["EFFECT_AST_MISSING", "SOURCE_MISSING"]


def test_invalid_identifier_metadata_is_omitted_but_valid_id_is_retained() -> None:
    invalid_root = "r" * 129
    invalid_task_id = "t" * 129
    result = project_reward_rules(
        [
            task(node("effect", []), root_id=invalid_root, task_id="valid_task"),
            task(node("effect", []), root_id="valid_root", task_id=invalid_task_id),
        ],
        "claims",
    )

    records = result["value"]["rules"]
    assert result["status"] == "unknown"
    assert [item["reason"]["code"] for item in records] == [
        "INVALID_IDENTIFIER",
        "INVALID_IDENTIFIER",
    ]
    assert "root_id" not in records[0]
    assert records[0]["task_id"] == "valid_task"
    assert records[1]["root_id"] == "valid_root"
    assert "task_id" not in records[1]


def test_repeated_effect_roots_keep_root_index_in_path() -> None:
    result = project_reward_rules(
        [
            task(
                [
                    node("effect", [node("add_stability", value=1)]),
                    node("effect", [node("add_claim", value="FRA", line=7)]),
                ]
            )
        ],
        "claims",
    )
    assert result["status"] == "known"
    rule = rules_for(result)[0]
    assert rule["path"] == [1, 0]
    assert rule["path_text"] == "effect[1].children[0]"


def test_depth_and_raw_ast_budgets_fail_closed() -> None:
    deep: dict = node("add_claim", value="FRA")
    for _ in range(MAX_DEPTH + 2):
        deep = node("if", [deep])
    depth_result = project_reward_rules([task(deep)], "claims")
    assert depth_result["status"] == "unknown"
    assert depth_result["value"]["rules"][0]["reason"]["code"] == "AST_DEPTH_LIMIT"

    huge = node(
        "add_claim",
        value="FRA",
        raw_script="x" * (MAX_RAW_NODE_BYTES + 1),
    )
    raw_result = project_reward_rules([task(node("effect", [huge]))], "claims")
    assert raw_result["status"] == "unknown"
    assert raw_result["value"]["rules"][0]["reason"]["code"] == "AST_NODE_SCALAR_LIMIT"


def test_output_budget_preserves_prefix_and_marks_later_tasks_unknown() -> None:
    tasks = [
        task(
            node("effect", [node("add_claim", value="x" * 1000)]),
            root_id=f"root_{index}",
            task_id=f"task_{index}",
        )
        for index in range(4096)
    ]
    result = project_reward_rules(tasks, "claims")

    assert result["status"] == "partial"
    assert result["value"]["known_task_count"] > 0
    assert result["value"]["unknown_task_count"] > 0
    assert result["provenance"]["unknown_reasons"]["OUTPUT_BUDGET_EXCEEDED"] > 0
    assert result["value"]["rules"][0]["status"] == "known"
    assert len(json.dumps(result, ensure_ascii=False).encode("utf-8")) <= MAX_OUTPUT_BYTES


def test_task_limit_aggregates_omitted_tail() -> None:
    tasks = [
        task(
            node("effect", [node("add_stability", value=1)]),
            root_id=f"root_{index}",
            task_id=f"task_{index}",
        )
        for index in range(MAX_TASKS + 3)
    ]
    result = project_reward_rules(tasks, "claims")

    assert result["status"] == "partial"
    assert result["value"]["task_count"] == MAX_TASKS + 3
    assert result["value"]["materialized_task_count"] == MAX_TASKS
    assert result["value"]["known_task_count"] == MAX_TASKS
    assert result["value"]["unknown_task_count"] == 3
    assert result["value"]["omitted_task_count"] == 3
    assert result["value"]["omitted_task_range"] == {
        "start": MAX_TASKS,
        "end": MAX_TASKS + 2,
    }
    assert len(result["value"]["rules"]) == MAX_TASKS
    assert result["provenance"]["unknown_reasons"] == {"TASK_COUNT_LIMIT": 3}


def test_invalid_field_and_invalid_tasks_are_explicit() -> None:
    with pytest.raises(ValueError, match="unsupported_reward_field"):
        project_reward_rules([], "prestige")

    result = project_reward_rules("not-a-task-sequence", "claims")
    assert result["status"] == "unknown"
    assert result["provenance"]["unknown_reasons"] == {"TASKS_NOT_SEQUENCE": 1}

