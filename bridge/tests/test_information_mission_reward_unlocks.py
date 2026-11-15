from __future__ import annotations

import copy
import json
from typing import Any

from bridge.information import mission_reward_duration as duration
from bridge.information.mission_reward_unlocks import (
    MAX_OUTPUT_BYTES,
    SCHEMA,
    project_reward_unlocks,
)


SOURCE_SHA = "a" * 64


def node(
    key: str,
    children: list[dict[str, Any]] | None = None,
    *,
    value: Any = None,
    raw_value: str | None = None,
    kind: str | None = None,
    assignment: str = "=",
    line: int = 1,
) -> dict[str, Any]:
    actual_children = list(children or [])
    if raw_value is None:
        raw_value = "{" if actual_children else ("" if value is None else str(value))
    return {
        "key": key,
        "raw_key": key,
        "value": value,
        "raw_value": raw_value,
        "kind": kind or ("block" if actual_children else "scalar"),
        "assignment": assignment,
        "children": actual_children,
        "line": line,
        "end_line": line,
        "ast_semantics": "structural",
    }


def scalar(key: str, value: Any, *, raw: str | None = None, line: int = 2) -> dict[str, Any]:
    return node(key, value=value, raw_value=raw, line=line)


def task(effect: Any, *, task_id: str = "task_a", include_source: bool = True) -> dict[str, Any]:
    result = {
        "root_id": "root_a",
        "task_id": task_id,
        "effect": effect,
    }
    if include_source:
        result["source"] = {
            "path": "missions/fixture.txt",
            "absolute_path": "C:/EU4/missions/fixture.txt",
            "source_kind": "basegame",
            "source": "basegame",
            "sha256": SOURCE_SHA,
            "size": 1024,
            "line": 1,
            "end_line": 80,
            "encoding": {"name": "utf-8", "structural_only": False},
        }
    return result


def only_group(result: dict[str, Any]) -> dict[str, Any]:
    return result["value"]["rules"][0]


def only_rule(group: dict[str, Any], command_name: str) -> dict[str, Any]:
    return next(rule for rule in group["rules"] if rule["command"] == command_name)


def test_nested_condition_context_is_retained_and_unreferenced_context_pruned() -> None:
    fake_condition_effect = scalar("unlock_cult", "not_a_reward", line=4)
    condition = node("limit", [node("NOT", [fake_condition_effect], line=3)], line=2)
    selected_branch = node(
        "if",
        [condition, scalar("complete_mission", "mission_a", line=5)],
        line=1,
    )
    irrelevant_branch = node(
        "if",
        [node("limit", [scalar("has_country_flag", "other", line=8)], line=7),
         scalar("add_mil_power", 10, line=9)],
        line=6,
    )
    result = project_reward_unlocks([task(node("effect", [selected_branch, irrelevant_branch]))])

    assert result["schema"] == SCHEMA
    group = only_group(result)
    assert [rule["command"] for rule in group["rules"]] == ["complete_mission"]
    rule = only_rule(group, "complete_mission")
    referenced = {row["context_id"] for row in rule["context_refs"]}
    retained = {row["context_id"] for row in group["context_table"]}
    assert retained == referenced
    assert {row["key"] for row in group["context_table"]} == {"if", "limit"}
    condition_context = next(row for row in group["context_table"] if row["key"] == "limit")
    assert "unlock_cult" in json.dumps(condition_context["raw_node"])
    assert result["value"]["literal_rule_count"] == 1


def test_literal_target_decoding_dynamic_and_malformed_values() -> None:
    effects = node(
        "effect",
        [
            scalar("unlock_cult", "cult_alpha", raw='"cult_alpha"', line=2),
            scalar("complete_mission", "mission_alpha", raw="mission_alpha", line=3),
            scalar("unlock_cult", "@cult_variable", raw="@cult_variable", line=4),
            scalar("complete_mission", "decoded_value", raw='"raw_value"', line=5),
            scalar("unlock_cult", "some_value", raw='"unterminated', line=6),
        ],
    )

    result = project_reward_unlocks([task(effects)])
    group = only_group(result)
    cult, mission, dynamic, mismatch, malformed = group["rules"]
    assert cult["target"] == {
        "status": "known_literal",
        "identifier": "cult_alpha",
        "namespace": "cult",
        "namespace_basis": "pinned_cwt_declaration",
    }
    assert mission["target"]["status"] == "known_literal"
    assert mission["target"]["identifier"] == "mission_alpha"
    assert dynamic["target"]["reason"] == "TARGET_NOT_LITERAL_IDENTIFIER"
    assert mismatch["target"]["reason"] == "TARGET_RAW_VALUE_MISMATCH"
    assert malformed["target"]["reason"] == "TARGET_QUOTING_MALFORMED"
    assert result["status"] == "known"
    assert result["value"]["actual_unlocks"] == "unknown"


def test_scope_and_event_target_references_remain_unknown_targets() -> None:
    symbolic = [
        "ROOT", "ROOT.capital", "PREV", "PREV.culture", "FROM", "FROM.owner",
        "THIS", "THIS.culture", "event_target:target", "saved_event_target:target",
        "var:target", "variable:target", "scope:target",
    ]
    commands = [scalar("unlock_cult", value, line=index + 1) for index, value in enumerate(symbolic)]
    commands.extend([
        scalar("unlock_cult", "cult_rooted", raw='"cult_rooted"', line=20),
        scalar("complete_mission", "mission_this_island", raw="mission_this_island", line=21),
    ])

    result = project_reward_unlocks([task(node("effect", commands))])
    rules = only_group(result)["rules"]

    for rule in rules[:len(symbolic)]:
        assert rule["target"]["status"] == "unknown"
        assert rule["target"]["reason"] == "TARGET_SYMBOLIC_REFERENCE"
        assert rule["scope_targets_resolved"] is False
        assert rule["raw_node"]["raw_value"] == rule["target"]["raw_value"]["value"]
    assert rules[-2]["target"]["status"] == "known_literal"
    assert rules[-2]["target"]["identifier"] == "cult_rooted"
    assert rules[-1]["target"]["status"] == "known_literal"
    assert rules[-1]["target"]["identifier"] == "mission_this_island"
    assert result["value"]["actual_unlocks"] == "unknown"


def test_swap_requires_exact_yes_and_reform_stays_unvalidated() -> None:
    reform = node(
        "unlock_government_reform",
        [scalar("government_reform", "reform_alpha", line=4)],
        kind="block",
        line=3,
    )
    duplicate_reform = node(
        "unlock_government_reform",
        [scalar("government_reform", "reform_a", line=6),
         scalar("government_reform", "reform_b", line=7)],
        kind="block",
        line=5,
    )
    effects = node(
        "effect",
        [
            scalar("swap_non_generic_missions", "yes", raw="yes", line=1),
            scalar("swap_non_generic_missions", "no", raw="no", line=2),
            reform,
            duplicate_reform,
        ],
    )

    result = project_reward_unlocks([task(effects)])
    group = only_group(result)
    yes, no, valid_reform, duplicate = group["rules"]
    assert yes["status"] == "known"
    assert yes["request_kind"] == "mission_tree_refresh_request"
    assert yes["request_value"] == {"status": "known_literal", "value": "yes"}
    assert no["status"] == "unknown"
    assert no["request_value"]["reason"] == "FLAG_NOT_EXACT_YES"
    assert valid_reform["status"] == "unknown"
    assert valid_reform["schema_validation"] == {
        "status": "unknown",
        "reason": "COMMAND_NOT_IN_PINNED_CWT",
    }
    assert valid_reform["target"] == {
        "status": "syntax_only",
        "identifier": "reform_alpha",
        "namespace": None,
        "namespace_validation": "unknown",
    }
    assert duplicate["target"]["reason"] == "REFORM_PARAMETER_DUPLICATE"
    assert result["status"] == "known"


def test_missing_effect_is_unknown_and_valid_empty_effect_is_known_empty() -> None:
    empty = project_reward_unlocks([task(node("effect", []))])
    missing = project_reward_unlocks([task(None)])
    mixed = project_reward_unlocks([task(node("effect", [])), task(None, task_id="missing")])

    assert empty["status"] == "known"
    assert empty["value"]["rules"] == []
    assert empty["value"]["no_match_task_count"] == 1
    assert empty["value"]["literal_rule_count"] == 0
    assert missing["status"] == "unknown"
    assert "value" not in missing
    assert missing["reason"]["code"] == "MISSION_AST_UNAVAILABLE"
    assert mixed["status"] == "partial"
    assert mixed["value"]["no_match_task_count"] == 1
    assert mixed["value"]["unknown_task_count"] == 1
    assert mixed["value"]["rules"][0]["reason"]["code"] == "EFFECT_AST_MISSING"


def test_invalid_source_and_ast_limits_fail_closed() -> None:
    bad_source = task(node("effect", [scalar("unlock_cult", "cult_a")]))
    bad_source["source"]["sha256"] = "not-a-sha"
    invalid_source_result = project_reward_unlocks([task(node("effect", [])), bad_source])
    assert invalid_source_result["status"] == "partial"
    assert invalid_source_result["value"]["unknown_task_count"] == 1
    assert invalid_source_result["value"]["rules"][0]["reason"]["code"] == "SOURCE_SHA256_INVALID"

    deep = scalar("leaf", "x")
    for index in range(70):
        deep = node(f"nested_{index}", [deep])
    limited = project_reward_unlocks([task(node("effect", [deep]))])
    assert limited["status"] == "unknown"
    assert "value" not in limited
    assert limited["reason"]["code"] == "MISSION_AST_UNAVAILABLE"


def test_cwt_pin_failure_is_unavailable_without_value(monkeypatch: Any) -> None:
    def fail_pin() -> dict[str, Any]:
        raise ValueError("pin mismatch")

    monkeypatch.setattr(duration, "_schema_evidence", fail_pin)
    result = project_reward_unlocks([task(node("effect", []))])
    assert result["status"] == "unavailable"
    assert "value" not in result
    assert result["reason"]["code"] == "CWT_EVIDENCE_UNAVAILABLE"


def test_input_is_not_mutated_and_oversized_public_output_fails_closed() -> None:
    payload = "x" * 9_000
    oversized_effect = node(
        "effect",
        [
            node(
                "complete_mission",
                [scalar("payload", payload, line=index + 2)],
                raw_value="{",
                kind="block",
                line=index + 1,
            )
            for index in range(70)
        ],
    )
    input_tasks = [task(oversized_effect)]
    before = copy.deepcopy(input_tasks)
    result = project_reward_unlocks(input_tasks)

    assert input_tasks == before
    assert result["status"] == "unknown"
    assert "value" not in result
    assert result["reason"]["code"] == "OUTPUT_BUDGET_EXCEEDED"
    assert len(json.dumps(result, ensure_ascii=False).encode("utf-8")) <= MAX_OUTPUT_BYTES

