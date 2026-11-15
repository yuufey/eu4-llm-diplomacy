"""Regression tests for bounded extension hooks in the M03 target projector."""
from __future__ import annotations

from bridge.information import mission_target_rules as base
from bridge.tests.test_information_mission_target_rules import block, scalar, task


def test_explicit_classifier_hook_matches_default_projector_byte_for_byte():
    tasks = [task(block("trigger", [
        block("OR", [
            block("NOT", [scalar("owns", 44, 4)], 3),
            scalar("controls", 45, 5),
        ], 2),
        scalar("controlled_by", "FRA", 6),
    ]))]

    default = base.project_target_rules(tasks, "provinces")
    hooked = base.project_target_rules(
        tasks, "provinces",
        _classifier=lambda node, ancestors: base._classify_node(node),
    )

    assert hooked == default


def test_symbolic_condition_records_allowlisted_scope_extras_without_literal_claim():
    trigger = block("trigger", [
        block("OR", [
            block("NOT", [scalar("owns", "ROOT", 4)], 3),
            scalar("controls", 5, 5),
        ], 2),
    ])
    tasks = [task(trigger)]

    def classifier(node, ancestors):
        classification, reason, fields = base._classify_node(node)
        if node["key"] == "owns" and node.get("value") == "ROOT":
            assert classification is None
            assert reason == "DYNAMIC_SCOPE_SYMBOL_UNRESOLVED"
            classification = {
                "record_kind": "symbolic_condition_reference",
                "normalized_value": "ROOT",
                "reference_kind": "province_id",
                "cwt_argument_type": "province_id",
                "fields": ["provinces"],
                "cwt_lines": [3494],
                "static_scope": {"scope_head": "ROOT", "chain": ["OR", "NOT"]},
                "expected_scope_type": "province",
                "target_resolution": {"status": "unresolved", "reason": reason},
                "unapproved_extra": {"should_not_escape": True},
            }
            return classification, None, ("provinces",)
        return classification, reason, fields

    result = base.project_target_rules(tasks, "provinces", _classifier=classifier)
    assert result["status"] == "known"
    record = result["value"]["rules"][0]
    assert record["kind"] == "symbolic_condition_reference"
    assert record["symbolic_value"] == "ROOT"
    assert "literal_value" not in record
    assert record["static_scope"] == {"scope_head": "ROOT", "chain": ["OR", "NOT"]}
    assert record["expected_scope_type"] == "province"
    assert record["target_resolution"] == {
        "status": "unresolved", "reason": "DYNAMIC_SCOPE_SYMBOL_UNRESOLVED",
    }
    assert "unapproved_extra" not in record
    assert [row["key"] for row in record["logical_ancestors"]] == ["OR", "NOT"]
    assert record["requiredness"] == "not_inferred"
    assert record["source"]["path"] == "missions/example.txt"
    assert record["source"]["line"] == 4
    assert record["path_text"] == "trigger.children[0].children[0].children[0]"


def test_single_extra_over_64k_fails_closed_without_reference_value():
    tasks = [task(block("trigger", [scalar("owns", 44, 2)]))]

    def classifier(node, ancestors):
        classification, reason, fields = base._classify_node(node)
        if classification is not None:
            classification = {**classification,
                              "static_scope": {"scope_head": "x" * (64 * 1024)}}
        return classification, reason, fields

    result = base.project_target_rules(tasks, "provinces", _classifier=classifier)
    assert result["status"] == "unknown"
    assert "value" not in result
    assert result["tasks"][0]["status"] == "unknown"
    assert result["tasks"][0]["reason"] == "EXTRA_REFERENCE_BYTES_LIMIT"
    assert result["gaps"][0]["reason"] == "EXTRA_REFERENCE_BYTES_LIMIT"


def test_cumulative_extra_over_4mib_fails_closed_at_budget_without_expansion():
    tasks = []
    for index in range(70):
        row = task(block("trigger", [scalar("owns", index + 1, 2)]),
                   task_id=f"task_{index:03d}")
        row["root_id"] = f"root_{index:03d}"
        tasks.append(row)

    def classifier(node, ancestors):
        classification, reason, fields = base._classify_node(node)
        if classification is not None:
            classification = {**classification,
                              "static_scope": {"scope_head": "x" * 61_000}}
        return classification, reason, fields

    result = base.project_target_rules(tasks, "provinces", _classifier=classifier)
    assert result["status"] == "partial"
    assert result["complete"] is False
    rules = result["value"]["rules"]
    assert 0 < len(rules) < len(tasks)
    rejected = [row for row in result["value"]["tasks"] if row["status"] == "unknown"]
    assert rejected
    assert all(row["reason"] == "EXTRA_REFERENCE_BYTES_LIMIT" for row in rejected)
    assert all(row["reason"] == "EXTRA_REFERENCE_BYTES_LIMIT"
               for row in result["value"]["gaps"])
    assert all(len(str(rule["static_scope"]["scope_head"])) == 61_000 for rule in rules)
    emitted_extra_bytes = sum(len(base._json_bytes({"static_scope": rule["static_scope"]}))
                              for rule in rules)
    assert emitted_extra_bytes <= base.MAX_TOTAL_CONTEXT_BYTES
