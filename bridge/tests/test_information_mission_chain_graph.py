"""Pure M05 dependency-graph projection tests."""

from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information.mission_chain_graph import project_chain
from bridge.tests.test_information_mission_targets_source import make_source, query


TARGET_NAMES = ["provinces", "regions", "countries", "ownership", "control", "cores", "subjects"]


def _targets():
    source, state, _definitions = make_source()
    result = source.read(query("M03", TARGET_NAMES), state.context())
    return result["fields"]


def _prerequisites(rows):
    return {
        "status": "known",
        "partial": True,
        "complete": False,
        "value_origin": "captured_loaded_required_missions",
        "value": rows,
    }


def _row(root_id, task_id, required_task_ids):
    return {"root_id": root_id, "task_id": task_id,
            "required_task_ids": list(required_task_ids)}


def test_cross_root_bidirectional_closure_and_filtered_target_contexts():
    prerequisites = _prerequisites([
        _row("root_main", "task_owned", []),
        _row("root_main", "task_core", ["task_owned"]),
        _row("root_extra", "task_region", ["task_core"]),
    ])
    result = project_chain(prerequisites, _targets(),
                           {"root_id": "root_main", "task_id": "task_owned"})

    assert result["linked_targets"]["status"] == "known"
    assert result["linked_targets"]["partial"] is True
    assert result["linked_targets"]["complete"] is False
    value = result["linked_targets"]["value"]
    assert value["selected"] == [{"root_id": "root_main", "task_id": "task_owned"}]
    assert value["prerequisite"] == []
    assert value["follow_up"] == [
        {"root_id": "root_extra", "task_id": "task_region"},
        {"root_id": "root_main", "task_id": "task_core"},
    ]
    assert value["dependency_edges"] == [
        {"from": {"root_id": "root_extra", "task_id": "task_region"},
         "to": {"root_id": "root_main", "task_id": "task_core"},
         "relation": "requires"},
        {"from": {"root_id": "root_main", "task_id": "task_core"},
         "to": {"root_id": "root_main", "task_id": "task_owned"},
         "relation": "requires"},
    ]
    assert value["target_rules"]["provinces"]["value"]["rules"]
    assert {row["task_id"] for row in value["target_rules"]["provinces"]["value"]["rules"]} == {
        "task_owned", "task_core",
    }
    assert all((row["root_id"], row["task_id"]) in {
        ("root_main", "task_owned"), ("root_main", "task_core"),
        ("root_extra", "task_region"),
    } for row in value["target_rules"]["provinces"]["value"]["trigger_contexts"])
    assert result["basis"]["status"] == "known"
    assert result["basis"]["value"]["conditions_evaluated"] is False
    assert len(result["basis"]["value"]["input_sha256"]["prerequisites_sha256"]) == 64


def test_follow_up_supporting_prerequisites_are_added_to_full_closure():
    # selected A -> C, while C independently requires B -> D.  B and D are
    # not ancestors of A, but omitting them would leave the C->B path partial.
    prerequisites = _prerequisites([
        _row("root_main", "selected", []),
        _row("root_main", "follow_up", ["selected", "branch"]),
        _row("root_other", "branch", ["branch_root"]),
        _row("root_other", "branch_root", []),
    ])
    result = project_chain(
        prerequisites,
        {name: {"status": "unknown", "reason": "NO_RULES"} for name in TARGET_NAMES},
        {"root_id": "root_main", "task_id": "selected"},
    )
    value = result["linked_targets"]["value"]
    assert value["follow_up"] == [{"root_id": "root_main", "task_id": "follow_up"}]
    assert value["supporting_prerequisite"] == [
        {"root_id": "root_other", "task_id": "branch"},
        {"root_id": "root_other", "task_id": "branch_root"},
    ]
    assert {(
        edge["from"]["task_id"], edge["to"]["task_id"]
    ) for edge in value["dependency_edges"]} == {
        ("follow_up", "selected"), ("follow_up", "branch"), ("branch", "branch_root"),
    }


def test_missing_and_ambiguous_bare_dependencies_are_explicit():
    missing = project_chain(
        _prerequisites([_row("root_main", "selected", ["not_loaded"])]),
        {name: {"status": "unknown", "reason": "NO_RULES"} for name in TARGET_NAMES},
        {"root_id": "root_main", "task_id": "selected"},
    )
    value = missing["linked_targets"]["value"]
    assert value["missing_dependencies"] == [{
        "root_id": "root_main", "task_id": "selected", "required_task_id": "not_loaded",
    }]
    assert any(item["code"] == "MISSING_DEPENDENCY"
               for item in value["unknowns"])

    ambiguous = project_chain(
        _prerequisites([
            _row("root_main", "selected", ["duplicate"]),
            _row("root_a", "duplicate", []),
            _row("root_b", "duplicate", []),
        ]),
        {}, {"root_id": "root_main", "task_id": "selected"},
    )
    # An empty target mapping is rejected before an ambiguous dependency can
    # be reported; provide explicit unknown fields for the graph-only case.
    assert ambiguous["linked_targets"]["status"] == "unknown"
    ambiguous = project_chain(
        _prerequisites([
            _row("root_main", "selected", ["duplicate"]),
            _row("root_a", "duplicate", []),
            _row("root_b", "duplicate", []),
        ]),
        {name: {"status": "unknown", "reason": "NO_RULES"} for name in TARGET_NAMES},
        {"root_id": "root_main", "task_id": "selected"},
    )
    assert ambiguous["linked_targets"]["value"]["ambiguous_dependencies"][0]["required_task_id"] == "duplicate"


def test_cycle_is_reported_without_recursive_walk_or_false_completeness():
    result = project_chain(
        _prerequisites([
            _row("root_main", "selected", ["next"]),
            _row("root_main", "next", ["selected"]),
        ]),
        {name: {"status": "unknown", "reason": "NO_RULES"} for name in TARGET_NAMES},
        {"root_id": "root_main", "task_id": "selected"},
    )
    value = result["linked_targets"]["value"]
    assert value["cycles"]
    assert value["complete"] is False
    assert any(item["code"] == "DEPENDENCY_CYCLE" for item in value["unknowns"])


def test_cycle_witnesses_are_bounded_with_partial_results_kept():
    rows = [_row("root", "selected", [])]
    for index in range(129):
        task_id = f"cycle_{index}"
        rows.append(_row("root", task_id, ["selected", task_id]))
    result = project_chain(
        _prerequisites(rows),
        {name: {"status": "unknown", "reason": "NO_RULES"} for name in TARGET_NAMES},
        {"root_id": "root", "task_id": "selected"},
    )
    value = result["linked_targets"]["value"]
    assert len(value["cycles"]) <= 128
    assert any(item["code"] == "CYCLE_WITNESSES_TRUNCATED" for item in value["unknowns"])


def test_provenance_and_duplicate_nodes_are_fail_closed():
    rows = [_row("root_main", "selected", [])]
    bad_origin = _prerequisites(rows)
    bad_origin["value_origin"] = "current_definitions_for_captured_roots"
    result = project_chain(bad_origin, {}, {"root_id": "root_main", "task_id": "selected"})
    assert result["linked_targets"]["reason"] == "LOADED_PREREQUISITES_REQUIRED"

    duplicate = project_chain(
        _prerequisites(rows + [_row("root_main", "selected", [])]),
        {name: {"status": "unknown", "reason": "NO_RULES"} for name in TARGET_NAMES},
        {"root_id": "root_main", "task_id": "selected"},
    )
    assert duplicate["linked_targets"]["reason"] == "DUPLICATE_PREREQUISITE_NODE"


def test_unknown_target_fields_are_retained_without_dropping_graph():
    prerequisites = _prerequisites([_row("root_main", "selected", [])])
    target_fields = {name: {"status": "unknown", "reason": "TARGET_UNAVAILABLE"}
                     for name in TARGET_NAMES}
    target_fields["provinces"] = {
        "status": "known", "complete": False,
        "value": {"rules": [], "evaluated": False,
                   "scope_targets_resolved": False, "full_target_set_resolved": False},
    }
    result = project_chain(prerequisites, target_fields,
                           {"root_id": "root_main", "task_id": "selected"})
    assert result["linked_targets"]["status"] == "known"
    assert result["linked_targets"]["value"]["selected"] == [
        {"root_id": "root_main", "task_id": "selected"},
    ]
    assert result["linked_targets"]["value"]["target_rules"]["regions"]["status"] == "unknown"
    assert result["linked_targets"]["value"]["target_rules"]["provinces"]["reason"] == "NO_TARGET_REFERENCES_FOR_CHAIN"


def test_filtered_target_counts_are_recomputed_and_empty_selection_is_unknown():
    targets = _targets()
    only_selected = project_chain(
        _prerequisites([_row("root_main", "task_owned", [])]), targets,
        {"root_id": "root_main", "task_id": "task_owned"},
    )
    provinces = only_selected["linked_targets"]["value"]["target_rules"]["provinces"]
    assert provinces["status"] == "known"
    assert provinces["value"]["upstream_counts"]["task_count"] == 3
    assert provinces["value"]["task_count"] == 1
    assert provinces["value"]["materialized_task_count"] == 1
    assert provinces["value"]["rule_count"] == len(provinces["value"]["rules"]) == 1

    empty = project_chain(
        _prerequisites([_row("root_main", "task_region", [])]), targets,
        {"root_id": "root_main", "task_id": "task_region"},
    )
    assert empty["linked_targets"]["value"]["target_rules"]["provinces"]["status"] == "unknown"
    assert empty["linked_targets"]["value"]["target_rules"]["provinces"]["reason"] == "NO_TARGET_REFERENCES_FOR_CHAIN"


def test_selector_and_limits_fail_closed():
    prerequisites = _prerequisites([_row("root_main", "selected", [])])
    target_fields = {name: {"status": "unknown", "reason": "NO_RULES"} for name in TARGET_NAMES}
    assert project_chain(prerequisites, target_fields, {"root_id": "root_main"})["linked_targets"]["reason"] == "SELECTOR_INVALID"
    huge = deepcopy(prerequisites)
    huge["value"] = [_row("root_main", "selected", ["selected"])] * 4097
    assert project_chain(huge, target_fields,
                         {"root_id": "root_main", "task_id": "selected"})["linked_targets"]["reason"] == "NODE_LIMIT_EXCEEDED"


def test_global_dependency_limit_is_checked_before_hashing(monkeypatch):
    from bridge.information import mission_chain_graph as graph
    monkeypatch.setattr(graph, "MAX_EDGES", 4)
    monkeypatch.setattr(graph, "_sha256", lambda value: pytest.fail("oversized input must not be hashed"))
    value = project_chain(_prerequisites([
        _row("root", "selected", ["a", "b", "c"]),
        _row("root", "other", ["a", "b", "c"]),
    ]), {name: {"status": "unknown"} for name in TARGET_NAMES},
        {"root_id": "root", "task_id": "selected"})
    assert value["linked_targets"]["reason"] == "EDGE_LIMIT_EXCEEDED"


def test_large_cycle_uses_unique_node_budget(monkeypatch):
    from bridge.information import mission_chain_graph as graph
    monkeypatch.setattr(graph, "MAX_NODES", 32)
    rows = [_row("root", f"task_{i}", [f"task_{(i + 1) % 32}"]) for i in range(32)]
    value = project_chain(_prerequisites(rows),
        {name: {"status": "unknown"} for name in TARGET_NAMES},
        {"root_id": "root", "task_id": "task_0"})
    assert value["linked_targets"]["status"] == "known"
    assert value["linked_targets"]["value"]["cycles"]
    assert value["basis"]["value"]["node_counts"]["closure"] == 32


def test_upstream_scope_provenance_and_uncertain_truncation_survive_filtering():
    targets = _targets()
    targets["provinces"]["provenance"] = {"scope_rules": "pinned-cwt", "scope_membership_is_static": True}
    targets["provinces"]["value"]["truncated_task_count"] = 1
    value = project_chain(_prerequisites([_row("root_main", "task_owned", [])]),
                          targets, {"root_id": "root_main", "task_id": "task_owned"})
    field = value["linked_targets"]["value"]["target_rules"]["provinces"]
    assert field["upstream_provenance"] == targets["provinces"]["provenance"]
    assert field["value"]["truncated_task_count"] is None
    assert any(item["code"] == "CHAIN_TARGET_TRUNCATION_UNRESOLVED"
               for item in value["basis"]["value"]["unknowns"])


def test_repeated_ambiguous_ids_have_a_cumulative_candidate_budget(monkeypatch):
    from bridge.information import mission_chain_graph as graph
    monkeypatch.setattr(graph, "MAX_EDGES", 4)
    result = project_chain(_prerequisites([
        _row("root", "selected", ["same"]),
        _row("root_a", "same", ["same"]),
        _row("root_b", "same", ["same"]),
    ]), {name: {"status": "unknown"} for name in TARGET_NAMES},
        {"root_id": "root", "task_id": "selected"})
    assert result["linked_targets"]["reason"] == "AMBIGUOUS_CANDIDATE_LIMIT_EXCEEDED"
