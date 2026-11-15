from __future__ import annotations

import pytest

from bridge.information.mission_target_rules import project_target_rules


SOURCE_SHA = "a" * 64


def scalar(key: str, value, line: int, *, assignment: str = "=") -> dict:
    return {
        "key": key,
        "line": line,
        "end_line": line,
        "value": value,
        "children": [],
        "ast_semantics": "structural",
        "kind": "scalar",
        "assignment": assignment,
        "raw_key": key,
        "raw_value": str(value),
    }


def block(key: str, children: list[dict], line: int = 1, *, assignment: str = "=") -> dict:
    return {
        "key": key,
        "line": line,
        "end_line": max([line, *(child["end_line"] for child in children)]),
        "value": None,
        "children": children,
        "ast_semantics": "structural",
        "kind": "block",
        "assignment": assignment,
        "raw_key": key,
        "raw_value": "{",
    }


def task(trigger: dict | list[dict], *, task_id: str = "task_one") -> dict:
    if isinstance(trigger, list):
        end_line = max([1, *(row["end_line"] for row in trigger)])
    else:
        end_line = trigger["end_line"]
    return {
        "root_id": "root_one",
        "task_id": task_id,
        "source": {
            "path": "missions/example.txt",
            "sha256": SOURCE_SHA,
            "source_kind": "mission_definition",
            "line": 1,
            "end_line": end_line,
            "encoding": {"name": "utf-8"},
        },
        "trigger": trigger,
    }


def project(field: str, *children: dict) -> dict:
    return project_target_rules([task(block("trigger", list(children)))], field)


def rules(result: dict) -> list[dict]:
    assert result["status"] in {"known", "partial"}
    assert result["complete"] is False
    assert result["value"]["evaluated"] is False
    assert result["value"]["scope_targets_resolved"] is False
    return result["value"]["rules"]


def test_cwt_pin_and_alias_sources_are_in_result():
    result = project("cores", scalar("owns_core_province", 42, 3))
    cwt = result["provenance"]["cwtools"]
    assert cwt["status"] == "pinned_source_verified"
    assert cwt["commit"] == "a85622d368bbb7afca938ed70fdd5eda44aec769"
    assert cwt["license"] == "MIT"
    assert cwt["trigger_rules"] == {
        "path": "third_party/cwtools-eu4-config/triggers.cwt",
        "bytes": 222281,
        "sha256": "3aa0f3382ea56ca759e4d3ac0dacd79627699b486bd4ac0f6d716e377f7b2f84",
    }
    alias = cwt["alias_sources"]["owns_core_province"][0]
    assert alias["line"] == 3498
    assert alias["text"].startswith("alias[trigger:owns_core_province]")
    assert rules(result)[0]["field_classifications"] == ["provinces", "ownership", "cores"]


def test_explicit_literal_mappings_cover_m03_fields_without_expansion():
    nodes = [
        scalar("owns", 7, 2),
        scalar("owns_core_province", 8, 3),
        scalar("controls", 9, 4),
        scalar("controlled_by", "FRA", 5),
        scalar("controlled_by", "NATIVES", 6),
        scalar("owned_by", "ENG", 7),
        scalar("is_core", 10, 8),
        scalar("is_core", "FRA", 9),
        scalar("is_territorial_core", 11, 10),
        scalar("is_territorial_core", "ENG", 11),
        scalar("subject_owns", 12, 12),
        scalar("area", "123", 13),
        scalar("area", "brittany_area", 14),
        scalar("region", "france_region", 15),
        scalar("tag", "GER", 16),
        scalar("is_subject_of", "POL", 17),
        scalar("owned_by_subject_of", "RUS", 18),
        scalar("country_or_subject_holds", "DAN", 19),
        scalar("country_or_vassal_holds", "SWE", 20),
        scalar("country_or_non_sovereign_subject_holds", "HOL", 21),
    ]
    by_field = {field: rules(project(field, *nodes)) for field in (
        "provinces", "regions", "countries", "ownership", "control", "cores", "subjects",
    )}

    assert [(row["command_key"], row["literal_value"]) for row in by_field["provinces"]] == [
        ("owns", 7), ("owns_core_province", 8), ("controls", 9),
        ("is_core", 10), ("is_territorial_core", 11), ("subject_owns", 12),
        ("area", 123),
    ]
    assert [(row["command_key"], row["reference_kind"]) for row in by_field["regions"]] == [
        ("area", "area"), ("region", "region"),
    ]
    country_tags = [(row["command_key"], row["literal_value"]) for row in by_field["countries"]]
    assert country_tags[:5] == [
        ("controlled_by", "FRA"), ("owned_by", "ENG"), ("is_core", "FRA"),
        ("is_territorial_core", "ENG"), ("tag", "GER"),
    ]
    assert ("controlled_by", "NATIVES") not in country_tags
    assert [row["literal_value"] for row in by_field["control"]] == [9, "FRA", "NATIVES"]
    assert [row["literal_value"] for row in by_field["cores"]] == [8, 10, "FRA", 11, "ENG"]
    assert [row["literal_value"] for row in by_field["subjects"]] == [
        12, "POL", "RUS", "DAN", "SWE", "HOL",
    ]
    assert all(row["scope_flow"] == "unresolved" for values in by_field.values() for row in values)
    assert all(row["kind"] == "literal_reference" for values in by_field.values() for row in values)


def test_not_or_ancestors_are_preserved_without_requiredness_inference():
    trigger = block("trigger", [
        block("OR", [block("NOT", [scalar("owns", 44, 4)], 3),
                      scalar("controls", 45, 5)], 2),
    ])
    recordset = rules(project_target_rules([task(trigger)], "provinces"))
    owns_record = next(record for record in recordset if record["command_key"] == "owns")
    control_record = next(record for record in recordset if record["command_key"] == "controls")
    assert [row["key"] for row in owns_record["logical_ancestors"]] == ["OR", "NOT"]
    assert [row["key"] for row in control_record["logical_ancestors"]] == ["OR"]
    assert owns_record["requiredness"] == "not_inferred"
    assert owns_record["evaluated"] is False
    assert owns_record["trigger_context_id"] == "t0:trigger0"
    assert owns_record["path_text"] == "trigger.children[0].children[0].children[0]"
    assert owns_record["source"]["line"] == 4


def test_dynamic_scope_and_non_scalar_candidates_are_gaps_not_literals():
    result = project(
        "countries",
        scalar("is_core", "FROM", 2),
        block("owned_by", [scalar("unclassified_child", "FRA", 4)], 3),
    )
    assert result["status"] == "unknown"
    assert "value" not in result
    assert {row["reason"] for row in result["gaps"]} == {
        "DYNAMIC_SCOPE_SYMBOL_UNRESOLVED", "TARGET_ARGUMENT_NOT_DIRECT_SCALAR",
    }
    assert all(row["field"] == "countries" for row in result["gaps"])


def test_no_matching_rule_is_unknown_not_known_empty():
    result = project("provinces", scalar("some_unclassified_trigger", "yes", 2))
    assert result["status"] == "unknown"
    assert result["reason"] == "NO_CLASSIFIED_LITERAL_REFERENCES"
    assert "value" not in result
    assert result["complete"] is False


def test_unknown_dynamic_argument_keeps_field_specific_gap():
    result = project("provinces", scalar("owns", "ROOT", 2))
    assert result["status"] == "unknown"
    assert result["gaps"][0]["reason"] == "DYNAMIC_SCOPE_SYMBOL_UNRESOLVED"
    assert result["gaps"][0]["key"] == "owns"


def test_invalid_province_or_boolean_does_not_become_a_reference():
    result = project("provinces", scalar("owns", True, 2), scalar("controls", 0, 3))
    assert result["status"] == "unknown"
    assert {row["reason"] for row in result["gaps"]} == {
        "ARGUMENT_NOT_LITERAL_SCALAR", "PROVINCE_ID_NOT_LITERAL_OR_OUT_OF_RANGE",
    }


def test_multiple_trigger_roots_preserve_separate_contexts():
    result = project_target_rules([
        task([block("first", [scalar("owns", 31, 2)]),
              block("second", [scalar("controls", 32, 3)])]),
    ], "provinces")
    value = result["value"]
    assert [row["context_id"] for row in value["trigger_contexts"]] == [
        "t0:trigger0", "t0:trigger1",
    ]
    assert [row["trigger_context_id"] for row in value["rules"]] == [
        "t0:trigger0", "t0:trigger1",
    ]
    assert [row["path_text"] for row in value["rules"]] == [
        "trigger[0].children[0]", "trigger[1].children[0]",
    ]


def test_cyclic_ast_fails_closed_without_serializing_it():
    trigger = block("trigger", [])
    trigger["children"].append(trigger)
    result = project_target_rules([task(trigger)], "provinces")
    assert result["status"] == "unknown"
    assert result["gaps"][0]["reason"] == "AST_CYCLE_OR_SHARED_NODE"
    assert "value" not in result


def test_unsupported_field_is_rejected():
    with pytest.raises(ValueError, match="unsupported_target_field"):
        project_target_rules([], "missions")

