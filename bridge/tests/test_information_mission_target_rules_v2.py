from __future__ import annotations

from copy import deepcopy

from bridge.information.mission_target_rules_v2 import (
    prepare_scope_projection,
    project_target_rules,
)


SOURCE_SHA = "a" * 64
CONFIG_SHA = "b" * 64


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


def task(trigger: dict, task_id: str = "task_one") -> dict:
    return {
        "root_id": "root_one",
        "task_id": task_id,
        "source": {
            "path": "missions/example.txt",
            "sha256": SOURCE_SHA,
            "source_kind": "mission_definition",
            "line": 1,
            "end_line": trigger["end_line"],
            "encoding": {"name": "utf-8"},
        },
        "trigger": trigger,
    }


def province_scope(name: str, province_id: int) -> dict:
    return {
        "status": "known",
        "kind": "province_id",
        "name": name,
        "value": province_id,
        "source": {
            "files": [{"relative": "map/definition.csv", "bytes": 100,
                       "sha256": "c" * 64, "source_kind": "basegame", "source": "game"}],
            "configuration_sha256": CONFIG_SHA,
        },
    }


def area_scope(name: str, members: list[int]) -> dict:
    return {
        "status": "known",
        "kind": "areas",
        "name": name,
        "value": name,
        "members": members,
        "source": {
            "files": [{"relative": "map/area.txt", "bytes": 100,
                       "sha256": "d" * 64, "source_kind": "basegame", "source": "game"}],
            "configuration_sha256": CONFIG_SHA,
        },
    }


def country_scope(name: str) -> dict:
    return {
        "status": "known",
        "kind": "country_tag",
        "name": name,
        "value": name,
        "source": {
            "files": [{"relative": "common/country_tags/00_countries.txt", "bytes": 100,
                       "sha256": "e" * 64, "source_kind": "basegame", "source": "game"}],
            "configuration_sha256": CONFIG_SHA,
        },
    }


def unavailable(reason: str = "SCOPE_NOT_FOUND", kind: str | None = None) -> dict:
    result = {"status": "unknown", "reason": reason}
    if kind is not None:
        result["kind"] = kind
    return result


class FakeScopeIndex:
    def __init__(self, rows: dict[str, dict] | None = None, *, complete: bool = False):
        self.rows = rows or {}
        self.complete = complete
        self.lookup_calls = 0
        self.context_calls = 0
        self.last_names: tuple[str, ...] = ()

    def context(self) -> dict:
        self.context_calls += 1
        return {
            "schema": "information.mission_scope_index_context.v1",
            "status": "ready",
            "complete": self.complete,
            "mode": "static",
            "context_scope": "static_rules",
            "game_version": "1.37.4",
            "configuration_sha256": CONFIG_SHA,
            "definitions_sha256": "f" * 64,
            "component_statuses": {"areas": {"status": "ready", "complete": self.complete,
                                               "reasons": []}},
            "scope_count_by_kind": {"areas": 1},
        }

    def lookup_scopes(self, names):
        self.lookup_calls += 1
        self.last_names = tuple(names)
        return {name: deepcopy(self.rows.get(name, unavailable())) for name in names}


def records(result: dict) -> list[dict]:
    assert result["status"] in {"known", "partial"}
    assert result["complete"] is False
    value = result["value"]
    assert value["complete"] is False
    assert value["evaluated"] is False
    assert value["scope_targets_resolved"] is False
    assert value["full_target_set_resolved"] is False
    assert value["semantics"] == "static_declared_mission_target_conditions"
    assert value["projection_version"] == 2
    return value["rules"]


def test_map_index_proves_numeric_and_named_scope_heads_without_expanding_targets():
    trigger = block("trigger", [
        block("OR", [
            block("201", [scalar("owned_by", "FRA", 4)], 3),
            block("normandy_area", [scalar("owns", 202, 6)], 5),
        ], 2),
    ])
    tasks = [task(trigger)]
    index = FakeScopeIndex({
        "201": province_scope("201", 201),
        "202": province_scope("202", 202),
        "normandy_area": area_scope("normandy_area", [17, 18, 19]),
    })
    prepared = prepare_scope_projection(tasks, index)
    province_result = project_target_rules(tasks, "provinces", scope_index=index, _prepared=prepared)
    region_result = project_target_rules(tasks, "regions", scope_index=index, _prepared=prepared)

    province = next(row for row in records(province_result) if row["kind"] == "scope_head_reference")
    assert province["literal_value"] == "201"
    assert province["static_scope"]["kind"] == "province"
    assert province["static_scope"]["index_kind"] == "province_id"
    assert province["static_scope"]["members"] == [201]
    assert province["static_scope"]["source"]["files"][0]["relative"] == "map/definition.csv"
    assert [row["key"] for row in province["logical_ancestors"]] == ["OR"]
    assert province["requiredness"] == "not_inferred"

    area = next(row for row in records(region_result) if row["kind"] == "scope_head_reference")
    assert area["literal_value"] == "normandy_area"
    assert area["static_scope"]["kind"] == "area"
    assert area["static_scope"]["index_kind"] == "areas"
    assert area["static_scope"]["members"] == [17, 18, 19]
    # prepare performs one batch lookup, shared across both field projections.
    assert index.lookup_calls == 1
    assert index.context_calls == 1


def test_country_tag_block_head_uses_index_not_capitalization_alone():
    trigger = block("trigger", [block("OR", [block("PAP", [scalar("always", "yes", 4)], 3)], 2)])
    tasks = [task(trigger)]
    index = FakeScopeIndex({"PAP": country_scope("PAP")}, complete=False)
    prepared = prepare_scope_projection(tasks, index)
    result = project_target_rules(tasks, "countries", scope_index=index, _prepared=prepared)
    record = records(result)[0]
    assert record["kind"] == "scope_head_reference"
    assert record["literal_value"] == "PAP"
    assert record["static_scope"]["kind"] == "country_tag"
    assert record["static_scope"]["members"] is None
    assert result["provenance"]["extended_reference_projection"]["scope_index_context"]["complete"] is False


def test_numeric_keys_inside_count_or_weight_parameters_are_gaps_not_provinces():
    for parent in ("num_of_owned_provinces_with", "random_list"):
        trigger = block("trigger", [block(parent, [block("201", [scalar("always", "yes", 4)], 3)], 2)])
        tasks = [task(trigger)]
        index = FakeScopeIndex({"201": province_scope("201", 201)})
        prepared = prepare_scope_projection(tasks, index)
        result = project_target_rules(tasks, "provinces", scope_index=index, _prepared=prepared)
        assert result["status"] == "unknown"
        assert "value" not in result
        assert any(gap["reason"] == "OPAQUE_TRIGGER_PARAMETER_CONTAINER" for gap in result["gaps"])


def test_unknown_area_suffix_does_not_become_a_scope_without_index_match():
    tasks = [task(block("trigger", [block("invented_area", [scalar("always", "yes", 3)], 2)]))]
    index = FakeScopeIndex({"invented_area": unavailable("SCOPE_NOT_FOUND")})
    prepared = prepare_scope_projection(tasks, index)
    result = project_target_rules(tasks, "regions", scope_index=index, _prepared=prepared)
    assert result["status"] == "unknown"
    assert result["reason"] == "NO_CLASSIFIED_LITERAL_REFERENCES"
    assert "value" not in result


def test_dynamic_scope_overload_is_symbolic_and_does_not_guess_country():
    tasks = [task(block("trigger", [scalar("controlled_by", "ROOT", 2)]))]
    prepared = prepare_scope_projection(tasks)
    control = project_target_rules(tasks, "control", _prepared=prepared)
    record = records(control)[0]
    assert record["kind"] == "symbolic_condition_reference"
    assert record["symbolic_value"] == "ROOT"
    assert record["field_classifications"] == ["control"]
    assert record["expected_scope_type"] == ["any"]
    assert record["target_resolution"] == {
        "status": "unknown", "reason": "DYNAMIC_SCOPE_SYMBOL_UNRESOLVED",
    }
    assert record["cwt_rule_lines"] == [525]
    countries = project_target_rules(tasks, "countries", _prepared=prepared)
    assert countries["status"] == "unknown"


def test_v1_literal_survives_unavailable_map_resolution():
    tasks = [task(block("trigger", [scalar("region", "france_region", 2)]))]
    index = FakeScopeIndex({"france_region": unavailable("SCOPE_COMPONENT_UNAVAILABLE", "regions")})
    prepared = prepare_scope_projection(tasks, index)
    result = project_target_rules(tasks, "regions", scope_index=index, _prepared=prepared)
    record = records(result)[0]
    assert record["kind"] == "literal_reference"
    assert record["literal_value"] == "france_region"
    assert record["target_resolution"] == {
        "status": "unknown", "reason": "SCOPE_COMPONENT_UNAVAILABLE",
        "scope_kind_candidate": "regions",
    }


def test_prepared_object_is_task_bound_and_mismatch_falls_back_to_v1_literals():
    original = [task(block("trigger", [scalar("region", "france_region", 2)]))]
    index = FakeScopeIndex({"france_region": unavailable("SCOPE_NOT_FOUND")})
    prepared = prepare_scope_projection(original, index)
    changed = [task(block("trigger", [scalar("region", "iberia_region", 2)]))]
    result = project_target_rules(changed, "regions", scope_index=index, _prepared=prepared)
    record = records(result)[0]
    assert record["literal_value"] == "iberia_region"
    assert "static_scope" not in record
    assert result["provenance"]["extended_reference_projection"]["v2_extension_disabled_reason"] == "PREPARED_TASKS_FINGERPRINT_MISMATCH"


def test_dynamic_argument_without_cwt_scope_overload_remains_a_gap():
    tasks = [task(block("trigger", [scalar("owns_core_province", "ROOT", 2)]))]
    prepared = prepare_scope_projection(tasks)
    result = project_target_rules(tasks, "cores", _prepared=prepared)
    assert result["status"] == "unknown"
    assert result["gaps"][0]["reason"] == "DYNAMIC_SCOPE_SYMBOL_UNRESOLVED"
    assert all(row.get("kind") != "symbolic_condition_reference" for row in result.get("rules", []))
