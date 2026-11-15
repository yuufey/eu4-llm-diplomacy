from __future__ import annotations

import json
from typing import Any

from bridge.information.mission_reward_duration import (
    EFFECTS_CWT_SHA256,
    SCHEMA,
    VENDOR_JSON_SHA256,
    project_reward_duration,
)


SOURCE_SHA = "b" * 64


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


def task(effect: object, *, task_id: str = "task_a") -> dict[str, Any]:
    return {
        "root_id": "root_a",
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
            "end_line": 80,
            "encoding": {"name": "utf-8", "structural_only": False},
        },
    }


def command(name: str, *parameters: dict[str, Any], line: int = 2) -> dict[str, Any]:
    return node(name, list(parameters), line=line)


def scalar(name: str, value: Any, *, raw: str | None = None, line: int = 3) -> dict[str, Any]:
    return node(name, value=value, raw_value=raw, line=line)


def result_rules(result: dict[str, Any], index: int = 0) -> list[dict[str, Any]]:
    if result.get("status") == "unknown" and isinstance(result.get("evidence"), dict):
        return result["evidence"]["rules"]
    tasks = result["value"]["rules"]
    return tasks[index]["rules"] if tasks else []


def only_rule(result: dict[str, Any], command_name: str) -> dict[str, Any]:
    return next(row for row in result_rules(result) if row["command"] == command_name)


def only_term(rule: dict[str, Any], parameter: str) -> dict[str, Any]:
    return next(term for term in rule["terms"] if term["parameter"] == parameter)


def test_closed_units_keep_command_specific_duration_roles() -> None:
    effects = node(
        "effect",
        [
            command("add_country_modifier", scalar("duration", 30)),
            command("add_province_modifier", scalar("duration", 7)),
            command("add_permanent_province_modifier", scalar("duration", 10)),
            command("extend_country_modifier", scalar("duration", 3)),
            command("add_casus_belli", scalar("months", 24)),
            command("add_loan", scalar("duration", 60)),
        ],
    )

    result = project_reward_duration([task(effects)])

    assert result["schema"] == SCHEMA
    assert result["status"] == "known"
    rows = result_rules(result)
    by_command = {row["command"]: row for row in rows}
    assert only_term(by_command["add_country_modifier"], "duration")["unit"] == "days"
    assert only_term(by_command["add_province_modifier"], "duration")["raw_integer"] == 7
    permanent = only_term(by_command["add_permanent_province_modifier"], "duration")
    assert permanent["unit"] == "days"
    assert by_command["add_permanent_province_modifier"]["ownership_change_behavior"] == (
        "persists_through_ownership_changes"
    )
    extension = only_term(by_command["extend_country_modifier"], "duration")
    assert extension["unit"] == "days"
    assert extension["quantity_role"] == "extension_delta"
    assert extension["duration_mode"] == "finite_literal"
    cb_months = only_term(by_command["add_casus_belli"], "months")
    assert (cb_months["raw_integer"], cb_months["unit"]) == (24, "months")
    loan = only_term(by_command["add_loan"], "duration")
    assert loan["quantity_role"] == "loan_due_interval"
    assert (loan["raw_integer"], loan["unit"]) == (60, "months")
    assert result["value"]["expiry_time"] == "unknown"
    assert result["value"]["applied"] == "unknown"
    assert result["complete"] is False


def test_opinion_components_remain_separate_without_unit_conversion() -> None:
    effects = node(
        "effect",
        [
            command("add_opinion", scalar("years", 2), scalar("months", 6)),
            command("reverse_add_opinion", scalar("months", 5)),
        ],
    )

    result = project_reward_duration([task(effects)])
    direct = only_rule(result, "add_opinion")
    years = only_term(direct, "years")
    months = only_term(direct, "months")
    assert (years["raw_integer"], years["unit"]) == (2, "years")
    assert (months["raw_integer"], months["unit"]) == (6, "months")
    assert years["composite_group"] == months["composite_group"] == "opinion_expiry_components"
    assert years["composite_conversion"] == months["composite_conversion"] == "not_performed"
    reverse = only_rule(result, "reverse_add_opinion")
    assert only_term(reverse, "years")["reason"] == "PARAMETER_MISSING"
    assert only_term(reverse, "months")["raw_integer"] == 5


def test_change_price_infinite_sentinel_is_command_specific() -> None:
    effects = node(
        "effect",
        [
            command("change_price", scalar("duration", -1)),
            command("change_price", scalar("duration", -2)),
            command("add_country_modifier", scalar("duration", -1)),
        ],
    )

    result = project_reward_duration([task(effects)])
    assert result["status"] == "known"
    price_rules = [row for row in result_rules(result) if row["command"] == "change_price"]
    assert only_term(price_rules[0], "duration")["duration_mode"] == "infinite"
    assert only_term(price_rules[0], "duration")["raw_integer"] == -1
    assert only_term(price_rules[1], "duration")["reason"] == (
        "UNIT_NOT_ESTABLISHED_BY_CWT"
    )
    country = only_rule(result, "add_country_modifier")
    assert only_term(country, "duration")["reason"] == (
        "NEGATIVE_VALUE_SEMANTICS_NOT_ESTABLISHED"
    )
    assert result["value"]["known_command_sentinel_count"] == 1


def test_zero_is_a_known_literal_but_cwt_minimum_still_applies() -> None:
    effects = node(
        "effect",
        [
            command("add_country_modifier", scalar("duration", 0)),
            command("extend_country_modifier", scalar("duration", 0)),
        ],
    )

    result = project_reward_duration([task(effects)])
    zero = only_term(only_rule(result, "add_country_modifier"), "duration")
    assert (zero["status"], zero["raw_integer"], zero["duration_mode"]) == (
        "known", 0, "zero_literal"
    )
    assert zero["runtime_semantics"] == "unknown"
    invalid_extension = only_term(only_rule(result, "extend_country_modifier"), "duration")
    assert invalid_extension["status"] == "unknown"
    assert invalid_extension["reason"] == "VALUE_OUTSIDE_CWT_RANGE"
    assert result["status"] == "known"


def test_documented_one_day_default_is_not_filled_when_parameter_is_absent() -> None:
    result = project_reward_duration(
        [task(node("effect", [command("add_country_modifier", scalar("name", "test_mod"))]))]
    )

    assert result["status"] == "unknown"
    term = only_term(only_rule(result, "add_country_modifier"), "duration")
    assert term["status"] == "unknown"
    assert term["reason"] == "PARAMETER_MISSING"
    assert "raw_integer" not in term
    cwt_commands = result["provenance"]["cwt_evidence"]["commands"]
    assert cwt_commands["add_country_modifier"]["documented_default"] == {
        "duration": 1,
        "unit": "days",
    }


def test_unknown_units_and_claim_modes_do_not_make_duration_field_known() -> None:
    effects = node(
        "effect",
        [
            command("add_trade_modifier", scalar("duration", 12)),
            node("add_claim", value="FRA"),
            node("add_permanent_claim", value="FRA"),
        ],
    )

    result = project_reward_duration([task(effects)])
    assert result["status"] == "unknown"
    trade = only_term(only_rule(result, "add_trade_modifier"), "duration")
    assert trade["raw_integer"] == 12
    assert trade["reason"] == "UNIT_NOT_ESTABLISHED_BY_CWT"
    assert only_term(only_rule(result, "add_claim"), "duration")["reason"] == (
        "CWT_DURATION_NOT_DECLARED"
    )
    evidence_trade = next(
        row for row in result["evidence"]["rules"] if row["command"] == "add_trade_modifier"
    )
    assert evidence_trade["terms"][0]["raw_integer"] == 12
    permanent_claim = only_rule(result, "add_permanent_claim")
    assert permanent_claim["status"] == "known"
    assert permanent_claim["duration_mode"] == "permanent_claim"
    assert permanent_claim["counts_as_numeric_duration"] is False
    assert result["value"]["known_permanent_claim_declaration_count"] == 1
    assert result["value"]["known_task_count"] == 0
    assert result["value"]["expiry_time"] == "unknown"


def test_permanent_claim_category_alone_does_not_make_duration_known() -> None:
    result = project_reward_duration(
        [task(node("effect", [node("add_permanent_claim", value="FRA")]))]
    )

    assert result["status"] == "unknown"
    assert result["reason"] == "NO_KNOWN_DURATION_TERM"
    assert result["value"]["known_task_count"] == 0
    assert result["value"]["unknown_task_count"] == 1
    assert result["value"]["known_permanent_claim_declaration_count"] == 1


def test_duplicate_duration_parameters_are_not_resolved_by_last_value() -> None:
    effects = node(
        "effect",
        [command("add_country_modifier", scalar("duration", 3), scalar("duration", 9))],
    )

    result = project_reward_duration([task(effects)])
    assert result["status"] == "unknown"
    term = only_term(only_rule(result, "add_country_modifier"), "duration")
    assert term["reason"] == "PARAMETER_DUPLICATE"
    assert term["occurrence_count"] == 2
    assert [row["raw_value"]["value"] for row in term["occurrences"]] == ["3", "9"]


def test_quoted_decimal_boolean_and_block_values_are_not_integer_literals() -> None:
    effects = node(
        "effect",
        [
            command("add_country_modifier", scalar("duration", "30", raw='"30"')),
            command("add_country_modifier", scalar("duration", 1.5, raw="1.5")),
            command("add_country_modifier", scalar("duration", "yes", raw="yes")),
            command("add_country_modifier", node("duration", [scalar("months", 2)])),
        ],
    )

    result = project_reward_duration([task(effects)])
    assert result["status"] == "unknown"
    terms = [only_term(row, "duration") for row in result_rules(result)]
    assert all(term["status"] == "unknown" for term in terms)
    assert terms[0]["reason"] == "PARAMETER_NOT_UNQUOTED_INTEGER"
    assert terms[1]["reason"] == "PARAMETER_NOT_UNQUOTED_INTEGER"
    assert terms[2]["reason"] == "PARAMETER_NOT_UNQUOTED_INTEGER"
    assert terms[3]["reason"] == "PARAMETER_NOT_DIRECT_SCALAR"


def test_condition_only_command_is_not_projected_as_reward() -> None:
    conditional = node(
        "if",
        [
            node("limit", [command("add_country_modifier", scalar("duration", 99))]),
            command("add_country_modifier", scalar("duration", 2), line=7),
        ],
    )
    result = project_reward_duration([task(node("effect", [conditional]))])

    rules = result_rules(result)
    assert len(rules) == 1
    assert only_term(rules[0], "duration")["raw_integer"] == 2
    assert [item["key"] for item in rules[0]["condition_context"]] == ["if", "limit"]
    assert result["value"]["evaluated"] is False
    assert rules[0]["applied"] == "unknown"


def test_no_matching_duration_rule_is_unknown_not_known_empty() -> None:
    result = project_reward_duration(
        [task(node("effect", [node("add_stability", value=1)]))]
    )

    assert result["status"] == "unknown"
    assert result["reason"] == "NO_DURATION_RULE_MATCH"
    assert result["value"]["no_duration_match_is_known_empty"] is False
    assert result["value"]["no_duration_match_is_unknown"] is True
    assert result["value"]["rules"] == []
    assert result["evidence"]["rules"] == []


def test_cwt_manifest_pins_are_present_in_provenance() -> None:
    result = project_reward_duration([task(node("effect", [command("add_loan", scalar("duration", 12))]))])
    evidence = result["provenance"]["cwt_evidence"]

    assert evidence["effects_cwt"]["sha256"] == EFFECTS_CWT_SHA256
    assert evidence["vendor_manifest"]["sha256"] == VENDOR_JSON_SHA256
    assert evidence["vendor_commit"] == "a85622d368bbb7afca938ed70fdd5eda44aec769"
    assert evidence["license"] == "MIT"
    assert evidence["schema_is_engine_execution_evidence"] is False


def test_change_price_sentinel_provenance_survives_json_roundtrip() -> None:
    result = project_reward_duration(
        [task(node("effect", [command("change_price", scalar("duration", -1))]))]
    )

    assert result["status"] == "known"
    assert only_term(only_rule(result, "change_price"), "duration")["duration_mode"] == "infinite"
    sentinel = result["provenance"]["cwt_evidence"]["commands"]["change_price"]["sentinels"]["duration"]
    assert sentinel == {"-1": "infinite"}
    assert json.loads(json.dumps(result, ensure_ascii=False, sort_keys=True)) == result
