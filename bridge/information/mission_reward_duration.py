"""Bounded projection of command-specific mission reward time terms.

This module consumes the already selected mission effect AST and reuses the
literal reward walker.  It does not execute effects, infer their current
application, or turn command-specific units into a shared calendar date.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from . import mission_reward_rules as _rules


ROOT = Path(__file__).resolve().parents[2]
EFFECTS_CWT_PATH = ROOT / "third_party/cwtools-eu4-config/effects.cwt"
EFFECTS_CWT_BYTES = 170323
EFFECTS_CWT_SHA256 = "9b8630319b86442b82b9c33190ea06c90c57db78df92867193ccccc3ac4b3cfd"
VENDOR_JSON_PATH = ROOT / "third_party/cwtools-eu4-config/VENDOR.json"
VENDOR_JSON_BYTES = 395
VENDOR_JSON_SHA256 = "0c09c3338fa0077fcb0b904464ffa494477abcb7ed5e62cab8a537333d37864d"
VENDOR_REPOSITORY = "https://github.com/cwtools/cwtools-eu4-config.git"
VENDOR_COMMIT = "a85622d368bbb7afca938ed70fdd5eda44aec769"
VENDOR_LICENSE = "MIT"

SCHEMA = "information.mission_reward_duration.v1"
FIELD = "duration"
_INTEGER = re.compile(r"[+-]?[0-9]{1,80}\Z")
_MAX_OCCURRENCES_TO_RETAIN = 16
_MAX_RAW_TEXT = 256


# The pinned CWT file supplies command-specific shapes and only the units or
# sentinels stated in its comments.  An absent unit stays unknown.
_COMMAND_SPECS: dict[str, dict[str, Any]] = {
    "add_claim": {
        "parameters": (),
        "claim_duration_not_declared": True,
        "evidence_lines": [2912, 2916, 2920, 2924],
    },
    "add_permanent_claim": {
        "parameters": (),
        "declared_mode": "permanent_claim",
        "evidence_lines": [2956, 2957, 2960, 2961, 2964, 2965, 2968, 2969],
    },
    "add_country_modifier": {
        "parameters": (("duration", "days", "duration"),),
        "documented_default": {"duration": 1, "unit": "days"},
        "evidence_lines": [204, 208, 209],
    },
    "add_province_modifier": {
        "parameters": (("duration", "days", "duration"),),
        "documented_default": {"duration": 1, "unit": "days"},
        "evidence_lines": [2489, 2493, 2494],
    },
    "add_permanent_province_modifier": {
        "parameters": (("duration", "days", "duration"),),
        "ownership_change_behavior": "persists_through_ownership_changes",
        "evidence_lines": [2504, 2505, 2509],
    },
    "extend_country_modifier": {
        "parameters": (("duration", "days", "extension_delta"),),
        "minimum": {"duration": 1},
        "evidence_lines": [4021, 4022, 4025],
    },
    "add_casus_belli": {
        "parameters": (("months", "months", "duration"),),
        "evidence_lines": [1572, 1577],
    },
    "reverse_add_casus_belli": {
        "parameters": (("months", "months", "duration"),),
        "evidence_lines": [1582, 1587],
    },
    "add_opinion": {
        "parameters": (("years", "years", "opinion_expiry_component"),
                        ("months", "months", "opinion_expiry_component")),
        "composite_group": "opinion_expiry_components",
        "evidence_lines": [1364, 1370, 1373],
    },
    "reverse_add_opinion": {
        "parameters": (("years", "years", "opinion_expiry_component"),
                        ("months", "months", "opinion_expiry_component")),
        "composite_group": "opinion_expiry_components",
        "evidence_lines": [1380, 1386, 1389],
    },
    "add_trade_modifier": {
        "parameters": (("duration", None, "duration"),),
        "evidence_lines": [3170, 3173, 3174],
    },
    "change_price": {
        "parameters": (("duration", None, "duration"),),
        "sentinels": {"duration": {-1: "infinite"}},
        "evidence_lines": [321, 327, 328],
    },
    "add_disaster_modifier": {
        "parameters": (("duration", None, "duration"),),
        "evidence_lines": [864, 866],
    },
    "add_ruler_modifier": {
        "parameters": (("duration", None, "duration"),),
        "evidence_lines": [1853, 1856],
    },
    "add_estate_influence_modifier": {
        "parameters": (("duration", None, "duration"),),
        "evidence_lines": [1649, 1660],
    },
    "add_estate_loyalty_modifier": {
        "parameters": (("duration", None, "duration"),),
        "evidence_lines": [1682, 1689],
    },
    "extend_province_modifier": {
        "parameters": (("duration", None, "extension_delta"),),
        "ownership_change_behavior": "persists_through_ownership_changes",
        "evidence_lines": [2527, 2528, 2531],
    },
    "add_loan": {
        "parameters": (("duration", "months", "loan_due_interval"),),
        "evidence_lines": [3342, 3343, 3345, 3346],
    },
}
_DURATION_COMMANDS = frozenset(_COMMAND_SPECS)


def _pin_file(path: Path, expected_bytes: int, maximum: int) -> dict[str, Any]:
    size = path.stat().st_size
    if size != expected_bytes or size > maximum:
        raise ValueError("CWT_EVIDENCE_SIZE_MISMATCH")
    digest = hashlib.sha256()
    read = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(min(64 * 1024, maximum + 1 - read))
            if not chunk:
                break
            read += len(chunk)
            if read > maximum:
                raise ValueError("CWT_EVIDENCE_SIZE_LIMIT")
            digest.update(chunk)
    if read != size:
        raise ValueError("CWT_EVIDENCE_CHANGED_DURING_READ")
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": read,
            "sha256": digest.hexdigest()}


def _schema_evidence() -> dict[str, Any]:
    effects = _pin_file(EFFECTS_CWT_PATH, EFFECTS_CWT_BYTES, 512 * 1024)
    vendor = _pin_file(VENDOR_JSON_PATH, VENDOR_JSON_BYTES, 8 * 1024)
    if effects["sha256"] != EFFECTS_CWT_SHA256 or vendor["sha256"] != VENDOR_JSON_SHA256:
        raise ValueError("CWT_EVIDENCE_PIN_MISMATCH")
    vendor_document = json.loads(VENDOR_JSON_PATH.read_text(encoding="utf-8"))
    if (not isinstance(vendor_document, dict)
            or vendor_document.get("repository_url") != VENDOR_REPOSITORY
            or vendor_document.get("commit") != VENDOR_COMMIT
            or vendor_document.get("license") != VENDOR_LICENSE):
        raise ValueError("CWT_VENDOR_IDENTITY_MISMATCH")
    evidence = {
        "effects_cwt": effects,
        "vendor_manifest": vendor,
        "vendor_repository": VENDOR_REPOSITORY,
        "vendor_commit": VENDOR_COMMIT,
        "license": VENDOR_LICENSE,
        "schema_is_engine_execution_evidence": False,
        "commands": {name: {key: value for key, value in spec.items()
                             if key != "parameters"}
                     | {"parameters": [
                         {"key": key, "unit": unit, "semantic_kind": kind}
                         for key, unit, kind in spec.get("parameters", ())
                     ]}
                     for name, spec in _COMMAND_SPECS.items()},
    }
    # Public JSON object keys are strings. Keep the in-memory scheduler result
    # identical to a persisted/direct result, including sentinel provenance.
    return json.loads(_rules._json_bytes(evidence))


def _safe_raw_value(value: Any) -> dict[str, Any]:
    if value is None or type(value) in (int, float, bool):
        return {"value": value}
    if isinstance(value, str):
        encoded = value.encode("utf-8", "surrogatepass")
        if len(encoded) <= _MAX_RAW_TEXT:
            return {"value": value}
        return {"value_prefix": value[:_MAX_RAW_TEXT], "bytes": len(encoded),
                "sha256": hashlib.sha256(encoded).hexdigest(), "truncated": True}
    return {"value_type": type(value).__name__}


def _occurrence_summary(node: Mapping[str, Any]) -> dict[str, Any]:
    raw = node.get("raw_value")
    value = node.get("value")
    return {
        "line": node.get("line"),
        "kind": node.get("kind"),
        "assignment": node.get("assignment"),
        "raw_value": _safe_raw_value(raw),
        "value": _safe_raw_value(value),
    }


def _unknown_term(parameter: str, reason: str, nodes: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    occurrences = [_occurrence_summary(node) for node in nodes[:_MAX_OCCURRENCES_TO_RETAIN]]
    return {
        "parameter": parameter,
        "status": "unknown",
        "reason": reason,
        "occurrence_count": len(nodes),
        "occurrences": occurrences,
        "omitted_occurrence_count": max(0, len(nodes) - len(occurrences)),
    }


def _parse_integer_occurrence(node: Mapping[str, Any]) -> tuple[int | None, str | None]:
    if (node.get("kind") != "scalar" or node.get("assignment") != "="
            or not isinstance(node.get("children"), (list, tuple)) or node.get("children")):
        return None, "PARAMETER_NOT_DIRECT_SCALAR"
    raw = node.get("raw_value")
    value = node.get("value")
    if not isinstance(raw, str) or _INTEGER.fullmatch(raw) is None:
        return None, "PARAMETER_NOT_UNQUOTED_INTEGER"
    try:
        parsed = int(raw, 10)
    except (TypeError, ValueError, OverflowError):
        return None, "PARAMETER_INTEGER_INVALID"
    if type(value) is int:
        if value != parsed:
            return None, "PARAMETER_RAW_VALUE_MISMATCH"
    elif isinstance(value, str):
        if _INTEGER.fullmatch(value) is None or int(value, 10) != parsed:
            return None, "PARAMETER_RAW_VALUE_MISMATCH"
    else:
        return None, "PARAMETER_VALUE_NOT_INTEGER"
    return parsed, None


def _extract_term(
    command: str,
    spec: Mapping[str, Any],
    parameter: str,
    unit: str | None,
    semantic_kind: str,
    raw_node: Mapping[str, Any],
) -> tuple[dict[str, Any], bool]:
    children = raw_node.get("children")
    if not isinstance(children, list):
        return _unknown_term(parameter, "COMMAND_CHILDREN_INVALID"), False
    occurrences = [node for node in children
                   if isinstance(node, Mapping) and node.get("key") == parameter]
    if not occurrences:
        return _unknown_term(parameter, "PARAMETER_MISSING"), False
    if len(occurrences) != 1:
        return _unknown_term(parameter, "PARAMETER_DUPLICATE", occurrences), False
    node = occurrences[0]
    parsed, parse_error = _parse_integer_occurrence(node)
    if parse_error is not None or parsed is None:
        return _unknown_term(parameter, parse_error or "PARAMETER_INTEGER_UNKNOWN", occurrences), False

    source_line = node.get("line")
    base = {
        "parameter": parameter,
        "status": "unknown",
        "raw_value": _safe_raw_value(node.get("raw_value")),
        "value": _safe_raw_value(node.get("value")),
        "source_line": source_line if type(source_line) is int else None,
        "semantic_kind": semantic_kind,
    }
    if semantic_kind == "claim_duration_not_declared":
        return {**base, "reason": "CWT_DURATION_NOT_DECLARED"}, False

    sentinel_map = spec.get("sentinels", {}).get(parameter, {})
    if parsed in sentinel_map:
        mode = sentinel_map[parsed]
        return ({**base, "status": "known", "raw_integer": parsed, "unit": unit,
                 "duration_mode": mode, "schema_evidence": "command_specific_sentinel"},
                mode == "infinite")
    if unit is None:
        return {**base, "raw_integer": parsed, "reason": "UNIT_NOT_ESTABLISHED_BY_CWT"}, False
    if parsed < 0:
        return {**base, "raw_integer": parsed,
                "unit": unit, "reason": "NEGATIVE_VALUE_SEMANTICS_NOT_ESTABLISHED"}, False
    if command == "extend_country_modifier" and parsed < 1:
        return {**base, "raw_integer": parsed, "unit": unit,
                "reason": "VALUE_OUTSIDE_CWT_RANGE"}, False

    mode = "zero_literal" if parsed == 0 else "finite_literal"
    term = {**base, "status": "known", "raw_integer": parsed, "unit": unit,
            "duration_mode": mode, "runtime_semantics": "unknown"}
    if semantic_kind in {"extension_delta", "loan_due_interval"}:
        term["quantity_role"] = semantic_kind
    if spec.get("ownership_change_behavior"):
        term["ownership_change_behavior"] = spec["ownership_change_behavior"]
    return term, True


def _project_rule(rule: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
    command = rule.get("command")
    spec = _COMMAND_SPECS.get(command) if isinstance(command, str) else None
    if spec is None:
        return {
            "command": command,
            "status": "unknown",
            "reason": "COMMAND_NOT_IN_DURATION_ALLOWLIST",
            "terms": [],
            "source": rule.get("source"),
            "path": rule.get("path"),
            "condition_context": rule.get("condition_context", []),
            "context_refs": rule.get("context_refs", []),
            "context_status": rule.get("context_status"),
            "scripted_effects_expanded": False,
            "scope_targets_resolved": False,
            "applied": "unknown",
        }
    raw_node = rule.get("raw_node")
    raw_node = raw_node if isinstance(raw_node, Mapping) else {}
    output = {
        "command": command,
        "status": "unknown",
        "terms": [],
        "source": rule.get("source"),
        "path": rule.get("path"),
        "path_text": rule.get("path_text"),
        "parent_scope": rule.get("parent_scope", []),
        "condition_context": rule.get("condition_context", []),
        "context_refs": rule.get("context_refs", []),
        "context_status": rule.get("context_status"),
        "scripted_effects_expanded": False,
        "scope_targets_resolved": False,
        "applied": "unknown",
    }
    for name in ("ownership_change_behavior", "composite_group"):
        if name in spec:
            output[name] = spec[name]

    if command == "add_permanent_claim":
        output.update(status="known", duration_mode="permanent_claim",
                      mode_basis="explicit_effect_command_and_CWT_comment",
                      counts_as_numeric_duration=False)
        return output, False
    if command == "add_claim":
        output["terms"] = [{"parameter": "duration", "status": "unknown",
                            "reason": "CWT_DURATION_NOT_DECLARED"}]
        return output, False

    known_for_field = False
    for parameter, unit, semantic_kind in spec.get("parameters", ()):
        term, qualifies = _extract_term(command, spec, parameter, unit, semantic_kind, raw_node)
        if spec.get("composite_group"):
            term["composite_group"] = spec["composite_group"]
            term["composite_conversion"] = "not_performed"
        output["terms"].append(term)
        known_for_field = known_for_field or qualifies
    output["status"] = "known" if any(term.get("status") == "known" for term in output["terms"]) else "unknown"
    if output["status"] == "unknown" and not output["terms"]:
        output["reason"] = "NO_DURATION_PARAMETER"
    return output, known_for_field


def _safe_cwt_metadata() -> dict[str, Any] | None:
    try:
        return _schema_evidence()
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def project_reward_duration(tasks: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Project bounded, command-specific duration terms from effect ASTs.

    A known field means at least one explicit numeric term has a CWT-supported
    unit, or a command-specific closed sentinel such as ``change_price=-1``.
    It never means the effect ran or has a known runtime expiry.
    """
    if not isinstance(tasks, (list, tuple)):
        return _empty_envelope("unknown", "TASKS_NOT_SEQUENCE")
    cwt = _safe_cwt_metadata()
    if cwt is None:
        return _empty_envelope("unavailable", "CWT_EVIDENCE_PIN_MISMATCH")

    state = {"task_nodes": 0, "total_nodes": 0, "output_bytes": 0}
    selected = list(tasks[:_rules.MAX_TASKS])
    task_results = []
    unknown_reasons: Counter[str] = Counter()
    known_numeric_terms = 0
    known_sentinels = 0
    known_permanent_claims = 0
    recognized_rule_count = 0
    known_rule_count = 0

    for index, task in enumerate(selected):
        result = _rules._project_task(task, index, _DURATION_COMMANDS, state)
        rules = result.get("rules", []) if isinstance(result, dict) else []
        duration_rules = []
        task_known = False
        for rule in rules if isinstance(rules, list) else []:
            if not isinstance(rule, Mapping):
                unknown_reasons["REWARD_RULE_SHAPE_INVALID"] += 1
                continue
            projected, qualifies = _project_rule(rule)
            duration_rules.append(projected)
            recognized_rule_count += 1
            if projected.get("duration_mode") == "permanent_claim":
                known_permanent_claims += 1
            if qualifies:
                task_known = True
                for term in projected.get("terms", []):
                    if term.get("status") == "known":
                        if term.get("duration_mode") == "infinite":
                            known_sentinels += 1
                        else:
                            known_numeric_terms += 1
            else:
                for term in projected.get("terms", []):
                    if term.get("status") == "unknown":
                        unknown_reasons[str(term.get("reason", "DURATION_TERM_UNKNOWN"))] += 1
        if result.get("status") == "unknown":
            reason = result.get("reason", {}).get("code", "TASK_PROJECTION_UNKNOWN")
            unknown_reasons[str(reason)] += 1
        if duration_rules:
            task_status = "known" if task_known else "unknown"
            task_reason = None if task_known else "NO_KNOWN_DURATION_TERM"
        else:
            task_status = "unknown"
            task_reason = "NO_DURATION_RULE_MATCH"
            unknown_reasons[task_reason] += 1
        if task_status == "known":
            known_rule_count += 1
        task_result = {
            "task_index": index,
            "root_id": result.get("root_id") if isinstance(result, dict) else None,
            "task_id": result.get("task_id") if isinstance(result, dict) else None,
            "status": task_status,
            "rules": duration_rules,
            "context_table": result.get("context_table", []) if isinstance(result, dict) else [],
            "context_table_status": "structural_only",
        }
        if task_reason:
            task_result["reason"] = {"code": task_reason}
        task_results.append(task_result)

    truncated = max(0, len(tasks) - _rules.MAX_TASKS)
    if truncated:
        unknown_reasons["TASK_COUNT_LIMIT"] += truncated
    known_task_count = sum(row["status"] == "known" for row in task_results)
    unknown_task_count = len(task_results) - known_task_count + truncated
    has_closed_term = known_numeric_terms > 0 or known_sentinels > 0
    status = "known" if has_closed_term else "unknown"
    reason = None if has_closed_term else (
        "NO_KNOWN_DURATION_TERM" if recognized_rule_count else "NO_DURATION_RULE_MATCH"
    )
    value = {
        "field": FIELD,
        "semantics": "declared_command_specific_effect_time_terms",
        "evaluated": False,
        "applied": "unknown",
        "start_time": "unknown",
        "expiry_time": "unknown",
        "scope_targets_resolved": False,
        "scripted_effects_expanded": False,
        "no_duration_match_is_known_empty": False,
        "no_duration_match_is_unknown": True,
        "complete": False,
        "rules": task_results,
        "task_count": len(tasks),
        "materialized_task_count": len(task_results),
        "known_task_count": known_task_count,
        "unknown_task_count": unknown_task_count,
        "recognized_rule_count": recognized_rule_count,
        "known_rule_count": known_rule_count,
        "known_numeric_term_count": known_numeric_terms,
        "known_command_sentinel_count": known_sentinels,
        "known_permanent_claim_declaration_count": known_permanent_claims,
        "unknown_term_count": sum(count for key, count in unknown_reasons.items()
                                   if key not in {"TASK_COUNT_LIMIT", "NO_DURATION_RULE_MATCH",
                                                  "NO_KNOWN_DURATION_TERM"}),
        "truncated_task_count": truncated,
        "omitted_task_count": truncated,
        "omitted_task_range": ({"start": _rules.MAX_TASKS, "end": len(tasks) - 1}
                                if truncated else None),
    }
    envelope = {
        "schema": SCHEMA,
        "field": FIELD,
        "status": status,
        "complete": False,
        "value": value,
        "reason": reason,
        "provenance": {
            "source": "MissionRewardDurationProjector",
            "mode": "static_rules",
            "field": FIELD,
            "duration_commands": sorted(_DURATION_COMMANDS),
            "cwt_evidence": cwt,
            "runtime_conditions_evaluated": False,
            "actual_reward_status": "unknown",
            "total_nodes_visited": state["total_nodes"],
            "unknown_reasons": dict(sorted(unknown_reasons.items())),
            "limits": {
                "max_tasks": _rules.MAX_TASKS,
                "max_effect_roots": _rules.MAX_EFFECT_ROOTS,
                "max_depth": _rules.MAX_DEPTH,
                "max_children": _rules.MAX_CHILDREN,
                "max_nodes_per_task": _rules.MAX_NODES_PER_TASK,
                "max_total_nodes": _rules.MAX_TOTAL_NODES,
                "max_rules_per_task": _rules.MAX_RULES_PER_TASK,
                "max_contexts_per_task": _rules.MAX_CONTEXTS_PER_TASK,
                "max_raw_node_bytes": _rules.MAX_RAW_NODE_BYTES,
                "max_output_bytes": _rules.MAX_OUTPUT_BYTES,
            },
        },
    }
    if status == "unknown":
        # Unknown field values are removed by the owning source's public
        # normalizer. Keep the bounded structural evidence on a separate key
        # so unsupported terms and explicit permanent-claim declarations do
        # not disappear or accidentally make the duration field known.
        envelope["evidence"] = {
            "kind": "bounded_static_duration_rule_evidence",
            "complete": False,
            "rules": [
                {
                    "task_index": task_result["task_index"],
                    "root_id": task_result.get("root_id"),
                    "task_id": task_result.get("task_id"),
                    "command": rule.get("command"),
                    "status": rule.get("status"),
                    "duration_mode": rule.get("duration_mode"),
                    "mode_basis": rule.get("mode_basis"),
                    "counts_as_numeric_duration": rule.get("counts_as_numeric_duration"),
                    "reason": rule.get("reason"),
                    "terms": rule.get("terms", []),
                    "source": rule.get("source"),
                    "path": rule.get("path"),
                    "path_text": rule.get("path_text"),
                    "condition_context": rule.get("condition_context", []),
                    "context_refs": rule.get("context_refs", []),
                    "context_status": rule.get("context_status"),
                }
                for task_result in task_results
                for rule in task_result.get("rules", [])
            ],
            "task_count": len(tasks),
            "materialized_task_count": len(task_results),
            "truncated_task_count": truncated,
        }
        value["rules"] = []
        value["rule_evidence_key"] = "evidence.rules"
    try:
        if len(_rules._json_bytes(envelope)) > _rules.MAX_OUTPUT_BYTES:
            return _empty_envelope("unknown", "OUTPUT_BUDGET_EXCEEDED")
    except _rules._ProjectionError:
        return _empty_envelope("unknown", "OUTPUT_NOT_SERIALIZABLE")
    return envelope


def _empty_envelope(status: str, reason: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "field": FIELD,
        "status": status,
        "complete": False,
        "value": {
            "field": FIELD,
            "semantics": "declared_command_specific_effect_time_terms",
            "evaluated": False,
            "applied": "unknown",
            "start_time": "unknown",
            "expiry_time": "unknown",
            "scope_targets_resolved": False,
            "scripted_effects_expanded": False,
            "no_duration_match_is_known_empty": False,
            "no_duration_match_is_unknown": True,
            "complete": False,
            "rules": [],
            "task_count": 0,
            "materialized_task_count": 0,
            "known_numeric_term_count": 0,
            "known_command_sentinel_count": 0,
            "known_permanent_claim_declaration_count": 0,
            "truncated_task_count": 0,
        },
        "reason": reason,
        "provenance": {
            "source": "MissionRewardDurationProjector",
            "mode": "static_rules",
            "field": FIELD,
            "duration_commands": sorted(_DURATION_COMMANDS),
            "runtime_conditions_evaluated": False,
            "actual_reward_status": "unknown",
        },
    }


__all__ = ["EFFECTS_CWT_BYTES", "EFFECTS_CWT_SHA256", "SCHEMA", "project_reward_duration"]
