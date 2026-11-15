"""Bounded projection of literal mission reward unlock requests.

This module inventories declared reward AST commands only.  It does not
evaluate conditions, select the post-reward mission tree, or resolve actual
unlocked tasks or applied game state.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import json
import re
from typing import Any, Mapping, Sequence

from . import mission_reward_duration as _duration
from . import mission_reward_rules as _rules


SCHEMA = "information.mission_reward_unlocks.v1"
FIELD = "unlocks"
MAX_OUTPUT_BYTES = 512 * 1024
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_SYMBOLIC_SCOPE = re.compile(r"(?:ROOT|PREV|FROM|THIS)(?:\.|\Z)", re.IGNORECASE)
_SYMBOLIC_PREFIX = re.compile(
    r"(?:event_target|saved_event_target|var|variable|scope):", re.IGNORECASE
)
_MAX_RAW_TEXT = 256

_COMMAND_SPECS: dict[str, dict[str, Any]] = {
    "unlock_cult": {
        "request_kind": "direct_unlock_declaration",
        "target_namespace": "cult",
        "scope": "country",
        "signature": "<cult>",
        "evidence_lines": [672, 673, 674],
        "comment": (
            "Adds the defined cult to the current scope. Cults can be found in "
            "/Europa Universalis IV/common/fetishist_cults/*.txt. No effect if "
            "the country does not hold a religion using fetishist_cult."
        ),
    },
    "swap_non_generic_missions": {
        "request_kind": "mission_tree_refresh_request",
        "target_namespace": None,
        "scope": "country",
        "signature": "yes",
        "evidence_lines": [3355, 3356],
        "comment": None,
    },
    "complete_mission": {
        "request_kind": "mission_completion_request",
        "target_namespace": "mission",
        "scope": "country",
        "signature": "<mission>",
        "evidence_lines": [3358, 3359],
        "comment": None,
    },
    # This literal appears in the selected FRA AST but has no alias in the
    # pinned effects.cwt.  Preserve the declaration without claiming validity.
    "unlock_government_reform": {
        "request_kind": "direct_unlock_declaration",
        "target_namespace": None,
        "scope": None,
        "signature": None,
        "evidence_lines": [],
        "comment": None,
    },
}
_COMMANDS = frozenset(_COMMAND_SPECS)
_CWT_COMMANDS = frozenset({"unlock_cult", "swap_non_generic_missions", "complete_mission"})


def _schema_evidence() -> dict[str, Any]:
    """Reuse the existing bounded CWT/vendor pin checks with unlock metadata."""

    duration_evidence = _duration._schema_evidence()
    commands = {
        name: {
            "request_kind": spec["request_kind"],
            "scope": spec["scope"],
            "signature": spec["signature"],
            "target_namespace": spec["target_namespace"],
            "evidence_lines": list(spec["evidence_lines"]),
            "comment": spec["comment"],
            "schema_validation": (
                "pinned_cwt_alias" if name in _CWT_COMMANDS else "not_in_pinned_cwt"
            ),
        }
        for name, spec in _COMMAND_SPECS.items()
    }
    evidence = {
        "effects_cwt": duration_evidence["effects_cwt"],
        "vendor_manifest": duration_evidence["vendor_manifest"],
        "vendor_repository": duration_evidence["vendor_repository"],
        "vendor_commit": duration_evidence["vendor_commit"],
        "license": duration_evidence["license"],
        "schema_is_engine_execution_evidence": False,
        "commands": commands,
        "commands_not_in_pinned_cwt": ["unlock_government_reform"],
    }
    return json.loads(_rules._json_bytes(evidence))


def _safe_raw_value(value: Any) -> dict[str, Any]:
    if value is None or type(value) in (int, float, bool):
        return {"value": value}
    if isinstance(value, str):
        encoded = value.encode("utf-8", "surrogatepass")
        if len(encoded) <= _MAX_RAW_TEXT:
            return {"value": value}
        return {
            "value_prefix": value[:_MAX_RAW_TEXT],
            "bytes": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
            "truncated": True,
        }
    return {"value_type": type(value).__name__}


def _direct_literal(node: Any) -> tuple[str | None, str | None]:
    """Return a conservative identifier only for a matching direct scalar."""

    if not isinstance(node, Mapping):
        return None, "TARGET_NOT_MAPPING"
    if (node.get("kind") != "scalar" or node.get("assignment") != "="
            or not isinstance(node.get("children"), (list, tuple))
            or node.get("children")):
        return None, "TARGET_NOT_DIRECT_SCALAR"
    raw = node.get("raw_value")
    value = node.get("value")
    if not isinstance(raw, str) or not isinstance(value, str):
        return None, "TARGET_RAW_VALUE_NOT_STRING"

    if raw.startswith('"') or raw.endswith('"'):
        if not (raw.startswith('"') and raw.endswith('"')):
            return None, "TARGET_QUOTING_MALFORMED"
        try:
            decoded = json.loads(raw)
        except (json.JSONDecodeError, UnicodeEncodeError):
            return None, "TARGET_QUOTING_MALFORMED"
        if not isinstance(decoded, str):
            return None, "TARGET_DECODED_VALUE_NOT_STRING"
    else:
        decoded = raw

    if decoded != value:
        return None, "TARGET_RAW_VALUE_MISMATCH"
    if _SYMBOLIC_SCOPE.match(decoded) or _SYMBOLIC_PREFIX.match(decoded):
        return None, "TARGET_SYMBOLIC_REFERENCE"
    if _IDENTIFIER.fullmatch(decoded) is None:
        return None, "TARGET_NOT_LITERAL_IDENTIFIER"
    return decoded, None


def _unknown_target(namespace: str | None, reason: str, raw: Any) -> dict[str, Any]:
    return {
        "status": "unknown",
        "identifier": None,
        "namespace": namespace,
        "reason": reason,
        "raw_value": _safe_raw_value(raw),
    }


def _normalize_scalar_target(node: Mapping[str, Any], namespace: str) -> dict[str, Any]:
    identifier, reason = _direct_literal(node)
    if reason is not None or identifier is None:
        return _unknown_target(namespace, reason or "TARGET_UNKNOWN", node.get("raw_value"))
    return {
        "status": "known_literal",
        "identifier": identifier,
        "namespace": namespace,
        "namespace_basis": "pinned_cwt_declaration",
    }


def _normalize_reform_target(node: Mapping[str, Any]) -> dict[str, Any]:
    if node.get("kind") != "block" or node.get("assignment") != "=":
        return _unknown_target(None, "REFORM_COMMAND_NOT_BLOCK", node.get("raw_value"))
    children = node.get("children")
    if not isinstance(children, (list, tuple)):
        return _unknown_target(None, "REFORM_CHILDREN_INVALID", node.get("raw_value"))
    parameters = [
        child for child in children
        if isinstance(child, Mapping) and child.get("key") == "government_reform"
    ]
    if not parameters:
        return _unknown_target(None, "REFORM_PARAMETER_MISSING", node.get("raw_value"))
    if len(parameters) != 1:
        return _unknown_target(None, "REFORM_PARAMETER_DUPLICATE", node.get("raw_value"))
    if len(children) != 1:
        return _unknown_target(None, "REFORM_CHILDREN_NOT_EXACT", node.get("raw_value"))
    identifier, reason = _direct_literal(parameters[0])
    if reason is not None or identifier is None:
        return _unknown_target(None, reason or "REFORM_TARGET_UNKNOWN", parameters[0].get("raw_value"))
    return {
        "status": "syntax_only",
        "identifier": identifier,
        "namespace": None,
        "namespace_validation": "unknown",
    }


def _exact_yes(node: Mapping[str, Any]) -> tuple[bool, str | None]:
    if (node.get("kind") != "scalar" or node.get("assignment") != "="
            or not isinstance(node.get("children"), (list, tuple))
            or node.get("children")):
        return False, "FLAG_NOT_DIRECT_SCALAR_YES"
    if node.get("raw_value") != "yes" or node.get("value") != "yes":
        return False, "FLAG_NOT_EXACT_YES"
    return True, None


def _normalize_rule(rule: Mapping[str, Any]) -> dict[str, Any]:
    command = rule.get("command")
    spec = _COMMAND_SPECS.get(command) if isinstance(command, str) else None
    result = deepcopy(dict(rule))
    result["request_kind"] = spec["request_kind"] if spec else "unknown"
    result["evaluated"] = False
    result["applied"] = "unknown"
    result["actual_unlocks"] = "unknown"
    result["scope_targets_resolved"] = False
    result["scripted_effects_expanded"] = False

    if spec is None:
        result["status"] = "unknown"
        result["schema_validation"] = {
            "status": "unknown",
            "reason": "COMMAND_NOT_IN_UNLOCK_ALLOWLIST",
        }
        result["target"] = _unknown_target(None, "COMMAND_NOT_IN_UNLOCK_ALLOWLIST", None)
        return result

    if command in _CWT_COMMANDS:
        result["schema_validation"] = {
            "status": "validated_by_pinned_cwt",
            "scope": spec["scope"],
            "signature": spec["signature"],
            "target_namespace": spec["target_namespace"],
            "evidence_lines": list(spec["evidence_lines"]),
        }
    else:
        result["schema_validation"] = {
            "status": "unknown",
            "reason": "COMMAND_NOT_IN_PINNED_CWT",
        }

    raw_node = rule.get("raw_node")
    if not isinstance(raw_node, Mapping):
        result["status"] = "unknown"
        result["target"] = _unknown_target(spec["target_namespace"], "COMMAND_RAW_NODE_INVALID", None)
        return result

    if command == "swap_non_generic_missions":
        exact, reason = _exact_yes(raw_node)
        if exact:
            result["status"] = "known"
            result["request_value"] = {"status": "known_literal", "value": "yes"}
            result["target"] = {"status": "not_applicable", "identifier": None, "namespace": None}
        else:
            result["status"] = "unknown"
            result["request_value"] = {"status": "unknown", "value": _safe_raw_value(raw_node.get("raw_value")), "reason": reason}
            result["schema_validation"] = {"status": "unknown", "reason": reason}
            result["target"] = {"status": "not_applicable", "identifier": None, "namespace": None}
        return result

    if command in {"unlock_cult", "complete_mission"}:
        namespace = spec["target_namespace"]
        target = _normalize_scalar_target(raw_node, namespace)
        result["status"] = "known"
        result["target"] = target
        return result

    if command == "unlock_government_reform":
        result["status"] = "unknown"
        result["target"] = _normalize_reform_target(raw_node)
        return result

    result["status"] = "unknown"
    result["target"] = _unknown_target(spec["target_namespace"], "COMMAND_NORMALIZER_MISSING", None)
    return result


def _prune_context_table(task_result: Mapping[str, Any], rules: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    referenced = {
        ref.get("context_id")
        for rule in rules
        for ref in rule.get("context_refs", [])
        if isinstance(ref, Mapping) and isinstance(ref.get("context_id"), str)
    }
    table = task_result.get("context_table", [])
    if not isinstance(table, (list, tuple)):
        return []
    return [deepcopy(dict(row)) for row in table
            if isinstance(row, Mapping) and row.get("context_id") in referenced]


def _failure(status: str, code: str, detail: str | None = None, *, provenance: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema": SCHEMA,
        "field": FIELD,
        "status": status,
        "complete": False,
        "reason": {"code": code},
    }
    if detail:
        result["reason"]["detail"] = detail[:256]
    if provenance:
        result["provenance"] = deepcopy(dict(provenance))
    return result


def _empty_value() -> dict[str, Any]:
    return {
        "field": FIELD,
        "semantics": "declared_reward_unlock_requests",
        "inventory_status_semantics": "AST traversal completeness; target and command schema status are rule-local.",
        "evaluated": False,
        "applied": "unknown",
        "actual_unlocks": "unknown",
        "scope_targets_resolved": False,
        "scripted_effects_expanded": False,
        "complete": False,
        "no_literal_match_is_known_empty": True,
        "rules": [],
        "task_count": 0,
        "materialized_task_count": 0,
        "known_task_count": 0,
        "unknown_task_count": 0,
        "no_match_task_count": 0,
        "literal_rule_count": 0,
        "truncated_task_count": 0,
        "omitted_task_count": 0,
        "omitted_task_range": None,
        "context_table_count": 0,
    }


def project_reward_unlocks(tasks: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Project literal unlock and mission-change requests from selected ASTs."""

    if not isinstance(tasks, (list, tuple)):
        return _failure("unknown", "TASKS_NOT_SEQUENCE")
    try:
        cwt_evidence = _schema_evidence()
    except Exception as exc:
        return _failure(
            "unavailable",
            "CWT_EVIDENCE_UNAVAILABLE",
            type(exc).__name__,
            provenance={"source": "MissionRewardUnlockProjector", "mode": "static_literal_requests", "field": FIELD},
        )

    state = {"task_nodes": 0, "total_nodes": 0, "output_bytes": 0}
    selected = list(tasks[:_rules.MAX_TASKS])
    truncated = max(0, len(tasks) - _rules.MAX_TASKS)
    task_groups: list[dict[str, Any]] = []
    unknown_reasons: Counter[str] = Counter()
    target_unknown_reasons: Counter[str] = Counter()
    schema_unknown_reasons: Counter[str] = Counter()
    known_task_count = 0
    unknown_task_count = 0
    no_match_task_count = 0
    literal_rule_count = 0

    for index, task in enumerate(selected):
        walked = _rules._project_task(task, index, _COMMANDS, state)
        if walked.get("status") == "unknown":
            unknown_task_count += 1
            reason = walked.get("reason", {}).get("code")
            unknown_reasons[str(reason or "UNKNOWN_AST")] += 1
        else:
            known_task_count += 1
            if not walked.get("rules"):
                no_match_task_count += 1

        normalized = [_normalize_rule(row) for row in walked.get("rules", []) if isinstance(row, Mapping)]
        for row in normalized:
            schema = row.get("schema_validation")
            if isinstance(schema, Mapping) and schema.get("status") == "unknown":
                schema_unknown_reasons[str(schema.get("reason", "SCHEMA_UNKNOWN"))] += 1
            target = row.get("target")
            if isinstance(target, Mapping) and target.get("status") == "unknown":
                target_unknown_reasons[str(target.get("reason", "TARGET_UNKNOWN"))] += 1
            request_value = row.get("request_value")
            if isinstance(request_value, Mapping) and request_value.get("status") == "unknown":
                target_unknown_reasons[str(request_value.get("reason", "REQUEST_VALUE_UNKNOWN"))] += 1

        has_rules = bool(normalized)
        if has_rules or walked.get("status") == "unknown":
            group = dict(walked)
            group["rules"] = normalized
            group["context_table"] = _prune_context_table(walked, normalized)
            group["context_table_count"] = len(group["context_table"])
            if group.get("status") == "known":
                group["literal_inventory"] = "nonempty"
            task_groups.append(group)
            literal_rule_count += len(normalized)

    if truncated:
        unknown_task_count += truncated
        unknown_reasons["TASK_COUNT_LIMIT"] += truncated

    # All unknown ASTs cannot establish an inventory. Do not expose a value
    # that could be mistaken for an empty or complete result.
    if tasks and known_task_count == 0:
        return _failure(
            "unknown",
            "MISSION_AST_UNAVAILABLE",
            provenance={
                "source": "MissionRewardUnlockProjector",
                "mode": "static_literal_requests",
                "field": FIELD,
                "cwt_evidence": cwt_evidence,
                "unknown_reasons": dict(unknown_reasons),
                "target_unknown_reasons": dict(target_unknown_reasons),
                "schema_unknown_reasons": dict(schema_unknown_reasons),
                "total_nodes_visited": state["total_nodes"],
            },
        )

    value = _empty_value()
    value.update({
        "rules": task_groups,
        "task_count": len(tasks),
        "materialized_task_count": len(task_groups),
        "known_task_count": known_task_count,
        "unknown_task_count": unknown_task_count,
        "no_match_task_count": no_match_task_count,
        "literal_rule_count": literal_rule_count,
        "truncated_task_count": truncated,
        "omitted_task_count": truncated,
        "omitted_task_range": {"start": _rules.MAX_TASKS, "end": len(tasks) - 1} if truncated else None,
        "context_table_count": sum(group.get("context_table_count", 0) for group in task_groups),
    })
    status = "known" if unknown_task_count == 0 else "partial"
    envelope = {
        "schema": SCHEMA,
        "field": FIELD,
        "status": status,
        "complete": False,
        "value": value,
        "provenance": {
            "source": "MissionRewardUnlockProjector",
            "mode": "static_literal_requests",
            "field": FIELD,
            "cwt_evidence": cwt_evidence,
            "unknown_reasons": dict(unknown_reasons),
            "target_unknown_reasons": dict(target_unknown_reasons),
            "schema_unknown_reasons": dict(schema_unknown_reasons),
            "total_nodes_visited": state["total_nodes"],
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
                "max_output_bytes": MAX_OUTPUT_BYTES,
            },
        },
    }
    try:
        if len(_rules._json_bytes(envelope)) > MAX_OUTPUT_BYTES:
            return _failure(
                "unknown",
                "OUTPUT_BUDGET_EXCEEDED",
                str(MAX_OUTPUT_BYTES),
                provenance={
                    "source": "MissionRewardUnlockProjector",
                    "mode": "static_literal_requests",
                    "field": FIELD,
                    "cwt_evidence": cwt_evidence,
                    "max_output_bytes": MAX_OUTPUT_BYTES,
                },
            )
    except _rules._ProjectionError as exc:
        return _failure("unknown", "OUTPUT_NOT_SERIALIZABLE", exc.code)
    return envelope


__all__ = ["FIELD", "MAX_OUTPUT_BYTES", "SCHEMA", "project_reward_unlocks"]
