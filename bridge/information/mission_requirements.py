"""Evaluate literal required_missions lists against captured completion IDs.

This covers the list conjunction at 1.37.4 RVA 0x8d4c90, not task triggers,
root potential, display visibility, or the full completion predicate.
"""
from __future__ import annotations

import re

IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
MAX_REQUIRED = 512
MAX_COMPLETED = 4096
SEMANTICS = {
    "game_version": "1.37.4",
    "executable_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
    "parser_rva": "0x8d5070", "predicate_rva": "0x8d4c90",
    "scope": "required_missions_only",
    "derivation": "all_literal_ids_in_captured_country_completion_records",
}


def evaluate_prerequisites(rules, completed, *, game_version):
    """Return a bounded derivation; malformed or unevaluated input stays unknown."""
    result = {"status": "unknown", "satisfied": None, "required_task_ids": None,
              "missing_task_ids": None, "semantics": dict(SEMANTICS)}

    def unknown(reason):
        return dict(result, reason=reason)

    if game_version != SEMANTICS["game_version"]:
        return unknown("PREREQUISITE_SEMANTICS_VERSION_UNSUPPORTED")
    # Missing required_missions is represented by [] by MissionDefinitionIndex.
    nodes = rules if isinstance(rules, list) else [rules]
    if len(nodes) > MAX_REQUIRED:
        return unknown("PREREQUISITE_LIST_LIMIT")
    required = []
    for node in nodes:
        if (not isinstance(node, dict) or node.get("key") != "required_missions"
                or node.get("kind") != "block" or node.get("assignment") != "="
                or node.get("value") is not None or not isinstance(node.get("children"), list)):
            return unknown("PREREQUISITE_EXPRESSION_UNSUPPORTED")
        for child in node["children"]:
            if (not isinstance(child, dict) or child.get("kind") != "bare"
                    or child.get("assignment") is not None or child.get("value") is not None
                    or child.get("children") != [] or not isinstance(child.get("key"), str)
                    or not IDENTIFIER.fullmatch(child["key"])):
                return unknown("PREREQUISITE_EXPRESSION_UNSUPPORTED")
            required.append(child["key"])
            if len(required) > MAX_REQUIRED:
                return unknown("PREREQUISITE_LIST_LIMIT")
    result["required_task_ids"] = required
    if not required:
        return dict(result, status="known", satisfied=True, missing_task_ids=[])
    if not isinstance(completed, dict) or completed.get("status") != "known":
        return unknown("COMPLETION_RECORDS_UNAVAILABLE")
    values = completed.get("task_ids")
    if (not isinstance(values, list) or len(values) > MAX_COMPLETED
            or any(not isinstance(value, str) or not IDENTIFIER.fullmatch(value) for value in values)):
        return unknown("COMPLETION_RECORDS_INVALID")
    completed_ids = set(values)
    missing = [task_id for task_id in required if task_id not in completed_ids]
    return dict(result, status="known", satisfied=not missing, missing_task_ids=missing)
