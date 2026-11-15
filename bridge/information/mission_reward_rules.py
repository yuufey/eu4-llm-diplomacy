"""Bounded projection of literal mission reward effect rules.

The mission definition index exposes structural AST data.  This module keeps
that boundary explicit: it indexes selected command nodes, but never executes
conditions, expands scripted effects, or claims that a reward is currently
owned or applied by the game.  Condition subtrees are retained once in each
task context table and are referenced by AST path from individual rules.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Mapping, Sequence


SUPPORTED_FIELDS = frozenset({"claims", "casus_belli", "trade_modifiers"})
_FIELD_COMMANDS = {
    "claims": frozenset({"add_claim", "add_permanent_claim"}),
    "casus_belli": frozenset({"add_casus_belli"}),
    "trade_modifiers": frozenset({"add_trade_modifier"}),
}
_ALL_REWARD_COMMANDS = frozenset().union(*_FIELD_COMMANDS.values())
_CONDITION_BLOCK_KEYS = frozenset(
    {
        "limit",
        "trigger",
        "potential",
        "potential_on_load",
        "allow",
        "condition",
        "conditions",
        "ai_will_do",
    }
)
_CONTROL_KEYS = frozenset(
    {
        "if",
        "else_if",
        "else",
        "hidden_effect",
        "random_list",
        "random",
        "random_country",
        "random_province",
        "random_owned_province",
    }
)
_OPAQUE_EFFECT_KEYS = frozenset({"scripted_effect", "scripted_effects"})
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
_MISSING = object()

MAX_TASKS = 4096
MAX_EFFECT_ROOTS = 256
MAX_DEPTH = 64
MAX_CHILDREN = 8192
MAX_NODES_PER_TASK = 32768
MAX_TOTAL_NODES = 131072
MAX_RULES_PER_TASK = 4096
MAX_CONTEXTS_PER_TASK = 4096
MAX_RAW_NODE_BYTES = 64 * 1024
MAX_SOURCE_BYTES = 32 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
_MAX_RULE_OUTPUT_BYTES = MAX_OUTPUT_BYTES // 2


class _ProjectionError(Exception):
    """Internal fail-closed error with a stable public reason code."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        self.code = code
        self.detail = detail
        super().__init__(code if detail is None else f"{code}: {detail}")


@dataclass(frozen=True)
class _PreparedNode:
    node: Mapping[str, Any]
    path: tuple[int, ...]
    structural_sha256: str
    header: Mapping[str, Any]
    children: tuple["_PreparedNode", ...]


def _json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, OverflowError, RecursionError) as exc:
        raise _ProjectionError("AST_NOT_JSON_SERIALIZABLE", type(exc).__name__) from exc


def _require_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise _ProjectionError("INVALID_IDENTIFIER", label)
    return value


def _valid_identifier(value: Any) -> str | None:
    """Return only a complete bounded identifier for unknown-task metadata."""

    if isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None:
        return value
    return None


def _require_line(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _ProjectionError("INVALID_AST_LINE", label)
    return value


def _is_control_key(key: str) -> bool:
    return (
        key in _CONTROL_KEYS
        or key.startswith(("every_", "any_", "random_"))
        or key.endswith("_scope")
    )


def _bounded_header(node: Mapping[str, Any], digest: str, child_count: int) -> dict[str, Any]:
    header: dict[str, Any] = {
        "key": node["key"],
        "line": node["line"],
        "end_line": node["end_line"],
        "children_count": child_count,
        "structural_sha256": digest,
    }
    for key in ("kind", "assignment", "raw_key", "raw_value", "operator"):
        value = node.get(key, _MISSING)
        if isinstance(value, (str, int, float, bool)) or value is None:
            if isinstance(value, str) and len(value.encode("utf-8", "surrogatepass")) > 2048:
                continue
            header[key] = value
    value = node.get("value", _MISSING)
    if isinstance(value, (str, int, float, bool)) or value is None:
        if not isinstance(value, str) or len(value.encode("utf-8", "surrogatepass")) <= 2048:
            header["value"] = value
    return header


def _prepare_node(
    node: Any,
    path: tuple[int, ...],
    depth: int,
    state: dict[str, int],
) -> _PreparedNode:
    if depth > MAX_DEPTH:
        raise _ProjectionError("AST_DEPTH_LIMIT", str(MAX_DEPTH))
    if not isinstance(node, Mapping):
        raise _ProjectionError("AST_NODE_NOT_MAPPING")
    state["task_nodes"] += 1
    state["total_nodes"] += 1
    if state["task_nodes"] > MAX_NODES_PER_TASK:
        raise _ProjectionError("AST_TASK_NODE_LIMIT", str(MAX_NODES_PER_TASK))
    if state["total_nodes"] > MAX_TOTAL_NODES:
        raise _ProjectionError("AST_TOTAL_NODE_LIMIT", str(MAX_TOTAL_NODES))
    if len(node) > 64:
        raise _ProjectionError("AST_NODE_FIELD_LIMIT", str(len(node)))

    key = _require_identifier(node.get("key"), "key")
    line = _require_line(node.get("line"), "line")
    end_line = _require_line(node.get("end_line"), "end_line")
    if end_line < line:
        raise _ProjectionError("INVALID_AST_LINE_RANGE")

    children = node.get("children", _MISSING)
    if children is _MISSING:
        raise _ProjectionError("AST_CHILDREN_MISSING")
    if not isinstance(children, (list, tuple)):
        raise _ProjectionError("AST_CHILDREN_NOT_SEQUENCE")
    if len(children) > MAX_CHILDREN:
        raise _ProjectionError("AST_CHILDREN_LIMIT", str(MAX_CHILDREN))

    shallow = {name: value for name, value in node.items() if name != "children"}
    shallow_bytes = _json_bytes(shallow)
    if len(shallow_bytes) > MAX_RAW_NODE_BYTES:
        raise _ProjectionError("AST_NODE_SCALAR_LIMIT", str(MAX_RAW_NODE_BYTES))

    if key in _OPAQUE_EFFECT_KEYS:
        # The body of a scripted effect is deliberately opaque.  Its child
        # nodes are neither indexed nor structurally walked.
        prepared_children: tuple[_PreparedNode, ...] = ()
        digest_payload = {"node": shallow, "opaque_children": len(children)}
    else:
        prepared_children = tuple(
            _prepare_node(child, path + (index,), depth + 1, state)
            for index, child in enumerate(children)
        )
        child_hashes = [child.structural_sha256 for child in prepared_children]
        digest_payload = {"node": shallow, "children": child_hashes}
    digest = hashlib.sha256(_json_bytes(digest_payload)).hexdigest()
    prepared_node = dict(node)
    prepared_node["key"] = key
    prepared_node["line"] = line
    prepared_node["end_line"] = end_line
    if key not in _OPAQUE_EFFECT_KEYS:
        prepared_node["children"] = [child.node for child in prepared_children]
    header = _bounded_header(prepared_node, digest, len(prepared_children))
    return _PreparedNode(
        node=prepared_node,
        path=path,
        structural_sha256=digest,
        header=header,
        children=prepared_children,
    )


def _source_base(task: Mapping[str, Any]) -> dict[str, Any]:
    source = task.get("source", _MISSING)
    if not isinstance(source, Mapping):
        raise _ProjectionError("SOURCE_MISSING")
    path = source.get("path")
    sha256 = source.get("sha256")
    if not isinstance(path, str) or not path or "\x00" in path or len(path) > 4096:
        raise _ProjectionError("SOURCE_PATH_INVALID")
    if not isinstance(sha256, str) or _SHA256.fullmatch(sha256) is None:
        raise _ProjectionError("SOURCE_SHA256_INVALID")
    try:
        result = deepcopy(dict(source))
    except Exception as exc:
        raise _ProjectionError("SOURCE_NOT_COPYABLE", type(exc).__name__) from exc
    result["sha256"] = sha256.lower()
    source_bytes = _json_bytes(result)
    if len(source_bytes) > MAX_SOURCE_BYTES:
        raise _ProjectionError("SOURCE_METADATA_LIMIT", str(MAX_SOURCE_BYTES))
    return result


def _source_for_node(source: Mapping[str, Any], node: _PreparedNode) -> dict[str, Any]:
    result = dict(source)
    result["line"] = node.node["line"]
    result["end_line"] = node.node["end_line"]
    return result


def _path_text(path: tuple[int, ...], effect_is_sequence: bool) -> str:
    if effect_is_sequence:
        if not path:
            return "effect"
        result = f"effect[{path[0]}]"
        rest = path[1:]
    else:
        result = "effect"
        rest = path
    for index in rest:
        result += f".children[{index}]"
    return result


def _header_at(node: _PreparedNode) -> dict[str, Any]:
    result = dict(node.header)
    result["path"] = list(node.path)
    return result


def _raw_node(node: _PreparedNode) -> tuple[dict[str, Any], int]:
    try:
        raw = deepcopy(dict(node.node))
    except Exception as exc:
        raise _ProjectionError("AST_NODE_NOT_COPYABLE", type(exc).__name__) from exc
    raw_bytes = _json_bytes(raw)
    if len(raw_bytes) > MAX_RAW_NODE_BYTES:
        raise _ProjectionError("AST_RAW_NODE_LIMIT", str(MAX_RAW_NODE_BYTES))
    return raw, len(raw_bytes)


def _rule(
    node: _PreparedNode,
    ancestors: tuple[_PreparedNode, ...],
    source: Mapping[str, Any],
    effect_is_sequence: bool,
    active_contexts: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    raw, raw_bytes = _raw_node(node)
    parent_scope = [_header_at(item) for item in ancestors]
    condition_context = [
        {
            "context_id": item["context_id"],
            "key": item["key"],
            "path": list(item["path"]),
            "kind": item["kind"],
            "header": dict(item["header"]),
        }
        for item in active_contexts
    ]
    context_refs = [
        {
            "context_id": item["context_id"],
            "path": list(item["path"]),
            "kind": item["kind"],
        }
        for item in active_contexts
    ]
    return {
        "command": node.node["key"],
        "path": list(node.path),
        "path_text": _path_text(node.path, effect_is_sequence),
        "raw_node": raw,
        "raw_node_bytes": raw_bytes,
        "parent_scope": parent_scope,
        "condition_context": condition_context,
        "context_refs": context_refs,
        "context_status": "unresolved" if active_contexts else "none",
        "source": _source_for_node(source, node),
        "scripted_effects_expanded": False,
    }


def _reserve_output(item: Mapping[str, Any], state: dict[str, int]) -> None:
    item_bytes = len(_json_bytes(item))
    state["output_bytes"] += item_bytes
    # Leave room for per-task envelopes and provenance.  This keeps the final
    # envelope within MAX_OUTPUT_BYTES while retaining already indexed tasks
    # when a later task exhausts the output budget.
    if state["output_bytes"] > _MAX_RULE_OUTPUT_BYTES:
        raise _ProjectionError("OUTPUT_BUDGET_EXCEEDED", str(MAX_OUTPUT_BYTES))


def _register_context(
    node: _PreparedNode,
    ancestors: tuple[_PreparedNode, ...],
    source: Mapping[str, Any],
    effect_is_sequence: bool,
    context_table: list[dict[str, Any]],
    context_by_path: dict[tuple[int, ...], dict[str, Any]],
    state: dict[str, int],
    kind: str | None = None,
) -> dict[str, Any]:
    existing = context_by_path.get(node.path)
    if existing is not None:
        return existing
    if len(context_table) >= MAX_CONTEXTS_PER_TASK:
        raise _ProjectionError("CONTEXT_TASK_LIMIT", str(MAX_CONTEXTS_PER_TASK))
    context_kind = kind or (
        "condition" if node.node["key"] in _CONDITION_BLOCK_KEYS else "control"
    )
    entry: dict[str, Any] = {
        "context_id": f"c{len(context_table)}",
        "kind": context_kind,
        "key": node.node["key"],
        "path": list(node.path),
        "path_text": _path_text(node.path, effect_is_sequence),
        "header": _header_at(node),
        "parent_scope": [_header_at(item) for item in ancestors],
        "source": _source_for_node(source, node),
    }
    if context_kind == "condition":
        raw, raw_bytes = _raw_node(node)
        entry["raw_node"] = raw
        entry["raw_node_bytes"] = raw_bytes
    else:
        entry["raw_node_bytes"] = 0
    _reserve_output(entry, state)
    context_table.append(entry)
    context_by_path[node.path] = entry
    return entry


def _collect(
    node: _PreparedNode,
    ancestors: tuple[_PreparedNode, ...],
    active_contexts: tuple[Mapping[str, Any], ...],
    commands: frozenset[str],
    source: Mapping[str, Any],
    effect_is_sequence: bool,
    rules: list[dict[str, Any]],
    context_table: list[dict[str, Any]],
    context_by_path: dict[tuple[int, ...], dict[str, Any]],
    state: dict[str, int],
) -> None:
    key = node.node["key"]
    if key in _CONDITION_BLOCK_KEYS:
        _register_context(
            node,
            ancestors,
            source,
            effect_is_sequence,
            context_table,
            context_by_path,
            state,
        )
        return

    if key in commands:
        if len(rules) >= MAX_RULES_PER_TASK:
            raise _ProjectionError("RULE_TASK_LIMIT", str(MAX_RULES_PER_TASK))
        item = _rule(node, ancestors, source, effect_is_sequence, active_contexts)
        _reserve_output(item, state)
        rules.append(item)

    if key in _OPAQUE_EFFECT_KEYS:
        return

    child_contexts = list(active_contexts)
    has_direct_condition = any(
        child.node["key"] in _CONDITION_BLOCK_KEYS for child in node.children
    )
    if _is_control_key(key) or has_direct_condition or (
        bool(node.children)
        and key not in _OPAQUE_EFFECT_KEYS
        and key != "effect"
        and key not in _ALL_REWARD_COMMANDS
    ):
        context_kind = "control" if _is_control_key(key) or has_direct_condition else "unknown_scope"
        control = _register_context(
            node,
            ancestors,
            source,
            effect_is_sequence,
            context_table,
            context_by_path,
            state,
            context_kind,
        )
        if all(item["context_id"] != control["context_id"] for item in child_contexts):
            child_contexts.append(control)
        for child in node.children:
            if child.node["key"] in _CONDITION_BLOCK_KEYS:
                condition = _register_context(
                    child,
                    ancestors + (node,),
                    source,
                    effect_is_sequence,
                    context_table,
                    context_by_path,
                    state,
                )
                if all(item["context_id"] != condition["context_id"] for item in child_contexts):
                    child_contexts.append(condition)

    next_ancestors = ancestors + (node,)
    for child in node.children:
        _collect(
            child,
            next_ancestors,
            tuple(child_contexts),
            commands,
            source,
            effect_is_sequence,
            rules,
            context_table,
            context_by_path,
            state,
        )


def _unknown_task(
    task: Any,
    index: int,
    code: str,
    detail: str | None,
    rules: Sequence[Mapping[str, Any]] = (),
    context_table: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    root_id = task.get("root_id") if isinstance(task, Mapping) else None
    task_id = task.get("task_id") if isinstance(task, Mapping) else None
    result: dict[str, Any] = {
        "task_index": index,
        "status": "unknown",
        "rules": [dict(item) for item in rules],
        "context_table": [dict(item) for item in context_table],
        "context_table_status": "structural_only",
        "literal_inventory": "unknown",
        "reason": {"code": code},
    }
    if detail:
        result["reason"]["detail"] = detail[:256]
    valid_root_id = _valid_identifier(root_id)
    if valid_root_id is not None:
        result["root_id"] = valid_root_id
    valid_task_id = _valid_identifier(task_id)
    if valid_task_id is not None:
        result["task_id"] = valid_task_id
    return result


def _project_task(
    task: Any,
    index: int,
    commands: frozenset[str],
    state: dict[str, int],
) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    context_table: list[dict[str, Any]] = []
    context_by_path: dict[tuple[int, ...], dict[str, Any]] = {}
    state["task_nodes"] = 0
    try:
        if not isinstance(task, Mapping):
            raise _ProjectionError("TASK_NOT_MAPPING")
        root_id = _require_identifier(task.get("root_id"), "root_id")
        task_id = _require_identifier(task.get("task_id"), "task_id")
        source = _source_base(task)
        effect = task.get("effect", _MISSING)
        if effect is _MISSING or effect is None:
            raise _ProjectionError("EFFECT_AST_MISSING")

        if isinstance(effect, Mapping):
            roots = [(effect, ())]
            effect_is_sequence = False
        elif isinstance(effect, (list, tuple)):
            if len(effect) > MAX_EFFECT_ROOTS:
                raise _ProjectionError("EFFECT_ROOT_LIMIT", str(MAX_EFFECT_ROOTS))
            roots = [(item, (root_index,)) for root_index, item in enumerate(effect)]
            effect_is_sequence = True
        else:
            raise _ProjectionError("EFFECT_AST_NOT_SEQUENCE")

        for root, root_path in roots:
            prepared = _prepare_node(root, root_path, 0, state)
            _collect(
                prepared,
                (),
                (),
                commands,
                source,
                effect_is_sequence,
                rules,
                context_table,
                context_by_path,
                state,
            )
        return {
            "task_index": index,
            "root_id": root_id,
            "task_id": task_id,
            "status": "known",
            "rules": rules,
            "context_table": context_table,
            "context_table_status": "structural_only",
            "literal_inventory": "nonempty" if rules else "empty",
        }
    except _ProjectionError as exc:
        return _unknown_task(task, index, exc.code, exc.detail, rules, context_table)
    except Exception as exc:
        return _unknown_task(
            task,
            index,
            "PROJECTION_EXCEPTION",
            type(exc).__name__,
            rules,
            context_table,
        )


def _empty_envelope(field: str, status: str, reason: str | None = None) -> dict[str, Any]:
    unknown_reasons: dict[str, int] = {}
    if reason:
        unknown_reasons[reason] = 1
    value = {
        "field": field,
        "semantics": "declared_literal_effect_rules",
        "evaluated": False,
        "applied": "unknown",
        "scope_targets_resolved": False,
        "scripted_effects_expanded": False,
        "no_literal_match_is_known_empty": True,
        "complete": False,
        "rules": [],
        "task_count": 0,
        "materialized_task_count": 0,
        "known_task_count": 0,
        "unknown_task_count": 0,
        "literal_rule_count": 0,
        "truncated_task_count": 0,
        "omitted_task_count": 0,
        "omitted_task_range": None,
        "context_table_count": 0,
    }
    return {
        "field": field,
        "status": status,
        "complete": False,
        "value": value,
        "provenance": {
            "source": "MissionRewardRuleProjector",
            "mode": "static_rules",
            "field": field,
            "total_nodes_visited": 0,
            "unknown_reasons": unknown_reasons,
            "limits": {
                "max_tasks": MAX_TASKS,
                "max_effect_roots": MAX_EFFECT_ROOTS,
                "max_depth": MAX_DEPTH,
                "max_children": MAX_CHILDREN,
                "max_nodes_per_task": MAX_NODES_PER_TASK,
                "max_total_nodes": MAX_TOTAL_NODES,
                "max_rules_per_task": MAX_RULES_PER_TASK,
                "max_contexts_per_task": MAX_CONTEXTS_PER_TASK,
                "max_raw_node_bytes": MAX_RAW_NODE_BYTES,
                "max_output_bytes": MAX_OUTPUT_BYTES,
            },
        },
    }


def project_reward_rules(tasks: Sequence[Mapping[str, Any]], field: str) -> dict[str, Any]:
    """Project selected literal reward commands from mission effect ASTs.

    The returned envelope is static rule inventory.  A known empty inventory
    means the inspected AST was valid and contained no direct command for the
    selected field; it does not mean that indirect or scripted effects are
    absent.
    """

    if not isinstance(field, str) or field not in SUPPORTED_FIELDS:
        raise ValueError(f"unsupported_reward_field:{field!r}")
    if not isinstance(tasks, (list, tuple)):
        return _empty_envelope(field, "unknown", "TASKS_NOT_SEQUENCE")

    state = {
        "task_nodes": 0,
        "total_nodes": 0,
        "output_bytes": 0,
    }
    selected_tasks = list(tasks[:MAX_TASKS])
    results: list[dict[str, Any]] = []
    unknown_reasons: dict[str, int] = {}
    commands = _FIELD_COMMANDS[field]
    for index, task in enumerate(selected_tasks):
        result = _project_task(task, index, commands, state)
        results.append(result)
        if result["status"] == "unknown":
            code = result["reason"]["code"]
            unknown_reasons[code] = unknown_reasons.get(code, 0) + 1

    truncated = max(0, len(tasks) - MAX_TASKS)
    omitted_range = (
        {"start": MAX_TASKS, "end": len(tasks) - 1}
        if truncated
        else None
    )
    if truncated:
        unknown_reasons["TASK_COUNT_LIMIT"] = truncated

    known_count = sum(1 for result in results if result["status"] == "known")
    unknown_count = len(results) - known_count + truncated
    retained_evidence = any(
        result.get("rules") or result.get("context_table")
        for result in results
        if result["status"] == "unknown"
    )
    if unknown_count == 0:
        status = "known"
    elif known_count or retained_evidence:
        status = "partial"
    else:
        status = "unknown"
    literal_rule_count = sum(len(result["rules"]) for result in results)
    context_table_count = sum(len(result["context_table"]) for result in results)
    value = {
        "field": field,
        "semantics": "declared_literal_effect_rules",
        "evaluated": False,
        "applied": "unknown",
        "scope_targets_resolved": False,
        "scripted_effects_expanded": False,
        "no_literal_match_is_known_empty": True,
        "complete": False,
        "rules": results,
        "task_count": len(tasks),
        "materialized_task_count": len(results),
        "known_task_count": known_count,
        "unknown_task_count": unknown_count,
        "literal_rule_count": literal_rule_count,
        "truncated_task_count": truncated,
        "omitted_task_count": truncated,
        "omitted_task_range": omitted_range,
        "context_table_count": context_table_count,
    }
    envelope = {
        "field": field,
        "status": status,
        "complete": False,
        "value": value,
        "provenance": {
            "source": "MissionRewardRuleProjector",
            "mode": "static_rules",
            "field": field,
            "total_nodes_visited": state["total_nodes"],
            "unknown_reasons": unknown_reasons,
            "limits": {
                "max_tasks": MAX_TASKS,
                "max_effect_roots": MAX_EFFECT_ROOTS,
                "max_depth": MAX_DEPTH,
                "max_children": MAX_CHILDREN,
                "max_nodes_per_task": MAX_NODES_PER_TASK,
                "max_total_nodes": MAX_TOTAL_NODES,
                "max_rules_per_task": MAX_RULES_PER_TASK,
                "max_contexts_per_task": MAX_CONTEXTS_PER_TASK,
                "max_raw_node_bytes": MAX_RAW_NODE_BYTES,
                "max_output_bytes": MAX_OUTPUT_BYTES,
            },
        },
    }
    try:
        if len(_json_bytes(envelope)) > MAX_OUTPUT_BYTES:
            return _empty_envelope(field, "unknown", "OUTPUT_BUDGET_EXCEEDED")
    except _ProjectionError:
        return _empty_envelope(field, "unknown", "OUTPUT_NOT_SERIALIZABLE")
    return envelope


__all__ = [
    "MAX_CHILDREN",
    "MAX_DEPTH",
    "MAX_CONTEXTS_PER_TASK",
    "MAX_OUTPUT_BYTES",
    "MAX_RAW_NODE_BYTES",
    "MAX_TASKS",
    "SUPPORTED_FIELDS",
    "project_reward_rules",
]
