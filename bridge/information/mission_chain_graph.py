"""Pure, bounded graph projection for the M05 linked-targets field.

The input is deliberately the already validated M02/M03 field envelopes.  This
module never reads the game, evaluates triggers, or invents an expansion plan;
it only joins loaded-task prerequisite identities with static target rule rows.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re
from typing import Any, Mapping


SCHEMA = "information.mission_chain_graph.v1"
BASIS_SCHEMA = "information.mission_chain_graph.basis.v1"
MAX_NODES = 4096
MAX_EDGES = 16384
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_CYCLE_WITNESSES = 128
MAX_CYCLE_WITNESS_NODES = 16384
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_TARGET_FIELDS = (
    "provinces", "regions", "countries", "ownership", "control", "cores", "subjects",
)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _node_key(node: Mapping[str, Any]) -> tuple[str, str]:
    return (node["root_id"], node["task_id"])


def _node(root_id: str, task_id: str) -> dict[str, str]:
    return {"root_id": root_id, "task_id": task_id}


def _sort_nodes(rows: list[Mapping[str, Any]]) -> list[dict[str, str]]:
    return [dict(root_id=root, task_id=task)
            for root, task in sorted({_node_key(row) for row in rows})]


def _field(status: str, *, reason: str | None = None, value: Any = None,
           unknowns: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": status, "partial": True, "complete": False}
    if value is not None:
        result["value"] = value
    if reason is not None:
        result["reason"] = reason
    if unknowns:
        result["unknowns"] = deepcopy(unknowns)
    return result


def _failure(reason: str, *, detail: Mapping[str, Any] | None = None) -> dict[str, Any]:
    unknown = {"code": reason}
    if detail:
        unknown.update(deepcopy(dict(detail)))
    return {
        "linked_targets": _field("unknown", reason=reason),
        "basis": _field("unknown", reason=reason, unknowns=[unknown]),
    }


def _valid_id(value: Any) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _validate_selector(selector: Any) -> tuple[str, str] | None:
    if (not isinstance(selector, Mapping)
            or set(selector) != {"root_id", "task_id"}
            or not _valid_id(selector.get("root_id"))
            or not _valid_id(selector.get("task_id"))):
        return None
    return (selector["root_id"], selector["task_id"])


def _target_projection(field_name: str, field: Any, closure: set[tuple[str, str]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Keep the field's rule rows and status metadata without copying all tasks."""

    if not isinstance(field, Mapping):
        return {"status": "unknown", "reason": "TARGET_FIELD_MISSING"}, [{
            "code": "TARGET_FIELD_MISSING", "field": field_name,
        }]
    status = field.get("status")
    if status != "known":
        reason = field.get("reason", "TARGET_FIELD_NOT_KNOWN")
        return {"status": status if isinstance(status, str) else "unknown",
                "complete": False, "reason": reason}, [{
                    "code": "TARGET_FIELD_NOT_KNOWN", "field": field_name,
                    "status": status, "reason": reason,
                }]
    value = field.get("value")
    if not isinstance(value, Mapping) or not isinstance(value.get("rules"), list):
        reason = "TARGET_FIELD_RULES_INVALID"
        return {"status": "unknown", "complete": False, "reason": reason}, [{
            "code": reason, "field": field_name,
        }]

    rows: list[dict[str, Any]] = []
    for row in value["rules"]:
        if not isinstance(row, Mapping):
            return {"status": "unknown", "complete": False,
                    "reason": "TARGET_RULE_INVALID"}, [{
                        "code": "TARGET_RULE_INVALID", "field": field_name,
                    }]
        root_id, task_id = row.get("root_id"), row.get("task_id")
        if not _valid_id(root_id) or not _valid_id(task_id):
            return {"status": "unknown", "complete": False,
                    "reason": "TARGET_RULE_ID_INVALID"}, [{
                        "code": "TARGET_RULE_ID_INVALID", "field": field_name,
                    }]
        if (root_id, task_id) in closure:
            rows.append(deepcopy(dict(row)))

    # Keep semantic flags and field-level gaps, while omitting the complete AST
    # task/context arrays that belong to M03 rather than this graph join.
    upstream_counts = {
        key: deepcopy(value[key]) for key in (
            "rule_count", "task_count", "materialized_task_count", "truncated_task_count",
        ) if key in value
    }
    if not rows:
        result = {"status": "unknown", "complete": False,
                  "reason": "NO_TARGET_REFERENCES_FOR_CHAIN"}
        if upstream_counts:
            result["upstream_counts"] = upstream_counts
        return result, [{
            "code": "NO_TARGET_REFERENCES_FOR_CHAIN", "field": field_name,
        }]
    keep = {
        "field", "semantics", "evaluated", "scope_targets_resolved",
        "full_target_set_resolved", "complete", "projection_version",
        "unresolved_candidate_rules", "unclassified_trigger_nodes", "gaps",
    }
    projected_value = {key: deepcopy(value[key]) for key in keep if key in value}
    projected_value["rules"] = rows
    projected_value["upstream_counts"] = upstream_counts
    # Rule rows carry context_id/trigger_context_id.  Preserve the matching
    # context and task metadata as well, but filter out unrelated loaded tasks
    # and their ASTs instead of copying the complete M03 payload.
    for key in ("tasks", "trigger_contexts"):
        records = value.get(key)
        if isinstance(records, list):
            projected_value[key] = [
                deepcopy(dict(record)) for record in records
                if isinstance(record, Mapping)
                and (record.get("root_id"), record.get("task_id")) in closure
            ]
    selected_task_count = len({
        (row.get("root_id"), row.get("task_id"))
        for row in rows
        if isinstance(row, Mapping)
    })
    if isinstance(projected_value.get("tasks"), list):
        selected_task_count = len(projected_value["tasks"])
    projected_value.update({
        "rule_count": len(rows),
        "task_count": selected_task_count,
        "materialized_task_count": selected_task_count,
        "truncated_task_count": (0 if not upstream_counts.get("truncated_task_count") else None),
    })
    result: dict[str, Any] = {
        "status": "known",
        "complete": field.get("complete") is True,
        "value": projected_value,
    }
    if "gaps" in field:
        result["gaps"] = deepcopy(field["gaps"])
    if "provenance" in field:
        result["upstream_provenance"] = deepcopy(field["provenance"])
    if upstream_counts.get("truncated_task_count"):
        return result, [{"code": "CHAIN_TARGET_TRUNCATION_UNRESOLVED", "field": field_name}]
    return result, []


def _find_cycles(nodes: set[tuple[str, str]], adjacency: Mapping[tuple[str, str], list[tuple[str, str]]]) -> tuple[list[list[dict[str, str]]], bool]:
    """Find back-edge cycles iteratively; bounded closure prevents recursion growth."""

    colour: dict[tuple[str, str], int] = {}
    path: list[tuple[str, str]] = []
    position: dict[tuple[str, str], int] = {}
    cycles: dict[tuple[tuple[str, str], ...], list[dict[str, str]]] = {}
    witness_nodes = 0
    truncated = False

    for root in sorted(nodes):
        if colour.get(root, 0):
            continue
        colour[root] = 1
        path.append(root)
        position[root] = 0
        stack: list[tuple[tuple[str, str], int]] = [(root, 0)]
        while stack:
            current, index = stack[-1]
            neighbours = adjacency.get(current, [])
            if index >= len(neighbours):
                stack.pop()
                colour[current] = 2
                position.pop(current, None)
                if path and path[-1] == current:
                    path.pop()
                continue
            nxt = neighbours[index]
            stack[-1] = (current, index + 1)
            if colour.get(nxt, 0) == 0:
                colour[nxt] = 1
                position[nxt] = len(path)
                path.append(nxt)
                stack.append((nxt, 0))
            elif colour.get(nxt) == 1 and nxt in position:
                cycle = path[position[nxt]:]
                if cycle:
                    # Rotate once at the minimum node instead of allocating an
                    # O(n^2) list of candidate tuples for a long cycle.
                    min_index = min(range(len(cycle)), key=lambda index: cycle[index])
                    canonical = cycle[min_index:] + cycle[:min_index]
                    key = tuple(canonical)
                    if key not in cycles:
                        if (len(cycles) >= MAX_CYCLE_WITNESSES
                                or witness_nodes + len(canonical) > MAX_CYCLE_WITNESS_NODES):
                            truncated = True
                            stack.clear()
                            break
                        cycles[key] = [_node(*pair) for pair in canonical]
                        witness_nodes += len(canonical)
        if truncated:
            break
    return [cycles[key] for key in sorted(cycles)], truncated


def project_chain(prerequisites: dict, target_fields: dict, selector: dict) -> dict:
    """Project M05 ``linked_targets`` and ``basis`` from M02/M03 envelopes.

    The function is pure and deterministic.  It returns partial fields even
    when unresolved dependencies or target-field gaps remain; malformed or
    untrusted prerequisite identity input is rejected instead of becoming an
    empty graph.
    """

    selected = _validate_selector(selector)
    if selected is None:
        return _failure("SELECTOR_INVALID")
    if not isinstance(prerequisites, Mapping):
        return _failure("PREREQUISITES_INVALID")
    if prerequisites.get("status") != "known":
        return _failure("PREREQUISITES_NOT_KNOWN")
    if prerequisites.get("value_origin") != "captured_loaded_required_missions":
        return _failure("LOADED_PREREQUISITES_REQUIRED")
    entries = prerequisites.get("value")
    if not isinstance(entries, list) or not entries:
        return _failure("PREREQUISITE_VALUE_EMPTY")
    if len(entries) > MAX_NODES:
        return _failure("NODE_LIMIT_EXCEEDED")
    if not isinstance(target_fields, Mapping) or not target_fields:
        return _failure("TARGET_FIELDS_EMPTY")

    by_pair: dict[tuple[str, str], dict[str, Any]] = {}
    by_task: dict[str, list[tuple[str, str]]] = {}
    unknowns: list[dict[str, Any]] = []
    input_edge_count = 0
    for entry in entries:
        if not isinstance(entry, Mapping):
            return _failure("PREREQUISITE_ENTRY_INVALID")
        root_id, task_id = entry.get("root_id"), entry.get("task_id")
        required = entry.get("required_task_ids")
        if (not _valid_id(root_id) or not _valid_id(task_id)
                or not isinstance(required, list)
                or len(required) > MAX_EDGES
                or any(not _valid_id(value) for value in required)):
            return _failure("PREREQUISITE_ENTRY_INVALID")
        input_edge_count += len(required)
        if input_edge_count > MAX_EDGES:
            return _failure("EDGE_LIMIT_EXCEEDED")
        pair = (root_id, task_id)
        if pair in by_pair:
            return _failure("DUPLICATE_PREREQUISITE_NODE", detail={
                "root_id": root_id, "task_id": task_id,
            })
        by_pair[pair] = dict(entry)
        by_task.setdefault(task_id, []).append(pair)

    if selected not in by_pair:
        return _failure("SELECTED_TASK_NOT_IN_PREREQUISITES")

    # Bound every dependency, including unresolved and unrelated branches,
    # before hashing or materializing any adjacency/diagnostic arrays.
    try:
        input_hashes = {
            "prerequisites_sha256": _sha256(prerequisites),
            "target_fields_sha256": _sha256(target_fields),
            "selector_sha256": _sha256(selector),
        }
    except (TypeError, ValueError, OverflowError):
        return _failure("INPUT_NOT_CANONICAL_JSON")

    adjacency: dict[tuple[str, str], list[tuple[str, str]]] = {pair: [] for pair in by_pair}
    reverse: dict[tuple[str, str], list[tuple[str, str]]] = {pair: [] for pair in by_pair}
    edge_keys: set[tuple[tuple[str, str], tuple[str, str]]] = set()
    missing: list[dict[str, Any]] = []
    ambiguous: list[dict[str, Any]] = []
    ambiguous_candidate_count = 0
    for pair, entry in by_pair.items():
        seen_required: set[str] = set()
        for required_id in entry["required_task_ids"]:
            if required_id in seen_required:
                unknowns.append({"code": "DUPLICATE_REQUIRED_TASK_ID",
                                 "root_id": pair[0], "task_id": pair[1],
                                 "required_task_id": required_id})
                continue
            seen_required.add(required_id)
            candidates = by_task.get(required_id, [])
            if not candidates:
                missing.append({"root_id": pair[0], "task_id": pair[1],
                                "required_task_id": required_id})
                continue
            if len(candidates) != 1:
                ambiguous_candidate_count += len(candidates)
                if ambiguous_candidate_count > MAX_EDGES:
                    return _failure("AMBIGUOUS_CANDIDATE_LIMIT_EXCEEDED")
                ambiguous.append({"root_id": pair[0], "task_id": pair[1],
                                  "required_task_id": required_id,
                                  "candidates": _sort_nodes([_node(*item) for item in candidates])})
                continue
            prerequisite = candidates[0]
            edge = (pair, prerequisite)
            if edge in edge_keys:
                unknowns.append({"code": "DUPLICATE_DEPENDENCY_EDGE",
                                 "from": _node(*pair), "to": _node(*prerequisite)})
                continue
            edge_keys.add(edge)
            adjacency[pair].append(prerequisite)
            reverse[prerequisite].append(pair)

    for mapping in (adjacency, reverse):
        for pair in mapping:
            mapping[pair] = sorted(set(mapping[pair]))

    # Bidirectional closure from the selected task.  Each traversal is
    # iterative and rejects no node solely because a different branch is bad.
    ancestors: set[tuple[str, str]] = set()
    stack = list(adjacency[selected])
    while stack:
        pair = stack.pop()
        if pair in ancestors:
            continue
        ancestors.add(pair)
        stack.extend(adjacency[pair])
    successors: set[tuple[str, str]] = set()
    stack = list(reverse[selected])
    while stack:
        pair = stack.pop()
        if pair in successors:
            continue
        successors.add(pair)
        stack.extend(reverse[pair])
    # A follow-up can depend on a second branch that is not an ancestor of the
    # selected task (A is selected, C follows A, but C also requires B). Walk
    # each follow-up's prerequisites so the graph never emits C without B or
    # B's own prerequisites.
    supporting: set[tuple[str, str]] = set()
    stack = []
    for pair in successors:
        stack.extend(adjacency[pair])
    while stack:
        pair = stack.pop()
        if pair in supporting:
            continue
        supporting.add(pair)
        stack.extend(adjacency[pair])
    closure = {selected} | ancestors | successors | supporting

    closure_edges = sorted(edge for edge in edge_keys if edge[0] in closure and edge[1] in closure)
    if len(closure_edges) > MAX_EDGES:
        return _failure("EDGE_LIMIT_EXCEEDED")
    cycles, cycles_truncated = _find_cycles(
        closure, {key: [value for value in adjacency.get(key, []) if value in closure]
                  for key in closure})
    if cycles:
        unknowns.append({"code": "DEPENDENCY_CYCLE", "cycles": deepcopy(cycles)})
    if cycles_truncated:
        unknowns.append({"code": "CYCLE_WITNESSES_TRUNCATED",
                         "max_witnesses": MAX_CYCLE_WITNESSES,
                         "max_witness_nodes": MAX_CYCLE_WITNESS_NODES})
    if missing:
        unknowns.append({"code": "MISSING_DEPENDENCY", "items": deepcopy(sorted(missing, key=lambda item: (item["root_id"], item["task_id"], item["required_task_id"])))})
    if ambiguous:
        unknowns.append({"code": "AMBIGUOUS_DEPENDENCY", "items": deepcopy(sorted(ambiguous, key=lambda item: (item["root_id"], item["task_id"], item["required_task_id"])))})

    target_projection: dict[str, Any] = {}
    target_unknowns: list[dict[str, Any]] = []
    for field_name in _TARGET_FIELDS:
        projection, gaps = _target_projection(field_name, target_fields.get(field_name), closure)
        target_projection[field_name] = projection
        target_unknowns.extend(gaps)
    unknowns.extend(target_unknowns)
    unknowns.extend([
        {"code": "MISSION_CONDITIONS_NOT_EVALUATED"},
        {"code": "TRADE_DIPLOMATIC_CONFLICTS_NOT_EVALUATED"},
        {"code": "COSTS_NOT_EVALUATED"},
        {"code": "CURRENT_EXPANSION_FEASIBILITY_UNKNOWN"},
    ])

    selected_nodes = [_node(*selected)]
    prerequisite_nodes = [_node(*pair) for pair in sorted(ancestors - {selected})]
    follow_up_nodes = [_node(*pair) for pair in sorted(successors - {selected})]
    supporting_nodes = [_node(*pair) for pair in sorted(
        supporting - ancestors - successors - {selected})]
    edge_rows = [{"from": _node(*source), "to": _node(*target), "relation": "requires"}
                 for source, target in closure_edges]
    linked_value = {
        "schema": SCHEMA,
        "selected": selected_nodes,
        "prerequisite": prerequisite_nodes,
        "follow_up": follow_up_nodes,
        "supporting_prerequisite": supporting_nodes,
        "dependency_edges": edge_rows,
        "missing_dependencies": sorted(missing, key=lambda item: (item["root_id"], item["task_id"], item["required_task_id"])),
        "ambiguous_dependencies": sorted(ambiguous, key=lambda item: (item["root_id"], item["task_id"], item["required_task_id"])),
        "cycles": cycles,
        "unknowns": deepcopy(unknowns),
        "target_rules": target_projection,
        "evaluated": False,
        "current_expansion_feasibility": "unknown",
        "simultaneous_completion": "unknown",
        "costs": "unknown",
        "complete": False,
    }
    basis_value = {
        "schema": BASIS_SCHEMA,
        "algorithm": "selected_task_bidirectional_dependency_closure_v1",
        "selector": deepcopy(selector),
        "input_sha256": input_hashes,
        "dependency_source": "M02.prerequisites.value with value_origin=captured_loaded_required_missions",
        "target_source": "M03 seven static target field rule projections",
        "node_counts": {"selected": 1, "prerequisite": len(prerequisite_nodes),
                        "follow_up": len(follow_up_nodes),
                        "supporting_prerequisite": len(supporting_nodes),
                        "closure": len(closure)},
        "edge_count": len(edge_rows),
        "target_rule_mapping": {field: len(target_projection[field].get("value", {}).get("rules", []))
                                for field in _TARGET_FIELDS},
        "unknowns": deepcopy(unknowns),
        "conditions_evaluated": False,
        "trade_diplomatic_conflicts_evaluated": False,
        "costs_evaluated": False,
        "complete": False,
    }
    result = {
        "linked_targets": _field("known", value=linked_value, unknowns=unknowns),
        "basis": _field("known", value=basis_value, unknowns=unknowns),
    }
    try:
        if len(_canonical(result)) > MAX_OUTPUT_BYTES:
            return _failure("OUTPUT_LIMIT_EXCEEDED")
    except (TypeError, ValueError, OverflowError):
        return _failure("OUTPUT_NOT_CANONICAL_JSON")
    return result


__all__ = ["BASIS_SCHEMA", "MAX_EDGES", "MAX_NODES", "MAX_OUTPUT_BYTES", "SCHEMA", "project_chain"]
