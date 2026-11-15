"""Validate the recorded M04 literal reward-rule projection through MCP.

The runner starts ``tools/serve_information.py`` with the fixed historical R70
save and ``--mission-game-data``.  It never binds an operator session and never
starts a game.  The expected command occurrences are built independently from
the bounded :class:`MissionDefinitionIndex` AST; this file deliberately does
not import or call the production reward-rule projector.

Three kinds of recorded query are compared with that independent expectation:
the complete FRA save root set, a selected task, and a selected root.  The
three new M04 fields remain declared literal effects with ``complete=false``;
runtime conditions, scope, and actual application are intentionally unknown.
The older ``rewards`` field is checked for compatibility, while ``unlocks`` and
``duration`` are deliberately checked as unsupported in a mixed query.
Recorded sources are query-only.  The runner does not create a subscription or
periodic call; discovery itself must advertise only the ``query`` trigger.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import queue
import subprocess
import sys
import threading
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ROOT_RESOLVED = ROOT.resolve()
sys.path.insert(0, str(ROOT))

from bridge.information.mission_definitions import MissionDefinitionIndex  # noqa: E402
from bridge.information.saved_missions import SavedMissionSnapshot  # noqa: E402
from work.local_config import user_data  # noqa: E402


EXPECTED_SAVE_SHA256 = "ffa91dbd2a2d544b18d586a895bb9b0c2b90e94ece47b2c74507555b8f58c2e0"
SAVE_NAME = "llm_diplomacy_r70_country_money_rejected_20261020.eu4"
COUNTRY = "FRA"
GAME_VERSION = "1.37.4"
MAX_SAVE_BYTES = 128 * 1024 * 1024
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
RULE_FIELDS = ("claims", "casus_belli", "trade_modifiers")
M04_FIELDS = ("rewards",) + RULE_FIELDS
UNSUPPORTED_M04_FIELDS = ("unlocks", "duration")

# These are effect command keys, not a claim that every command is evaluated.
# They intentionally mirror the public M04 projector's declared support.
FIELD_COMMAND_KEYS = {
    "claims": frozenset({
        "add_claim",
        "add_permanent_claim",
    }),
    "casus_belli": frozenset({"add_casus_belli"}),
    "trade_modifiers": frozenset({"add_trade_modifier"}),
}
# Spellings that may occur in game scripts but are outside the M04 public
# projector's declared support.  They are recorded as unsupported evidence;
# their absence in this save must not silently turn them into supported keys.
UNSUPPORTED_FIELD_COMMAND_KEYS = {
    "claims": frozenset({"add_russian_claim", "give_claims"}),
}

# Keep this structural boundary in the independent checker in lockstep with
# the public projector's contract, without importing or calling that helper.
# ``if``/``else_if`` are effect-control blocks: a direct command in their
# effect branch is still a literal effect.  The nested condition blocks below
# contain predicates and must never be counted as reward commands.  The
# boundary is structural only; none of these conditions are evaluated.
CONDITION_BLOCK_KEYS = frozenset({
    "limit",
    "trigger",
    "potential",
    "potential_on_load",
    "allow",
    "condition",
    "conditions",
    "ai_will_do",
})
OPAQUE_EFFECT_KEYS = frozenset({"scripted_effect", "scripted_effects"})


def _require(condition: Any, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _sha256_file(path: Path, *, max_bytes: int | None = None) -> tuple[str, int]:
    path = path.resolve(strict=True)
    if not path.is_file():
        raise ValueError(f"Expected a regular file: {path}")
    size = path.stat().st_size
    if max_bytes is not None and size > max_bytes:
        raise ValueError(f"File exceeds bounded read budget: {path} ({size}>{max_bytes})")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb", buffering=1024 * 1024) as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(block)
            if max_bytes is not None and total > max_bytes:
                raise ValueError(f"File exceeds bounded read budget while reading: {path}")
            digest.update(block)
    return digest.hexdigest(), total


def _canonical_sha(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _write_json(path: Path, value: Any, *, max_bytes: int = MAX_ARTIFACT_BYTES) -> dict[str, Any]:
    path = path.resolve()
    if not path.is_relative_to(ROOT_RESOLVED):
        raise ValueError(f"Artifact path is outside workspace: {path}")
    encoded = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(encoded) > max_bytes:
        raise ValueError(f"Artifact exceeds bounded output budget: {path} ({len(encoded)}>{max_bytes})")
    if path.exists():
        raise ValueError(f"Refusing to overwrite artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)
    return {"path": path.relative_to(ROOT_RESOLVED).as_posix(),
            "bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}


def _normalise_source_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    value = value.replace("\\", "/")
    marker = "missions/"
    lower = value.lower()
    at = lower.find(marker)
    if at >= 0:
        return value[at:]
    return value


def _int_value(value: Any) -> int | None:
    if type(value) is int:
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _walk_ast(value: Any, path: tuple[int, ...] = (), *, blocked: bool = False):
    """Yield nodes and whether they are inside a non-effect condition block.

    This is deliberately an independent structural walk.  A condition node is
    retained as an audit boundary, but its children are not searched for
    reward commands.  Effect-control nodes such as ``if`` remain traversable
    so a command in the effect branch can still be represented literally.
    Opaque scripted effects are retained as nodes but are not expanded.
    """

    if isinstance(value, dict):
        key = value.get("key")
        current_blocked = blocked or key in CONDITION_BLOCK_KEYS
        yield value, path, current_blocked
        if key in OPAQUE_EFFECT_KEYS or key in CONDITION_BLOCK_KEYS:
            return
        children = value.get("children")
        if isinstance(children, list):
            for index, child in enumerate(children):
                yield from _walk_ast(child, path + (index,), blocked=current_blocked)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_ast(child, path + (index,), blocked=blocked)


def _condition_contexts(value: Any, path: tuple[int, ...] = ()):
    """Yield first-level condition blocks with no predicate evaluation."""

    if isinstance(value, dict):
        key = value.get("key")
        if key in CONDITION_BLOCK_KEYS:
            yield value, path
            return
        if key in OPAQUE_EFFECT_KEYS:
            return
        children = value.get("children")
        if isinstance(children, list):
            for index, child in enumerate(children):
                yield from _condition_contexts(child, path + (index,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _condition_contexts(child, path + (index,))


def _condition_walker_self_check() -> dict[str, Any]:
    """Protect the direct-effect/condition boundary with a tiny AST check."""

    sample = {
        "key": "effect",
        "children": [
            {"key": "if", "children": [
                {"key": "limit", "children": [{"key": "add_claim"}]},
                {"key": "add_claim"},
            ]},
            {"key": "trigger", "children": [{"key": "add_claim"}]},
            {"key": "hidden_effect", "children": [{"key": "add_claim"}]},
        ],
    }
    direct = [node.get("key") for node, _path, blocked in _walk_ast(sample)
              if node.get("key") == "add_claim" and not blocked]
    all_commands: list[str] = []
    def collect_all(value: Any) -> None:
        if isinstance(value, dict):
            if value.get("key") == "add_claim":
                all_commands.append("add_claim")
            children = value.get("children")
            if isinstance(children, list):
                for child in children:
                    collect_all(child)
        elif isinstance(value, list):
            for child in value:
                collect_all(child)
    collect_all(sample)
    excluded_count = len(all_commands) - len(direct)
    context_keys = [node.get("key") for node, _path in _condition_contexts(sample)]
    _require(direct == ["add_claim", "add_claim"],
             "independent condition walker direct-effect self-check failed")
    _require(all_commands == ["add_claim", "add_claim", "add_claim", "add_claim"]
             and excluded_count == 2,
             "independent condition walker condition self-check failed")
    _require(context_keys == ["limit", "trigger"],
             "independent condition context self-check failed")
    return {"passed": True, "direct_effect_commands": 2,
            "condition_commands_excluded": excluded_count, "condition_keys": context_keys}


def _selected_tasks(index: MissionDefinitionIndex, root_ids: list[str], *,
                    root_id: str | None = None, task_id: str | None = None) -> list[dict[str, Any]]:
    if root_id is not None:
        _require(root_id in root_ids, f"root selector is not present in the recorded save: {root_id}")
        selected_roots = index.roots([root_id])
    else:
        selected_roots = index.roots(root_ids)
    tasks: list[dict[str, Any]] = []
    for root in selected_roots:
        if task_id is not None:
            selected = [task for task in root["tasks"] if task.get("task_id") == task_id]
        else:
            selected = list(root["tasks"])
        for task in selected:
            tasks.append(dict(task, root_id=root["root_id"]))
    if task_id is not None:
        _require(tasks, f"task selector is not present in selected roots: {task_id}")
    return tasks


def _expected_occurrences(index: MissionDefinitionIndex, root_ids: list[str], field: str, *,
                          root_id: str | None = None, task_id: str | None = None) -> dict[str, Any]:
    _require(field in RULE_FIELDS, f"unsupported reward field: {field}")
    tasks = _selected_tasks(index, root_ids, root_id=root_id, task_id=task_id)
    rows: list[dict[str, Any]] = []
    for task in tasks:
        source = task.get("source") if isinstance(task.get("source"), dict) else {}
        source_path = _normalise_source_path(source.get("path"))
        _require(source_path is not None, f"task source path is missing: {task.get('task_id')}")
        effect = task.get("effect")
        for node, ast_path, blocked in _walk_ast(effect):
            key = node.get("key")
            if blocked or key not in FIELD_COMMAND_KEYS[field]:
                continue
            line = _int_value(node.get("line"))
            end_line = _int_value(node.get("end_line"))
            _require(line is not None, f"effect command has no line: {key}")
            rows.append({
                "key": key,
                "root_id": task["root_id"],
                "task_id": task["task_id"],
                "line": line,
                "end_line": end_line,
                "path": source_path,
                "ast_path": list(ast_path),
                "tuple": [key, task["root_id"], task["task_id"], line, source_path],
            })
    rows.sort(key=lambda row: (row["path"], row["line"], row["root_id"], row["task_id"], row["key"], row["ast_path"]))
    context_rows: list[dict[str, Any]] = []
    seen_contexts: set[tuple[str, tuple[int, ...]]] = set()
    for task in tasks:
        source = task.get("source") if isinstance(task.get("source"), dict) else {}
        source_path = _normalise_source_path(source.get("path"))
        _require(source_path is not None, f"task source path is missing: {task.get('task_id')}")
        for node, ast_path in _condition_contexts(task.get("effect")):
            key = node.get("key")
            line = _int_value(node.get("line"))
            end_line = _int_value(node.get("end_line"))
            _require(line is not None, f"condition node has no line: {key}")
            marker = (task["root_id"], task["task_id"], ast_path)
            if marker in seen_contexts:
                continue
            seen_contexts.add(marker)
            context_rows.append({
                "key": key,
                "root_id": task["root_id"],
                "task_id": task["task_id"],
                "line": line,
                "end_line": end_line,
                "path": source_path,
                "ast_path": list(ast_path),
            })
    context_rows.sort(key=lambda row: (row["path"], row["line"], row["root_id"],
                                       row["task_id"], row["key"], row["ast_path"]))
    return {
        "field": field,
        "root_selector": root_id,
        "task_selector": task_id,
        "selected_root_ids": [root_id] if root_id else list(root_ids),
        "selected_task_count": len(tasks),
        "occurrences": rows,
        "occurrence_tuples": [row["tuple"] for row in rows],
        "condition_contexts": context_rows,
        "condition_context_count": len(context_rows),
        "ast_semantics": "structural_literal_only",
    }


def _result_item(result: dict[str, Any]) -> dict[str, Any]:
    items = result.get("items")
    _require(isinstance(items, list) and len(items) == 1, "M04 query must return exactly one item")
    item = items[0]
    _require(isinstance(item, dict) and item.get("topic") == "M04", "M04 item is missing")
    return item


def _assert_recorded_context(result: dict[str, Any], save_date: str, request_id: str) -> None:
    context = result.get("context")
    _require(isinstance(context, dict), f"{request_id}: result context missing")
    _require(context.get("mode") == "recorded", f"{request_id}: result is not recorded")
    _require(context.get("observer") == COUNTRY, f"{request_id}: observer is not FRA")
    _require(context.get("game_date") == save_date, f"{request_id}: recorded date mismatch")
    _require(context.get("session_id") is None, f"{request_id}: fabricated live session identity")
    _require(context.get("status") == "ready", f"{request_id}: recorded context is not ready")
    _require(result.get("request_id") == request_id, f"{request_id}: request ID mismatch")
    _require(result.get("delivery", {}).get("status") == "delivered", f"{request_id}: result not delivered")


def _iter_pairs(value: Any, *, max_nodes: int = 300_000):
    pending = [value]
    seen = 0
    while pending:
        current = pending.pop()
        seen += 1
        if seen > max_nodes:
            raise ValueError("MCP reward result exceeds bounded structural traversal")
        if isinstance(current, dict):
            for key, item in current.items():
                yield key, item
                pending.append(item)
        elif isinstance(current, list):
            pending.extend(current)


def _assert_literal_metadata(field: str, envelope: dict[str, Any]) -> None:
    _require(envelope.get("status") in {"known", "partial"}, f"{field}: literal field is not known/partial")
    _require(envelope.get("complete") is False, f"{field}: literal projection must remain complete=false")
    _require(isinstance(envelope.get("value"), (dict, list)), f"{field}: literal value is missing")
    pairs = list(_iter_pairs(envelope))
    literal_marker = any(
        (key == "declared_literal_effect_rules" and value is True)
        or value == "declared_literal_effect_rules"
        for key, value in pairs
    )
    _require(literal_marker, f"{field}: declared_literal_effect_rules marker is missing")
    for key, value in pairs:
        if key in {"runtime_conditions_evaluated", "conditions_evaluated", "evaluated",
                   "scope_evaluated", "scope_verified", "condition_scope_verified",
                   "execution_evaluated", "execution_verified", "effects_applied"}:
            _require(value is not True, f"{field}: runtime condition/evaluation was overclaimed")
        if key in {"actual_reward_status", "applied", "execution_status", "effect_status",
                   "actual_effect_status"}:
            _require(value in {"unknown", None, False}, f"{field}: actual reward status was overclaimed")


def _extract_occurrences(field: str, envelope: dict[str, Any]) -> list[dict[str, Any]]:
    """Read occurrence records from the public result without using a helper.

    The public adapter may wrap occurrences in task records or expose a small
    literal AST.  Both forms retain the same root/task/key/line/source path
    identity.  Nested AST children are skipped once an explicit occurrence
    record is found so the same command is not counted twice.
    """

    allowed = FIELD_COMMAND_KEYS[field]
    found: list[dict[str, Any]] = []

    def visit(value: Any, inherited: dict[str, Any] | None = None,
              *, condition_blocked: bool = False) -> None:
        inherited = dict(inherited or {})
        if isinstance(value, list):
            if (len(value) >= 5 and isinstance(value[0], str) and value[0] in allowed
                    and isinstance(value[1], str) and isinstance(value[2], str)):
                line = _int_value(value[3])
                path = _normalise_source_path(value[4])
                if line is not None and path is not None:
                    found.append({"key": value[0], "root_id": value[1], "task_id": value[2],
                                  "line": line, "path": path, "tuple": [value[0], value[1], value[2], line, path]})
                    return
            for child in value:
                visit(child, inherited, condition_blocked=condition_blocked)
            return
        if not isinstance(value, dict):
            return

        key_name = value.get("key")
        local_condition_blocked = condition_blocked or key_name in CONDITION_BLOCK_KEYS
        # Context-table raw AST and parent/header metadata are evidence for a
        # rule, not additional public occurrences.  Explicit rule records are
        # handled before this branch and are therefore still counted once.
        if local_condition_blocked and key_name not in allowed:
            return

        current = dict(inherited)
        for alias, target in (
            (("root_id", "root", "root_key"), "root_id"),
            (("task_id", "task", "task_key"), "task_id"),
            (("line", "line_number", "source_line"), "line"),
            (("path", "source_path", "file", "source_file"), "path"),
            (("key", "command", "effect_key", "command_key", "rule_key"), "key"),
        ):
            for alias_name in alias:
                if alias_name in value:
                    current[target] = value[alias_name]
                    break
        source = value.get("source")
        if isinstance(source, dict):
            if "path" in source:
                current["path"] = source["path"]
            if "line" in source:
                current["line"] = source["line"]

        command = current.get("key")
        root_id = current.get("root_id")
        task_id = current.get("task_id")
        line = _int_value(current.get("line"))
        path = _normalise_source_path(current.get("path"))
        recognised = (command in allowed and isinstance(root_id, str) and isinstance(task_id, str)
                      and line is not None and path is not None)
        if recognised:
            found.append({"key": command, "root_id": root_id, "task_id": task_id,
                          "line": line, "path": path,
                          "tuple": [command, root_id, task_id, line, path]})
            # An explicit occurrence can carry a literal AST and context
            # metadata, but those children are evidence for this same
            # occurrence and must not be double-counted.
            return
        for key, child in value.items():
            if key in {"context_table", "raw_node", "condition_context", "parent_scope",
                       "header", "source"}:
                continue
            visit(child, current, condition_blocked=local_condition_blocked)

    visit(envelope.get("value"))
    return found


def _compare_occurrences(field: str, envelope: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    actual = _extract_occurrences(field, envelope)
    expected_counter = Counter(tuple(row["tuple"]) for row in expected["occurrences"])
    actual_counter = Counter(tuple(row["tuple"]) for row in actual)
    _require(actual_counter == expected_counter,
             f"{field}: occurrence tuples differ; expected={list(expected_counter.elements())[:8]} "
             f"actual={list(actual_counter.elements())[:8]}")
    return {
        "field": field,
        "expected_count": sum(expected_counter.values()),
        "actual_count": sum(actual_counter.values()),
        "occurrences_match": True,
        "tuple_definition": "[effect_key, root_id, task_id, source_line, source_path]",
    }


def _assert_condition_projection(field: str, envelope: dict[str, Any],
                                 expected: dict[str, Any]) -> dict[str, Any]:
    """Verify shared structural condition tables without evaluating them."""

    value = envelope.get("value")
    _require(isinstance(value, dict), f"{field}: literal value is not an object")
    task_records = value.get("rules")
    _require(isinstance(task_records, list), f"{field}: per-task rule records are missing")
    expected_by_task: dict[tuple[str, str], Counter] = {}
    for row in expected.get("condition_contexts", []):
        task_key = (row["root_id"], row["task_id"])
        expected_by_task.setdefault(task_key, Counter())[tuple((
            row["key"], row["line"], row["end_line"], row["path"],
            tuple(row["ast_path"]),
        ))] += 1

    actual_by_task: dict[tuple[str, str], Counter] = {}
    total_contexts = 0
    for task in task_records:
        _require(isinstance(task, dict), f"{field}: task rule record is not an object")
        root_id = task.get("root_id")
        task_id = task.get("task_id")
        _require(isinstance(root_id, str) and isinstance(task_id, str),
                 f"{field}: task rule record identity is missing")
        task_key = (root_id, task_id)
        table = task.get("context_table")
        _require(isinstance(table, list), f"{field}: {task_key} context_table is missing")
        _require(task.get("context_table_status") == "structural_only",
                 f"{field}: {task_key} context table is not structural_only")
        by_id: dict[str, dict[str, Any]] = {}
        condition_counter: Counter = Counter()
        for context in table:
            _require(isinstance(context, dict), f"{field}: context entry is not an object")
            context_id = context.get("context_id")
            _require(isinstance(context_id, str) and context_id not in by_id,
                     f"{field}: duplicate/invalid context_id in {task_key}")
            by_id[context_id] = context
            key = context.get("key")
            path = context.get("path")
            _require(isinstance(key, str) and isinstance(path, list)
                     and all(type(item) is int and item >= 0 for item in path),
                     f"{field}: malformed context path in {task_key}")
            source = context.get("source")
            _require(isinstance(source, dict), f"{field}: context source is missing in {task_key}")
            source_path = _normalise_source_path(source.get("path"))
            line = _int_value(source.get("line"))
            end_line = _int_value(source.get("end_line"))
            _require(source_path is not None and line is not None,
                     f"{field}: context source identity is incomplete in {task_key}")
            total_contexts += 1
            if context.get("kind") == "condition":
                _require(isinstance(context.get("raw_node"), dict),
                         f"{field}: condition raw AST is missing in {task_key}")
                condition_counter[(key, line, end_line, source_path, tuple(path))] += 1
            else:
                _require(context.get("kind") in {"control", "unknown_scope"},
                         f"{field}: unsupported context kind in {task_key}")

        actual_by_task[task_key] = condition_counter
        _require(condition_counter == expected_by_task.get(task_key, Counter()),
                 f"{field}: condition context table differs for {task_key}")

        rules = task.get("rules")
        _require(isinstance(rules, list), f"{field}: task rules list missing for {task_key}")
        for rule in rules:
            _require(isinstance(rule, dict), f"{field}: rule is not an object in {task_key}")
            refs = rule.get("context_refs")
            _require(isinstance(refs, list), f"{field}: rule context_refs missing in {task_key}")
            _require(rule.get("context_status") == ("unresolved" if refs else "none"),
                     f"{field}: rule context status is inconsistent in {task_key}")
            for ref in refs:
                _require(isinstance(ref, dict), f"{field}: context ref is not an object")
                ref_id = ref.get("context_id")
                _require(ref_id in by_id, f"{field}: dangling context ref in {task_key}")
                context = by_id[ref_id]
                _require(ref.get("path") == context.get("path")
                         and ref.get("kind") == context.get("kind"),
                         f"{field}: context ref disagrees with table in {task_key}")
                if ref.get("kind") == "condition":
                    _require(context.get("kind") == "condition",
                             f"{field}: condition ref does not resolve to condition context")
            condition_context = rule.get("condition_context")
            _require(isinstance(condition_context, list),
                     f"{field}: rule condition_context missing in {task_key}")
            for ref in condition_context:
                _require(isinstance(ref, dict) and ref.get("context_id") in by_id,
                         f"{field}: dangling condition_context ref in {task_key}")
                context = by_id[ref["context_id"]]
                _require(ref.get("path") == context.get("path")
                         and ref.get("kind") == context.get("kind"),
                         f"{field}: condition_context disagrees with table in {task_key}")

    _require(set(expected_by_task).issubset(actual_by_task),
             f"{field}: condition context task identities are missing")
    _require(value.get("context_table_count") == total_contexts,
             f"{field}: context_table_count is inconsistent")
    return {
        "context_table_status": "structural_only",
        "task_count": len(task_records),
        "condition_context_count": sum(sum(counter.values()) for counter in actual_by_task.values()),
        "context_entry_count": total_contexts,
        "conditions_evaluated": False,
        "context_tables_match": True,
    }


def _assert_old_rewards(envelope: dict[str, Any], expected_task_count: int) -> None:
    _require(envelope.get("status") == "known", "legacy rewards field is not known")
    value = envelope.get("value")
    _require(isinstance(value, dict), "legacy rewards value is not an object")
    _require(value.get("evaluated") is False, "legacy rewards evaluated flag changed")
    _require(value.get("applied") == "unknown", "legacy rewards applied flag changed")
    tasks = value.get("tasks")
    _require(isinstance(tasks, list) and len(tasks) == expected_task_count,
             "legacy rewards task projection is incomplete")


def _assert_m04_result(result: dict[str, Any], request_id: str, save_date: str,
                       expected_by_field: dict[str, dict[str, Any]]) -> dict[str, Any]:
    _assert_recorded_context(result, save_date, request_id)
    _require(result.get("complete") is False, f"{request_id}: partial reward result overclaims complete")
    item = _result_item(result)
    _require(item.get("complete") is False, f"{request_id}: item overclaims complete")
    fields = item.get("fields")
    _require(isinstance(fields, dict), f"{request_id}: fields missing")
    _assert_old_rewards(fields.get("rewards", {}), expected_by_field["claims"]["selected_task_count"])
    checks = {}
    for field in RULE_FIELDS:
        envelope = fields.get(field)
        _require(isinstance(envelope, dict), f"{request_id}: {field} field missing")
        _assert_literal_metadata(field, envelope)
        occurrence_check = _compare_occurrences(field, envelope, expected_by_field[field])
        context_check = _assert_condition_projection(field, envelope, expected_by_field[field])
        checks[field] = {**occurrence_check, **context_check}
    return {"request_id": request_id, "item_complete": item.get("complete"), "field_checks": checks}


def _assert_mixed_unsupported(result: dict[str, Any], request_id: str) -> dict[str, Any]:
    item = _result_item(result)
    fields = item.get("fields")
    _require(isinstance(fields, dict), f"{request_id}: mixed result fields missing")
    checks = {}
    for field in UNSUPPORTED_M04_FIELDS:
        envelope = fields.get(field)
        _require(isinstance(envelope, dict), f"{request_id}: {field} missing from mixed result")
        _require(envelope.get("status") == "unsupported",
                 f"{request_id}: {field} unexpectedly became known")
        _require(envelope.get("reason") == "FIELD_NOT_IMPLEMENTED_BY_ADAPTER",
                 f"{request_id}: {field} unsupported reason changed")
        checks[field] = {"status": envelope.get("status"), "reason": envelope.get("reason")}
    return checks


class RecordedMcpClient:
    """Small line-framed MCP client with a compact, non-content wire audit."""

    def __init__(self, save: Path, output: Path):
        self.output = output
        self.queue: queue.Queue[dict[str, Any]] = queue.Queue()
        self.next_id = 0
        self.audit: list[dict[str, Any]] = []
        self.returncode: int | None = None
        stderr = (output / "mcp-stderr.txt").open("w", encoding="utf-8")
        self._stderr = stderr
        command = [
            sys.executable,
            str(ROOT / "tools" / "serve_information.py"),
            "--mission-game-data",
            "--mission-save", str(save),
            "--observer", COUNTRY,
            "--database", str(output / "information.sqlite3"),
        ]
        self.process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        self._reader = threading.Thread(target=self._read, name="recorded-mcp-reader", daemon=True)
        self._reader.start()
        init = self.rpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "mission-reward-recorded-acceptance", "version": "1"},
        })
        negotiated = init.get("protocolVersion") if isinstance(init, dict) else None
        _require(negotiated in {"2025-03-26", "2024-11-05"},
                 f"MCP server negotiated an unsupported protocol: {negotiated!r}")
        self.protocol = {"requested": "2025-03-26", "negotiated": negotiated}
        self.notification("notifications/initialized", {})

    def _read(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            try:
                value = json.loads(line)
                if isinstance(value, dict):
                    self.queue.put(value)
                else:
                    self.queue.put({"_invalid_json_value": value})
            except json.JSONDecodeError:
                self.queue.put({"_invalid_json_line": line[:512]})
        self.queue.put({"_eof": True})

    @staticmethod
    def _param_summary(method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method != "tools/call":
            return {"keys": sorted(params)}
        args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        summary: dict[str, Any] = {"tool": params.get("name"), "argument_keys": sorted(args)}
        if isinstance(args.get("request_id"), str):
            summary["request_id"] = args["request_id"]
        queries = args.get("queries")
        if isinstance(queries, list):
            summary["query_count"] = len(queries)
            summary["selectors"] = [
                {"topic": query.get("topic"), "fields": query.get("fields"),
                 "parameters": query.get("parameters", {})}
                for query in queries if isinstance(query, dict)
            ]
        return summary

    @staticmethod
    def _result_summary(method: str, result: dict[str, Any]) -> dict[str, Any]:
        if method == "initialize":
            return {"protocolVersion": result.get("protocolVersion"),
                    "serverInfo": result.get("serverInfo"),
                    "capability_keys": sorted((result.get("capabilities") or {}).keys())}
        if method == "tools/list":
            tools = result.get("tools") if isinstance(result.get("tools"), list) else []
            return {"tool_count": len(tools), "tool_names": [tool.get("name") for tool in tools if isinstance(tool, dict)]}
        return {"result_keys": sorted(result), "isError": result.get("isError", False),
                "content_count": len(result.get("content", [])) if isinstance(result.get("content"), list) else None,
                "content_sha256": _canonical_sha(result.get("content"))}

    def _send(self, message: dict[str, Any]) -> None:
        if self.process.stdin is None:
            raise RuntimeError("MCP stdin is closed")
        self.process.stdin.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
        self.process.stdin.flush()

    def notification(self, method: str, params: dict[str, Any]) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})
        self.audit.append({"kind": "notification", "method": method, "parameter_summary": self._param_summary(method, params)})

    def rpc(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.next_id += 1
        identifier = self.next_id
        self._send({"jsonrpc": "2.0", "id": identifier, "method": method, "params": params})
        response = self.queue.get(timeout=60)
        if response.get("_eof") or "_invalid_json_line" in response:
            raise RuntimeError(f"MCP server ended or emitted invalid JSON for {method}")
        if response.get("id") != identifier:
            raise RuntimeError(f"MCP response ID mismatch for {method}: {response.get('id')!r}")
        audit = {"kind": "request_response", "id": identifier, "method": method,
                 "parameter_summary": self._param_summary(method, params),
                 "response_error": response.get("error") is not None}
        if "error" in response:
            audit["error_code"] = response["error"].get("code") if isinstance(response["error"], dict) else None
            self.audit.append(audit)
            raise RuntimeError(f"MCP {method} failed: {response['error']}")
        result = response.get("result")
        if not isinstance(result, dict):
            self.audit.append(audit)
            raise RuntimeError(f"MCP {method} returned a non-object result")
        audit["result_summary"] = self._result_summary(method, result)
        self.audit.append(audit)
        return result

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = self.rpc("tools/call", {"name": name, "arguments": arguments})
        _require(result.get("isError") is not True, f"MCP tool {name} returned isError")
        content = result.get("content")
        _require(isinstance(content, list) and content and isinstance(content[0], dict),
                 f"MCP tool {name} returned no content")
        text = content[0].get("text")
        _require(isinstance(text, str), f"MCP tool {name} returned non-text content")
        value = json.loads(text)
        _require(isinstance(value, dict) and "error" not in value,
                 f"MCP tool {name} returned a business error: {value!r}")
        return value

    def close(self) -> None:
        if getattr(self, "process", None) is None:
            return
        try:
            if self.process.stdin is not None:
                self.process.stdin.close()
            self.process.wait(timeout=45)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
            raise
        finally:
            self.returncode = self.process.returncode
            self._reader.join(timeout=5)
            self._stderr.close()
        _require(self.returncode == 0, f"recorded MCP process exited with {self.returncode}")


def _query(fields: list[str], *, root_id: str | None = None, task_id: str | None = None) -> dict[str, Any]:
    parameters: dict[str, str] = {}
    if root_id is not None:
        parameters["root_id"] = root_id
    if task_id is not None:
        parameters["task_id"] = task_id
    return {"topic": "M04", "object": {"type": "country", "country": COUNTRY},
            "fields": list(fields), "parameters": parameters}


def _assert_discovery(discovery: dict[str, Any]) -> dict[str, Any]:
    context = discovery.get("context")
    _require(isinstance(context, dict) and context.get("mode") == "recorded", "discovery is not recorded")
    topics = discovery.get("topics")
    _require(isinstance(topics, list), "discovery topics are missing")
    m04 = next((topic for topic in topics if isinstance(topic, dict) and topic.get("topic_id") == "M04"), None)
    _require(isinstance(m04, dict), "M04 is absent from discovery")
    _require(m04.get("status") == "available", "M04 is not queryable in recorded mission mode")
    _require(m04.get("triggers") == ["query"], "recorded M04 unexpectedly advertises scheduling")
    fields = m04.get("fields")
    _require(isinstance(fields, dict), "M04 fields missing from discovery")
    for field in RULE_FIELDS:
        metadata = fields.get(field)
        _require(isinstance(metadata, dict), f"M04 discovery field missing: {field}")
        _require(metadata.get("coverage") == "partial", f"{field} discovery coverage is not partial")
        _require(metadata.get("declared_literal_effect_rules") is True,
                 f"{field} discovery does not declare literal-effect scope")
        _require(metadata.get("runtime_conditions_evaluated") is False,
                 f"{field} discovery overclaims condition evaluation")
        _require(metadata.get("actual_reward_status") == "unknown",
                 f"{field} discovery overclaims actual reward status")
    return {"topic_id": "M04", "status": m04.get("status"), "triggers": m04.get("triggers"),
            "field_coverage": {field: fields[field].get("coverage") for field in RULE_FIELDS}}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--save", type=Path,
                        default=user_data() / "save games" / SAVE_NAME,
                        help="fixed historical R70 save path")
    parser.add_argument("--output", type=Path, required=True,
                        help="new output directory; it must not already exist")
    args = parser.parse_args(argv)

    save_path = args.save.expanduser().resolve(strict=True)
    output = args.output.expanduser().resolve()
    _require(output.is_relative_to(ROOT_RESOLVED), "output directory must remain inside the workspace")
    if output.exists():
        raise ValueError(f"Refusing to overwrite existing output directory: {output}")
    output.mkdir(parents=True, exist_ok=False)
    _require(save_path.is_file(), f"save path is not a regular file: {save_path}")
    _require(save_path.stat().st_size <= MAX_SAVE_BYTES, "save exceeds the bounded streaming limit")

    report: dict[str, Any] = {
        "schema": "information_mission_reward_rules_recorded_acceptance_v1",
        "status": "failed",
        "mode": "recorded",
        "scope": {"country": COUNTRY, "topic": "M04", "fields": list(M04_FIELDS),
                  "source": "SavedMissionSnapshot", "query_only": True},
        "save_is_recorded": True,
        "not_a_live_state_fallback": True,
        "native_query_invoked": False,
        "checks": {},
        "limitations": [
            "The save is historical and has no live session or world identity.",
            "Literal effect ASTs are not condition-evaluated and do not prove scope, execution, or applied reward state.",
            "This acceptance does not create subscriptions, schedule periodic reads, start a game, use RPM, or call REA.",
        ],
    }
    client: RecordedMcpClient | None = None
    close_error: Exception | None = None
    try:
        snapshot = SavedMissionSnapshot(save_path, COUNTRY, expected_sha256=EXPECTED_SAVE_SHA256)
        save_data = snapshot.as_dict()
        _require(save_data.get("mode") == "recorded" and save_data.get("country") == COUNTRY,
                 "save snapshot identity is not recorded FRA")
        _require(save_data.get("file", {}).get("sha256") == EXPECTED_SAVE_SHA256,
                 "fixed R70 save SHA mismatch")
        save_version = save_data.get("version")
        _require(isinstance(save_version, str) and save_version.startswith(GAME_VERSION),
                 f"unsupported recorded save version: {save_version!r}")
        mission_slots = save_data.get("country_missions", {}).get("mission_slots")
        _require(isinstance(mission_slots, list) and mission_slots, "recorded country mission slots missing")
        root_ids = [root_id for slot in mission_slots for root_id in slot.get("root_ids", [])]
        _require(len(root_ids) == len(set(root_ids)) == 18, "expected 18 unique saved FRA mission roots")

        # This is the independent currentMissionDefinitionIndex used by the
        # checker.  No production reward projection is imported or called.
        definition_index = MissionDefinitionIndex()
        definition_context = definition_index.context()
        _require(definition_context.get("status") == "ready", "current mission definition index is not ready")
        _require(definition_context.get("game_version") == GAME_VERSION,
                 "current mission definition index version mismatch")
        selected_roots = definition_index.roots(root_ids)
        selected_task_count = sum(len(root.get("tasks", [])) for root in selected_roots)
        _require(selected_task_count == 61, f"expected 61 tasks in saved roots, got {selected_task_count}")

        save_fingerprint = {
            "path": str(save_path),
            "sha256": save_data["file"]["sha256"],
            "bytes": save_data["file"]["size_bytes"],
            "mtime_ns": save_data["file"]["mtime_ns"],
            "date": save_data.get("date"),
            "version": save_version,
            "country": COUNTRY,
            "mode": save_data.get("mode"),
            "root_ids": root_ids,
            "slot_count": len(mission_slots),
            "completed_missions_present": save_data.get("completed_missions", {}).get("present"),
            "scan": "SavedMissionSnapshot bounded streaming parse",
        }
        definition_fingerprint = {
            "name": "currentMissionDefinitionIndex",
            "status": definition_context.get("status"),
            "game_version": definition_context.get("game_version"),
            "configuration_sha256": definition_context.get("configuration_sha256"),
            "definitions_sha256": definition_context.get("definitions_sha256"),
            "root_count": definition_context.get("root_count"),
            "selected_root_count": len(selected_roots),
            "selected_task_count": selected_task_count,
            "definition_files": [
                {key: item.get(key) for key in ("relative", "source_kind", "source", "sha256", "size")}
                for item in definition_context.get("definition_files", [])
            ],
        }
        source_paths = [
            ROOT / "bridge/information/saved_missions.py",
            ROOT / "bridge/information/mission_definitions.py",
            ROOT / "bridge/information/mission_reward_rules.py",
            ROOT / "bridge/information/missions.py",
            ROOT / "tools/serve_information.py",
            Path(__file__).resolve(),
        ]
        source_fingerprints = []
        for path in source_paths:
            digest, size = _sha256_file(path, max_bytes=MAX_ARTIFACT_BYTES)
            source_fingerprints.append({"path": path.relative_to(ROOT_RESOLVED).as_posix(),
                                        "sha256": digest, "bytes": size})
        fingerprints = {"save": save_fingerprint, "definitions": definition_fingerprint,
                        "definitions_context_sha256": _canonical_sha(definition_context),
                        "source_files": source_fingerprints}
        _write_json(output / "fingerprints.json", fingerprints)

        expected_specs = {
            "full": {field: _expected_occurrences(definition_index, root_ids, field) for field in RULE_FIELDS},
            "single_task_casus": {
                field: _expected_occurrences(definition_index, root_ids, field,
                                             root_id="french_missions_5_normal",
                                             task_id="fra_ducal_lands_avignon")
                for field in RULE_FIELDS
            },
            "single_task_trade": {
                field: _expected_occurrences(definition_index, root_ids, field,
                                             root_id="french_missions_5_continuation_normal_1",
                                             task_id="fra_restore_signoria")
                for field in RULE_FIELDS
            },
            "single_root": {
                field: _expected_occurrences(definition_index, root_ids, field,
                                             root_id="french_missions_5_normal")
                for field in RULE_FIELDS
            },
        }
        walker_check = _condition_walker_self_check()
        _write_json(output / "ast-expected.json", {
            "schema": "information_mission_reward_rules_independent_ast_expectation_v1",
            "source": "currentMissionDefinitionIndex",
            "save_sha256": EXPECTED_SAVE_SHA256,
            "root_ids": root_ids,
            "task_count": selected_task_count,
            "fields": {field: sorted(commands) for field, commands in FIELD_COMMAND_KEYS.items()},
            "unsupported_command_spellings": {
                field: sorted(commands) for field, commands in UNSUPPORTED_FIELD_COMMAND_KEYS.items()
            },
            "queries": expected_specs,
            "condition_block_keys": sorted(CONDITION_BLOCK_KEYS),
            "condition_walker_self_check": walker_check,
            "conditions_evaluated": False,
            "effects_applied": False,
        })
        _write_json(output / "fixture-inputs.json", {
            "schema": "information_mission_reward_rules_recorded_fixture_inputs_v1",
            "fixture_kind": "recorded_fra_definition_input",
            "live_state": False,
            "task_membership_source": "definitions_for_captured_roots",
            "loaded_task_membership_verified": False,
            "save": {
                "sha256": EXPECTED_SAVE_SHA256,
                "country": COUNTRY,
                "mode": save_data.get("mode"),
                "version": save_version,
                "date": save_data.get("date"),
                "root_ids": root_ids,
            },
            "country_missions": {"mission_slots": mission_slots},
            "selected_roots": selected_roots,
            "definition_context": definition_context,
            "expected_occurrence_tuples": {
                name: {field: spec[field]["occurrence_tuples"]
                       for field in RULE_FIELDS}
                for name, spec in expected_specs.items()
            },
            "expected_condition_contexts": {
                name: {field: spec[field]["condition_contexts"]
                       for field in RULE_FIELDS}
                for name, spec in expected_specs.items()
            },
        })
        report["fingerprints"] = fingerprints
        report["expected"] = {
            name: {field: {
                "selected_task_count": spec[field]["selected_task_count"],
                "occurrence_count": len(spec[field]["occurrences"]),
                "condition_context_count": spec[field]["condition_context_count"],
            } for field in RULE_FIELDS} for name, spec in expected_specs.items()
        }
        report["checks"]["independent_condition_boundary"] = walker_check
        report["checks"]["recorded_save_and_definition_scope"] = True

        client = RecordedMcpClient(save_path, output)
        tools_list = client.rpc("tools/list", {})
        tool_names = {tool.get("name") for tool in tools_list.get("tools", []) if isinstance(tool, dict)}
        _require({"information_discover", "information_query"}.issubset(tool_names),
                 "MCP tool discovery lacks recorded information tools")
        discover = client.call_tool("information_discover", {})
        _write_json(output / "discovery.json", discover)
        report["checks"]["mcp_discovery_recorded_query_only"] = _assert_discovery(discover)

        save_date = save_data.get("date")
        _require(isinstance(save_date, str), "recorded save date is missing")
        full_query = _query(list(M04_FIELDS))
        full = client.call_tool("information_query", {"request_id": "mission-reward-recorded-full", "queries": [full_query]})
        _write_json(output / "manual-result.json", full)
        report["checks"]["full_root_effect_occurrences"] = _assert_m04_result(
            full, "mission-reward-recorded-full", save_date, expected_specs["full"])

        mixed_query = _query(list(M04_FIELDS) + list(UNSUPPORTED_M04_FIELDS))
        mixed = client.call_tool("information_query", {
            "request_id": "mission-reward-recorded-mixed", "queries": [mixed_query]})
        _write_json(output / "mixed-unimplemented-result.json", mixed)
        mixed_check = _assert_m04_result(
            mixed, "mission-reward-recorded-mixed", save_date, expected_specs["full"])
        mixed_check["unsupported_fields"] = _assert_mixed_unsupported(
            mixed, "mission-reward-recorded-mixed")
        report["checks"]["mixed_unimplemented_fields_remain_unsupported"] = mixed_check

        task_results = []
        for request_id, key in (
            ("mission-reward-recorded-task-casus", "single_task_casus"),
            ("mission-reward-recorded-task-trade", "single_task_trade"),
        ):
            spec = expected_specs[key]
            first_field = next(field for field in RULE_FIELDS if spec[field]["occurrences"])
            row = spec[first_field]["occurrences"][0]
            query = _query(list(M04_FIELDS), root_id=row["root_id"], task_id=row["task_id"])
            result = client.call_tool("information_query", {"request_id": request_id, "queries": [query]})
            task_results.append({"request_id": request_id, "query": query, "result": result})
            _assert_m04_result(result, request_id, save_date, spec)
        _write_json(output / "single-task-results.json", task_results)
        report["checks"]["single_task_effect_occurrences"] = {
            "queries": len(task_results), "all_match": True,
            "selectors": [{"root_id": row["query"]["parameters"]["root_id"],
                            "task_id": row["query"]["parameters"]["task_id"]} for row in task_results],
        }

        root_query = _query(list(M04_FIELDS), root_id="french_missions_5_normal")
        root_result = client.call_tool("information_query", {
            "request_id": "mission-reward-recorded-root", "queries": [root_query]})
        _write_json(output / "single-root-result.json", root_result)
        report["checks"]["single_root_effect_occurrences"] = _assert_m04_result(
            root_result, "mission-reward-recorded-root", save_date, expected_specs["single_root"])
        report["checks"]["legacy_rewards_compatible"] = True
        report["checks"]["recorded_queries_only"] = True
        report["status"] = "passed"
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        if client is not None:
            try:
                client.close()
            except Exception as exc:
                close_error = exc
                report["cleanup_error"] = {"type": type(exc).__name__, "message": str(exc)}
                report["status"] = "failed"
            report["process"] = {"returncode": client.returncode, "closed": close_error is None,
                                  "wire_message_count": len(client.audit)}
            try:
                _write_json(output / "mcp-wire-audit.json", {
                    "schema": "information_mcp_compact_wire_audit_v1",
                    "protocol": getattr(client, "protocol", None),
                    "message_count": len(client.audit),
                    "messages": client.audit,
                    "content_policy": "request and response summaries only; full public results are in separate files",
                })
            except Exception as exc:
                report["wire_audit_error"] = {"type": type(exc).__name__, "message": str(exc)}
                report["status"] = "failed"
        report_artifact = {
            "path": (output / "report.json").relative_to(ROOT_RESOLVED).as_posix(),
            "status": report.get("status"),
            "checks": report.get("checks", {}),
        }
        # report.json is the final artifact; it is written directly so its own
        # hash can be supplied by the parent after the process exits.
        report["artifacts"] = {"report": report_artifact}
        _write_json(output / "report.json", report)
        if close_error is not None and "error" not in report:
            raise close_error

    print(json.dumps({"status": report["status"], "output": str(output),
                      "save_sha256": EXPECTED_SAVE_SHA256,
                      "selected_roots": len(root_ids), "selected_tasks": selected_task_count},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
