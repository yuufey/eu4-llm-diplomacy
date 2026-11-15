"""Project a bounded, partial view of loaded mission trigger trees."""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import json
from typing import Any
from .mission_trigger_selection import select_tasks

from .mission_trigger_memory import (
    AND_EVALUATE_RVA,
    EXPLORER_EVALUATE_RVA,
    GALLEY_EVALUATE_RVA,
    NOR_EVALUATE_RVA,
    OR_EVALUATE_RVA,
    SAILORS_EVALUATE_RVA,
    PROVINCE_SCOPE_EVALUATE_RVA,
    PROVINCE_OWNED_EVALUATE_RVA,
    PROVINCE_CONTROLLED_EVALUATE_RVA,
    PROVINCE_HELD_EVALUATE_RVA,
    IF_EVALUATE_RVA,
    ARMY_RATIO_EVALUATE_RVA,
    UNITY_EVALUATE_RVA,
    COUNTRY_MODIFIER_EVALUATE_RVA,
    GEOGRAPHIC_EVALUATE_RVA,
    DLC_EVALUATE_RVA,
    COUNT_EVALUATE_RVA,
    STORED_BOOLEAN_EVALUATE_RVA,
    BOOLEAN_MATCH_EVALUATE_RVA,
    PROVINCE_ID_EVALUATE_RVA,
)
from .mission_trigger_profile import PROFILE_SHA256


MAX_CAPTURED_TASKS = 4096
MAX_TREE_DEPTH = 32
MAX_TOTAL_NODES = 2048
MAX_PUBLIC_JSON_BYTES = 512 * 1024
SUPPORTED_GAME_VERSION = "1.37.4"

_LOGIC_METHODS = {
    "and": AND_EVALUATE_RVA,
    "or": OR_EVALUATE_RVA,
    "nor": NOR_EVALUATE_RVA,
}
_SCALAR_METHODS = {
    EXPLORER_EVALUATE_RVA,
    GALLEY_EVALUATE_RVA,
    SAILORS_EVALUATE_RVA,
    PROVINCE_OWNED_EVALUATE_RVA,
    PROVINCE_CONTROLLED_EVALUATE_RVA,
    PROVINCE_HELD_EVALUATE_RVA,
    ARMY_RATIO_EVALUATE_RVA,
    UNITY_EVALUATE_RVA,
    COUNTRY_MODIFIER_EVALUATE_RVA,
    DLC_EVALUATE_RVA,
    STORED_BOOLEAN_EVALUATE_RVA,
    PROVINCE_ID_EVALUATE_RVA,
}
_KINDS = {"and", "or", "nor", "scope", "geographic", "if", "leaf", "unsupported",
          "count", "boolean_match"}
_COUNTRY_METHODS = {SAILORS_EVALUATE_RVA, EXPLORER_EVALUATE_RVA, GALLEY_EVALUATE_RVA,
                    ARMY_RATIO_EVALUATE_RVA, UNITY_EVALUATE_RVA, COUNTRY_MODIFIER_EVALUATE_RVA}
_MISSING = object()


def gap(reason: str) -> dict[str, str]:
    return {"status": "unknown", "reason": reason}


def _strict_int(value: Any) -> bool:
    return type(value) is int


def _valid_pair(row: Any) -> tuple[str, str] | None:
    if not isinstance(row, Mapping):
        return None
    root_id, task_id = row.get("root_id"), row.get("task_id")
    if (not isinstance(root_id, str) or not root_id
            or not isinstance(task_id, str) or not task_id
            or len(root_id) > 1024 or len(task_id) > 1024):
        return None
    return root_id, task_id


def _valid_address(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    va = value.get("va")
    rva = value.get("rva", _MISSING)
    identity = value.get("rva_identity")
    if not isinstance(va, str) or not va.startswith("0x"):
        return False
    try:
        if int(va[2:], 16) < 0x10000:
            return False
    except (TypeError, ValueError):
        return False
    if rva is not None:
        if not isinstance(rva, str) or not rva.startswith("0x"):
            return False
        try:
            int(rva[2:], 16)
        except (TypeError, ValueError):
            return False
    if identity not in {
        "contract_module_rva", "module_relative_candidate", "runtime_va_or_heap",
        "not_applicable",
    }:
        return False
    return rva is not _MISSING


def _evaluation(node: Mapping[str, Any]) -> tuple[str, bool | None] | None:
    value = node.get("evaluation")
    if not isinstance(value, Mapping):
        return None
    status, satisfied = value.get("status"), value.get("satisfied", _MISSING)
    if status == "known":
        if type(satisfied) is not bool:
            return None
    elif status == "unknown":
        if satisfied is not None:
            return None
    else:
        return None
    if "reason" in value and not isinstance(value["reason"], str):
        return None
    return status, satisfied


def _combine(kind: str, child_values: list[bool | None]) -> bool | None:
    if kind == "and":
        if any(value is False for value in child_values):
            return False
        if all(value is True for value in child_values):
            return True
        return None
    if kind == "or":
        if any(value is True for value in child_values):
            return True
        if all(value is False for value in child_values):
            return False
        return None
    if kind == "nor":
        if any(value is True for value in child_values):
            return False
        if all(value is False for value in child_values):
            return True
        return None
    raise ValueError("MISSION_TRIGGER_LOGIC_KIND_INVALID")


def _validate_tree(node: Any, *, depth: int, counter: list[int], is_root: bool = False,
                   allow_geographic_body: bool = False, country_scope: str = "FRA",
                   province_scope: bool = False, allow_count_filter: bool = False,
                   ) -> bool:
    """Validate memory output and recompute every logical node from children."""
    if depth > MAX_TREE_DEPTH or not isinstance(node, Mapping):
        return False
    counter[0] += 1
    if counter[0] > MAX_TOTAL_NODES:
        return False

    kind = node.get("kind")
    if kind not in _KINDS:
        return False
    token = node.get("token", _MISSING)
    if token is _MISSING or (token is not None and not _strict_int(token)):
        return False
    if token is not None and not 0 <= token <= 0xFFFFFFFF:
        return False
    method_rva = node.get("method_rva", _MISSING)
    if (not _strict_int(method_rva) or not 0 <= method_rva < 0x40000000
            or not _valid_address(node.get("native_pointer"))):
        return False
    evaluation = _evaluation(node)
    if evaluation is None:
        return False
    if "condition_name" in node and not isinstance(node["condition_name"], str):
        return False
    if "labeltoken" in node and node["labeltoken"] is not None and not _strict_int(node["labeltoken"]):
        return False

    if kind == 'boolean_match':
        body, expected = node.get('body'), node.get('expected_satisfied')
        if (is_root or method_rva != BOOLEAN_MATCH_EVALUATE_RVA
                or type(expected) is not bool or 'children' in node
                or not isinstance(body, Mapping) or body.get('kind') != 'and'
                or body.get('method_rva') != AND_EVALUATE_RVA
                or not _validate_tree(body, depth=depth + 1, counter=counter,
                                      country_scope=country_scope, province_scope=province_scope)):
            return False
        value = body['evaluation']['satisfied']
        result = value == expected if value is not None else None
        return evaluation == (('known', result) if result is not None else ('unknown', None))

    if kind == 'geographic':
        scope, members = node.get('scope'), node.get('members')
        if (is_root or method_rva != GEOGRAPHIC_EVALUATE_RVA or 'children' in node
                or not isinstance(scope, Mapping) or scope.get('kind') != 'province_set'
                or not isinstance(scope.get('name'), str) or not 0 < len(scope['name']) <= 256
                or not scope['name'].isascii() or scope.get('quantifier') not in {'all', 'any'}
                or type(scope.get('definition_found')) is not bool
                or scope.get('domain_complete') is not scope['definition_found']
                or not isinstance(members, list) or len(members) > 64):
            return False
        if scope['definition_found'] is False:
            return not members and evaluation == ('known', False)
        seen, values = set(), []
        for member in members:
            if not isinstance(member, Mapping):
                return False
            province = member.get('province_id')
            tree = member.get('tree')
            if (type(province) is not int or not 1 <= province < 65536 or province in seen
                    or not isinstance(tree, Mapping) or tree.get('kind') not in {'and', 'unsupported'}
                    or tree.get('method_rva') != GEOGRAPHIC_EVALUATE_RVA):
                return False
            seen.add(province)
            if not _validate_tree(tree, depth=depth + 1, counter=counter,
                                  allow_geographic_body=True, country_scope=country_scope,
                                  province_scope=True):
                return False
            values.append(tree['evaluation']['satisfied'])
        result = _combine('and' if scope['quantifier'] == 'all' else 'or', values)
        expected = ('known', result) if result is not None else ('unknown', None)
        return evaluation == expected

    if kind == "count":
        if (is_root or method_rva != COUNT_EVALUATE_RVA
                or country_scope != "FRA" or province_scope):
            return False
        expected_mode = {0x2BF9: "owned", 0x37FC: "non_sovereign_subjects"}.get(token)
        scope, metric = node.get("scope"), node.get("metric")
        filter_node, samples = node.get("filter"), node.get("samples")
        if (expected_mode is None or not isinstance(scope, Mapping)
                or set(scope) != {"kind", "country", "mode"}
                or scope.get("kind") != "owned_provinces"
                or scope.get("country") != "FRA" or scope.get("mode") != expected_mode
                or not isinstance(metric, Mapping)
                or set(metric) != {"threshold", "domain_count", "lower_bound", "upper_bound",
                                   "sampled_count", "fully_evaluated"}
                or not isinstance(samples, list)):
            return False

        threshold = metric.get("threshold")
        domain_count = metric.get("domain_count")
        lower_bound, upper_bound = metric.get("lower_bound"), metric.get("upper_bound")
        sampled_count, fully_evaluated = (metric.get("sampled_count"),
                                          metric.get("fully_evaluated"))
        if (not _strict_int(threshold) or not -(1 << 31) <= threshold < (1 << 31)
                or not _strict_int(domain_count) or not 0 <= domain_count <= 256
                or not _strict_int(lower_bound) or not 0 <= lower_bound <= domain_count
                or not _strict_int(upper_bound) or not 0 <= upper_bound <= domain_count
                or not _strict_int(sampled_count) or not 0 <= sampled_count <= 4
                or sampled_count != len(samples) or sampled_count > domain_count
                or type(fully_evaluated) is not bool):
            return False

        if (not isinstance(filter_node, Mapping) or filter_node.get("kind") != "and"
                or filter_node.get("method_rva") != COUNT_EVALUATE_RVA
                or not _validate_tree(
                    filter_node, depth=depth + 1, counter=counter,
                    country_scope="__unbound__", province_scope=True,
                    allow_count_filter=True,
                )):
            return False
        filter_evaluation = _evaluation(filter_node)
        if filter_evaluation is None:
            return False

        true_samples = false_samples = 0
        for sample in samples:
            if (not isinstance(sample, Mapping)
                    or set(sample) != {"province_id", "evaluation"}):
                return False
            province_id = sample.get("province_id")
            sample_evaluation = sample.get("evaluation")
            parsed_evaluation = (_evaluation({"evaluation": sample_evaluation})
                                 if isinstance(sample_evaluation, Mapping) else None)
            if parsed_evaluation is None:
                return False
            if province_id is None:
                if parsed_evaluation[0] == "known":
                    return False
            elif (not _strict_int(province_id) or not 1 <= province_id < 65536):
                return False
            if parsed_evaluation == ("known", True):
                true_samples += 1
            elif parsed_evaluation == ("known", False):
                false_samples += 1

        if filter_evaluation[0] == "known":
            if filter_evaluation[1] is True:
                expected_bounds = (domain_count, domain_count, 0, True)
            else:
                expected_bounds = (0, 0, 0, True)
        else:
            expected_bounds = (
                true_samples,
                domain_count - false_samples,
                sampled_count,
                sampled_count == domain_count,
            )
        if (lower_bound, upper_bound, sampled_count, fully_evaluated) != expected_bounds:
            return False

        if lower_bound > 0 and lower_bound >= threshold:
            counted_value: bool | None = True
        elif upper_bound == 0 or upper_bound < threshold:
            counted_value = False
        else:
            counted_value = None
        expected_evaluation = (("known", counted_value) if counted_value is not None
                               else ("unknown", None))
        return evaluation == expected_evaluation

    if kind == "if":
        if is_root or method_rva != IF_EVALUATE_RVA or "children" in node:
            return False
        branches = [node.get(key) for key in ("limit", "then", "else")]
        if (any(not isinstance(branch, Mapping) for branch in branches)
                or branches[0].get("kind") != "and" or branches[1].get("kind") != "and"
                or branches[2].get("kind") not in {"and", "if"}):
            return False
        for branch in branches:
            if not _validate_tree(branch, depth=depth + 1, counter=counter,
                                  country_scope=country_scope, province_scope=province_scope):
                return False
        limit, positive, negative = [branch["evaluation"]["satisfied"] for branch in branches]
        selection = "then" if limit is True else "else" if limit is False else "unknown"
        if node.get("selected_branch") != selection:
            return False
        if limit is True:
            recomputed = positive
        elif limit is False:
            recomputed = negative
        elif positive is not None and positive == negative:
            recomputed = positive
        else:
            recomputed = None
        expected = ("known", recomputed) if recomputed is not None else ("unknown", None)
        return evaluation == expected

    if kind in {"and", "or", "nor", "scope"}:
        child_country, child_province = country_scope, province_scope
        if kind == "scope":
            scope = node.get("scope")
            if method_rva != PROVINCE_SCOPE_EVALUATE_RVA or not isinstance(scope, Mapping):
                return False
            if scope.get('kind') == 'province':
                if (scope.get('selection') not in {'literal', 'capital'}
                        or (scope.get('selection') == 'capital' and province_scope)):
                    return False
                if type(scope.get('province_id')) is not int or not 1 <= scope['province_id'] < 65536:
                    return False
                child_province = True
            elif scope.get('kind') == 'country':
                if scope.get('selection') not in {'literal', 'emperor'}:
                    return False
                tag = scope.get('country')
                if (not isinstance(tag, str) or len(tag) != 3 or not tag.isascii()
                        or not all('A' <= char <= 'Z' or '0' <= char <= '9' for char in tag)):
                    return False
                child_country, child_province = tag, False
            else:
                return False
        elif method_rva != _LOGIC_METHODS[kind] and not (
                kind == 'and' and allow_geographic_body and method_rva == GEOGRAPHIC_EVALUATE_RVA
        ) and not (
                kind == 'and' and allow_count_filter and method_rva == COUNT_EVALUATE_RVA
        ):
            return False
        if allow_count_filter and (kind != "and" or method_rva != COUNT_EVALUATE_RVA):
            return False
        if not isinstance(node.get("children"), list):
            return False
        if is_root and kind != "and":
            return False
        child_values: list[bool | None] = []
        for child in node["children"]:
            if not _validate_tree(child, depth=depth + 1, counter=counter,
                                  country_scope=child_country, province_scope=child_province):
                return False
            child_evaluation = _evaluation(child)
            if child_evaluation is None:
                return False
            child_values.append(child_evaluation[1])
        recomputed = _combine("and" if kind == "scope" else kind, child_values)
        expected = ("known", recomputed) if recomputed is not None else ("unknown", None)
        if evaluation != expected:
            return False
        return True

    if is_root or "children" in node:
        return False
    if kind == "leaf":
        if method_rva not in _SCALAR_METHODS:
            return False
        metric = node.get("metric", _MISSING)
        if metric is not _MISSING and not isinstance(metric, Mapping):
            return False
        if method_rva == PROVINCE_ID_EVALUATE_RVA:
            if not isinstance(metric, Mapping) or set(metric) != {
                    'province_id', 'required_province_id', 'dynamic_selector'}:
                return False
            actual, required, dynamic = (metric['province_id'], metric['required_province_id'],
                                         metric['dynamic_selector'])
            if (not _strict_int(required) or not -(1 << 31) <= required < (1 << 31)
                    or type(dynamic) is not bool
                    or (actual is not None and (not _strict_int(actual) or not 1 <= actual < 65536))):
                return False
            result = (None if province_scope else False) if actual is None else (
                None if dynamic else actual == required)
            if evaluation != (('known', result) if result is not None else ('unknown', None)):
                return False
        if method_rva in _COUNTRY_METHODS and (country_scope != 'FRA' or province_scope):
            if evaluation[0] != 'unknown' or metric is not _MISSING:
                return False
    elif evaluation[0] != "unknown":
        return False
    return True


def _normalized_rows(captured: Any, prerequisites: Any, selector=None) -> list[tuple[tuple[str, str], Mapping[str, Any]]]:
    if not isinstance(captured, Mapping) or not isinstance(prerequisites, Mapping):
        raise ValueError("MISSION_TRIGGER_TASKS_INVALID")
    rows, expected = captured.get("tasks"), prerequisites.get("tasks")
    if (not isinstance(rows, list) or not isinstance(expected, list)
            or len(expected) > MAX_CAPTURED_TASKS
            or captured.get('task_selector') != selector):
        raise ValueError("MISSION_TRIGGER_TASKS_INCOMPLETE")
    expected = select_tasks(expected, selector)
    if len(rows) != len(expected):
        raise ValueError("MISSION_TRIGGER_TASKS_INCOMPLETE")
    result = []
    node_counter = [0]
    for row, task in zip(rows, expected):
        pair, expected_pair = _valid_pair(row), _valid_pair(task)
        if pair is None or pair != expected_pair:
            raise ValueError("MISSION_TRIGGER_TASK_MISMATCH")
        tree = row.get("tree")
        if not _validate_tree(tree, depth=0, counter=node_counter, is_root=True):
            raise ValueError("MISSION_TRIGGER_TREE_INVALID")
        result.append((pair, row))
    return result


def normalize_triggers(report: Any, prerequisites: Any) -> dict[str, Any]:
    """Accept only double-pass, profile-pinned trigger trees bound to loaded tasks."""
    try:
        if not isinstance(report, Mapping) or not isinstance(prerequisites, Mapping):
            return gap("MISSION_TRIGGERS_NOT_VERIFIED")
        request = report.get("request")
        doublepass = report.get("doublepass")
        cleanup = report.get("cleanup")
        handle_close = cleanup.get("handle_close") if isinstance(cleanup, Mapping) else None
        captured = report.get("mission_triggers")
        if (not isinstance(request, Mapping) or request.get("include_triggers") is not True
                or report.get("trigger_profile_sha256") != PROFILE_SHA256
                or not isinstance(doublepass, Mapping)
                or doublepass.get("trigger_consistent") is not True
                or not isinstance(handle_close, Mapping)
                or handle_close.get("closed") is not True
                or not isinstance(captured, Mapping)
                or captured.get("status") != "observed"
                or captured.get("complete") is not True
                or prerequisites.get("status") != "known"):
            return gap("MISSION_TRIGGERS_NOT_VERIFIED")
        selector = request.get('trigger_selector')
        rows = _normalized_rows(captured, prerequisites, selector)
        tasks = [
            {"root_id": pair[0], "task_id": pair[1], "tree": deepcopy(row["tree"])}
            for pair, row in rows
        ]
        return {
            "status": "known",
            "tasks": tasks,
            "profile_sha256": PROFILE_SHA256,
            "loaded_trigger_binding_verified": True,
            "task_selector": deepcopy(selector),
        }
    except Exception as exc:
        reason = str(exc)
        if not reason.startswith("MISSION_TRIGGER_"):
            reason = "MISSION_TRIGGER_INPUT_INVALID"
        return gap(reason)


class _OutputBudgetExceeded(ValueError):
    pass


_SENSITIVE_PUBLIC_KEYS = {
    "_compare", "method", "method_address", "method_rva", "native_pointer",
    "head_address", "head_raw_hex", "rawreads", "raw_reads",
}


def _copy_json_value(value: Any, budget: list[int], *, strip_native_fields: bool = False,
                     depth: int = 0) -> Any:
    """Copy JSON primitives while stopping before a public payload can grow large."""
    if depth > 64:
        raise _OutputBudgetExceeded("public_value_depth_exceeded")
    if value is None or type(value) is bool:
        budget[0] += 5
        return value
    if type(value) is int:
        if value.bit_length() > 4096:
            raise _OutputBudgetExceeded("integer_too_large")
        budget[0] += max(1, len(str(value)))
        return value
    if type(value) is float:
        if not (value == value and value not in (float("inf"), float("-inf"))):
            raise _OutputBudgetExceeded("non_finite_number")
        budget[0] += 24
        return value
    if isinstance(value, str):
        if len(value) > MAX_PUBLIC_JSON_BYTES:
            raise _OutputBudgetExceeded("public_payload_budget_exceeded")
        budget[0] += len(value.encode("utf-8")) + 2
        if budget[0] > MAX_PUBLIC_JSON_BYTES:
            raise _OutputBudgetExceeded("public_payload_budget_exceeded")
        return value
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > MAX_PUBLIC_JSON_BYTES:
                raise _OutputBudgetExceeded("non_string_object_key")
            if strip_native_fields and key.casefold().replace("-", "_") in _SENSITIVE_PUBLIC_KEYS:
                continue
            budget[0] += len(key.encode("utf-8")) + 3
            if budget[0] > MAX_PUBLIC_JSON_BYTES:
                raise _OutputBudgetExceeded("public_payload_budget_exceeded")
            result[key] = _copy_json_value(child, budget, strip_native_fields=strip_native_fields,
                                           depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        result = []
        for child in value:
            budget[0] += 1
            if budget[0] > MAX_PUBLIC_JSON_BYTES:
                raise _OutputBudgetExceeded("public_payload_budget_exceeded")
            result.append(_copy_json_value(child, budget, strip_native_fields=strip_native_fields,
                                           depth=depth + 1))
        return result
    raise _OutputBudgetExceeded("non_json_public_value")


def _public_tree(node: Mapping[str, Any], budget: list[int], *, depth: int = 0) -> dict[str, Any]:
    if depth > MAX_TREE_DEPTH:
        raise _OutputBudgetExceeded("tree_depth_exceeded")
    result: dict[str, Any] = {
        "kind": node["kind"],
        "token": node["token"],
        "evaluation": _copy_json_value(node["evaluation"], budget),
    }
    for key in ("labeltoken", "condition_name", "metric", "scope"):
        if key in node:
            result[key] = _copy_json_value(
                node[key], budget, strip_native_fields=(key in {"metric", "scope"}),
            )
    if node["kind"] in {"and", "or", "nor", "scope"}:
        result["children"] = [
            _public_tree(child, budget, depth=depth + 1)
            for child in node["children"]
        ]
    elif node["kind"] == "if":
        result["selected_branch"] = node["selected_branch"]
        for role in ("limit", "then", "else"):
            result[role] = _public_tree(node[role], budget, depth=depth + 1)
    elif node['kind'] == 'geographic':
        result['members'] = [{'province_id': member['province_id'],
                              'tree': _public_tree(member['tree'], budget, depth=depth + 1)}
                             for member in node['members']]
    elif node['kind'] == 'boolean_match':
        result['expected_satisfied'] = node['expected_satisfied']
        result['body'] = _public_tree(node['body'], budget, depth=depth + 1)
    elif node["kind"] == "count":
        result["filter"] = _public_tree(node["filter"], budget, depth=depth + 1)
        result["samples"] = _copy_json_value(
            node["samples"], budget, strip_native_fields=True,
        )
    return result


def _pair_index(records: Any, *, require_conditions: bool) -> dict[tuple[str, str], Mapping[str, Any]]:
    if not isinstance(records, list) or len(records) > MAX_CAPTURED_TASKS:
        raise ValueError("MISSION_TRIGGER_TASKS_INVALID")
    indexed: dict[tuple[str, str], Mapping[str, Any]] = {}
    for row in records:
        pair = _valid_pair(row)
        if pair is None or pair in indexed:
            raise ValueError("MISSION_TRIGGER_TASKS_INVALID")
        if not isinstance(row, Mapping):
            raise ValueError("MISSION_TRIGGER_TASKS_INVALID")
        if require_conditions and (
                type(row.get("task_completed")) is not bool
                or type(row.get("prerequisites_satisfied")) is not bool):
            raise ValueError("MISSION_CONDITIONS_INVALID")
        indexed[pair] = row
    return indexed


def _count_leaves(node: Mapping[str, Any]) -> tuple[int, int, int, int]:
    if node["kind"] in {"leaf", "unsupported", "count"}:
        evaluation = node["evaluation"]
        if evaluation["status"] == "unknown":
            return 0, 0, 0, 1
        if evaluation["satisfied"] is True:
            return 1, 1, 0, 0
        return 1, 0, 1, 0
    totals = [0, 0, 0, 0]
    if node['kind'] == 'boolean_match':
        branches = [node['body']]
    elif node['kind'] == 'geographic':
        branches = [member['tree'] for member in node['members']]
    else:
        branches = ([node[role] for role in ("limit", "then", "else")]
                    if node["kind"] == "if" else node["children"])
    for child in branches:
        child_counts = _count_leaves(child)
        for index, value in enumerate(child_counts):
            totals[index] += value
    return tuple(totals)


def project_progress(state: Any, entries: Any, game_version: Any) -> dict[str, Any]:
    """Project selected loaded tasks with partial native trigger trees and checks."""
    if game_version != SUPPORTED_GAME_VERSION:
        return gap("MISSION_TRIGGER_VERSION_UNSUPPORTED")
    if entries is None:
        return gap("LOADED_TASK_MEMBERSHIP_REQUIRED")
    if not isinstance(entries, list):
        return gap("LOADED_TASK_MEMBERSHIP_INVALID")
    if not isinstance(state, Mapping):
        return gap("MISSION_TRIGGER_STATE_INVALID")

    captured = state.get("mission_triggers")
    if (not isinstance(captured, Mapping) or captured.get("status") != "known"
            or captured.get("loaded_trigger_binding_verified") is not True
            or captured.get("profile_sha256") != PROFILE_SHA256):
        reason = captured.get("reason") if isinstance(captured, Mapping) else None
        return gap(reason if isinstance(reason, str) else "MISSION_TRIGGER_CAPTURE_UNVERIFIED")
    try:
        trigger_by_pair = _pair_index(captured.get("tasks"), require_conditions=False)
        node_counter = [0]
        for row in trigger_by_pair.values():
            if not _validate_tree(row.get("tree"), depth=0, counter=node_counter, is_root=True):
                raise ValueError("MISSION_TRIGGER_TREE_INVALID")

        conditions = state.get("mission_conditions")
        conditions_by_pair: dict[tuple[str, str], Mapping[str, Any]] = {}
        conditions_known = isinstance(conditions, Mapping) and conditions.get("status") == "known"
        if conditions_known:
            if conditions.get("canonical_pointer_keys_verified") is not True:
                raise ValueError("MISSION_CONDITIONS_INVALID")
            conditions_by_pair = _pair_index(conditions.get("tasks"), require_conditions=True)

        selected: list[tuple[str, str]] = []
        selected_seen: set[tuple[str, str]] = set()
        for entry in entries:
            pair = _valid_pair(entry)
            if pair is None or pair in selected_seen:
                raise ValueError("LOADED_TASK_MEMBERSHIP_INVALID")
            if pair not in trigger_by_pair:
                raise ValueError("MISSION_TRIGGER_TASKS_INCOMPLETE")
            if conditions_known and pair not in conditions_by_pair:
                raise ValueError("MISSION_CONDITION_TASKS_INCOMPLETE")
            selected_seen.add(pair)
            selected.append(pair)

        budget = [0]
        tasks = []
        total_leaves = [0, 0, 0, 0]
        for pair in selected:
            condition = conditions_by_pair.get(pair)
            checks = {
                "already_completed": condition.get("task_completed") if condition else None,
                "prerequisites_satisfied": condition.get("prerequisites_satisfied") if condition else None,
            }
            tree = trigger_by_pair[pair]["tree"]
            public_tree = _public_tree(tree, budget)
            leaf_counts = _count_leaves(tree)
            for index, value in enumerate(leaf_counts):
                total_leaves[index] += value
            tasks.append({
                "root_id": pair[0],
                "task_id": pair[1],
                "checks": checks,
                "trigger": public_tree,
            })
        value = {
            "tasks": tasks,
            "task_count": len(tasks),
            "evaluated_leaf_count": total_leaves[0],
            "satisfied_leaf_count": total_leaves[1],
            "unsatisfied_leaf_count": total_leaves[2],
            "unknown_leaf_count": total_leaves[3],
        }
        result = {
            "status": "known",
            "value": value,
            "complete": False,
            "value_origin": "loaded_native_trigger_tree_partial",
            "task_trigger_complete": False,
            "native_function_called": False,
            "branch_visibility_evaluated": False,
            "ui_visibility_evaluated": False,
        }
        encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(encoded) > MAX_PUBLIC_JSON_BYTES:
            return gap("MISSION_TRIGGER_PUBLIC_BUDGET_EXCEEDED")
        return result
    except _OutputBudgetExceeded:
        return gap("MISSION_TRIGGER_PUBLIC_BUDGET_EXCEEDED")
    except Exception as exc:
        reason = str(exc)
        if not reason.startswith(("MISSION_TRIGGER_", "MISSION_CONDITION_", "LOADED_TASK_")):
            reason = "MISSION_TRIGGER_PROJECTION_INVALID"
        return gap(reason)


def trigger_results(state: Any) -> dict[tuple[str, str], dict[str, Any]]:
    """Return verified root evaluations for eligibility composition, or no evidence."""
    if not isinstance(state, Mapping):
        return {}
    captured = state.get("mission_triggers")
    if (not isinstance(captured, Mapping) or captured.get("status") != "known"
            or captured.get("loaded_trigger_binding_verified") is not True
            or captured.get("profile_sha256") != PROFILE_SHA256):
        return {}
    try:
        indexed = _pair_index(captured.get("tasks"), require_conditions=False)
        if len(indexed) != len(captured["tasks"]):
            return {}
        counter = [0]
        result: dict[tuple[str, str], dict[str, Any]] = {}
        for pair, row in indexed.items():
            tree = row.get("tree")
            if not _validate_tree(tree, depth=0, counter=counter, is_root=True):
                return {}
            evaluation = tree["evaluation"]
            result[pair] = {
                key: evaluation[key]
                for key in ("status", "satisfied", "reason")
                if key in evaluation
            }
        return result
    except Exception:
        return {}


__all__ = ["normalize_triggers", "project_progress", "trigger_results"]
