"""Static M03 target references enriched with the bounded map-scope index.

This module keeps the v1 literal projector as its only AST validator. Map
membership adds definition-time context; it does not evaluate triggers or
claim that a referenced province/country is a current target.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from . import mission_target_rules as _base


_ROOT = Path(__file__).resolve().parents[2]
_SCOPE_LINKS_PATH = Path("third_party/cwtools-eu4-config/scope_links.cwt")
_TRIGGERS_PATH = Path("third_party/cwtools-eu4-config/triggers.cwt")
_SCOPE_LINKS_BYTES = 55_779
_SCOPE_LINKS_SHA256 = "edf81dcb3b77ae270d2dcc77c44cbbe28715e8bb16e1ff8a91ffe9d92bfdc06a"
_TRIGGERS_BYTES = 222_281
_TRIGGERS_SHA256 = "3aa0f3382ea56ca759e4d3ac0dacd79627699b486bd4ac0f6d716e377f7b2f84"
_CWT_MAX_BYTES = 512 * 1024
_MAX_SCOPE_LOOKUPS = 8192
_MAX_COLLECT_NODES = _base.MAX_TOTAL_NODES
_MAX_COLLECT_DEPTH = _base.MAX_DEPTH

# Syntax containers whose children are trigger expressions. Unknown blocks are
# opaque until the static index proves that the block key is itself a scope.
_TRIGGER_CONTAINERS = frozenset({
    "trigger", "AND", "OR", "NOT", "if", "else", "limit",
    "custom_trigger_tooltip",
})
_DYNAMIC_SCOPE_BLOCKS = frozenset({
    "root", "from", "prev", "this", "owner", "controller", "capital",
    "capital_scope", "overlord", "emperor", "current", "scope", "random",
})
_LOGICAL_BLOCKS = frozenset({"AND", "OR", "NOT"})
_COUNT_OR_WEIGHT_BLOCKS = frozenset({"random_list", "random_repeating", "weight", "chance"})
_DYNAMIC_SYMBOLS = frozenset(_base._DYNAMIC_SYMBOLS)

# The index uses these plural/internal names. The public projection uses stable
# singular names while retaining the original index kind alongside them.
_KIND_NORMALIZATION = (
    ("province_id", "province", "province", ("provinces",), 142),
    ("country_tag", "country_tag", "country", ("countries",), 19),
    ("areas", "area", "province", ("regions",), 149),
    ("regions", "region", "province", ("regions",), 174),
    ("superregions", "superregion", "province", ("regions",), 182),
    ("continents", "continent", "province", ("regions",), 191),
    ("province_groups", "province_group", "province", ("regions",), 158),
)
_KIND_INFO = MappingProxyType({row[0]: row[1:] for row in _KIND_NORMALIZATION})
_SCOPE_ALIAS_ROWS = (
    (4, "alias[trigger:scope_field]"),
    (19, "alias[trigger:enum[country_tags]]"),
    (142, "alias[trigger:<province_id>]"),
    (149, "alias[trigger:<area.used>]"),
    (158, "alias[trigger:<province_group.used>]"),
    (174, "alias[trigger:<region>]"),
    (182, "alias[trigger:<superregion>]"),
    (191, "alias[trigger:<continent>]"),
)

# Only relations whose meaning identifies one of the existing M03 relation
# fields are projected. We deliberately omit generic country/province entity
# guesses when a scope[any] argument does not identify an entity kind.
_DYNAMIC_FIELD_ITEMS = (
    ("area", ("regions",)),
    ("region", ("regions",)),
    ("controlled_by", ("control",)),
    ("owned_by", ("ownership",)),
    ("owns", ("ownership",)),
    ("is_core", ("cores",)),
    ("is_territorial_core", ("cores",)),
    ("is_subject_of", ("subjects",)),
    ("country_or_non_sovereign_subject_holds", ("ownership", "subjects")),
    ("country_or_subject_holds", ("ownership", "subjects")),
    ("country_or_vassal_holds", ("ownership", "subjects")),
    ("owned_by_subject_of", ("ownership", "subjects")),
    ("subject_owns", ("ownership", "subjects")),
)
_DYNAMIC_FIELDS = MappingProxyType(dict(_DYNAMIC_FIELD_ITEMS))
_MAP_KIND_FIELDS = MappingProxyType({
    "province_id": ("provinces",),
    "country_tag": ("countries",),
    "areas": ("regions",),
    "regions": ("regions",),
    "superregions": ("regions",),
    "continents": ("regions",),
    "province_groups": ("regions",),
})
_EXPECTED_LITERAL_KIND = MappingProxyType({
    "province_id": frozenset({"province_id"}),
    "country_tag": frozenset({"country_tag"}),
    "area_identifier": frozenset({"areas"}),
    "region_identifier": frozenset({"regions"}),
})
_SCOPE_HEAD_RE = re.compile(r"^alias\[trigger:([^\]]+)\]\s*=\s*(.+?)\s*$")
_SCOPE_OVERLOAD_RE = re.compile(r"^scope\[([^\]]+)\]$")
_PROVINCE_KEY_RE = re.compile(r"[0-9]+\Z")
_TAG_KEY_RE = re.compile(r"[A-Z0-9]{3}\Z")


@dataclass(frozen=True)
class PreparedScopeProjection:
    """Immutable, per-task preparation reusable across the seven M03 fields."""

    tasks_sha256: str
    scope_index_identity: int | None
    lookup_rows_json: str
    scope_context_json: str
    cwt_evidence_json: str
    collector_json: str
    prepare_status: str


def _json(value: Any) -> bytes:
    return _base._json_bytes(value)


def _tasks_sha256(tasks: Any) -> str | None:
    try:
        return hashlib.sha256(_json(tasks)).hexdigest()
    except Exception:
        return None


def _read_pinned(path: Path, expected_bytes: int, expected_sha: str) -> tuple[bytes | None, dict[str, Any]]:
    absolute = _ROOT / path
    try:
        size = absolute.stat().st_size
        if size < 1 or size > _CWT_MAX_BYTES or size != expected_bytes:
            return None, {"path": path.as_posix(), "bytes": size, "sha256": None,
                          "status": "unavailable", "reason": "CWT_SIZE_MISMATCH"}
        raw = absolute.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if len(raw) != size or digest != expected_sha:
            return None, {"path": path.as_posix(), "bytes": len(raw), "sha256": digest,
                          "status": "unavailable", "reason": "CWT_PIN_MISMATCH"}
        return raw, {"path": path.as_posix(), "bytes": len(raw), "sha256": digest,
                     "status": "pinned_source_verified"}
    except OSError as exc:
        return None, {"path": path.as_posix(), "bytes": None, "sha256": None,
                      "status": "unavailable", "reason": type(exc).__name__}


def _cwt_evidence() -> dict[str, Any]:
    scope_raw, scope_pin = _read_pinned(
        _SCOPE_LINKS_PATH, _SCOPE_LINKS_BYTES, _SCOPE_LINKS_SHA256)
    trigger_raw, trigger_pin = _read_pinned(
        _TRIGGERS_PATH, _TRIGGERS_BYTES, _TRIGGERS_SHA256)
    scope_lines: list[dict[str, Any]] = []
    scope_alias_ok = scope_raw is not None
    if scope_raw is not None:
        lines = scope_raw.decode("utf-8-sig").splitlines()
        for line_number, expected_prefix in _SCOPE_ALIAS_ROWS:
            actual = lines[line_number - 1].strip() if line_number <= len(lines) else ""
            if not actual.startswith(expected_prefix):
                scope_alias_ok = False
            scope_lines.append({"line": line_number, "text": actual})
    overloads: dict[str, list[dict[str, Any]]] = {}
    trigger_command_names: set[str] = set()
    trigger_alias_ok = trigger_raw is not None
    if trigger_raw is not None:
        for line_number, raw_line in enumerate(trigger_raw.decode("utf-8-sig").splitlines(), 1):
            match = _SCOPE_HEAD_RE.match(raw_line)
            if match is None:
                continue
            command, rhs = match.groups()
            trigger_command_names.add(command)
            typed = _SCOPE_OVERLOAD_RE.fullmatch(rhs)
            if typed is not None:
                overloads.setdefault(command, []).append({
                    "type": typed.group(1), "line": line_number,
                })
    ready = scope_pin["status"] == "pinned_source_verified" and trigger_pin["status"] == "pinned_source_verified" and scope_alias_ok and trigger_alias_ok
    return {
        "status": "pinned_source_verified" if ready else "unavailable",
        "scope_links": scope_pin,
        "triggers": trigger_pin,
        "scope_link_aliases": scope_lines,
        "trigger_scope_overloads": overloads if trigger_raw is not None else {},
        "trigger_command_names": sorted(trigger_command_names),
        "vendor_commit": _base._VENDOR_COMMIT,
        "license": _base._VENDOR_LICENSE,
    }


def _scope_context_summary(scope_index: Any) -> dict[str, Any]:
    context_method = getattr(scope_index, "context", None)
    if not callable(context_method):
        return {"status": "unavailable", "reason": "SCOPE_INDEX_CONTEXT_UNAVAILABLE"}
    try:
        context = context_method()
    except Exception as exc:
        return {"status": "unavailable", "reason": f"SCOPE_INDEX_CONTEXT_{type(exc).__name__}"}
    if not isinstance(context, Mapping):
        return {"status": "unavailable", "reason": "SCOPE_INDEX_CONTEXT_INVALID"}
    component_statuses: dict[str, Any] = {}
    raw_components = context.get("component_statuses")
    if isinstance(raw_components, Mapping):
        for name, row in raw_components.items():
            if not isinstance(name, str) or not isinstance(row, Mapping):
                continue
            reasons = row.get("reasons")
            component_statuses[name] = {
                "status": row.get("status") if isinstance(row.get("status"), str) else "unknown",
                "complete": row.get("complete") if type(row.get("complete")) is bool else False,
                "reason_codes": [r.get("code") for r in reasons[:8]
                                 if isinstance(r, Mapping) and isinstance(r.get("code"), str)]
                if isinstance(reasons, list) else [],
            }
    summary = {
        "schema": context.get("schema"),
        "status": context.get("status"),
        "complete": context.get("complete") if type(context.get("complete")) is bool else False,
        "mode": context.get("mode"),
        "context_scope": context.get("context_scope"),
        "game_version": context.get("game_version"),
        "configuration_sha256": context.get("configuration_sha256"),
        "definitions_sha256": context.get("definitions_sha256"),
        "component_statuses": component_statuses,
        "scope_count_by_kind": context.get("scope_count_by_kind")
        if isinstance(context.get("scope_count_by_kind"), Mapping) else {},
    }
    # Keep the provenance bound small even if an injected resolver returns an
    # unusually verbose context.
    try:
        if len(_json(summary)) > 16 * 1024:
            summary["component_statuses"] = {
                key: {"status": value["status"], "complete": value["complete"]}
                for key, value in component_statuses.items()
            }
            summary["scope_count_by_kind"] = {}
    except (TypeError, ValueError):
        return {"status": "unavailable", "reason": "SCOPE_INDEX_CONTEXT_NOT_JSON"}
    return summary


def _collect_lookup_names(tasks: Any) -> tuple[tuple[str, ...], dict[str, Any]]:
    names: set[str] = set()
    visited = 0
    truncated = False
    malformed = False
    if not isinstance(tasks, (list, tuple)):
        return (), {"status": "unavailable", "reason": "TASKS_NOT_SEQUENCE",
                    "visited_nodes": 0, "unique_names": 0}
    direct_commands = frozenset(_base._RULES)
    direct_reference_commands = frozenset(
        command for command, variants in _base._RULES.items()
        if any(v.get("argument") in ("province_id", "country_tag", "area_identifier", "region_identifier")
               for v in variants)
    )
    for task in tasks[:_base.MAX_TASKS]:
        if not isinstance(task, Mapping):
            malformed = True
            continue
        trigger = task.get("trigger")
        roots = list(trigger) if isinstance(trigger, (list, tuple)) else [trigger]
        for root in roots:
            stack: list[tuple[Any, int]] = [(root, 0)]
            seen: set[int] = set()
            while stack:
                node, depth = stack.pop()
                if not isinstance(node, Mapping) or depth > _MAX_COLLECT_DEPTH:
                    malformed = True
                    continue
                identity = id(node)
                if identity in seen:
                    malformed = True
                    continue
                seen.add(identity)
                visited += 1
                if visited > _MAX_COLLECT_NODES:
                    truncated = True
                    break
                key = node.get("key")
                kind = node.get("kind")
                children = node.get("children")
                if not isinstance(children, list):
                    malformed = True
                    continue
                # Ask the index about block names without inferring their kind
                # from a suffix or capitalization pattern.
                if (kind == "block" and node.get("assignment") == "="
                        and isinstance(key, str) and 0 < len(key) <= 128 and "\x00" not in key):
                    names.add(key)
                # Literal arguments already supported by v1 can be enriched
                # with exact map membership from the same batch lookup.
                elif (kind == "scalar" and key in direct_reference_commands
                      and isinstance(node.get("value"), (str, int))
                      and type(node.get("value")) is not bool):
                    lexical = str(node["value"])
                    if 0 < len(lexical) <= 128 and "\x00" not in lexical:
                        names.add(lexical)
                for child in reversed(children):
                    stack.append((child, depth + 1))
            if truncated:
                break
        if truncated:
            break
    if len(names) > _MAX_SCOPE_LOOKUPS:
        truncated = True
    status = "ready" if not (truncated or malformed) else "partial"
    return tuple(sorted(names)[:_MAX_SCOPE_LOOKUPS]), {
        "status": status,
        "reason": ("SCOPE_NAME_COLLECTION_LIMIT" if truncated else
                   "SCOPE_NAME_COLLECTION_SHAPE" if malformed else None),
        "visited_nodes": min(visited, _MAX_COLLECT_NODES),
        "unique_names": len(names),
        "lookup_name_limit": _MAX_SCOPE_LOOKUPS,
    }


def _safe_lookup_rows(raw: Any, names: Sequence[str]) -> tuple[dict[str, Any], dict[str, int], str | None]:
    if not isinstance(raw, Mapping):
        return {}, {}, "SCOPE_LOOKUP_RESULT_INVALID"
    clean: dict[str, Any] = {}
    statuses: dict[str, int] = {}
    for name in names:
        row = raw.get(name)
        if not isinstance(row, Mapping):
            clean[name] = {"status": "unknown", "name": name, "reason": "SCOPE_LOOKUP_RESULT_MISSING"}
            statuses["unknown:SCOPE_LOOKUP_RESULT_MISSING"] = statuses.get("unknown:SCOPE_LOOKUP_RESULT_MISSING", 0) + 1
            continue
        status = row.get("status")
        if status == "known":
            kind = row.get("kind")
            if (not isinstance(kind, str) or kind not in _KIND_INFO
                    or row.get("name") != name or "value" not in row
                    or not isinstance(row.get("source"), Mapping)):
                clean[name] = {"status": "unknown", "name": name, "reason": "SCOPE_LOOKUP_ROW_INVALID"}
                statuses["unknown:SCOPE_LOOKUP_ROW_INVALID"] = statuses.get("unknown:SCOPE_LOOKUP_ROW_INVALID", 0) + 1
                continue
            members = row.get("members")
            if members is not None and (not isinstance(members, list)
                    or len(members) > 65535
                    or any(type(member) is not int or member < 1 or member > 65535 for member in members)):
                clean[name] = {"status": "unknown", "name": name, "reason": "SCOPE_LOOKUP_MEMBERS_INVALID",
                               "kind": kind}
                statuses["unknown:SCOPE_LOOKUP_MEMBERS_INVALID"] = statuses.get("unknown:SCOPE_LOOKUP_MEMBERS_INVALID", 0) + 1
                continue
            safe = {"status": "known", "name": name, "kind": kind,
                    "value": row.get("value"), "source": dict(row["source"])}
            if members is not None:
                safe["members"] = list(members)
            clean[name] = safe
            statuses[f"known:{kind}"] = statuses.get(f"known:{kind}", 0) + 1
        elif status == "unknown":
            reason = row.get("reason")
            if not isinstance(reason, str) or len(reason) > 128:
                reason = "SCOPE_LOOKUP_UNKNOWN"
            kind = row.get("kind") if isinstance(row.get("kind"), str) and row.get("kind") in _KIND_INFO else None
            safe = {"status": "unknown", "name": name, "reason": reason}
            if kind is not None:
                safe["kind"] = kind
            clean[name] = safe
            statuses[f"unknown:{reason}"] = statuses.get(f"unknown:{reason}", 0) + 1
        else:
            clean[name] = {"status": "unknown", "name": name, "reason": "SCOPE_LOOKUP_STATUS_INVALID"}
            statuses["unknown:SCOPE_LOOKUP_STATUS_INVALID"] = statuses.get("unknown:SCOPE_LOOKUP_STATUS_INVALID", 0) + 1
    return clean, statuses, None


def prepare_scope_projection(tasks: Sequence[Mapping[str, Any]], scope_index=None) -> PreparedScopeProjection:
    """Collect all candidate names and resolve them in one bounded batch."""
    task_digest = _tasks_sha256(tasks) or "unhashable"
    names, collector = _collect_lookup_names(tasks)
    cwt = _cwt_evidence()
    scope_context: dict[str, Any] = {"status": "not_supplied"}
    lookups: dict[str, Any] = {}
    status_counts: dict[str, int] = {}
    error = None
    scope_index_identity = id(scope_index) if scope_index is not None else None
    if scope_index is not None:
        scope_context = _scope_context_summary(scope_index)
        if collector["status"] != "ready":
            error = collector.get("reason") or "SCOPE_NAME_COLLECTION_INCOMPLETE"
        elif names:
            lookup_method = getattr(scope_index, "lookup_scopes", None)
            if not callable(lookup_method):
                error = "SCOPE_INDEX_LOOKUP_UNAVAILABLE"
            else:
                try:
                    raw = lookup_method(names)
                    lookups, status_counts, error = _safe_lookup_rows(raw, names)
                except Exception as exc:
                    error = f"SCOPE_INDEX_LOOKUP_{type(exc).__name__}"
        else:
            error = None
    if error:
        lookups = {}
        status_counts = {}
    known_configs = {
        row.get("source", {}).get("configuration_sha256")
        for row in lookups.values()
        if row.get("status") == "known" and isinstance(row.get("source"), Mapping)
        and isinstance(row.get("source", {}).get("configuration_sha256"), str)
    }
    context_config = scope_context.get("configuration_sha256")
    if (isinstance(context_config, str) and known_configs
            and any(value != context_config for value in known_configs)):
        lookups = {}
        status_counts = {}
        error = "SCOPE_CONTEXT_DRIFT_DURING_PREPARE"
    summary = {
        "schema": "information.mission_target_rules_v2.prepared_scope_projection.v1",
        "projection_version": 2,
        "scope_index_supplied": scope_index is not None,
        "scope_index_context": scope_context,
        "lookup_name_count": len(names),
        "lookup_status_counts": status_counts,
        "lookup_error": error,
        "collector": collector,
        "cwt": cwt,
        "limits": {"max_scope_lookups": _MAX_SCOPE_LOOKUPS,
                   "max_scope_members": 65535,
                   "max_cwt_file_bytes": _CWT_MAX_BYTES},
    }
    try:
        cwt_json = json.dumps(cwt, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        lookups_json = json.dumps(lookups, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        context_json = json.dumps(scope_context, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        collector_json = json.dumps({**collector, "lookup_error": error,
                                     "lookup_status_counts": status_counts},
                                    ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        # Keep the cross-field provenance compact; per-reference source rows
        # carry the detailed file pins only when actually used.
        summary_bytes = len(_json(summary))
        if summary_bytes > 32 * 1024:
            summary["scope_index_context"] = {
                k: scope_context.get(k) for k in
                ("status", "mode", "game_version", "configuration_sha256", "definitions_sha256")
            }
            summary["cwt"]["trigger_scope_overloads"] = {
                command: rows for command, rows in cwt.get("trigger_scope_overloads", {}).items()
                if command in _DYNAMIC_FIELDS
            }
        if len(_json(summary)) > 32 * 1024:
            summary["cwt"]["scope_link_aliases"] = []
            summary["cwt"]["trigger_scope_overloads"] = {}
        prepare_status = "ready" if cwt.get("status") == "pinned_source_verified" and not error else "partial"
    except (TypeError, ValueError):
        lookups_json = "{}"
        context_json = "{}"
        cwt_json = "{}"
        collector_json = json.dumps({"status": "unavailable", "reason": "PREPARED_SCOPE_JSON_INVALID"})
        summary = {"schema": "information.mission_target_rules_v2.prepared_scope_projection.v1",
                   "projection_version": 2, "prepare_error": "PREPARED_SCOPE_JSON_INVALID"}
        prepare_status = "unavailable"
    return PreparedScopeProjection(
        tasks_sha256=task_digest,
        scope_index_identity=scope_index_identity,
        lookup_rows_json=lookups_json,
        scope_context_json=context_json,
        cwt_evidence_json=cwt_json,
        collector_json=collector_json,
        prepare_status=prepare_status,
    )


def _public_kind(index_kind: str) -> tuple[str, str, tuple[str, ...], int] | None:
    return _KIND_INFO.get(index_kind)


def _source_scope_payload(row: Mapping[str, Any]) -> dict[str, Any] | None:
    raw_kind = row.get("kind")
    kind_info = _public_kind(raw_kind) if isinstance(raw_kind, str) else None
    if kind_info is None:
        return None
    normalized_kind, expected_type, _fields, _line = kind_info
    value = row.get("value")
    members = row.get("members")
    if raw_kind == "province_id":
        if type(value) is not int or not 1 <= value <= 65535:
            return None
        members = [value]
    elif raw_kind == "country_tag":
        members = None
    if members is not None and (not isinstance(members, list)
            or any(type(member) is not int or not 1 <= member <= 65535 for member in members)):
        return None
    static_scope = {
        "kind": normalized_kind,
        "index_kind": raw_kind,
        "name": row.get("name"),
        "value": value,
        "members": list(members) if members is not None else None,
        "source": dict(row.get("source", {})),
    }
    try:
        if len(_json(static_scope)) > _base.MAX_NODE_SCALAR_BYTES - 1024:
            return None
    except (TypeError, ValueError):
        return None
    return static_scope


def _kind_fields(index_kind: str) -> tuple[str, ...]:
    return _MAP_KIND_FIELDS.get(index_kind, ())


def _cwt_provenance_view(cwt: Mapping[str, Any]) -> dict[str, Any]:
    all_overloads = cwt.get("trigger_scope_overloads", {})
    relevant = {command: all_overloads[command] for command in _DYNAMIC_FIELDS
                if isinstance(all_overloads, Mapping) and command in all_overloads}
    return {
        "status": cwt.get("status"),
        "scope_links": cwt.get("scope_links"),
        "triggers": cwt.get("triggers"),
        "scope_link_aliases": cwt.get("scope_link_aliases", []),
        "relevant_trigger_scope_overloads": relevant,
        "trigger_scope_overload_count": sum(len(rows) for rows in all_overloads.values())
        if isinstance(all_overloads, Mapping) else 0,
        "vendor_commit": cwt.get("vendor_commit"),
        "license": cwt.get("license"),
        "vendor_consumed_files_limit": "VENDOR.json consumed_files pins scopes.cwt only; scope_links.cwt and triggers.cwt are pinned above by local file SHA-256",
    }


def _context_safe(ancestors: Sequence[Mapping[str, Any]], lookups: Mapping[str, Any],
                  trigger_names: frozenset[str]) -> tuple[bool, str | None]:
    if not ancestors or ancestors[0].get("key") != "trigger":
        return False, "NOT_IN_TRIGGER_ROOT"
    for parent in ancestors[1:]:
        key = parent.get("key")
        if not isinstance(key, str):
            return False, "INVALID_PARENT_KEY"
        if key in _TRIGGER_CONTAINERS:
            continue
        if key.casefold() in _DYNAMIC_SCOPE_BLOCKS:
            continue
        row = lookups.get(key)
        if (parent.get("kind") == "block" and parent.get("assignment") == "="
                and isinstance(row, Mapping) and row.get("status") == "known"
                and key not in trigger_names):
            continue
        return False, key
    return True, None


def _literal_scope_compatible(classification: Mapping[str, Any], row: Mapping[str, Any]) -> bool:
    expected = _EXPECTED_LITERAL_KIND.get(classification.get("cwt_argument_type"))
    if expected is None:
        return True
    return row.get("kind") in expected


def _known_scope_classification(key: str, row: Mapping[str, Any]) -> dict[str, Any] | None:
    info = _public_kind(str(row.get("kind")))
    if info is None:
        return None
    normalized_kind, expected_type, fields, line = info
    static_scope = _source_scope_payload(row)
    if static_scope is None:
        return None
    argument = f"scope_head:{row['kind']}"
    reference_kind = "province_id" if row["kind"] == "province_id" else normalized_kind
    return {
        "record_kind": "scope_head_reference",
        "normalized_value": key,
        "reference_kind": reference_kind,
        "cwt_argument_type": argument,
        "fields": fields,
        "cwt_lines": [line],
        "static_scope": static_scope,
        "expected_scope_type": expected_type,
    }


def _prepare_valid(tasks: Any, scope_index: Any, prepared: Any) -> tuple[bool, dict[str, Any], dict[str, Any]]:
    if not isinstance(prepared, PreparedScopeProjection):
        return False, {}, {"reason": "PREPARED_SCOPE_OBJECT_INVALID"}
    current_digest = _tasks_sha256(tasks)
    if current_digest is None or prepared.tasks_sha256 != current_digest:
        return False, {}, {"reason": "PREPARED_TASKS_FINGERPRINT_MISMATCH"}
    if (scope_index is not None and id(scope_index) != prepared.scope_index_identity):
        return False, {}, {"reason": "PREPARED_SCOPE_INDEX_MISMATCH"}
    try:
        rows = json.loads(prepared.lookup_rows_json)
        context = json.loads(prepared.scope_context_json)
        cwt = json.loads(prepared.cwt_evidence_json)
        collector = json.loads(prepared.collector_json)
    except (TypeError, ValueError, json.JSONDecodeError):
        return False, {}, {"reason": "PREPARED_SCOPE_JSON_INVALID"}
    if not all(isinstance(x, dict) for x in (rows, context, cwt, collector)):
        return False, {}, {"reason": "PREPARED_SCOPE_SHAPE_INVALID"}
    return True, {"lookups": rows, "context": context, "cwt": cwt,
                  "collector": collector}, {}


def _annotate_v2(result: dict[str, Any], prepared_summary: Mapping[str, Any],
                 counters: Mapping[str, Any], disabled_reason: str | None) -> dict[str, Any]:
    provenance = result.setdefault("provenance", {})
    extended = provenance.setdefault("extended_reference_projection", {})
    if not isinstance(extended, dict):
        extended = {}
        provenance["extended_reference_projection"] = extended
    extended["runtime_counts"] = dict(counters)
    if disabled_reason:
        extended["v2_extension_disabled_reason"] = disabled_reason
    try:
        if len(_json(extended)) > 32 * 1024:
            extended["runtime_counts"] = {k: v for k, v in counters.items()
                                           if not k.endswith("_examples")}
            if len(_json(extended)) > 32 * 1024:
                extended["scope_index_context"] = {
                    k: prepared_summary.get("scope_index_context", {}).get(k)
                    for k in ("status", "mode", "game_version", "configuration_sha256", "definitions_sha256")
                }
    except (TypeError, ValueError):
        extended["runtime_counts"] = {"provenance_compaction": "failed"}
    value = result.get("value")
    if isinstance(value, dict):
        value["semantics"] = "static_declared_mission_target_conditions"
        value["projection_version"] = 2
        value["full_target_set_resolved"] = False
        value["complete"] = False
        value["evaluated"] = False
    return result


def project_target_rules(tasks: Sequence[Mapping[str, Any]], field: str, *,
                         scope_index=None, _prepared: PreparedScopeProjection | None = None) -> dict[str, Any]:
    """Project one M03 field, reusing one prepared, batched scope lookup."""
    prepared = _prepared if _prepared is not None else prepare_scope_projection(tasks, scope_index)
    valid, unpacked, invalid = _prepare_valid(tasks, scope_index, prepared)
    if not valid:
        extra = {"schema": "information.mission_target_rules_v2.scope_projection.v1",
                 "projection_version": 2, "scope_index_supplied": scope_index is not None,
                 "prepared_status": "invalid", "prepare_error": invalid.get("reason")}
        result = _base.project_target_rules(
            tasks, field,
            _classifier=lambda node, _ancestors: _base._classify_node(node),
            _extra_provenance=extra)
        return _annotate_v2(result, extra, {}, invalid.get("reason"))

    lookups: dict[str, Any] = unpacked["lookups"]
    cwt: dict[str, Any] = unpacked["cwt"]
    collector: dict[str, Any] = unpacked["collector"]
    overloads: dict[str, list[dict[str, Any]]] = cwt.get("trigger_scope_overloads", {})
    trigger_names = frozenset(cwt.get("trigger_command_names", ()))
    cwt_ready = cwt.get("status") == "pinned_source_verified"
    counters: dict[str, Any] = {
        "static_scope_heads": 0,
        "static_literal_enrichments": 0,
        "dynamic_scope_references": 0,
        "scope_lookup_unknowns": 0,
        "opaque_scope_head_gaps": 0,
        "untyped_scope_head_candidates": 0,
        "unmapped_dynamic_scope_commands": 0,
        "opaque_examples": [],
        "unmapped_dynamic_examples": [],
    }
    extra = {
        "schema": "information.mission_target_rules_v2.scope_projection.v1",
        "projection_version": 2,
        "scope_index_supplied": prepared.scope_index_identity is not None,
        "scope_index_context": unpacked["context"],
        "lookup_name_count": collector.get("unique_names", len(lookups)),
        "lookup_status_counts": collector.get("lookup_status_counts", {}),
        "lookup_error": collector.get("lookup_error"),
        "collector": collector,
        "cwt": _cwt_provenance_view(cwt),
        "semantics": "static_scope_definition_membership_only",
        "limits": {"scope_targets_resolved": False,
                   "full_target_set_resolved": False,
                   "engine_conditions_evaluated": False},
    }

    def classifier(node: Mapping[str, Any], ancestors: tuple[Mapping[str, Any], ...]):
        classification, reason, candidates = _base._classify_node(node)
        key = node.get("key")
        value = node.get("value")
        children = node.get("children")
        # Keep every v1 literal, optionally attaching exact map membership.
        if classification is not None:
            enriched = dict(classification)
            if prepared.scope_index_identity is not None:
                lookup_name = str(classification.get("normalized_value"))
                row = lookups.get(lookup_name)
                if isinstance(row, Mapping) and row.get("status") == "known":
                    if _literal_scope_compatible(classification, row):
                        static_scope = _source_scope_payload(row)
                        if static_scope is not None:
                            enriched["static_scope"] = static_scope
                            counters["static_literal_enrichments"] += 1
                        else:
                            enriched["target_resolution"] = {
                                "status": "unknown", "reason": "STATIC_SCOPE_PAYLOAD_LIMIT"}
                    else:
                        enriched["target_resolution"] = {
                            "status": "unknown", "reason": "SCOPE_KIND_MISMATCH",
                            "scope_kind_candidate": row.get("kind")}
                elif isinstance(row, Mapping):
                    counters["scope_lookup_unknowns"] += 1
                    enriched["target_resolution"] = {
                        "status": "unknown", "reason": row.get("reason", "SCOPE_NOT_RESOLVED")}
                    if isinstance(row.get("kind"), str):
                        enriched["target_resolution"]["scope_kind_candidate"] = row["kind"]
            return enriched, None, candidates

        # Dynamic symbols become records only when the exact pinned CWT file
        # shows a scope[...] overload and the command has a narrow M03 relation.
        if (cwt_ready and isinstance(key, str) and isinstance(value, str)
                and node.get("kind") == "scalar" and node.get("assignment") == "="
                and isinstance(children, list) and not children
                and value.casefold() in _DYNAMIC_SYMBOLS):
            overload_rows = overloads.get(key, [])
            fields = _DYNAMIC_FIELDS.get(key)
            if overload_rows and fields:
                safe, blocked_by = _context_safe(ancestors, lookups, trigger_names)
                if not safe:
                    counters["opaque_scope_head_gaps"] += 1
                    if len(counters["opaque_examples"]) < 4:
                        counters["opaque_examples"].append({"key": key, "line": node.get("line"),
                                                             "blocked_by": blocked_by})
                    return None, "OPAQUE_TRIGGER_PARAMETER_CONTAINER", tuple(fields)
                types = sorted({row["type"] for row in overload_rows
                                if isinstance(row, Mapping) and isinstance(row.get("type"), str)})
                if not types:
                    return None, "CWT_SCOPE_OVERLOAD_INVALID", tuple(fields)
                counters["dynamic_scope_references"] += 1
                return {
                    "record_kind": "symbolic_condition_reference",
                    "normalized_value": value,
                    "reference_kind": "dynamic_scope_symbol",
                    "cwt_argument_type": "scope_overload",
                    "cwt_lines": sorted({row["line"] for row in overload_rows
                                          if type(row.get("line")) is int}),
                    "fields": tuple(sorted(fields)),
                    "expected_scope_type": types,
                    "target_resolution": {"status": "unknown",
                                          "reason": "DYNAMIC_SCOPE_SYMBOL_UNRESOLVED"},
                }, None, tuple(sorted(fields))
            if overload_rows and candidates:
                counters["unmapped_dynamic_scope_commands"] += 1
                if len(counters["unmapped_dynamic_examples"]) < 4:
                    counters["unmapped_dynamic_examples"].append({"key": key,
                                                                  "line": node.get("line"),
                                                                  "symbol": value,
                                                                  "cwt_lines": [r.get("line") for r in overload_rows]})
                return None, "DYNAMIC_SCOPE_FIELD_UNMAPPED", candidates

        # A resolved block key is a scope head only at a known trigger position.
        if (cwt_ready and isinstance(key, str) and node.get("kind") == "block"
                and node.get("assignment") == "=" and isinstance(children, list)):
            row = lookups.get(key)
            is_command = key in trigger_names or key in _TRIGGER_CONTAINERS
            if isinstance(row, Mapping) and row.get("status") == "known" and not is_command:
                kind = row.get("kind")
                fields = _kind_fields(kind) if isinstance(kind, str) else ()
                if fields:
                    safe, blocked_by = _context_safe(ancestors, lookups, trigger_names)
                    if not safe:
                        counters["opaque_scope_head_gaps"] += 1
                        if len(counters["opaque_examples"]) < 4:
                            counters["opaque_examples"].append({"key": key, "line": node.get("line"),
                                                                 "kind": kind, "blocked_by": blocked_by})
                        return None, "OPAQUE_TRIGGER_PARAMETER_CONTAINER", fields
                    result = _known_scope_classification(key, row)
                    if result is not None:
                        counters["static_scope_heads"] += 1
                        return result, None, fields
                    counters["scope_lookup_unknowns"] += 1
                    return None, "STATIC_SCOPE_PAYLOAD_LIMIT", fields
            elif not is_command and isinstance(row, Mapping) and row.get("status") == "unknown":
                kind = row.get("kind")
                fields = _kind_fields(kind) if isinstance(kind, str) else ()
                if not fields and _PROVINCE_KEY_RE.fullmatch(key):
                    fields = ("provinces",)
                elif not fields and _TAG_KEY_RE.fullmatch(key):
                    fields = ("countries",)
                if fields:
                    safe, blocked_by = _context_safe(ancestors, lookups, trigger_names)
                    if safe:
                        counters["scope_lookup_unknowns"] += 1
                        return None, row.get("reason", "SCOPE_NOT_RESOLVED"), tuple(fields)
                    if len(counters["opaque_examples"]) < 4:
                        counters["opaque_examples"].append({"key": key, "line": node.get("line"),
                                                             "kind": kind, "blocked_by": blocked_by})
                    return None, "OPAQUE_TRIGGER_PARAMETER_CONTAINER", tuple(fields)
                counters["untyped_scope_head_candidates"] += 1
        # Retain v1-specific gaps for non-scalar recognized arguments.
        return None, reason, candidates

    result = _base.project_target_rules(tasks, field, _classifier=classifier,
                                        _extra_provenance=extra)
    disabled = None if cwt_ready else "CWT_SCOPE_RULES_UNAVAILABLE"
    return _annotate_v2(result, extra, counters, disabled)


__all__ = ["PreparedScopeProjection", "prepare_scope_projection", "project_target_rules"]
