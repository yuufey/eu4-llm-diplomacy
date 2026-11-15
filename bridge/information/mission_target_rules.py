"""Bounded inventory of literal target references in mission trigger ASTs.

This module records static condition references only. It does not evaluate a
mission trigger, decide which branch is active, resolve ROOT/FROM/scope values,
or claim that a referenced target is required or currently satisfied.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence


SUPPORTED_FIELDS = frozenset({
    "provinces", "regions", "countries", "ownership", "control", "cores", "subjects",
})

_REPOSITORY_URL = "https://github.com/cwtools/cwtools-eu4-config.git"
_VENDOR_COMMIT = "a85622d368bbb7afca938ed70fdd5eda44aec769"
_VENDOR_LICENSE = "MIT"
_TRIGGERS_RELATIVE = Path("third_party/cwtools-eu4-config/triggers.cwt")
_VENDOR_RELATIVE = Path("third_party/cwtools-eu4-config/VENDOR.json")
_VENDOR_FALLBACK_RELATIVE = Path("third_party/cwtools-eu4-config.vendor.json")
_TRIGGERS_BYTES = 222281
_TRIGGERS_SHA256 = "3aa0f3382ea56ca759e4d3ac0dacd79627699b486bd4ac0f6d716e377f7b2f84"
_VENDOR_BYTES = 395
_VENDOR_SHA256 = "0c09c3338fa0077fcb0b904464ffa494477abcb7ed5e62cab8a537333d37864d"

_TAG_RE = re.compile(r"[A-Z0-9]{3}\Z")
_PROVINCE_RE = re.compile(r"[1-9][0-9]{0,4}\Z")
_REFERENCE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_KEY_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,255}\Z")
_SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
_DYNAMIC_SYMBOLS = frozenset({
    "root", "from", "prev", "this", "owner", "capital", "overlord", "controller",
    "emperor", "current", "scope", "random",
})

MAX_TASKS = 4096
MAX_TRIGGER_ROOTS_PER_TASK = 128
MAX_DEPTH = 64
MAX_CHILDREN = 8192
MAX_NODES_PER_TASK = 32768
MAX_TOTAL_NODES = 131072
MAX_RULES_PER_TASK = 4096
MAX_TOTAL_RULES = 32768
MAX_GAPS_PER_TASK = 1024
MAX_TOTAL_CONTEXT_BYTES = 4 * 1024 * 1024
MAX_TRIGGER_ROOT_BYTES = 128 * 1024
MAX_NODE_SCALAR_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024


# These variants are the explicitly pinned direct-literal forms in triggers.cwt.
# Other overloads (for example scope[province] or scope[country]) remain
# uninterpreted. Line numbers are checked against the exact pinned file.
_RULES: dict[str, tuple[dict[str, Any], ...]] = {
    "owns": ({
        "argument": "province_id", "reference_kind": "province_id",
        "fields": ("provinces", "ownership"), "lines": (3494,),
    },),
    "owns_core_province": ({
        "argument": "province_id", "reference_kind": "province_id",
        "fields": ("provinces", "ownership", "cores"), "lines": (3498,),
    },),
    "controls": ({
        "argument": "province_id", "reference_kind": "province_id",
        "fields": ("provinces", "control"), "lines": (537,),
    },),
    "controlled_by": (
        {"argument": "country_tag", "reference_kind": "country_tag",
         "fields": ("countries", "control"), "lines": (529,)},
        {"argument": "rebel_type", "reference_kind": "rebel_type",
         "fields": ("control",), "lines": (533,)},
    ),
    "owned_by": ({
        "argument": "country_tag", "reference_kind": "country_tag",
        "fields": ("countries", "ownership"), "lines": (3487,),
    },),
    "is_core": (
        {"argument": "province_id", "reference_kind": "province_id",
         "fields": ("provinces", "cores"), "lines": (2133,)},
        {"argument": "country_tag", "reference_kind": "country_tag",
         "fields": ("countries", "cores"), "lines": (2145,)},
    ),
    "is_territorial_core": (
        {"argument": "province_id", "reference_kind": "province_id",
         "fields": ("provinces", "cores"), "lines": (2578,)},
        {"argument": "country_tag", "reference_kind": "country_tag",
         "fields": ("countries", "cores"), "lines": (2590,)},
    ),
    "subject_owns": ({
        "argument": "province_id", "reference_kind": "province_id",
        "fields": ("provinces", "ownership", "subjects"), "lines": (5816,),
    },),
    "area": (
        {"argument": "area_identifier", "reference_kind": "area",
         "fields": ("regions",), "lines": (140,)},
        {"argument": "province_id", "reference_kind": "province_id",
         "fields": ("provinces",), "lines": (148,)},
    ),
    "region": ({
        "argument": "region_identifier", "reference_kind": "region",
        "fields": ("regions",), "lines": (3707,),
    },),
    "tag": ({
        "argument": "country_tag", "reference_kind": "country_tag",
        "fields": ("countries",), "lines": (4068,),
    },),
    "is_subject_of": ({
        "argument": "country_tag", "reference_kind": "country_tag",
        "fields": ("countries", "subjects"), "lines": (2570,),
    },),
    "owned_by_subject_of": ({
        "argument": "country_tag", "reference_kind": "country_tag",
        "fields": ("countries", "ownership", "subjects"), "lines": (5773,),
    },),
    "country_or_subject_holds": ({
        "argument": "country_tag", "reference_kind": "country_tag",
        "fields": ("countries", "ownership", "subjects"), "lines": (569,),
    },),
    "country_or_vassal_holds": ({
        "argument": "country_tag", "reference_kind": "country_tag",
        "fields": ("countries", "ownership", "subjects"), "lines": (561,),
    },),
    "country_or_non_sovereign_subject_holds": ({
        "argument": "country_tag", "reference_kind": "country_tag",
        "fields": ("countries", "ownership", "subjects"), "lines": (4745,),
    },),
}

_CWT_ALIAS_LINES: dict[str, tuple[int, ...]] = {
    "area": (140, 144, 148),
    "controlled_by": (525, 529, 533),
    "controls": (537,),
    "country_or_non_sovereign_subject_holds": (4742, 4745),
    "country_or_subject_holds": (565, 569),
    "country_or_vassal_holds": (557, 561),
    "is_core": (2133, 2137, 2141, 2145),
    "is_subject_of": (2566, 2570),
    "is_territorial_core": (2578, 2582, 2586, 2590),
    "owned_by": (3483, 3487),
    "owned_by_subject_of": (5773, 5777),
    "owns": (3491, 3494),
    "owns_core_province": (3498,),
    "region": (3707, 3711, 3715),
    "subject_owns": (5812, 5816),
    "tag": (4064, 4068),
}


class _ProjectError(ValueError):
    def __init__(self, code: str, detail: str | None = None) -> None:
        self.code = code
        self.detail = detail
        super().__init__(code if detail is None else f"{code}:{detail}")


def _json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, OverflowError, RecursionError) as exc:
        raise _ProjectError("AST_NOT_JSON_SERIALIZABLE", type(exc).__name__) from exc


def _pin(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise _ProjectError("CWT_RULE_FILE_MISSING", path.name)
    size = path.stat().st_size
    if size > _TRIGGERS_BYTES:
        raise _ProjectError("CWT_RULE_FILE_OVERSIZE", str(size))
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if len(raw) != size:
        raise _ProjectError("CWT_RULE_FILE_CHANGED_DURING_READ", path.name)
    root = Path(__file__).resolve().parents[2]
    try:
        relative = path.resolve().relative_to(root).as_posix()
    except ValueError as exc:
        raise _ProjectError("CWT_RULE_PATH_OUTSIDE_REPOSITORY", path.name) from exc
    return {"path": relative, "bytes": len(raw), "sha256": digest, "raw": raw}


def _strict_json(raw: bytes) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)


def _cwt_provenance() -> dict[str, Any]:
    root = Path(__file__).resolve().parents[2]
    try:
        vendor_path = root / _VENDOR_RELATIVE
        if not vendor_path.is_file():
            vendor_path = root / _VENDOR_FALLBACK_RELATIVE
        vendor = _pin(vendor_path)
        triggers = _pin(root / _TRIGGERS_RELATIVE)
        if (vendor["bytes"] != _VENDOR_BYTES or vendor["sha256"] != _VENDOR_SHA256
                or triggers["bytes"] != _TRIGGERS_BYTES
                or triggers["sha256"] != _TRIGGERS_SHA256):
            raise _ProjectError("CWT_SOURCE_PIN_MISMATCH")
        manifest = _strict_json(vendor.pop("raw"))
        if (not isinstance(manifest, dict)
                or manifest.get("repository_url") != _REPOSITORY_URL
                or manifest.get("commit") != _VENDOR_COMMIT
                or manifest.get("license") != _VENDOR_LICENSE):
            raise _ProjectError("CWT_VENDOR_MANIFEST_MISMATCH")
        lines = triggers.pop("raw").decode("utf-8").splitlines()
        aliases: dict[str, list[dict[str, Any]]] = {}
        for key, numbers in _CWT_ALIAS_LINES.items():
            entries = []
            for number in numbers:
                if number < 1 or number > len(lines):
                    raise _ProjectError("CWT_ALIAS_LINE_OUT_OF_RANGE", f"{key}:{number}")
                text = lines[number - 1].strip()
                if not text.startswith(f"alias[trigger:{key}]"):
                    raise _ProjectError("CWT_ALIAS_LINE_MISMATCH", f"{key}:{number}")
                entries.append({"line": number, "text": text})
            aliases[key] = entries
        return {
            "status": "pinned_source_verified",
            "repository_url": _REPOSITORY_URL,
            "commit": _VENDOR_COMMIT,
            "license": _VENDOR_LICENSE,
            "vendor_manifest": vendor,
            "trigger_rules": triggers,
            "alias_sources": aliases,
            "scope": "selected direct-literal trigger signatures only; not complete CWTools schema validation",
            "engine_conditions_evaluated": False,
        }
    except Exception as exc:
        code = exc.code if isinstance(exc, _ProjectError) else "CWT_SOURCE_UNAVAILABLE"
        return {"status": "unavailable", "reason": code,
                "commit": _VENDOR_COMMIT,
                "trigger_rules": {"path": _TRIGGERS_RELATIVE.as_posix(),
                                  "bytes_expected": _TRIGGERS_BYTES,
                                  "sha256_expected": _TRIGGERS_SHA256}}


def _valid_line(value: Any) -> int:
    if type(value) is not int or value < 0 or value > 10_000_000:
        raise _ProjectError("INVALID_AST_LINE")
    return value


def _safe_source(task: Mapping[str, Any]) -> dict[str, Any]:
    source = task.get("source")
    if not isinstance(source, Mapping):
        raise _ProjectError("TASK_SOURCE_MISSING")
    path = source.get("path")
    digest = source.get("sha256")
    if (not isinstance(path, str) or not path or len(path) > 4096 or "\x00" in path
            or path.startswith(("/", "\\")) or ":" in path.split("/", 1)[0]
            or any(part in {".", ".."} for part in path.replace("\\", "/").split("/"))):
        raise _ProjectError("TASK_SOURCE_PATH_INVALID")
    if not isinstance(digest, str) or _SHA_RE.fullmatch(digest) is None:
        raise _ProjectError("TASK_SOURCE_SHA_INVALID")
    line = _valid_line(source.get("line"))
    end_line = _valid_line(source.get("end_line"))
    if end_line < line:
        raise _ProjectError("TASK_SOURCE_LINE_RANGE_INVALID")
    source_kind = source.get("source_kind")
    if source_kind is not None and (not isinstance(source_kind, str) or len(source_kind) > 128):
        raise _ProjectError("TASK_SOURCE_KIND_INVALID")
    encoding = source.get("encoding")
    if encoding is not None:
        if isinstance(encoding, str):
            valid_encoding = len(encoding.encode("utf-8", "surrogatepass")) <= 256
        elif isinstance(encoding, Mapping) and len(encoding) <= 16:
            valid_encoding = all(
                isinstance(key, str) and len(key) <= 64
                and (value is None or type(value) in (str, int, float, bool)
                     or (key == "c1_byte_slots_preserved" and isinstance(value, list)
                         and len(value) <= 5
                         and all(type(slot) is str and slot in {"81", "8d", "8f", "90", "9d"}
                                 for slot in value) and len(value) == len(set(value))))
                and (not isinstance(value, str) or len(value) <= 128)
                for key, value in encoding.items())
        else:
            valid_encoding = False
        if not valid_encoding:
            raise _ProjectError("TASK_SOURCE_ENCODING_OVERSIZE")
        encoding = deepcopy(encoding)
    return {"path": path.replace("\\", "/"), "sha256": digest,
            "source_kind": source_kind, "line": line,
            "end_line": end_line, "encoding": encoding}


def _identifier(value: Any) -> str:
    if not isinstance(value, str) or _KEY_RE.fullmatch(value) is None:
        raise _ProjectError("TASK_ID_INVALID")
    return value


def _source_at(source: Mapping[str, Any], node: Mapping[str, Any]) -> dict[str, Any]:
    return {"path": source["path"], "sha256": source["sha256"],
            "source_kind": source.get("source_kind"), "line": node["line"],
            "end_line": node["end_line"]}


def _header(node: Mapping[str, Any], path: tuple[int, ...]) -> dict[str, Any]:
    result: dict[str, Any] = {"key": node["key"], "path": list(path),
                              "line": node["line"], "end_line": node["end_line"]}
    for key in ("kind", "assignment", "operator", "raw_key", "raw_value", "value"):
        value = node.get(key)
        if value is None or type(value) in (str, int, float, bool):
            if not isinstance(value, str) or len(value.encode("utf-8", "surrogatepass")) <= 512:
                result[key] = value
    return result


def _validate_node(node: Any, *, depth: int, state: dict[str, Any]) -> Mapping[str, Any]:
    if depth > MAX_DEPTH:
        raise _ProjectError("AST_DEPTH_LIMIT")
    if not isinstance(node, Mapping) or len(node) > 64:
        raise _ProjectError("AST_NODE_INVALID")
    identity = id(node)
    seen = state["seen"]
    if identity in seen:
        raise _ProjectError("AST_CYCLE_OR_SHARED_NODE")
    seen.add(identity)
    key = node.get("key")
    if not isinstance(key, str) or len(key) > 256 or not key or "\x00" in key:
        raise _ProjectError("AST_KEY_INVALID")
    children = node.get("children")
    if not isinstance(children, list) or len(children) > MAX_CHILDREN:
        raise _ProjectError("AST_CHILDREN_INVALID")
    line = _valid_line(node.get("line"))
    end_line = _valid_line(node.get("end_line"))
    if end_line < line:
        raise _ProjectError("AST_LINE_RANGE_INVALID")
    if node.get("kind") not in {"block", "scalar", "bare", None}:
        raise _ProjectError("AST_KIND_INVALID")
    assignment = node.get("assignment")
    if assignment is not None and (not isinstance(assignment, str) or len(assignment) > 4):
        raise _ProjectError("AST_ASSIGNMENT_INVALID")
    scalar = {key: value for key, value in node.items() if key != "children"}
    scalar_size = len(_json_bytes(scalar))
    if scalar_size > MAX_NODE_SCALAR_BYTES:
        raise _ProjectError("AST_SCALAR_BYTES_LIMIT")
    state["trigger_scalar_bytes"] += scalar_size
    if state["trigger_scalar_bytes"] > MAX_TRIGGER_ROOT_BYTES:
        raise _ProjectError("TRIGGER_ROOT_BYTES_LIMIT")
    state["nodes"] += 1
    if state["nodes"] > MAX_NODES_PER_TASK:
        raise _ProjectError("AST_TASK_NODE_LIMIT")
    counters = state["counters"]
    counters["nodes_visited"] += 1
    if counters["nodes_visited"] > MAX_TOTAL_NODES:
        raise _ProjectError("AST_TOTAL_NODE_LIMIT")
    return node


def _validate_trigger_tree(root: Any, *, state: dict[str, Any]) -> None:
    """Validate a tree before serialization/copying so oversized inputs fail closed."""
    state["trigger_scalar_bytes"] = 0
    stack: list[tuple[Any, int]] = [(root, 0)]
    while stack:
        node_value, depth = stack.pop()
        node = _validate_node(node_value, depth=depth, state=state)
        children = node["children"]
        for child in reversed(children):
            stack.append((child, depth + 1))


def _classify_argument(value: Any, raw_value: Any, argument: str) -> tuple[str | int | None, str | None]:
    if type(value) is bool or value is None:
        return None, "ARGUMENT_NOT_LITERAL_SCALAR"
    if isinstance(value, (int, float)):
        lexical = str(value)
    elif isinstance(value, str):
        lexical = value
    else:
        return None, "ARGUMENT_NOT_LITERAL_SCALAR"
    if len(lexical) > 256 or "\x00" in lexical:
        return None, "ARGUMENT_LITERAL_INVALID"
    if lexical.casefold() in _DYNAMIC_SYMBOLS:
        return None, "DYNAMIC_SCOPE_SYMBOL_UNRESOLVED"

    if argument == "province_id":
        if isinstance(value, int) and not isinstance(value, bool):
            number = value
        elif isinstance(value, str) and _PROVINCE_RE.fullmatch(value):
            number = int(value, 10)
        else:
            return None, "PROVINCE_ID_NOT_LITERAL_OR_OUT_OF_RANGE"
        if not 1 <= number <= 65535:
            return None, "PROVINCE_ID_NOT_LITERAL_OR_OUT_OF_RANGE"
        return number, None
    if argument == "country_tag":
        if isinstance(value, str) and _TAG_RE.fullmatch(value):
            return value, None
        return None, "COUNTRY_TAG_NOT_LITERAL"
    if argument in {"area_identifier", "region_identifier", "rebel_type"}:
        if isinstance(value, str) and _REFERENCE_RE.fullmatch(value):
            return value, None
        return None, "REFERENCE_IDENTIFIER_NOT_LITERAL"
    return None, "CWT_ARGUMENT_TYPE_UNSUPPORTED"


def _classify_node(node: Mapping[str, Any]) -> tuple[dict[str, Any] | None, str | None, tuple[str, ...]]:
    key = node.get("key")
    variants = _RULES.get(key) if isinstance(key, str) else None
    if variants is None:
        return None, None, ()
    candidate_fields = tuple(sorted({field for variant in variants for field in variant["fields"]}))
    children = node.get("children")
    if (node.get("kind") != "scalar" or node.get("assignment") != "="
            or not isinstance(children, list) or children):
        return None, "TARGET_ARGUMENT_NOT_DIRECT_SCALAR", candidate_fields
    value = node.get("value")
    raw_value = node.get("raw_value")
    if raw_value is not None and (not isinstance(raw_value, str) or len(raw_value) > 512):
        return None, "RAW_LITERAL_INVALID", candidate_fields
    ordered_variants = variants
    # The CWT `area` alias has a province-id overload as well as a named-area
    # overload. Numeric literals select the explicitly typed province-id form.
    value_lexical = str(value) if type(value) in (int, float) else value
    if key == "area" and isinstance(value_lexical, str) and _PROVINCE_RE.fullmatch(value_lexical):
        ordered_variants = tuple(sorted(variants,
                                        key=lambda item: item["argument"] != "province_id"))
    for variant in ordered_variants:
        normalized, reason = _classify_argument(value, raw_value, variant["argument"])
        if reason is None:
            return ({"normalized_value": normalized,
                     "reference_kind": variant["reference_kind"],
                     "cwt_argument_type": variant["argument"],
                     "fields": variant["fields"],
                     "cwt_lines": variant["lines"]}, None, candidate_fields)
    # Keep the useful most-specific failure (dynamic-scope marker before generic type failure).
    reasons = [_classify_argument(value, raw_value, variant["argument"])[1]
               for variant in variants]
    reason = ("DYNAMIC_SCOPE_SYMBOL_UNRESOLVED" if "DYNAMIC_SCOPE_SYMBOL_UNRESOLVED" in reasons
              else reasons[-1] or "TARGET_ARGUMENT_UNCLASSIFIED")
    return None, reason, candidate_fields


def _path_text(path: tuple[int, ...], *, trigger_index: int, repeated: bool) -> str:
    prefix = f"trigger[{trigger_index}]" if repeated else "trigger"
    return prefix + "".join(f".children[{index}]" for index in path)


def _gap(reason: str, *, task_index: int, root_id: Any, task_id: Any,
         trigger_index: int | None = None, path: tuple[int, ...] | None = None,
         key: Any = None, source: Mapping[str, Any] | None = None,
         field: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"reason": reason, "task_index": task_index,
                              "root_id": root_id, "task_id": task_id}
    if field is not None:
        result["field"] = field
    if trigger_index is not None:
        result["trigger_index"] = trigger_index
    if path is not None:
        result["path"] = list(path)
    if isinstance(key, str):
        result["key"] = key
    if source is not None:
        result["source"] = dict(source)
    return result


def _walk_trigger(root: Mapping[str, Any], *, trigger_index: int, repeated: bool,
                  task_index: int, task: Mapping[str, Any], source: Mapping[str, Any],
                  state: dict[str, Any], contexts: list[dict[str, Any]],
                  rules_by_field: dict[str, list[dict[str, Any]]],
                  gaps_by_field: dict[str, list[dict[str, Any]]],
                  counters: dict[str, int], classifier=None) -> None:
    _validate_trigger_tree(root, state=state)
    root_bytes = _json_bytes(root)
    if len(root_bytes) > MAX_TRIGGER_ROOT_BYTES:
        raise _ProjectError("TRIGGER_ROOT_BYTES_LIMIT")
    context_id = f"t{task_index}:trigger{trigger_index}"
    context = {"context_id": context_id, "task_index": task_index,
               "root_id": task["root_id"], "task_id": task["task_id"],
               "trigger_index": trigger_index, "source": dict(source),
               "trigger_source": _source_at(source, root),
               "trigger_ast": deepcopy(dict(root)),
               "trigger_ast_bytes": len(root_bytes),
               "ast_semantics": "preserved_structural_condition; no evaluation"}
    contexts.append(context)
    counters["context_bytes"] += len(root_bytes)
    if counters["context_bytes"] > MAX_TOTAL_CONTEXT_BYTES:
        contexts.pop()
        counters["context_bytes"] -= len(root_bytes)
        raise _ProjectError("TOTAL_TRIGGER_CONTEXT_BYTES_LIMIT")

    def visit(node_value: Any, path: tuple[int, ...], ancestors: tuple[Mapping[str, Any], ...], depth: int) -> None:
        node = node_value
        key = node["key"]
        classification, reason, candidate_fields = (
            classifier(node, ancestors) if classifier is not None else _classify_node(node))
        if classification is not None or candidate_fields:
            if classification is None:
                counters["candidate_rules_unresolved"] += 1
                for field in candidate_fields:
                    if len(gaps_by_field[field]) < MAX_GAPS_PER_TASK:
                        gaps_by_field[field].append(_gap(
                            reason or "TARGET_ARGUMENT_UNCLASSIFIED", task_index=task_index,
                            root_id=task["root_id"], task_id=task["task_id"],
                            trigger_index=trigger_index, path=path, key=key,
                            source=_source_at(source, node), field=field))
            else:
                if counters["classified_rules"] >= MAX_TOTAL_RULES:
                    raise _ProjectError("TOTAL_RULE_LIMIT")
                counters["classified_rules"] += 1
                parent_headers = [_header(parent, path[:index])
                                  for index, parent in enumerate(ancestors)]
                logic_keys = {"not", "or", "and"}
                logical_ancestors = [header for header in parent_headers
                                     if str(header["key"]).casefold() in logic_keys]
                record = {
                    "kind": classification.get("record_kind", "literal_reference"),
                    "semantics": "declared_static_condition_reference",
                    "requiredness": "not_inferred",
                    "evaluated": False,
                    "scope_targets_resolved": False,
                    "field_classifications": list(classification["fields"]),
                    "command_key": key,
                    "assignment": node.get("assignment"),
                    "literal_value": classification["normalized_value"],
                    "raw_value": node.get("raw_value"),
                    "reference_kind": classification["reference_kind"],
                    "cwt_argument_type": classification["cwt_argument_type"],
                    "cwt_rule_lines": list(classification["cwt_lines"]),
                    "root_id": task["root_id"], "task_id": task["task_id"],
                    "task_index": task_index,
                    "trigger_context_id": context_id,
                    "trigger_index": trigger_index,
                    "path": list(path),
                    "path_text": _path_text(path, trigger_index=trigger_index,
                                             repeated=repeated),
                    "ancestor_headers": parent_headers,
                    "logical_ancestors": logical_ancestors,
                    "scope_flow": "unresolved",
                    "source": _source_at(source, node),
                }
                if record["kind"] == "symbolic_condition_reference":
                    record["symbolic_value"] = record.pop("literal_value")
                extras = {name: classification[name] for name in
                          ("static_scope", "expected_scope_type", "target_resolution")
                          if name in classification}
                if extras:
                    extra_bytes = len(_json_bytes(extras))
                    total = counters.get("extra_reference_bytes", 0) + extra_bytes
                    if extra_bytes > MAX_NODE_SCALAR_BYTES or total > MAX_TOTAL_CONTEXT_BYTES:
                        raise _ProjectError("EXTRA_REFERENCE_BYTES_LIMIT")
                    counters["extra_reference_bytes"] = total
                    record.update(deepcopy(extras))
                for field in classification["fields"]:
                    if len(rules_by_field[field]) < MAX_RULES_PER_TASK:
                        rules_by_field[field].append(record)
                    else:
                        counters["candidate_rules_unresolved"] += 1
                        if len(gaps_by_field[field]) < MAX_GAPS_PER_TASK:
                            gaps_by_field[field].append(_gap(
                                "RULE_TASK_LIMIT", task_index=task_index,
                                root_id=task["root_id"], task_id=task["task_id"],
                                trigger_index=trigger_index, path=path, key=key,
                                source=_source_at(source, node), field=field))
        else:
            counters["unclassified_nodes"] += 1
        children = node["children"]
        for index, child in enumerate(children):
            visit(child, path + (index,), ancestors + (node,), depth + 1)

    visit(root, (), (), 0)


def _unknown_task(task: Any, index: int, reason: str) -> dict[str, Any]:
    root_id = task.get("root_id") if isinstance(task, Mapping) else None
    task_id = task.get("task_id") if isinstance(task, Mapping) else None
    return {"task_index": index, "root_id": root_id, "task_id": task_id,
            "status": "unknown", "reason": reason}


def project_target_rules(tasks: Sequence[Mapping[str, Any]], field: str, *,
                         _classifier=None, _extra_provenance=None) -> dict[str, Any]:
    """Inventory supported literal references for one M03 field.

    Positive results are partial static evidence. No result means unknown, not
    a known-empty list, because an unclassified trigger can contain other rules.
    """
    if not isinstance(field, str) or field not in SUPPORTED_FIELDS:
        raise ValueError(f"unsupported_target_field:{field!r}")
    cwt = _cwt_provenance()
    provenance: dict[str, Any] = {
        "source": "MissionTargetRuleProjector",
        "mode": "static_rules",
        "field": field,
        "cwtools": cwt,
        "trigger_ast_schema_validated_by_full_engine": False,
        "engine_conditions_evaluated": False,
        "limits": {"max_tasks": MAX_TASKS,
                   "max_trigger_roots_per_task": MAX_TRIGGER_ROOTS_PER_TASK,
                   "max_depth": MAX_DEPTH, "max_children": MAX_CHILDREN,
                   "max_nodes_per_task": MAX_NODES_PER_TASK,
                   "max_total_nodes": MAX_TOTAL_NODES,
                   "max_rules_per_task": MAX_RULES_PER_TASK,
                   "max_gaps_per_task": MAX_GAPS_PER_TASK,
                   "max_trigger_root_bytes": MAX_TRIGGER_ROOT_BYTES,
                   "max_total_context_bytes": MAX_TOTAL_CONTEXT_BYTES,
                   "max_output_bytes": MAX_OUTPUT_BYTES},
    }
    if _extra_provenance is not None:
        if not isinstance(_extra_provenance, Mapping) or len(_json_bytes(_extra_provenance)) > 32 * 1024:
            raise ValueError("TARGET_EXTRA_PROVENANCE_INVALID")
        provenance["extended_reference_projection"] = deepcopy(dict(_extra_provenance))
    if cwt.get("status") != "pinned_source_verified":
        provenance["gaps"] = {"CWT_SOURCE_UNAVAILABLE": 1}
        return {"field": field, "status": "unavailable", "reason": "CWT_SOURCE_UNAVAILABLE",
                "complete": False, "provenance": provenance}
    if not isinstance(tasks, (list, tuple)):
        provenance["gaps"] = {"TASKS_NOT_SEQUENCE": 1}
        return {"field": field, "status": "unknown", "reason": "TASKS_NOT_SEQUENCE",
                "complete": False, "provenance": provenance}

    task_rows: list[dict[str, Any]] = []
    contexts: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    counts: dict[str, int] = {"nodes_visited": 0, "unclassified_nodes": 0,
                              "candidate_rules_unresolved": 0, "context_bytes": 0,
                              "classified_rules": 0,
                              "truncated_tasks": max(0, len(tasks) - MAX_TASKS)}
    total = min(len(tasks), MAX_TASKS)
    partial = total != len(tasks)
    for index, task in enumerate(tasks[:MAX_TASKS]):
        task_rules = {name: [] for name in SUPPORTED_FIELDS}
        task_gaps = {name: [] for name in SUPPORTED_FIELDS}
        context_start = len(contexts)
        context_bytes_start = counts["context_bytes"]
        task_state: dict[str, Any] = {"nodes": 0, "seen": set(), "counters": counts,
                                      "trigger_scalar_bytes": 0}
        try:
            if not isinstance(task, Mapping):
                raise _ProjectError("TASK_NOT_MAPPING")
            root_id = _identifier(task.get("root_id"))
            task_id = _identifier(task.get("task_id"))
            source = _safe_source(task)
            trigger_value = task.get("trigger", None)
            if trigger_value is None:
                raise _ProjectError("TRIGGER_AST_MISSING")
            if isinstance(trigger_value, Mapping):
                roots = [trigger_value]
                repeated = False
            elif isinstance(trigger_value, (list, tuple)):
                if not trigger_value or len(trigger_value) > MAX_TRIGGER_ROOTS_PER_TASK:
                    raise _ProjectError("TRIGGER_ROOT_COUNT_INVALID")
                roots = list(trigger_value)
                repeated = True
            else:
                raise _ProjectError("TRIGGER_AST_INVALID")
            task_record = {"task_index": index, "root_id": root_id, "task_id": task_id,
                           "source": source, "status": "known",
                           "trigger_root_count": len(roots), "rule_count": 0,
                           "candidate_gap_count": 0, "context_ids": []}
            for trigger_index, root in enumerate(roots):
                if not isinstance(root, Mapping):
                    raise _ProjectError("TRIGGER_ROOT_NOT_MAPPING")
                task_record["context_ids"].append(f"t{index}:trigger{trigger_index}")
                _walk_trigger(root, trigger_index=trigger_index, repeated=repeated,
                              task_index=index, task=task_record, source=source,
                              state=task_state, contexts=contexts,
                              rules_by_field=task_rules, gaps_by_field=task_gaps,
                              counters=counts, classifier=_classifier)
            task_record["rule_count"] = sum(len(values) for values in task_rules.values())
            task_record["candidate_gap_count"] = sum(len(values) for values in task_gaps.values())
            task_rows.append(task_record)
            records.extend(task_rules[field])
            gaps.extend(task_gaps[field])
            if task_gaps[field]:
                partial = True
        except _ProjectError as exc:
            del contexts[context_start:]
            counts["context_bytes"] = context_bytes_start
            task_row = _unknown_task(task, index, exc.code)
            task_rows.append(task_row)
            gaps.append(_gap(exc.code, task_index=index,
                             root_id=task.get("root_id") if isinstance(task, Mapping) else None,
                             task_id=task.get("task_id") if isinstance(task, Mapping) else None,
                             field=field))
            partial = True
        except Exception as exc:
            del contexts[context_start:]
            counts["context_bytes"] = context_bytes_start
            task_rows.append(_unknown_task(task, index, "PROJECTION_EXCEPTION"))
            gaps.append(_gap("PROJECTION_EXCEPTION", task_index=index,
                             root_id=task.get("root_id") if isinstance(task, Mapping) else None,
                             task_id=task.get("task_id") if isinstance(task, Mapping) else None,
                             field=field))
            provenance.setdefault("exception_types", {})[type(exc).__name__] = (
                provenance.setdefault("exception_types", {}).get(type(exc).__name__, 0) + 1)
            partial = True

    counts["nodes_visited"] = min(counts["nodes_visited"], MAX_TOTAL_NODES)
    gap_counts: dict[str, int] = {}
    for item in gaps:
        gap_counts[item["reason"]] = gap_counts.get(item["reason"], 0) + 1
    provenance["gaps"] = gap_counts
    provenance["nodes_visited"] = counts["nodes_visited"]
    provenance["unclassified_trigger_nodes"] = counts["unclassified_nodes"]
    provenance["unresolved_candidate_rules"] = counts["candidate_rules_unresolved"]
    provenance["truncated_task_count"] = counts["truncated_tasks"]

    if not records:
        reason = "TARGET_REFERENCES_UNRESOLVED" if gaps else "NO_CLASSIFIED_LITERAL_REFERENCES"
        result = {"field": field, "status": "unknown", "reason": reason,
                  "complete": False, "provenance": provenance,
                  "tasks": task_rows, "gaps": gaps}
    else:
        value = {
            "field": field,
            "semantics": "static_declared_literal_mission_target_conditions",
            "evaluated": False,
            "scope_targets_resolved": False,
            "complete": False,
            "rule_count": len(records),
            "task_count": len(tasks),
            "materialized_task_count": len(task_rows),
            "truncated_task_count": counts["truncated_tasks"],
            "rules": records,
            "trigger_contexts": contexts,
            "tasks": task_rows,
            "gaps": gaps,
        }
        status = "partial" if partial or counts["truncated_tasks"] else "known"
        result = {"field": field, "status": status, "complete": False,
                  "value": value, "provenance": provenance}
    if len(_json_bytes(result)) > MAX_OUTPUT_BYTES:
        # Fail closed rather than returning a silently truncated target inventory.
        return {"field": field, "status": "unknown", "reason": "OUTPUT_BYTES_LIMIT",
                "complete": False,
                "provenance": {**provenance, "gaps": {"OUTPUT_BYTES_LIMIT": 1}},
                "tasks": task_rows[:MAX_TASKS]}
    return result

