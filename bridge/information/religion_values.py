"""Strict public projections for captured and configured religion data."""
from __future__ import annotations

from copy import deepcopy
from pathlib import PurePosixPath
import re
from typing import Any

from ..native_text import decode_native_text_hex
from .model import canonical


MAX_RULE_AST_NODES = 32768
MAX_RULE_AST_DEPTH = 64
MAX_RULE_AST_JSON_BYTES = 2 * 1024 * 1024

_KEY = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_NAME_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){1,128}\Z")
_ABSOLUTE_PATH = re.compile(r"(?:[A-Za-z]:[\\/]|^\\\\|^/)")
_POINTER = re.compile(r"0x[0-9a-fA-F]{6,}", re.IGNORECASE)
_OPERATORS = {None, "=", "==", "!=", "<", ">", "<=", ">=", "?="}
_IDENTITY_KEYS = {"religion_key", "religion_group_key"}
_SOURCE_PIN_KEYS = {
    "configuration_sha256", "definitions_sha256", "parser_manifest_sha256",
    "cwt_sha256", "cwt_commit",
}
_RULE_FLAGS = {
    "conditions_evaluated": False,
    "effects_executed": False,
    "runtime_state_observed": False,
}


def _fail(code: str) -> None:
    raise ValueError(code)


def _valid_key(value: Any) -> bool:
    return type(value) is str and _KEY.fullmatch(value) is not None


def identity_value(value: Any) -> dict[str, str]:
    """Validate and copy the exact captured religion identity pair."""
    if type(value) is not dict or set(value) != _IDENTITY_KEYS:
        _fail("RELIGION_IDENTITY_SHAPE_INVALID")
    if not _valid_key(value["religion_key"]):
        _fail("RELIGION_IDENTITY_RELIGION_KEY_INVALID")
    if not _valid_key(value["religion_group_key"]):
        _fail("RELIGION_IDENTITY_GROUP_KEY_INVALID")
    return deepcopy(value)


def faith_value(value: Any) -> dict[str, Any]:
    """Validate and copy the legacy faith display-name/icon-request value."""
    if (type(value) is not dict
            or set(value) != {"primary_religion_name", "icon_frame_request"}):
        _fail("RELIGION_FAITH_VALUE_SHAPE_INVALID")
    name = value["primary_religion_name"]
    if (type(name) is not dict
            or set(name) != {"text", "raw_hex", "encoding"}):
        _fail("RELIGION_FAITH_NAME_SHAPE_INVALID")
    text, raw_hex, encoding = name["text"], name["raw_hex"], name["encoding"]
    icon_frame_request = value["icon_frame_request"]
    if (type(text) is not str or not text or "\x00" in text
            or type(raw_hex) is not str or _NAME_HEX.fullmatch(raw_hex) is None
            or type(encoding) is not str or encoding != "eu4_escape"
            or type(icon_frame_request) is not int
            or not 0 <= icon_frame_request <= 0xFFFF_FFFF):
        _fail("RELIGION_FAITH_VALUE_INVALID")
    raw = bytes.fromhex(raw_hex)
    if not raw or b"\x00" in raw:
        _fail("RELIGION_FAITH_NAME_BYTES_INVALID")
    try:
        decoded = decode_native_text_hex(raw_hex, codec="eu4_escape", max_bytes=128)
    except (TypeError, ValueError) as exc:
        raise ValueError("RELIGION_FAITH_NAME_DECODE_INVALID") from exc
    if not decoded or text != decoded:
        _fail("RELIGION_FAITH_NAME_DECODE_MISMATCH")
    return {
        "primary_religion_name": {
            "text": decoded,
            "raw_hex": raw_hex.lower(),
            "encoding": "eu4_escape",
        },
        "icon_frame_request": icon_frame_request,
    }


def _safe_ast_text(value: Any) -> bool:
    return (type(value) is str and len(value) <= 65536 and "\x00" not in value
            and _ABSOLUTE_PATH.search(value) is None
            and _POINTER.search(value) is None)


def _safe_relative_file(value: Any) -> bool:
    if (type(value) is not str or not value or len(value) > 512
            or "\x00" in value or "\\" in value or ":" in value
            or value.startswith("/")):
        return False
    path = PurePosixPath(value)
    parts = path.parts
    return (not path.is_absolute() and len(parts) >= 3
            and parts[:2] == ("common", "religions")
            and parts[-1].endswith(".txt")
            and all(part not in ("", ".", "..") for part in parts)
            and value == "/".join(parts))


def _source_pins(value: Any) -> dict[str, str]:
    if type(value) is not dict or set(value) != _SOURCE_PIN_KEYS:
        _fail("RELIGION_RULE_SOURCE_PINS_INVALID")
    for name in ("configuration_sha256", "definitions_sha256",
                 "parser_manifest_sha256", "cwt_sha256"):
        if type(value[name]) is not str or _HEX64.fullmatch(value[name]) is None:
            _fail("RELIGION_RULE_SOURCE_PIN_INVALID")
    if type(value["cwt_commit"]) is not str or _HEX40.fullmatch(value["cwt_commit"]) is None:
        _fail("RELIGION_RULE_SOURCE_PIN_INVALID")
    return {name: value[name] for name in (
        "configuration_sha256", "definitions_sha256", "parser_manifest_sha256",
        "cwt_sha256", "cwt_commit",
    )}


def _syntax_tree(value: Any) -> dict[str, Any]:
    count = 0
    estimated_chars = 0
    seen: set[int] = set()

    def visit(node: Any, depth: int) -> dict[str, Any]:
        nonlocal count, estimated_chars
        count += 1
        if count > MAX_RULE_AST_NODES or depth > MAX_RULE_AST_DEPTH:
            _fail("RELIGION_RULE_AST_LIMIT")
        if type(node) is not dict:
            _fail("RELIGION_RULE_AST_NODE_INVALID")
        identity = id(node)
        if identity in seen:
            _fail("RELIGION_RULE_AST_CYCLE_OR_ALIAS")
        seen.add(identity)
        required = {"key", "assignment", "kind", "value", "children", "line", "end_line"}
        optional = {"source_column", "end_column"}
        if not required <= set(node) or set(node) - required - optional:
            _fail("RELIGION_RULE_AST_NODE_KEYS_INVALID")
        key, assignment = node["key"], node["assignment"]
        kind, node_value, children = node["kind"], node["value"], node["children"]
        line, end_line = node["line"], node["end_line"]
        if (not _safe_ast_text(key)
                or assignment is not None and (type(assignment) is not str or assignment not in _OPERATORS)
                or type(kind) is not str or kind not in {"block", "scalar", "bare"}
                or node_value is not None and not _safe_ast_text(node_value)
                or type(children) is not list
                or type(line) is not int or line < 1
                or type(end_line) is not int or end_line < line):
            _fail("RELIGION_RULE_AST_NODE_INVALID")
        if (kind == "block" and node_value is not None
                or kind == "scalar" and (node_value is None or assignment is None or children)
                or kind == "bare" and (node_value is not None or assignment is not None or children)):
            _fail("RELIGION_RULE_AST_NODE_INVALID")
        for name in optional:
            if name in node and (type(node[name]) is not int or node[name] < 0):
                _fail("RELIGION_RULE_AST_LOCATION_INVALID")
        estimated_chars += len(key) + (len(node_value) if node_value is not None else 0) + 128
        if estimated_chars * 6 > MAX_RULE_AST_JSON_BYTES:
            _fail("RELIGION_RULE_AST_BYTE_LIMIT")
        out = {
            "key": key,
            "assignment": assignment,
            "kind": kind,
            "value": node_value,
            "children": [visit(child, depth + 1) for child in children],
            "line": line,
            "end_line": end_line,
        }
        for name in ("source_column", "end_column"):
            if name in node:
                out[name] = node[name]
        return out

    result = visit(value, 0)
    try:
        if len(canonical(result).encode("utf-8")) > MAX_RULE_AST_JSON_BYTES:
            _fail("RELIGION_RULE_AST_BYTE_LIMIT")
    except (TypeError, ValueError, UnicodeError) as exc:
        if isinstance(exc, ValueError) and str(exc).startswith("RELIGION_RULE_"):
            raise
        raise ValueError("RELIGION_RULE_AST_JSON_INVALID") from exc
    return result


def rule_value(record: Any, expected_key: str, *, group: bool = False) -> dict[str, Any]:
    """Project one known definition into a small, static, path-safe DTO."""
    if not _valid_key(expected_key) or type(group) is not bool:
        _fail("RELIGION_RULE_EXPECTATION_INVALID")
    if type(record) is not dict:
        _fail("RELIGION_RULE_RECORD_INVALID")
    status = record.get("status")
    if type(status) is str and status == "unknown":
        return {"status": "unknown", "reason": "RELIGION_RULES_UNAVAILABLE"}
    if type(status) is not str or status != "known":
        _fail("RELIGION_RULE_STATUS_INVALID")

    key_name = "religion_group_key" if group else "religion_key"
    expected_fields = {
        "status", key_name, "definition", "source", "source_pins", "syntax",
        "conditions_evaluated", "effects_executed", "runtime_state_observed",
    }
    if not group:
        expected_fields.add("religion_group_key")
    if set(record) != expected_fields:
        _fail("RELIGION_RULE_RECORD_KEYS_INVALID")
    if not _valid_key(record[key_name]) or record[key_name] != expected_key:
        _fail("RELIGION_RULE_KEY_MISMATCH")
    if not group and not _valid_key(record["religion_group_key"]):
        _fail("RELIGION_RULE_GROUP_KEY_INVALID")
    if any(record[name] is not False for name in _RULE_FLAGS):
        _fail("RELIGION_RULE_SEMANTICS_INVALID")

    definition = record["definition"]
    if (type(definition) is not dict
            or set(definition) != {"relative_file", "line", "file_sha256", "source_kind"}
            or not _safe_relative_file(definition["relative_file"])
            or type(definition["line"]) is not int or definition["line"] < 1
            or type(definition["file_sha256"]) is not str
            or _HEX64.fullmatch(definition["file_sha256"]) is None
            or type(definition["source_kind"]) is not str
            or definition["source_kind"] not in {"basegame", "enabled_mod"}):
        _fail("RELIGION_RULE_DEFINITION_INVALID")
    pins = _source_pins(record["source_pins"])
    source = _source_pins(record["source"])
    if source != pins:
        _fail("RELIGION_RULE_SOURCE_PINS_MISMATCH")
    syntax = _syntax_tree(record["syntax"])
    output = {
        "status": "known",
        "syntax": syntax,
        "definition": {
            "relative_file": definition["relative_file"],
            "line": definition["line"],
            "file_sha256": definition["file_sha256"],
            "source_kind": definition["source_kind"],
        },
        "source_pins": pins,
        "static_semantics": dict(_RULE_FLAGS),
    }
    try:
        if len(canonical(output).encode("utf-8")) > MAX_RULE_AST_JSON_BYTES:
            _fail("RELIGION_RULE_AST_BYTE_LIMIT")
    except (TypeError, ValueError, UnicodeError) as exc:
        if isinstance(exc, ValueError) and str(exc).startswith("RELIGION_RULE_"):
            raise
        raise ValueError("RELIGION_RULE_OUTPUT_INVALID") from exc
    return deepcopy(output)


__all__ = ["identity_value", "faith_value", "rule_value"]
