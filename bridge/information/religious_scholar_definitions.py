"""Static mapping of religious schools to their displayed scholar modifiers.

This wrapper reuses the effective-definition resolver and syntax AST exposed by
``ReligionDefinitionIndex``. It never evaluates conditions or effects and does
not infer whether any modifier is active in a running game.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from pathlib import PurePosixPath
import re
from typing import Any, Mapping

from . import religion_definitions as _religion_definitions
from .imperial_reform_definitions import AST_ASSIGNMENTS as _AST_ASSIGNMENTS
from .model import canonical


MAX_GROUPS = 256
MAX_TOTAL_SCHOOLS = 2048
MAX_TOTAL_AST_NODES = 131072
MAX_TOTAL_AST_BYTES = 8 * 1024 * 1024
MAX_MAPPING_JSON_BYTES = 4 * 1024 * 1024

_AST_REQUIRED_KEYS = frozenset({
    "key", "assignment", "kind", "value", "children", "line", "end_line",
})
_AST_OPTIONAL_KEYS = frozenset({"source_column", "end_column"})
_PIN_KEYS = frozenset({
    "configuration_sha256", "definitions_sha256", "parser_manifest_sha256",
    "cwt_sha256", "cwt_commit",
})
_HASH64 = re.compile(r"[0-9a-f]{64}\Z")
_HASH40 = re.compile(r"[0-9a-f]{40}\Z")


class _MappingUnavailable(ValueError):
    pass


class _EnumerableReligionDefinitionIndex(_religion_definitions.ReligionDefinitionIndex):
    """Add bounded enumeration using the base index's already parsed groups.

    The compatibility point is the current private ``_groups`` index built by
    ReligionDefinitionIndex._parse_definitions. No files are reparsed here;
    a future change to that structure fails closed until this adapter is updated.
    """

    def group_keys(self) -> list[str]:
        self.assert_current()
        groups = getattr(self, "_groups", None)
        if not isinstance(groups, dict) or len(groups) > MAX_GROUPS:
            raise ValueError("RELIGIOUS_SCHOLAR_GROUP_INDEX_UNAVAILABLE")
        keys: list[str] = []
        for records in groups.values():
            if not isinstance(records, list) or not records:
                raise ValueError("RELIGIOUS_SCHOLAR_GROUP_INDEX_INVALID")
            for record in records:
                if not isinstance(record, Mapping):
                    raise ValueError("RELIGIOUS_SCHOLAR_GROUP_RECORD_INVALID")
                key = record.get("religion_group_key")
                if (not isinstance(key, str)
                        or not _religion_definitions.RELIGION_KEY_RE.fullmatch(key)):
                    raise ValueError("RELIGIOUS_SCHOLAR_GROUP_KEY_INVALID")
                keys.append(key)
                if len(keys) > MAX_GROUPS:
                    raise ValueError("RELIGIOUS_SCHOLAR_GROUP_LIMIT")
        self.assert_current()
        return sorted(keys, key=lambda item: (item.casefold(), item))


def _unknown() -> dict[str, Any]:
    return {
        "status": "unknown",
        "reason": "RELIGIOUS_SCHOLAR_MAPPING_UNAVAILABLE",
    }


def _context_pins(context: Any) -> dict[str, str]:
    if not isinstance(context, Mapping) or context.get("status") != "ready":
        raise _MappingUnavailable("index_context_unready")
    parser = context.get("script_parser")
    cwt = context.get("cwt_contract")
    schema = cwt.get("schema_file") if isinstance(cwt, Mapping) else None
    if not isinstance(parser, Mapping) or not isinstance(schema, Mapping):
        raise _MappingUnavailable("index_context_pins_missing")
    pins = {
        "configuration_sha256": context.get("configuration_sha256"),
        "definitions_sha256": context.get("definitions_sha256"),
        "parser_manifest_sha256": parser.get("manifest_sha256"),
        "cwt_sha256": schema.get("sha256"),
        "cwt_commit": cwt.get("commit"),
    }
    if (set(pins) != _PIN_KEYS
            or any(type(pins[name]) is not str for name in _PIN_KEYS)
            or any(not _HASH64.fullmatch(pins[name]) for name in _PIN_KEYS - {"cwt_commit"})
            or not _HASH40.fullmatch(pins["cwt_commit"])):
        raise _MappingUnavailable("index_context_pins_invalid")
    return pins  # type: ignore[return-value]


def _validate_definition(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "relative_file", "line", "file_sha256", "source_kind",
    }:
        raise _MappingUnavailable("group_definition_source_invalid")
    relative = value.get("relative_file")
    if (type(relative) is not str or "\\" in relative or "\x00" in relative
            or relative.startswith("/") or ":" in relative):
        raise _MappingUnavailable("group_definition_path_invalid")
    path = PurePosixPath(relative)
    if (not path.parts or path.parts[0] != "common"
            or len(path.parts) < 3 or path.parts[1] != "religions"
            or path.suffix.casefold() != ".txt" or ".." in path.parts):
        raise _MappingUnavailable("group_definition_path_invalid")
    if (type(value.get("line")) is not int or value["line"] < 1
            or type(value.get("file_sha256")) is not str
            or not _HASH64.fullmatch(value["file_sha256"])
            or value.get("source_kind") not in {"basegame", "mod"}):
        raise _MappingUnavailable("group_definition_source_invalid")
    return deepcopy(dict(value))


def _validate_group_result(
    result: Any,
    group_key: str,
    expected_pins: Mapping[str, str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    required = {
        "status", "religion_group_key", "definition", "source", "source_pins",
        "syntax", "conditions_evaluated", "effects_executed", "runtime_state_observed",
    }
    if not isinstance(result, Mapping) or set(result) != required:
        raise _MappingUnavailable("group_definition_shape_invalid")
    if (result.get("status") != "known"
            or result.get("religion_group_key") != group_key
            or result.get("conditions_evaluated") is not False
            or result.get("effects_executed") is not False
            or result.get("runtime_state_observed") is not False):
        raise _MappingUnavailable("group_definition_semantics_invalid")
    pins = result.get("source_pins")
    if (not isinstance(pins, Mapping) or set(pins) != _PIN_KEYS
            or dict(pins) != dict(expected_pins)
            or result.get("source") != dict(expected_pins)):
        raise _MappingUnavailable("group_definition_pins_invalid")
    definition = _validate_definition(result.get("definition"))
    syntax = result.get("syntax")
    if not isinstance(syntax, Mapping):
        raise _MappingUnavailable("group_definition_ast_missing")
    return definition, dict(syntax)


def _validate_ast(root: Mapping[str, Any]) -> tuple[int, int]:
    pending: list[tuple[Any, int]] = [(root, 0)]
    seen: set[int] = set()
    count = 0
    estimated_chars = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > _religion_definitions.MAX_DECLARATION_AST_NODES:
            raise _MappingUnavailable("declaration_ast_node_limit")
        if depth > _religion_definitions.MAX_DECLARATION_AST_DEPTH:
            raise _MappingUnavailable("declaration_ast_depth_limit")
        if not isinstance(node, Mapping):
            raise _MappingUnavailable("declaration_ast_node_invalid")
        identity = id(node)
        if identity in seen:
            raise _MappingUnavailable("declaration_ast_alias_or_cycle")
        seen.add(identity)
        keys = set(node)
        if (not _AST_REQUIRED_KEYS.issubset(keys)
                or keys - _AST_REQUIRED_KEYS - _AST_OPTIONAL_KEYS):
            raise _MappingUnavailable("declaration_ast_keys_invalid")
        key = node.get("key")
        assignment = node.get("assignment")
        kind = node.get("kind")
        value = node.get("value")
        line = node.get("line")
        end_line = node.get("end_line")
        children = node.get("children")
        if (type(key) is not str or not key or len(key) > 65536
                or (assignment is not None and assignment not in _AST_ASSIGNMENTS)
                or kind not in {"block", "scalar", "bare"}
                or (value is not None and type(value) is not str)
                or type(line) is not int or line < 1
                or type(end_line) is not int or end_line < line
                or not isinstance(children, list)
                or (kind == "block" and value is not None)
                or (kind == "scalar" and children)):
            raise _MappingUnavailable("declaration_ast_node_invalid")
        estimated_chars += len(key) + (len(value) if value is not None else 0) + 96
        if estimated_chars * 6 > _religion_definitions.MAX_DECLARATION_JSON_BYTES:
            raise _MappingUnavailable("declaration_ast_json_limit")
        for column in ("source_column", "end_column"):
            if column in node and node[column] is not None:
                if type(node[column]) is not int or node[column] < 0:
                    raise _MappingUnavailable("declaration_ast_column_invalid")
        pending.extend((child, depth + 1) for child in reversed(children))
    encoded = canonical(root).encode("utf-8")
    if len(encoded) > _religion_definitions.MAX_DECLARATION_JSON_BYTES:
        raise _MappingUnavailable("declaration_ast_json_limit")
    return count, len(encoded)


def _modifier_name(block: Mapping[str, Any]) -> str:
    if block.get("kind") != "block" or block.get("assignment") != "=":
        raise _MappingUnavailable("add_country_modifier_shape_invalid")
    children = block.get("children")
    if not isinstance(children, list):
        raise _MappingUnavailable("add_country_modifier_children_invalid")
    names = [node for node in children if isinstance(node, Mapping) and node.get("key") == "name"]
    if (len(names) != 1 or names[0].get("kind") != "scalar"
            or names[0].get("assignment") != "="
            or type(names[0].get("value")) is not str
            or not _religion_definitions.RELIGION_KEY_RE.fullmatch(names[0]["value"])):
        raise _MappingUnavailable("add_country_modifier_name_invalid")
    return names[0]["value"]


def _school_rows(
    group_key: str,
    syntax: Mapping[str, Any],
    definition: Mapping[str, Any],
    pins: Mapping[str, str],
) -> list[dict[str, Any]]:
    if (syntax.get("key") != group_key or syntax.get("kind") != "block"
            or syntax.get("assignment") != "=" or not isinstance(syntax.get("children"), list)):
        raise _MappingUnavailable("group_ast_root_invalid")
    schools_blocks = [node for node in syntax["children"]
                      if isinstance(node, Mapping) and node.get("key") == "religious_schools"]
    if not schools_blocks:
        return []
    if len(schools_blocks) != 1:
        raise _MappingUnavailable("religious_schools_block_ambiguous")
    schools_block = schools_blocks[0]
    if (schools_block.get("kind") != "block" or schools_block.get("assignment") != "="
            or not isinstance(schools_block.get("children"), list)):
        raise _MappingUnavailable("religious_schools_block_invalid")

    school_nodes = schools_block["children"]
    school_keys: list[str] = []
    for school in school_nodes:
        if (not isinstance(school, Mapping) or school.get("kind") != "block"
                or school.get("assignment") != "="
                or type(school.get("key")) is not str
                or not _religion_definitions.RELIGION_KEY_RE.fullmatch(school["key"])):
            raise _MappingUnavailable("religious_school_node_invalid")
        school_keys.append(school["key"])
    school_counts = Counter(key.casefold() for key in school_keys)
    if any(count != 1 for count in school_counts.values()):
        raise _MappingUnavailable("religious_school_key_ambiguous")

    rows: list[dict[str, Any]] = []
    for school, school_key in zip(school_nodes, school_keys):
        children = school.get("children")
        if not isinstance(children, list):
            raise _MappingUnavailable("religious_school_children_invalid")
        displays = [node for node in children if isinstance(node, Mapping)
                    and node.get("key") == "invite_scholar_modifier_display"]
        if (len(displays) != 1 or displays[0].get("kind") != "scalar"
                or displays[0].get("assignment") != "="
                or type(displays[0].get("value")) is not str
                or not _religion_definitions.RELIGION_KEY_RE.fullmatch(displays[0]["value"])):
            raise _MappingUnavailable("invite_scholar_modifier_display_invalid")
        modifier_key = displays[0]["value"]
        handlers = [node for node in children if isinstance(node, Mapping)
                    and node.get("key") == "on_invite_scholar"]
        if (len(handlers) != 1 or handlers[0].get("kind") != "block"
                or handlers[0].get("assignment") != "="
                or not isinstance(handlers[0].get("children"), list)):
            raise _MappingUnavailable("on_invite_scholar_invalid")

        modifier_names: list[str] = []
        pending = [handlers[0]]
        while pending:
            node = pending.pop()
            if not isinstance(node, Mapping):
                raise _MappingUnavailable("on_invite_scholar_ast_invalid")
            if node.get("key") == "add_country_modifier":
                modifier_names.append(_modifier_name(node))
            pending.extend(reversed(node.get("children", [])))
        exact = [name for name in modifier_names if name == modifier_key]
        folded = [name for name in modifier_names if name.casefold() == modifier_key.casefold()]
        if len(exact) != 1 or len(folded) != 1:
            raise _MappingUnavailable("scholar_modifier_declaration_ambiguous_or_missing")
        rows.append({
            "religion_group_key": group_key,
            "school_key": school_key,
            "modifier_key": modifier_key,
            "definition": {
                **deepcopy(dict(definition)),
                "line": school["line"],
            },
            "source_pins": deepcopy(dict(pins)),
            "conditions_evaluated": False,
            "effects_executed": False,
            "runtime_state_observed": False,
        })
    return rows


class ReligiousScholarDefinitionIndex:
    """Enumerate unique static school-to-scholar-modifier mappings."""

    def __init__(
        self,
        index: Any | None = None,
        *,
        game_root: Any = None,
        user_data: Any = None,
        enabled_mods: Any = None,
        parser: Any = None,
        parser_manifest: Any = None,
    ) -> None:
        if index is not None and any(value is not None for value in
                                     (game_root, user_data, enabled_mods, parser, parser_manifest)):
            raise ValueError("index and index constructor arguments are mutually exclusive")
        if index is None:
            self._index = _EnumerableReligionDefinitionIndex(
                game_root, user_data, enabled_mods,
                parser=parser, parser_manifest=parser_manifest,
            )
        else:
            self._index = index

    def mapping(self) -> dict[str, Any]:
        try:
            index = self._index
            if not callable(getattr(index, "assert_current", None)):
                raise _MappingUnavailable("index_assert_current_missing")
            index.assert_current()
            context_before = index.context()
            pins = _context_pins(context_before)
            group_keys_method = getattr(index, "group_keys", None)
            if not callable(group_keys_method):
                raise _MappingUnavailable("group_keys_unavailable")
            group_keys = group_keys_method()
            if (not isinstance(group_keys, list) or len(group_keys) > MAX_GROUPS
                    or any(type(key) is not str
                           or not _religion_definitions.RELIGION_KEY_RE.fullmatch(key)
                           for key in group_keys)):
                raise _MappingUnavailable("group_keys_invalid_or_over_limit")
            if len({key.casefold() for key in group_keys}) != len(group_keys):
                raise _MappingUnavailable("religion_group_ambiguous")

            group_definition = getattr(index, "group_definition", None)
            if not callable(group_definition):
                raise _MappingUnavailable("group_definition_unavailable")
            rows: list[dict[str, Any]] = []
            total_ast_nodes = 0
            total_ast_bytes = 0
            for group_key in group_keys:
                result = group_definition(group_key)
                definition, syntax = _validate_group_result(result, group_key, pins)
                node_count, ast_bytes = _validate_ast(syntax)
                total_ast_nodes += node_count
                total_ast_bytes += ast_bytes
                if (total_ast_nodes > MAX_TOTAL_AST_NODES
                        or total_ast_bytes > MAX_TOTAL_AST_BYTES):
                    raise _MappingUnavailable("mapping_ast_budget_exceeded")
                rows.extend(_school_rows(group_key, syntax, definition, pins))
                if len(rows) > MAX_TOTAL_SCHOOLS:
                    raise _MappingUnavailable("mapping_school_limit_exceeded")

            modifier_owners: dict[str, tuple[str, str]] = {}
            for row in rows:
                folded = row["modifier_key"].casefold()
                owner = modifier_owners.get(folded)
                if owner is not None and owner != (
                    row["religion_group_key"], row["school_key"]
                ):
                    raise _MappingUnavailable("modifier_mapped_to_multiple_schools")
                modifier_owners[folded] = (
                    row["religion_group_key"], row["school_key"]
                )
            rows.sort(key=lambda row: (
                row["religion_group_key"].casefold(), row["religion_group_key"],
                row["school_key"].casefold(), row["school_key"],
            ))
            index.assert_current()
            context_after = index.context()
            if (not isinstance(context_after, Mapping)
                    or canonical(context_before) != canonical(context_after)
                    or _context_pins(context_after) != pins):
                raise _MappingUnavailable("index_context_changed")
            result = {
                "status": "known",
                "mappings": rows,
                "source_pins": deepcopy(pins),
                "conditions_evaluated": False,
                "effects_executed": False,
                "runtime_state_observed": False,
            }
            if len(canonical(result).encode("utf-8")) > MAX_MAPPING_JSON_BYTES:
                raise _MappingUnavailable("mapping_json_budget_exceeded")
            return result
        except Exception:
            return _unknown()


__all__ = [
    "MAX_GROUPS", "MAX_TOTAL_SCHOOLS", "MAX_TOTAL_AST_NODES",
    "MAX_TOTAL_AST_BYTES", "MAX_MAPPING_JSON_BYTES",
    "ReligiousScholarDefinitionIndex",
]
