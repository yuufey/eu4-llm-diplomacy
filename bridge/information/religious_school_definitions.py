"""Bounded projection of one religious-school declaration from a group AST."""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import re
from typing import Any

from .model import canonical
from .religion_definitions import RELIGION_KEY_RE, ReligionDefinitionIndex


_UNKNOWN = {
    "status": "unknown",
    "reason": "RELIGIOUS_SCHOOL_DEFINITION_UNAVAILABLE",
}
_PIN_KEYS = {
    "configuration_sha256", "definitions_sha256", "parser_manifest_sha256",
    "cwt_sha256", "cwt_commit",
}
_GROUP_RESULT_KEYS = {
    "status", "religion_group_key", "definition", "source", "source_pins",
    "syntax", "conditions_evaluated", "effects_executed",
    "runtime_state_observed",
}
_AST_KEYS = {
    "key", "assignment", "kind", "value", "children", "line", "end_line",
}
_AST_OPTIONAL_KEYS = {"source_column", "end_column"}
_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX_40 = re.compile(r"[0-9a-f]{40}\Z")


class ReligiousSchoolDefinitionIndex:
    """Select school syntax from the already pinned religion-group index."""

    def __init__(self, index: Any | None = None):
        self.index = ReligionDefinitionIndex() if index is None else index
        if not all(callable(getattr(self.index, name, None)) for name in (
            "context", "assert_current", "group_definition",
        )):
            raise TypeError("index must expose context, assert_current, and group_definition")

    def context(self) -> dict[str, Any]:
        """Return an isolated copy of the wrapped index context."""
        return deepcopy(self.index.context())

    def assert_current(self) -> None:
        """Forward the wrapped index's file/parser freshness check."""
        return self.index.assert_current()

    @staticmethod
    def _unknown() -> dict[str, str]:
        return dict(_UNKNOWN)

    @staticmethod
    def _pin_bundle(group: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]] | None:
        source, pins = group.get("source"), group.get("source_pins")
        if (not isinstance(source, Mapping) or not isinstance(pins, Mapping)
                or set(source) != _PIN_KEYS or set(pins) != _PIN_KEYS
                or dict(source) != dict(pins)):
            return None
        for key in ("configuration_sha256", "definitions_sha256",
                    "parser_manifest_sha256", "cwt_sha256"):
            if type(pins.get(key)) is not str or _HEX_64.fullmatch(pins[key]) is None:
                return None
        if type(pins.get("cwt_commit")) is not str or _HEX_40.fullmatch(pins["cwt_commit"]) is None:
            return None
        return deepcopy(dict(source)), deepcopy(dict(pins))

    @staticmethod
    def _node_shape(node: object) -> bool:
        if not isinstance(node, Mapping):
            return False
        keys = set(node)
        if not _AST_KEYS <= keys or keys - (_AST_KEYS | _AST_OPTIONAL_KEYS):
            return False
        if (type(node.get("key")) is not str or not node["key"]
                or type(node.get("assignment")) not in (str, type(None))
                or node.get("kind") not in ("block", "scalar", "bare")
                or (node.get("value") is not None and type(node.get("value")) is not str)
                or not isinstance(node.get("children"), list)
                or type(node.get("line")) is not int or node["line"] < 1
                or type(node.get("end_line")) is not int or node["end_line"] < node["line"]):
            return False
        for column in _AST_OPTIONAL_KEYS & keys:
            if node[column] is not None and (type(node[column]) is not int or node[column] < 0):
                return False
        if node["kind"] == "block" and node["value"] is not None:
            return False
        if node["kind"] == "scalar" and node["children"]:
            return False
        return True

    @staticmethod
    def _valid_group_result(group: object, requested_group: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
        if not isinstance(group, Mapping) or set(group) != _GROUP_RESULT_KEYS:
            return None
        if (group.get("status") != "known"
                or type(group.get("religion_group_key")) is not str
                or group["religion_group_key"] != requested_group
                or group.get("conditions_evaluated") is not False
                or group.get("effects_executed") is not False
                or group.get("runtime_state_observed") is not False):
            return None
        syntax = group.get("syntax")
        if (not ReligiousSchoolDefinitionIndex._node_shape(syntax)
                or syntax["key"] != requested_group
                or syntax["assignment"] != "="
                or syntax["kind"] != "block"
                or syntax["value"] is not None):
            return None
        bundle = ReligiousSchoolDefinitionIndex._pin_bundle(group)
        if bundle is None:
            return None
        return deepcopy(syntax), bundle[0], bundle[1]

    def definition(self, religion_group_key: str, school_key: str) -> dict[str, Any]:
        """Return one unique school declaration, or a safe unknown result."""
        if (type(religion_group_key) is not str or RELIGION_KEY_RE.fullmatch(religion_group_key) is None
                or type(school_key) is not str or RELIGION_KEY_RE.fullmatch(school_key) is None):
            return self._unknown()

        try:
            self.assert_current()
            before_context = canonical(self.context())
        except Exception:
            return self._unknown()

        group = None
        group_error = False
        try:
            # This is the one source of syntax. Its parser output has already
            # passed the group's serializer and AST budgets.
            group = self.index.group_definition(religion_group_key)
        except Exception:
            group_error = True

        try:
            self.assert_current()
            after_context = canonical(self.context())
        except Exception:
            return self._unknown()
        if group_error or before_context != after_context:
            return self._unknown()

        validated = self._valid_group_result(group, religion_group_key)
        if validated is None:
            return self._unknown()
        group_syntax, source, source_pins = validated
        group_children = group_syntax["children"]
        if any(not self._node_shape(child) for child in group_children):
            return self._unknown()
        schools_blocks = [
            child for child in group_children
            if child["key"].casefold() == "religious_schools"
        ]
        if len(schools_blocks) != 1:
            return self._unknown()
        schools = schools_blocks[0]
        if (schools["assignment"] != "=" or schools["kind"] != "block"
                or schools["value"] is not None):
            return self._unknown()

        school_children = schools["children"]
        if any(not self._node_shape(child) for child in school_children):
            return self._unknown()
        folded_matches = [
            child for child in school_children
            if child["key"].casefold() == school_key.casefold()
        ]
        exact_matches = [child for child in school_children if child["key"] == school_key]
        if len(folded_matches) != 1 or len(exact_matches) != 1:
            return self._unknown()
        school = exact_matches[0]
        if (school["assignment"] != "=" or school["kind"] != "block"
                or school["value"] is not None):
            return self._unknown()

        return {
            "status": "known",
            "religion_group_key": religion_group_key,
            "school_key": school_key,
            "source": source,
            "source_pins": source_pins,
            "syntax": deepcopy(school),
            "conditions_evaluated": False,
            "effects_executed": False,
            "active_effects_proven": False,
        }
