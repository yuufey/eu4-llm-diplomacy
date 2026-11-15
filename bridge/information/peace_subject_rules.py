"""Project scalar configuration rules from effective subject type files."""
from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any, Sequence

from .cwtools_script import CwtoolsScriptParser


SUBJECT_RULES = (
    "created_by_overlord",
    "can_be_annexed", "can_be_integrated", "integration_requires_same_religion_group",
    "annex_cost_per_development", "pays_overlord", "can_send_tribute",
    "forcelimit_to_overlord", "manpower_to_overlord", "sailors_to_overlord",
    "joins_overlords_wars",
    "overlord_can_attack", "can_fight_independence_war",
)
_BOOL_RULES = frozenset({'created_by_overlord', 'can_be_annexed', 'can_be_integrated',
    'integration_requires_same_religion_group', 'can_send_tribute',
    'joins_overlords_wars', 'overlord_can_attack', 'can_fight_independence_war'})
_NUMBER = re.compile(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?\Z")


class PeaceSubjectRules:
    """Read selected static subject-type values; no rule trigger is evaluated."""

    def __init__(self, defines_index, *, parser=None, defaults=None):
        self.defines_index = defines_index
        self.parser = parser
        self.defaults = dict(defaults or {})

    @staticmethod
    def _scalar(node):
        if (getattr(node, "kind", None) != "scalar" or getattr(node, "assignment", None) != "="
                or getattr(node, "children", None)):
            return None, "value is not a scalar assignment"
        raw = getattr(node, "value", None)
        if raw == "yes":
            return True, None
        if raw == "no":
            return False, None
        if isinstance(raw, bool):
            return raw, None
        if type(raw) in (int, float):
            return (raw, None) if not isinstance(raw, float) or math.isfinite(raw) else (None, "non-finite number")
        if not isinstance(raw, str) or _NUMBER.fullmatch(raw.strip()) is None:
            return None, "value is not a boolean or numeric literal"
        raw = raw.strip()
        try:
            number = float(raw) if any(c in raw for c in ".eE") else int(raw)
        except (ValueError, OverflowError):
            return None, "numeric literal is invalid"
        return (number, None) if not isinstance(number, float) or math.isfinite(number) else (None, "non-finite number")

    def read(self, names: Sequence[str]) -> dict[str, Any]:
        requested = list(dict.fromkeys([names] if isinstance(names, str) else names))
        requested = [name for name in requested if isinstance(name, str)]
        stack = self.defines_index._stack
        state, compat = stack._state, stack._state.compatibility
        source = {
            "game_version": state.game_version,
            "configuration_files": [dict(row) for row in compat.configuration_files],
            "enabled_mods": [{"descriptor": str(m.descriptor), "descriptor_sha256": m.descriptor_sha256,
                              "name": m.name, "root": m.root_label, "replace_paths": list(m.replace_paths)}
                             for m in state.mods],
            "definition_files": [],
        }
        values, reasons = {}, {}

        def ensure(name):
            if name not in values:
                values[name] = {key: self.defaults.get(key) for key in SUBJECT_RULES}
                reasons[name] = {key: {"code": "DEFAULT_UNKNOWN", "message": f"no supplied default for {key}"}
                                 for key in SUBJECT_RULES if self.defaults.get(key) is None}
            return values[name], reasons[name]

        def fail(code, message, details=None):
            source["errors"] = details or [{"code": code, "message": message}]
            for name in requested:
                row, why = ensure(name)
                for key in SUBJECT_RULES:
                    row[key] = None
                    why[key] = {"code": code, "message": message}
            return {"values": {n: values[n] for n in requested}, "source": source,
                    "reasons": {n: reasons[n] for n in requested}}

        files, errors = self.defines_index._effective_files(
            directory_path="common/subject_types", suffix=".txt", root_path=None
        )
        errors = [*state.errors, *compat.errors, *errors]
        if errors:
            err = errors[0]
            return fail(err.get("code", "SUBJECT_RULES_UNAVAILABLE"),
                        err.get("message", "subject type configuration unavailable"), errors)

        loaded = []
        for item in files:
            try:
                raw = stack._read_bounded(Path(item["path"]), stack.max_file_bytes)
            except Exception as exc:
                return fail("SUBJECT_FILE_UNAVAILABLE", str(exc))
            source["definition_files"].append({
                "relative": item["relative"], "path": str(item["path"]),
                "source_kind": item["source_kind"], "source": item["source"],
                "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            })
            loaded.append((item, Path(item["path"]).resolve()))

        try:
            parser = self.parser or CwtoolsScriptParser()
            self.parser = parser
            parser_context = parser.context()
            if parser_context.get("status") != "ready" or parser_context.get("complete") is not True:
                raise ValueError("CWTOOLS_PARSER_UNREADY")
            parser.assert_current()
            parsed = parser.parse_files([path for _, path in loaded])
            parser.assert_current()
            if not isinstance(parsed, dict) or set(parsed) != {str(path) for _, path in loaded}:
                raise ValueError("CWTOOLS_OUTPUT_FILES_MISMATCH")
        except Exception as exc:
            return fail("SUBJECT_PARSE_FAILED", str(exc))
        source["parser"] = dict(parser_context)
        for item, path in loaded:
            result = parsed[str(path)]
            echo = result.get("parser") if isinstance(result, dict) else None
            if (not isinstance(result, dict) or "error" in result or not isinstance(result.get("nodes"), list)
                    or not isinstance(echo, dict)
                    or echo.get("manifest_sha256") != parser_context.get("manifest_sha256")):
                return fail("SUBJECT_FILE_PARSE_FAILED", item["relative"])

        for item, path in loaded:
            for subject in parsed[str(path)]["nodes"]:
                name = getattr(subject, "key", None)
                if (not isinstance(name, str) or getattr(subject, "kind", None) != "block"
                        or getattr(subject, "assignment", None) != "="):
                    continue
                row, why = ensure(name)
                for child in getattr(subject, "children", []):
                    key = getattr(child, "key", None)
                    if key == "copy_from":
                        parent = getattr(child, "value", None)
                        if (getattr(child, "kind", None) == "scalar" and getattr(child, "assignment", None) == "="
                                and isinstance(parent, str)
                                and parent in values):
                            row.update(values[parent])
                            why.update(reasons[parent])
                            for prop in SUBJECT_RULES:
                                if prop not in reasons[parent]:
                                    why.pop(prop, None)
                        else:
                            for prop in SUBJECT_RULES:
                                row[prop] = None
                                why[prop] = {"code": "COPY_FROM_UNAVAILABLE", "message": f"parent unavailable for {name}"}
                    elif key in SUBJECT_RULES:
                        value, error = self._scalar(child)
                        if error is None and ((key in _BOOL_RULES and type(value) is not bool)
                                or (key not in _BOOL_RULES and type(value) not in (int, float))):
                            error = 'value type does not match the subject rule'
                        if error:
                            row[key] = None
                            why[key] = {"code": "SUBJECT_VALUE_UNSUPPORTED", "message": f"{item['relative']}:{getattr(child, 'line', '?')}: {error}"}
                        else:
                            row[key] = value
                            why.pop(key, None)

        for name in requested:
            if name not in values:
                values[name] = {key: None for key in SUBJECT_RULES}
                reasons[name] = {key: {'code': 'SUBJECT_TYPE_NOT_DECLARED',
                    'message': f'No definition for {name}'} for key in SUBJECT_RULES}
        source["definitions_sha256"] = hashlib.sha256(json.dumps(
            [{"relative": row["relative"], "sha256": row["sha256"], "source_kind": row["source_kind"]}
             for row in source["definition_files"]], sort_keys=True, separators=(",", ":")
        ).encode("utf-8")).hexdigest()
        return {"values": {n: values[n] for n in requested}, "source": source,
                "reasons": {n: reasons[n] for n in requested}}


__all__ = ["SUBJECT_RULES", "PeaceSubjectRules"]
