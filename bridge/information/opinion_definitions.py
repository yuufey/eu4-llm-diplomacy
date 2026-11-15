"""Index static opinion-modifier declarations with the existing CWTools AST."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping, Sequence

from . import static_data as _static
from .cwtools_script import CwtoolsScriptParser
from .model import canonical
from .religion_definitions import (
    MAX_DIRECTORY_MEMBERS, MAX_EFFECTIVE_FILES, MAX_TOTAL_INPUT_BYTES,
    ReligionDefinitionIndex as _ReligionIndex,
    _explicit_mod_signature, _is_prefix, _is_reparse, _read_bounded, _sha256,
)
from .strait_definitions import (
    DEFAULT_MAX_FILE_BYTES, MAX_ENABLED_MODS,
    StraitDefinitionIndex as _LayerResolver,
    _IndexState as _ResolverState,
)


DIRECTORY = "common/opinion_modifiers"
FIELDS = ("opinion", "min", "max", "yearly_decay", "years", "months")
MAX_KEY_LENGTH = 128
MAX_DEFINITIONS = 8192
_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_NUMBER = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\Z")


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _read_member_directory(
    root: Path, limit: int, directory: str = DIRECTORY,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Boundedly list one layer's modifier-definition directory and .txt files."""
    definition_directory = directory.replace("\\", "/")
    parts = definition_directory.split("/")
    if (not definition_directory or definition_directory.startswith("/")
            or any(part in {"", ".", ".."} for part in parts)
            or ":" in parts[0]):
        raise ValueError("OPINION_DEFINITION_DIRECTORY_INVALID")
    scope = _ReligionIndex._safe_candidate(root, definition_directory)
    root_resolved = root.resolve(strict=True)
    scope.relative_to(root_resolved)
    if not scope.exists():
        return {"exists": False, "is_directory": False, "members": None}, []
    if _is_reparse(scope) or not scope.is_dir():
        raise ValueError("OPINION_DEFINITION_DIRECTORY_INVALID")

    members: list[dict[str, str]] = []
    candidates: list[dict[str, Any]] = []
    pending: list[tuple[Path, str]] = [(scope, "")]
    while pending:
        directory_path, relative_dir = pending.pop()
        with os.scandir(directory_path) as scan:
            names = []
            for entry in scan:
                names.append(entry.name)
                if len(members) + len(names) > limit:
                    raise ValueError("OPINION_DEFINITION_MEMBER_LIMIT")
            names.sort(key=lambda name: (name.casefold(), name))
        for name in names:
            child = directory_path / name
            subpath = f"{relative_dir}/{name}" if relative_dir else name
            info = child.lstat()
            if _is_reparse(child, info.st_mode, getattr(info, "st_file_attributes", 0)):
                raise ValueError("OPINION_DEFINITION_REPARSE_POINT")
            is_directory = stat.S_ISDIR(info.st_mode)
            is_file = stat.S_ISREG(info.st_mode)
            if not is_directory and not is_file:
                raise ValueError("OPINION_DEFINITION_ENTRY_TYPE_INVALID")
            members.append({"relative": subpath, "kind": "directory" if is_directory else "file"})
            if len(members) > limit:
                raise ValueError("OPINION_DEFINITION_MEMBER_LIMIT")
            if is_directory:
                pending.append((child, subpath))
            elif child.suffix.casefold() == ".txt":
                file_relative = f"{definition_directory}/{subpath}"
                path = _ReligionIndex._safe_candidate(root, file_relative)
                candidates.append({"relative": file_relative, "path": path})
    members.sort(key=lambda row: (row["relative"].casefold(), row["relative"], row["kind"]))
    candidates.sort(key=lambda row: (row["relative"].casefold(), row["relative"]))
    return {"exists": True, "is_directory": True, "members": members}, candidates


class OpinionModifierDefinitionIndex:
    """Read declared scalar syntax from effective modifier-definition files.

    This index describes disk configuration only. It does not determine which
    modifier is currently attached to a live country pair or evaluate decay.
    The default directory and fields describe opinion modifiers. Other direct
    modifier definitions reuse the same parser and enabled-mod resolution.
    """

    def __init__(
        self,
        game_root: str | Path | None = None,
        user_data: str | Path | None = None,
        enabled_mods: Sequence[str | Path | Mapping[str, Any]] | str | Path | None = None,
        *, parser: Any | None = None,
        directory: str | Path = DIRECTORY,
        fields: Sequence[str] | None = FIELDS,
    ) -> None:
        self.game_root = (Path(game_root) if game_root is not None
                          else _static.StaticTradeSource._configured_path("game_root"))
        self.user_data = (Path(user_data) if user_data is not None
                          else _static.StaticTradeSource._configured_path("user_data"))
        self._explicit_enabled_mods = enabled_mods is not None
        if enabled_mods is None:
            self.enabled_mods: list[Any] | None = None
            request_mods: Any = None
        elif isinstance(enabled_mods, (str, Path)):
            self.enabled_mods = [enabled_mods]
            request_mods = self.enabled_mods
        else:
            self.enabled_mods = list(enabled_mods)
            request_mods = self.enabled_mods
        self._requested_mod_signature = _explicit_mod_signature(request_mods)
        self.directory = str(directory).replace("\\", "/")
        self.fields = tuple(fields) if fields is not None else None
        self._initial_roots = {
            "game_root": str(self.game_root.resolve(strict=False)) if self.game_root is not None else None,
            "user_data": str(self.user_data.resolve(strict=False)) if self.user_data is not None else None,
        }
        self.max_file_bytes = DEFAULT_MAX_FILE_BYTES
        self._parser = parser
        self._parser_context: dict[str, Any] = {}
        self._resolver: Any = None
        self._errors: list[dict[str, str]] = []
        self._directory_snapshots: list[dict[str, Any]] = []
        self._effective_files: list[dict[str, Any]] = []
        self._definitions: dict[str, list[dict[str, Any]]] = {}
        self._configuration_sha256: str | None = None
        self._definitions_sha256: str | None = None
        self._build()

    def _add_error(self, code: str, message: str) -> None:
        self._errors.append({"code": code, "message": message})

    def _make_resolver(self) -> None:
        resolver = object.__new__(_LayerResolver)
        resolver.game_root = self.game_root
        resolver.user_data = self.user_data
        resolver._explicit_enabled_mods = self._explicit_enabled_mods
        resolver.enabled_mods = deepcopy(self.enabled_mods)
        resolver.max_file_bytes = self.max_file_bytes
        resolver._state = _ResolverState(compatibility=_static._StaticState())
        resolver._load_version()
        resolver._load_mods()
        self._resolver = resolver
        self._errors.extend(deepcopy(resolver._state.errors))
        self._errors.extend(deepcopy(resolver._state.compatibility.errors))
        if len(resolver._state.mods) > MAX_ENABLED_MODS:
            self._add_error("MOD_COUNT_EXCEEDED", "enabled mods exceed the resolver limit")

    def _make_parser(self) -> None:
        try:
            if self._parser is None:
                self._parser = CwtoolsScriptParser()
            context = self._parser.context()
            if (not isinstance(context, dict) or context.get("status") != "ready"
                    or context.get("complete") is not True
                    or not callable(getattr(self._parser, "parse_files", None))
                    or not callable(getattr(self._parser, "assert_current", None))):
                raise ValueError("CWTOOLS_PARSER_UNREADY")
            self._parser.assert_current()
            self._parser_context = deepcopy(context)
        except Exception:
            self._add_error("CWTOOLS_PARSER_UNAVAILABLE", "CWTools script parser is unavailable")
            self._parser_context = {"status": "unready", "complete": False,
                                    "semantics": "syntax_only"}

    def _scan_layer(self, index: int, layer: Any, member_budget: int):
        snapshot, candidates = _read_member_directory(
            Path(layer.root), member_budget, self.directory,
        )
        snapshot = {"layer_index": index, "source_kind": layer.kind, **snapshot}
        for item in candidates:
            item.update(source_kind=layer.kind, source=layer.source, layer_index=index)
        return snapshot, candidates

    def _resolve_effective_files(self) -> None:
        if self._resolver is None or not self._resolver._state.layers:
            self._add_error("DEFINITION_LAYERS_UNAVAILABLE", "no game data layers resolved")
            return
        winners: dict[str, dict[str, Any]] = {}
        snapshots: list[dict[str, Any]] = []
        total_members = 0
        for index, layer in enumerate(self._resolver._state.layers):
            try:
                snapshot, candidates = self._scan_layer(
                    index, layer, MAX_DIRECTORY_MEMBERS - total_members)
            except Exception:
                self._add_error("DEFINITION_DIRECTORY_INVALID", "opinion modifier directory is invalid")
                return
            snapshots.append(snapshot)
            total_members += len(snapshot["members"] or [])
            if total_members > MAX_DIRECTORY_MEMBERS:
                self._add_error("DIRECTORY_MEMBER_LIMIT", "opinion modifier directory exceeds its limit")
                return
            seen: set[str] = set()
            for item in candidates:
                folded = item["relative"].casefold()
                if folded in seen:
                    self._add_error("DUPLICATE_DEFINITION_PATH", item["relative"])
                    return
                seen.add(folded)
            if index > 0:
                mod = (self._resolver._state.mods[index - 1]
                       if index - 1 < len(self._resolver._state.mods) else None)
                for replace_path in tuple(mod.replace_paths) if mod is not None else ():
                    normalized = replace_path.casefold()
                    removed = [key for key, row in winners.items()
                               if _is_prefix(row["relative"], normalized)]
                    for key in removed:
                        del winners[key]
                    replacements = [row for row in candidates
                                    if _is_prefix(row["relative"].casefold(), normalized)]
                    if removed and not replacements:
                        self._add_error("REPLACED_DEFINITION_PATH_EMPTY",
                                        "replace_path removed definitions without replacements")
                        return
            for item in candidates:
                winners[item["relative"].casefold()] = item

        self._directory_snapshots = snapshots
        effective = [winners[key] for key in sorted(winners)]
        if len(effective) > MAX_EFFECTIVE_FILES:
            self._add_error("DEFINITION_FILE_LIMIT", "effective opinion modifier files exceed limit")
            return
        total_bytes = self._resolver._configuration_bytes()
        for item in effective:
            try:
                raw = _read_bounded(Path(item["path"]), self.max_file_bytes, allow_empty=True)
            except Exception:
                self._add_error("DEFINITION_FILE_INVALID", item["relative"])
                return
            total_bytes += len(raw)
            if total_bytes > MAX_TOTAL_INPUT_BYTES:
                self._add_error("TOTAL_INPUT_LIMIT_EXCEEDED", "opinion modifier inputs exceed byte limit")
                return
            item.update(size=len(raw), sha256=_sha256(raw))
        self._effective_files = effective
        config = {
            "configuration_files": [dict(row) for row in self._resolver._state.compatibility.configuration_files],
            "enabled_mods": [{"descriptor_sha256": mod.descriptor_sha256,
                               "name": mod.name, "replace_paths": list(mod.replace_paths)}
                              for mod in self._resolver._state.mods],
            "directory_candidates": self._directory_snapshots,
            "parser": self._parser_context,
        }
        self._configuration_sha256 = _sha(config)
        self._definitions_sha256 = _sha([
            {key: row[key] for key in ("relative", "sha256", "size", "source_kind")}
            for row in effective
        ])

    def _field_declaration(self, nodes: list[Any], name: str) -> dict[str, Any]:
        found = [node for node in nodes if isinstance(getattr(node, "key", None), str)
                 and node.key.casefold() == name]
        if not found:
            return {"status": "not_declared"}
        if len(found) != 1:
            return {"status": "unknown", "reason": "DUPLICATE_FIELD_DECLARATION"}
        node = found[0]
        value = getattr(node, "value", None)
        if (getattr(node, "kind", None) != "scalar" or getattr(node, "assignment", None) != "="
                or getattr(node, "children", None) or not isinstance(value, str)
                or _NUMBER.fullmatch(value) is None):
            return {"status": "unknown", "reason": "NON_LITERAL_DECLARATION"}
        return {"status": "declared", "value": value}

    def _parse_definitions(self) -> None:
        if self._errors or not self._effective_files:
            return
        paths = [Path(row["path"]).resolve() for row in self._effective_files]
        try:
            self._parser.assert_current()
            parsed = self._parser.parse_files(paths)
            self._parser.assert_current()
            if not isinstance(parsed, dict) or set(parsed) != {str(path) for path in paths}:
                raise ValueError("CWTOOLS_OUTPUT_FILES_MISMATCH")
        except Exception:
            self._add_error("CWTOOLS_PARSE_FAILED", "CWTools parsing failed")
            return
        definitions: dict[str, list[dict[str, Any]]] = {}
        count = 0
        for file_item, path in zip(self._effective_files, paths):
            result = parsed.get(str(path))
            if not isinstance(result, dict) or result.get("error"):
                self._add_error("CWTOOLS_FILE_PARSE_FAILED", file_item["relative"])
                return
            echo = result.get("parser")
            if (not isinstance(echo, dict)
                    or echo.get("manifest_sha256") != self._parser_context.get("manifest_sha256")):
                self._add_error("CWTOOLS_FILE_PARSER_ECHO_INVALID", file_item["relative"])
                return
            roots = result.get("nodes")
            if not isinstance(roots, list):
                self._add_error("CWTOOLS_ROOTS_INVALID", file_item["relative"])
                return
            for node in roots:
                key = getattr(node, "key", None)
                if not isinstance(key, str) or _KEY.fullmatch(key) is None:
                    continue
                count += 1
                if count > MAX_DEFINITIONS:
                    self._add_error("DEFINITION_LIMIT", "opinion modifier definitions exceed limit")
                    return
                children = getattr(node, "children", None)
                is_block = (getattr(node, "kind", None) == "block"
                            and getattr(node, "assignment", None) == "="
                            and isinstance(children, list))
                definitions.setdefault(key.casefold(), []).append({
                    "key": key, "valid": is_block,
                    "line": getattr(node, "line", None),
                    "relative_file": file_item["relative"],
                    "file_sha256": file_item["sha256"],
                    "source_kind": file_item["source_kind"],
                    "children": children if is_block else [],
                })
        self._definitions = definitions

    def _build(self) -> None:
        try:
            self._make_resolver()
        except Exception:
            self._add_error("MOD_RESOLVER_UNAVAILABLE", "game/mod layer resolver is unavailable")
        self._make_parser()
        if self._resolver is not None:
            self._resolve_effective_files()
        if not self._errors:
            self._parse_definitions()

    def _current_errors(self) -> list[dict[str, str]]:
        errors: list[dict[str, str]] = []
        roots = {
            "game_root": str(self.game_root.resolve(strict=False)) if self.game_root is not None else None,
            "user_data": str(self.user_data.resolve(strict=False)) if self.user_data is not None else None,
        }
        if roots != self._initial_roots:
            errors.append({"code": "INPUT_CHANGED", "message": "configured root changed"})
        try:
            requested = self.enabled_mods if self._explicit_enabled_mods else None
            if _explicit_mod_signature(requested) != self._requested_mod_signature:
                errors.append({"code": "INPUT_CHANGED", "message": "enabled mod request changed"})
        except Exception:
            errors.append({"code": "INPUT_CHANGED", "message": "enabled mod request is invalid"})
        try:
            errors.extend(self._resolver._fingerprint_errors())
        except Exception:
            errors.append({"code": "INPUT_CHANGED", "message": "configuration fingerprint changed"})
        for path_text, expected in self._resolver._state.compatibility.fingerprint.items():
            try:
                actual = _sha256(_read_bounded(Path(path_text), self.max_file_bytes))
                if actual != expected:
                    errors.append({"code": "INPUT_CHANGED", "message": "configuration file changed"})
            except Exception:
                errors.append({"code": "INPUT_CHANGED", "message": "configuration file unavailable"})
        try:
            self._parser.assert_current()
            if self._parser.context() != self._parser_context:
                errors.append({"code": "INPUT_CHANGED", "message": "CWTools parser changed"})
        except Exception:
            errors.append({"code": "INPUT_CHANGED", "message": "CWTools parser unavailable"})
        try:
            snapshots = []
            total = 0
            for index, layer in enumerate(self._resolver._state.layers):
                snapshot, _ = self._scan_layer(index, layer, MAX_DIRECTORY_MEMBERS - total)
                total += len(snapshot["members"] or [])
                snapshots.append(snapshot)
            if snapshots != self._directory_snapshots:
                errors.append({"code": "INPUT_CHANGED", "message": "modifier definition directory changed"})
        except Exception:
            errors.append({"code": "INPUT_CHANGED", "message": "modifier definition directory unavailable"})
        for item in self._effective_files:
            try:
                raw = _read_bounded(Path(item["path"]), self.max_file_bytes, allow_empty=True)
                if len(raw) != item["size"] or _sha256(raw) != item["sha256"]:
                    errors.append({"code": "INPUT_CHANGED", "message": "selected definition file changed"})
            except Exception:
                errors.append({"code": "INPUT_CHANGED", "message": "selected definition file unavailable"})
        return errors

    def assert_current(self) -> None:
        if self._errors:
            raise ValueError("OPINION_DEFINITION_INDEX_UNREADY")
        if self._current_errors():
            raise ValueError("OPINION_DEFINITION_INDEX_CHANGED")

    def _pins(self) -> dict[str, Any]:
        return {
            "configuration_sha256": self._configuration_sha256,
            "definitions_sha256": self._definitions_sha256,
            "parser_manifest_sha256": self._parser_context.get("manifest_sha256"),
        }

    def context(self) -> dict[str, Any]:
        reasons = deepcopy(self._errors)
        if not reasons:
            reasons = self._current_errors()
        return {
            "status": "ready" if not reasons else "unready",
            "complete": False, "mode": "static_definition_index",
            "definition_scope": self.directory, "source_basis": "disk_configuration",
            "loaded_membership_verified": False,
            "conditions_evaluated": False, "effects_executed": False,
            "current_decay_evaluated": False, "end_date_evaluated": False,
            "game_version": self._resolver._state.game_version if self._resolver else None,
            "reasons": reasons, "source_pins": self._pins(),
            "definition_files": [
                {key: row[key] for key in ("relative", "size", "sha256", "source_kind")}
                for row in self._effective_files
            ],
            "definition_count": sum(len(rows) for rows in self._definitions.values()),
            "unique_key_count": len(self._definitions),
            "declaration_fields": list(self.fields) if self.fields is not None else None,
            "parser": deepcopy(self._parser_context),
        }

    def lookup(self, key: str) -> dict[str, Any]:
        if not isinstance(key, str) or _KEY.fullmatch(key) is None:
            return {"status": "unknown", "reason": "OPINION_DEFINITION_KEY_INVALID"}
        try:
            self.assert_current()
        except Exception:
            return {"status": "unknown", "reason": "OPINION_DEFINITION_INDEX_UNAVAILABLE",
                    "key": key, "source_pins": self._pins()}
        rows = self._definitions.get(key.casefold(), [])
        if not rows:
            return {"status": "unknown", "reason": "OPINION_DEFINITION_NOT_FOUND",
                    "key": key, "source_pins": self._pins()}
        if len(rows) != 1:
            return {"status": "unknown", "reason": "OPINION_DEFINITION_AMBIGUOUS",
                    "key": key, "definitions": [self._public_row(row) for row in rows],
                    "source_pins": self._pins()}
        row = rows[0]
        if not row["valid"]:
            return {"status": "unknown", "reason": "OPINION_DEFINITION_INVALID",
                    "key": row["key"], "definition": self._public_row(row),
                    "source_pins": self._pins()}
        if self.fields is None:
            field_names: dict[str, str] = {}
            for child in row["children"]:
                name = getattr(child, "key", None)
                if isinstance(name, str) and name:
                    field_names.setdefault(name.casefold(), name)
            declarations = {
                field_names[folded]: self._field_declaration(row["children"], folded)
                for folded in sorted(field_names)
            }
        else:
            declarations = {
                name: self._field_declaration(row["children"], name.casefold())
                for name in self.fields
            }
        return {
            "status": "known", "key": row["key"], "declarations": declarations,
            "definition": self._public_row(row), "source_pins": self._pins(),
            "source_basis": "disk_configuration", "loaded_membership_verified": False,
            "conditions_evaluated": False, "effects_executed": False,
            "current_decay_evaluated": False, "end_date_evaluated": False,
        }

    @staticmethod
    def _public_row(row: Mapping[str, Any]) -> dict[str, Any]:
        return {key: row[key] for key in (
            "key", "line", "relative_file", "file_sha256", "source_kind", "valid",
        )}


__all__ = ["OpinionModifierDefinitionIndex", "DIRECTORY", "FIELDS"]
