"""Bind the effective static ``has_river_estuary_trigger`` definition.

This module reports rule syntax only.  It never reads province history or
claims that a modifier is active in a running game.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import re
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from .cwtools_script import CwtoolsScriptParser
from .model import canonical
from .strait_definitions import StraitDefinitionIndex, _path_under


SCRIPTED_TRIGGER_DIRECTORY = "common/scripted_triggers"
ESTUARY_TRIGGER_NAME = "has_river_estuary_trigger"
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_TRIGGER_FILES = 256
MAX_DIRECTORY_MEMBERS = 4096
MAX_TOTAL_DIRECTORY_MEMBERS = 16384
MAX_MODS = 256
MAX_KEY_COUNT = 64
MAX_KEY_BYTES = 255
MAX_RELATIVE_PATH_BYTES = 512
_SUPPORTED_VERSIONS = frozenset({"1.37.4"})
_VALID_KEY = re.compile(r"[A-Za-z0-9_-]+\Z")
_CONFIG_ERROR_CODES = frozenset({
    "GAME_ROOT_UNAVAILABLE", "GAME_VERSION_UNAVAILABLE", "UNSUPPORTED_GAME_VERSION",
    "ENABLED_MOD_CONFIG_UNAVAILABLE", "ENABLED_MOD_CONFIG_INVALID",
    "ENABLED_MOD_UNSUPPORTED", "MOD_ROOT_UNAVAILABLE", "MOD_COUNT_EXCEEDED",
})


class _BindingError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code = code


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: Any) -> str:
    return _sha256(canonical(value).encode("utf-8"))


def _read_bounded(path: Path, limit: int) -> bytes:
    if not path.is_file():
        raise _BindingError("STATIC_INPUT_UNAVAILABLE", str(path))
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise _BindingError("STATIC_INPUT_UNAVAILABLE", str(path)) from exc
    if size < 1 or size > limit:
        raise _BindingError("STATIC_INPUT_SIZE_OUT_OF_RANGE", f"{size}:{path}")
    try:
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
    except OSError as exc:
        raise _BindingError("STATIC_INPUT_UNAVAILABLE", str(path)) from exc
    if len(raw) != size or len(raw) > limit:
        raise _BindingError("STATIC_INPUT_CHANGED_DURING_READ", str(path))
    return raw


def _node_attr(node: Any, name: str, default: Any = None) -> Any:
    if isinstance(node, Mapping):
        return node.get(name, default)
    return getattr(node, name, default)


def _node_json(node: Any) -> dict[str, Any]:
    children = _node_attr(node, "children", [])
    result: dict[str, Any] = {
        "key": _node_attr(node, "key"),
        "kind": _node_attr(node, "kind"),
        "assignment": _node_attr(node, "assignment"),
        "value": _node_attr(node, "value"),
        "line": _node_attr(node, "line"),
        "end_line": _node_attr(node, "end_line"),
        "raw_key": _node_attr(node, "raw_key"),
        "raw_value": _node_attr(node, "raw_value"),
        "children": [_node_json(child) for child in children],
        "ast_semantics": "structural_only",
    }
    for name in ("source_column", "end_column", "cwtools_normalization"):
        value = _node_attr(node, name)
        if value is not None:
            result[name] = value
    return result


def _block(node: Any, key: str) -> list[Any]:
    if (_node_attr(node, "key") != key or _node_attr(node, "kind") != "block"
            or _node_attr(node, "assignment") != "=" or _node_attr(node, "value") is not None):
        raise _BindingError("UNSUPPORTED_TRIGGER_SHAPE", f"expected block {key}")
    children = _node_attr(node, "children", [])
    if not isinstance(children, list):
        raise _BindingError("SCRIPT_AST_INVALID", key)
    return children


def _scalar(node: Any, key: str) -> str:
    value = _node_attr(node, "value")
    if (_node_attr(node, "key") != key or _node_attr(node, "kind") != "scalar"
            or _node_attr(node, "assignment") != "=" or not isinstance(value, str)
            or _node_attr(node, "children", [])):
        raise _BindingError("UNSUPPORTED_TRIGGER_SHAPE", f"expected literal scalar {key}")
    return value


def _modifier_key(value: str) -> str:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise _BindingError("INVALID_MODIFIER_KEY", "modifier key is not ASCII") from exc
    if not encoded or len(encoded) > MAX_KEY_BYTES or not _VALID_KEY.fullmatch(value):
        raise _BindingError("INVALID_MODIFIER_KEY", "modifier key is outside the literal-key boundary")
    return value


def _extract_keys(trigger: Any) -> list[str]:
    """Accept only an OR tree whose leaves are literal province modifiers."""

    def expression(node: Any, *, wrapper_allowed: bool) -> list[str]:
        key = _node_attr(node, "key")
        if key == "has_province_modifier":
            value = _scalar(node, "has_province_modifier")
            return [_modifier_key(value)]
        if key == "OR":
            children = _block(node, "OR")
            if not children:
                raise _BindingError("UNSUPPORTED_TRIGGER_SHAPE", "empty OR")
            values: list[str] = []
            for child in children:
                values.extend(expression(child, wrapper_allowed=True))
            return values
        if key == "custom_trigger_tooltip" and wrapper_allowed:
            children = _block(node, "custom_trigger_tooltip")
            tooltips = [child for child in children if _node_attr(child, "key") == "tooltip"]
            expressions = [child for child in children if _node_attr(child, "key") != "tooltip"]
            if len(tooltips) != 1 or len(expressions) != 1:
                raise _BindingError("UNSUPPORTED_TRIGGER_SHAPE", "tooltip wrapper must contain one tooltip and one condition")
            _scalar(tooltips[0], "tooltip")  # Descriptive token; it is not a trigger leaf.
            return expression(expressions[0], wrapper_allowed=False)
        raise _BindingError("UNSUPPORTED_TRIGGER_SHAPE", f"unsupported OR operation: {key!r}")

    children = _block(trigger, ESTUARY_TRIGGER_NAME)
    if len(children) != 1:
        raise _BindingError("UNSUPPORTED_TRIGGER_SHAPE", "trigger must contain exactly one OR expression")
    values = expression(children[0], wrapper_allowed=True)
    ordered: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
            if len(ordered) > MAX_KEY_COUNT:
                raise _BindingError("ESTUARY_KEY_COUNT_LIMIT")
    if not ordered:
        raise _BindingError("ESTUARY_KEYS_EMPTY")
    return ordered


def _relative(root: Path, path: Path) -> str:
    try:
        return PurePosixPath(path.relative_to(root).as_posix()).as_posix()
    except ValueError as exc:
        raise _BindingError("STATIC_PATH_ESCAPES_LAYER", str(path)) from exc


class BoundEstuaryDefinition:
    """Bind one effective estuary trigger to static files and mod config.

    ``enabled_mods`` follows the existing static source contract: it may
    contain enabled descriptor paths or descriptor/root mappings, in their
    effective order. Root-only entries are not promoted into a second mod
    loader. The returned ``game_fact`` is always false because no runtime
    modifier state is observed here.
    """

    def __init__(
        self,
        game_root: str | Path | None = None,
        user_data: str | Path | None = None,
        enabled_mods: Sequence[str | Path | Mapping[str, Any]] | None = None,
        *,
        script_parser: Any | None = None,
        max_file_bytes: int = MAX_FILE_BYTES,
        max_total_bytes: int = MAX_TOTAL_BYTES,
        max_files: int = MAX_TRIGGER_FILES,
    ) -> None:
        if type(max_file_bytes) is not int or not 0 < max_file_bytes <= MAX_FILE_BYTES:
            raise ValueError("max_file_bytes must be in 1..4 MiB")
        if type(max_total_bytes) is not int or not 0 < max_total_bytes <= MAX_TOTAL_BYTES:
            raise ValueError("max_total_bytes must be in 1..16 MiB")
        if type(max_files) is not int or not 0 < max_files <= MAX_TRIGGER_FILES:
            raise ValueError("max_files must be in 1..256")
        self.game_root = Path(game_root).expanduser() if game_root is not None else None
        self.user_data = Path(user_data).expanduser() if user_data is not None else None
        self.enabled_mods = enabled_mods
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.max_files = max_files
        self.script_parser = script_parser
        self._source: StraitDefinitionIndex | None = None
        self._layers: list[Any] = []
        self._configuration_sha256: str | None = None
        self._configuration_files: list[dict[str, Any]] = []
        self._enabled_mods: list[dict[str, Any]] = []
        self._base_status = "unknown"
        self._reasons: list[dict[str, str]] = []
        self._trigger_ast: dict[str, Any] | None = None
        self._keys: list[str] = []
        self._candidate_keys: list[str] = []
        self._definition_file: dict[str, Any] | None = None
        self._definition_files: list[dict[str, Any]] = []
        self._definitions_sha256: str | None = None
        self._ast_sha256: str | None = None
        self._identity_before: dict[str, Any] | None = None
        self._identity_after: dict[str, Any] | None = None
        self._script_parser_context: dict[str, Any] | None = None
        self._bind()

    def _add_reason(self, code: str, detail: str = "") -> None:
        row = {"code": code}
        if detail:
            row["detail"] = detail[:400]
        if row not in self._reasons:
            self._reasons.append(row)

    def _load_stack(self) -> None:
        if self.game_root is None:
            self._add_reason("GAME_ROOT_UNAVAILABLE")
            return
        if self.enabled_mods is None and self.user_data is None:
            self._add_reason("ENABLED_MOD_CONFIG_UNAVAILABLE")
            return
        try:
            self._source = StraitDefinitionIndex(
                self.game_root, self.user_data, enabled_mods=self.enabled_mods,
                max_file_bytes=min(self.max_file_bytes, 4 * 1024 * 1024),
            )
        except Exception as exc:
            self._add_reason("EFFECTIVE_MOD_STACK_UNAVAILABLE", str(exc))
            return
        state = self._source._state
        all_errors = [*state.errors, *getattr(state.compatibility, "errors", [])]
        for error in all_errors:
            if error.get("code") in _CONFIG_ERROR_CODES:
                self._add_reason(str(error.get("code")), str(error.get("message", "")))
        if state.game_version not in _SUPPORTED_VERSIONS:
            self._add_reason("UNSUPPORTED_GAME_VERSION", str(state.game_version))
        if not self._source.game_root or not Path(self._source.game_root).is_dir():
            self._add_reason("GAME_ROOT_UNAVAILABLE")
        if len(state.layers) > 1 + MAX_MODS:
            self._add_reason("MOD_COUNT_EXCEEDED")
        self._layers = list(state.layers)
        self._configuration_sha256 = state.configuration_sha256
        self._configuration_files = [
            {"path": str(Path(row["path"]).resolve()), "kind": row.get("kind"), "sha256": row.get("sha256")}
            for row in getattr(state.compatibility, "configuration_files", [])
            if row.get("kind") in {"launcher_settings", "enabled_mod_config", "mod_descriptor"}
            and isinstance(row.get("path"), str)
        ]
        self._enabled_mods = [{
            "descriptor": str(mod.descriptor) if mod.descriptor is not None else None,
            "descriptor_sha256": mod.descriptor_sha256,
            "root": str(Path(mod.root).resolve()) if mod.root is not None else None,
            "replace_paths": list(mod.replace_paths),
        } for mod in state.mods]
        if self._configuration_sha256 is None:
            self._add_reason("CONFIGURATION_IDENTITY_UNAVAILABLE")
        if not self._layers:
            self._add_reason("EFFECTIVE_MOD_STACK_UNAVAILABLE", "no ordered layers")

    def _scan_layer(self, index: int, layer: Any) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
        try:
            root = Path(layer.root).resolve(strict=True)
            directory = root.joinpath(*PurePosixPath(SCRIPTED_TRIGGER_DIRECTORY).parts)
            resolved_directory = directory.resolve(strict=False)
            resolved_directory.relative_to(root)
        except (OSError, ValueError, AttributeError) as exc:
            raise _BindingError("SCRIPTED_TRIGGER_PATH_INVALID", str(exc)) from exc
        exists = directory.exists()
        if exists and not directory.is_dir():
            raise _BindingError("SCRIPTED_TRIGGER_PATH_NOT_DIRECTORY", str(directory))
        members: list[dict[str, Any]] = []
        files: dict[str, dict[str, Any]] = {}
        if exists:
            try:
                entries = []
                for item in directory.rglob("*"):
                    entries.append(item)
                    if len(entries) > MAX_DIRECTORY_MEMBERS:
                        raise _BindingError("SCRIPTED_TRIGGER_DIRECTORY_MEMBER_LIMIT", str(directory))
                entries.sort(key=lambda item: item.as_posix().casefold())
            except _BindingError:
                raise
            except OSError as exc:
                raise _BindingError("SCRIPTED_TRIGGER_DIRECTORY_UNAVAILABLE", str(directory)) from exc
            seen_layer_paths: set[str] = set()
            for item in entries:
                if item.is_symlink():
                    raise _BindingError("SCRIPTED_TRIGGER_SYMLINK_UNSUPPORTED", str(item))
                try:
                    resolved = item.resolve(strict=True)
                    resolved.relative_to(root)
                except (OSError, ValueError) as exc:
                    raise _BindingError("STATIC_PATH_ESCAPES_LAYER", str(item)) from exc
                relative_inside = _relative(directory, item)
                full_relative = f"{SCRIPTED_TRIGGER_DIRECTORY}/{relative_inside}"
                if len(full_relative.encode("utf-8")) > MAX_RELATIVE_PATH_BYTES:
                    raise _BindingError("SCRIPTED_TRIGGER_PATH_LENGTH_LIMIT", full_relative[:120])
                kind = "directory" if item.is_dir() else "file" if item.is_file() else "other"
                members.append({"relative": full_relative, "kind": kind})
                if kind != "file" or item.suffix.casefold() != ".txt":
                    continue
                key = full_relative.casefold()
                if key in seen_layer_paths:
                    raise _BindingError("DUPLICATE_SCRIPTED_TRIGGER_PATH", full_relative)
                seen_layer_paths.add(key)
                files[key] = {
                    "relative": full_relative,
                    "path": str(item.resolve()),
                    "source_kind": layer.kind,
                    "source": layer.source,
                }
        layer_manifest = {
            "layer_index": index,
            "root": str(root),
            "source_kind": layer.kind,
            "source": layer.source,
            "replace_paths": list(layer.replace_paths),
            "directory_exists": exists,
            "member_count": len(members),
            "members_sha256": _digest(members),
        }
        return layer_manifest, files

    def _effective_files(self) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
        resolved: dict[str, dict[str, Any]] = {}
        directory_manifests: list[dict[str, Any]] = []
        total_members = 0
        for index, layer in enumerate(self._layers):
            layer_manifest, layer_files = self._scan_layer(index, layer)
            total_members += layer_manifest["member_count"]
            if total_members > MAX_TOTAL_DIRECTORY_MEMBERS:
                raise _BindingError("SCRIPTED_TRIGGER_TOTAL_MEMBER_LIMIT")
            directory_manifests.append(layer_manifest)
            if index:
                for replace_path in layer.replace_paths:
                    for existing in list(resolved):
                        if _path_under(resolved[existing]["relative"], replace_path):
                            del resolved[existing]
            resolved.update(layer_files)
        if len(resolved) > self.max_files:
            raise _BindingError("SCRIPTED_TRIGGER_FILE_COUNT_LIMIT", str(len(resolved)))
        records = [resolved[key] for key in sorted(resolved)]
        return directory_manifests, {key: dict(value) for key, value in resolved.items()}

    def _snapshot(self) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
        if not self._layers:
            raise _BindingError("EFFECTIVE_MOD_STACK_UNAVAILABLE")
        config_files: list[dict[str, Any]] = []
        for row in self._configuration_files:
            path = Path(row["path"])
            raw = _read_bounded(path, self.max_file_bytes)
            actual_sha256 = _sha256(raw)
            if actual_sha256 != row.get("sha256"):
                raise _BindingError("CONFIGURATION_IDENTITY_CHANGED", str(path))
            config_files.append({"path": str(path.resolve()), "kind": row.get("kind"), "sha256": actual_sha256})
        directory_manifests, resolved = self._effective_files()
        total_bytes = 0
        definition_files: list[dict[str, Any]] = []
        for key in sorted(resolved):
            row = resolved[key]
            raw = _read_bounded(Path(row["path"]), self.max_file_bytes)
            total_bytes += len(raw)
            if total_bytes > self.max_total_bytes:
                raise _BindingError("SCRIPTED_TRIGGER_TOTAL_INPUT_LIMIT", str(total_bytes))
            definition_files.append({
                "relative": row["relative"],
                "path": row["path"],
                "source_kind": row["source_kind"],
                "source": row["source"],
                "bytes": len(raw),
                "sha256": _sha256(raw),
            })
        definitions_sha = _digest([
            {"relative": item["relative"], "sha256": item["sha256"],
             "source_kind": item["source_kind"], "source": item["source"]}
            for item in definition_files
        ])
        snapshot = {
            "schema": "information.province_estuary_static_identity.v1",
            "game_root": str(Path(self.game_root).resolve()) if self.game_root is not None else None,
            "game_version": self._source._state.game_version if self._source is not None else None,
            "configuration_sha256": self._configuration_sha256,
            "configuration_files": config_files,
            "enabled_mods": deepcopy(self._enabled_mods),
            "scripted_trigger_directories": directory_manifests,
            "definition_files": definition_files,
            "definitions_sha256": definitions_sha,
        }
        return snapshot, resolved

    def _parse_trigger(self, files: Mapping[str, dict[str, Any]]) -> None:
        if not files:
            raise _BindingError("SCRIPTED_TRIGGER_FILES_MISSING")
        paths = [Path(files[key]["path"]) for key in sorted(files)]
        parser = self.script_parser or CwtoolsScriptParser()
        self.script_parser = parser
        try:
            parser_context = parser.context()
        except Exception as exc:
            raise _BindingError("SCRIPT_PARSER_UNREADY", str(exc)) from exc
        if not isinstance(parser_context, Mapping) or parser_context.get("status") != "ready":
            raise _BindingError("SCRIPT_PARSER_UNREADY")
        self._script_parser_context = dict(parser_context)
        try:
            documents = parser.parse_files(paths)
        except Exception as exc:
            raise _BindingError("SCRIPT_PARSE_FAILED", str(exc)) from exc
        matches: list[tuple[str, Any]] = []
        for key in sorted(files):
            path = Path(files[key]["path"]).resolve()
            document = documents.get(str(path))
            if not isinstance(document, Mapping) or document.get("error"):
                raise _BindingError("SCRIPT_PARSE_FAILED", str(path))
            nodes = document.get("nodes")
            if not isinstance(nodes, list):
                raise _BindingError("SCRIPT_AST_INVALID", str(path))
            for node in nodes:
                node_key = _node_attr(node, "key")
                if not isinstance(node_key, str):
                    raise _BindingError("SCRIPT_AST_INVALID", str(path))
                if node_key.casefold() == ESTUARY_TRIGGER_NAME.casefold():
                    if node_key != ESTUARY_TRIGGER_NAME:
                        raise _BindingError("ESTUARY_TRIGGER_NAME_CASE_MISMATCH", node_key)
                    matches.append((key, node))
        if not matches:
            raise _BindingError("ESTUARY_TRIGGER_MISSING")
        if len(matches) != 1:
            raise _BindingError("ESTUARY_TRIGGER_DUPLICATE_DEFINITION", str(len(matches)))
        file_key, node = matches[0]
        self._trigger_ast = _node_json(node)
        self._ast_sha256 = _digest(self._trigger_ast)
        self._definition_file = next(
            item for item in self._definition_files if item["relative"].casefold() == file_key
        )
        try:
            self._keys = _extract_keys(node)
        except _BindingError as exc:
            self._add_reason(exc.code, str(exc))
            return
        self._candidate_keys = list(self._keys)

    def _bind(self) -> None:
        self._load_stack()
        if self._reasons:
            return
        try:
            before, files = self._snapshot()
        except _BindingError as exc:
            self._add_reason(exc.code, str(exc))
            return
        self._identity_before = before
        self._definition_files = before["definition_files"]
        self._definitions_sha256 = before["definitions_sha256"]
        try:
            self._parse_trigger(files)
        except _BindingError as exc:
            self._add_reason(exc.code, str(exc))
        try:
            after, _files_after = self._snapshot()
        except _BindingError as exc:
            self._add_reason(exc.code, str(exc))
            return
        self._identity_after = after
        if _digest(before) != _digest(after):
            self._add_reason("INPUT_CHANGED_DURING_BIND")
        if self._trigger_ast is not None and self._keys and not self._reasons:
            self._base_status = "known"

    def _current_identity(self) -> tuple[str | None, str | None]:
        if self._identity_after is None:
            return None, "INITIAL_BIND_UNAVAILABLE"
        try:
            current, _files = self._snapshot()
        except _BindingError as exc:
            return None, exc.code
        if _digest(current) != _digest(self._identity_after):
            return _digest(current), "INPUT_IDENTITY_CHANGED"
        if self.script_parser is None:
            return _digest(current), None
        try:
            parser_context = self.script_parser.context()
        except Exception:
            return _digest(current), "SCRIPT_PARSER_UNREADY"
        if not isinstance(parser_context, Mapping) or parser_context.get("status") != "ready":
            return _digest(current), "SCRIPT_PARSER_UNREADY"
        return _digest(current), None

    def context(self) -> dict[str, Any]:
        current_identity, drift_reason = self._current_identity()
        status = self._base_status
        reasons = deepcopy(self._reasons)
        if drift_reason:
            status = "unknown"
            reasons.append({"code": drift_reason})
        before_sha = _digest(self._identity_before) if self._identity_before is not None else None
        after_sha = _digest(self._identity_after) if self._identity_after is not None else None
        stable = before_sha is not None and before_sha == after_sha
        if not stable and not any(item.get("code") == "INPUT_CHANGED_DURING_BIND" for item in reasons):
            status = "unknown"
        return {
            "schema": "information.province_estuary_static_definition.v1",
            "status": status,
            "complete": status == "known",
            "game_fact": False,
            "context_scope": "static_rules",
            "rule_name": ESTUARY_TRIGGER_NAME,
            "game_root": str(Path(self.game_root).resolve()) if self.game_root is not None else None,
            "game_version": self._source._state.game_version if self._source is not None else None,
            "configuration_sha256": self._configuration_sha256,
            "configuration_files": deepcopy(self._configuration_files),
            "enabled_mods": deepcopy(self._enabled_mods),
            "definitions_sha256": self._definitions_sha256,
            "definition_files": deepcopy(self._definition_files),
            "definition_file": deepcopy(self._definition_file),
            "scriptedtrigger_ast": deepcopy(self._trigger_ast),
            "scriptedtrigger_ast_sha256": self._ast_sha256,
            "known_modifier_keys": list(self._keys) if status == "known" else [],
            "candidate_modifier_keys": list(self._candidate_keys),
            "identity": {
                "algorithm": "SHA-256",
                "before_sha256": before_sha,
                "after_sha256": after_sha,
                "current_sha256": current_identity,
                "stable_before_after": stable,
            },
            "script_parser": deepcopy(self._script_parser_context),
            "reasons": reasons,
        }


__all__ = ["BoundEstuaryDefinition"]
