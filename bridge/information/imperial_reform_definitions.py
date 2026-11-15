"""Bounded static index of the effective EU4 imperial-reform definitions.

This module resolves mod overlays with the shared static-data resolver and
uses the pinned CWTools parser. It preserves declarations as syntax; it does
not evaluate conditions, effects, or current reform state.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Mapping, Sequence

from . import static_data as _static
from .cwtools_script import CwtoolsScriptParser
from .model import canonical
from .strait_definitions import (
    DEFAULT_MAX_FILE_BYTES,
    MAX_ENABLED_MODS,
    StraitDefinitionIndex as _SharedResolver,
    _IndexState as _ResolverState,
    _normalise_replace_path,
)


ROOT = Path(__file__).resolve().parents[2]
REFORM_DIRECTORY = "common/imperial_reforms"
MAX_EFFECTIVE_FILES = 512
MAX_DIRECTORY_MEMBERS = 4096
MAX_TOTAL_INPUT_BYTES = 16 * 1024 * 1024
MAX_TOTAL_AST_NODES = 524288
MAX_REFORM_ID_LENGTH = 128
REFORM_ID_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
AST_ASSIGNMENTS = {None, "=", "==", "!=", "<", ">", "<=", ">=", "?="}
VENDOR_PATH = ROOT / "third_party/cwtools-eu4-config/VENDOR.json"
CWT_PATH = ROOT / "third_party/cwtools-eu4-config/common/imperial_reforms.cwt"
EXPECTED_VENDOR_COMMIT = "a85622d368bbb7afca938ed70fdd5eda44aec769"
EXPECTED_CWT_BYTES = 3428
EXPECTED_CWT_SHA256 = "1119acad950d86c6d2f1e7dc1799a0f5f52d4d4636128c5d5e64b369abc883dd"
_INVALID_PATH_CHARS = ("\x00",)


def _reason(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_bounded(path: Path, max_bytes: int, *, allow_empty: bool = False) -> bytes:
    before = path.stat()
    size = before.st_size
    if (size < 0 if allow_empty else size < 1) or size > max_bytes:
        raise ValueError(f"INPUT_SIZE_OUT_OF_RANGE:{size}:{path}")
    with path.open("rb") as stream:
        raw = stream.read(max_bytes + 1)
    after = path.stat()
    if len(raw) != size or len(raw) > max_bytes or (before.st_size, before.st_mtime_ns) != (
        after.st_size, after.st_mtime_ns
    ):
        raise ValueError(f"INPUT_CHANGED_DURING_READ:{path}")
    return raw


def _pin(path: Path, *, expected_bytes: int | None = None,
         expected_sha256: str | None = None) -> dict[str, Any]:
    raw = _read_bounded(path, DEFAULT_MAX_FILE_BYTES)
    digest = _sha256(raw)
    if expected_bytes is not None and len(raw) != expected_bytes:
        raise ValueError(f"PIN_SIZE_MISMATCH:{path}")
    if expected_sha256 is not None and digest != expected_sha256:
        raise ValueError(f"PIN_HASH_MISMATCH:{path}")
    return {"path": str(path.resolve()), "bytes": len(raw), "sha256": digest}


def _is_reparse(path: Path, mode: int | None = None, attributes: int | None = None) -> bool:
    if mode is None or attributes is None:
        info = path.lstat()
        mode = info.st_mode
        attributes = getattr(info, "st_file_attributes", 0)
    return stat.S_ISLNK(mode) or bool(attributes & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT


def _is_prefix(path: str, prefix: str) -> bool:
    path_parts = tuple(part.casefold() for part in PurePosixPath(path).parts)
    prefix_parts = tuple(part.casefold() for part in PurePosixPath(prefix).parts)
    return len(path_parts) >= len(prefix_parts) and path_parts[:len(prefix_parts)] == prefix_parts


def _explicit_mod_signature(value: Any) -> str:
    def safe(item: Any) -> Any:
        if isinstance(item, Path):
            return str(item)
        if isinstance(item, Mapping):
            return {str(key): safe(subvalue) for key, subvalue in item.items()}
        if isinstance(item, (tuple, list)):
            return [safe(subitem) for subitem in item]
        if item is None or isinstance(item, (str, int, float, bool)):
            return item
        raise ValueError("ENABLED_MOD_ENTRY_UNSUPPORTED")

    return hashlib.sha256(canonical(safe(value)).encode("utf-8")).hexdigest()


def _ast_node(node: Any, *, counter: list[int], depth: int = 0) -> dict[str, Any]:
    if depth > 96:
        raise ValueError("AST_DEPTH_LIMIT")
    counter[0] += 1
    if counter[0] > MAX_TOTAL_AST_NODES:
        raise ValueError("AST_NODE_LIMIT")
    key = getattr(node, "key", None)
    assignment = getattr(node, "assignment", None)
    kind = getattr(node, "kind", None)
    value = getattr(node, "value", None)
    line = getattr(node, "line", None)
    end_line = getattr(node, "end_line", line)
    children = getattr(node, "children", None)
    if (not isinstance(key, str) or not key or len(key) > 65536
            or (assignment is not None and assignment not in AST_ASSIGNMENTS)
            or kind not in ("block", "scalar", "bare")
            or (value is not None and not isinstance(value, str))
            or type(line) is not int or line < 1 or type(end_line) is not int or end_line < line
            or not isinstance(children, list)):
        raise ValueError("AST_NODE_SHAPE_INVALID")
    if kind == "block" and value is not None:
        raise ValueError("AST_BLOCK_VALUE_INVALID")
    if kind == "scalar" and children:
        raise ValueError("AST_SCALAR_CHILDREN_INVALID")
    out: dict[str, Any] = {
        "key": key,
        "assignment": assignment,
        "kind": kind,
        "value": value,
        "children": [_ast_node(child, counter=counter, depth=depth + 1) for child in children],
        "line": line,
        "end_line": end_line,
    }
    for name in ("source_column", "end_column"):
        column = getattr(node, name, None)
        if column is not None:
            if type(column) is not int or column < 0:
                raise ValueError("AST_COLUMN_INVALID")
            out[name] = column
    return out


class ImperialReformDefinitionIndex:
    """Resolve and parse effective static reform declarations for EU4."""

    def __init__(
        self,
        game_root: str | Path | None = None,
        user_data: str | Path | None = None,
        enabled_mods: Sequence[str | Path | Mapping[str, Any]] | None = None,
        *,
        parser: Any | None = None,
        parser_manifest: str | Path | None = None,
    ) -> None:
        if parser is not None and parser_manifest is not None:
            raise ValueError("specify parser or parser_manifest, not both")
        self.game_root = (Path(game_root) if game_root is not None
                          else _static.StaticTradeSource._configured_path("game_root"))
        self.user_data = (Path(user_data) if user_data is not None
                          else _static.StaticTradeSource._configured_path("user_data"))
        self._explicit_enabled_mods = enabled_mods is not None
        if enabled_mods is None:
            self.enabled_mods: list[Any] | None = None
            self._requested_mod_signature = _explicit_mod_signature(None)
        elif isinstance(enabled_mods, (str, Path)):
            self.enabled_mods = [enabled_mods]
            self._requested_mod_signature = _explicit_mod_signature(self.enabled_mods)
        else:
            self.enabled_mods = list(enabled_mods)
            self._requested_mod_signature = _explicit_mod_signature(self.enabled_mods)
        self._initial_roots = {
            "game_root": str(self.game_root.resolve(strict=False)) if self.game_root is not None else None,
            "user_data": str(self.user_data.resolve(strict=False)) if self.user_data is not None else None,
        }
        self._max_file_bytes = DEFAULT_MAX_FILE_BYTES
        self._errors: list[dict[str, str]] = []
        self._gaps: list[dict[str, Any]] = []
        self._definitions: dict[str, list[dict[str, Any]]] = {"hre": [], "celestial_empire": []}
        self._unknown_count = 0
        self._effective_files: list[dict[str, Any]] = []
        self._directory_snapshots: list[dict[str, Any]] = []
        self._layer_roots: list[dict[str, Any]] = []
        self._cwt_contract: dict[str, Any] | None = None
        self._parser = parser
        self._parser_context: dict[str, Any] = {}
        self._parser_manifest = Path(parser_manifest).resolve() if parser_manifest is not None else None
        self._resolver: Any = None
        self._configuration_sha256: str | None = None
        self._definitions_sha256: str | None = None
        self._initial_directory_members = 0
        self._initial_effective_bytes = 0
        self._build()

    @staticmethod
    def _safe_candidate(root: Path, relative: str) -> Path:
        resolved_root = root.resolve(strict=True)
        candidate = resolved_root.joinpath(*PurePosixPath(relative).parts)
        resolved = candidate.resolve(strict=False)
        try:
            resolved.relative_to(resolved_root)
        except ValueError as exc:
            raise ValueError(f"PATH_ESCAPES_LAYER:{relative}") from exc
        return resolved

    def _make_shared_resolver(self) -> None:
        resolver = object.__new__(_SharedResolver)
        resolver.game_root = self.game_root
        resolver.user_data = self.user_data
        resolver._explicit_enabled_mods = self._explicit_enabled_mods
        resolver.enabled_mods = deepcopy(self.enabled_mods)
        resolver.max_file_bytes = self._max_file_bytes
        resolver._state = _ResolverState(compatibility=_static._StaticState())
        resolver._load_version()
        resolver._load_mods()
        for mod in resolver._state.mods:
            mod.replace_paths = tuple(_normalise_replace_path(value) for value in mod.replace_paths)
        self._resolver = resolver
        self._errors.extend(deepcopy(resolver._state.errors))
        self._errors.extend(deepcopy(resolver._state.compatibility.errors))
        if len(resolver._state.mods) > MAX_ENABLED_MODS:
            self._errors.append(_reason("MOD_COUNT_EXCEEDED", f"enabled mod count exceeds {MAX_ENABLED_MODS}"))

    def _make_parser(self) -> None:
        try:
            if self._parser is None:
                self._parser = CwtoolsScriptParser(self._parser_manifest)
            context = self._parser.context()
            if not isinstance(context, dict):
                raise ValueError("PARSER_CONTEXT_INVALID")
            self._parser_context = deepcopy(context)
            if context.get("status") != "ready" or context.get("complete") is not True:
                raise ValueError("PARSER_UNREADY")
            if not callable(getattr(self._parser, "parse_files", None)):
                raise ValueError("PARSER_API_INVALID")
            current = getattr(self._parser, "assert_current", None)
            if not callable(current):
                raise ValueError("PARSER_CURRENT_CHECK_UNAVAILABLE")
            current()
        except Exception as exc:
            self._errors.append(_reason("CWTOOLS_PARSER_UNAVAILABLE", str(exc)))
            self._parser_context = {"status": "unready", "complete": False,
                                    "semantics": "syntax_only", "reasons": [
                                        {"code": "CWTOOLS_PARSER_UNAVAILABLE"}]}

    def _read_cwt_contract(self) -> None:
        try:
            vendor_raw = _read_bounded(VENDOR_PATH, 256 * 1024)
            vendor = json.loads(vendor_raw.decode("utf-8-sig"))
            if (not isinstance(vendor, dict) or vendor.get("schema") != "cwtools-eu4-config.vendored-scope-rules.v1"
                    or vendor.get("commit") != EXPECTED_VENDOR_COMMIT or vendor.get("license") != "MIT"):
                raise ValueError("CWT_VENDOR_MANIFEST_MISMATCH")
            cwt = _pin(CWT_PATH, expected_bytes=EXPECTED_CWT_BYTES, expected_sha256=EXPECTED_CWT_SHA256)
            self._cwt_contract = {
                "repository_url": vendor.get("repository_url"),
                "commit": vendor["commit"],
                "license": vendor["license"],
                "vendor_manifest": {"path": str(VENDOR_PATH.resolve()),
                                    "bytes": len(vendor_raw), "sha256": _sha256(vendor_raw)},
                "schema_file": cwt,
                "schema_validation_complete": False,
                "used_for": "type_and_path_contract_reference_only",
            }
            self._vendor_raw = vendor_raw
        except Exception as exc:
            self._cwt_contract = None
            self._errors.append(_reason("CWT_CONTRACT_UNAVAILABLE", str(exc)))

    def _scan_layer(self, index: int, layer: Any, member_budget: int = MAX_DIRECTORY_MEMBERS
                    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        root = Path(layer.root)
        scope_path = self._safe_candidate(root, REFORM_DIRECTORY)
        root_resolved = root.resolve(strict=True)
        try:
            scope_path.relative_to(root_resolved)
        except ValueError as exc:
            raise ValueError(f"REFORM_DIRECTORY_ESCAPES_LAYER:{root}") from exc
        if not scope_path.exists():
            return ({"layer_index": index, "root": str(root_resolved),
                     "source_kind": layer.kind, "source": layer.source,
                     "directory": str(scope_path), "exists": False, "is_directory": False,
                     "members": None}, [])
        if _is_reparse(scope_path):
            raise ValueError(f"REFORM_DIRECTORY_REPARSE_POINT:{scope_path}")
        if not scope_path.is_dir():
            raise ValueError(f"REFORM_DIRECTORY_NOT_DIRECTORY:{scope_path}")
        members: list[dict[str, str]] = []
        candidates: list[dict[str, Any]] = []
        pending: list[tuple[Path, str]] = [(scope_path, "")]
        while pending:
            directory, relative_dir = pending.pop()
            try:
                with os.scandir(directory) as scan:
                    names: list[str] = []
                    for entry in scan:
                        names.append(entry.name)
                        if len(members) + len(names) > member_budget:
                            raise ValueError("DIRECTORY_MEMBER_LIMIT")
            except Exception as exc:
                raise ValueError(f"REFORM_DIRECTORY_SCAN_FAILED:{directory}:{exc}") from exc
            names.sort(key=lambda name: (name.casefold(), name))
            for name in names:
                child = directory / name
                relative = f"{relative_dir}/{name}" if relative_dir else name
                try:
                    info = child.lstat()
                    if _is_reparse(child, info.st_mode, getattr(info, "st_file_attributes", 0)):
                        raise ValueError(f"REFORM_ENTRY_REPARSE_POINT:{child}")
                    is_directory = stat.S_ISDIR(info.st_mode)
                    is_file = stat.S_ISREG(info.st_mode)
                    if not is_directory and not is_file:
                        raise ValueError(f"REFORM_ENTRY_TYPE_UNSUPPORTED:{child}")
                    members.append({"relative": relative, "kind": "directory" if is_directory else "file"})
                    if len(members) > member_budget:
                        raise ValueError("DIRECTORY_MEMBER_LIMIT")
                    if is_directory:
                        pending.append((child, relative))
                    elif not relative_dir and child.suffix.casefold() == ".txt":
                        safe = self._safe_candidate(root, f"{REFORM_DIRECTORY}/{name}")
                        candidates.append({
                            "relative": f"{REFORM_DIRECTORY}/{name}",
                            "path": safe,
                            "source_kind": layer.kind,
                            "source": layer.source,
                            "layer_index": index,
                        })
                except Exception as exc:
                    if isinstance(exc, ValueError) and str(exc) in {"DIRECTORY_MEMBER_LIMIT"}:
                        raise
                    raise ValueError(f"REFORM_DIRECTORY_ENTRY_INVALID:{child}:{exc}") from exc
        members.sort(key=lambda item: (item["relative"].casefold(), item["relative"], item["kind"]))
        candidates.sort(key=lambda item: (item["relative"].casefold(), item["relative"]))
        return ({"layer_index": index, "root": str(root_resolved),
                 "source_kind": layer.kind, "source": layer.source,
                 "directory": str(scope_path), "exists": True, "is_directory": True,
                 "members": members}, candidates)

    @staticmethod
    def _replacement_affects(relative: str, replace_path: str) -> bool:
        return _is_prefix(relative, replace_path)

    def _resolve_effective_files(self) -> None:
        layers = self._resolver._state.layers
        if not layers:
            self._errors.append(_reason("DEFINITION_LAYERS_UNAVAILABLE", "no game data layers resolved"))
            return
        winners: dict[str, dict[str, Any]] = {}
        snapshots: list[dict[str, Any]] = []
        total_members = 0
        all_layer_candidates: list[list[dict[str, Any]]] = []
        for index, layer in enumerate(layers):
            try:
                remaining_members = MAX_DIRECTORY_MEMBERS - total_members
                snapshot, candidates = self._scan_layer(index, layer, remaining_members)
            except Exception as exc:
                self._errors.append(_reason("DEFINITION_DIRECTORY_INVALID", str(exc)))
                snapshot, candidates = ({"layer_index": index, "root": str(layer.root),
                                         "source_kind": layer.kind, "source": layer.source,
                                         "directory": None, "exists": False, "is_directory": False,
                                         "members": None}, [])
            snapshots.append(snapshot)
            total_members += len(snapshot["members"] or [])
            if total_members > MAX_DIRECTORY_MEMBERS:
                self._errors.append(_reason("DIRECTORY_MEMBER_LIMIT", f"directory members exceed {MAX_DIRECTORY_MEMBERS}"))
            all_layer_candidates.append(candidates)
            seen_in_layer: set[str] = set()
            for candidate in candidates:
                key = candidate["relative"].casefold()
                if key in seen_in_layer:
                    self._errors.append(_reason("DUPLICATE_DEFINITION_PATH", candidate["relative"]))
                seen_in_layer.add(key)
            if index > 0:
                mod = self._resolver._state.mods[index - 1] if index - 1 < len(self._resolver._state.mods) else None
                replace_paths = tuple(mod.replace_paths) if mod is not None else ()
                for replace_path in replace_paths:
                    normalized = _normalise_replace_path(replace_path).casefold()
                    removed = [key for key, item in winners.items()
                               if self._replacement_affects(item["relative"].casefold(), normalized)]
                    for key in removed:
                        del winners[key]
                    replacement_files = [item for item in candidates
                                         if self._replacement_affects(item["relative"].casefold(), normalized)]
                    if removed and not replacement_files:
                        self._errors.append(_reason(
                            "REPLACED_DEFINITION_PATH_EMPTY",
                            f"replace_path removed reform definitions without replacements: {replace_path}",
                        ))
            for candidate in candidates:
                winners[candidate["relative"].casefold()] = candidate

        if not layers[0].root.is_dir():
            self._errors.append(_reason("GAME_ROOT_UNAVAILABLE", f"game root not found: {layers[0].root}"))
        self._directory_snapshots = snapshots
        self._initial_directory_members = total_members
        effective = [winners[key] for key in sorted(winners)]
        if len(effective) > MAX_EFFECTIVE_FILES:
            self._errors.append(_reason("DEFINITION_FILE_LIMIT", f"effective files exceed {MAX_EFFECTIVE_FILES}"))
            return
        total_bytes = self._resolver._configuration_bytes()
        resolved: list[dict[str, Any]] = []
        for item in effective:
            try:
                path = Path(item["path"])
                size = path.stat().st_size
                if size < 0 or size > self._max_file_bytes:
                    raise ValueError(f"INPUT_SIZE_OUT_OF_RANGE:{size}:{path}")
                raw = _read_bounded(path, self._max_file_bytes, allow_empty=True)
                if len(raw) != size:
                    raise ValueError(f"INPUT_CHANGED_DURING_READ:{path}")
                total_bytes += size
                if total_bytes > MAX_TOTAL_INPUT_BYTES:
                    raise ValueError("TOTAL_INPUT_LIMIT_EXCEEDED")
                resolved.append({
                    **item, "size": size, "sha256": _sha256(raw),
                })
            except Exception as exc:
                self._errors.append(_reason("DEFINITION_FILE_INVALID", f"{item['relative']}: {exc}"))
        self._initial_effective_bytes = sum(item["size"] for item in resolved)
        self._effective_files = resolved
        # Preserve resolver configuration hashes while adding this index's
        # directory membership, parser, and fixed CWT contract pins.
        compat = self._resolver._state.compatibility
        self._resolver._state.input_fingerprints.update(compat.fingerprint)
        config_material = {
            "configuration_files": [dict(item) for item in compat.configuration_files],
            "enabled_mods": [
                {"descriptor": str(mod.descriptor), "descriptor_sha256": mod.descriptor_sha256,
                 "root": str(mod.root), "replace_paths": list(mod.replace_paths)}
                for mod in self._resolver._state.mods
            ],
            "directory_candidates": self._directory_snapshots,
            "parser": self._parser_context,
            "cwt_contract": self._cwt_contract,
        }
        self._configuration_sha256 = _sha256(canonical(config_material).encode("utf-8"))
        self._definitions_sha256 = _sha256(canonical([
            {"relative": item["relative"], "sha256": item["sha256"], "size": item["size"],
             "source_kind": item["source_kind"], "source": item["source"]}
            for item in resolved
        ]).encode("utf-8"))

    def _parse_definitions(self) -> None:
        if self._errors:
            return
        paths = [Path(item["path"]).resolve() for item in self._effective_files]
        try:
            self._parser.assert_current()
            parsed = self._parser.parse_files(paths)
            self._parser.assert_current()
            parser_context = self._parser.context()
            if parser_context != self._parser_context:
                raise ValueError("CWTOOLS_PARSER_CONTEXT_CHANGED")
            if not isinstance(parsed, dict) or set(parsed) != {str(path) for path in paths}:
                raise ValueError("CWTOOLS_OUTPUT_FILES_MISMATCH")
        except Exception as exc:
            self._errors.append(_reason("CWTOOLS_PARSE_FAILED", str(exc)))
            return
        seen_ids: dict[str, str] = {}
        total_nodes = [0]
        definitions: dict[str, list[dict[str, Any]]] = {"hre": [], "celestial_empire": []}
        gaps: list[dict[str, Any]] = []
        for file_item, path in zip(self._effective_files, paths):
            result = parsed.get(str(path))
            if not isinstance(result, dict) or "error" in result:
                self._errors.append(_reason("CWTOOLS_FILE_PARSE_FAILED", file_item["relative"]))
                continue
            parser_echo = result.get("parser")
            if not isinstance(parser_echo, dict) or parser_echo.get("manifest_sha256") != self._parser_context.get("manifest_sha256"):
                self._errors.append(_reason("CWTOOLS_FILE_PARSER_ECHO_INVALID", file_item["relative"]))
                continue
            roots = result.get("nodes")
            if not isinstance(roots, list):
                self._errors.append(_reason("CWTOOLS_ROOTS_INVALID", file_item["relative"]))
                continue
            for root_node in roots:
                root_id = getattr(root_node, "key", None)
                line = getattr(root_node, "line", None)
                if (not isinstance(root_id, str) or not REFORM_ID_RE.fullmatch(root_id)
                        or len(root_id) > MAX_REFORM_ID_LENGTH):
                    self._errors.append(_reason("REFORM_ID_INVALID", f"{file_item['relative']}:{line}"))
                    continue
                root_kind = getattr(root_node, "kind", None)
                root_assignment = getattr(root_node, "assignment", None)
                root_children = getattr(root_node, "children", None)
                if root_kind != "block" or root_assignment != "=" or not isinstance(root_children, list):
                    self._errors.append(_reason("REFORM_ROOT_SHAPE_INVALID", f"{file_item['relative']}:{root_id}"))
                    continue
                id_key = root_id.casefold()
                if id_key in seen_ids:
                    self._errors.append(_reason(
                        "REFORM_ID_DUPLICATE", f"{root_id} in {seen_ids[id_key]} and {file_item['relative']}"
                    ))
                    continue
                seen_ids[id_key] = file_item["relative"]
                declarations = [_ast_node(child, counter=total_nodes) for child in root_children]
                empire_declarations = [child for child in root_children if getattr(child, "key", None) == "empire"]
                assigned_empire: str | None = None
                gap_reason: str | None = None
                empire_values: list[str | None] = []
                for node in empire_declarations:
                    value = getattr(node, "value", None)
                    empire_values.append(value if isinstance(value, str) else None)
                if len(empire_declarations) != 1:
                    gap_reason = "EMPIRE_DECLARATION_MISSING" if not empire_declarations else "EMPIRE_DECLARATION_AMBIGUOUS"
                else:
                    empire_node = empire_declarations[0]
                    if (getattr(empire_node, "kind", None) != "scalar"
                            or getattr(empire_node, "assignment", None) != "="
                            or not isinstance(getattr(empire_node, "value", None), str)):
                        gap_reason = "EMPIRE_DECLARATION_NOT_EXPLICIT_SCALAR"
                    elif empire_node.value in definitions:
                        assigned_empire = empire_node.value
                    else:
                        gap_reason = "EMPIRE_VALUE_UNKNOWN"
                if assigned_empire is None:
                    gaps.append({"reform_id": root_id, "relative_file": file_item["relative"],
                                 "line": line, "reason": gap_reason, "empire_values": empire_values})
                    continue
                record = {
                    "reform_id": root_id,
                    "empire": assigned_empire,
                    "relative_file": file_item["relative"],
                    "line": line,
                    "declarations": declarations,
                }
                definitions[assigned_empire].append(record)
        self._definitions = definitions
        self._gaps = gaps
        self._unknown_count = len(gaps)

    def _build(self) -> None:
        try:
            self._make_shared_resolver()
        except Exception as exc:
            self._errors.append(_reason("MOD_RESOLVER_UNAVAILABLE", str(exc)))
        self._read_cwt_contract()
        self._make_parser()
        if self._resolver is not None:
            self._resolve_effective_files()
        if not self._errors:
            self._parse_definitions()

    def _current_errors(self) -> list[dict[str, str]]:
        errors: list[dict[str, str]] = []
        if self._resolver is None:
            return [_reason("MOD_RESOLVER_UNAVAILABLE", "shared mod resolver is unavailable")]
        current_roots = {
            "game_root": str(self.game_root.resolve(strict=False)) if self.game_root is not None else None,
            "user_data": str(self.user_data.resolve(strict=False)) if self.user_data is not None else None,
        }
        if current_roots != self._initial_roots:
            errors.append(_reason("INPUT_CHANGED", "configured game_root or user_data changed"))
        try:
            signature = _explicit_mod_signature(self.enabled_mods if self._explicit_enabled_mods else None)
            if signature != self._requested_mod_signature:
                errors.append(_reason("INPUT_CHANGED", "enabled_mods request changed"))
        except Exception as exc:
            errors.append(_reason("INPUT_CHANGED", str(exc)))
        try:
            errors.extend(self._resolver._fingerprint_errors())
        except Exception as exc:
            errors.append(_reason("INPUT_CHANGED", f"configuration recheck failed: {exc}"))
        try:
            if self._parser is None:
                raise ValueError("parser missing")
            self._parser.assert_current()
            parser_context = self._parser.context()
            if parser_context != self._parser_context:
                raise ValueError("CWTOOLS_PARSER_CONTEXT_CHANGED")
        except Exception as exc:
            errors.append(_reason("INPUT_CHANGED", f"CWTools parser changed: {exc}"))
        try:
            vendor_raw = _read_bounded(VENDOR_PATH, 256 * 1024)
            vendor = json.loads(vendor_raw.decode("utf-8-sig"))
            cwt = _pin(CWT_PATH, expected_bytes=EXPECTED_CWT_BYTES,
                       expected_sha256=EXPECTED_CWT_SHA256)
            if (not isinstance(vendor, dict) or vendor.get("commit") != EXPECTED_VENDOR_COMMIT
                    or vendor.get("license") != "MIT"
                    or self._cwt_contract is None
                    or _sha256(vendor_raw) != self._cwt_contract["vendor_manifest"]["sha256"]
                    or cwt != self._cwt_contract["schema_file"]):
                raise ValueError("CWT_CONTRACT_CHANGED")
        except Exception as exc:
            errors.append(_reason("INPUT_CHANGED", f"CWT contract changed: {exc}"))
        try:
            current_snapshots: list[dict[str, Any]] = []
            total_members = 0
            for index, layer in enumerate(self._resolver._state.layers):
                snapshot, _candidates = self._scan_layer(
                    index, layer, MAX_DIRECTORY_MEMBERS - total_members
                )
                total_members += len(snapshot["members"] or [])
                current_snapshots.append(snapshot)
            if current_snapshots != self._directory_snapshots:
                errors.append(_reason("INPUT_CHANGED", "reform definition directory membership changed"))
        except Exception as exc:
            errors.append(_reason("INPUT_CHANGED", f"reform directory changed: {exc}"))
        for item in self._effective_files:
            try:
                path = Path(item["path"])
                raw = _read_bounded(path, self._max_file_bytes, allow_empty=True)
                if len(raw) != item["size"] or _sha256(raw) != item["sha256"]:
                    errors.append(_reason("INPUT_CHANGED", f"selected reform file changed: {item['relative']}"))
            except Exception as exc:
                errors.append(_reason("INPUT_CHANGED", f"selected reform file unavailable: {item['relative']}: {exc}"))
        return errors

    def assert_current(self) -> None:
        if self._errors:
            first = self._errors[0]["code"]
            raise ValueError(f"IMPERIAL_REFORM_INDEX_UNREADY:{first}")
        errors = self._current_errors()
        if errors:
            raise ValueError(f"IMPERIAL_REFORM_INDEX_CHANGED:{errors[0]['code']}")

    def context(self) -> dict[str, Any]:
        reasons = deepcopy(self._errors)
        if not reasons:
            reasons.extend(self._current_errors())
        status = "ready" if not reasons else "unready"
        mods = []
        if self._resolver is not None:
            mods = [{
                "descriptor": str(item.descriptor),
                "descriptor_sha256": item.descriptor_sha256,
                "name": item.name,
                "root": str(item.root) if item.root is not None else None,
                "replace_paths": list(item.replace_paths),
            } for item in self._resolver._state.mods]
        return {
            "status": status,
            "complete": False,
            "mode": "static_definition_index",
            "game_version": self._resolver._state.game_version if self._resolver is not None else None,
            "configuration_sha256": self._configuration_sha256,
            "definitions_sha256": self._definitions_sha256,
            "game_root": str(self.game_root) if self.game_root is not None else None,
            "user_data": str(self.user_data) if self.user_data is not None else None,
            "enabled_mods": mods,
            "configuration_files": deepcopy(list(self._resolver._state.compatibility.configuration_files))
                if self._resolver is not None else [],
            "definition_files": [
                {**{key: value for key, value in item.items() if key != "path"},
                 "path": str(item["path"])}
                for item in self._effective_files
            ],
            "directory_candidates": deepcopy(self._directory_snapshots),
            "script_parser": deepcopy(self._parser_context),
            "cwt_contract": deepcopy(self._cwt_contract),
            "definition_count": sum(len(items) for items in self._definitions.values()),
            "hre_definition_count": len(self._definitions["hre"]),
            "celestial_empire_definition_count": len(self._definitions["celestial_empire"]),
            "unknown_empire_count": self._unknown_count,
            "unknown_empire_definitions": deepcopy(self._gaps),
            "static_semantics": {
                "conditions_evaluated": False,
                "effects_executed": False,
                "current_reform_state_observed": False,
                "cwt_schema_validation_complete": False,
            },
            "reasons": reasons,
        }

    def definitions(self, empire: str = "hre") -> list[dict[str, Any]]:
        if not isinstance(empire, str) or empire not in self._definitions:
            raise ValueError("unsupported empire; expected 'hre' or 'celestial_empire'")
        self.assert_current()
        return deepcopy(self._definitions[empire])

