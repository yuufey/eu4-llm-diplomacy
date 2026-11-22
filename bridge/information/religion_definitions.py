"""Bounded index of effective EU4 religion definitions.

The index resolves ``common/religions`` through the same game/mod resolver
used by the static-data sources, then uses the pinned CWTools syntax parser.
It only relates a directly nested religion definition key to its enclosing
religion-group key; it does not evaluate triggers or effects.
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
from .imperial_reform_definitions import AST_ASSIGNMENTS as _AST_ASSIGNMENTS
from .imperial_reform_definitions import _ast_node as _serialize_ast_node
from .model import canonical
from .strait_definitions import (
    DEFAULT_MAX_FILE_BYTES,
    MAX_ENABLED_MODS,
    StraitDefinitionIndex as _SharedResolver,
    _IndexState as _ResolverState,
    _normalise_replace_path,
)


ROOT = Path(__file__).resolve().parents[2]
RELIGION_DIRECTORY = "common/religions"
MAX_EFFECTIVE_FILES = 512
MAX_DIRECTORY_MEMBERS = 4096
MAX_TOTAL_INPUT_BYTES = 16 * 1024 * 1024
MAX_TOTAL_DEFINITIONS = 524288
MAX_KEY_LENGTH = 128
MAX_DECLARATION_AST_NODES = 32768
MAX_DECLARATION_AST_DEPTH = 64
MAX_DECLARATION_JSON_BYTES = 2 * 1024 * 1024
RELIGION_KEY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
VENDOR_PATH = ROOT / "third_party/cwtools-eu4-config/VENDOR.json"
SIDECAR_VENDOR_PATH = ROOT / "third_party/cwtools-eu4-config.vendor.json"
CWT_PATH = ROOT / "third_party/cwtools-eu4-config/common/religions_and_related.cwt"
EXPECTED_VENDOR_COMMIT = "a85622d368bbb7afca938ed70fdd5eda44aec769"
EXPECTED_CWT_BYTES = 22541
EXPECTED_CWT_SHA256 = "bc7e80059f6b71acd12b8af9d8bf2d98850b891073326d845a1d62aa8760f1af"
# The fixed CWT type_key_filter for religion_group excludes these direct
# children from type[religion] recognition.
NON_RELIGION_GROUP_CHILDREN = frozenset({"religious_schools", "flag_emblem_index_range"})
_INVALID_PATH_CHARS = ("\x00",)


def _vendor_manifest_path() -> Path:
    return VENDOR_PATH if VENDOR_PATH.is_file() else SIDECAR_VENDOR_PATH


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
    return stat.S_ISLNK(mode) or bool(attributes & 0x400)


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


class ReligionDefinitionIndex:
    """Resolve religion-key to group-key mappings from effective script files.

    Configuration changes invalidate this instance. Construct a new index to
    use changed game or mod inputs; an old instance never falls back to stale
    definitions.
    """

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
            request_mods: Any = None
        elif isinstance(enabled_mods, (str, Path)):
            self.enabled_mods = [enabled_mods]
            request_mods = self.enabled_mods
        else:
            self.enabled_mods = list(enabled_mods)
            request_mods = self.enabled_mods
        self._requested_mod_signature = _explicit_mod_signature(request_mods)
        self._initial_roots = {
            "game_root": self._root_identity(self.game_root),
            "user_data": self._root_identity(self.user_data),
        }
        self._max_file_bytes = DEFAULT_MAX_FILE_BYTES
        self._errors: list[dict[str, str]] = []
        self._parser = parser
        self._parser_context: dict[str, Any] = {}
        self._parser_manifest = Path(parser_manifest).resolve() if parser_manifest is not None else None
        self._resolver: Any = None
        self._effective_files: list[dict[str, Any]] = []
        self._directory_snapshots: list[dict[str, Any]] = []
        self._cwt_contract: dict[str, Any] | None = None
        self._configuration_sha256: str | None = None
        self._definitions_sha256: str | None = None
        self._religions: dict[str, list[dict[str, Any]]] = {}
        self._groups: dict[str, list[dict[str, Any]]] = {}
        self._group_counts: dict[str, int] = {}
        self._duplicate_group_keys: list[str] = []
        self._invalid_definition_count = 0
        self._build()

    @staticmethod
    def _root_identity(path: Path | None) -> str | None:
        return str(path.resolve(strict=False)) if path is not None else None

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

    def _add_error(self, code: str, message: str) -> None:
        self._errors.append(_reason(code, message))

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
        self._resolver = resolver
        self._errors.extend(deepcopy(resolver._state.errors))
        self._errors.extend(deepcopy(resolver._state.compatibility.errors))
        if len(resolver._state.mods) > MAX_ENABLED_MODS:
            self._add_error("MOD_COUNT_EXCEEDED", f"enabled mods exceed {MAX_ENABLED_MODS}")

    def _make_parser(self) -> None:
        try:
            if self._parser is None:
                self._parser = CwtoolsScriptParser(self._parser_manifest)
            context = self._parser.context()
            if (not isinstance(context, dict) or context.get("status") != "ready"
                    or context.get("complete") is not True
                    or not callable(getattr(self._parser, "parse_files", None))
                    or not callable(getattr(self._parser, "assert_current", None))):
                raise ValueError("CWTOOLS_PARSER_UNREADY")
            self._parser.assert_current()
            self._parser_context = deepcopy(context)
        except Exception as exc:
            self._add_error("CWTOOLS_PARSER_UNAVAILABLE", str(exc))
            self._parser_context = {
                "status": "unready", "complete": False,
                "semantics": "syntax_only", "conditions_evaluated": False,
                "effects_executed": False,
                "reasons": [{"code": "CWTOOLS_PARSER_UNAVAILABLE"}],
            }

    def _read_cwt_contract(self) -> None:
        try:
            vendor_raw = _read_bounded(_vendor_manifest_path(), 256 * 1024)
            vendor = json.loads(vendor_raw.decode("utf-8-sig"))
            if (not isinstance(vendor, dict)
                    or vendor.get("schema") != "cwtools-eu4-config.vendored-scope-rules.v1"
                    or vendor.get("commit") != EXPECTED_VENDOR_COMMIT
                    or vendor.get("license") != "MIT"):
                raise ValueError("CWT_VENDOR_MANIFEST_MISMATCH")
            cwt = _pin(CWT_PATH, expected_bytes=EXPECTED_CWT_BYTES,
                       expected_sha256=EXPECTED_CWT_SHA256)
            self._cwt_contract = {
                "repository_url": vendor.get("repository_url"),
                "commit": vendor["commit"],
                "license": vendor["license"],
                "vendor_manifest": {"bytes": len(vendor_raw), "sha256": _sha256(vendor_raw)},
                "schema_file": {key: value for key, value in cwt.items() if key != "path"},
                "religion_group_non_religion_children": sorted(NON_RELIGION_GROUP_CHILDREN),
                "used_for": "religion_group_child_key_filter_reference_only",
            }
            self._vendor_sha256 = _sha256(vendor_raw)
        except Exception as exc:
            self._cwt_contract = None
            self._vendor_sha256 = None
            self._add_error("CWT_CONTRACT_UNAVAILABLE", str(exc))

    def _scan_layer(self, index: int, layer: Any, member_budget: int
                    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        root = Path(layer.root)
        scope_path = self._safe_candidate(root, RELIGION_DIRECTORY)
        root_resolved = root.resolve(strict=True)
        try:
            scope_path.relative_to(root_resolved)
        except ValueError as exc:
            raise ValueError(f"RELIGION_DIRECTORY_ESCAPES_LAYER:{root}") from exc
        if not scope_path.exists():
            return ({"layer_index": index, "source_kind": layer.kind,
                     "exists": False,
                     "is_directory": False, "members": None}, [])
        if _is_reparse(scope_path):
            raise ValueError(f"RELIGION_DIRECTORY_REPARSE_POINT:{scope_path}")
        if not scope_path.is_dir():
            raise ValueError(f"RELIGION_DIRECTORY_NOT_DIRECTORY:{scope_path}")

        members: list[dict[str, str]] = []
        candidates: list[dict[str, Any]] = []
        pending: list[tuple[Path, str]] = [(scope_path, "")]
        while pending:
            directory, relative_dir = pending.pop()
            try:
                with os.scandir(directory) as scan:
                    names = []
                    for entry in scan:
                        names.append(entry.name)
                        if len(members) + len(names) > member_budget:
                            raise ValueError("DIRECTORY_MEMBER_LIMIT")
                    names.sort(key=lambda name: (name.casefold(), name))
            except Exception as exc:
                if isinstance(exc, ValueError) and str(exc) == "DIRECTORY_MEMBER_LIMIT":
                    raise
                raise ValueError(f"RELIGION_DIRECTORY_SCAN_FAILED:{exc}") from exc
            for name in names:
                child = directory / name
                relative = f"{relative_dir}/{name}" if relative_dir else name
                try:
                    info = child.lstat()
                    if _is_reparse(child, info.st_mode, getattr(info, "st_file_attributes", 0)):
                        raise ValueError("REPARSE_POINT")
                    is_directory = stat.S_ISDIR(info.st_mode)
                    is_file = stat.S_ISREG(info.st_mode)
                    if not is_directory and not is_file:
                        raise ValueError("ENTRY_TYPE_UNSUPPORTED")
                    members.append({"relative": relative,
                                    "kind": "directory" if is_directory else "file"})
                    if len(members) > member_budget:
                        raise ValueError("DIRECTORY_MEMBER_LIMIT")
                    if is_directory:
                        pending.append((child, relative))
                    elif child.suffix.casefold() == ".txt":
                        full_relative = f"{RELIGION_DIRECTORY}/{relative}"
                        safe = self._safe_candidate(root, full_relative)
                        candidates.append({
                            "relative": full_relative, "path": safe,
                            "source_kind": layer.kind, "source": layer.source,
                            "layer_index": index,
                        })
                except Exception as exc:
                    if isinstance(exc, ValueError) and str(exc) == "DIRECTORY_MEMBER_LIMIT":
                        raise
                    raise ValueError(f"RELIGION_DIRECTORY_ENTRY_INVALID:{relative}:{exc}") from exc
        members.sort(key=lambda item: (item["relative"].casefold(), item["relative"], item["kind"]))
        candidates.sort(key=lambda item: (item["relative"].casefold(), item["relative"]))
        return ({"layer_index": index, "source_kind": layer.kind,
                 "exists": True, "is_directory": True,
                 "members": members}, candidates)

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
            except Exception as exc:
                self._add_error("DEFINITION_DIRECTORY_INVALID", str(exc))
                snapshot, candidates = ({"layer_index": index,
                    "source_kind": layer.kind,
                    "exists": False, "is_directory": False, "members": None}, [])
            snapshots.append(snapshot)
            total_members += len(snapshot["members"] or [])
            if total_members > MAX_DIRECTORY_MEMBERS:
                self._add_error("DIRECTORY_MEMBER_LIMIT", "religion directory members exceed limit")
            seen_in_layer: set[str] = set()
            for candidate in candidates:
                key = candidate["relative"].casefold()
                if key in seen_in_layer:
                    self._add_error("DUPLICATE_DEFINITION_PATH", candidate["relative"])
                seen_in_layer.add(key)

            if index > 0:
                mod = (self._resolver._state.mods[index - 1]
                       if index - 1 < len(self._resolver._state.mods) else None)
                replace_paths = tuple(mod.replace_paths) if mod is not None else ()
                for replace_path in replace_paths:
                    normalized = _normalise_replace_path(replace_path).casefold()
                    removed = [key for key, item in winners.items()
                               if _is_prefix(item["relative"], normalized)]
                    for key in removed:
                        del winners[key]
                    replacement_files = [item for item in candidates
                                         if _is_prefix(item["relative"].casefold(), normalized)]
                    if removed and not replacement_files:
                        self._add_error("REPLACED_DEFINITION_PATH_EMPTY",
                            f"replace_path removed religion definitions without replacements: {replace_path}")
            for candidate in candidates:
                winners[candidate["relative"].casefold()] = candidate

        if total_members > MAX_DIRECTORY_MEMBERS:
            return
        if not self._resolver._state.layers[0].root.is_dir():
            self._add_error("GAME_ROOT_UNAVAILABLE", "game root is not a directory")
        self._directory_snapshots = snapshots
        effective = [winners[key] for key in sorted(winners)]
        if len(effective) > MAX_EFFECTIVE_FILES:
            self._add_error("DEFINITION_FILE_LIMIT", f"effective files exceed {MAX_EFFECTIVE_FILES}")
            return

        total_bytes = self._resolver._configuration_bytes()
        resolved: list[dict[str, Any]] = []
        for item in effective:
            try:
                size = item["path"].stat().st_size
                raw = _read_bounded(item["path"], self._max_file_bytes, allow_empty=True)
                if len(raw) != size:
                    raise ValueError("INPUT_CHANGED_DURING_READ")
                total_bytes += size
                if total_bytes > MAX_TOTAL_INPUT_BYTES:
                    raise ValueError("TOTAL_INPUT_LIMIT_EXCEEDED")
                resolved.append({**item, "size": size, "sha256": _sha256(raw)})
            except Exception as exc:
                self._add_error("DEFINITION_FILE_INVALID", f"{item['relative']}: {exc}")
        self._effective_files = resolved

        compat = self._resolver._state.compatibility
        self._resolver._state.input_fingerprints.update(compat.fingerprint)
        config_material = {
            "configuration_files": [dict(item) for item in compat.configuration_files],
            "enabled_mods": [
                {"descriptor_sha256": mod.descriptor_sha256, "name": mod.name,
                 "replace_paths": list(mod.replace_paths)}
                for mod in self._resolver._state.mods
            ],
            "directory_candidates": self._directory_snapshots,
            "parser": self._parser_context,
            "cwt_contract": self._cwt_contract,
        }
        self._configuration_sha256 = _sha256(canonical(config_material).encode("utf-8"))
        self._definitions_sha256 = _sha256(canonical([
            {"relative": item["relative"], "sha256": item["sha256"], "size": item["size"],
             "source_kind": item["source_kind"]}
            for item in resolved
        ]).encode("utf-8"))

    def _parse_definitions(self) -> None:
        if self._errors:
            return
        if not self._effective_files:
            # A normal empty directory is a ready, empty index, not a parser failure.
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
            self._add_error("CWTOOLS_PARSE_FAILED", str(exc))
            return

        religions: dict[str, list[dict[str, Any]]] = {}
        groups: dict[str, list[dict[str, Any]]] = {}
        group_counts: dict[str, int] = {}
        group_names: dict[str, str] = {}
        definition_total = 0
        for file_item, path in zip(self._effective_files, paths):
            result = parsed.get(str(path))
            if not isinstance(result, dict) or "error" in result:
                self._add_error("CWTOOLS_FILE_PARSE_FAILED", file_item["relative"])
                continue
            parser_echo = result.get("parser")
            if (not isinstance(parser_echo, dict)
                    or parser_echo.get("manifest_sha256") != self._parser_context.get("manifest_sha256")):
                self._add_error("CWTOOLS_FILE_PARSER_ECHO_INVALID", file_item["relative"])
                continue
            roots = result.get("nodes")
            if not isinstance(roots, list):
                self._add_error("CWTOOLS_ROOTS_INVALID", file_item["relative"])
                continue
            for group_node in roots:
                group_key = getattr(group_node, "key", None)
                group_kind = getattr(group_node, "kind", None)
                if group_kind != "block":
                    continue
                group_line = getattr(group_node, "line", None)
                group_children = getattr(group_node, "children", None)
                if (not isinstance(group_key, str) or not RELIGION_KEY_RE.fullmatch(group_key)
                        or len(group_key) > MAX_KEY_LENGTH
                        or getattr(group_node, "assignment", None) != "="
                        or not isinstance(group_children, list)):
                    self._add_error("RELIGION_GROUP_SHAPE_INVALID", file_item["relative"])
                    continue
                group_id = group_key.casefold()
                group_counts[group_id] = group_counts.get(group_id, 0) + 1
                group_names.setdefault(group_id, group_key)
                group_record = {
                    "religion_group_key": group_key,
                    "relative_file": file_item["relative"],
                    "line": group_line,
                    "file_sha256": file_item["sha256"],
                    "source_kind": file_item["source_kind"],
                    "source": file_item["source"],
                }
                groups.setdefault(group_id, []).append(group_record)
                for religion_node in group_children:
                    key = getattr(religion_node, "key", None)
                    kind = getattr(religion_node, "kind", None)
                    if not isinstance(key, str) or key.casefold() in NON_RELIGION_GROUP_CHILDREN:
                        continue
                    if kind != "block":
                        continue
                    if not RELIGION_KEY_RE.fullmatch(key) or len(key) > MAX_KEY_LENGTH:
                        self._invalid_definition_count += 1
                        continue
                    definition_total += 1
                    if definition_total > MAX_TOTAL_DEFINITIONS:
                        self._add_error("RELIGION_DEFINITION_LIMIT", "religion definitions exceed limit")
                        return
                    valid = getattr(religion_node, "assignment", None) == "="
                    record = {
                        "religion_key": key,
                        "religion_group_key": group_key,
                        "group_id": group_id,
                        "valid": valid,
                        "relative_file": file_item["relative"],
                        "line": getattr(religion_node, "line", None),
                        "group_line": group_line,
                        "file_sha256": file_item["sha256"],
                        "source_kind": file_item["source_kind"],
                        "source": file_item["source"],
                    }
                    religions.setdefault(key.casefold(), []).append(record)
        self._religions = religions
        self._groups = groups
        self._group_counts = group_counts
        self._duplicate_group_keys = sorted(
            (group_names[key] for key, count in group_counts.items() if count > 1),
            key=lambda value: (value.casefold(), value),
        )

    def _build(self) -> None:
        try:
            self._make_shared_resolver()
        except Exception as exc:
            self._add_error("MOD_RESOLVER_UNAVAILABLE", str(exc))
        self._read_cwt_contract()
        self._make_parser()
        if self._resolver is not None:
            self._resolve_effective_files()
        if not self._errors:
            self._parse_definitions()

    def _current_errors(self) -> list[dict[str, str]]:
        errors: list[dict[str, str]] = []
        if self._resolver is None:
            return [_reason("MOD_RESOLVER_UNAVAILABLE", "shared resolver is unavailable")]
        current_roots = {
            "game_root": self._root_identity(self.game_root),
            "user_data": self._root_identity(self.user_data),
        }
        if current_roots != self._initial_roots:
            errors.append(_reason("INPUT_CHANGED", "configured game_root or user_data changed"))
        try:
            requested = self.enabled_mods if self._explicit_enabled_mods else None
            if _explicit_mod_signature(requested) != self._requested_mod_signature:
                errors.append(_reason("INPUT_CHANGED", "enabled_mods request changed"))
        except Exception as exc:
            errors.append(_reason("INPUT_CHANGED", str(exc)))
        try:
            errors.extend(self._resolver._fingerprint_errors())
        except Exception as exc:
            errors.append(_reason("INPUT_CHANGED", f"configuration recheck failed: {exc}"))
        try:
            self._parser.assert_current()
            if self._parser.context() != self._parser_context:
                raise ValueError("CWTOOLS_PARSER_CONTEXT_CHANGED")
        except Exception as exc:
            errors.append(_reason("INPUT_CHANGED", f"CWTools parser changed: {exc}"))
        try:
            vendor_raw = _read_bounded(_vendor_manifest_path(), 256 * 1024)
            vendor = json.loads(vendor_raw.decode("utf-8-sig"))
            cwt = _pin(CWT_PATH, expected_bytes=EXPECTED_CWT_BYTES,
                       expected_sha256=EXPECTED_CWT_SHA256)
            if (not isinstance(vendor, dict)
                    or vendor.get("commit") != EXPECTED_VENDOR_COMMIT
                    or vendor.get("license") != "MIT"
                    or _sha256(vendor_raw) != self._vendor_sha256
                    or self._cwt_contract is None
                    or {key: value for key, value in cwt.items() if key != "path"}
                    != self._cwt_contract["schema_file"]):
                raise ValueError("CWT_CONTRACT_CHANGED")
        except Exception as exc:
            errors.append(_reason("INPUT_CHANGED", f"CWT contract changed: {exc}"))

        try:
            current_snapshots = []
            total_members = 0
            for index, layer in enumerate(self._resolver._state.layers):
                snapshot, _candidates = self._scan_layer(
                    index, layer, MAX_DIRECTORY_MEMBERS - total_members)
                total_members += len(snapshot["members"] or [])
                current_snapshots.append(snapshot)
            if current_snapshots != self._directory_snapshots:
                errors.append(_reason("INPUT_CHANGED", "religion directory membership changed"))
        except Exception as exc:
            errors.append(_reason("INPUT_CHANGED", f"religion directory changed: {exc}"))
        for item in self._effective_files:
            try:
                raw = _read_bounded(Path(item["path"]), self._max_file_bytes, allow_empty=True)
                if len(raw) != item["size"] or _sha256(raw) != item["sha256"]:
                    errors.append(_reason("INPUT_CHANGED", f"selected religion file changed: {item['relative']}"))
            except Exception as exc:
                errors.append(_reason("INPUT_CHANGED", f"selected religion file unavailable: {item['relative']}: {exc}"))
        return errors

    def assert_current(self) -> None:
        if self._errors:
            raise ValueError(f"RELIGION_DEFINITION_INDEX_UNREADY:{self._errors[0]['code']}")
        errors = self._current_errors()
        if errors:
            raise ValueError(f"RELIGION_DEFINITION_INDEX_CHANGED:{errors[0]['code']}")

    def _source_pins(self) -> dict[str, Any]:
        cwt = self._cwt_contract.get("schema_file", {}) if self._cwt_contract else {}
        parser_sha = self._parser_context.get("manifest_sha256")
        return {
            "configuration_sha256": self._configuration_sha256,
            "definitions_sha256": self._definitions_sha256,
            "parser_manifest_sha256": parser_sha,
            "cwt_sha256": cwt.get("sha256"),
            "cwt_commit": self._cwt_contract.get("commit") if self._cwt_contract else None,
        }

    @staticmethod
    def _public_definition(record: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "relative_file": record["relative_file"],
            "line": record["line"],
            "file_sha256": record["file_sha256"],
            "source_kind": record["source_kind"],
        }

    def lookup_group(self, group_key: str) -> dict[str, Any]:
        """Return provenance for one unique effective religion group key."""
        if not isinstance(group_key, str) or not RELIGION_KEY_RE.fullmatch(group_key):
            return {"status": "unknown", "reason": "RELIGION_GROUP_KEY_INVALID"}
        try:
            self.assert_current()
        except Exception:
            return {
                "status": "unknown", "reason": "RELIGION_DEFINITION_INDEX_UNAVAILABLE",
                "religion_group_key": group_key,
            }
        records = self._groups.get(group_key.casefold(), [])
        if not records:
            return {
                "status": "unknown", "reason": "RELIGION_GROUP_NOT_FOUND",
                "religion_group_key": group_key,
                "source": self._source_pins(),
                "source_pins": self._source_pins(),
            }
        if len(records) != 1:
            return {
                "status": "unknown", "reason": "RELIGION_GROUP_AMBIGUOUS",
                "religion_group_key": group_key,
                "definitions": [self._public_definition(item) for item in records],
                "source": self._source_pins(),
                "source_pins": self._source_pins(),
            }
        record = records[0]
        return {
            "status": "known",
            "religion_group_key": record["religion_group_key"],
            "definition": self._public_definition(record),
            "source": self._source_pins(),
            "source_pins": self._source_pins(),
        }

    def lookup(self, religion_key: str) -> dict[str, Any]:
        """Return the unique group key for a religion definition, if known.

        The index validates its source pins before every lookup. Use a new
        instance after game, mod, parser, or definition files change.
        """
        if not isinstance(religion_key, str) or not RELIGION_KEY_RE.fullmatch(religion_key):
            return {"status": "unknown", "reason": "RELIGION_KEY_INVALID"}
        try:
            self.assert_current()
        except Exception:
            return {
                "status": "unknown", "reason": "RELIGION_DEFINITION_INDEX_UNAVAILABLE",
                "religion_key": religion_key,
            }
        records = self._religions.get(religion_key.casefold(), [])
        if not records:
            return {
                "status": "unknown", "reason": "RELIGION_DEFINITION_NOT_FOUND",
                "religion_key": religion_key, "source_pins": self._source_pins(),
            }
        group_id = records[0]["group_id"]
        ambiguous = (len(records) != 1 or not records[0]["valid"]
                     or self._group_counts.get(group_id, 0) != 1
                     or any(not item["valid"] for item in records))
        if ambiguous:
            return {
                "status": "unknown", "reason": "RELIGION_DEFINITION_AMBIGUOUS",
                "religion_key": religion_key,
                "definitions": [self._public_definition(item) for item in records],
                "source": self._source_pins(),
                "source_pins": self._source_pins(),
            }
        record = records[0]
        return {
            "status": "known",
            "religion_key": record["religion_key"],
            "religion_group_key": record["religion_group_key"],
            "definition": self._public_definition(record),
            "source": self._source_pins(),
            "source_pins": self._source_pins(),
        }

    def _declaration_file(self, record: Mapping[str, Any]) -> dict[str, Any]:
        matches = [item for item in self._effective_files
                   if item.get("relative") == record.get("relative_file")]
        if (len(matches) != 1
                or matches[0].get("sha256") != record.get("file_sha256")
                or matches[0].get("source_kind") != record.get("source_kind")):
            raise ValueError("RELIGION_DECLARATION_FILE_MISMATCH")
        return matches[0]

    @staticmethod
    def _group_ast_view(group_node: Any) -> Any:
        children = getattr(group_node, "children", None)
        if not isinstance(children, list):
            raise ValueError("RELIGION_GROUP_AST_CHILDREN_INVALID")
        included = []
        seen_keys: set[str] = set()
        for child in children:
            key = getattr(child, "key", None)
            kind = getattr(child, "kind", None)
            assignment = getattr(child, "assignment", None)
            child_children = getattr(child, "children", None)
            if (not isinstance(key, str) or not key or len(key) > 65536
                    or kind not in ("block", "scalar", "bare")
                    or (assignment is not None and
                        (not isinstance(assignment, str) or assignment not in _AST_ASSIGNMENTS))
                    or not isinstance(child_children, list)):
                raise ValueError("RELIGION_GROUP_AST_CHILD_INVALID")
            folded = key.casefold()
            if folded in seen_keys:
                raise ValueError("RELIGION_GROUP_AST_DUPLICATE_CHILD")
            seen_keys.add(folded)
            # The pinned CWT type_key_filter identifies every direct group
            # block as a religion except these declared non-religion blocks.
            if kind == "block" and folded not in NON_RELIGION_GROUP_CHILDREN:
                if assignment != "=":
                    raise ValueError("RELIGION_GROUP_AST_RELIGION_ASSIGNMENT_INVALID")
                continue
            included.append(child)
        return type("_ReligionGroupAstView", (), {
            "key": getattr(group_node, "key", None),
            "assignment": getattr(group_node, "assignment", None),
            "kind": getattr(group_node, "kind", None),
            "value": getattr(group_node, "value", None),
            "children": included,
            "line": getattr(group_node, "line", None),
            "end_line": getattr(group_node, "end_line", getattr(group_node, "line", None)),
            "source_column": getattr(group_node, "source_column", None),
            "end_column": getattr(group_node, "end_column", None),
        })()

    @staticmethod
    def _validate_declaration_ast(root: Any) -> None:
        pending = [(root, 0)]
        seen: set[int] = set()
        count = 0
        estimated_chars = 0
        while pending:
            node, depth = pending.pop()
            count += 1
            if count > MAX_DECLARATION_AST_NODES:
                raise ValueError("RELIGION_DECLARATION_AST_NODE_LIMIT")
            if depth > MAX_DECLARATION_AST_DEPTH:
                raise ValueError("RELIGION_DECLARATION_AST_DEPTH_LIMIT")
            identity = id(node)
            if identity in seen:
                raise ValueError("RELIGION_DECLARATION_AST_CYCLE_OR_ALIAS")
            seen.add(identity)
            key = getattr(node, "key", None)
            value = getattr(node, "value", None)
            assignment = getattr(node, "assignment", None)
            kind = getattr(node, "kind", None)
            line = getattr(node, "line", None)
            end_line = getattr(node, "end_line", line)
            children = getattr(node, "children", None)
            if (not isinstance(key, str) or not key or len(key) > 65536
                    or (assignment is not None and
                        (not isinstance(assignment, str) or assignment not in _AST_ASSIGNMENTS))
                    or kind not in ("block", "scalar", "bare")
                    or (value is not None and not isinstance(value, str))
                    or type(line) is not int or line < 1
                    or type(end_line) is not int or end_line < line
                    or not isinstance(children, list)
                    or (kind == "block" and value is not None)
                    or (kind == "scalar" and children)):
                raise ValueError("RELIGION_DECLARATION_AST_NODE_INVALID")
            estimated_chars += len(key) + (len(value) if value is not None else 0) + 96
            if estimated_chars * 6 > MAX_DECLARATION_JSON_BYTES:
                raise ValueError("RELIGION_DECLARATION_AST_JSON_LIMIT")
            for column_name in ("source_column", "end_column"):
                column = getattr(node, column_name, None)
                if column is not None and (type(column) is not int or column < 0):
                    raise ValueError("RELIGION_DECLARATION_AST_COLUMN_INVALID")
            pending.extend((child, depth + 1) for child in reversed(children))

    def _parse_selected_declaration(self, record: Mapping[str, Any], *,
                                    group_only: bool) -> dict[str, Any]:
        self.assert_current()
        file_item = self._declaration_file(record)
        path = Path(file_item["path"]).resolve()
        parsed = self._parser.parse_files([path])
        self._parser.assert_current()
        if self._parser.context() != self._parser_context:
            raise ValueError("CWTOOLS_PARSER_CONTEXT_CHANGED")
        self.assert_current()
        if not isinstance(parsed, dict) or set(parsed) != {str(path)}:
            raise ValueError("CWTOOLS_DECLARATION_OUTPUT_FILES_MISMATCH")
        result = parsed.get(str(path))
        if not isinstance(result, dict) or "error" in result:
            raise ValueError("CWTOOLS_DECLARATION_FILE_PARSE_FAILED")
        parser_echo = result.get("parser")
        if (not isinstance(parser_echo, dict)
                or parser_echo.get("manifest_sha256") != self._parser_context.get("manifest_sha256")):
            raise ValueError("CWTOOLS_DECLARATION_PARSER_ECHO_INVALID")
        roots = result.get("nodes")
        if not isinstance(roots, list):
            raise ValueError("CWTOOLS_DECLARATION_ROOTS_INVALID")

        group_key = (record.get("religion_group_key") if not group_only
                     else record.get("religion_group_key"))
        group_candidates = [node for node in roots
                            if getattr(node, "key", None) == group_key
                            and getattr(node, "kind", None) == "block"
                            and getattr(node, "assignment", None) == "="
                            and getattr(node, "line", None) ==
                            (record.get("group_line") if not group_only else record.get("line"))]
        if len(group_candidates) != 1:
            raise ValueError("RELIGION_DECLARATION_GROUP_MATCH_AMBIGUOUS")
        group_node = group_candidates[0]
        if group_only:
            root = self._group_ast_view(group_node)
        else:
            group_children = getattr(group_node, "children", None)
            if not isinstance(group_children, list):
                raise ValueError("RELIGION_DECLARATION_GROUP_CHILDREN_INVALID")
            religion_key = record.get("religion_key")
            matches = [node for node in group_children
                       if getattr(node, "key", None) == religion_key
                       and getattr(node, "kind", None) == "block"
                       and getattr(node, "assignment", None) == "="
                       and getattr(node, "line", None) == record.get("line")]
            if len(matches) != 1:
                raise ValueError("RELIGION_DECLARATION_RELIGION_MATCH_AMBIGUOUS")
            root = matches[0]
        self._validate_declaration_ast(root)
        syntax = _serialize_ast_node(root, counter=[0])
        if len(canonical(syntax).encode("utf-8")) > MAX_DECLARATION_JSON_BYTES:
            raise ValueError("RELIGION_DECLARATION_AST_JSON_LIMIT")
        self.assert_current()
        return syntax

    def _declaration_result(self, lookup: dict[str, Any], record: Mapping[str, Any], *,
                            group_only: bool) -> dict[str, Any]:
        key_name = "religion_group_key" if group_only else "religion_key"
        target = lookup.get(key_name)
        try:
            syntax = self._parse_selected_declaration(record, group_only=group_only)
        except Exception as exc:
            candidate = str(exc).split(":", 1)[0]
            reason = (candidate if re.fullmatch(r"[A-Z][A-Z0-9_]{7,95}", candidate)
                      else "RELIGION_DECLARATION_UNAVAILABLE")
            result = {
                "status": "unknown",
                "reason": reason,
                key_name: target,
                "source": self._source_pins(),
                "source_pins": self._source_pins(),
            }
            return result
        return {
            "status": "known",
            key_name: target,
            **({"religion_group_key": lookup["religion_group_key"]} if not group_only else {}),
            "definition": deepcopy(lookup["definition"]),
            "source": deepcopy(lookup["source"]),
            "source_pins": deepcopy(lookup["source_pins"]),
            "syntax": deepcopy(syntax),
            "conditions_evaluated": False,
            "effects_executed": False,
            "runtime_state_observed": False,
        }

    def definition(self, religion_key: str) -> dict[str, Any]:
        """Return bounded static syntax for one uniquely indexed religion."""
        lookup = self.lookup(religion_key)
        if lookup.get("status") != "known":
            return deepcopy(lookup)
        records = self._religions.get(str(lookup["religion_key"]).casefold(), [])
        if len(records) != 1:
            return deepcopy(lookup)
        return self._declaration_result(lookup, records[0], group_only=False)

    def group_definition(self, group_key: str) -> dict[str, Any]:
        """Return group syntax while excluding direct religion declaration blocks."""
        lookup = self.lookup_group(group_key)
        if lookup.get("status") != "known":
            return deepcopy(lookup)
        records = self._groups.get(str(lookup["religion_group_key"]).casefold(), [])
        if len(records) != 1:
            return deepcopy(lookup)
        return self._declaration_result(lookup, records[0], group_only=True)

    def context(self) -> dict[str, Any]:
        reasons = deepcopy(self._errors)
        if not reasons:
            reasons.extend(self._current_errors())
        return {
            "status": "ready" if not reasons else "unready",
            "complete": False,
            "mode": "static_definition_index",
            "game_version": (self._resolver._state.game_version
                             if self._resolver is not None else None),
            "configuration_sha256": self._configuration_sha256,
            "definitions_sha256": self._definitions_sha256,
            "script_parser": deepcopy(self._parser_context),
            "cwt_contract": deepcopy(self._cwt_contract),
            "definition_files": [
                {"relative": item["relative"], "size": item["size"],
                 "sha256": item["sha256"], "source_kind": item["source_kind"]}
                for item in self._effective_files
            ],
            "directory_candidates": deepcopy(self._directory_snapshots),
            "religion_definition_count": sum(len(rows) for rows in self._religions.values()),
            "religion_key_count": len(self._religions),
            "religion_group_count": len(self._groups),
            "duplicate_group_keys": deepcopy(self._duplicate_group_keys),
            "invalid_definition_count": self._invalid_definition_count,
            "static_semantics": {
                "conditions_evaluated": False,
                "effects_executed": False,
                "current_religion_observed": False,
            },
            "reasons": reasons,
        }
