"""Read the effective, bounded EU4 map adjacency definitions.

This source reports static ``sea`` rows from the enabled map files. It does
not infer movement permission, runtime access, or whether a route is usable.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping, Sequence

from tools.build_diplomacy_catalog import parse_script

from . import static_data as _static
from .model import canonical
from .strait_csv import parse_adjacencies, parse_definition_ids


DEFAULT_MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 12 * 1024 * 1024
MAX_ENABLED_MODS = 256
_MAP_DEFAULT = "map/default.map"
_VERSION_RELATIVE = "launcher-settings.json"
_INVALID_PATH_CHARS = ("\x00",)


def _reason(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def _path_under(path: str, parent: str) -> bool:
    path_parts = PurePosixPath(path).parts
    parent_parts = PurePosixPath(parent).parts
    if len(path_parts) < len(parent_parts):
        return False
    return tuple(part.casefold() for part in path_parts[:len(parent_parts)]) == tuple(
        part.casefold() for part in parent_parts
    )


def _normalise_map_relative(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("MAP_PATH_MISSING")
    raw = value.strip().replace("\\", "/")
    if any(char in raw for char in _INVALID_PATH_CHARS):
        raise ValueError("MAP_PATH_INVALID")
    while raw.startswith("./"):
        raw = raw[2:]
    if raw.startswith("/") or re.match(r"^[A-Za-z]:", raw):
        raise ValueError("MAP_PATH_ABSOLUTE")
    parts = raw.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("MAP_PATH_TRAVERSAL")
    relative = raw if raw.casefold().startswith("map/") else f"map/{raw}"
    parsed = PurePosixPath(relative)
    if parsed.is_absolute() or parsed.parts[0].casefold() != "map":
        raise ValueError("MAP_PATH_OUTSIDE_MAP")
    if any(part in {".", ".."} for part in parsed.parts) or parsed.suffix.casefold() != ".csv":
        raise ValueError("MAP_CSV_PATH_INVALID")
    return parsed.as_posix()


def _normalise_replace_path(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("MOD_REPLACE_PATH_INVALID")
    raw = value.strip().replace("\\", "/")
    if any(char in raw for char in _INVALID_PATH_CHARS):
        raise ValueError("MOD_REPLACE_PATH_INVALID")
    while raw.startswith("./"):
        raw = raw[2:]
    if raw.startswith("/") or re.match(r"^[A-Za-z]:", raw):
        raise ValueError("MOD_REPLACE_PATH_ABSOLUTE")
    parts = raw.rstrip("/").split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("MOD_REPLACE_PATH_TRAVERSAL")
    return PurePosixPath(*parts).as_posix()


@dataclass
class _Layer:
    root: Path
    kind: str
    source: str
    replace_paths: tuple[str, ...] = ()


@dataclass
class _ResolvedFile:
    relative: str
    path: Path
    source_kind: str
    source: str
    sha256: str
    size: int

    def public(self) -> dict[str, Any]:
        return {
            "relative": self.relative,
            "path": str(self.path),
            "source_kind": self.source_kind,
            "source": self.source,
            "sha256": self.sha256,
            "size": self.size,
        }


@dataclass
class _IndexState:
    errors: list[dict[str, str]] = field(default_factory=list)
    compatibility: Any = None
    mods: list[Any] = field(default_factory=list)
    layers: list[_Layer] = field(default_factory=list)
    input_fingerprints: dict[str, str] = field(default_factory=dict)
    candidate_presence: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    files: list[_ResolvedFile] = field(default_factory=list)
    valid_province_ids: set[int] = field(default_factory=set)
    edges: list[dict[str, Any]] = field(default_factory=list)
    statistics: dict[str, Any] = field(default_factory=dict)
    encoding: str | None = None
    game_version: str | None = None
    raw_game_version: str | None = None
    definitions_sha256: str | None = None
    configuration_sha256: str | None = None
    initial_input_bytes: int = 0


class StraitDefinitionIndex:
    """Index effective ``map/default.map`` and its selected CSV inputs.

    ``enabled_mods=None`` reads ``user_data/dlc_load.json``; an explicit empty
    list selects base-game data only. File and configuration changes make the
    index unavailable until a new instance is built.
    """

    def __init__(
        self,
        game_root: str | Path | None = None,
        user_data: str | Path | None = None,
        enabled_mods: Sequence[str | Path | Mapping[str, Any]] | None = None,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    ) -> None:
        if type(max_file_bytes) is not int or max_file_bytes <= 0 or max_file_bytes > DEFAULT_MAX_FILE_BYTES:
            raise ValueError("max_file_bytes must be an integer in 1..4 MiB")
        self.game_root = Path(game_root) if game_root is not None else _static.StaticTradeSource._configured_path("game_root")
        self.user_data = Path(user_data) if user_data is not None else _static.StaticTradeSource._configured_path("user_data")
        self._explicit_enabled_mods = enabled_mods is not None
        if enabled_mods is None:
            self.enabled_mods: list[Any] | None = None
        elif isinstance(enabled_mods, (str, Path)):
            self.enabled_mods = [enabled_mods]
        else:
            self.enabled_mods = list(enabled_mods)
        self.max_file_bytes = max_file_bytes
        self._state = self._build_state()

    @staticmethod
    def _read_bounded(path: Path, max_file_bytes: int) -> bytes:
        if not path.is_file():
            raise FileNotFoundError(str(path))
        size = path.stat().st_size
        if size < 1 or size > max_file_bytes:
            raise ValueError(f"INPUT_SIZE_OUT_OF_RANGE:{size}:{path}")
        with path.open("rb") as stream:
            raw = stream.read(max_file_bytes + 1)
        if len(raw) != size or len(raw) > max_file_bytes:
            raise ValueError(f"INPUT_CHANGED_DURING_READ:{path}")
        return raw

    def _add_error(self, code: str, message: str) -> None:
        self._state.errors.append(_reason(code, message))

    def _configuration_bytes(self) -> int:
        compat = self._state.compatibility
        paths = {str(Path(item["path"])) for item in compat.configuration_files if item.get("path")}
        total = 0
        for path_text in paths:
            try:
                total += Path(path_text).stat().st_size
            except OSError:
                continue
        return total

    def _load_version(self) -> None:
        if self.game_root is None:
            self._add_error("GAME_ROOT_UNAVAILABLE", "EU4 game root is not configured")
            return
        path = self.game_root / _VERSION_RELATIVE
        try:
            raw = self._read_bounded(path, self.max_file_bytes)
            payload = json.loads(raw.decode("utf-8-sig"))
            if not isinstance(payload, dict):
                raise ValueError("launcher-settings.json must contain an object")
            raw_version = payload.get("rawVersion") or payload.get("version")
            self._state.raw_game_version = raw_version if isinstance(raw_version, str) else None
            self._state.game_version = _static._normalise_version(raw_version)
            digest = hashlib.sha256(raw).hexdigest()
            compat = self._state.compatibility
            compat.fingerprint[str(path)] = digest
            compat.configuration_files += ({"path": str(path), "kind": "launcher_settings", "sha256": digest},)
            if self._state.game_version not in _static.SUPPORTED_VERSIONS:
                self._add_error(
                    "UNSUPPORTED_GAME_VERSION",
                    f"strait definitions are verified for {_static.SUPPORTED_VERSIONS}, got {self._state.game_version}",
                )
        except Exception as exc:
            self._add_error("GAME_VERSION_UNAVAILABLE", f"{path}: {exc}")

    def _enabled_entries(self) -> list[Any]:
        compat = self._state.compatibility
        if not self._explicit_enabled_mods and self.user_data is not None:
            load_path = self.user_data / "dlc_load.json"
            try:
                if load_path.is_file() and load_path.stat().st_size > self.max_file_bytes:
                    self._add_error("ENABLED_MOD_CONFIG_INVALID", f"dlc_load.json exceeds max_file_bytes: {load_path}")
                    return []
            except OSError as exc:
                self._add_error("ENABLED_MOD_CONFIG_INVALID", f"{load_path}: {exc}")
                return []
        entries = _static.StaticTradeSource._load_enabled_entries(self, compat)
        if len(entries) > MAX_ENABLED_MODS:
            self._add_error("MOD_COUNT_EXCEEDED", f"enabled mod count exceeds {MAX_ENABLED_MODS}")
            return []
        return entries

    def _descriptor_path(self, entry: Any) -> tuple[Path | None, Path | None]:
        """Adapt the shared descriptor parser's bound-method call contract."""
        return _static.StaticTradeSource._descriptor_path(self, entry)

    def _load_mods(self) -> None:
        compat = self._state.compatibility
        entries = self._enabled_entries()
        mods: list[Any] = []
        for entry in entries:
            try:
                mod = _static.StaticTradeSource._parse_mod(self, entry, compat)
                normalized_replace_paths = tuple(_normalise_replace_path(value) for value in mod.replace_paths)
                mod.replace_paths = normalized_replace_paths
                mods.append(mod)
            except Exception as exc:
                self._add_error("ENABLED_MOD_UNSUPPORTED", str(exc))
        self._state.mods = mods
        if self.game_root is not None:
            self._state.layers.append(_Layer(self.game_root, "basegame", "basegame"))
        for mod in mods:
            if mod.root is None or not mod.root.is_dir():
                self._add_error("MOD_ROOT_UNAVAILABLE", f"enabled mod root not found: {mod.root}")
                continue
            self._state.layers.append(_Layer(
                Path(mod.root), "enabled_mod", str(mod.descriptor), tuple(mod.replace_paths),
            ))

    def _safe_candidate(self, layer: _Layer, relative: str) -> Path:
        root = layer.root.resolve(strict=True)
        candidate = root.joinpath(*PurePosixPath(relative).parts)
        resolved = candidate.resolve(strict=False)
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"MAP_PATH_ESCAPES_LAYER:{relative}:{layer.root}") from exc
        return resolved

    def _resolve_file(self, relative: str) -> Path | None:
        winner: Path | None = None
        winner_layer: _Layer | None = None
        candidates: list[dict[str, Any]] = []
        for index, layer in enumerate(self._state.layers):
            try:
                candidate = self._safe_candidate(layer, relative)
                exists = candidate.exists()
                is_file = candidate.is_file()
            except Exception as exc:
                self._add_error("MAP_CANDIDATE_INVALID", str(exc))
                continue
            candidates.append({
                "layer_index": index,
                "root": str(layer.root),
                "path": str(candidate),
                "exists": exists,
                "is_file": is_file,
                "source_kind": layer.kind,
                "source": layer.source,
            })
            if exists and not is_file:
                self._add_error("MAP_CANDIDATE_NOT_FILE", f"expected a file: {candidate}")
            if index > 0:
                for replace_path in layer.replace_paths:
                    if _path_under(relative, replace_path):
                        winner = None
                        winner_layer = None
            if is_file:
                winner = candidate
                winner_layer = layer
        self._state.candidate_presence[relative] = candidates
        if winner is None or winner_layer is None:
            self._add_error("MAP_SELECTED_FILE_MISSING", f"no effective file for {relative}")
            return None
        # Source kind/label are stored from the winning layer by path lookup.
        return winner

    def _source_for_path(self, path: Path) -> tuple[str, str]:
        for layer in reversed(self._state.layers):
            try:
                path.resolve(strict=False).relative_to(layer.root.resolve(strict=True))
                return layer.kind, layer.source
            except (ValueError, OSError):
                continue
        return "unknown", "unknown"

    def _read_source(self, relative: str) -> tuple[Path, bytes] | None:
        path = self._resolve_file(relative)
        if path is None:
            return None
        try:
            raw = self._read_bounded(path, self.max_file_bytes)
        except Exception as exc:
            self._add_error("MAP_INPUT_UNAVAILABLE", f"{relative}: {exc}")
            return None
        self._state.initial_input_bytes += len(raw)
        total = self._configuration_bytes() + self._state.initial_input_bytes
        if total > MAX_TOTAL_BYTES:
            self._add_error("TOTAL_INPUT_LIMIT_EXCEEDED", f"static inputs exceed {MAX_TOTAL_BYTES} bytes")
            return None
        digest = hashlib.sha256(raw).hexdigest()
        self._state.input_fingerprints[str(path)] = digest
        self._state.compatibility.fingerprint[str(path)] = digest
        kind, source = self._source_for_path(path)
        self._state.files.append(_ResolvedFile(relative, path, kind, source, digest, len(raw)))
        return path, raw

    def _load_effective_definitions(self) -> None:
        default = self._read_source(_MAP_DEFAULT)
        if default is None:
            return
        _default_path, default_raw = default
        try:
            text = default_raw.decode("utf-8-sig")
            nodes = parse_script(text)
            definitions_value = _static._last_scalar_from_roots(nodes, "definitions")
            adjacencies_value = _static._last_scalar_from_roots(nodes, "adjacencies")
            definitions_relative = _normalise_map_relative(definitions_value)
            adjacencies_relative = _normalise_map_relative(adjacencies_value)
        except Exception as exc:
            self._add_error("DEFAULT_MAP_INVALID", str(exc))
            return

        definitions = self._read_source(definitions_relative)
        adjacencies = self._read_source(adjacencies_relative)
        if definitions is None or adjacencies is None:
            return
        try:
            self._state.valid_province_ids = parse_definition_ids(definitions[1])
            parsed = parse_adjacencies(adjacencies[1], self._state.valid_province_ids)
            self._state.edges = parsed["edges"]
            self._state.statistics = parsed["statistics"]
            self._state.encoding = parsed["encoding"]
        except Exception as exc:
            self._add_error("MAP_CSV_INVALID", str(exc))

    def _build_state(self) -> _IndexState:
        state = _IndexState(compatibility=_static._StaticState())
        self._state = state
        self._load_version()
        if self.game_root is None or not self.game_root.is_dir():
            self._add_error("GAME_ROOT_UNAVAILABLE", f"game root not found: {self.game_root}")
        self._load_mods()
        if len(self._state.layers) > 1 + MAX_ENABLED_MODS:
            self._add_error("MOD_COUNT_EXCEEDED", f"enabled mod count exceeds {MAX_ENABLED_MODS}")
        self._load_effective_definitions()
        compat = self._state.compatibility
        self._state.input_fingerprints.update(compat.fingerprint)
        config_manifest = [dict(item) for item in compat.configuration_files]
        self._state.configuration_sha256 = hashlib.sha256(canonical({
            "configuration_files": config_manifest,
            "enabled_mods": [
                {"descriptor": str(mod.descriptor), "root": str(mod.root), "replace_paths": list(mod.replace_paths)}
                for mod in self._state.mods
            ],
        }).encode("utf-8")).hexdigest()
        if self._state.files:
            self._state.definitions_sha256 = hashlib.sha256(canonical([
                item.public() for item in self._state.files
            ]).encode("utf-8")).hexdigest()
        if self._configuration_bytes() + self._state.initial_input_bytes > MAX_TOTAL_BYTES:
            self._add_error("TOTAL_INPUT_LIMIT_EXCEEDED", f"static inputs exceed {MAX_TOTAL_BYTES} bytes")
        return self._state

    def _fingerprint_errors(self) -> list[dict[str, str]]:
        errors: list[dict[str, str]] = []
        for relative, expected_layers in self._state.candidate_presence.items():
            if len(expected_layers) != len(self._state.layers):
                errors.append(_reason("INPUT_CHANGED", f"layer candidate set changed for {relative}"))
                continue
            for expected, layer in zip(expected_layers, self._state.layers):
                try:
                    candidate = self._safe_candidate(layer, relative)
                    actual = {"exists": candidate.exists(), "is_file": candidate.is_file()}
                except Exception as exc:
                    errors.append(_reason("INPUT_CHANGED", f"candidate is unavailable for {relative}: {exc}"))
                    continue
                if actual != {"exists": expected["exists"], "is_file": expected["is_file"]}:
                    errors.append(_reason("INPUT_CHANGED", f"candidate presence changed for {relative}: {candidate}"))
        for path_text, expected in self._state.input_fingerprints.items():
            path = Path(path_text)
            try:
                raw = self._read_bounded(path, self.max_file_bytes)
                actual = hashlib.sha256(raw).hexdigest()
            except Exception as exc:
                errors.append(_reason("INPUT_CHANGED", f"tracked input is unavailable: {path}: {exc}"))
                continue
            if actual != expected:
                errors.append(_reason("INPUT_CHANGED", f"tracked input changed: {path}"))
        return errors

    def context(self) -> dict[str, Any]:
        reasons = [deepcopy(item) for item in self._state.errors]
        reasons.extend(self._fingerprint_errors())
        ready = not reasons and self._state.game_version in _static.SUPPORTED_VERSIONS
        files = [item.public() for item in self._state.files]
        mods = [{
            "descriptor": str(item.descriptor),
            "descriptor_sha256": item.descriptor_sha256,
            "name": item.name,
            "root": item.root_label,
            "replace_paths": list(item.replace_paths),
        } for item in self._state.mods]
        return {
            "status": "ready" if ready else "unready",
            "complete": ready,
            "mode": "static",
            "context_scope": "static_map_definitions",
            "game_root": str(self.game_root) if self.game_root is not None else None,
            "user_data": str(self.user_data) if self.user_data is not None else None,
            "game_version": self._state.game_version,
            "game_version_raw": self._state.raw_game_version,
            "supported_versions": list(_static.SUPPORTED_VERSIONS),
            "definitions_sha256": self._state.definitions_sha256,
            "configuration_sha256": self._state.configuration_sha256,
            "config_sha256": self._state.configuration_sha256,
            "configuration_files": deepcopy(list(self._state.compatibility.configuration_files)),
            "definition_files": files,
            "enabled_mods": mods,
            "provenance": {
                "source": "StraitDefinitionIndex",
                "definition_files": deepcopy(files),
                "enabled_mods": deepcopy(mods),
                "candidate_presence": deepcopy(self._state.candidate_presence),
                "adjacency_statistics": deepcopy(self._state.statistics),
                "adjacency_encoding": self._state.encoding,
            },
            "adjacency_statistics": deepcopy(self._state.statistics),
            "adjacency_encoding": self._state.encoding,
            "valid_province_count": len(self._state.valid_province_ids),
            "sea_edge_count": len(self._state.edges),
            "initial_input_bytes": self._state.initial_input_bytes,
            "reasons": reasons,
        }

    def lookup(self, province_id: int) -> dict[str, Any]:
        current = self.context()
        if current["status"] != "ready":
            reason = current["reasons"][0]["code"] if current["reasons"] else "SOURCE_UNREADY"
            return {"status": "unavailable", "reason": reason}
        if type(province_id) is not int or province_id <= 0 or province_id > 0x7FFFFFFF:
            return {"status": "unknown", "reason": "INVALID_PROVINCE_ID"}
        if province_id not in self._state.valid_province_ids:
            return {"status": "unknown", "reason": "PROVINCE_NOT_IN_MAP_DEFINITIONS"}
        edges = [
            edge for edge in self._state.edges
            if province_id in (edge["from_province"], edge["to_province"], edge["through_province"])
        ]
        return {"status": "known", "value": deepcopy(edges)}


__all__ = ["StraitDefinitionIndex", "DEFAULT_MAX_FILE_BYTES", "MAX_TOTAL_BYTES", "MAX_ENABLED_MODS"]
