"""Read-only, bounded index of EU4 ``missions/*.txt`` definitions.

This module deliberately indexes rule text rather than claiming that a mission
tree is currently loaded by a running game.  It resolves the base game and
the explicitly enabled mod stack, keeps the effective file provenance, and
fails closed when that scope cannot be established.

The public object is :class:`MissionDefinitionIndex`.  Its JSON-compatible
``context()``, ``roots()`` and ``root()`` results contain rule-expression
trees as data.  No trigger, potential, effect, DLC condition or localization
is evaluated here.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Sequence

MISSION_RELATIVE = "missions"
SUPPORTED_VERSIONS = ("1.37.4",)
DEFAULT_MAX_FILE_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_FILES = 4096
_VERSION_RE = re.compile(r"(?<!\d)(\d+\.\d+(?:\.\d+)?)(?!\d)")
_NUMBER_RE = re.compile(r"[+-]?\d+(?:\.\d+)?")
_SCRIPT_TOKEN = re.compile(
    r'\s+|#[^\n]*|"(?:\\.|[^"\\])*"|(?:>=|<=|!=|==|>|<)|[{}=]|[^\s{}=#<>!]+')
_COMPARISON_OPERATORS = frozenset({">=", "<=", "!=", "==", ">", "<"})
_ROOT_METADATA = frozenset({
    "slot", "generic", "ai", "potential_on_load", "potential",
    "has_country_shield", "country_shield", "icon",
})


@dataclass
class _ScriptNode:
    """Ordered structural node produced by the mission-local parser."""

    key: str
    line: int
    value: str | None = None
    children: list["_ScriptNode"] = field(default_factory=list)
    end_line: int = 0
    kind: str = "bare"
    assignment: str | None = None
    raw_key: str | None = None
    raw_value: str | None = None


def _copy(value: Any) -> Any:
    return deepcopy(value)


def _normalise_version(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    match = _VERSION_RE.search(value)
    if not match:
        return None
    parts = match.group(1).split(".")
    if len(parts) == 2:
        parts.append("0")
    return ".".join(parts[:3])


def _normalise_relative(value: str) -> str:
    value = value.strip().replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    return value.rstrip("/")


def _under(relative: str, prefix: str) -> bool:
    relative = _normalise_relative(relative)
    prefix = _normalise_relative(prefix)
    return not prefix or relative == prefix or relative.startswith(prefix + "/")


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _hash_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_limited(path: Path, limit: int) -> bytes:
    if not path.is_file():
        raise FileNotFoundError(str(path))
    size = path.stat().st_size
    if size > limit:
        raise ValueError(f"file exceeds limit {limit} bytes: {path} ({size})")
    chunks: list[bytes] = []
    total = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ValueError(f"file exceeds limit {limit} bytes: {path}")
            chunks.append(chunk)
    return b"".join(chunks)


def _hash_file(path: Path, limit: int) -> tuple[str, int]:
    if not path.is_file():
        raise FileNotFoundError(str(path))
    size = path.stat().st_size
    if size > limit:
        raise ValueError(f"file exceeds limit {limit} bytes: {path} ({size})")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(chunk)
            if total > limit:
                raise ValueError(f"file exceeds limit {limit} bytes: {path}")
            digest.update(chunk)
    return digest.hexdigest(), total


def _decode_script(raw: bytes) -> tuple[str, dict[str, Any]]:
    """Decode a script and return an explicit provenance marker.

    Mission definitions are not localization data.  If UTF-8 is invalid, a
    latin-1 one-to-one decode is usable for brace/key structure only; callers
    receive the marker and no display name is manufactured from those bytes.
    """

    try:
        return raw.decode("utf-8-sig"), {
            "name": "utf-8-sig", "structural_only": False,
        }
    except UnicodeDecodeError as exc:
        return raw.decode("latin-1"), {
            "name": "latin-1", "structural_only": True,
            "reason": "UTF8_DECODE_FAILED",
            "error": str(exc),
        }


def _token_value(token: str) -> str:
    """Remove only the outer quotes; keep escape spelling in raw_value/key."""

    if len(token) >= 2 and token[0] == token[-1] == '"':
        return token[1:-1]
    return token


def _parse_script_with_bare_blocks(text: str) -> list[_ScriptNode]:
    """Parse the bounded Clausewitz subset used by mission definitions.

    Retain both ordinary ``key = value`` assignments and EU4 effects such as
    ``command { ... }`` without an equals sign.  The local grammar preserves
    syntax kinds, comparison operators, quoted tokens and ordered children.
    """

    tokens: list[tuple[str, int]] = []
    line = 1
    cursor = 0
    for match in _SCRIPT_TOKEN.finditer(text):
        if match.start() != cursor:
            raise ValueError(f"invalid token at line {line}")
        token = match.group()
        if not token.isspace() and not token.startswith("#"):
            tokens.append((token, line))
        line += token.count("\n")
        cursor = match.end()
    if cursor != len(text):
        raise ValueError(f"invalid token at line {line}")
    index = 0

    def block(nested: bool = False) -> tuple[list[_ScriptNode], int]:
        nonlocal index
        nodes: list[_ScriptNode] = []
        while index < len(tokens):
            key, start = tokens[index]
            index += 1
            if key == "}":
                if not nested:
                    raise ValueError(f"unexpected closing brace at line {start}")
                return nodes, start
            if key in ("{", "="):
                raise ValueError(f"unexpected token {key} at line {start}")
            node = _ScriptNode(
                _token_value(key), start, end_line=start, raw_key=key,
            )
            assignment = tokens[index][0] if index < len(tokens) else None
            if assignment == "=" or assignment in _COMPARISON_OPERATORS:
                index += 1
                if index >= len(tokens):
                    raise ValueError(f"missing value at line {start}")
                value, finish = tokens[index]
                index += 1
                node.assignment = assignment
                if value == "{":
                    node.kind = "block"
                    node.raw_value = value
                    node.children, node.end_line = block(True)
                elif value in ("}", "="):
                    raise ValueError(f"unexpected value token {value} at line {finish}")
                else:
                    node.kind = "scalar"
                    node.value = _token_value(value)
                    node.raw_value = value
                    node.end_line = finish
            elif index < len(tokens) and tokens[index][0] == "{":
                index += 1
                node.kind = "block"
                node.raw_value = "{"
                node.children, node.end_line = block(True)
            nodes.append(node)
        if nested:
            raise ValueError("unclosed block")
        return nodes, line

    return block()[0]


def _parse_mission_script(text: str) -> list[_ScriptNode]:
    """Parse only with the local operator-aware, ordered grammar."""

    return _parse_script_with_bare_blocks(text)


def _json_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _scalar_values(nodes: Iterable[_ScriptNode], key: str) -> list[str]:
    values: list[str] = []
    for node in nodes:
        if node.key != key:
            continue
        if node.children or node.value is None:
            raise ValueError(f"{key!r} must be a scalar at line {node.line}")
        values.append(node.value)
    return values


def _first_scalar(nodes: Iterable[_ScriptNode], key: str) -> str | None:
    values = _scalar_values(nodes, key)
    if len(values) > 1:
        raise ValueError(f"descriptor has repeated {key!r}")
    return values[0] if values else None


def _node_json(node: _ScriptNode, *, raw_script: str | None = None) -> dict[str, Any]:
    """Convert a parser node without collapsing repeated children."""

    result: dict[str, Any] = {
        "key": node.key,
        "line": node.line,
        "end_line": node.end_line,
        "value": node.value,
        "children": [_node_json(child) for child in node.children],
        "ast_semantics": "structural",
        "kind": node.kind,
        "assignment": node.assignment,
        "raw_key": node.raw_key,
        "raw_value": node.raw_value,
    }
    if node.assignment in _COMPARISON_OPERATORS:
        result["operator"] = node.assignment
    if raw_script is not None:
        result["raw_script"] = raw_script
    for name in ("source_column", "end_column"):
        if hasattr(node, name):
            result[name] = getattr(node, name)
    if hasattr(node, "cwtools_normalization"):
        result["parser_normalization"] = node.cwtools_normalization
    return result


def _scalar_value(node: _ScriptNode) -> Any:
    if node.children or node.value is None:
        return _node_json(node)
    value = node.value
    if value == "yes":
        return True
    if value == "no":
        return False
    if _NUMBER_RE.fullmatch(value):
        try:
            return int(value) if "." not in value else float(value)
        except ValueError:
            pass
    return value


def _field_nodes(nodes: Iterable[_ScriptNode], key: str) -> list[_ScriptNode]:
    return [node for node in nodes if node.key == key]


def _raw_script(source: _DefinitionFile | None, node: _ScriptNode) -> str | None:
    if source is None or source.text is None:
        return None
    if source.lines is None:
        source.lines = source.text.splitlines(keepends=True)
    lines = source.lines
    start = max(1, node.line)
    end = min(len(lines), max(start, node.end_line))
    return "".join(lines[start - 1:end])


def _field_value(nodes: Iterable[_ScriptNode], key: str, source: _DefinitionFile | None = None) -> Any:
    matches = _field_nodes(nodes, key)
    if not matches:
        return None
    values = [
        _node_json(node, raw_script=_raw_script(source, node)) if node.children
        else _scalar_value(node)
        for node in matches
    ]
    return values[0] if len(values) == 1 else values


def _mission_prefix(replace_path: str) -> str | None:
    path = _normalise_relative(replace_path)
    if path == MISSION_RELATIVE:
        return ""
    prefix = MISSION_RELATIVE + "/"
    if path.startswith(prefix):
        return path[len(prefix):]
    return None


def _safe_members(directory: Path, max_files: int) -> tuple[str, ...] | None:
    """Return a bounded recursive member manifest, or ``None`` if absent."""

    if not directory.is_dir():
        return None
    members: list[str] = []
    for item in directory.rglob("*"):
        members.append(item.relative_to(directory).as_posix())
        if len(members) > max_files:
            raise ValueError(f"directory has more than {max_files} members: {directory}")
    return tuple(sorted(members))


@dataclass
class _DefinitionFile:
    relative: str
    path: Path
    source_kind: str
    source_label: str
    sha256: str
    size: int
    encoding: dict[str, Any] | None = None
    text: str | None = None
    lines: list[str] | None = None


@dataclass
class _ModRecord:
    descriptor: Path | None
    descriptor_sha256: str | None
    root: Path | None
    root_label: str | None
    replace_paths: tuple[str, ...] = ()
    name: str | None = None
    archive: str | None = None
    files: list[str] = field(default_factory=list)


@dataclass
class _State:
    errors: list[dict[str, str]] = field(default_factory=list)
    warnings: list[dict[str, str]] = field(default_factory=list)
    tracked_files: dict[str, str | None] = field(default_factory=dict)
    directory_members: dict[str, tuple[str, ...] | None] = field(default_factory=dict)
    configuration_files: list[dict[str, Any]] = field(default_factory=list)
    input_files: list[_DefinitionFile] = field(default_factory=list)
    definition_files: list[_DefinitionFile] = field(default_factory=list)
    mods: list[_ModRecord] = field(default_factory=list)
    roots: list[dict[str, Any]] = field(default_factory=list)
    root_by_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    game_version: str | None = None
    raw_game_version: str | None = None
    definitions_sha256: str | None = None
    config_sha256: str | None = None


def _error(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


class MissionDefinitionError(ValueError):
    """A fail-closed error from the bounded static mission index."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class MissionDefinitionIndex:
    """Index effective static mission definitions without evaluating rules.

    ``enabled_mods=None`` reads ``user_data/dlc_load.json``.  Passing an
    explicit empty list is meaningful and means base game only.  The index
    records every relevant directory, including an initially missing one, so
    a later added or removed mission file invalidates the original scope.
    """

    def __init__(
        self,
        game_root: str | Path | None = None,
        user_data: str | Path | None = None,
        enabled_mods: Sequence[str | Path | Mapping[str, Any]] | str | Path | None = None,
        *,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
        max_files: int = DEFAULT_MAX_FILES,
        script_parser=None,
        load_definitions: bool = True,
    ) -> None:
        if type(load_definitions) is not bool:
            raise ValueError("load_definitions must be a boolean")
        for name, value in (
            ("max_file_bytes", max_file_bytes),
            ("max_total_bytes", max_total_bytes),
            ("max_files", max_files),
        ):
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        self.game_root = self._configured_path("game_root") if game_root is None else Path(game_root)
        self.user_data = self._configured_path("user_data") if user_data is None else Path(user_data)
        if enabled_mods is None:
            self._explicit_enabled_mods = False
            self.enabled_mods: list[Any] | None = None
        else:
            self._explicit_enabled_mods = True
            if isinstance(enabled_mods, (str, Path)):
                self.enabled_mods = [enabled_mods]
            else:
                self.enabled_mods = list(enabled_mods)
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.max_files = max_files
        self.script_parser = script_parser
        self.load_definitions = load_definitions
        self._state = self._build_state()

    @staticmethod
    def _configured_path(kind: str) -> Path | None:
        try:
            from work import local_config

            return local_config.game_root() if kind == "game_root" else local_config.user_data()
        except Exception:
            return None

    def _track(self, path: Path, digest: str | None) -> None:
        self._state.tracked_files[str(path)] = digest

    def _record_config(self, path: Path, kind: str, digest: str | None) -> None:
        self._track(path, digest)
        item: dict[str, Any] = {"path": str(path), "kind": kind}
        if digest is not None:
            item["sha256"] = digest
        self._state.configuration_files.append(item)

    def _record_directory(self, directory: Path, role: str) -> tuple[str, ...] | None:
        try:
            members = _safe_members(directory, self.max_files)
        except Exception as exc:
            self._state.errors.append(_error("MISSION_DIRECTORY_SCAN_FAILED", f"{directory}: {exc}"))
            members = None
        self._state.directory_members[str(directory)] = members
        if members is None and role == "basegame":
            self._state.errors.append(_error(
                "MISSION_DIRECTORY_MISSING", f"base mission directory not found: {directory}"
            ))
        return members

    def _load_version(self) -> None:
        if self.game_root is None:
            self._state.errors.append(_error("GAME_ROOT_UNAVAILABLE", "EU4 game root is not configured"))
            return
        launcher = self.game_root / "launcher-settings.json"
        if not launcher.is_file():
            self._record_config(launcher, "launcher_settings", None)
            self._state.errors.append(_error("GAME_VERSION_UNAVAILABLE", f"missing {launcher}"))
            return
        try:
            raw = _read_limited(launcher, self.max_file_bytes)
            digest = _hash_bytes(raw)
            self._record_config(launcher, "launcher_settings", digest)
            payload = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_json_no_duplicates)
            if not isinstance(payload, dict):
                raise ValueError("launcher-settings.json must contain an object")
            raw_version = payload.get("rawVersion") or payload.get("version")
            self._state.raw_game_version = raw_version if isinstance(raw_version, str) else None
            self._state.game_version = _normalise_version(raw_version)
            if self._state.game_version is None:
                self._state.errors.append(_error(
                    "GAME_VERSION_UNAVAILABLE", f"could not determine a version from {launcher}"
                ))
            elif self._state.game_version not in SUPPORTED_VERSIONS:
                self._state.errors.append(_error(
                    "UNSUPPORTED_GAME_VERSION",
                    f"mission definitions are verified for {SUPPORTED_VERSIONS}, got {self._state.game_version}",
                ))
        except Exception as exc:
            self._record_config(launcher, "launcher_settings", None)
            self._state.errors.append(_error("GAME_VERSION_UNAVAILABLE", f"{launcher}: {exc}"))

    def _enabled_entries(self) -> list[Any]:
        if self._explicit_enabled_mods:
            return list(self.enabled_mods or [])
        if self.user_data is None:
            self._state.errors.append(_error(
                "ENABLED_MOD_CONFIG_UNAVAILABLE",
                "enabled_mods was not supplied and EU4 user data is not configured",
            ))
            return []
        load_path = self.user_data / "dlc_load.json"
        if not load_path.is_file():
            self._record_config(load_path, "enabled_mod_config", None)
            self._state.errors.append(_error("ENABLED_MOD_CONFIG_UNAVAILABLE", f"missing {load_path}"))
            return []
        try:
            raw = _read_limited(load_path, self.max_file_bytes)
            digest = _hash_bytes(raw)
            self._record_config(load_path, "enabled_mod_config", digest)
            payload = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_json_no_duplicates)
            if not isinstance(payload, dict) or not isinstance(payload.get("enabled_mods"), list):
                raise ValueError("enabled_mods must be a list")
            return list(payload["enabled_mods"])
        except Exception as exc:
            self._state.errors.append(_error("ENABLED_MOD_CONFIG_INVALID", f"{load_path}: {exc}"))
            return []

    def _descriptor_candidates(self, entry: Any) -> tuple[Path | None, Path | None]:
        override_root: Path | None = None
        if isinstance(entry, Mapping):
            raw_descriptor = entry.get("descriptor") or entry.get("file") or entry.get("path")
            raw_root = entry.get("root") or entry.get("mod_root")
            if raw_root is not None:
                override_root = Path(str(raw_root))
        else:
            raw_descriptor = entry
        if not isinstance(raw_descriptor, (str, Path)):
            raise ValueError(f"invalid enabled mod entry: {entry!r}")
        candidate = Path(raw_descriptor).expanduser()
        if candidate.is_dir():
            return None, override_root or candidate
        if not candidate.is_absolute() and self.user_data is not None:
            candidate = self.user_data / candidate
        if not candidate.exists() and self.user_data is not None and not candidate.suffix:
            named = self.user_data / "mod" / (str(raw_descriptor) + ".mod")
            if named.exists():
                candidate = named
        return candidate, override_root

    def _parse_mod(self, entry: Any) -> _ModRecord:
        descriptor, override_root = self._descriptor_candidates(entry)
        descriptor_sha: str | None = None
        name: str | None = None
        archive: str | None = None
        replace_paths: list[str] = []
        raw_root: str | None = None
        if descriptor is not None:
            if not descriptor.is_file():
                self._track(descriptor, None)
                raise FileNotFoundError(f"enabled mod descriptor not found: {descriptor}")
            raw = _read_limited(descriptor, self.max_file_bytes)
            descriptor_sha = _hash_bytes(raw)
            self._record_config(descriptor, "mod_descriptor", descriptor_sha)
            text, _encoding = _decode_script(raw)
            nodes = _parse_mission_script(text)
            name = _first_scalar(nodes, "name")
            raw_root = _first_scalar(nodes, "path")
            archive = _first_scalar(nodes, "archive")
            replace_paths = _scalar_values(nodes, "replace_path")
            if archive:
                raise MissionDefinitionError("MOD_ARCHIVE_UNSUPPORTED", f"archive mod is unsupported: {descriptor}")
            for value in replace_paths:
                if not value or "\x00" in value:
                    raise ValueError(f"invalid replace_path in {descriptor}")
        root = override_root
        if root is None and raw_root:
            root_candidate = Path(raw_root).expanduser()
            candidates = [root_candidate]
            if not root_candidate.is_absolute():
                candidates = [descriptor.parent / root_candidate] if descriptor is not None else []
                if self.user_data is not None:
                    candidates.append(self.user_data / root_candidate)
                if self.user_data is not None:
                    candidates.append(self.user_data / "mod" / root_candidate)
            root = next((item for item in candidates if item.is_dir()), candidates[0] if candidates else None)
        if root is not None and not root.is_absolute() and descriptor is not None:
            root = descriptor.parent / root
        if root is None:
            raise ValueError(f"mod root is not declared: {descriptor or entry!r}")
        if not root.is_dir():
            raise FileNotFoundError(f"enabled mod root not found: {root}")
        return _ModRecord(
            descriptor=descriptor,
            descriptor_sha256=descriptor_sha,
            root=root,
            root_label=str(root),
            replace_paths=tuple(_normalise_relative(value) for value in replace_paths),
            name=name,
            archive=archive,
        )

    def _collect_files(self, directory: Path, source_kind: str, source_label: str) -> list[_DefinitionFile]:
        if not directory.is_dir():
            return []
        result: list[_DefinitionFile] = []
        seen: set[str] = set()
        for path in sorted(directory.rglob("*.txt"), key=lambda item: item.as_posix().casefold()):
            if not path.is_file():
                continue
            rel_name = path.relative_to(directory).as_posix()
            relative = f"{MISSION_RELATIVE}/{rel_name}"
            key = relative.casefold()
            if key in seen:
                self._state.errors.append(_error("DUPLICATE_MISSION_FILE", f"duplicate mission path: {relative}"))
                continue
            seen.add(key)
            try:
                digest, size = _hash_file(path, self.max_file_bytes)
            except Exception as exc:
                self._state.errors.append(_error("MISSION_FILE_UNAVAILABLE", f"{path}: {exc}"))
                self._track(path, None)
                continue
            self._track(path, digest)
            result.append(_DefinitionFile(relative, path, source_kind, source_label, digest, size))
        return result

    def _build_resolved_files(self, base_files: list[_DefinitionFile], mods: list[_ModRecord]) -> list[_DefinitionFile]:
        resolved: dict[str, _DefinitionFile] = {item.relative.casefold(): item for item in base_files}
        all_files = list(base_files)
        for mod in mods:
            mod_dir = mod.root / MISSION_RELATIVE if mod.root is not None else None
            self._record_directory(mod_dir, "mod") if mod_dir is not None else None
            mod_files = self._collect_files(mod_dir, "enabled_mod", str(mod.descriptor or mod.root)) if mod_dir else []
            all_files.extend(mod_files)
            mod.files = [str(item.path) for item in mod_files]
            for replace_path in mod.replace_paths:
                prefix = _mission_prefix(replace_path)
                if prefix is None:
                    continue
                if mod_dir is None or not mod_dir.is_dir():
                    self._state.errors.append(_error(
                        "REPLACED_MISSION_PATH_EMPTY",
                        f"replace_path removes base missions but mod directory is missing: {replace_path}",
                    ))
                for key, item in list(resolved.items()):
                    if _under(item.relative[len(MISSION_RELATIVE) + 1:], prefix):
                        del resolved[key]
                if not any(_under(item.relative[len(MISSION_RELATIVE) + 1:], prefix) for item in mod_files):
                    self._state.errors.append(_error(
                        "REPLACED_MISSION_PATH_EMPTY",
                        f"replace_path supplied no mission files: {replace_path}",
                    ))
            for item in mod_files:
                resolved[item.relative.casefold()] = item
        self._state.input_files = sorted(
            all_files,
            key=lambda item: (item.relative.casefold(), str(item.path).casefold()),
        )
        return [resolved[key] for key in sorted(resolved)]

    def _build_state(self) -> _State:
        self._state = _State()
        self._load_version()
        entries = self._enabled_entries()
        mods: list[_ModRecord] = []
        for entry in entries:
            try:
                mods.append(self._parse_mod(entry))
            except MissionDefinitionError as exc:
                self._state.errors.append(_error(exc.code, exc.message))
            except Exception as exc:
                self._state.errors.append(_error("ENABLED_MOD_UNSUPPORTED", str(exc)))
        self._state.mods = mods
        if self.game_root is None:
            return self._finish_state()
        base_dir = self.game_root / MISSION_RELATIVE
        self._record_directory(base_dir, "basegame")
        base_files = self._collect_files(base_dir, "basegame", "basegame")
        resolved = self._build_resolved_files(base_files, mods)
        total_bytes = sum(item.size for item in self._state.input_files)
        if len(self._state.input_files) > self.max_files:
            self._state.errors.append(_error(
                "MISSION_FILE_LIMIT", f"mission input count exceeds {self.max_files} files"
            ))
        if total_bytes > self.max_total_bytes:
            self._state.errors.append(_error(
                "MISSION_TOTAL_SIZE_LIMIT",
                f"mission input size exceeds {self.max_total_bytes} bytes ({total_bytes})",
            ))
        self._state.definition_files = resolved
        if self.load_definitions:
            self._parse_definitions(resolved)
        if not resolved and self.load_definitions:
            self._state.errors.append(_error("MISSION_DEFINITIONS_MISSING", "no resolved missions/*.txt files"))
        self._state.definitions_sha256 = _hash_bytes(_canonical([
            {"relative": item.relative, "sha256": item.sha256, "source": item.source_label}
            for item in resolved
        ]).encode("utf-8"))
        self._state.config_sha256 = _hash_bytes(_canonical({
            "configuration_files": self._state.configuration_files,
            "enabled_mods": [
                {"descriptor": str(mod.descriptor) if mod.descriptor else None,
                 "root": mod.root_label, "replace_paths": list(mod.replace_paths)}
                for mod in mods
            ],
        }).encode("utf-8"))
        return self._finish_state()

    def _finish_state(self) -> _State:
        # Keep the object graph bounded and JSON-compatible even if callers
        # inspect private state while diagnosing an unavailable source.
        return self._state

    def _parse_definitions(self, files: list[_DefinitionFile]) -> None:
        seen_roots: dict[str, str] = {}
        parsed = None
        if self.script_parser is not None:
            try:
                parsed = self.script_parser.parse_files([item.path for item in files])
            except Exception as exc:
                self._state.errors.append(_error("MISSION_SCRIPT_PARSER_FAILED", str(exc)))
                return
        for item in files:
            try:
                if parsed is None:
                    raw = _read_limited(item.path, self.max_file_bytes)
                    text, encoding = _decode_script(raw)
                    nodes = _parse_mission_script(text)
                else:
                    document = parsed[str(item.path.resolve())]
                    if document.get("error"):
                        raise ValueError(document["error"])
                    text, encoding = document["text"], document["encoding"]
                    nodes = document["nodes"]
                item.encoding = encoding
                item.text = text
                item.lines = None
            except Exception as exc:
                self._state.errors.append(_error("MISSION_DEFINITION_PARSE_FAILED", f"{item.path}: {exc}"))
                continue
            for node in nodes:
                if not any(child.key == "slot" for child in node.children):
                    continue
                root_id = node.key
                previous = seen_roots.get(root_id)
                if previous is not None:
                    self._state.errors.append(_error(
                        "DUPLICATE_MISSION_ROOT",
                        f"mission root {root_id!r} is repeated in {previous} and {item.relative}:{node.line}",
                    ))
                    continue
                seen_roots[root_id] = f"{item.relative}:{node.line}"
                definition = self._root_definition(node, item)
                self._state.roots.append(definition)
                self._state.root_by_id[root_id] = definition
            item.lines = None

    def _source_location(self, item: _DefinitionFile, node: _ScriptNode) -> dict[str, Any]:
        return {
            "path": item.relative,
            "absolute_path": str(item.path),
            "source_kind": item.source_kind,
            "source": item.source_label,
            "sha256": item.sha256,
            "size": item.size,
            "line": node.line,
            "end_line": node.end_line,
            "encoding": _copy(item.encoding or {"name": "unknown", "structural_only": True}),
        }

    def _task_definition(self, node: _ScriptNode, item: _DefinitionFile) -> dict[str, Any]:
        return {
            "task_id": node.key,
            "position": _field_value(node.children, "position", item),
            "required_missions": _field_value(node.children, "required_missions", item) or [],
            "trigger": _field_value(node.children, "trigger", item),
            "effect": _field_value(node.children, "effect", item),
            "provinces_to_highlight": _field_value(node.children, "provinces_to_highlight", item),
            "source": self._source_location(item, node),
        }

    def _root_definition(self, node: _ScriptNode, item: _DefinitionFile) -> dict[str, Any]:
        tasks = [
            self._task_definition(child, item)
            for child in node.children
            if child.children and child.key not in _ROOT_METADATA
        ]
        return {
            "root_id": node.key,
            "slot": _field_value(node.children, "slot", item),
            "generic": _field_value(node.children, "generic", item),
            "potential_on_load": _field_value(node.children, "potential_on_load", item),
            "potential": _field_value(node.children, "potential", item),
            "tasks": tasks,
            "source": self._source_location(item, node),
        }

    def _fingerprint_errors(self) -> list[dict[str, str]]:
        errors: list[dict[str, str]] = []
        for directory_text, expected in self._state.directory_members.items():
            directory = Path(directory_text)
            try:
                actual = _safe_members(directory, self.max_files)
            except Exception as exc:
                errors.append(_error("MISSION_DIRECTORY_SCAN_FAILED", f"{directory}: {exc}"))
                continue
            if actual != expected:
                errors.append(_error(
                    "MISSION_DIRECTORY_CHANGED",
                    f"mission directory membership changed: {directory}",
                ))
        for path_text, expected in self._state.tracked_files.items():
            path = Path(path_text)
            if expected is None:
                if path.exists():
                    errors.append(_error("MISSION_INPUT_CHANGED", f"input appeared after construction: {path}"))
                continue
            try:
                actual, _size = _hash_file(path, self.max_file_bytes)
            except Exception as exc:
                errors.append(_error("MISSION_INPUT_UNAVAILABLE", f"{path}: {exc}"))
                continue
            if actual != expected:
                errors.append(_error("MISSION_INPUT_CHANGED", f"static input changed: {path}"))
        return errors

    def context(self) -> dict[str, Any]:
        reasons = [*_copy(self._state.errors), *_copy(self._state.warnings), *self._fingerprint_errors()]
        parser_context = ({"name": "not_loaded", "semantics": "configuration_only"}
                          if not self.load_definitions else
                          self.script_parser.context() if self.script_parser is not None
                          else {"name": "legacy_mission_subset", "semantics": "syntax_only"})
        if self.load_definitions and self.script_parser is not None and parser_context.get("status") != "ready":
            reasons.append(_error("MISSION_SCRIPT_PARSER_CHANGED", "the configured script parser is unavailable or changed"))
        ready = not reasons and self._state.game_version in SUPPORTED_VERSIONS
        result = {
            "status": "ready" if ready else "unready",
            "complete": ready,
            "mode": "static",
            "context_scope": "static_rules",
            "game_root": str(self.game_root) if self.game_root is not None else None,
            "user_data": str(self.user_data) if self.user_data is not None else None,
            "game_version": self._state.game_version if self._state.game_version in SUPPORTED_VERSIONS else None,
            "game_version_raw": self._state.raw_game_version,
            "supported_versions": list(SUPPORTED_VERSIONS) if self._state.game_version in SUPPORTED_VERSIONS else [],
            "reasons": reasons,
            "configuration_sha256": self._state.config_sha256,
            "config_sha256": self._state.config_sha256,
            "definitions_sha256": self._state.definitions_sha256,
            "configuration_files": _copy(self._state.configuration_files),
            "definition_files": [
                {"relative": item.relative, "path": str(item.path), "source_kind": item.source_kind,
                 "source": item.source_label, "sha256": item.sha256, "size": item.size,
                 "encoding": _copy(item.encoding)}
                for item in self._state.definition_files
            ],
            "input_files": [
                {"relative": item.relative, "path": str(item.path), "source_kind": item.source_kind,
                 "source": item.source_label, "sha256": item.sha256, "size": item.size}
                for item in self._state.input_files
            ],
            "mission_directory_members": [
                {"path": path, "exists": members is not None, "members": list(members or ())}
                for path, members in self._state.directory_members.items()
            ],
            "enabled_mods": [
                {"descriptor": str(item.descriptor) if item.descriptor else None,
                 "descriptor_sha256": item.descriptor_sha256,
                 "name": item.name, "root": item.root_label,
                 "replace_paths": list(item.replace_paths),
                 "mission_definition_files": list(item.files)}
                for item in self._state.mods
            ],
            "root_count": len(self._state.roots),
            "static_source": "MissionDefinitionIndex",
            "script_parser": _copy(parser_context),
        }
        if not self.load_definitions:
            result["definitions_loaded"] = False
            result["root_count"] = None
        return result

    def _ensure_ready(self) -> None:
        if not self.load_definitions:
            raise MissionDefinitionError(
                "MISSION_DEFINITIONS_NOT_LOADED",
                "this index contains configuration metadata only; mission definitions were not loaded",
            )
        current = self.context()
        if current["status"] != "ready":
            reasons = current.get("reasons") or [{"code": "MISSION_SOURCE_UNREADY", "message": "source is unavailable"}]
            first = reasons[0] if isinstance(reasons[0], Mapping) else {}
            raise MissionDefinitionError(
                str(first.get("code", "MISSION_SOURCE_UNREADY")),
                str(first.get("message", "mission source is unavailable")),
            )

    def roots(self, ids: Sequence[str] | str | None = None) -> list[dict[str, Any]]:
        """Return all roots or the explicitly requested root IDs.

        Rule trees are returned as raw JSON-compatible nodes.  Passing an
        unknown ID raises ``MissionDefinitionError(code='UNKNOWN_ROOT_ID')``
        instead of silently dropping it.
        """

        self._ensure_ready()
        if ids is None:
            return _copy(self._state.roots)
        requested = [ids] if isinstance(ids, str) else list(ids)
        for root_id in requested:
            if not isinstance(root_id, str) or root_id not in self._state.root_by_id:
                raise MissionDefinitionError("UNKNOWN_ROOT_ID", f"unknown mission root: {root_id!r}")
        return [_copy(self._state.root_by_id[root_id]) for root_id in requested]

    def root(self, root_id: str) -> dict[str, Any]:
        """Return one root, or raise an explicit unknown-ID error."""

        if not isinstance(root_id, str) or not root_id:
            raise MissionDefinitionError("INVALID_ROOT_ID", "root_id must be a non-empty string")
        values = self.roots([root_id])
        return values[0]


__all__ = [
    "MissionDefinitionError",
    "MissionDefinitionIndex",
    "MISSION_RELATIVE",
    "SUPPORTED_VERSIONS",
]
