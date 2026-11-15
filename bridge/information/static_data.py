"""只读读取 EU4 安装目录中的静态贸易节点定义。

``StaticTradeSource`` 只解释 ``common/tradenodes`` 中的规则文件。它把
文件、启用模组描述文件和版本文件的 SHA-256 保存到来源上下文中，并在读取
时重新核对这些文件。这样静态节点图可以作为 T01、G04 和 T02 的一个可组合
来源，但不会被误报成当前游戏的贸易价值、国家 home node 或实时竞争力。

构造接口为::

    StaticTradeSource(
        game_root=None, user_data=None, enabled_mods=None,
        context_provider=None, max_file_bytes=8 * 1024 * 1024,
        localization_reader=None,
    )

``game_root`` 和 ``user_data`` 缺省时通过 ``work.local_config`` 读取本地
配置。``enabled_mods`` 可以是 ``dlc_load.json`` 中的描述文件列表；显式传入
空列表表示不读取启用模组。可选的 ``context_provider`` 只用于核对外部游戏
版本和附加采集时间，不用于从静态定义推断国家或实时状态。
``localization_reader`` 是一个可选的中性原生缓存读取器；它只在显式请求
T01 ``name`` 且调用者提供 ready live context 时被调用。
"""

from __future__ import annotations

from collections import OrderedDict
from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Callable, Iterable, Mapping, Sequence

from tools.build_diplomacy_catalog import Node, parse_script

from .catalog import get_topic, validate_query as catalog_validate_query
from .model import InformationError, canonical


TRADE_RELATIVE = "common/tradenodes"
SUPPORTED_VERSIONS = ("1.37.4",)
DEFAULT_MAX_FILE_BYTES = 8 * 1024 * 1024

# A trade node file is a data definition. These keys introduce a condition or
# executable script rather than a fixed graph. Treating one of them as a
# plain value would make the result depend on an unimplemented game condition.
_UNSUPPORTED_CONDITIONAL_KEYS = frozenset({
    "if", "else", "limit", "trigger", "potential", "allow", "condition",
    "conditional", "modifier", "factor", "has_dlc", "has_country_flag",
    "has_global_flag", "has_variable", "check_variable", "hidden_trigger",
})
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_VERSION_RE = re.compile(r"(?<!\d)(\d+\.\d+(?:\.\d+)?)(?!\d)")

_IMPLEMENTED_FIELDS = {
    "T01": frozenset({"node_id", "name", "provinces", "upstream", "downstream", "routes"}),
    # Static membership is the only G04 fact this source can establish. A
    # node's ``location`` is a map anchor, not proof that a port exists, and
    # node outgoing edges are not country trade-power transfer relations.
    "G04": frozenset({"trade_node"}),
    "T02": frozenset({"upstream", "routes"}),
}
_SUPPORTED_TOPICS = frozenset(_IMPLEMENTED_FIELDS)


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


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_text(path: Path, max_file_bytes: int) -> str:
    if not path.is_file():
        raise FileNotFoundError(str(path))
    size = path.stat().st_size
    if size > max_file_bytes:
        raise ValueError(f"file exceeds max_file_bytes ({size}>{max_file_bytes}): {path}")
    return path.read_text(encoding="utf-8-sig")


def _normalise_relative(value: str) -> str:
    value = value.strip().replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    return value.rstrip("/")


def _is_under(path: str, parent: str) -> bool:
    path = _normalise_relative(path)
    parent = _normalise_relative(parent)
    return path == parent or path.startswith(parent + "/")


def _node_values(node: Node, key: str) -> list[Node]:
    return [child for child in node.children if child.key == key]


def _last_scalar(node: Node, key: str) -> str | None:
    values = _node_values(node, key)
    for child in reversed(values):
        if child.children:
            raise ValueError(f"nested value is not supported for {key!r} at line {child.line}")
        if child.value is not None:
            return child.value
    return None


def _leaf_tokens(node: Node) -> list[str]:
    """Read a Clausewitz list whose leaves are bare or quoted tokens."""

    if node.value is not None:
        return [node.value]
    result: list[str] = []
    for child in node.children:
        if child.children:
            raise ValueError(f"nested list value at line {child.line}")
        result.append(child.value if child.value is not None else child.key)
    return result


def _coerce_number(value: str) -> int | float | str:
    if re.fullmatch(r"[+-]?\d+", value):
        try:
            return int(value)
        except ValueError:
            return value
    if re.fullmatch(r"[+-]?(?:\d+\.\d*|\d*\.\d+)", value):
        try:
            return float(value)
        except ValueError:
            return value
    return value


def _list_value(node: Node, key: str, *, numbers: bool = False) -> list[Any]:
    result: list[Any] = []
    for item in _node_values(node, key):
        tokens = _leaf_tokens(item)
        result.extend(_coerce_number(token) if numbers else token for token in tokens)
    return result


def _unique(values: Iterable[Any]) -> list[Any]:
    result: list[Any] = []
    seen: set[str] = set()
    for value in values:
        marker = canonical(value)
        if marker not in seen:
            seen.add(marker)
            result.append(value)
    return result


def _walk_for_unsupported(nodes: Iterable[Node]) -> str | None:
    for node in nodes:
        if node.key in _UNSUPPORTED_CONDITIONAL_KEYS:
            return node.key
        nested = _walk_for_unsupported(node.children)
        if nested:
            return nested
    return None


@dataclass(frozen=True)
class _TradeFile:
    relative: str
    path: Path
    source_kind: str
    source_label: str
    sha256: str


@dataclass
class _ModRecord:
    descriptor: Path
    descriptor_sha256: str
    root: Path | None
    root_label: str | None
    replace_paths: tuple[str, ...] = ()
    name: str | None = None
    archive: str | None = None
    files: list[str] = field(default_factory=list)


@dataclass
class _StaticState:
    files: tuple[_TradeFile, ...] = ()
    mods: tuple[_ModRecord, ...] = ()
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    province_to_nodes: dict[str, list[str]] = field(default_factory=dict)
    fingerprint: dict[str, str] = field(default_factory=dict)
    # Every base/enabled-mod trade directory is recorded, including a
    # directory that did not exist during construction. This lets the source
    # notice a new override file instead of continuing to serve the old graph.
    trade_directory_members: dict[str, tuple[str, ...] | None] = field(default_factory=dict)
    configuration_files: tuple[dict[str, Any], ...] = ()
    definitions_sha256: str | None = None
    config_sha256: str | None = None
    game_version: str | None = None
    raw_game_version: str | None = None
    game_sha256: str | None = None
    errors: list[dict[str, str]] = field(default_factory=list)
    warnings: list[dict[str, str]] = field(default_factory=list)


def _error(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


class StaticTradeSource:
    """Read static trade-node topology and province membership.

    The graph is built once from the resolved base-game and enabled-mod files.
    On every ``context``/``read`` call the source compares the recorded hashes
    and trade-directory member lists with the current inputs. A changed or
    unsupported overlay makes the source unavailable; it never silently falls
    back to a base-game definition.
    """

    event_types: tuple[str, ...] = ()

    def __init__(
        self,
        game_root: str | Path | None = None,
        user_data: str | Path | None = None,
        enabled_mods: Sequence[str | Path | Mapping[str, Any]] | None = None,
        context_provider: Callable[[], Mapping[str, Any]] | Any | None = None,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        localization_reader: Any | None = None,
    ) -> None:
        if type(max_file_bytes) is not int or max_file_bytes <= 0:
            raise ValueError("max_file_bytes must be a positive integer")
        self.game_root = Path(game_root) if game_root is not None else self._configured_path("game_root")
        self.user_data = Path(user_data) if user_data is not None else self._configured_path("user_data")
        self._explicit_enabled_mods = enabled_mods is not None
        self.enabled_mods = list(enabled_mods) if enabled_mods is not None else None
        self.context_provider = context_provider
        self.max_file_bytes = max_file_bytes
        # The reader is deliberately optional and neutral.  A static source
        # context is never passed to it as a substitute for a live context.
        self.localization_reader = localization_reader
        self._state = self._build_state()

    @staticmethod
    def _configured_path(kind: str) -> Path | None:
        try:
            from work import local_config

            return local_config.game_root() if kind == "game_root" else local_config.user_data()
        except Exception:
            return None

    # ------------------------- source discovery -------------------------

    def _load_enabled_entries(self, state: _StaticState) -> list[Any]:
        if self._explicit_enabled_mods:
            return list(self.enabled_mods or [])
        if self.user_data is None:
            state.errors.append(_error(
                "ENABLED_MOD_CONFIG_UNAVAILABLE",
                "enabled_mods was not supplied and EU4 user data is not configured",
            ))
            return []
        load_path = self.user_data / "dlc_load.json"
        if not load_path.exists():
            state.errors.append(_error(
                "ENABLED_MOD_CONFIG_UNAVAILABLE",
                f"enabled_mods was not supplied and {load_path} is missing",
            ))
            return []
        try:
            raw = load_path.read_bytes()
            if len(raw) > self.max_file_bytes:
                raise ValueError("dlc_load.json exceeds max_file_bytes")
            digest = hashlib.sha256(raw).hexdigest()
            state.fingerprint[str(load_path)] = digest
            state.configuration_files += ({
                "path": str(load_path), "kind": "enabled_mod_config", "sha256": digest,
            },)
            payload = json.loads(raw.decode("utf-8-sig"))
            entries = payload.get("enabled_mods", []) if isinstance(payload, dict) else None
            if not isinstance(entries, list):
                raise ValueError("enabled_mods must be a list")
            return entries
        except Exception as exc:
            state.errors.append(_error("ENABLED_MOD_CONFIG_INVALID", str(exc)))
            return []

    def _descriptor_path(self, entry: str | Path | Mapping[str, Any]) -> tuple[Path | None, Path | None]:
        override_root: Path | None = None
        if isinstance(entry, Mapping):
            raw_descriptor = entry.get("descriptor") or entry.get("file") or entry.get("path")
            raw_root = entry.get("root") or entry.get("mod_root")
            if raw_root:
                override_root = Path(str(raw_root))
        else:
            raw_descriptor = entry
        if not isinstance(raw_descriptor, (str, Path)):
            raise ValueError(f"invalid enabled mod descriptor entry: {entry!r}")
        descriptor = Path(raw_descriptor)
        if not descriptor.is_absolute() and self.user_data is not None:
            descriptor = self.user_data / descriptor
        return descriptor, override_root

    def _parse_mod(self, entry: str | Path | Mapping[str, Any], state: _StaticState) -> _ModRecord:
        descriptor, override_root = self._descriptor_path(entry)
        if descriptor is None or not descriptor.is_file():
            raise FileNotFoundError(f"enabled mod descriptor not found: {descriptor}")
        text = _read_text(descriptor, self.max_file_bytes)
        nodes = parse_script(text)
        unsupported = _walk_for_unsupported(nodes)
        if unsupported:
            raise ValueError(f"conditional descriptor key is unsupported: {unsupported}")
        descriptor_sha = _hash_file(descriptor)
        state.fingerprint[str(descriptor)] = descriptor_sha
        state.configuration_files += ({
            "path": str(descriptor), "kind": "mod_descriptor", "sha256": descriptor_sha,
        },)
        name = _last_scalar_from_roots(nodes, "name")
        raw_root = _last_scalar_from_roots(nodes, "path")
        archive = _last_scalar_from_roots(nodes, "archive")
        replace_values = _all_scalar_from_roots(nodes, "replace_path")
        if archive:
            raise ValueError(f"mod archive is unsupported: {descriptor}")
        if replace_values is None:
            replace_values = []
        for value in replace_values:
            if not isinstance(value, str) or not value:
                raise ValueError(f"invalid replace_path in {descriptor}")
        root = override_root
        if root is None and raw_root:
            root_candidate = Path(raw_root)
            candidates = [root_candidate]
            if not root_candidate.is_absolute():
                candidates = []
                if descriptor.parent:
                    candidates.append(descriptor.parent / root_candidate)
                if self.user_data is not None:
                    candidates.append(self.user_data / root_candidate)
                candidates.append(descriptor.parent / root_candidate)
            root = next((item for item in candidates if item.is_dir()), candidates[0] if candidates else None)
        if root is not None and not root.is_absolute():
            root = descriptor.parent / root
        if root is not None and not root.is_dir():
            raise FileNotFoundError(f"enabled mod root not found: {root}")
        return _ModRecord(
            descriptor=descriptor,
            descriptor_sha256=descriptor_sha,
            root=root,
            root_label=str(root) if root is not None else None,
            replace_paths=tuple(_normalise_relative(value) for value in replace_values),
            name=name,
            archive=archive,
        )

    def _build_resolved_files(self, state: _StaticState, mods: list[_ModRecord]) -> dict[str, _TradeFile]:
        if self.game_root is None:
            raise FileNotFoundError("EU4 game root is not configured")
        base_dir = self.game_root / TRADE_RELATIVE
        if not base_dir.is_dir():
            raise FileNotFoundError(f"trade node directory not found: {base_dir}")
        self._record_trade_directory(state, base_dir)
        resolved: dict[str, _TradeFile] = {}
        for path in sorted(base_dir.glob("*.txt")):
            relative = f"{TRADE_RELATIVE}/{path.name}"
            digest = _hash_file(path)
            state.fingerprint[str(path)] = digest
            resolved[relative] = _TradeFile(relative, path, "basegame", "basegame", digest)

        for mod in mods:
            mod_dir = mod.root / TRADE_RELATIVE if mod.root is not None else None
            if mod_dir is not None:
                self._record_trade_directory(state, mod_dir)
            mod_files = sorted(mod_dir.glob("*.txt")) if mod_dir is not None and mod_dir.is_dir() else []
            mod.files = [str(path) for path in mod_files]
            for path in mod_files:
                relative = f"{TRADE_RELATIVE}/{path.name}"
                digest = _hash_file(path)
                state.fingerprint[str(path)] = digest
                state.configuration_files += ({
                    "path": str(path), "kind": "mod_trade_definition",
                    "sha256": digest, "mod_descriptor": str(mod.descriptor),
                },)
                resolved[relative] = _TradeFile(
                    relative, path, "enabled_mod", str(mod.descriptor), digest,
                )
            # replace_path changes the resolution root. Remove all earlier
            # candidates below the replaced path before applying this mod.
            for replace_path in mod.replace_paths:
                if not _is_under(TRADE_RELATIVE, replace_path) and not _is_under(replace_path, TRADE_RELATIVE):
                    continue
                for relative in list(resolved):
                    if _is_under(relative, replace_path):
                        del resolved[relative]
                for path in mod_files:
                    relative = f"{TRADE_RELATIVE}/{path.name}"
                    # The file was already added above. Keeping this branch
                    # explicit documents that no base-game fallback occurs.
                    if _is_under(relative, replace_path):
                        digest = _hash_file(path)
                        resolved[relative] = _TradeFile(
                            relative, path, "enabled_mod", str(mod.descriptor), digest,
                        )
                if not any(_is_under(relative, replace_path) for relative in resolved):
                    state.errors.append(_error(
                        "REPLACED_TRADE_PATH_EMPTY",
                        f"replace_path removed base definitions but supplied no trade files: {replace_path}",
                    ))
        return resolved

    def _record_trade_directory(self, state: _StaticState, directory: Path) -> None:
        """Record a bounded immediate member list, even when ``directory`` is absent."""

        key = str(directory)
        if not directory.is_dir():
            state.trade_directory_members[key] = None
            return
        members: list[str] = []
        try:
            for index, item in enumerate(directory.iterdir()):
                if index >= 4096:
                    raise ValueError(f"trade directory has more than 4096 members: {directory}")
                members.append(item.name)
        except Exception as exc:
            state.errors.append(_error("TRADE_DIRECTORY_SCAN_FAILED", f"{directory}: {exc}"))
            state.trade_directory_members[key] = None
            return
        state.trade_directory_members[key] = tuple(sorted(members))

    # ------------------------------ parsing ------------------------------

    def _parse_graph(self, files: Mapping[str, _TradeFile], state: _StaticState) -> None:
        definitions: "OrderedDict[str, list[Node]]" = OrderedDict()
        definition_sources: dict[str, str] = {}
        duplicate_ids: set[str] = set()
        for relative in sorted(files):
            item = files[relative]
            try:
                nodes = parse_script(_read_text(item.path, self.max_file_bytes))
            except Exception as exc:
                state.errors.append(_error("TRADE_DEFINITION_PARSE_FAILED", f"{item.path}: {exc}"))
                continue
            unsupported = _walk_for_unsupported(nodes)
            if unsupported:
                state.errors.append(_error(
                    "UNSUPPORTED_TRADE_CONDITION",
                    f"{item.path}: conditional key {unsupported!r} cannot be evaluated statically",
                ))
                continue
            for node in nodes:
                if not _ID_RE.fullmatch(node.key):
                    state.errors.append(_error(
                        "INVALID_TRADE_NODE_ID", f"{item.path}:{node.line}: invalid node id {node.key!r}",
                    ))
                    continue
                previous_source = definition_sources.get(node.key)
                if previous_source is not None:
                    duplicate_ids.add(node.key)
                    state.errors.append(_error(
                        "DUPLICATE_TRADE_NODE",
                        f"node {node.key!r} has repeated top-level definitions in {previous_source} and {relative}",
                    ))
                    continue
                definition_sources.setdefault(node.key, relative)
                definitions.setdefault(node.key, []).append(node)

        for node_id, blocks in definitions.items():
            if node_id in duplicate_ids:
                continue
            children = [child for block in blocks for child in block.children]
            members: list[Any] = []
            routes: list[dict[str, Any]] = []
            for child in children:
                if child.key == "members":
                    members.extend(_coerce_number(value) for value in _leaf_tokens(child))
                elif child.key == "outgoing":
                    try:
                        name = _last_scalar(child, "name")
                        if not name:
                            raise ValueError("outgoing route has no name")
                        route: dict[str, Any] = {
                            "source": node_id,
                            "target": name,
                            "path": _list_value(child, "path", numbers=True),
                            "control": _list_value(child, "control", numbers=True),
                        }
                        routes.append(route)
                    except Exception as exc:
                        state.errors.append(_error(
                            "INVALID_TRADE_ROUTE", f"{node_id}:{child.line}: {exc}",
                        ))
            state.nodes[node_id] = {
                "node_id": node_id,
                # EU4 localised display names are in a separate localisation
                # tree. Keep the field absent rather than presenting the key
                # as a translated display name.
                "name": node_id,
                "provinces": _unique(members),
                "routes": routes,
            }

        # Reverse edges are derived only from the static outgoing declarations.
        upstream: dict[str, list[str]] = {node_id: [] for node_id in state.nodes}
        for node_id, node in state.nodes.items():
            for route in node["routes"]:
                target = route["target"]
                upstream.setdefault(target, [])
                if node_id not in upstream[target]:
                    upstream[target].append(node_id)
        for node_id, node in state.nodes.items():
            node["upstream"] = list(upstream.get(node_id, []))
            node["downstream"] = _unique(route["target"] for route in node["routes"])
        for node_id, node in state.nodes.items():
            for province in node["provinces"]:
                key = str(province)
                state.province_to_nodes.setdefault(key, [])
                if node_id not in state.province_to_nodes[key]:
                    state.province_to_nodes[key].append(node_id)

    def _build_state(self) -> _StaticState:
        state = _StaticState()
        try:
            if self.game_root is None:
                raise FileNotFoundError("EU4 game root is not configured")
            launcher = self.game_root / "launcher-settings.json"
            if launcher.is_file():
                raw = launcher.read_bytes()
                if len(raw) > self.max_file_bytes:
                    raise ValueError("launcher-settings.json exceeds max_file_bytes")
                launcher_sha = hashlib.sha256(raw).hexdigest()
                state.fingerprint[str(launcher)] = launcher_sha
                state.configuration_files += ({
                    "path": str(launcher), "kind": "launcher_settings", "sha256": launcher_sha,
                },)
                payload = json.loads(raw.decode("utf-8-sig"))
                raw_version = payload.get("rawVersion") or payload.get("version")
                state.raw_game_version = raw_version if isinstance(raw_version, str) else None
                state.game_version = _normalise_version(raw_version)
                if state.game_version and state.game_version not in SUPPORTED_VERSIONS:
                    state.errors.append(_error(
                        "UNSUPPORTED_GAME_VERSION", f"static trade definitions are verified for {SUPPORTED_VERSIONS}, got {state.game_version}",
                    ))
            else:
                state.errors.append(_error("GAME_VERSION_UNAVAILABLE", f"missing {launcher}"))
            if launcher.is_file() and state.game_version is None:
                state.errors.append(_error(
                    "GAME_VERSION_UNAVAILABLE",
                    f"could not determine a supported version from {launcher}",
                ))
            exe = self.game_root / "eu4.exe"
            if exe.is_file():
                state.game_sha256 = _hash_file(exe)

            entries = self._load_enabled_entries(state)
            mods: list[_ModRecord] = []
            for entry in entries:
                try:
                    mods.append(self._parse_mod(entry, state))
                except Exception as exc:
                    state.errors.append(_error("ENABLED_MOD_UNSUPPORTED", str(exc)))
            state.mods = tuple(mods)
            resolved = self._build_resolved_files(state, mods)
            state.files = tuple(resolved[key] for key in sorted(resolved))
            self._parse_graph(resolved, state)
            if not state.files:
                state.errors.append(_error("TRADE_DEFINITIONS_MISSING", "no resolved common/tradenodes/*.txt files"))
            state.definitions_sha256 = hashlib.sha256(canonical([
                {"relative": item.relative, "sha256": item.sha256, "source": item.source_label}
                for item in state.files
            ]).encode("utf-8")).hexdigest()
            state.config_sha256 = hashlib.sha256(canonical({
                "configuration_files": list(state.configuration_files),
                "enabled_mods": [str(item.descriptor) for item in state.mods],
            }).encode("utf-8")).hexdigest()
        except Exception as exc:
            state.errors.append(_error("STATIC_SOURCE_INITIALIZATION_FAILED", str(exc)))
        return state

    # --------------------------- public contract -------------------------

    def _provider_context(self) -> dict[str, Any]:
        provider = self.context_provider
        if provider is None:
            return {}
        try:
            value = provider() if callable(provider) else provider.context()
        except Exception as exc:
            return {"_error": str(exc)}
        return _copy(value) if isinstance(value, Mapping) else {"_error": "context_provider did not return an object"}

    def _fingerprint_errors(self) -> list[dict[str, str]]:
        errors: list[dict[str, str]] = []
        for path_text, expected_members in self._state.trade_directory_members.items():
            directory = Path(path_text)
            if expected_members is None:
                if directory.exists():
                    errors.append(_error(
                        "STATIC_TRADE_DIRECTORY_CHANGED",
                        f"trade definition directory was created after source construction: {directory}",
                    ))
                continue
            if not directory.is_dir():
                errors.append(_error(
                    "STATIC_TRADE_DIRECTORY_CHANGED",
                    f"trade definition directory was removed after source construction: {directory}",
                ))
                continue
            try:
                members_list: list[str] = []
                for index, item in enumerate(directory.iterdir()):
                    if index >= 4096:
                        raise ValueError("trade directory has more than 4096 members")
                    members_list.append(item.name)
                members = tuple(sorted(members_list))
            except Exception as exc:
                errors.append(_error("TRADE_DIRECTORY_SCAN_FAILED", f"{directory}: {exc}"))
                continue
            if members != expected_members:
                errors.append(_error(
                    "STATIC_TRADE_DIRECTORY_CHANGED",
                    f"trade definition directory membership changed: {directory}",
                ))
        for path_text, expected in self._state.fingerprint.items():
            path = Path(path_text)
            try:
                actual = _hash_file(path)
            except Exception as exc:
                errors.append(_error("STATIC_INPUT_UNAVAILABLE", f"{path}: {exc}"))
                continue
            if actual != expected:
                errors.append(_error("STATIC_INPUT_CHANGED", f"static input changed after source construction: {path}"))
        return errors

    def context(self) -> dict[str, Any]:
        provider = self._provider_context()
        errors = list(self._state.errors)
        errors.extend(self._fingerprint_errors())
        provider_error = provider.get("_error")
        if provider_error:
            errors.append(_error("CONTEXT_PROVIDER_FAILED", str(provider_error)))
        provider_version = _normalise_version(provider.get("game_version"))
        if provider_version and self._state.game_version and provider_version != self._state.game_version:
            errors.append(_error(
                "CONTEXT_GAME_VERSION_MISMATCH",
                f"context provider reports {provider_version}, static files report {self._state.game_version}",
            ))
        ready = not errors
        reasons = errors + list(self._state.warnings)
        result: dict[str, Any] = {
            "status": "ready" if ready else "unready",
            "session_id": provider.get("session_id"),
            "game_version": self._state.game_version,
            "game_version_raw": self._state.raw_game_version,
            "game_sha256": self._state.game_sha256,
            "observer": provider.get("observer"),
            "game_date": provider.get("game_date"),
            "game_day": provider.get("game_day"),
            "world_id": provider.get("world_id"),
            "paused": provider.get("paused"),
            "mode": "static",
            "context_scope": "static_rules",
            "complete": ready and not self._state.warnings,
            "reasons": reasons,
            "game_date_raw": provider.get("game_date_raw", provider.get("game_date")),
            "game_date_kind": provider.get("game_date_kind", "source_value"),
            "configuration_sha256": self._state.config_sha256,
            # Keep a short alias for callers that use ``config_sha256`` as
            # the provenance field name. Both values hash the same ordered
            # configuration-file manifest.
            "config_sha256": self._state.config_sha256,
            "static_config_sha256": self._state.config_sha256,
            "definitions_sha256": self._state.definitions_sha256,
            "trade_definitions_sha256": self._state.definitions_sha256,
            "configuration_files": _copy(list(self._state.configuration_files)),
            "definition_files": [{
                "relative": item.relative, "path": str(item.path), "source_kind": item.source_kind,
                "source": item.source_label, "sha256": item.sha256,
            } for item in self._state.files],
            "trade_directory_members": [{
                "path": path,
                "exists": members is not None,
                "members": list(members or ()),
            } for path, members in self._state.trade_directory_members.items()],
            "enabled_mods": [{
                "descriptor": str(item.descriptor), "descriptor_sha256": item.descriptor_sha256,
                "name": item.name, "root": item.root_label, "replace_paths": list(item.replace_paths),
                "trade_definition_files": list(item.files),
            } for item in self._state.mods],
            "static_source": "StaticTradeSource",
        }
        return result

    def catalog(self) -> list[dict[str, Any]]:
        version = self._state.game_version
        supported_versions = [version] if version in SUPPORTED_VERSIONS else []
        output: list[dict[str, Any]] = []
        for topic_id in ("T01", "G04", "T02"):
            base = get_topic(topic_id)
            fields = {
                field_name: _copy(base["fields"][field_name])
                for field_name in _IMPLEMENTED_FIELDS[topic_id]
                if field_name in base["fields"]
            }
            for field_name, field_spec in fields.items():
                field_spec["coverage"] = (
                    "partial" if field_name == "name" or topic_id == "T02" else "available"
                )
                field_spec["source"] = "StaticTradeSource"
                if topic_id == "T01" and field_name == "name":
                    field_spec["description"] = (
                        "本地化显示名称；node_id 来自静态贸易定义，文字仅在显式 live "
                        "查询中读取原生 literal cache；动态模板、缺失或校验失败保持 gap"
                    )
                if topic_id == "T02" and field_name == "routes":
                    field_spec["description"] = (
                        "节点定义中的单跳静态 outgoing 边；不是多跳候选路线或当前流量"
                    )
            base["fields"] = fields
            base["status"] = "available"
            base["source"] = "StaticTradeSource"
            base["context_scope"] = "static_rules"
            base["supported_versions"] = supported_versions
            # Only T01.name can use the optional live cache reader. Static
            # topology remains query-only, and this source never advertises
            # change/event delivery.
            base["triggers"] = (
                ["query", "periodic"]
                if self.localization_reader is not None and topic_id == "T01"
                else ["query"]
            )
            output.append(base)
        return output

    def validate_query(self, query: dict, context: dict | None = None) -> dict:
        if not isinstance(query, dict) or query.get("topic") not in _SUPPORTED_TOPICS:
            raise InformationError("unsupported_topic", "StaticTradeSource supports T01, G04 and T02 only")
        # Use the shared schema for object identity, field names and parameter
        # shape. Unimplemented fields remain valid so a composite can ask this
        # source for them and receive an explicit unsupported status.
        return catalog_validate_query(query, context)

    def _effective_context(self, supplied: Mapping[str, Any] | None) -> dict[str, Any]:
        own = self.context()
        if not isinstance(supplied, Mapping):
            return own
        # Static provenance remains authoritative. These values describe when
        # a composite source sampled the file, and do not alter static fields.
        for key in ("session_id", "observer", "game_date", "game_day", "world_id", "paused"):
            if key in supplied:
                own[key] = _copy(supplied[key])
        supplied_version = _normalise_version(supplied.get("game_version"))
        if supplied_version and own.get("game_version") and supplied_version != own["game_version"]:
            own["status"] = "unready"
            own["complete"] = False
            own.setdefault("reasons", []).append(_error(
                "CONTEXT_GAME_VERSION_MISMATCH",
                f"query context reports {supplied_version}, static files report {own['game_version']}",
            ))
        return own

    @staticmethod
    def _field_known(value: Any) -> dict[str, Any]:
        return {"status": "known", "value": _copy(value)}

    @staticmethod
    def _field_unknown(reason: str) -> dict[str, Any]:
        return {"status": "unknown", "reason": reason}

    @staticmethod
    def _field_unsupported(reason: str = "STATIC_FIELD_NOT_IMPLEMENTED") -> dict[str, Any]:
        return {"status": "unsupported", "reason": reason}

    @staticmethod
    def _field_unavailable(reason: str) -> dict[str, Any]:
        return {"status": "unavailable", "reason": reason}

    @staticmethod
    def _is_live_localization_context(context: Mapping[str, Any] | None) -> bool:
        """Return whether ``context`` can authorize one native cache read.

        ``StaticTradeSource.context()`` is intentionally a ``static_rules``
        context even when a real game installation is present. Requiring a
        ready live mode prevents that context from being mistaken for a
        session identity. Recorded, saved, and offline contexts are likewise
        query-only.
        """

        if not isinstance(context, Mapping):
            return False
        if context.get("status") != "ready" or context.get("mode") != "live":
            return False
        if context.get("context_scope") in {
            "static_rules", "static_localisation", "recorded", "saved", "offline",
        }:
            return False
        if context.get("recorded") is True or context.get("saved") is True:
            return False
        return isinstance(context.get("observer"), str) and bool(context.get("observer"))

    @staticmethod
    def _name_localization_metadata(
        key: str,
        localized: Mapping[str, Any] | None = None,
        entry: Mapping[str, Any] | None = None,
        *,
        status: str | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Build audit metadata without exposing a cache template as text."""

        localized = localized if isinstance(localized, Mapping) else {}
        entry = entry if isinstance(entry, Mapping) else {}
        reader_provenance = localized.get("provenance", {})
        if not isinstance(reader_provenance, Mapping):
            reader_provenance = {}
        codec = entry.get("codec")
        if codec is None:
            codec = localized.get("codec")
        if codec is None:
            codec = reader_provenance.get("codec")
        raw_template_hex = entry.get("raw_template_hex")
        if raw_template_hex is None:
            # ``value_hex`` is the raw field used by the capture report. The
            # normalized decoded-template contract normally renames it, but
            # preserving it here makes malformed records auditable too.
            raw_template_hex = entry.get("value_hex")
        metadata: dict[str, Any] = {
            "key": key,
            "language": localized.get("language", entry.get("language")),
            "codec": codec,
            "raw_template_hex": _copy(raw_template_hex),
            "reader_provenance": _copy(dict(reader_provenance)),
        }
        if status is not None:
            metadata["status"] = status
        if reason is not None:
            metadata["reason"] = reason
        return metadata

    @staticmethod
    def _static_context_unchanged(before: Mapping[str, Any], after: Mapping[str, Any]) -> bool:
        """Check the static guards again after a live cache read."""

        if before.get("status") != "ready" or after.get("status") != "ready":
            return False
        # These values are derived from the constructor-time file/mod
        # manifests or their current integrity checks. Compare the complete
        # manifests so an added/removed overlay cannot leave an old known name
        # attached to a new topology.
        for key in (
            "definitions_sha256", "trade_definitions_sha256",
            "configuration_sha256", "config_sha256", "static_config_sha256",
            "definition_files", "configuration_files", "enabled_mods",
            "trade_directory_members",
        ):
            if before.get(key) != after.get(key):
                return False
        return True

    def _name_value(
        self,
        obj: Mapping[str, Any],
        live_context: Mapping[str, Any] | None,
    ) -> tuple[str, Any, dict[str, Any] | None, bool]:
        """Resolve one T01 display name through the optional native cache.

        The static node lookup deliberately precedes every reader call. No
        static/localisation-index value is used as a fallback display string.

        The final boolean records whether the reader was actually invoked.
        ``read`` uses it to perform one whole-query static guard check after
        the reader returns, including for reader errors or incomplete entries.
        """

        node_id = obj.get("node_id")
        node = self._state.nodes.get(node_id)
        if node is None:
            return "unknown", "NODE_NOT_FOUND", None, False
        key = str(node_id)
        metadata = self._name_localization_metadata(key)
        if self.localization_reader is None or not self._is_live_localization_context(live_context):
            metadata.update({"status": "unknown", "reason": "LOCALISATION_NOT_READ"})
            return "unknown", "LOCALISATION_NOT_READ", metadata, False

        method = getattr(self.localization_reader, "localized_text", None)
        if not callable(method):
            metadata.update({"status": "unknown", "reason": "LOCALISATION_NOT_READ"})
            return "unknown", "LOCALISATION_NOT_READ", metadata, False

        country = live_context.get("observer")
        try:
            localized = method(country, _copy(dict(live_context)), [key])
        except InformationError as exc:
            reason = str(getattr(exc, "code", "LOCALIZATION_READ_FAILED"))
            metadata.update({"status": "unavailable", "reason": reason})
            return "unavailable", reason, metadata, True
        except Exception as exc:
            reason = getattr(exc, "code", None)
            if not isinstance(reason, str) or not reason:
                reason = "LOCALIZATION_READ_FAILED"
            metadata.update({"status": "unknown", "reason": reason})
            return "unknown", reason, metadata, True

        if not isinstance(localized, Mapping):
            metadata.update({"status": "unknown", "reason": "LOCALIZATION_READER_INVALID_RESULT"})
            return "unknown", "LOCALIZATION_READER_INVALID_RESULT", metadata, True
        entries = localized.get("entries")
        entry = entries.get(key) if isinstance(entries, Mapping) else None
        metadata = self._name_localization_metadata(key, localized, entry if isinstance(entry, Mapping) else None)

        top_status = localized.get("status")
        if top_status != "known":
            reason = localized.get("reason")
            if not isinstance(reason, str) or not reason:
                if isinstance(entry, Mapping) and isinstance(entry.get("reason"), str):
                    reason = entry["reason"]
                else:
                    provenance = localized.get("provenance")
                    reason = provenance.get("reason") if isinstance(provenance, Mapping) else None
                    if not isinstance(reason, str) or not reason:
                        reason = provenance.get("unknown_reason") if isinstance(provenance, Mapping) else None
                    if not isinstance(reason, str) or not reason:
                        reason = "LOCALIZATION_READER_INCOMPLETE"
            status = "unavailable" if top_status == "unavailable" else "unknown"
            metadata.update({"status": status, "reason": reason})
            return status, reason, metadata, True
        if not isinstance(entries, Mapping) or set(entries) != {key}:
            metadata.update({"status": "unknown", "reason": "LOCALIZATION_KEY_UNRESOLVED"})
            return "unknown", "LOCALIZATION_KEY_UNRESOLVED", metadata, True
        if not isinstance(entry, Mapping):
            metadata.update({"status": "unknown", "reason": "LOCALIZATION_KEY_UNRESOLVED"})
            return "unknown", "LOCALIZATION_KEY_UNRESOLVED", metadata, True

        entry_status = entry.get("status")
        if entry_status != "known":
            reason = entry.get("reason")
            if not isinstance(reason, str) or not reason:
                reason = entry.get("unknown_reason")
            if not isinstance(reason, str) or not reason:
                reason = (
                    "DYNAMIC_LOCALIZATION_UNRESOLVED"
                    if entry_status in {"template", "dynamic"}
                    else "LOCALIZATION_KEY_UNRESOLVED"
                )
            status = "unavailable" if entry_status == "unavailable" else "unknown"
            metadata.update({"status": status, "reason": reason})
            return status, reason, metadata, True

        text = entry.get("text")
        raw_template_hex = entry.get("raw_template_hex")
        if raw_template_hex is None:
            raw_template_hex = entry.get("value_hex")
        if raw_template_hex is not None and (
            not isinstance(raw_template_hex, str)
            or len(raw_template_hex) % 2
            or re.fullmatch(r"[0-9a-fA-F]*", raw_template_hex) is None
        ):
            reason = entry.get("reason") if isinstance(entry.get("reason"), str) else "LOCALIZATION_BYTES_INVALID"
            metadata.update({"status": "unknown", "reason": reason})
            return "unknown", reason, metadata, True
        codec = entry.get("codec")
        if codec is not None:
            try:
                from bridge.native_text import validate_native_text_codec
                validate_native_text_codec(codec)
            except Exception:
                reason = entry.get("reason") if isinstance(entry.get("reason"), str) else "LOCALIZATION_CODEC_INVALID"
                metadata.update({"status": "unknown", "reason": reason})
                return "unknown", reason, metadata, True
        dynamic = (
            not isinstance(text, str)
            or any(marker in text for marker in "[]$")
            or bool(entry.get("dynamic_tokens"))
            or bool(entry.get("unresolved_tokens"))
            or bool(entry.get("unresolved_markers"))
            or (
                isinstance(entry.get("template"), str)
                and (
                    entry.get("template") != text
                    or any(marker in entry["template"] for marker in "[]$")
                )
            )
            or entry.get("decoded_status") not in {None, "decoded"}
        )
        if dynamic:
            reason = entry.get("reason") if isinstance(entry.get("reason"), str) else (
                "LOCALIZATION_TEXT_INVALID" if not isinstance(text, str)
                else "DYNAMIC_LOCALIZATION_UNRESOLVED"
            )
            metadata.update({"status": "unknown", "reason": reason})
            return "unknown", reason, metadata, True

        metadata.update({"status": "known"})
        return "known", text, metadata, True

    def _values_for(self, topic: str, obj: Mapping[str, Any], field_name: str) -> tuple[str, Any]:
        object_type = obj.get("type")
        if field_name not in _IMPLEMENTED_FIELDS[topic]:
            return "unsupported", "STATIC_FIELD_NOT_IMPLEMENTED"
        if object_type == "trade_node":
            node_id = obj.get("node_id")
            node = self._state.nodes.get(node_id)
            if node is None:
                return "unknown", "NODE_NOT_FOUND"
            if topic == "T01":
                if field_name == "name":
                    return "unknown", "LOCALISATION_NOT_READ"
                return "known", node.get(field_name)
            if topic == "T02":
                return ("known", node.get(field_name)) if field_name in {"upstream", "routes"} else ("unknown", "COUNTRY_HOME_NODE_UNAVAILABLE")
        if topic == "G04" and object_type == "province":
            province_id = obj.get("province_id")
            node_ids = self._state.province_to_nodes.get(str(province_id), [])
            if field_name == "trade_node":
                if len(node_ids) == 1:
                    return "known", node_ids[0]
                if not node_ids:
                    return "unknown", "PROVINCE_NOT_IN_STATIC_TRADE_NODE"
                return "unknown", "AMBIGUOUS_PROVINCE_TRADE_NODE"
            return "unknown", "PROVINCE_STATIC_ROUTE_DETAIL_UNAVAILABLE"
        if topic == "T02" and object_type == "country":
            return "unknown", "COUNTRY_HOME_NODE_UNAVAILABLE"
        return "unknown", "OBJECT_NOT_SUPPORTED_BY_STATIC_TRADE_RULES"

    def read(self, query: dict, context: dict | None = None) -> dict:
        normalized = self.validate_query(query, context)
        current = self._effective_context(context)
        topic = normalized["topic"]
        fields: dict[str, dict[str, Any]] = {}
        name_localization = None
        localization_reader_invoked = False
        if current.get("status") != "ready":
            reason = (current.get("reasons") or [{"code": "STATIC_SOURCE_UNREADY"}])[0]
            reason_code = reason.get("code", "STATIC_SOURCE_UNREADY") if isinstance(reason, Mapping) else str(reason)
            fields = {
                field: self._field_unavailable(reason_code)
                for field in normalized["fields"]
            }
        else:
            for field_name in normalized["fields"]:
                if topic == "T01" and field_name == "name":
                    status, value, name_localization, reader_invoked = self._name_value(
                        normalized["object"], context
                    )
                    localization_reader_invoked = localization_reader_invoked or reader_invoked
                else:
                    status, value = self._values_for(topic, normalized["object"], field_name)
                if status == "known":
                    fields[field_name] = self._field_known(value)
                elif status == "unsupported":
                    fields[field_name] = self._field_unsupported(str(value))
                elif status == "unavailable":
                    fields[field_name] = self._field_unavailable(str(value))
                else:
                    fields[field_name] = self._field_unknown(str(value))

            # A live reader may race with a definition/modification update.
            # Recheck once for the entire query so a stale literal cannot be
            # combined with topology values sampled from the old state. This
            # runs even when the reader returned an unknown result or raised.
            if localization_reader_invoked:
                after = self.context()
                if not self._static_context_unchanged(current, after):
                    reason = "STATIC_SOURCE_CHANGED_DURING_LOCALIZATION"
                    fields = {
                        field: self._field_unavailable(reason)
                        for field in normalized["fields"]
                    }
                    current = _copy(after)
                    # Keep the caller's live identity/date on the item while
                    # taking static guard/provenance from the post-read
                    # context. ``_effective_context`` is intentionally not
                    # called again here: the post-read guard is one context
                    # sample and must not hash the inputs twice.
                    if isinstance(context, Mapping):
                        for key in ("session_id", "observer", "game_date", "game_day", "world_id", "paused"):
                            if key in context:
                                current[key] = _copy(context[key])
                    if current.get("status") == "ready":
                        current["status"] = "unready"
                        current["complete"] = False
                        current.setdefault("reasons", []).append(_error(reason, reason))
                    if name_localization is not None:
                        name_localization.update({"status": "unavailable", "reason": reason})
        if current.get("status") != "ready":
            # An initially unready source never invokes the reader, so there
            # is no live name provenance to expose. A post-read guard failure
            # retains its attempted live lookup metadata for auditability.
            if not localization_reader_invoked:
                name_localization = None
        complete = all(item.get("status") == "known" for item in fields.values())
        live_name_read = localization_reader_invoked
        source = {
            "name": "StaticTradeSource",
            "mode": "mixed" if live_name_read else "static",
            "context_scope": (
                "static_rules_and_native_localization"
                if live_name_read else "static_rules"
            ),
            "status": "observed" if current.get("status") == "ready" else "unavailable",
            "session_id": current.get("session_id"),
            "observer": current.get("observer"),
            "complete": complete,
            "game_version": current.get("game_version"),
            "definitions_sha256": current.get("definitions_sha256"),
            "configuration_sha256": current.get("configuration_sha256"),
            "config_sha256": current.get("config_sha256"),
            "enabled_mods": _copy(current.get("enabled_mods", [])),
            "provenance": {
                "game_version": current.get("game_version"),
                "game_sha256": current.get("game_sha256"),
                "config_sha256": current.get("config_sha256"),
                "definitions_sha256": current.get("definitions_sha256"),
                "definition_files": _copy(current.get("definition_files", [])),
                "configuration_files": _copy(current.get("configuration_files", [])),
                "enabled_mods": _copy(current.get("enabled_mods", [])),
                "trade_directory_members": _copy(current.get("trade_directory_members", [])),
            },
        }
        if name_localization is not None:
            if live_name_read:
                live = context if isinstance(context, Mapping) else {}
                name_localization.update({
                    "mode": "live",
                    "context_scope": "live",
                    "session_id": _copy(live.get("session_id")),
                    "game_date": _copy(live.get("game_date")),
                })
            source["name_localization"] = name_localization
        return {
            "topic": topic,
            "fields": fields,
            "source": source,
            "complete": complete,
            "game_date": current.get("game_date"),
            "objects": [_copy(normalized["object"])],
        }

    def poll_events(self, context: dict | None, cursor: Any) -> dict:
        if not isinstance(cursor, (dict, type(None))):
            raise InformationError("invalid_cursor", "cursor must be an object or null")
        # Static files have no native event stream. The empty result makes this
        # source safe to compose with a primary live/event source.
        return {"events": [], "cursor": _copy(cursor or {}), "complete": True, "gaps": []}


def _all_scalar_from_roots(nodes: Iterable[Node], key: str) -> list[str] | None:
    values: list[str] = []
    found = False
    for node in nodes:
        candidates = [node] if node.key == key else []
        candidates.extend(child for child in node.children if child.key == key)
        for child in candidates:
            if child.key != key:
                continue
            found = True
            if child.children or child.value is None:
                raise ValueError(f"nested or missing scalar value for {key!r} at line {child.line}")
            values.append(child.value)
    return values if found else None


def _last_scalar_from_roots(nodes: Iterable[Node], key: str) -> str | None:
    values = _all_scalar_from_roots(nodes, key)
    return values[-1] if values else None


__all__ = ["StaticTradeSource", "SUPPORTED_VERSIONS", "TRADE_RELATIVE"]
