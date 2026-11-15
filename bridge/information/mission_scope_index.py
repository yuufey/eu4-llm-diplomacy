"""Bounded static resolver for literal EU4 mission-scope identifiers.

This index records definition membership only.  It does not evaluate mission
conditions, determine whether a task is loaded, or claim runtime visibility.
"""
from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
import hashlib
import re
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from . import static_data as _static
from . import strait_definitions as _straits
from .cwtools_script import CwtoolsScriptParser
from .model import canonical
from .strait_csv import parse_definition_ids


MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_INPUT_BYTES = 16 * 1024 * 1024
MAX_SCOPE_FILES = 512
MAX_DIRECTORY_MEMBERS = 4096
MAX_MEMBERS_PER_SCOPE = 65535
_TAG_RE = re.compile(r"[A-Z0-9]{3}\Z")
_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}\Z")
_PROVINCE_RE = re.compile(r"[1-9][0-9]{0,4}\Z")

_MAP_SCOPE_FILES = {
    "areas": "map/area.txt",
    "regions": "map/region.txt",
    "superregions": "map/superregion.txt",
    "continents": "map/continent.txt",
    "province_groups": "map/provincegroup.txt",
}
_MAP_DEPENDENCIES = {
    "province_ids": {"province_ids"},
    "areas": {"province_ids", "areas"},
    "regions": {"province_ids", "areas", "regions"},
    "superregions": {"province_ids", "areas", "regions", "superregions"},
    "continents": {"province_ids", "continents"},
    "province_groups": {"province_ids", "province_groups"},
    "country_tags": {"country_tags"},
}


def _sha_file(path: Path, limit: int) -> tuple[str, int]:
    if not path.is_file():
        raise FileNotFoundError(str(path))
    size = path.stat().st_size
    if size < 1 or size > limit:
        raise ValueError(f"SCOPE_INPUT_SIZE_OUT_OF_RANGE:{size}:{path}")
    digest = hashlib.sha256()
    read_size = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(min(1024 * 1024, limit + 1 - read_size))
            if not chunk:
                break
            digest.update(chunk)
            read_size += len(chunk)
            if read_size > limit:
                raise ValueError(f"SCOPE_INPUT_SIZE_OUT_OF_RANGE:{read_size}:{path}")
    if read_size != size:
        raise ValueError(f"SCOPE_INPUT_CHANGED_DURING_HASH:{path}")
    return digest.hexdigest(), read_size


def _read_raw(path: Path, limit: int) -> bytes:
    if not path.is_file():
        raise FileNotFoundError(str(path))
    size = path.stat().st_size
    if size < 1 or size > limit:
        raise ValueError(f"SCOPE_INPUT_SIZE_OUT_OF_RANGE:{size}:{path}")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) != size or len(raw) > limit:
        raise ValueError(f"SCOPE_INPUT_CHANGED_DURING_READ:{path}")
    return raw


def _attr(node: Any, name: str, default: Any = None) -> Any:
    if isinstance(node, Mapping):
        return node.get(name, default)
    return getattr(node, name, default)


def _children(node: Any) -> list[Any]:
    value = _attr(node, "children", [])
    return value if isinstance(value, list) else []


def _node_text(node: Any) -> str | None:
    value = _attr(node, "value")
    return value if isinstance(value, str) else None


def _bare_name(node: Any) -> str | None:
    if (_attr(node, "kind") != "bare" or _attr(node, "assignment") is not None
            or _children(node)):
        return None
    key = _attr(node, "key")
    return key if isinstance(key, str) else None


def _block_name(node: Any) -> str | None:
    if (_attr(node, "kind") != "block" or _attr(node, "assignment") != "="
            or _node_text(node) is not None):
        return None
    key = _attr(node, "key")
    return key if isinstance(key, str) else None


def _last_scalar(nodes: Sequence[Any], key: str) -> str:
    matches = [node for node in nodes if _attr(node, "key") == key]
    if not matches:
        raise ValueError(f"MAP_DEFAULT_KEY_MISSING:{key}")
    node = matches[-1]
    if (_attr(node, "kind") != "scalar" or _attr(node, "assignment") != "="
            or _children(node) or _node_text(node) is None):
        raise ValueError(f"MAP_DEFAULT_KEY_INVALID:{key}")
    return _node_text(node)  # type: ignore[return-value]


def _scope_members(nodes: Sequence[Any], valid_ids: set[int], *, allow_color: bool = False) -> list[int]:
    values: list[int] = []
    seen: set[int] = set()
    for node in nodes:
        if allow_color and _attr(node, "key") == "color" and _block_name(node) is not None:
            continue
        text = _bare_name(node)
        if text is None or not _PROVINCE_RE.fullmatch(text):
            raise ValueError("SCOPE_MEMBER_NOT_PROVINCE_ID")
        province_id = int(text, 10)
        if province_id not in valid_ids:
            raise ValueError(f"SCOPE_MEMBER_NOT_IN_DEFINITIONS:{province_id}")
        if province_id not in seen:
            values.append(province_id)
            seen.add(province_id)
        if len(values) > MAX_MEMBERS_PER_SCOPE:
            raise ValueError("SCOPE_MEMBER_LIMIT")
    if not values:
        raise ValueError("SCOPE_HAS_NO_LITERAL_MEMBERS")
    return sorted(values)


def _file_record(path: Path, relative: str, source_kind: str, source: str,
                 digest: str, size: int) -> dict[str, Any]:
    return {"relative": relative, "bytes": size, "sha256": digest,
            "source_kind": source_kind, "source": source}


class StaticMissionScopeIndex:
    """Resolve named static geographic scopes against one effective mod stack.

    ``script_parser=None`` selects the repository's pinned CWTools parser.  A
    parser can be injected for offline tests, but there is no grammar fallback.
    """

    def __init__(self, game_root=None, user_data=None, enabled_mods=None,
                 script_parser=None, *, max_file_bytes: int = MAX_FILE_BYTES,
                 max_total_bytes: int = MAX_TOTAL_INPUT_BYTES,
                 max_files: int = MAX_SCOPE_FILES):
        if type(max_file_bytes) is not int or not 0 < max_file_bytes <= MAX_FILE_BYTES:
            raise ValueError("max_file_bytes must be in 1..4 MiB")
        if type(max_total_bytes) is not int or not 0 < max_total_bytes <= MAX_TOTAL_INPUT_BYTES:
            raise ValueError("max_total_bytes must be in 1..16 MiB")
        if type(max_files) is not int or not 0 < max_files <= MAX_SCOPE_FILES:
            raise ValueError("max_files must be in 1..512")
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.max_files = max_files
        self.game_root = (Path(game_root).expanduser().resolve() if game_root is not None
                          else _static.StaticTradeSource._configured_path("game_root"))
        self.user_data = (Path(user_data).expanduser().resolve() if user_data is not None
                          else _static.StaticTradeSource._configured_path("user_data"))
        self.script_parser = script_parser if script_parser is not None else CwtoolsScriptParser()
        self._explicit_enabled_mods = enabled_mods
        self._source: _straits.StraitDefinitionIndex | None = None
        self._global_errors: list[dict[str, str]] = []
        self._component_errors: dict[str, list[dict[str, str]]] = defaultdict(list)
        self._component_files: dict[str, set[str]] = defaultdict(set)
        self._file_records: dict[str, dict[str, Any]] = {}
        self._file_paths: dict[str, Path] = {}
        self._candidate_presence: dict[str, list[tuple[str, bool, bool]]] = {}
        self._country_directory_members: list[dict[str, Any]] = []
        self._configuration_files: list[dict[str, Any]] = []
        self._configuration_sha256: str | None = None
        self._definitions_sha256: str | None = None
        self._initial_input_bytes = 0
        self._game_version: str | None = None
        self._enabled_mods: list[dict[str, Any]] = []
        self._province_ids: set[int] = set()
        self._records: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
        self._record_errors: dict[tuple[str, str], str] = {}
        self._component_state: dict[str, str] = {}
        self._build()

    @staticmethod
    def _layers(source: _straits.StraitDefinitionIndex) -> list[Any]:
        return list(source._state.layers)

    def _resolve(self, relative: str, component: str) -> Path | None:
        assert self._source is not None
        try:
            path = self._source._resolve_file(relative)
        except Exception as exc:
            self._component_errors[component].append({"code": "SCOPE_PATH_RESOLUTION_FAILED",
                                                       "message": str(exc)[:300]})
            path = None
        presence = self._source._state.candidate_presence.get(relative, [])
        self._candidate_presence[relative] = [
            (str(item.get("root", "")), bool(item.get("exists")), bool(item.get("is_file")))
            for item in presence
        ]
        return path

    def _read_input(self, path: Path, relative: str, component: str) -> bytes | None:
        try:
            resolved = path.resolve(strict=True)
            if self._source is None or not any(
                    resolved.is_relative_to(Path(layer.root).resolve(strict=True))
                    for layer in self._layers(self._source)):
                raise ValueError("selected path is outside declared layers")
        except (OSError, ValueError, AttributeError) as exc:
            self._component_errors[component].append({"code": "SCOPE_PATH_OUTSIDE_LAYER",
                                                       "message": f"{relative}:{str(exc)[:160]}"})
            return None
        try:
            raw = _read_raw(path, self.max_file_bytes)
            digest = hashlib.sha256(raw).hexdigest()
            assert self._source is not None
            source_kind, source_label = self._source._source_for_path(path)
            record = _file_record(path, relative, source_kind, source_label, digest, len(raw))
            self._file_records[relative.casefold()] = record
            self._file_paths[relative.casefold()] = path.resolve()
            self._component_files[component].add(relative.casefold())
            self._initial_input_bytes += len(raw)
            if self._initial_input_bytes > self.max_total_bytes:
                raise ValueError("SCOPE_TOTAL_INPUT_LIMIT")
            return raw
        except Exception as exc:
            self._component_errors[component].append({"code": "SCOPE_INPUT_UNAVAILABLE",
                                                       "message": f"{relative}: {str(exc)[:240]}"})
            return None

    def _parsed_nodes(self, parsed: Mapping[str, Any], path: Path, component: str) -> list[Any] | None:
        row = parsed.get(str(path.resolve()))
        if not isinstance(row, Mapping):
            self._component_errors[component].append({"code": "SCOPE_PARSER_RESULT_MISSING",
                                                       "message": str(path)})
            return None
        if row.get("error"):
            self._component_errors[component].append({"code": str(row.get("error")),
                                                       "message": str(path)})
            return None
        nodes = row.get("nodes")
        if not isinstance(nodes, list):
            self._component_errors[component].append({"code": "SCOPE_PARSER_AST_INVALID",
                                                       "message": str(path)})
            return None
        return nodes

    def _country_candidates(self) -> list[str]:
        assert self._source is not None
        relative_names: dict[str, str] = {}
        layers = self._layers(self._source)
        for index, layer in enumerate(layers):
            root = Path(layer.root).resolve(strict=True)
            directory = root / "common" / "country_tags"
            exists = directory.is_dir()
            members: list[str] | None = None
            if exists:
                members = []
                try:
                    for item in directory.rglob("*"):
                        if len(members) >= MAX_DIRECTORY_MEMBERS:
                            raise ValueError("COUNTRY_TAG_DIRECTORY_LIMIT")
                        if not item.is_file() or item.suffix.casefold() != ".txt":
                            continue
                        resolved = item.resolve(strict=True)
                        resolved.relative_to(root)
                        relative = PurePosixPath("common/country_tags", item.relative_to(directory).as_posix()).as_posix()
                        if len(relative.encode("utf-8")) > 512:
                            raise ValueError("COUNTRY_TAG_PATH_LIMIT")
                        members.append(relative)
                        relative_names.setdefault(relative.casefold(), relative)
                except Exception as exc:
                    self._component_errors["country_tags"].append({"code": "COUNTRY_TAG_DIRECTORY_INVALID",
                                                                      "message": str(exc)[:240]})
            self._country_directory_members.append({
                "layer_index": index, "root": str(root), "exists": exists,
                "members": sorted(members) if members is not None else None,
            })
        if len(relative_names) > self.max_files:
            self._component_errors["country_tags"].append({"code": "SCOPE_FILE_COUNT_LIMIT",
                                                              "message": str(len(relative_names))})
            return []
        return [relative_names[key] for key in sorted(relative_names)]

    def _capture_configuration(self) -> None:
        assert self._source is not None
        state = self._source._state
        self._game_version = state.game_version
        self._configuration_sha256 = state.configuration_sha256
        config_items = list(state.compatibility.configuration_files)
        for item in config_items:
            path_text = item.get("path")
            if not isinstance(path_text, str):
                continue
            self._configuration_files.append({
                "path": str(Path(path_text).resolve()),
                "kind": item.get("kind"),
                "sha256": item.get("sha256"),
            })
        self._enabled_mods = [{
            "descriptor": str(mod.descriptor) if mod.descriptor is not None else None,
            "descriptor_sha256": mod.descriptor_sha256,
            "root": str(Path(mod.root).resolve()) if mod.root is not None else None,
            "replace_paths": list(mod.replace_paths),
        } for mod in state.mods]
        critical = {"GAME_ROOT_UNAVAILABLE", "GAME_VERSION_UNAVAILABLE", "UNSUPPORTED_GAME_VERSION",
                    "ENABLED_MOD_CONFIG_UNAVAILABLE", "ENABLED_MOD_CONFIG_INVALID",
                    "ENABLED_MOD_UNSUPPORTED", "MOD_ROOT_UNAVAILABLE", "MOD_COUNT_EXCEEDED"}
        for error in state.errors:
            if error.get("code") in critical:
                self._global_errors.append(dict(error))
        if self.game_root is None or state.game_version not in _straits._static.SUPPORTED_VERSIONS:
            self._global_errors.append({"code": "SCOPE_GAME_VERSION_UNAVAILABLE",
                                        "message": str(state.game_version)})

    def _build(self) -> None:
        if self.game_root is None or self.user_data is None:
            self._global_errors.append({"code": "SCOPE_CONFIGURATION_UNAVAILABLE",
                                        "message": "game_root/user_data is not configured"})
            return
        try:
            self._source = _straits.StraitDefinitionIndex(
                self.game_root, self.user_data, enabled_mods=self._explicit_enabled_mods,
                max_file_bytes=self.max_file_bytes)
        except Exception as exc:
            self._global_errors.append({"code": "SCOPE_LAYER_INITIALIZATION_FAILED",
                                        "message": str(exc)[:400]})
            return
        self._capture_configuration()
        if self._global_errors:
            return

        default_relative = "map/default.map"
        default_path = self._resolve(default_relative, "province_ids")
        default_raw = self._read_input(default_path, default_relative, "province_ids") if default_path else None
        parser_context = self.script_parser.context()
        if not isinstance(parser_context, Mapping) or parser_context.get("status") != "ready":
            self._global_errors.append({"code": "SCOPE_SCRIPT_PARSER_UNREADY",
                                        "message": "pinned CWTools parser is unavailable"})
            return
        default_nodes = None
        if default_path is not None and default_raw is not None:
            try:
                default_parsed = self.script_parser.parse_files([default_path])
                default_nodes = self._parsed_nodes(default_parsed, default_path, "province_ids")
            except Exception as exc:
                self._component_errors["province_ids"].append({"code": "MAP_DEFAULT_PARSE_FAILED",
                                                                  "message": str(exc)[:300]})
        definitions_path = None
        definitions_relative = None
        if default_nodes is not None:
            try:
                definitions_value = _last_scalar(default_nodes, "definitions")
                definitions_relative = _straits._normalise_map_relative(definitions_value)
                definitions_path = self._resolve(definitions_relative, "province_ids")
            except Exception as exc:
                self._component_errors["province_ids"].append({"code": "MAP_DEFINITION_SELECTION_INVALID",
                                                                  "message": str(exc)[:300]})
        definitions_raw = (self._read_input(definitions_path, definitions_relative, "province_ids")
                           if definitions_path is not None and definitions_relative is not None else None)
        if definitions_raw is not None:
            try:
                self._province_ids = parse_definition_ids(definitions_raw)
            except Exception as exc:
                self._component_errors["province_ids"].append({"code": "MAP_PROVINCE_IDS_INVALID",
                                                                  "message": str(exc)[:300]})

        parse_paths: dict[Path, tuple[str, str]] = {}
        map_paths: dict[str, Path] = {}
        for component, relative in _MAP_SCOPE_FILES.items():
            path = self._resolve(relative, component)
            if path is None:
                self._component_errors[component].append({"code": "SCOPE_DEFINITION_FILE_MISSING",
                                                           "message": relative})
                continue
            raw = self._read_input(path, relative, component)
            if raw is None:
                continue
            if self._initial_input_bytes > self.max_total_bytes:
                self._component_errors[component].append({"code": "SCOPE_TOTAL_INPUT_LIMIT"})
                continue
            map_paths[component] = path
            parse_paths[path] = (component, relative)
        country_relatives = self._country_candidates()
        country_paths: list[Path] = []
        for relative in country_relatives:
            path = self._resolve(relative, "country_tags")
            if path is None:
                continue
            raw = self._read_input(path, relative, "country_tags")
            if raw is None:
                continue
            country_paths.append(path)
            parse_paths[path] = ("country_tags", relative)

        if len(parse_paths) > self.max_files:
            for component in {value[0] for value in parse_paths.values()}:
                self._component_errors[component].append({"code": "SCOPE_FILE_COUNT_LIMIT",
                                                            "message": str(len(parse_paths))})
            parse_paths = {}
        if self._initial_input_bytes > self.max_total_bytes:
            self._global_errors.append({"code": "SCOPE_TOTAL_INPUT_LIMIT"})
            return
        if parse_paths:
            try:
                parsed = self.script_parser.parse_files(list(parse_paths))
            except Exception as exc:
                parsed = None
                for component in {value[0] for value in parse_paths.values()}:
                    self._component_errors[component].append({"code": "SCOPE_SCRIPT_PARSE_FAILED",
                                                                "message": str(exc)[:300]})
            if isinstance(parsed, Mapping):
                for path, (component, relative) in parse_paths.items():
                    nodes = self._parsed_nodes(parsed, path, component)
                    if nodes is None:
                        continue
                    try:
                        if component == "areas":
                            self._parse_areas(nodes)
                        elif component == "regions":
                            self._parse_regions(nodes)
                        elif component == "superregions":
                            self._parse_superregions(nodes)
                        elif component == "continents":
                            self._parse_direct_groups(nodes, "continents")
                        elif component == "province_groups":
                            self._parse_direct_groups(nodes, "province_groups", allow_color=True)
                        elif component == "country_tags":
                            self._parse_country_tags(nodes, relative)
                    except Exception as exc:
                        self._component_errors[component].append({"code": "SCOPE_DEFINITION_INVALID",
                                                                    "message": f"{relative}: {str(exc)[:240]}"})
        self._validate_derived_scopes()
        self._definitions_sha256 = hashlib.sha256(canonical({
            "files": [self._file_records[key] for key in sorted(self._file_records)],
            "component_files": {key: sorted(value) for key, value in sorted(self._component_files.items())},
        }).encode("utf-8")).hexdigest()
        all_components = set(_MAP_DEPENDENCIES)
        for component in all_components:
            self._component_state[component] = "ready" if not self._component_errors.get(component) else "unavailable"

    def _add_record(self, kind: str, name: str, value: Any, members: list[int] | None,
                    source_relative: str) -> None:
        if not _NAME_RE.fullmatch(name):
            raise ValueError(f"SCOPE_NAME_INVALID:{name[:80]}")
        key = name
        if (kind, key) in self._record_errors:
            return
        if key in self._records[kind]:
            self._record_errors[(kind, key)] = "SCOPE_NAME_DUPLICATE"
            self._records[kind].pop(key, None)
            return
        component = "country_tags" if kind == "country_tag" else kind
        dependencies = _MAP_DEPENDENCIES[component]
        files = {relative.casefold() for dependency in dependencies
                 for relative in self._component_files.get(dependency, set())}
        if kind == "country_tag":
            files = {source_relative.casefold()}
        else:
            files.add(source_relative.casefold())
        ordered_files = sorted(files)
        source_files = [deepcopy(self._file_records[file_key]) for file_key in ordered_files
                        if file_key in self._file_records]
        self._records[kind][key] = {
            "name": name, "value": deepcopy(value),
            "members": deepcopy(members) if members is not None else None,
            "source": {"files": source_files,
                       "configuration_sha256": self._configuration_sha256},
        }

    def _parse_areas(self, nodes: list[Any]) -> None:
        if not self._province_ids:
            self._component_errors["areas"].append({"code": "PROVINCE_DEFINITIONS_UNAVAILABLE"})
            return
        for node in nodes:
            name = _block_name(node)
            if name is None:
                raise ValueError("AREA_ROOT_NOT_BLOCK")
            try:
                members = _scope_members(_children(node), self._province_ids, allow_color=True)
                self._add_record("areas", name, name, members, "map/area.txt")
            except Exception as exc:
                self._record_errors[("areas", name)] = str(exc)

    def _parse_regions(self, nodes: list[Any]) -> None:
        seen_names: set[str] = set()
        for node in nodes:
            name = _block_name(node)
            if name is None:
                raise ValueError("REGION_ROOT_NOT_BLOCK")
            if name in seen_names:
                self._record_errors[("regions", name)] = "SCOPE_NAME_DUPLICATE"
                self._records["regions"].pop(name, None)
                continue
            seen_names.add(name)
            if not _NAME_RE.fullmatch(name):
                self._record_errors[("regions", name)] = "SCOPE_NAME_INVALID"
                continue
            area_blocks = [child for child in _children(node) if _attr(child, "key") == "areas"]
            other = [child for child in _children(node) if _attr(child, "key") != "areas"]
            if (len(area_blocks) != 1 or any(_attr(child, "key") != "monsoon" for child in other)
                    or _block_name(area_blocks[0]) is None):
                self._record_errors[("regions", name)] = "REGION_LAYOUT_UNSUPPORTED"
                continue
            area_names = []
            valid = True
            for child in _children(area_blocks[0]):
                value = _bare_name(child)
                if value is None or not _NAME_RE.fullmatch(value):
                    valid = False
                    break
                area_names.append(value)
            if not area_names:
                self._record_errors[("regions", name)] = "REGION_HAS_NO_STATIC_AREAS"
                continue
            if len(area_names) != len(set(area_names)):
                self._record_errors[("regions", name)] = "REGION_AREA_DUPLICATE"
                continue
            self._records["regions"][name] = {"name": name, "value": name,
                                                "area_names": area_names,
                                                "members": None,
                                                "source": {"files": [], "configuration_sha256": self._configuration_sha256}}
            if not valid:
                self._record_errors[("regions", name)] = "REGION_AREA_REFERENCE_INVALID"

    def _parse_superregions(self, nodes: list[Any]) -> None:
        seen_names: set[str] = set()
        for node in nodes:
            name = _block_name(node)
            if name is None:
                raise ValueError("SUPERREGION_ROOT_NOT_BLOCK")
            if name in seen_names:
                self._record_errors[("superregions", name)] = "SCOPE_NAME_DUPLICATE"
                self._records["superregions"].pop(name, None)
                continue
            seen_names.add(name)
            if not _NAME_RE.fullmatch(name):
                self._record_errors[("superregions", name)] = "SCOPE_NAME_INVALID"
                continue
            region_names = []
            valid = True
            for child in _children(node):
                value = _bare_name(child)
                if value == "restrict_charter":
                    continue
                if value is None or not _NAME_RE.fullmatch(value):
                    valid = False
                    break
                region_names.append(value)
            if not region_names:
                self._record_errors[("superregions", name)] = "SUPERREGION_HAS_NO_STATIC_REGIONS"
                continue
            if len(region_names) != len(set(region_names)):
                self._record_errors[("superregions", name)] = "SUPERREGION_REGION_DUPLICATE"
                continue
            self._records["superregions"][name] = {"name": name, "value": name,
                                                     "region_names": region_names,
                                                     "members": None,
                                                     "source": {"files": [], "configuration_sha256": self._configuration_sha256}}
            if not valid:
                self._record_errors[("superregions", name)] = "SUPERREGION_REGION_REFERENCE_INVALID"

    def _parse_direct_groups(self, nodes: list[Any], kind: str, *, allow_color: bool = False) -> None:
        for node in nodes:
            name = _block_name(node)
            if name is None:
                raise ValueError(f"{kind.upper()}_ROOT_NOT_BLOCK")
            try:
                members = _scope_members(_children(node), self._province_ids, allow_color=allow_color)
                self._add_record(kind, name, name, members, _MAP_SCOPE_FILES[kind])
            except Exception as exc:
                self._record_errors[(kind, name)] = str(exc)

    def _parse_country_tags(self, nodes: list[Any], relative: str) -> None:
        for node in nodes:
            name = _attr(node, "key")
            value = _node_text(node)
            if (_attr(node, "kind") != "scalar" or _attr(node, "assignment") != "="
                    or _children(node) or not isinstance(name, str) or not _TAG_RE.fullmatch(name)
                    or not isinstance(value, str) or not value or len(value) > 512
                    or "\x00" in value):
                raise ValueError("COUNTRY_TAG_ENTRY_INVALID")
            if name in self._records["country_tag"]:
                raise ValueError(f"COUNTRY_TAG_DUPLICATE:{name}")
            self._add_record("country_tag", name, name, None, relative)

    def _validate_derived_scopes(self) -> None:
        for name, record in list(self._records["regions"].items()):
            invalid = self._record_errors.get(("regions", name))
            member_ids: set[int] = set()
            if invalid is None:
                for area_name in record.get("area_names", []):
                    area = self._records["areas"].get(area_name)
                    if area is None or ("areas", area_name) in self._record_errors:
                        invalid = "REGION_AREA_REFERENCE_MISSING"
                        break
                    member_ids.update(area["members"] or [])
            if invalid is not None:
                self._record_errors[("regions", name)] = invalid
                continue
            record["members"] = sorted(member_ids)
            files = {file["relative"].casefold(): file for area_name in record.get("area_names", [])
                     for file in self._records["areas"][area_name]["source"]["files"]}
            for relative in sorted(self._component_files.get("regions", set())):
                if relative in self._file_records:
                    files[relative] = self._file_records[relative]
            record["source"]["files"] = [deepcopy(files[key]) for key in sorted(files)]

        for name, record in list(self._records["superregions"].items()):
            invalid = self._record_errors.get(("superregions", name))
            member_ids: set[int] = set()
            source_files: dict[str, dict[str, Any]] = {}
            if invalid is None:
                for region_name in record.get("region_names", []):
                    region = self._records["regions"].get(region_name)
                    if region is None or ("regions", region_name) in self._record_errors:
                        invalid = "SUPERREGION_REGION_REFERENCE_MISSING"
                        break
                    member_ids.update(region["members"] or [])
                    for file in region["source"]["files"]:
                        source_files[file["relative"].casefold()] = file
            if invalid is not None:
                self._record_errors[("superregions", name)] = invalid
                continue
            record["members"] = sorted(member_ids)
            for relative in self._component_files.get("superregions", set()):
                if relative in self._file_records:
                    source_files[relative] = self._file_records[relative]
            record["source"]["files"] = [deepcopy(source_files[key]) for key in sorted(source_files)]

    def _current_staleness(self) -> dict[str, list[dict[str, str]]]:
        stale: dict[str, list[dict[str, str]]] = defaultdict(list)
        if self._global_errors:
            for component in _MAP_DEPENDENCIES:
                stale[component].extend(deepcopy(self._global_errors))
            return stale
        try:
            parser_context = self.script_parser.context()
            if not isinstance(parser_context, Mapping) or parser_context.get("status") != "ready":
                for component in _MAP_DEPENDENCIES:
                    stale[component].append({"code": "SCOPE_SCRIPT_PARSER_CHANGED", "message": ""})
        except Exception as exc:
            for component in _MAP_DEPENDENCIES:
                stale[component].append({"code": "SCOPE_SCRIPT_PARSER_CHANGED", "message": str(exc)[:200]})

        for item in self._configuration_files:
            path = Path(item["path"])
            expected = item.get("sha256")
            try:
                if expected is None:
                    if path.exists():
                        raise ValueError("input_appeared")
                elif _sha_file(path, self.max_file_bytes)[0] != expected:
                    raise ValueError("input_hash_changed")
            except Exception as exc:
                for component in _MAP_DEPENDENCIES:
                    stale[component].append({"code": "SCOPE_CONFIGURATION_CHANGED",
                                             "message": f"{path.name}:{str(exc)[:100]}"})

        if self._source is not None:
            layers = self._layers(self._source)
            for relative, expected_rows in self._candidate_presence.items():
                actual_rows = []
                for layer in layers:
                    try:
                        candidate = self._source._safe_candidate(layer, relative)
                        actual_rows.append((str(layer.root), candidate.exists(), candidate.is_file()))
                    except Exception:
                        actual_rows.append((str(layer.root), False, False))
                if actual_rows != expected_rows:
                    for component, dependency in _MAP_DEPENDENCIES.items():
                        if component == "country_tags" and relative.startswith("common/country_tags/"):
                            stale[component].append({"code": "SCOPE_CANDIDATE_SET_CHANGED", "message": relative})
                        elif component != "country_tags" and relative in self._component_files.get(component, set()):
                            stale[component].append({"code": "SCOPE_CANDIDATE_SET_CHANGED", "message": relative})

        for relative, expected in self._file_records.items():
            try:
                actual = _sha_file(self._file_paths[relative], self.max_file_bytes)
                if (actual[0], actual[1]) != (expected["sha256"], expected["bytes"]):
                    raise ValueError("input_hash_changed")
            except Exception as exc:
                for component, files in self._component_files.items():
                    if relative in files:
                        stale[component].append({"code": "SCOPE_DEFINITION_CHANGED",
                                                 "message": f"{expected['relative']}:{str(exc)[:100]}"})

        if self._source is not None:
            layers = self._layers(self._source)
            for expected in self._country_directory_members:
                layer_index = expected["layer_index"]
                try:
                    root = Path(expected["root"]).resolve(strict=True)
                    directory = root / "common" / "country_tags"
                    exists = directory.is_dir()
                    members = None
                    if exists:
                        members = []
                        for item in directory.rglob("*.txt"):
                            if len(members) >= MAX_DIRECTORY_MEMBERS:
                                raise ValueError("member_limit")
                            if item.is_file():
                                item.resolve(strict=True).relative_to(root)
                                members.append(PurePosixPath("common/country_tags", item.relative_to(directory).as_posix()).as_posix())
                        members.sort()
                    actual = {"layer_index": layer_index, "root": str(root),
                              "exists": exists, "members": members}
                    if actual != expected:
                        stale["country_tags"].append({"code": "COUNTRY_TAG_DIRECTORY_CHANGED", "message": str(root)})
                except Exception as exc:
                    stale["country_tags"].append({"code": "COUNTRY_TAG_DIRECTORY_CHANGED",
                                                    "message": str(exc)[:180]})
        if stale.get("province_ids"):
            for component in ("areas", "regions", "superregions", "continents", "province_groups"):
                stale[component].append({"code": "PROVINCE_DEFINITION_DEPENDENCY_CHANGED", "message": ""})
        if stale.get("areas"):
            for component in ("regions", "superregions"):
                stale[component].append({"code": "AREA_DEPENDENCY_CHANGED", "message": ""})
        if stale.get("regions"):
            stale["superregions"].append({"code": "REGION_DEPENDENCY_CHANGED", "message": ""})
        return stale

    def context(self) -> dict[str, Any]:
        stale = self._current_staleness()
        parser_context = self.script_parser.context() if not self._global_errors else {"status": "unready"}
        components = {}
        for name in _MAP_DEPENDENCIES:
            errors = [*self._component_errors.get(name, []), *stale.get(name, [])]
            components[name] = {"status": "ready" if not errors else "unavailable",
                                "complete": not errors,
                                "definition_files": sorted(self._component_files.get(name, set())),
                                "reasons": deepcopy(errors)}
        global_ready = not self._global_errors and parser_context.get("status") == "ready"
        return {
            "schema": "information.mission_scope_index_context.v1",
            "status": "ready" if global_ready else "unready",
            "complete": global_ready and all(row["complete"] for row in components.values()),
            "mode": "static", "context_scope": "static_rules",
            "game_root": str(self.game_root.resolve()) if self.game_root is not None else None,
            "user_data": str(self.user_data.resolve()) if self.user_data is not None else None,
            "game_version": self._game_version,
            "configuration_sha256": self._configuration_sha256,
            "definitions_sha256": self._definitions_sha256,
            "configuration_files": deepcopy(self._configuration_files),
            "enabled_mods": deepcopy(self._enabled_mods),
            "definition_files": [deepcopy(self._file_records[key]) for key in sorted(self._file_records)],
            "component_statuses": components,
            "script_parser": parser_context,
            "initial_input_bytes": self._initial_input_bytes,
            "scope_count_by_kind": {kind: len(records) for kind, records in sorted(self._records.items())},
            "reasons": deepcopy(self._global_errors),
        }

    def _unknown(self, name: str, reason: str, kind: str | None = None) -> dict[str, Any]:
        result = {"status": "unknown", "name": name, "reason": reason}
        if kind is not None:
            result["kind"] = kind
        return result

    def lookup_scope(self, name: str) -> dict[str, Any]:
        return self.lookup_scopes([name]).get(name, self._unknown(str(name), "SCOPE_NOT_FOUND"))

    def lookup_scopes(self, names: Sequence[str]) -> dict[str, dict[str, Any]]:
        if isinstance(names, (str, bytes)) or not isinstance(names, Sequence):
            return {str(names): self._unknown(str(names), "INVALID_SCOPE_NAME_LIST")}
        current = self.context()
        component_states = current["component_statuses"]
        result: dict[str, dict[str, Any]] = {}
        for raw_name in names:
            if not isinstance(raw_name, str) or not raw_name or len(raw_name) > 128 or "\x00" in raw_name:
                key = str(raw_name)
                result[key] = self._unknown(key, "INVALID_SCOPE_NAME")
                continue
            name = raw_name
            matches: list[tuple[str, dict[str, Any]]] = []
            errors: list[tuple[str, str]] = []
            if _PROVINCE_RE.fullmatch(name):
                if component_states["province_ids"]["status"] == "ready" and int(name) in self._province_ids:
                    matches.append(("province_id", {"name": name, "value": int(name), "members": None,
                                                     "source": {"files": [self._file_records[key] for key in sorted(self._component_files.get("province_ids", set())) if key in self._file_records],
                                                                "configuration_sha256": self._configuration_sha256}}))
                elif component_states["province_ids"]["status"] != "ready":
                    errors.append(("province_id", "SCOPE_COMPONENT_UNAVAILABLE"))
            for kind, component in (("areas", "areas"), ("regions", "regions"),
                                    ("superregions", "superregions"), ("continents", "continents"),
                                    ("province_groups", "province_groups"), ("country_tag", "country_tags")):
                if component_states[component]["status"] != "ready":
                    if ((kind == "country_tag" and _TAG_RE.fullmatch(name))
                            or (kind != "country_tag" and _NAME_RE.fullmatch(name))):
                        errors.append((kind, "SCOPE_COMPONENT_UNAVAILABLE"))
                    continue
                record = self._records.get(kind, {}).get(name)
                if record is not None:
                    matches.append((kind, record))
                record_error = self._record_errors.get((kind, name))
                if record_error:
                    errors.append((kind, record_error))
            if len(matches) > 1:
                result[name] = self._unknown(name, "SCOPE_KIND_COLLISION")
                continue
            if errors:
                result[name] = self._unknown(name, errors[0][1], errors[0][0])
                continue
            if not matches:
                result[name] = self._unknown(name, "SCOPE_NOT_FOUND")
                continue
            kind, record = matches[0]
            row = {"status": "known", "kind": kind, "name": name,
                   "value": deepcopy(record["value"]),
                   "source": deepcopy(record["source"])}
            if record.get("members") is not None:
                row["members"] = deepcopy(record["members"])
            result[name] = row
        return result


__all__ = ["StaticMissionScopeIndex", "MAX_FILE_BYTES", "MAX_TOTAL_INPUT_BYTES", "MAX_SCOPE_FILES"]
