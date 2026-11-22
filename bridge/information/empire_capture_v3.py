"""Bounded global-HRE passed-reform projection with a pinned static widget link.

The profile binds the saved reform table to the HRE ``reform_selected_frame``
GUI declaration. It does not verify that the engine loaded or drew that GUI,
and it does not evaluate button availability, effects, or complete observer
visibility.
"""
from __future__ import annotations

from collections.abc import Mapping
from functools import partial
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any

from . import empire_capture as _v1_capture
from . import empire_capture_v2 as _v2
from . import empire_memory as _base_memory
from . import empire_reforms_memory as _memory
from . import foreign_technology_capture as _owner
from .strait_definitions import StraitDefinitionIndex


ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name("profiles") / "empire-memory-1374-v3-sampling-r2.json"
PROFILE_SHA256 = "463f00eac14a775a8de8aa810ef25cf4f1aa1708e9616b7b8e3062b1fd9209ab"
EXE_SHA256 = _v1_capture.EXE_SHA256
SCHEMA = "information.empire_capture.v3"
INNER_SCHEMA = "information.empire_observer_snapshot.v3"
_OBSERVER = "FRA"
_OBJECT = {"type": "country", "country": "HRE"}
_MAX_PROFILE_BYTES = 64 * 1024
_MAX_EXTERNAL_BYTES = 1024 * 1024
_REQUIRED_GUARDS = set(_v2._REQUIRED_GUARDS) | {
    "hre_ui_selected_frame_builder_key",
            "hre_ui_selected_frame_table_dispatch",
    "hre_ui_selected_frame_native_key",
}
_REQUIRED_DEPENDENCIES = {
    "bridge/information/foreign_technology_capture.py",
    "bridge/information/country_reference_memory.py",
    "bridge/information/empire_memory.py",
    "bridge/information/empire_capture.py",
    "bridge/information/empire_reforms_memory.py",
    "bridge/information/empire_capture_v2.py",
    "bridge/information/mission_memory.py",
    "bridge/information/localization_memory.py",
    "bridge/information/strait_definitions.py",
    "bridge/information/static_data.py",
    "tools/build_diplomacy_catalog.py",
}
_REQUIRED_SOURCES = {
    "work/runtime/information-full-regression-20261103-117-001/reform-ui-gates-001/widget-binding-report.json",
    "work/runtime/information-full-regression-20261103-117-001/reform-ui-gates-001/widget-binding-type-correction-001.json",
    "work/runtime/information-empire-reform-definitions-20261103-116-001/ui-binding-seeds-001/function-1164660.bin",
    "work/runtime/information-empire-reform-definitions-20261103-116-001/ui-binding-seeds-001/function-1164660.asm.txt",
    "bridge/information/profiles/empire-memory-1374-v2.json",
}
_EXPECTED_NEW_GUARDS = {
    "hre_ui_selected_frame_builder_key": (0x11648F7, 0x116492C),
    "hre_ui_selected_frame_table_dispatch": (0x1164C99, 0x1164D94),
    "hre_ui_selected_frame_native_key": (0x1D52310, 0x1D52326),
}
_TAG = re.compile(r"[A-Z0-9]{3}\Z")


def _sha(path: Path, *, limit: int | None = None) -> tuple[int, str]:
    size = path.stat().st_size
    if not path.is_file() or size < 1 or (limit is not None and size > limit):
        raise ValueError("EMPIRE_V3_INPUT_SIZE")
    digest = hashlib.sha256()
    read = 0
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            read += len(block)
            if limit is not None and read > limit:
                raise ValueError("EMPIRE_V3_INPUT_SIZE")
            digest.update(block)
    if read != size:
        raise ValueError("EMPIRE_V3_INPUT_CHANGED")
    return read, digest.hexdigest()


def _path_key(value: Any) -> str:
    if isinstance(value, Path):
        value = str(value)
    if not isinstance(value, str) or not value:
        raise ValueError("EMPIRE_V3_PATH_INVALID")
    return os.path.normcase(str(Path(value).resolve(strict=True)))


def _source_key(value: Any) -> str:
    if value == "basegame":
        return value
    return _path_key(value)


def _repo_pin_rows(profile: dict[str, Any], name: str) -> set[str]:
    rows = profile.get(name)
    if not isinstance(rows, list):
        raise ValueError("EMPIRE_V3_DEPENDENCIES_SHAPE")
    paths: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or not {"path", "bytes", "sha256"} <= set(row):
            raise ValueError("EMPIRE_V3_DEPENDENCY_SHAPE")
        rel = PurePosixPath(row["path"])
        if rel.is_absolute() or ".." in rel.parts or not rel.parts:
            raise ValueError("EMPIRE_V3_DEPENDENCY_PATH")
        path = (ROOT / Path(*rel.parts)).resolve(strict=True)
        path.relative_to(ROOT)
        if type(row["bytes"]) is not int or row["bytes"] < 0:
            raise ValueError("EMPIRE_V3_DEPENDENCY_SIZE_TYPE")
        if not _v1_capture._matches_reviewed_layout(row):
            raise ValueError("EMPIRE_V3_DEPENDENCY_PIN")
        paths.add(rel.as_posix())
    if len(paths) != len(rows):
        raise ValueError("EMPIRE_V3_DEPENDENCY_DUPLICATE")
    return paths


def _external_file_pin(row: Any) -> dict[str, Any]:
    if (not isinstance(row, dict) or not isinstance(row.get("path"), str)
            or not isinstance(row.get("kind"), str)
            or type(row.get("bytes")) is not int
            or not isinstance(row.get("sha256"), str)):
        raise ValueError("EMPIRE_V3_EXTERNAL_PIN_SHAPE")
    path = Path(row["path"]).resolve(strict=True)
    size, digest = _sha(path, limit=_MAX_EXTERNAL_BYTES)
    if size != row["bytes"] or digest != row["sha256"]:
        raise ValueError("EMPIRE_V3_EXTERNAL_PIN")
    return {"path": _path_key(path), "kind": row["kind"], "bytes": size, "sha256": digest}


def _configuration_paths(profile: dict[str, Any]) -> tuple[Path, Path]:
    binding = profile.get("ui_binding")
    if not isinstance(binding, dict):
        raise ValueError("EMPIRE_V3_UI_BINDING_SHAPE")
    try:
        game_root = Path(binding["game_root"]).resolve(strict=True)
        user_data = Path(binding["user_data"]).resolve(strict=True)
    except (KeyError, OSError, TypeError) as exc:
        raise ValueError("EMPIRE_V3_UI_ROOTS_INVALID") from exc
    if not game_root.is_dir() or not user_data.is_dir():
        raise ValueError("EMPIRE_V3_UI_ROOTS_INVALID")
    return game_root, user_data


def _current_ui_binding_snapshot(binding: dict[str, Any]) -> dict[str, Any]:
    """Re-resolve the pinned GUI and inputs through the existing mod resolver."""
    try:
        game_root = Path(binding["game_root"]).resolve(strict=True)
        user_data = Path(binding["user_data"]).resolve(strict=True)
        index = StraitDefinitionIndex(game_root=game_root, user_data=user_data)
        selected = index._resolve_file("interface/hre.gui")
        if selected is None:
            raise ValueError("EMPIRE_V3_EFFECTIVE_GUI_MISSING")
        context = index.context()
        selected_path = Path(selected).resolve(strict=True)
        gui_size, gui_sha = _sha(selected_path, limit=_MAX_EXTERNAL_BYTES)
        config_files = []
        for row in context.get("configuration_files", []):
            if not isinstance(row, dict):
                raise ValueError("EMPIRE_V3_CONFIG_FILE_SHAPE")
            path = Path(row["path"]).resolve(strict=True)
            size, digest = _sha(path, limit=_MAX_EXTERNAL_BYTES)
            if digest != row.get("sha256"):
                raise ValueError("EMPIRE_V3_CONFIG_FILE_CHANGED")
            config_files.append({
                "path": _path_key(path), "kind": row.get("kind"),
                "bytes": size, "sha256": digest,
            })
        enabled_mods = []
        for row in context.get("enabled_mods", []):
            if not isinstance(row, dict):
                raise ValueError("EMPIRE_V3_MOD_SHAPE")
            enabled_mods.append({
                "descriptor": _path_key(row.get("descriptor")),
                "descriptor_sha256": row.get("descriptor_sha256"),
                "name": row.get("name"),
                "root": _path_key(row.get("root")),
                "replace_paths": list(row.get("replace_paths", [])),
            })
        candidates = context.get("provenance", {}).get("candidate_presence", {}).get("interface/hre.gui")
        if not isinstance(candidates, list):
            raise ValueError("EMPIRE_V3_GUI_CANDIDATES_MISSING")
        selected_candidate = next(
            row for row in candidates
            if isinstance(row, dict) and _path_key(row.get("path")) == _path_key(selected_path)
        )
        return {
            "game_version": context.get("game_version"),
            "game_root": _path_key(game_root),
            "user_data": _path_key(user_data),
            "configuration_sha256": context.get("configuration_sha256"),
            "configuration_files": config_files,
            "enabled_mods": enabled_mods,
            "effective_gui": {
                "path": _path_key(selected_path), "bytes": gui_size, "sha256": gui_sha,
                "selected_layer_kind": selected_candidate.get("source_kind"),
                "selected_layer_source": _source_key(selected_candidate.get("source")),
            },
        }
    except Exception as exc:
        if isinstance(exc, ValueError) and str(exc).startswith("EMPIRE_V3_"):
            raise
        raise ValueError("EMPIRE_V3_UI_INPUT_UNAVAILABLE") from exc


def _expected_ui_binding_snapshot(profile: dict[str, Any]) -> dict[str, Any]:
    binding = profile["ui_binding"]
    return {
        "game_version": profile["game_version"],
        "game_root": _path_key(binding["game_root"]),
        "user_data": _path_key(binding["user_data"]),
        "configuration_sha256": binding["configuration_sha256"],
        "configuration_files": [
            _external_file_pin(row) for row in binding["configuration_files"]
        ],
        "enabled_mods": [
            {
                "descriptor": _path_key(row["descriptor"]),
                "descriptor_sha256": row["descriptor_sha256"],
                "name": row["name"],
                "root": _path_key(row["root"]),
                "replace_paths": list(row["replace_paths"]),
            }
            for row in binding["enabled_mods"]
        ],
        "effective_gui": {
            "path": _path_key(binding["effective_gui"]["path"]),
            "bytes": binding["effective_gui"]["bytes"],
            "sha256": binding["effective_gui"]["sha256"],
            "selected_layer_kind": binding["effective_gui"]["selected_layer_kind"],
            "selected_layer_source": _source_key(binding["effective_gui"]["selected_layer_source"]),
        },
    }


def _assert_ui_binding(profile: dict[str, Any]) -> dict[str, Any]:
    actual = _current_ui_binding_snapshot(profile["ui_binding"])
    expected = _expected_ui_binding_snapshot(profile)
    # Paths are canonicalized when the snapshot is constructed; the profile's
    # copies are canonicalized in the expected view as well.
    if not _owner._same(actual, expected):
        raise ValueError("EMPIRE_V3_UI_BINDING_CHANGED")
    return actual


def _load_profile() -> dict[str, Any]:
    # The frozen v2 profile is revalidated as a dependency. Its private-only
    # status is not used as the v3 publication decision.
    _owner._load_profile()
    v2_profile = _v2._load_profile()
    if (not re.fullmatch(r"[0-9a-f]{64}", PROFILE_SHA256)
            or not PROFILE_FILE.is_file()
            or not 0 < PROFILE_FILE.stat().st_size <= _MAX_PROFILE_BYTES):
        raise ValueError("EMPIRE_V3_PROFILE_NOT_FINALIZED")
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError("EMPIRE_V3_PROFILE_PIN")
    profile = json.loads(raw)
    if not isinstance(profile, dict):
        raise ValueError("EMPIRE_V3_PROFILE_SHAPE")
    if (profile.get("profile_id") != "empire-memory-1374-v3"
            or profile.get("profile_version") != 3
            or profile.get("schema") != "information.empire_capture_profile.v3"
            or profile.get("game_version") != "1.37.4"
            or profile.get("executable", {}).get("sha256") != EXE_SHA256
            or profile.get("object_scope") != "single_global_hre_record"
            or profile.get("profile_scope") != "global_hre_record_projection"
            or profile.get("publication_admitted") is not True
            or profile.get("reforms_publication_admitted") is not True
            or profile.get("framework_profile_sha256") != _owner.PROFILE_SHA256
            or profile.get("visibility") != {
                "actual_ui_observed": False,
                "visibility_evaluated": False,
                "reforms_publication_admitted": True,
                "basis": "static_global_record_to_selected_frame_widget_binding; no engine-loaded GUI or actual render observation",
            }
            or profile.get("reform_layout") != v2_profile.get("reform_layout")
            or profile.get("read_limits") != v2_profile.get("read_limits")):
        raise ValueError("EMPIRE_V3_PROFILE_BUILD")
    binding = profile.get("ui_binding")
    if (not isinstance(binding, dict)
            or binding.get("status") != "pinned_static_widget_binding"
            or binding.get("scope") != "global_hre_record_projection"
            or binding.get("static_only") is not True
            or binding.get("engine_loaded_gui_verified") is not False
            or binding.get("actual_ui_observed") is not False
            or binding.get("visibility_evaluated") is not False
            or binding.get("configuration_sha256") != "7b628430d182e2fcc113f9b5d9ec9094913b12b2d608fdfffc97fccf8d1a4122"):
        raise ValueError("EMPIRE_V3_UI_BINDING_POLICY")
    widget = binding.get("widget")
    gui = binding.get("effective_gui")
    if (not isinstance(widget, dict) or not isinstance(gui, dict)
            or not isinstance(binding.get("configuration_files"), list)
            or not binding["configuration_files"]
            or not isinstance(binding.get("enabled_mods"), list)
            or not binding["enabled_mods"]
            or widget.get("name") != "reform_selected_frame"
            or widget.get("gui_type") != "iconType"
            or widget.get("builder_rva") != "0x1164660"
            or widget.get("builder_object_offset") != "+0x28"
            or widget.get("key_compare_table_offset") != "+0x28"
            or widget.get("key_compare_count_offset") != "+0x34"
            or widget.get("matching_path_virtual_slots") != ["0x300", "0x88"]
            or widget.get("nonmatching_path_virtual_slot") != "0x2f8"
            or gui.get("bytes") != 18880
            or gui.get("sha256") != "3d1c21ef9addead74fc14b049dcdf0a75c4b6bfbab5d955b70f55b5351dc0f07"):
        raise ValueError("EMPIRE_V3_UI_BINDING_LAYOUT")
    source_paths = _repo_pin_rows(profile, "source_evidence")
    dependency_paths = _repo_pin_rows(profile, "layout_dependencies")
    if (not _REQUIRED_SOURCES <= source_paths
            or not _REQUIRED_DEPENDENCIES <= dependency_paths):
        raise ValueError("EMPIRE_V3_PROFILE_DEPENDENCIES")
    guards = profile.get("code_guards")
    if not isinstance(guards, list):
        raise ValueError("EMPIRE_V3_PROFILE_GUARDS")
    names: set[str] = set()
    for guard in guards:
        try:
            body = bytes.fromhex(guard["bytes"])
            start = int(guard["rva"], 0)
            end = int(guard["end_rva_exclusive"], 0)
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("EMPIRE_V3_PROFILE_GUARD_SHAPE") from exc
        if (not isinstance(guard.get("name"), str) or guard["name"] in names
                or not body or end != start + len(body)
                or type(guard.get("length")) is not int or guard["length"] != len(body)
                or hashlib.sha256(body).hexdigest() != guard.get("sha256")
                or len(body) > 1024
                or guard.get("relocation_sites") != []):
            raise ValueError("EMPIRE_V3_PROFILE_GUARD_INVALID")
        names.add(guard["name"])
        expected_range = _EXPECTED_NEW_GUARDS.get(guard["name"])
        if expected_range is not None and (start, end) != expected_range:
            raise ValueError("EMPIRE_V3_PROFILE_GUARD_RANGE")
    if not _REQUIRED_GUARDS <= names:
        raise ValueError("EMPIRE_V3_PROFILE_GUARD_SET")
    source_by_path = {row["path"]: row for row in profile["source_evidence"]}
    if (binding.get("source_report") != source_by_path.get(
            "work/runtime/information-full-regression-20261103-117-001/reform-ui-gates-001/widget-binding-report.json")
            or binding.get("ordinary_function") != source_by_path.get(
                "work/runtime/information-empire-reform-definitions-20261103-116-001/ui-binding-seeds-001/function-1164660.bin")):
        raise ValueError("EMPIRE_V3_UI_EVIDENCE_LINK")
    _assert_ui_binding(profile)
    return profile


def _process_path_matches_root(process_path: Any, game_root: Any) -> bool:
    if not isinstance(process_path, str) or not isinstance(game_root, str):
        return False
    try:
        process = Path(process_path).resolve(strict=True)
        root = Path(game_root).resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return False
    return os.path.normcase(str(process.parent)) == os.path.normcase(str(root))


def _binding_public(profile: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    ui = profile["ui_binding"]
    return {
        "status": "pinned_static_configuration_and_gui",
        "scope": "global_hre_record_projection",
        "configuration_sha256": snapshot["configuration_sha256"],
        "effective_gui": deepcopy(snapshot["effective_gui"]),
        "widget_name": ui["widget"]["name"],
        "widget_type": ui["widget"]["gui_type"],
        "builder_rva": ui["widget"]["builder_rva"],
        "builder_object_offset": ui["widget"]["builder_object_offset"],
        "key_compare_table_offset": ui["widget"]["key_compare_table_offset"],
        "key_compare_count_offset": ui["widget"]["key_compare_count_offset"],
        "engine_loaded_gui_verified": False,
        "actual_ui_observed": False,
        "visibility_evaluated": False,
    }


def _observe(reader: Any, module_base: int, country: str,
             profile: dict[str, Any], *, observer: str = _OBSERVER) -> dict[str, Any]:
    expected = _expected_ui_binding_snapshot(profile)
    binding_before = _current_ui_binding_snapshot(profile["ui_binding"])
    if not _owner._same(binding_before, expected):
        raise ValueError("EMPIRE_V3_UI_BINDING_CHANGED_BEFORE_READ")
    observation = _v2._observe(reader, module_base, country, profile, observer=observer)
    binding_after = _current_ui_binding_snapshot(profile["ui_binding"])
    binding_stable = (
        _owner._same(binding_after, expected)
        and _owner._same(binding_before, binding_after)
    )
    observation["profile_scope"] = "global_hre_record_projection"
    observation["publication_admitted"] = True
    observation["reforms_publication_admitted"] = True
    observation["ui_binding_before"] = binding_before
    observation["ui_binding_after"] = binding_after
    observation["static_widget_binding"] = _binding_public(profile, binding_before)
    observation["ui_binding_stable"] = binding_stable
    observation["actual_ui_observed"] = False
    observation["visibility_evaluated"] = False
    observation["stable"] = observation.get("stable") is True and binding_stable
    if not observation["stable"]:
        observation["status"] = "unknown"
    return observation


def capture(installation: Path, *, observer: str = _OBSERVER) -> dict[str, Any]:
    if not _v1_capture._valid_observer(observer):
        raise ValueError("EMPIRE_V3_OBSERVER_SCOPE")
    loaded: dict[str, Any] = {}

    def load_profile() -> dict[str, Any]:
        profile = _load_profile()
        loaded["profile"] = profile
        return profile

    inner = _owner._capture_common(
        installation, "HRE", observer=observer, schema=INNER_SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=load_profile,
        observe=partial(_observe, observer=observer), observer_scoped=True,
        allow_observer_target=True,
    )
    profile = loaded.get("profile")
    if (inner.get("status") == "observed" and inner.get("completed") is True
            and isinstance(profile, dict)):
        identity = inner.get("identity")
        identity_after = inner.get("identity_after")
        root = profile["ui_binding"]["game_root"]
        if (not isinstance(identity, dict) or not isinstance(identity_after, dict)
                or not _process_path_matches_root(identity.get("process_path"), root)
                or not _process_path_matches_root(identity_after.get("process_path"), root)):
            inner["status"] = "unknown"
            inner["completed"] = False
            errors = inner.setdefault("errors", [])
            errors.append({"type": "ValueError", "reason": "EMPIRE_V3_PROCESS_ROOT_MISMATCH"})
    return {"schema": SCHEMA, "observer": observer, "object": dict(_OBJECT), "capture": inner}


def validate_capture(report: Any, context: Mapping[str, Any], creation: int) -> bool:
    try:
        observer = context.get("observer") if isinstance(context, Mapping) else None
        if (not _v1_capture._valid_observer(observer) or not isinstance(report, dict)
                or set(report) != {"schema", "observer", "object", "capture"}
                or report.get("schema") != SCHEMA or report.get("observer") != observer
                or not _owner._same(report.get("object"), _OBJECT)
                or type(creation) is not int or creation <= 0
                or not isinstance(context, Mapping)):
            return False
        inner = report.get("capture")
        if not isinstance(inner, dict) or inner.get("schema") != INNER_SCHEMA:
            return False
        request = inner.get("request")
        identity = inner.get("identity")
        identity_after = inner.get("identity_after")
        if (not isinstance(request, dict) or not isinstance(identity, dict)
                or not isinstance(identity_after, dict)
                or type(request.get("creation_filetime")) is not int
                or request["creation_filetime"] <= 0):
            return False
        for row in (identity, identity_after):
            for key in ("installation_creation_filetime", "process_creation_filetime"):
                if type(row.get(key)) is not int or row[key] <= 0:
                    return False
        if (inner.get("profile_sha256") != PROFILE_SHA256
                or request.get("observer") != observer or request.get("country") != "HRE"
                or request.get("creation_filetime") != creation):
            return False
        profile = _load_profile()
        root = profile["ui_binding"]["game_root"]
        if (not _process_path_matches_root(identity.get("process_path"), root)
                or not _process_path_matches_root(identity_after.get("process_path"), root)):
            return False
        return _owner._validate_capture_common(
            inner, context, creation, "HRE", schema=INNER_SCHEMA,
            profile_sha256=PROFILE_SHA256, load_profile=lambda: profile,
            observe=partial(_observe, observer=observer), observer_scoped=True,
            allow_observer_target=True, require_access=True,
        )
    except Exception:
        return False


def _v2_projection_report(report: dict[str, Any]) -> dict[str, Any]:
    inner = deepcopy(report["capture"])
    inner["schema"] = _v2.INNER_SCHEMA
    inner["profile_sha256"] = _v2.PROFILE_SHA256
    return {"schema": _v2.SCHEMA, "observer": report["observer"],
            "object": dict(_OBJECT), "capture": inner}


def project_fields(report: Any) -> dict[str, Any]:
    if (not isinstance(report, dict) or set(report) != {"schema", "observer", "object", "capture"}
            or report.get("schema") != SCHEMA
            or not _v1_capture._valid_observer(report.get("observer"))
            or not _owner._same(report.get("object"), _OBJECT)):
        raise ValueError("EMPIRE_V3_PROJECTION_SCOPE")
    profile = _load_profile()
    inner = report.get("capture")
    if (not isinstance(inner, dict) or inner.get("schema") != INNER_SCHEMA
            or inner.get("profile_sha256") != PROFILE_SHA256
            or inner.get("status") != "observed" or inner.get("completed") is not True
            or inner.get("profile_sha256") != PROFILE_SHA256
            or not isinstance(inner.get("cleanup"), dict)
            or inner["cleanup"].get("status") != "closed"
            or inner["cleanup"].get("closed") is not True
            or inner["cleanup"].get("success") is not True):
        raise ValueError("EMPIRE_V3_CAPTURE_NOT_COMPLETE")
    root = profile["ui_binding"]["game_root"]
    identity = inner.get("identity")
    identity_after = inner.get("identity_after")
    if (not isinstance(identity, dict) or not isinstance(identity_after, dict)
            or not _process_path_matches_root(identity.get("process_path"), root)
            or not _process_path_matches_root(identity_after.get("process_path"), root)):
        raise ValueError("EMPIRE_V3_PROCESS_ROOT_MISMATCH")
    observation = inner.get("observation")
    expected_ui = _expected_ui_binding_snapshot(profile)
    expected_public = _binding_public(profile, expected_ui)
    if (not isinstance(observation, dict) or observation.get("status") != "observed"
            or observation.get("stable") is not True
            or observation.get("ui_binding_stable") is not True
            or observation.get("profile_scope") != "global_hre_record_projection"
            or observation.get("publication_admitted") is not True
            or observation.get("reforms_publication_admitted") is not True
            or observation.get("actual_ui_observed") is not False
            or observation.get("visibility_evaluated") is not False
            or not _owner._same(observation.get("ui_binding_before"), expected_ui)
            or not _owner._same(observation.get("ui_binding_after"), expected_ui)
            or not _owner._same(observation.get("static_widget_binding"), expected_public)):
        raise ValueError("EMPIRE_V3_CAPTURE_NOT_STABLE")

    # The v2 projector is reused only as a pure whitelist for the unchanged
    # country tags. V3 profile admission and replay checks above authorize this
    # report; the synthetic v2 identity is never used for permission.
    fields = _v2.project_fields(_v2_projection_report(report))
    if set(fields) != {"emperor", "electors", "reforms"}:
        raise ValueError("EMPIRE_V3_PROJECTION_FIELDS")
    reform_field = fields["reforms"]
    if not isinstance(reform_field, dict):
        raise ValueError("EMPIRE_V3_REFORM_PROJECTION")
    reform_field = dict(reform_field)
    reform_field["basis"] = "global_hre_passed_reform_ids_with_static_selected_frame_binding"
    reform_field["complete"] = False
    reform_field["actual_ui_observed"] = False
    reform_field["visibility_evaluated"] = False
    fields["reforms"] = reform_field
    return fields


__all__ = ["capture", "validate_capture", "project_fields", "PROFILE_SHA256"]
