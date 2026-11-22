"""Bounded read-only directed relation predicates.

This child reader replays the audited guarantee and military-access leaves from
copied country relation rows. It never calls a game function. Selected-pair
captures retain the requested operand direction, while country network
captures keep both directions explicit.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from . import country_resources_memory as _crm
from . import localization_memory as _loc
from . import mission_memory as _mm
from . import relation_memory as _rel


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "directed-relations-memory-1374.json"
PROFILE_MAX_BYTES = 64 * 1024
SOURCE_MAX_BYTES = 16 * 1024 * 1024
EXPECTED_PROFILE_ID = "directed-relations-memory-1374"
EXPECTED_PROFILE_SHA256 = "8672cf2642148fe02ac030dcc18c3589c26f62d1321b53819af82bf06341b727"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_VERSION = "1.37.4"
EXPECTED_COUNTRY = "FRA"
FIELDS = ("guarantee", "military_access")
FAMILIES = FIELDS
BASIS = "native_current_directed_relation_predicate"
VALUE_ORIGIN = "derived_from_copied_relation_rows_and_owner_vectors"
UNIT = "relation_state"
SCALE = 1
PERIOD = "current"
NULL_COUNTRY_FULLREF_RAW_HEX = "2d2d2d0000000000"
MAX_SINGLE_RPM = 65_536
MAX_TOTAL_RPM = 512 * 1024
NETWORK_MAX_TOTAL_RPM = 2 * 1024 * 1024
MAX_COUNTRY_ENTRIES = 4096
MAX_VECTOR_COUNT = 4096
MAX_USER_ADDRESS = _mm.MAX_USER_ADDRESS
PROCESS_ACCESS = _mm.PROCESS_ACCESS

AddressBoundedRPM = _crm.AddressBoundedRPM
NetworkAddressBoundedRPM = _rel.NetworkAddressBoundedRPM
_load_installation = _loc._load_installation
_configure_kernel = _loc._configure_kernel
_capture_identity = _loc._capture_identity
_close_process_handle = _loc._close_process_handle
_read_pe_rva_bytes = _loc._read_pe_rva_bytes
_valid_pointer = _rel._valid_pointer
_safe_add = _rel._safe_add
_addr = _rel._addr
_field = _rel._field
_slot_from_fullref = _rel._slot_from_fullref
_signed_i16 = _rel._signed_i16
_tag_and_slot = _rel._tag_and_slot
_context_snapshot = _rel._context_snapshot
_network_context_snapshot = _rel._network_context_snapshot
_relation_row = _rel._relation_row
_without_volatile = _rel._without_volatile
_diff_paths = _rel._diff_paths
ProbeError = _crm.ProbeError


class ProfileError(RuntimeError):
    """The pinned directed-relation profile or source contract is invalid."""


def _copy_evidence(value: Any) -> Any:
    """Copy the reader's JSON evidence while keeping mutable children separate."""
    if isinstance(value, dict):
        return {key: _copy_evidence(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_copy_evidence(child) for child in value]
    return value


def _index_elements(elements: list[dict[str, Any]]) -> dict[int, list[dict[str, Any]]]:
    result: dict[int, list[dict[str, Any]]] = {}
    for element in elements:
        result.setdefault(element["first_dword"], []).append(element)
    return result


def _parse_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ProfileError(f"profile_integer_invalid:{label}")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        try:
            result = int(value, 0)
        except ValueError as exc:
            raise ProfileError(f"profile_integer_invalid:{label}") from exc
    else:
        raise ProfileError(f"profile_integer_invalid:{label}")
    if result < 0:
        raise ProfileError(f"profile_integer_negative:{label}")
    return result


def _sha256_file(path: Path, limit: int | None = None) -> str:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if limit is not None and size > limit:
                raise ProfileError(f"file_over_bound:{path}")
            digest.update(chunk)
    return digest.hexdigest()


def _workspace_path(raw_path: Any) -> Path:
    if not isinstance(raw_path, str) or not raw_path:
        raise ProfileError("source_path_invalid")
    root = Path(__file__).resolve().parents[2]
    path = Path(raw_path)
    resolved = (path if path.is_absolute() else root / path).resolve()
    if resolved != root and root not in resolved.parents:
        raise ProfileError("source_path_outside_workspace")
    return resolved


def _bounded_file(path: Path, limit: int, label: str) -> bytes:
    try:
        size = path.stat().st_size
        if size <= 0 or size > limit:
            raise ProfileError(f"{label}_size_out_of_bound:{size}")
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
    except (OSError, UnicodeError) as exc:
        raise ProfileError(f"{label}_read_failed:{exc}") from exc
    if len(raw) != size or len(raw) > limit:
        raise ProfileError(f"{label}_read_size_changed:{path}")
    return raw


def _profile_code_guards(profile: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    profile = _load_profile() if profile is None else profile
    raw = profile.get("code_guards")
    if not isinstance(raw, list) or not raw:
        raise ProfileError("profile_code_guards_missing")
    result: list[dict[str, Any]] = []
    names: set[str] = set()
    for item in raw:
        if not isinstance(item, Mapping):
            raise ProfileError("profile_code_guard_invalid")
        name = item.get("name")
        hex_value = item.get("hex", item.get("bytes"))
        if not isinstance(name, str) or not name or name in names or not isinstance(hex_value, str):
            raise ProfileError("profile_code_guard_shape_invalid")
        try:
            expected = bytes.fromhex(hex_value)
        except ValueError as exc:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}") from exc
        rva = _parse_int(item.get("rva"), f"code_guard.{name}.rva")
        end = _parse_int(item.get("end_rva_exclusive"), f"code_guard.{name}.end")
        if end != rva + len(expected) or len(expected) > MAX_SINGLE_RPM:
            raise ProfileError(f"profile_code_guard_range_invalid:{name}")
        if hashlib.sha256(expected).hexdigest().lower() != str(item.get("sha256", "")).lower():
            raise ProfileError(f"profile_code_guard_sha_invalid:{name}")
        kind = item.get("kind", "bytes")
        if kind not in {"bytes", "pointer_slot"}:
            raise ProfileError(f"profile_code_guard_kind_invalid:{name}")
        target_rva = _parse_int(item.get("target_rva"), f"code_guard.{name}.target_rva") if kind == "pointer_slot" else None
        result.append({"name": name, "kind": kind, "rva": rva, "end": end, "expected": expected, "target_rva": target_rva})
        names.add(name)
    return result


def _profile_layout(profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
    profile = _load_profile() if profile is None else profile
    try:
        executable = profile["executable"]
        globals_ = profile["globals"]
        country = profile["country"]
        relation = profile["relation"]
        families = profile["families"]
        limits = profile["limits"]
        if not all(isinstance(item, Mapping) for item in (executable, globals_, country, relation, families, limits)):
            raise ProfileError("profile_layout_not_object")
        if profile.get("profile_id") != EXPECTED_PROFILE_ID or profile.get("game_version") != EXPECTED_VERSION:
            raise ProfileError("profile_identity_invalid")
        if str(executable.get("sha256", "")).lower() != EXPECTED_EXE_SHA256:
            raise ProfileError("profile_executable_sha_invalid")
        if country.get("supported_actor") != EXPECTED_COUNTRY:
            raise ProfileError("profile_supported_actor_invalid")
        result: dict[str, Any] = {
            "database_rva": _parse_int(globals_.get("database_rva"), "globals.database_rva"),
            "game_rva": _parse_int(globals_.get("game_rva"), "globals.game_rva"),
            "game_date_offset": _parse_int(globals_.get("game_date_offset"), "globals.game_date_offset"),
            "country_table_offset": _parse_int(country.get("table_offset"), "country.table_offset"),
            "country_count_offset": _parse_int(country.get("count_offset"), "country.count_offset"),
            "country_fullref_offset": _parse_int(country.get("fullref_offset"), "country.fullref_offset"),
            "max_country_entries": _parse_int(country.get("max_entries"), "country.max_entries"),
            "relation_table_offset": _parse_int(relation.get("table_offset"), "relation.table_offset"),
            "relation_row_stride": _parse_int(relation.get("row_stride"), "relation.row_stride"),
            "relation_row_owner_offset": _parse_int(relation.get("row_owner_offset"), "relation.row_owner_offset"),
            "relation_row_recipient_offset": _parse_int(relation.get("row_recipient_fullref_offset"), "relation.row_recipient_fullref_offset"),
            "element_stride": _parse_int(relation.get("element_stride"), "relation.element_stride"),
            "max_total_rpm": _parse_int(limits.get("max_total_rpm"), "limits.max_total_rpm"),
            "network_max_total_rpm": _parse_int(limits.get("network_max_total_rpm"), "limits.network_max_total_rpm"),
            "max_single_rpm": _parse_int(limits.get("max_single_rpm"), "limits.max_single_rpm"),
            "max_requested_families": _parse_int(limits.get("max_requested_families"), "limits.max_requested_families"),
            "max_vector_count": _parse_int(limits.get("max_vector_count"), "limits.max_vector_count"),
            "network_max_candidates": _parse_int(limits.get("network_max_candidates"), "limits.network_max_candidates"),
            "families": {},
        }
        if (result["max_country_entries"] != MAX_COUNTRY_ENTRIES
                or result["max_vector_count"] != MAX_VECTOR_COUNT
                or result["element_stride"] != 0x10
                or result["max_total_rpm"] != MAX_TOTAL_RPM
                or result["network_max_total_rpm"] != NETWORK_MAX_TOTAL_RPM
                or result["max_single_rpm"] != MAX_SINGLE_RPM
                or result["max_requested_families"] != len(FAMILIES)):
            raise ProfileError("profile_bounds_invalid")
        if result["network_max_candidates"] != MAX_COUNTRY_ENTRIES:
            raise ProfileError("profile_network_bound_invalid")
        if set(families) != set(FAMILIES):
            raise ProfileError("profile_family_set_invalid")
        for family in FAMILIES:
            item = families[family]
            if not isinstance(item, Mapping):
                raise ProfileError(f"profile_family_invalid:{family}")
            parsed = {
                "vector_begin_offset": _parse_int(item.get("vector_begin_offset"), f"{family}.vector_begin_offset"),
                "vector_count_offset": _parse_int(item.get("vector_count_offset"), f"{family}.vector_count_offset"),
                "predicate_rva": _parse_int(item.get("predicate_rva"), f"{family}.predicate_rva"),
                "direction_map": dict(item.get("direction_map", {})),
            }
            if family == "guarantee":
                parsed["record_pointer_offset"] = _parse_int(item.get("record_pointer_offset"), f"{family}.record_pointer_offset")
                parsed["record_fullref_offset"] = _parse_int(item.get("record_fullref_offset"), f"{family}.record_fullref_offset")
                if item.get("first_match") is not True:
                    raise ProfileError("profile_guarantee_first_match_invalid")
            if set(parsed["direction_map"]) != {"forward", "reverse"}:
                raise ProfileError(f"profile_direction_map_invalid:{family}")
            result["families"][family] = parsed
        return result
    except (KeyError, TypeError, ValueError) as exc:
        raise ProfileError(f"profile_layout_invalid:{exc}") from exc


def _load_profile(path: Path | None = None, expected_sha256: str | None = None) -> dict[str, Any]:
    path = PROFILE_FILE if path is None else Path(path)
    expected = EXPECTED_PROFILE_SHA256 if expected_sha256 is None else expected_sha256
    raw = _bounded_file(path, PROFILE_MAX_BYTES, "profile")
    if not isinstance(expected, str) or len(expected) != 64 or expected.startswith("__"):
        raise ProfileError("profile_sha256_pin_invalid")
    if hashlib.sha256(raw).hexdigest().lower() != expected.lower():
        raise ProfileError("profile_sha256_mismatch")
    try:
        profile = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"profile_json_invalid:{exc}") from exc
    if not isinstance(profile, dict):
        raise ProfileError("profile_json_shape_invalid")
    layout = _profile_layout(profile)
    source_checks: dict[str, bool] = {}
    refs = profile.get("source_evidence")
    if not isinstance(refs, list) or not refs:
        raise ProfileError("source_evidence_missing")
    for item in refs:
        if not isinstance(item, Mapping):
            raise ProfileError("source_evidence_item_invalid")
        source = _workspace_path(item.get("path"))
        expected_source = item.get("sha256")
        if not isinstance(expected_source, str) or len(expected_source) != 64:
            raise ProfileError("source_evidence_sha_invalid")
        actual = _sha256_file(source, SOURCE_MAX_BYTES)
        source_checks[str(item["path"])] = actual.lower() == expected_source.lower()
        if not source_checks[str(item["path"])]:
            raise ProfileError(f"source_evidence_sha_mismatch:{item['path']}")
        if item.get("bytes") is not None and _parse_int(item["bytes"], "source_evidence.bytes") != source.stat().st_size:
            raise ProfileError(f"source_evidence_size_mismatch:{item['path']}")
    guards = _profile_code_guards(profile)
    semantics = profile.get("semantics")
    if not isinstance(semantics, Mapping) or semantics.get("basis") != BASIS or semantics.get("unit") != UNIT or semantics.get("scale") != SCALE or semantics.get("period") != PERIOD:
        raise ProfileError("profile_semantics_invalid")
    enriched = dict(profile)
    enriched["_layout"] = layout
    enriched["_guards"] = guards
    enriched["_source_checks"] = source_checks
    return enriched


try:
    PROFILE: dict[str, Any] | None = _load_profile()
except ProfileError:
    PROFILE = None


def _static_contract_guard(profile: Mapping[str, Any] | None = None, reason: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "profile_id": EXPECTED_PROFILE_ID, "profile_sha256": EXPECTED_PROFILE_SHA256, "checks": {}, "source_checks": {}, "accepted_rea": {}, "unknown_conditions": []}
    try:
        active = _load_profile() if profile is None else profile
        layout = active.get("_layout") or _profile_layout(active)
        guards = active.get("_guards") or _profile_code_guards(active)
        source_checks = active.get("_source_checks", {})
        checks = {
            "profile_id": active.get("profile_id") == EXPECTED_PROFILE_ID,
            "game_version": active.get("game_version") == EXPECTED_VERSION,
            "executable_sha256": str(active.get("executable", {}).get("sha256", "")).lower() == EXPECTED_EXE_SHA256,
            "families": set(layout.get("families", {})) == set(FAMILIES),
            "code_guards": len(guards) == 6,
            "source_pins": bool(source_checks) and all(value is True for value in source_checks.values()),
            "native_call": active.get("semantics", {}).get("native_call") is False,
            "expiry_unknown": "unknown_native_expiry_unread" in str(active.get("semantics", {}).get("expiry_semantics")),
        }
        result["checks"] = checks
        result["source_checks"] = dict(source_checks)
        result["accepted_rea"] = deepcopy(active.get("accepted_rea", {}))
        failed = [name for name, value in checks.items() if value is not True]
        if failed:
            result["unknown_conditions"].append("profile_contract_failed:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except Exception as exc:
        result["unknown_conditions"].append(f"{type(exc).__name__}:{exc}")
    if reason:
        result["unknown_conditions"].append(reason)
    return result


def _file_code_guard(path: Path, profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "path": str(path), "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        for item in _profile_code_guards(profile):
            actual = _read_pe_rva_bytes(path, item["rva"], len(item["expected"]))
            result["records"][item["name"]] = {"rva": hex(item["rva"]), "expected_hex": item["expected"].hex(), "actual_hex": actual.hex()}
            result["checks"][item["name"]] = actual == item["expected"]
        failed = [name for name, value in result["checks"].items() if value is not True]
        result["status"] = "observed" if not failed else "mismatch"
        if failed:
            result["unknown_conditions"].append("file_code_guard_mismatch:" + ",".join(failed))
    except Exception as exc:
        result["unknown_conditions"].append(f"{type(exc).__name__}:{exc}")
    return result


def _runtime_code_guard(reader: Any, budget: _rel._ReadBudget, module_base: int, profile: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "module_base": _addr(module_base), "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        for item in _profile_code_guards(profile):
            address = _safe_add(module_base, item["rva"], "code_guard." + item["name"])
            actual = budget.read(reader, address, len(item["expected"]), "code_guard." + item["name"])
            record: dict[str, Any] = {
                "rva": hex(item["rva"]),
                "address": _addr(address, module_base),
                "kind": item["kind"],
                "expected_hex": item["expected"].hex(),
                "actual_hex": actual.hex(),
                "expected_sha256": hashlib.sha256(item["expected"]).hexdigest(),
                "actual_sha256": hashlib.sha256(actual).hexdigest(),
            }
            if item["kind"] == "pointer_slot":
                pointer = int.from_bytes(actual, "little", signed=False)
                target_rva = pointer - module_base if pointer >= module_base else None
                record.update({
                    "actual_pointer": hex(pointer),
                    "actual_target_rva": hex(target_rva) if target_rva is not None else None,
                    "target_rva": hex(item["target_rva"]),
                })
                ok = target_rva == item["target_rva"]
            else:
                ok = actual == item["expected"]
            result["records"][item["name"]] = record
            result["checks"][item["name"]] = ok
        failed = [name for name, value in result["checks"].items() if value is not True]
        result["status"] = "observed" if not failed else "mismatch"
        if failed:
            result["unknown_conditions"].append("runtime_code_guard_mismatch:" + ",".join(failed))
    except Exception as exc:
        result["unknown_conditions"].append(f"{type(exc).__name__}:{exc}")
    return result


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _valid_tag(tag: Any) -> bool:
    return isinstance(tag, str) and bool(re.fullmatch(r"[A-Z0-9]{3}", tag))


def _normalize_families(families: Sequence[str] | None) -> list[str]:
    if families is None:
        return list(FIELDS)
    if isinstance(families, (str, bytes)) or not isinstance(families, Sequence):
        raise ProbeError("families_must_be_sequence")
    selected = list(families)
    if not selected or len(selected) > len(FIELDS) or len(set(selected)) != len(selected):
        raise ProbeError("families_count_or_duplicate_invalid")
    if any(not isinstance(item, str) or item not in FIELDS for item in selected):
        raise ProbeError("family_not_supported")
    return selected


def _unknown_field(reason: str, family: str, *, network: bool) -> dict[str, Any]:
    return {
        "status": "unknown",
        "family": family,
        "value": [] if network else None,
        "unit": UNIT,
        "scale": SCALE,
        "period": PERIOD,
        "partial": True,
        "complete": False,
        "basis": BASIS,
        "value_origin": VALUE_ORIGIN,
        "reason": reason,
        "rows": [],
        "unknown_rows": [],
        "candidate_failures": [],
        "expires_at": {"status": "unknown", "reason": "RELATION_EXPIRY_UNREAD"},
    }


def _empty_network_field(family: str) -> dict[str, Any]:
    return {
        "status": "unknown", "family": family, "value": [], "rows": [], "unknown_rows": [], "candidate_failures": [],
        "candidate_count": 0, "unit": UNIT, "scale": SCALE, "period": PERIOD, "partial": True, "complete": False,
        "basis": BASIS, "value_origin": VALUE_ORIGIN, "expires_at": {"status": "unknown", "reason": "RELATION_EXPIRY_UNREAD"},
    }


def _base_report(installation: Path, actor: str, recipient: str | None, families: Sequence[str]) -> dict[str, Any]:
    network = recipient is None
    return {
        "schema": "information_directed_relation_network_runtime.v1",
        "probe": "information-directed-relation-network",
        "probe_version": 1,
        "probe_script": str(Path(__file__).resolve()),
        "probe_script_sha256": None,
        "read_only": True,
        "evidence_kind": "pure_runtime_observation_not_static_evidence",
        "profile": {"path": str(PROFILE_FILE), "profile_id": EXPECTED_PROFILE_ID, "sha256": EXPECTED_PROFILE_SHA256, "max_bytes": PROFILE_MAX_BYTES},
        "request": {"installation": str(installation), "actor": actor, "recipient": recipient, "families": list(families), "mode": "network" if network else "pair"},
        "target_build": {"version": EXPECTED_VERSION, "expected_exe_sha256": EXPECTED_EXE_SHA256, "image_base": "0x140000000"},
        "static_contract_guard": None,
        "file_code_guard": None,
        "runtime_code_guard": None,
        "identity": {"installation_path": str(installation), "installation_pid": None, "installation_creation_filetime": None, "installation_session_id": None, "process_path": None, "process_path_sha256": None, "process_path_sha256_matches_expected": None, "process_creation_filetime": None, "process_creation_utc": None, "process_creation_matches_installation": None, "module_path": None, "module_path_matches_process": None, "binding_verified": False},
        "module_base": None,
        "context_before": None,
        "context_after": None,
        "fields": {family: _empty_network_field(family) if network else _unknown_field("not_read", family, network=False) for family in families},
        "before": None,
        "after": None,
        "relation_row": None,
        "owner_cache": {},
        "targets": [],
        "network_stats": None,
        "doublepass": {"performed": False, "consistent": None, "mismatches": []},
        "access": {"open_process_mask": "QUERY_INFORMATION|VM_READ", "open_process_mask_hex": hex(PROCESS_ACCESS), "rpm_total_limit": NETWORK_MAX_TOTAL_RPM if network else MAX_TOTAL_RPM, "rpm_single_read_limit": MAX_SINGLE_RPM, "rpm_bytes_requested": 0, "rpm_calls": 0, "native_game_calls": False, "target_memory_writes": False, "dll_injection": False, "private_heap_scan": False, "ui_control": False, "date_advance": False, "save_or_reload": False},
        "cleanup": {"handle_close": {"status": "unknown", "success": None, "closed": False}},
        "status": "starting",
        "errors": [],
        "completed": False,
    }


def _vector_snapshot(reader: Any, budget: _rel._ReadBudget, family: str, relation_row: Mapping[str, Any], layout: Mapping[str, Any], module_base: int) -> dict[str, Any]:
    spec = layout["families"][family]
    owner = _as_int((relation_row.get("owner") or {}).get("va"))
    if owner is None or not _valid_pointer(owner):
        raise ProbeError(f"{family}.owner_invalid")
    begin_address = _safe_add(owner, spec["vector_begin_offset"], f"{family}.vector_begin", aligned=True)
    count_address = _safe_add(owner, spec["vector_count_offset"], f"{family}.vector_count")
    begin, begin_raw = budget.qword(reader, begin_address, f"{family}.vector_begin")
    count, count_raw = budget.i32(reader, count_address, f"{family}.vector_count")
    if count < 0 or count > layout["max_vector_count"]:
        raise ProbeError(f"{family}.vector_count_out_of_bound")
    if count and not _valid_pointer(begin):
        raise ProbeError(f"{family}.vector_begin_invalid")
    raw_elements = budget.read(reader, begin, count * layout["element_stride"], f"{family}.vector.elements") if count else b""
    elements: list[dict[str, Any]] = []
    for index in range(count):
        chunk = raw_elements[index * 16:(index + 1) * 16]
        address = _safe_add(begin, index * 16, f"{family}.element[{index}]")
        elements.append({"index": index, "address": _addr(address, module_base), "raw_hex": chunk.hex(), "first_dword_raw_hex": chunk[:4].hex(), "first_dword": int.from_bytes(chunk[:4], "little"), "unread_tail_raw_hex": chunk[4:].hex(), "unread_tail_semantics": "+0x4..+0xf_unread_by_direct_leaf"})
    return {
        "raw": {"owner_pointer": _addr(owner, module_base), "owner_pointer_raw_hex": owner.to_bytes(8, "little").hex(), "vector_begin": _field(begin_address, begin_raw, begin, module_base), "vector_count": _field(count_address, count_raw, count, module_base), "element_stride": layout["element_stride"], "elements": elements},
        "proof": {"family": family, "predicate_rva": hex(spec["predicate_rva"]), "leaf_va": hex(module_base + spec["predicate_rva"]), "unread_element_bytes": "+0x4..+0xf"},
    }


def _project_family(reader: Any, budget: _rel._ReadBudget, family: str, cached: Mapping[str, Any], target_fullref: int, layout: Mapping[str, Any], module_base: int, *, element_index: Mapping[int, list[dict[str, Any]]] | None = None) -> tuple[bool, dict[str, Any]]:
    raw = cached.get("raw")
    if not isinstance(raw, Mapping) or not isinstance(raw.get("elements"), list):
        raise ProbeError("owner_vector_cache_shape_invalid")
    expected = _signed_i16(_slot_from_fullref(target_fullref))
    matches = (element_index.get(expected & 0xFFFFFFFF, []) if element_index is not None else
               [element for element in raw["elements"] if isinstance(element, Mapping) and element.get("first_dword") == (expected & 0xFFFFFFFF)])
    proof = _copy_evidence(dict(cached.get("proof", {})))
    proof.update({"comparison_slot_signed_i16": expected, "matching_element_indices": [int(item["index"]) for item in matches]})
    if family == "military_access":
        proof["native_leaf_al"] = bool(matches)
        return bool(matches), proof
    proof["first_matching_element_index"] = int(matches[0]["index"]) if matches else None
    if not matches:
        proof["native_leaf_al"] = False
        return False, proof
    first = matches[0]
    element_raw = bytes.fromhex(str(first["raw_hex"]))
    pointer_raw = element_raw[8:16]
    record_pointer = int.from_bytes(pointer_raw, "little")
    proof.update({"record_pointer": _addr(record_pointer, module_base), "record_pointer_raw_hex": pointer_raw.hex()})
    if record_pointer == 0:
        proof.update({"record_status": "null", "native_leaf_al": False})
        return False, proof
    if not _valid_pointer(record_pointer):
        raise ProbeError("guarantee_record_pointer_invalid")
    record_address = _safe_add(record_pointer, layout["families"][family]["record_fullref_offset"], "guarantee.record_fullref")
    record_fullref, record_raw = budget.qword(reader, record_address, "guarantee.record_fullref")
    record_slot = _signed_i16(_slot_from_fullref(record_fullref))
    proof.update({"record_fullref": _field(record_address, record_raw, record_fullref, module_base), "record_slot_signed_i16": record_slot, "record_status": "observed", "native_leaf_al": record_slot == expected})
    return record_slot == expected, proof


def _family_field_pair(family: str, value: bool, raw: Mapping[str, Any], proof: Mapping[str, Any], relation_row: Mapping[str, Any]) -> dict[str, Any]:
    return {"status": "known", "family": family, "value": bool(value), "unit": UNIT, "scale": SCALE, "period": PERIOD, "partial": True, "complete": False, "basis": BASIS, "value_origin": VALUE_ORIGIN, "raw": _copy_evidence(dict(raw)), "proof": _copy_evidence(dict(proof)), "relation_row": _copy_evidence(dict(relation_row)), "expires_at": {"status": "unknown", "reason": "RELATION_EXPIRY_UNREAD"}}


def _cache_key(row: Mapping[str, Any], family: str) -> str:
    owner = _as_int((row.get("owner") or {}).get("va"))
    if owner is None:
        raise ProbeError("relation_row_owner_pointer_invalid")
    return f"{owner:#x}:{family}"


def _pair_pass(reader: Any, budget: _rel._ReadBudget, module_base: int, actor: str, recipient: str, families: Sequence[str], profile: Mapping[str, Any]) -> dict[str, Any]:
    layout = _profile_layout(profile)
    result: dict[str, Any] = {"status": "unknown", "runtime_code_guard": None, "context": None, "relation_row": None, "fields": {family: _unknown_field("not_read", family, network=False) for family in families}, "owner_cache": {}, "read_budget": None, "read_log": [], "unknown_conditions": [], "complete": False}
    start = len(budget.log)
    try:
        guard = _runtime_code_guard(reader, budget, module_base, profile)
        result["runtime_code_guard"] = guard
        if guard.get("status") != "observed":
            result["unknown_conditions"].append("runtime_code_guard_not_observed")
            return result
        context = _context_snapshot(reader, budget, module_base, actor, recipient, layout)
        result["context"] = context
        if context.get("status") != "observed":
            result["unknown_conditions"].extend(context.get("unknown_conditions", []))
            return result
        row = _relation_row(reader, budget, context["actor"], context["recipient"], layout, module_base)
        result["relation_row"] = row
        target_fullref = int(context["recipient"]["fullref"]["value"])
        for family in families:
            try:
                cached = _vector_snapshot(reader, budget, family, row, layout, module_base)
                key = _cache_key(row, family)
                result["owner_cache"][key] = cached
                value, proof = _project_family(reader, budget, family, cached, target_fullref, layout, module_base)
                raw = dict(cached["raw"])
                raw["recipient_fullref"] = row["recipient_fullref"]
                raw["recipient_slot_signed_i16"] = _signed_i16(_slot_from_fullref(target_fullref))
                result["fields"][family] = _family_field_pair(family, value, raw, proof, row)
            except Exception as exc:
                result["fields"][family] = _unknown_field(f"{type(exc).__name__}:{exc}", family, network=False)
        result["status"] = "observed"
        result["complete"] = all(field.get("status") == "known" for field in result["fields"].values())
    except Exception as exc:
        result["unknown_conditions"].append(f"{type(exc).__name__}:{exc}")
    finally:
        result["read_budget"] = budget.snapshot()
        result["read_log"] = _copy_evidence(budget.log[start:])
    return result


def _target_entries(context: Mapping[str, Any]) -> list[dict[str, Any]]:
    scan = context.get("country_scan")
    actor = context.get("actor")
    if not isinstance(scan, Mapping) or not isinstance(actor, Mapping):
        raise ProbeError("network_country_scan_missing")
    actor_index = _as_int(actor.get("index"))
    if actor_index is None:
        raise ProbeError("network_actor_index_missing")
    result: list[dict[str, Any]] = []
    for entry in scan.get("entries", []):
        if not isinstance(entry, Mapping) or entry.get("status") in {"empty", "null_sentinel", "unknown"} or entry.get("index") == actor_index:
            continue
        pointer = entry.get("pointer")
        fullref = (entry.get("fullref") or {}).get("value")
        tag = entry.get("tag")
        slot = entry.get("slot")
        if not isinstance(pointer, Mapping) or _as_int(pointer.get("va")) is None or not isinstance(fullref, int) or not _valid_tag(tag) or not isinstance(slot, int):
            continue
        raw_hex = (entry.get("fullref") or {}).get("raw_hex")
        result.append({"index": int(entry["index"]), "country": tag, "country_pointer": _copy_evidence(pointer), "fullref": fullref, "fullref_hex": raw_hex or fullref.to_bytes(8, "little").hex(), "slot": slot})
    if len(result) > MAX_COUNTRY_ENTRIES:
        raise ProbeError("network_candidate_count_out_of_bound")
    return result


def _direction_row(target: Mapping[str, Any], family: str, operand: str, relation_row: Mapping[str, Any] | None) -> dict[str, Any]:
    layout = PROFILE["_layout"] if isinstance(PROFILE, Mapping) and PROFILE.get("_layout") else _profile_layout()
    direction = layout["families"][family]["direction_map"][operand]
    return {"index": target["index"], "country": target["country"], "fullref_hex": target["fullref_hex"], "fullref_raw_hex": target["fullref_hex"], "slot": target["slot"], "direction": direction, "operand_direction": operand, "relation_row": _copy_evidence(relation_row), "predicate_cache_key": None, "status": "unknown", "active": None}


def _network_pass(reader: Any, budget: _rel._ReadBudget, module_base: int, actor: str, families: Sequence[str], profile: Mapping[str, Any]) -> dict[str, Any]:
    layout = _profile_layout(profile)
    result: dict[str, Any] = {"status": "unknown", "runtime_code_guard": None, "context": None, "targets": [], "owner_cache": {}, "candidate_failures": [], "fields": {family: _empty_network_field(family) for family in families}, "network_stats": {"candidate_count": 0, "known_rows": {family: 0 for family in families}, "unknown_rows": {family: 0 for family in families}}, "read_budget": None, "read_log": [], "unknown_conditions": [], "complete": False}
    start = len(budget.log)
    try:
        guard = _runtime_code_guard(reader, budget, module_base, profile)
        result["runtime_code_guard"] = guard
        if guard.get("status") != "observed":
            result["unknown_conditions"].append("runtime_code_guard_not_observed")
            return result
        context = _network_context_snapshot(reader, budget, module_base, actor, layout)
        result["context"] = context
        if context.get("status") != "observed" or not isinstance(context.get("actor"), Mapping):
            result["unknown_conditions"].extend(context.get("unknown_conditions", []))
            return result
        result["candidate_failures"] = _copy_evidence(context.get("country_scan", {}).get("candidate_failures", []))
        targets = _target_entries(context)
        result["targets"] = _copy_evidence(targets)
        result["network_stats"]["candidate_count"] = len(targets)
        actor_entry = context["actor"]
        actor_fullref = int(actor_entry["fullref"]["value"])
        for target in targets:
            target["operands"] = {}
            target_entry = {"pointer": target["country_pointer"], "fullref": {"value": target["fullref"], "raw_hex": target["fullref_hex"]}}
            actor_target_entry = {"pointer": actor_entry["pointer"], "fullref": {"value": actor_fullref, "raw_hex": actor_entry["fullref"]["raw_hex"]}}
            for operand, source_entry, recipient_entry in (("forward", actor_entry, target_entry), ("reverse", target_entry, actor_target_entry)):
                try:
                    target["operands"][operand] = {"status": "observed", "relation_row": _relation_row(reader, budget, source_entry, recipient_entry, layout, module_base)}
                except Exception as exc:
                    target["operands"][operand] = {"status": "unknown", "reason": f"{type(exc).__name__}:{exc}", "relation_row": None}
        cache_failures: dict[str, str] = {}
        element_indices: dict[str, dict[int, list[dict[str, Any]]]] = {}
        for family in families:
            rows: list[dict[str, Any]] = []
            active_rows: list[dict[str, Any]] = []
            unknown_rows: list[dict[str, Any]] = []
            for target in targets:
                for operand in ("forward", "reverse"):
                    operand_info = target["operands"].get(operand, {})
                    row = _direction_row(target, family, operand, operand_info.get("relation_row"))
                    try:
                        if operand_info.get("status") != "observed":
                            raise ProbeError(str(operand_info.get("reason", "relation_row_unknown")))
                        relation_row = operand_info["relation_row"]
                        key = _cache_key(relation_row, family)
                        row["predicate_cache_key"] = key
                        if key in cache_failures:
                            raise ProbeError(cache_failures[key])
                        cached = result["owner_cache"].get(key)
                        if cached is None:
                            try:
                                cached = _vector_snapshot(reader, budget, family, relation_row, layout, module_base)
                            except Exception as exc:
                                cache_failures[key] = f"{type(exc).__name__}:{exc}"
                                result["owner_cache"][key] = {"status": "unknown", "reason": cache_failures[key]}
                                raise
                            result["owner_cache"][key] = cached
                            element_indices[key] = _index_elements(cached["raw"]["elements"])
                        target_fullref = target["fullref"] if operand == "forward" else actor_fullref
                        value, proof = _project_family(reader, budget, family, cached, target_fullref, layout, module_base, element_index=element_indices[key])
                        row.update({"status": "known", "active": bool(value), "predicate": proof})
                        result["network_stats"]["known_rows"][family] += 1
                        if value:
                            active_rows.append({"country": target["country"], "fullref_hex": target["fullref_hex"], "slot": target["slot"], "active": True, "direction": row["direction"], "operand_direction": operand})
                    except Exception as exc:
                        row.update({"status": "unknown", "active": None, "reason": f"{type(exc).__name__}:{exc}"})
                        unknown_rows.append({"index": target["index"], "country": target["country"], "fullref_hex": target["fullref_hex"], "fullref_raw_hex": target["fullref_hex"], "slot": target["slot"], "direction": row["direction"], "operand_direction": operand, "reason": row["reason"]})
                        result["network_stats"]["unknown_rows"][family] += 1
                    rows.append(row)
            field_status = "known" if not unknown_rows and not result["candidate_failures"] else "partial"
            result["fields"][family] = {"status": field_status, "family": family, "value": active_rows, "rows": rows, "unknown_rows": unknown_rows, "candidate_failures": _copy_evidence(result["candidate_failures"]), "candidate_count": len(targets), "direction_count": 2, "unit": UNIT, "scale": SCALE, "period": PERIOD, "partial": True, "complete": False, "basis": BASIS, "value_origin": VALUE_ORIGIN, "expires_at": {"status": "unknown", "reason": "RELATION_EXPIRY_UNREAD"}}
        result["status"] = "observed"
        result["complete"] = all(field.get("status") == "known" for field in result["fields"].values())
    except Exception as exc:
        result["unknown_conditions"].append(f"{type(exc).__name__}:{exc}")
    finally:
        result["read_budget"] = budget.snapshot()
        result["read_log"] = _copy_evidence(budget.log[start:])
    return result


def _retract(report: dict[str, Any], reason: str) -> None:
    network = report.get("request", {}).get("recipient") is None
    families = report.get("request", {}).get("families", [])
    report["fields"] = {family: _unknown_field(reason, family, network=network) for family in families}
    for key in ("before", "after"):
        item = report.get(key)
        if isinstance(item, Mapping):
            item["fields"] = {family: _unknown_field(reason, family, network=network) for family in families}
            item["complete"] = False
    report["owner_cache"] = {}
    report["targets"] = []
    report["network_stats"] = None


def _invalid_request_report(installation: Path, actor: str, recipient: str | None, families: Sequence[str], status: str, error: str) -> dict[str, Any]:
    report = _base_report(installation, actor, recipient, families)
    report["status"] = status
    report["errors"].append({"stage": "request", "status": "unknown", "error": error})
    report["cleanup"]["handle_close"] = _close_process_handle(None, None)
    report["completed"] = True
    return report


def capture(installation: Path, actor: str = EXPECTED_COUNTRY, recipient: str | None = None, families: Sequence[str] | None = None) -> dict[str, Any]:
    installation = Path(installation)
    try:
        selected = _normalize_families(families)
    except ProbeError as exc:
        return _invalid_request_report(installation, actor, recipient, list(FIELDS) if families is None else [], "invalid_request", str(exc))
    if not _valid_tag(actor) or (recipient is not None and (not _valid_tag(recipient) or recipient == actor)):
        return _invalid_request_report(installation, actor, recipient, selected, "invalid_request", "actor_or_recipient_tag_invalid")
    report = _base_report(installation, actor, recipient, selected)
    try:
        report["probe_script_sha256"] = _sha256_file(Path(__file__).resolve())
        profile = _load_profile()
        report["static_contract_guard"] = _static_contract_guard(profile)
        if report["static_contract_guard"].get("status") != "observed":
            report["status"] = "static_contract_mismatch"
            report["cleanup"]["handle_close"] = _close_process_handle(None, None)
            report["completed"] = True
            return report
        kernel = None
        handle = None
        reader = None
        try:
            document = _load_installation(installation)
            kernel = _configure_kernel()
            handle = kernel.OpenProcess(PROCESS_ACCESS, False, int(document["pid"]))
            if not handle:
                raise ProbeError("OpenProcess_failed")
            module_base = _capture_identity(report, document, kernel, handle)
            if report["identity"].get("binding_verified") is not True or not _valid_pointer(module_base):
                raise ProbeError("identity_binding_not_verified")
            report["module_base"] = _addr(module_base)
            process_path = Path(report["identity"]["process_path"])
            report["file_code_guard"] = _file_code_guard(process_path, profile)
            if report["file_code_guard"].get("status") != "observed":
                report["status"] = "file_code_mismatch"
            else:
                network = recipient is None
                reader = NetworkAddressBoundedRPM(kernel, handle, module_base) if network else AddressBoundedRPM(kernel, handle, module_base)
                budget = _rel._ReadBudget(NETWORK_MAX_TOTAL_RPM if network else MAX_TOTAL_RPM)
                first = _network_pass(reader, budget, module_base, actor, selected, profile) if network else _pair_pass(reader, budget, module_base, actor, recipient, selected, profile)
                report["before"] = first
                report["context_before"] = _copy_evidence(first.get("context"))
                if first.get("status") != "observed":
                    report["status"] = "unknown"
                else:
                    second = _network_pass(reader, budget, module_base, actor, selected, profile) if network else _pair_pass(reader, budget, module_base, actor, recipient, selected, profile)
                    report["after"] = second
                    report["context_after"] = _copy_evidence(second.get("context"))
                    report["doublepass"]["performed"] = True
                    if second.get("status") != "observed":
                        report["status"] = "doublepass_mismatch"
                        report["doublepass"]["consistent"] = False
                        report["doublepass"]["mismatches"] = ["$.after.status"]
                    else:
                        mismatches = _diff_paths(_without_volatile(first), _without_volatile(second))
                        if not _rel._observation_dates_match(first.get("context"), second.get("context")):
                            mismatches.append("$.context.game_date")
                        report["doublepass"]["mismatches"] = mismatches[:256]
                        report["doublepass"]["consistent"] = not mismatches
                        report["status"] = "observed" if not mismatches else "doublepass_mismatch"
                        if not mismatches:
                            report["fields"] = _copy_evidence(second.get("fields", {}))
                            report["owner_cache"] = _copy_evidence(second.get("owner_cache", {}))
                            report["targets"] = _copy_evidence(second.get("targets", []))
                            report["network_stats"] = _copy_evidence(second.get("network_stats"))
                            report["relation_row"] = _copy_evidence(second.get("relation_row"))
                    before_guard = (report.get("before") or {}).get("runtime_code_guard", {})
                    after_guard = (report.get("after") or {}).get("runtime_code_guard", {})
                    report["runtime_code_guard"] = {"status": "observed" if before_guard.get("status") == "observed" and after_guard.get("status") == "observed" else "unknown", "passes": [before_guard, after_guard]}
        finally:
            if reader is not None:
                report["access"]["rpm_bytes_requested"] = getattr(reader, "bytes_requested", 0)
                report["access"]["rpm_calls"] = getattr(reader, "calls", 0)
            cleanup = _close_process_handle(kernel, handle)
            report["cleanup"]["handle_close"] = cleanup
        report["completed"] = report.get("status") == "observed" and report["cleanup"]["handle_close"].get("closed") is True
        if not report["completed"]:
            _retract(report, "observation_not_completed")
    except Exception as exc:
        report["status"] = "error"
        report["errors"].append({"stage": "capture", "status": "unknown", "error": f"{type(exc).__name__}:{exc}"})
        report["cleanup"]["handle_close"] = _close_process_handle(None, None)
        report["completed"] = False
        _retract(report, "observation_not_completed")
    return report


def _validate_budget_accounting(report: Mapping[str, Any]) -> bool:
    before, after = report.get("before"), report.get("after")
    if not isinstance(before, Mapping) or not isinstance(after, Mapping):
        return False
    first_log, second_log = before.get("read_log"), after.get("read_log")
    first_budget, second_budget = before.get("read_budget"), after.get("read_budget")
    if not isinstance(first_log, list) or not isinstance(second_log, list) or not isinstance(first_budget, Mapping) or not isinstance(second_budget, Mapping):
        return False
    def accounted(log: list[Any]) -> tuple[int, int] | None:
        total = 0
        for item in log:
            if not isinstance(item, Mapping) or not isinstance(item.get("size"), int) or item["size"] <= 0:
                return None
            total += item["size"]
        return total, len(log)
    first = accounted(first_log)
    second = accounted(second_log)
    if first is None or second is None:
        return False
    first_bytes, first_calls = first_budget.get("bytes_reserved"), first_budget.get("calls_reserved")
    second_bytes, second_calls = second_budget.get("bytes_reserved"), second_budget.get("calls_reserved")
    if (first_bytes, first_calls) != first or not all(isinstance(item, int) and item >= 0 for item in (second_bytes, second_calls)):
        return False
    if (second_bytes - first_bytes, second_calls - first_calls) != second:
        return False
    access = report.get("access", {})
    return access.get("rpm_bytes_requested") == second_bytes and access.get("rpm_calls") == second_calls


def _validate_runtime_code_guard(guard: Mapping[str, Any], module_base: int, profile: Mapping[str, Any]) -> bool:
    """Validate the captured runtime guards, including ASLR pointer slots."""
    if not isinstance(guard, Mapping) or guard.get("status") != "observed":
        return False
    base_field = guard.get("module_base")
    if not isinstance(base_field, Mapping) or _as_int(base_field.get("va")) != module_base:
        return False
    guards = _profile_code_guards(profile)
    checks = guard.get("checks")
    records = guard.get("records")
    if (not isinstance(checks, Mapping) or set(checks) != {item["name"] for item in guards}
            or any(value is not True for value in checks.values())
            or not isinstance(records, Mapping) or set(records) != {item["name"] for item in guards}):
        return False
    for item in guards:
        got = records.get(item["name"])
        if not isinstance(got, Mapping):
            return False
        if (got.get("rva") != hex(item["rva"])
                or got.get("address") != _addr(module_base + item["rva"], module_base)
                or got.get("kind") != item["kind"]
                or got.get("expected_hex") != item["expected"].hex()
                or got.get("expected_sha256") != hashlib.sha256(item["expected"]).hexdigest()):
            return False
        actual_hex = got.get("actual_hex")
        if not isinstance(actual_hex, str):
            return False
        try:
            actual = bytes.fromhex(actual_hex)
        except ValueError:
            return False
        if len(actual) != len(item["expected"]) or got.get("actual_sha256") != hashlib.sha256(actual).hexdigest():
            return False
        if item["kind"] == "pointer_slot":
            pointer = int.from_bytes(actual, "little", signed=False)
            target_rva = pointer - module_base if pointer >= module_base else None
            if (got.get("actual_pointer") != hex(pointer)
                    or got.get("actual_target_rva") != (hex(target_rva) if target_rva is not None else None)
                    or got.get("target_rva") != hex(item["target_rva"])
                    or target_rva != item["target_rva"]):
                return False
        elif actual != item["expected"] or got.get("actual_hex") != item["expected"].hex():
            return False
    return True


def _validate_relation_row(row: Mapping[str, Any], source_pointer: int, expected_fullref: int, layout: Mapping[str, Any]) -> bool:
    table = row.get("relation_table")
    table_ptr = _as_int(table.get("value")) if isinstance(table, Mapping) else None
    table_addr = _as_int((table.get("address") or {}).get("va")) if isinstance(table, Mapping) else None
    row_addr = _as_int((row.get("address") or {}).get("va"))
    row_owner = _as_int((row.get("owner") or {}).get("va"))
    row_fullref = _as_int((row.get("recipient_fullref") or {}).get("value"))
    try:
        expected_row = table_ptr + _slot_from_fullref(expected_fullref) * layout["relation_row_stride"] if table_ptr is not None else None
        return (_valid_pointer(source_pointer) and table_addr == source_pointer + layout["relation_table_offset"] and table_ptr is not None and _valid_pointer(table_ptr) and table.get("raw_hex") == table_ptr.to_bytes(8, "little").hex() and row_addr == expected_row and row_fullref == expected_fullref and (row.get("recipient_fullref") or {}).get("raw_hex") == expected_fullref.to_bytes(8, "little").hex() and row_owner is not None and _valid_pointer(row_owner) and row.get("owner_raw_hex") == row_owner.to_bytes(8, "little").hex())
    except (OverflowError, TypeError):
        return False


def _validate_elements(raw: Mapping[str, Any], owner: int, family: str, layout: Mapping[str, Any]) -> bool:
    begin_field, count_field = raw.get("vector_begin"), raw.get("vector_count")
    begin = _as_int(begin_field.get("value")) if isinstance(begin_field, Mapping) else None
    count = _as_int(count_field.get("value")) if isinstance(count_field, Mapping) else None
    elements = raw.get("elements")
    if begin is None or count is None or count < 0 or count > MAX_VECTOR_COUNT or not isinstance(elements, list) or len(elements) != count:
        return False
    spec = layout["families"][family]
    if _as_int((begin_field or {}).get("address", {}).get("va")) != owner + spec["vector_begin_offset"] or _as_int((count_field or {}).get("address", {}).get("va")) != owner + spec["vector_count_offset"] or begin_field.get("raw_hex") != begin.to_bytes(8, "little").hex() or count_field.get("raw_hex") != count.to_bytes(4, "little", signed=True).hex():
        return False
    for index, item in enumerate(elements):
        if not isinstance(item, Mapping) or item.get("index") != index or not isinstance(item.get("raw_hex"), str) or len(item["raw_hex"]) != 32:
            return False
        try:
            chunk = bytes.fromhex(item["raw_hex"])
        except ValueError:
            return False
        if (_as_int((item.get("address") or {}).get("va")) != begin + index * layout["element_stride"] or item.get("first_dword") != int.from_bytes(chunk[:4], "little") or item.get("first_dword_raw_hex") != chunk[:4].hex() or item.get("unread_tail_raw_hex") != chunk[4:].hex()):
            return False
    return True


def _validate_predicate(family: str, active: bool, proof: Mapping[str, Any], raw: Mapping[str, Any], target_fullref: int, layout: Mapping[str, Any], *, element_index: Mapping[int, list[dict[str, Any]]] | None = None) -> bool:
    owner = _as_int((raw.get("owner_pointer") or {}).get("va"))
    if owner is None or not _valid_pointer(owner) or raw.get("owner_pointer_raw_hex") != owner.to_bytes(8, "little").hex() or (element_index is None and not _validate_elements(raw, owner, family, layout)):
        return False
    expected = _signed_i16(_slot_from_fullref(target_fullref))
    matches = (element_index.get(expected & 0xFFFFFFFF, []) if element_index is not None else
               [item for item in raw["elements"] if item.get("first_dword") == (expected & 0xFFFFFFFF)])
    if proof.get("comparison_slot_signed_i16") != expected:
        return False
    if family == "military_access":
        return proof.get("matching_element_indices") == [int(item["index"]) for item in matches] and active is bool(matches)
    if proof.get("first_matching_element_index") != (int(matches[0]["index"]) if matches else None):
        return False
    if not matches:
        return active is False and proof.get("native_leaf_al") is False
    first_raw = bytes.fromhex(matches[0]["raw_hex"])
    pointer_raw = first_raw[8:16]
    pointer = int.from_bytes(pointer_raw, "little")
    if proof.get("record_pointer_raw_hex") != pointer_raw.hex():
        return False
    if pointer == 0:
        return active is False and proof.get("record_status") == "null" and proof.get("native_leaf_al") is False
    if not _valid_pointer(pointer):
        return False
    record = proof.get("record_fullref")
    record_value = _as_int(record.get("value")) if isinstance(record, Mapping) else None
    record_address = _as_int((record.get("address") or {}).get("va")) if isinstance(record, Mapping) else None
    if record_value is None or record_address != pointer + layout["families"][family]["record_fullref_offset"] or record.get("raw_hex") != record_value.to_bytes(8, "little").hex():
        return False
    record_slot = _signed_i16(_slot_from_fullref(record_value))
    return proof.get("record_slot_signed_i16") == record_slot and proof.get("record_status") == "observed" and active is (record_slot == expected)


def _validate_cache(cache: Mapping[str, Any], key: str, family: str, layout: Mapping[str, Any], module_base: int | None = None) -> bool:
    if not isinstance(cache, Mapping):
        return False
    item = cache.get(key)
    if not isinstance(item, Mapping):
        return False
    if item.get("status") == "unknown":
        return isinstance(item.get("reason"), str)
    raw = item.get("raw")
    proof = item.get("proof")
    owner_text, _, key_family = key.partition(":")
    try:
        owner = int(owner_text, 16)
    except ValueError:
        return False
    if key_family != family or not isinstance(raw, Mapping) or not isinstance(proof, Mapping) or _as_int((raw.get("owner_pointer") or {}).get("va")) != owner or proof.get("predicate_rva") != hex(layout["families"][family]["predicate_rva"]):
        return False
    return _validate_elements(raw, owner, family, layout)


def _validate_pair(report: Mapping[str, Any], layout: Mapping[str, Any]) -> bool:
    context = report.get("context_after")
    fields = report.get("fields")
    row = report.get("relation_row")
    if not isinstance(context, Mapping) or not isinstance(fields, Mapping) or not isinstance(row, Mapping):
        return False
    actor = context.get("actor")
    recipient = context.get("recipient")
    if not isinstance(actor, Mapping) or not isinstance(recipient, Mapping):
        return False
    actor_ptr = _as_int((actor.get("pointer") or {}).get("va"))
    recipient_fullref = _as_int((recipient.get("fullref") or {}).get("value"))
    if actor_ptr is None or recipient_fullref is None or not _validate_relation_row(row, actor_ptr, recipient_fullref, layout):
        return False
    cache = report.get("owner_cache")
    for family in report.get("request", {}).get("families", []):
        field = fields.get(family)
        if not isinstance(field, Mapping):
            return False
        if field.get("status") == "unknown":
            if not isinstance(field.get("reason"), str) or field.get("value") is not None:
                return False
            continue
        if field.get("status") != "known" or field.get("family") != family or field.get("value") not in (True, False):
            return False
        field_row = field.get("relation_row")
        raw, proof = field.get("raw"), field.get("proof")
        if not isinstance(field_row, Mapping) or not isinstance(raw, Mapping) or not isinstance(proof, Mapping) or field_row != row:
            return False
        key = _cache_key(row, family)
        if not _validate_cache(cache, key, family, layout):
            return False
        if raw.get("owner_pointer") != cache[key]["raw"].get("owner_pointer") or not _validate_predicate(family, bool(field["value"]), proof, raw, recipient_fullref, layout):
            return False
    return True


def _validate_network(report: Mapping[str, Any], layout: Mapping[str, Any]) -> bool:
    context = report.get("context_after")
    fields = report.get("fields")
    cache = report.get("owner_cache")
    if not isinstance(context, Mapping) or not isinstance(fields, Mapping) or not isinstance(cache, Mapping) or not isinstance(context.get("actor"), Mapping):
        return False
    actor = context["actor"]
    actor_ptr = _as_int((actor.get("pointer") or {}).get("va"))
    actor_fullref = _as_int((actor.get("fullref") or {}).get("value"))
    if actor_ptr is None or actor_fullref is None:
        return False
    scan = context.get("country_scan")
    if not isinstance(scan, Mapping):
        return False
    expected_targets = _target_entries(context)
    expected_by_key = {(item["index"], item["country"], item["fullref_hex"], item["slot"]): item for item in expected_targets}
    candidate_failures = scan.get("candidate_failures", [])
    validated_elements: dict[str, dict[int, list[dict[str, Any]]]] = {}
    for family in report.get("request", {}).get("families", []):
        field = fields.get(family)
        if not isinstance(field, Mapping) or field.get("family") != family or not isinstance(field.get("rows"), list) or not isinstance(field.get("unknown_rows"), list) or field.get("candidate_failures") != candidate_failures:
            return False
        rows = field["rows"]
        if len(rows) != len(expected_targets) * 2 or field.get("candidate_count") != len(expected_targets):
            return False
        expected_status = "known" if not field["unknown_rows"] and not candidate_failures else "partial"
        if field.get("status") != expected_status:
            return False
        seen: set[tuple[Any, ...]] = set()
        active: list[dict[str, Any]] = []
        unknown: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, Mapping) or row.get("operand_direction") not in {"forward", "reverse"} or row.get("direction") != layout["families"][family]["direction_map"].get(row.get("operand_direction")):
                return False
            target_key = (row.get("index"), row.get("country"), row.get("fullref_hex"), row.get("slot"))
            if target_key not in expected_by_key or (target_key, row.get("operand_direction")) in seen:
                return False
            seen.add((target_key, row.get("operand_direction")))
            target = expected_by_key[target_key]
            relation_row = row.get("relation_row")
            if row.get("operand_direction") == "forward":
                source_ptr = actor_ptr
                operand_fullref = target["fullref"]
            else:
                source_ptr = _as_int((target["country_pointer"] or {}).get("va"))
                operand_fullref = actor_fullref
            if source_ptr is None:
                return False
            if row.get("status") == "unknown":
                if row.get("active") is not None or not isinstance(row.get("reason"), str):
                    return False
                if relation_row is not None and not _validate_relation_row(relation_row, source_ptr, operand_fullref, layout):
                    return False
                unknown.append({"index": target["index"], "country": target["country"], "fullref_hex": target["fullref_hex"], "fullref_raw_hex": target["fullref_hex"], "slot": target["slot"], "direction": row["direction"], "operand_direction": row["operand_direction"], "reason": row["reason"]})
                continue
            if row.get("status") != "known" or row.get("active") not in (True, False) or not isinstance(relation_row, Mapping) or not _validate_relation_row(relation_row, source_ptr, operand_fullref, layout):
                return False
            owner = _as_int((relation_row.get("owner") or {}).get("va"))
            key = row.get("predicate_cache_key")
            expected_key = f"{owner:#x}:{family}" if owner is not None else None
            if key != expected_key or expected_key is None:
                return False
            if expected_key not in validated_elements:
                if not _validate_cache(cache, expected_key, family, layout):
                    return False
                validated_elements[expected_key] = _index_elements(cache[expected_key]["raw"]["elements"])
            cached_raw = cache[expected_key].get("raw") if isinstance(cache.get(expected_key), Mapping) else None
            proof = row.get("predicate")
            if not isinstance(cached_raw, Mapping) or not isinstance(proof, Mapping) or not _validate_predicate(family, bool(row["active"]), proof, cached_raw, operand_fullref, layout, element_index=validated_elements[expected_key]):
                return False
            if row["active"]:
                active.append({"country": target["country"], "fullref_hex": target["fullref_hex"], "slot": target["slot"], "active": True, "direction": row["direction"], "operand_direction": row["operand_direction"]})
        expected_keys = {(key, operand) for key in expected_by_key for operand in ("forward", "reverse")}
        if seen != expected_keys or field.get("unknown_rows") != unknown or field.get("value") != active:
            return False
    expected_cache_keys = {row.get("predicate_cache_key") for family in report.get("request", {}).get("families", []) for row in fields[family].get("rows", []) if isinstance(row, Mapping) and row.get("predicate_cache_key") is not None}
    if set(cache) != expected_cache_keys:
        return False
    return True


def validate_capture(report: Mapping[str, Any], context: Mapping[str, Any] | None = None, creation_filetime: int | None = None, actor: str | None = None, recipient: str | None = None) -> bool:
    if not isinstance(report, Mapping):
        return False
    try:
        if report.get("schema") != "information_directed_relation_network_runtime.v1" or report.get("status") != "observed" or report.get("completed") is not True:
            return False
        cleanup = report.get("cleanup", {}).get("handle_close", {})
        access = report.get("access", {})
        if cleanup.get("closed") is not True or access.get("native_game_calls") is not False or access.get("target_memory_writes") is not False:
            return False
        if report.get("profile", {}).get("profile_id") != EXPECTED_PROFILE_ID or report.get("profile", {}).get("sha256") != EXPECTED_PROFILE_SHA256 or report.get("target_build", {}).get("expected_exe_sha256", "").lower() != EXPECTED_EXE_SHA256:
            return False
        if report.get("target_build", {}).get("version") != EXPECTED_VERSION or report.get("static_contract_guard", {}).get("status") != "observed" or report.get("file_code_guard", {}).get("status") != "observed" or report.get("runtime_code_guard", {}).get("status") != "observed":
            return False
        identity = report.get("identity")
        if not isinstance(identity, Mapping) or identity.get("binding_verified") is not True or identity.get("process_path_sha256_matches_expected") is not True or identity.get("process_creation_matches_installation") is not True:
            return False
        if creation_filetime is not None and identity.get("process_creation_filetime") != creation_filetime:
            return False
        request = report.get("request")
        if not isinstance(request, Mapping) or not _valid_tag(request.get("actor")) or request.get("recipient") == request.get("actor"):
            return False
        if actor is not None and request.get("actor") != actor:
            return False
        if recipient is not None and request.get("recipient") != recipient:
            return False
        if request.get("recipient") is not None and not _valid_tag(request.get("recipient")):
            return False
        selected = _normalize_families(request.get("families"))
        if list(request.get("families", [])) != selected or set(report.get("fields", {})) != set(selected) or report.get("request", {}).get("mode") != ("network" if request.get("recipient") is None else "pair") or report.get("doublepass", {}).get("performed") is not True or report.get("doublepass", {}).get("consistent") is not True:
            return False
        if not _validate_budget_accounting(report):
            return False
        before, after = report.get("before"), report.get("after")
        if (not isinstance(before, Mapping) or not isinstance(after, Mapping)
                or _without_volatile(before) != _without_volatile(after)
                or not _rel._observation_dates_match(before.get("context"), after.get("context"))):
            return False
        if report.get("context_before") != before.get("context") or report.get("context_after") != after.get("context") or report.get("fields") != after.get("fields") or report.get("owner_cache") != after.get("owner_cache"):
            return False
        if request.get("recipient") is None and report.get("network_stats") != after.get("network_stats"):
            return False
        context_after = report.get("context_after")
        if not isinstance(context_after, Mapping) or context_after.get("status") != "observed":
            return False
        if context is not None:
            if not isinstance(context, Mapping):
                return False
            for key in ("session_id", "process_creation_filetime", "game_date", "actor", "recipient"):
                if key not in context:
                    continue
                if key == "game_date":
                    if not _rel._observation_dates_match(before.get("context"), after.get("context"), context[key], anchor_present=True):
                        return False
                    continue
                observed = identity.get("installation_session_id") if key == "session_id" else identity.get("process_creation_filetime") if key == "process_creation_filetime" else context_after.get("game_date", {}).get("value") if key == "game_date" else request.get(key)
                if observed != context[key]:
                    return False
        profile = _load_profile()
        module_base = _as_int((report.get("module_base") or {}).get("va")) if isinstance(report.get("module_base"), Mapping) else None
        if module_base is None or not _valid_pointer(module_base):
            return False
        if not _validate_runtime_code_guard(before.get("runtime_code_guard"), module_base, profile):
            return False
        if not _validate_runtime_code_guard(after.get("runtime_code_guard"), module_base, profile):
            return False
        top_runtime = report.get("runtime_code_guard")
        if (not isinstance(top_runtime, Mapping) or top_runtime.get("status") != "observed"
                or top_runtime.get("passes") != [before.get("runtime_code_guard"), after.get("runtime_code_guard")]):
            return False
        layout = _profile_layout(profile)
        return _validate_network(report, layout) if request.get("recipient") is None else _validate_pair(report, layout)
    except (ProfileError, ProbeError, KeyError, TypeError, ValueError, AttributeError):
        return False


def retract_record(record: Mapping[str, Any], reason: str = "observation_retracted") -> dict[str, Any]:
    result = deepcopy(dict(record))
    network = result.get("request", {}).get("recipient") is None
    result["fields"] = {family: _unknown_field(reason, family, network=network) for family in result.get("request", {}).get("families", [])}
    result["status"] = "unknown"
    result["completed"] = False
    return result


__all__ = [
    "AddressBoundedRPM", "NetworkAddressBoundedRPM", "PROFILE_FILE", "PROFILE_MAX_BYTES", "EXPECTED_PROFILE_ID", "EXPECTED_PROFILE_SHA256", "EXPECTED_EXE_SHA256", "EXPECTED_VERSION", "EXPECTED_COUNTRY", "FIELDS", "FAMILIES", "MAX_SINGLE_RPM", "MAX_TOTAL_RPM", "NETWORK_MAX_TOTAL_RPM", "ProfileError", "ProbeError", "capture", "validate_capture", "retract_record", "_load_profile", "_profile_layout", "_profile_code_guards", "_static_contract_guard", "_file_code_guard", "_runtime_code_guard", "_pair_pass", "_network_pass", "_vector_snapshot", "_project_family"
]



