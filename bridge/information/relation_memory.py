"""Read-only current alliance and royal-marriage relation predicates.

The two predicates in this module are intentionally implemented as bounded RPM
replays of the two audited membership leaves.  No game function is called:
the reader copies the relation row and the selected owner's vector and then
applies the proven first-DWORD comparison.  Unknown relation dates and the
remaining twelve bytes of every vector element stay raw and unexplained.
"""
from __future__ import annotations

import ctypes as C
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from . import country_resources_memory as _crm
from . import localization_memory as _loc
from . import mission_memory as _mm
from .observation_time import dates_match, without_clock, active as _sampling_active, _CLOCK_KEYS


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "relation-memory-1374-v2-sampling-r1.json"
PROFILE_MAX_BYTES = 64 * 1024
EXPECTED_PROFILE_SHA256 = "e17440069891de796eb969d63f0fb2cdaf8a22933e446d44d62e574c6cabe9d8"
LEGACY_PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "relation-memory-1374.json"
LEGACY_PROFILE_SHA256 = "156cdfc92c96694189544ed99a1e15028236cee0d40460e326a0106597a77ba6"
LEGACY_ARCHIVE_ALLIANCE_QUERY_SOURCE = Path(
    "work/runtime/information-debt-quote-query-20261101-001/root-before-001/work/native/alliance-query.inc"
)
RELATION_EVIDENCE_EXECUTION_SOURCE = Path(
    "work/runtime/diplomacy-observer-20261107-outcome-tail-v40-001/alliance-execution.inc"
)
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_VERSION = "1.37.4"
EXPECTED_COUNTRY = "FRA"
FIELDS = ("alliance", "royal_marriage")
FAMILY_ORDER = FIELDS
# The native country table uses this exact raw handle for an unoccupied
# country slot.  It is an observed null sentinel, not an invalid candidate.
NULL_COUNTRY_FULLREF_RAW_HEX = "2d2d2d0000000000"
PROCESS_ACCESS = _mm.PROCESS_ACCESS
MAX_USER_ADDRESS = _mm.MAX_USER_ADDRESS
MAX_SINGLE_RPM = 65_536
MAX_TOTAL_RPM = 512 * 1024
MAX_VECTOR_COUNT = 4096
NETWORK_MAX_TOTAL_RPM = 2 * 1024 * 1024
_COMPARISON_SCALARS = frozenset((str, int, float, bool, bytes, type(None)))

AddressBoundedRPM = _crm.AddressBoundedRPM
_load_installation = _loc._load_installation
_configure_kernel = _loc._configure_kernel
_capture_identity = _loc._capture_identity
_close_process_handle = _loc._close_process_handle
_read_pe_rva_bytes = _loc._read_pe_rva_bytes
_valid_pointer = _loc._valid_pointer
_address = _loc._address
_tag_and_slot = _loc._tag_and_slot


class ProfileError(RuntimeError):
    """The pinned relation profile or its static evidence is invalid."""


ProbeError = _crm.ProbeError


def _parse_int(value: Any, label: str = "value") -> int:
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


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _workspace_path(raw_path: str) -> Path:
    raw = Path(raw_path)
    if raw.is_absolute():
        raise ProfileError(f"source_path_absolute:{raw_path}")
    workspace = Path(__file__).resolve().parents[2]
    resolved = (workspace / raw).resolve()
    if resolved != workspace and workspace not in resolved.parents:
        raise ProfileError(f"source_path_outside_workspace:{raw_path}")
    return resolved


def _load_profile(path: Path | None = None, expected_sha256: str | None = None) -> dict[str, Any]:
    path = PROFILE_FILE if path is None else Path(path)
    expected_sha256 = EXPECTED_PROFILE_SHA256 if expected_sha256 is None else expected_sha256
    try:
        size = path.stat().st_size
        if size <= 0 or size > PROFILE_MAX_BYTES:
            raise ProfileError(f"profile_size_out_of_bound:{size}")
        raw = path.read_bytes()
    except (OSError, UnicodeError) as exc:
        raise ProfileError(f"profile_read_failed:{exc}") from exc
    if len(raw) != size:
        raise ProfileError("profile_read_size_changed")
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
        raise ProfileError("profile_sha256_pin_invalid")
    actual = hashlib.sha256(raw).hexdigest()
    if actual.lower() != expected_sha256.lower():
        raise ProfileError("profile_sha256_mismatch")
    try:
        profile = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"profile_json_invalid:{exc}") from exc
    if not isinstance(profile, dict) or profile.get("profile_id") != "relation-memory-1374":
        raise ProfileError("profile_shape_invalid")
    return profile


def _load_legacy_archive_profile() -> dict[str, Any]:
    """Load the exact v1 profile only for validating retained archive reports."""
    profile = _load_profile(LEGACY_PROFILE_FILE, LEGACY_PROFILE_SHA256)
    if profile.get("profile_version") != 1:
        raise ProfileError("legacy_archive_profile_version_invalid")
    return profile


try:
    PROFILE: dict[str, Any] | None = _load_profile()
except ProfileError:
    PROFILE = None


def _hex(value: int | None) -> str | None:
    return hex(value) if isinstance(value, int) else None


def _addr(value: int | None, module_base: int | None = None, *, rva: int | None = None) -> dict[str, Any] | None:
    if not isinstance(value, int):
        return None
    result: dict[str, Any] = {"va": hex(value)}
    if isinstance(module_base, int) and value >= module_base:
        result["rva"] = hex(value - module_base)
    if isinstance(rva, int):
        result["rva"] = hex(rva)
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
        if profile.get("game_version") != EXPECTED_VERSION or profile.get("profile_id") != "relation-memory-1374":
            raise ProfileError("profile_identity_invalid")
        if str(executable.get("sha256", "")).lower() != EXPECTED_EXE_SHA256:
            raise ProfileError("profile_executable_sha_invalid")
        if country.get("supported_actor") != EXPECTED_COUNTRY:
            raise ProfileError("profile_supported_actor_invalid")
        if set(families) != set(FIELDS):
            raise ProfileError("profile_family_set_invalid")
        result = {
            "database_rva": _parse_int(globals_.get("database_rva"), "globals.database_rva"),
            "game_rva": _parse_int(globals_.get("game_rva"), "globals.game_rva"),
            "game_date_offset": _parse_int(globals_.get("game_date_offset"), "globals.game_date_offset"),
            "country_table_offset": _parse_int(country.get("table_offset"), "country.table_offset"),
            "country_count_offset": _parse_int(country.get("count_offset"), "country.count_offset"),
            "country_fullref_offset": _parse_int(country.get("fullref_offset"), "country.fullref_offset"),
            "country_handle_offset": _parse_int(country.get("handle_offset"), "country.handle_offset"),
            "max_country_entries": _parse_int(country.get("max_entries"), "country.max_entries"),
            "relation_table_offset": _parse_int(relation.get("table_offset"), "relation.table_offset"),
            "relation_row_stride": _parse_int(relation.get("row_stride"), "relation.row_stride"),
            "relation_row_owner_offset": _parse_int(relation.get("row_owner_offset"), "relation.row_owner_offset"),
            "relation_row_recipient_offset": _parse_int(relation.get("row_recipient_fullref_offset"), "relation.row_recipient_fullref_offset"),
            "element_stride": _parse_int(relation.get("element_stride"), "relation.element_stride"),
            "max_vector_count": _parse_int(limits.get("max_vector_count"), "limits.max_vector_count"),
        }
        if result["max_country_entries"] <= 0 or result["max_country_entries"] > MAX_VECTOR_COUNT:
            raise ProfileError("profile_country_bound_invalid")
        if result["max_vector_count"] != MAX_VECTOR_COUNT or result["element_stride"] != 0x10:
            raise ProfileError("profile_vector_contract_invalid")
        parsed_families: dict[str, dict[str, Any]] = {}
        for family in FIELDS:
            item = families[family]
            if not isinstance(item, Mapping):
                raise ProfileError(f"profile_family_not_object:{family}")
            leaf_hex = item.get("leaf_hex")
            if not isinstance(leaf_hex, str) or not leaf_hex or len(leaf_hex) % 2:
                raise ProfileError(f"profile_leaf_hex_invalid:{family}")
            leaf = bytes.fromhex(leaf_hex)
            leaf_hash = item.get("leaf_sha256")
            if hashlib.sha256(leaf).hexdigest() != str(leaf_hash).lower():
                raise ProfileError(f"profile_leaf_sha_invalid:{family}")
            parsed_families[family] = {
                "selector": _parse_int(item.get("selector"), f"families.{family}.selector"),
                "selector_case_rva": _parse_int(item.get("selector_case_rva"), f"families.{family}.selector_case_rva"),
                "call_rva": _parse_int(item.get("call_rva"), f"families.{family}.call_rva"),
                "leaf_rva": _parse_int(item.get("leaf_rva"), f"families.{family}.leaf_rva"),
                "begin_offset": _parse_int(item.get("vector_begin_offset"), f"families.{family}.vector_begin_offset"),
                "count_offset": _parse_int(item.get("vector_count_offset"), f"families.{family}.vector_count_offset"),
                "leaf": leaf,
                "leaf_sha256": str(leaf_hash).lower(),
            }
        result["families"] = parsed_families
        return result
    except (KeyError, TypeError, ValueError) as exc:
        raise ProfileError(f"profile_layout_invalid:{exc}") from exc


def _profile_code_guards(profile: Mapping[str, Any] | None = None) -> list[tuple[str, int, bytes]]:
    profile = _load_profile() if profile is None else profile
    raw_guards = profile.get("code_guards")
    if not isinstance(raw_guards, list) or not raw_guards:
        raise ProfileError("profile_code_guards_invalid")
    guards: list[tuple[str, int, bytes]] = []
    for item in raw_guards:
        if not isinstance(item, Mapping):
            raise ProfileError("profile_code_guard_not_object")
        name = item.get("name")
        if not isinstance(name, str) or not name:
            raise ProfileError("profile_code_guard_name_invalid")
        rva = _parse_int(item.get("rva"), f"code_guard.{name}.rva")
        raw_hex = item.get("bytes")
        if not isinstance(raw_hex, str) or not raw_hex or len(raw_hex) % 2:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}")
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}") from exc
        if len(raw) > MAX_SINGLE_RPM or hashlib.sha256(raw).hexdigest() != str(item.get("sha256", "")).lower():
            raise ProfileError(f"profile_code_guard_hash_invalid:{name}")
        end = item.get("end_rva_exclusive")
        if end is not None and _parse_int(end, f"code_guard.{name}.end") != rva + len(raw):
            raise ProfileError(f"profile_code_guard_range_invalid:{name}")
        guards.append((name, rva, raw))
    return guards


def _dependency_checks(
    profile: Mapping[str, Any], *, offline_legacy_archive: bool = False
) -> tuple[bool, dict[str, bool], list[str]]:
    checks: dict[str, bool] = {}
    unknown: list[str] = []
    if type(offline_legacy_archive) is not bool:
        return False, checks, ["offline_archive_flag_invalid"]
    expected_version = 1 if offline_legacy_archive else 2
    if profile.get("profile_id") != "relation-memory-1374" or profile.get("profile_version") != expected_version:
        return False, checks, ["source_profile_identity_invalid"]
    refs = profile.get("source_evidence")
    if not isinstance(refs, list) or not refs:
        return False, checks, ["source_evidence_missing"]
    for item in refs:
        if not isinstance(item, Mapping) or not isinstance(item.get("path"), str) or not isinstance(item.get("sha256"), str):
            unknown.append("source_evidence_shape_invalid")
            continue
        raw_path = str(item["path"])
        expected = str(item["sha256"])
        try:
            verification_path = raw_path
            if raw_path == "work/native/alliance-execution.inc":
                # Both profiles pin this retained producer revision. Runtime
                # executable identity and code guards are checked separately.
                verification_path = RELATION_EVIDENCE_EXECUTION_SOURCE.as_posix()
            elif offline_legacy_archive and raw_path == "work/native/alliance-query.inc":
                verification_path = LEGACY_ARCHIVE_ALLIANCE_QUERY_SOURCE.as_posix()
            path = _workspace_path(verification_path)
            size = path.stat().st_size
            if size > 16 * 1024 * 1024:
                raise OSError("source_evidence_too_large")
            actual = _sha256_file(path)
            checks[raw_path] = actual.lower() == expected.lower()
            if not checks[raw_path]:
                unknown.append(f"source_evidence_sha_mismatch:{raw_path}")
        except (OSError, ValueError, ProfileError) as exc:
            checks[raw_path] = False
            unknown.append(f"source_evidence_read_failed:{raw_path}:{exc}")
    return bool(checks) and all(checks.values()) and not unknown, checks, unknown


def _static_contract_guard(*, offline_legacy_archive: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "profile_sha256": LEGACY_PROFILE_SHA256 if offline_legacy_archive is True else EXPECTED_PROFILE_SHA256,
        "checks": {},
        "source_hash_checks": {},
        "unknown_conditions": [],
    }
    try:
        if type(offline_legacy_archive) is not bool:
            raise ProfileError("offline_archive_flag_invalid")
        profile = _load_legacy_archive_profile() if offline_legacy_archive else _load_profile()
        expected_version = 1 if offline_legacy_archive else 2
        if profile.get("profile_id") != "relation-memory-1374" or profile.get("profile_version") != expected_version:
            raise ProfileError("profile_identity_invalid_for_validation_mode")
        layout = _profile_layout(profile)
        deps_ok, dep_checks, dep_unknown = _dependency_checks(
            profile, offline_legacy_archive=offline_legacy_archive
        )
        guards = _profile_code_guards(profile)
        result["source_hash_checks"] = dep_checks
        result["unknown_conditions"].extend(dep_unknown)
        result["checks"] = {
            "profile_id": profile.get("profile_id") == "relation-memory-1374",
            "game_version": profile.get("game_version") == EXPECTED_VERSION,
            "exe_sha256": str(profile.get("executable", {}).get("sha256", "")).lower() == EXPECTED_EXE_SHA256,
            "actor": profile.get("country", {}).get("supported_actor") == EXPECTED_COUNTRY,
            "families": set(layout["families"]) == set(FIELDS),
            "guards": len(guards) == 4,
            "source_evidence": deps_ok,
            "native_call": profile.get("semantics", {}).get("native_call") is False,
            "expiry_unknown": "unknown_native_expiry_unread" in str(profile.get("semantics", {}).get("expiry_semantics")),
        }
        failed = [key for key, value in result["checks"].items() if value is not True]
        if failed:
            result["unknown_conditions"].append("profile_contract_check_failed:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (ProfileError, KeyError, TypeError, ValueError) as exc:
        result["unknown_conditions"].append(f"profile_contract_read_failed:{exc}")
    return result


def _file_code_guard(path: Path, profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "path": str(path), "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        for name, rva, expected in _profile_code_guards(profile):
            actual = _read_pe_rva_bytes(path, rva, len(expected))
            result["records"][name] = {"rva": _hex(rva), "expected_hex": expected.hex(), "actual_hex": actual.hex()}
            result["checks"][name] = actual == expected
        failed = [name for name, value in result["checks"].items() if value is not True]
        if failed:
            result["unknown_conditions"].append("file_code_guard_mismatch:" + ",".join(failed))
            result["status"] = "mismatch"
        else:
            result["status"] = "observed"
    except (OSError, ProbeError, ProfileError, KeyError, TypeError, ValueError) as exc:
        result["unknown_conditions"].append(str(exc))
    return result


class _ReadBudget:
    """Precharge reads before dispatching them to the process reader."""

    def __init__(self, limit: int = MAX_TOTAL_RPM):
        self.limit = limit
        self.reserved = 0
        self.calls = 0
        self.log: list[dict[str, Any]] = []

    def read(self, reader: Any, address: int, size: int, label: str) -> bytes:
        if not isinstance(size, int) or size <= 0 or size > MAX_SINGLE_RPM:
            raise ProbeError(f"invalid_size:{label}")
        if self.reserved + size > self.limit:
            self.log.append({"label": label, "address": _hex(address), "size": size, "status": "budget_rejected"})
            raise ProbeError(f"RPM_TOTAL_BUDGET_EXCEEDED:{label}")
        # Reservation is deliberately before reader.read.  Failed RPM calls
        # therefore cannot be retried until a parent budget is exhausted.
        self.reserved += size
        self.calls += 1
        try:
            raw = reader.read(address, size, label)
        except Exception as exc:
            self.log.append({"label": label, "address": _hex(address), "size": size, "status": "error", "error": f"{type(exc).__name__}:{exc}"})
            raise
        if not isinstance(raw, (bytes, bytearray)) or len(raw) != size:
            raise ProbeError(f"short_read:{label}")
        self.log.append({"label": label, "address": _hex(address), "size": size, "status": "observed", "raw_hex": bytes(raw).hex()})
        return bytes(raw)

    def qword(self, reader: Any, address: int, label: str) -> tuple[int, bytes]:
        raw = self.read(reader, address, 8, label)
        return int.from_bytes(raw, "little", signed=False), raw

    def i32(self, reader: Any, address: int, label: str) -> tuple[int, bytes]:
        raw = self.read(reader, address, 4, label)
        return int.from_bytes(raw, "little", signed=True), raw

    def u32(self, reader: Any, address: int, label: str) -> tuple[int, bytes]:
        raw = self.read(reader, address, 4, label)
        return int.from_bytes(raw, "little", signed=False), raw

    def snapshot(self) -> dict[str, Any]:
        return {"bytes_reserved": self.reserved, "calls_reserved": self.calls, "limit": self.limit}


class NetworkAddressBoundedRPM(AddressBoundedRPM):
    """The network view has its own 2 MiB bounded reader budget.

    ``AddressBoundedRPM`` is intentionally shared by the small pair readers
    and retains their 512 KiB contract.  The country view may inspect the
    bounded country table plus all selected rows, so it uses this identical
    read-only wrapper with only the explicit larger network ceiling.
    """

    network_limit = NETWORK_MAX_TOTAL_RPM

    def read(self, address: int, size: int, label: str) -> bytes:
        if not isinstance(address, int) or isinstance(address, bool) or address < 0x10000:
            self._reject(address, size, label, "invalid_address")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0 or size > MAX_SINGLE_RPM:
            self._reject(address, size, label, "invalid_size")
        if address + size > MAX_USER_ADDRESS:
            self._reject(address, size, label, "address_range_overflow")
        if self.bytes_requested + size > self.network_limit:
            self._reject(address, size, label, "NETWORK_RPM_TOTAL_BUDGET_EXCEEDED")
        self.bytes_requested += size
        self.calls += 1
        entry: dict[str, Any] = {"label": label, "address": hex(address), "size": size, "status": "requested"}
        self.read_log.append(entry)
        buffer = C.create_string_buffer(size)
        actual = C.c_size_t()
        try:
            ok = self.kernel.ReadProcessMemory(self.handle, C.c_void_p(address), buffer, size, C.byref(actual))
        except Exception as exc:
            entry.update(status="error", error=f"{type(exc).__name__}:{exc}")
            raise
        if not ok:
            entry.update(status="error", error="ReadProcessMemory_failed")
            raise C.WinError(C.get_last_error())
        if actual.value != size:
            entry.update(status="error", error=f"short_read:{actual.value}/{size}")
            raise ProbeError(f"short_read:{label}:{actual.value}/{size}")
        raw = buffer.raw
        entry.update(status="observed", raw_hex=raw.hex())
        return raw


def _safe_add(base: int, offset: int, label: str, *, aligned: bool = False) -> int:
    if not isinstance(base, int) or isinstance(base, bool) or not isinstance(offset, int) or offset < 0:
        raise ProbeError(f"invalid_address_arithmetic:{label}")
    value = base + offset
    if value < 0x10000 or value >= MAX_USER_ADDRESS:
        raise ProbeError(f"address_range_overflow:{label}")
    if aligned and value % 8:
        raise ProbeError(f"invalid_alignment:{label}")
    return value


def _slot_from_fullref(fullref: int) -> int:
    return (fullref >> 32) & 0xFFFF


def _signed_i16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def _field(address: int, raw: bytes, value: int, module_base: int) -> dict[str, Any]:
    return {"address": _addr(address, module_base), "raw_hex": raw.hex(), "value": value}


def _country_scan(reader: Any, budget: _ReadBudget, module_base: int, database: int, requested: Sequence[str], layout: Mapping[str, Any]) -> dict[str, Any]:
    table_address = _safe_add(database, int(layout["country_table_offset"]), "database.country_table", aligned=True)
    table, table_raw = budget.qword(reader, table_address, "database.country_table")
    count_address = _safe_add(database, int(layout["country_count_offset"]), "database.country_count", aligned=False)
    count, count_raw = budget.i32(reader, count_address, "database.country_count")
    result: dict[str, Any] = {
        "status": "unknown",
        "table": _field(table_address, table_raw, table, module_base),
        "count": _field(count_address, count_raw, count, module_base),
        "scanned_entries": 0,
        "entries": [],
        "matches": {},
        "candidate_failures": [],
        "unknown_conditions": [],
    }
    if not _valid_pointer(table):
        result["unknown_conditions"].append("country_table_pointer_invalid")
        return result
    if count <= 0 or count > int(layout["max_country_entries"]):
        result["unknown_conditions"].append("country_count_out_of_bound")
        return result
    pointers_raw = budget.read(reader, table, count * 8, "country_table.entries")
    matches: dict[str, list[dict[str, Any]]] = {tag: [] for tag in requested}
    entries: list[dict[str, Any]] = []
    for index in range(count):
        entry_address = table + index * 8
        pointer_raw = pointers_raw[index * 8:(index + 1) * 8]
        pointer = int.from_bytes(pointer_raw, "little")
        entry: dict[str, Any] = {"index": index, "address": _addr(entry_address, module_base), "pointer_raw_hex": pointer_raw.hex(), "pointer": _addr(pointer, module_base)}
        if pointer == 0:
            entry["status"] = "empty"
            entries.append(entry)
            continue
        if not _valid_pointer(pointer):
            entry["status"] = "unknown"
            entry["reason"] = "nonzero_country_pointer_invalid"
            result["candidate_failures"].append({"index": index, "reason": entry["reason"], "pointer_raw_hex": pointer_raw.hex()})
            entries.append(entry)
            continue
        fullref_address = _safe_add(pointer, int(layout["country_fullref_offset"]), f"country[{index}].fullref", aligned=True)
        fullref, fullref_raw = budget.qword(reader, fullref_address, f"country[{index}].fullref")
        tag, slot = _tag_and_slot(fullref)
        entry.update({"fullref": _field(fullref_address, fullref_raw, fullref, module_base), "tag": tag, "slot": slot})
        if fullref_raw.hex() == NULL_COUNTRY_FULLREF_RAW_HEX:
            entry["status"] = "null_sentinel"
            entry["reason"] = "known_null_country_sentinel"
            entries.append(entry)
            continue
        entry["status"] = "other"
        if not isinstance(tag, str) or slot != index:
            entry["status"] = "unknown"
            entry["reason"] = "country_fullref_tag_or_slot_invalid"
            result["candidate_failures"].append({"index": index, "reason": entry["reason"], "fullref_raw_hex": fullref_raw.hex(), "tag": tag, "slot": slot})
        elif isinstance(tag, str) and tag in matches:
            entry["status"] = "match"
            matches[tag].append(entry)
        entries.append(entry)
    result["entries"] = entries
    result["scanned_entries"] = count
    for tag in requested:
        candidates = matches.get(tag, [])
        if len(candidates) != 1:
            result["unknown_conditions"].append(f"country_identity_match_count_invalid:{tag}")
        else:
            result["matches"][tag] = deepcopy(candidates[0])
    result["status"] = "observed" if not result["unknown_conditions"] else "unknown"
    return result


def _context_snapshot(reader: Any, budget: _ReadBudget, module_base: int, actor: str, recipient: str, layout: Mapping[str, Any]) -> dict[str, Any]:
    database_address = _safe_add(module_base, int(layout["database_rva"]), "global.database", aligned=True)
    database, database_raw = budget.qword(reader, database_address, "global.database")
    game_address = _safe_add(module_base, int(layout["game_rva"]), "global.game", aligned=True)
    game, game_raw = budget.qword(reader, game_address, "global.game")
    if not _valid_pointer(database) or not _valid_pointer(game):
        return {"status": "unknown", "unknown_conditions": ["game_or_database_pointer_invalid"]}
    date_address = _safe_add(game, int(layout["game_date_offset"]), "game.date", aligned=False)
    date, date_raw = budget.i32(reader, date_address, "game.raw_date")
    country_scan = _country_scan(reader, budget, module_base, database, (actor, recipient), layout)
    result: dict[str, Any] = {
        "status": "unknown",
        "database": _field(database_address, database_raw, database, module_base),
        "game": _field(game_address, game_raw, game, module_base),
        "game_date": _field(date_address, date_raw, date, module_base),
        "country_scan": country_scan,
        "actor": None,
        "recipient": None,
        "unknown_conditions": [],
    }
    if country_scan.get("status") != "observed":
        result["unknown_conditions"].extend(country_scan.get("unknown_conditions", []))
        return result
    result["actor"] = deepcopy(country_scan["matches"].get(actor))
    result["recipient"] = deepcopy(country_scan["matches"].get(recipient))
    if not result["actor"] or not result["recipient"]:
        result["unknown_conditions"].append("actor_or_recipient_identity_missing")
        return result
    result["status"] = "observed"
    return result


def _unknown_field(reason: str, family: str) -> dict[str, Any]:
    return {
        "status": "unknown",
        "family": family,
        "value": None,
        "unit": "relation_state",
        "scale": 1,
        "period": "current",
        "partial": True,
        "complete": False,
        "reason": reason,
        "expires_at": {"status": "unknown", "reason": "RELATION_EXPIRY_UNREAD"},
    }


def _relation_row(reader: Any, budget: _ReadBudget, actor_entry: Mapping[str, Any], recipient_entry: Mapping[str, Any], layout: Mapping[str, Any], module_base: int) -> dict[str, Any]:
    actor_pointer = int(actor_entry["pointer"]["va"], 0)
    recipient_fullref = int(recipient_entry["fullref"]["value"])
    recipient_slot = _slot_from_fullref(recipient_fullref)
    if recipient_slot >= int(layout["max_country_entries"]):
        raise ProbeError("recipient_slot_out_of_bound")
    table_address = _safe_add(actor_pointer, int(layout["relation_table_offset"]), "actor.relation_table", aligned=True)
    table_pointer, table_raw = budget.qword(reader, table_address, "actor.relation_table.pointer")
    if not _valid_pointer(table_pointer):
        raise ProbeError("relation_table_pointer_invalid")
    row_address = _safe_add(table_pointer, recipient_slot * int(layout["relation_row_stride"]), "relation.row", aligned=True)
    row_raw = budget.read(reader, row_address, 0x20, "relation.row.prefix")
    owner = int.from_bytes(row_raw[int(layout["relation_row_owner_offset"]):int(layout["relation_row_owner_offset"])+8], "little")
    row_recipient = int.from_bytes(row_raw[int(layout["relation_row_recipient_offset"]):int(layout["relation_row_recipient_offset"])+8], "little")
    # The row's +0 owner is the native relation-vector owner object.  Static
    # source names it ``owner`` but the network audit proves it is not
    # necessarily the actor country object; only the row address itself is
    # derived from the actor country table entry.
    if not _valid_pointer(owner):
        raise ProbeError("relation_row_owner_pointer_invalid")
    if row_recipient != recipient_fullref:
        raise ProbeError("relation_row_recipient_fullref_mismatch")
    return {
        "address": _addr(row_address, module_base),
        "relation_table": _field(table_address, table_raw, table_pointer, module_base),
        "prefix_raw_hex": row_raw.hex(),
        "owner": _addr(owner, module_base),
        "owner_raw_hex": row_raw[0:8].hex(),
        "recipient_fullref": _field(row_address + int(layout["relation_row_recipient_offset"]), row_raw[int(layout["relation_row_recipient_offset"]):int(layout["relation_row_recipient_offset"])+8], row_recipient, module_base),
        "recipient_slot": recipient_slot,
        "row_stride": int(layout["relation_row_stride"]),
    }


def _family_snapshot(reader: Any, budget: _ReadBudget, family: str, relation_row: Mapping[str, Any], recipient_fullref: int, layout: Mapping[str, Any], module_base: int) -> dict[str, Any]:
    spec = layout["families"][family]
    owner = int(relation_row["owner"]["va"], 0)
    begin_address = _safe_add(owner, int(spec["begin_offset"]), f"{family}.vector_begin", aligned=True)
    count_address = _safe_add(owner, int(spec["count_offset"]), f"{family}.vector_count", aligned=False)
    begin, begin_raw = budget.qword(reader, begin_address, f"{family}.vector_begin")
    count, count_raw = budget.i32(reader, count_address, f"{family}.vector_count")
    if count < 0 or count > int(layout["max_vector_count"]):
        raise ProbeError(f"{family}.vector_count_out_of_bound")
    if count and not _valid_pointer(begin):
        raise ProbeError(f"{family}.vector_begin_invalid")
    expected = _signed_i16(_slot_from_fullref(recipient_fullref))
    elements: list[dict[str, Any]] = []
    if count:
        size = count * int(layout["element_stride"])
        if size > MAX_SINGLE_RPM:
            raise ProbeError(f"{family}.vector_read_too_large")
        raw = budget.read(reader, begin, size, f"{family}.vector.elements")
        for index in range(count):
            chunk = raw[index * 16:(index + 1) * 16]
            address = _safe_add(begin, index * 16, f"{family}.element[{index}]")
            first = int.from_bytes(chunk[:4], "little", signed=False)
            elements.append({
                "index": index,
                "address": _addr(address, module_base),
                "raw_hex": chunk.hex(),
                "first_dword_raw_hex": chunk[:4].hex(),
                "first_dword": first,
                "unread_tail_raw_hex": chunk[4:].hex(),
                "unread_tail_semantics": "+0x4..+0xf_unread_by_direct_leaf",
            })
    matches = [item["index"] for item in elements if item["first_dword"] == (expected & 0xFFFFFFFF)]
    return {
        "status": "known",
        "family": family,
        "value": bool(matches),
        "unit": "relation_state",
        "scale": 1,
        "period": "current",
        "partial": True,
        "complete": False,
        "basis": "native_current_selected_pair_relation_predicate",
        "value_origin": "derived_from_copied_relation_row_and_owner_vector",
        "expires_at": {"status": "unknown", "reason": "RELATION_EXPIRY_UNREAD"},
        "raw": {
            "owner_pointer": deepcopy(relation_row["owner"]),
            "owner_pointer_raw_hex": relation_row["owner_raw_hex"],
            "recipient_fullref": deepcopy(relation_row["recipient_fullref"]),
            "recipient_slot_signed_i16": expected,
            "vector_begin": _field(begin_address, begin_raw, begin, module_base),
            "vector_count": _field(count_address, count_raw, count, module_base),
            "element_stride": int(layout["element_stride"]),
            "elements": elements,
        },
        "proof": {
            "selector": _hex(spec["selector"]),
            "selector_case_rva": _hex(spec["selector_case_rva"]),
            "call_rva": _hex(spec["call_rva"]),
            "leaf_rva": _hex(spec["leaf_rva"]),
            "leaf_va": _hex(module_base + spec["leaf_rva"]),
            "offer": False,
            "matching_element_indices": matches,
            "unread_element_bytes": "+0x4..+0xf",
        },
    }


def _without_volatile(value: Any) -> Any:
    sampling = _sampling_active()
    excluded = {'read_budget', 'read_log'} | (_CLOCK_KEYS if sampling else set())

    def project(item: Any) -> Any:
        if type(item) in _COMPARISON_SCALARS:
            return item
        if isinstance(item, Mapping):
            return {key: project(child) for key, child in item.items() if key not in excluded}
        if isinstance(item, list):
            return [project(child) for child in item
                    if not (sampling and isinstance(child, Mapping) and child.get('label') == 'game.raw_date')]
        # The original budget projection leaves tuples intact. Clock projection
        # traverses them only inside a live observation window.
        if isinstance(item, tuple) and sampling:
            return without_clock(item, date_labels=('game.raw_date',))
        return item

    return project(value)


def _observation_dates_match(before_context: Any, after_context: Any, anchor_date: Any = None, *, anchor_present: bool = False) -> bool:
    if not isinstance(before_context, Mapping) or not isinstance(after_context, Mapping):
        return False
    before_field = before_context.get("game_date")
    after_field = after_context.get("game_date")
    if not isinstance(before_field, Mapping) or not isinstance(after_field, Mapping):
        return False
    before_date = before_field.get("value")
    after_date = after_field.get("value")
    # without_clock removes the complete game_date field; retain and verify its
    # address binding separately while allowing only the value/raw bytes to move.
    before_binding = {key: value for key, value in before_field.items() if key not in {"value", "raw_hex"}}
    after_binding = {key: value for key, value in after_field.items() if key not in {"value", "raw_hex"}}
    if before_binding != after_binding or not dates_match(before_date, after_date):
        return False
    return not anchor_present or dates_match(anchor_date, before_date, after_date)


def _pass(reader: Any, budget: _ReadBudget, module_base: int, actor: str, recipient: str, families: Sequence[str], profile: Mapping[str, Any]) -> dict[str, Any]:
    layout = _profile_layout(profile)
    result: dict[str, Any] = {
        "status": "unknown",
        "runtime_code_guard": None,
        "context": None,
        "relation_row": None,
        "fields": {family: _unknown_field("not_read", family) for family in families},
        "read_budget": None,
        "read_log": [],
        "unknown_conditions": [],
        "complete": False,
    }
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
        relation_row = _relation_row(reader, budget, context["actor"], context["recipient"], layout, module_base)
        result["relation_row"] = relation_row
        recipient_fullref = int(context["recipient"]["fullref"]["value"])
        for family in families:
            try:
                result["fields"][family] = _family_snapshot(reader, budget, family, relation_row, recipient_fullref, layout, module_base)
            except Exception as exc:
                result["fields"][family] = _unknown_field(f"{type(exc).__name__}:{exc}", family)
        result["status"] = "observed"
        result["complete"] = all(item.get("status") == "known" for item in result["fields"].values())
    except Exception as exc:
        result["unknown_conditions"].append(f"{type(exc).__name__}:{exc}")
    finally:
        result["read_budget"] = budget.snapshot()
        result["read_log"] = deepcopy(budget.log[start:])
    return result


def _runtime_code_guard(reader: Any, budget_or_module_base: _ReadBudget | int, module_base: int | None = None, profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
    # Keep the familiar ``_runtime_code_guard(reader, module_base)`` seam for
    # diagnostics/tests while capture passes its shared precharge budget.
    if module_base is None:
        module_base = int(budget_or_module_base)
        budget = _ReadBudget()
        profile = _load_profile() if profile is None else profile
    else:
        budget = budget_or_module_base
        if not isinstance(budget, _ReadBudget):
            raise ProbeError("runtime_guard_budget_invalid")
        profile = _load_profile() if profile is None else profile
    result: dict[str, Any] = {"status": "unknown", "module_base": _addr(module_base), "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        for name, rva, expected in _profile_code_guards(profile):
            actual = budget.read(reader, _safe_add(module_base, rva, f"code_guard.{name}"), len(expected), f"code_guard.{name}")
            result["records"][name] = {"rva": _hex(rva), "address": _addr(module_base + rva, module_base, rva=rva), "expected_hex": expected.hex(), "actual_hex": actual.hex()}
            result["checks"][name] = actual == expected
        failed = [name for name, ok in result["checks"].items() if ok is not True]
        if failed:
            result["unknown_conditions"].append("runtime_code_guard_mismatch:" + ",".join(failed))
            result["status"] = "mismatch"
        else:
            result["status"] = "observed"
    except Exception as exc:
        result["unknown_conditions"].append(f"{type(exc).__name__}:{exc}")
    return result


def _base_report(installation: Path, actor: str, recipient: str, families: Sequence[str]) -> dict[str, Any]:
    return {
        "schema": "information_relation_current_runtime.v1",
        "probe": "information-relation-current",
        "probe_version": 1,
        "probe_script": str(Path(__file__).resolve()),
        "probe_script_sha256": None,
        "read_only": True,
        "evidence_kind": "pure_runtime_observation_not_static_evidence",
        "profile": {"path": str(PROFILE_FILE), "profile_id": EXPECTED_PROFILE_ID if 'EXPECTED_PROFILE_ID' in globals() else "relation-memory-1374", "sha256": EXPECTED_PROFILE_SHA256, "max_bytes": PROFILE_MAX_BYTES},
        "request": {"installation": str(installation), "actor": actor, "recipient": recipient, "families": list(families)},
        "target_build": {"version": EXPECTED_VERSION, "expected_exe_sha256": EXPECTED_EXE_SHA256, "image_base": "0x140000000"},
        "static_contract_guard": None,
        "file_code_guard": None,
        "runtime_code_guard": None,
        "identity": {"installation_path": str(installation), "installation_pid": None, "installation_creation_filetime": None, "installation_session_id": None, "process_path": None, "process_path_sha256": None, "process_path_sha256_matches_expected": None, "process_creation_filetime": None, "process_creation_utc": None, "process_creation_matches_installation": None, "module_path": None, "module_path_matches_process": None, "binding_verified": False},
        "module_base": None,
        "context_before": None,
        "context_after": None,
        "relation_row": None,
        "fields": {family: _unknown_field("not_read", family) for family in families},
        "before": None,
        "after": None,
        "doublepass": {"performed": False, "consistent": None, "mismatches": []},
        "access": {"open_process_mask": "QUERY_INFORMATION|VM_READ", "open_process_mask_hex": _hex(PROCESS_ACCESS), "rpm_total_limit": MAX_TOTAL_RPM, "rpm_single_read_limit": MAX_SINGLE_RPM, "rpm_bytes_requested": 0, "rpm_calls": 0, "native_game_calls": False, "target_memory_writes": False, "dll_injection": False, "private_heap_scan": False, "ui_control": False, "date_advance": False, "save_or_reload": False},
        "cleanup": {"handle_close": {"status": "unknown", "success": None, "closed": False}},
        "status": "starting",
        "errors": [],
        "completed": False,
    }


EXPECTED_PROFILE_ID = "relation-memory-1374"


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


def _valid_tag(tag: Any) -> bool:
    return isinstance(tag, str) and bool(re.fullmatch(r"[A-Z0-9]{3}", tag))


def _retract(report: dict[str, Any], reason: str) -> None:
    fields = report.get("fields")
    if isinstance(fields, Mapping):
        report["fields"] = {family: _unknown_field(reason, family) for family in fields}
    for key in ("before", "after"):
        item = report.get(key)
        if isinstance(item, Mapping):
            item["fields"] = {family: _unknown_field(reason, family) for family in report.get("request", {}).get("families", [])}
            item["complete"] = False
    report["relation_row"] = None


def capture(installation: Path, actor: str, recipient: str, families: Sequence[str] | None = None) -> dict[str, Any]:
    """Capture the selected current relation pair with two bounded RPM passes."""
    installation = Path(installation)
    try:
        selected = _normalize_families(families)
    except ProbeError as exc:
        selected = list(FIELDS) if families is None else []
        report = _base_report(installation, actor, recipient, selected)
        report["status"] = "invalid_request"
        report["errors"].append({"stage": "request", "status": "unknown", "error": str(exc)})
        report["cleanup"]["handle_close"] = _close_process_handle(None, None)
        report["completed"] = True
        return report
    report = _base_report(installation, actor, recipient, selected)
    try:
        report["probe_script_sha256"] = _sha256_file(Path(__file__).resolve())
    except OSError as exc:
        report["errors"].append({"stage": "probe_identity", "status": "unknown", "error": str(exc)})
    if not _valid_tag(actor) or not _valid_tag(recipient) or actor == recipient:
        report["status"] = "unsupported_request"
        report["errors"].append({"stage": "request", "status": "unknown", "error": "actor and recipient must be distinct three-character tags"})
        report["cleanup"]["handle_close"] = _close_process_handle(None, None)
        report["completed"] = True
        return report
    report["static_contract_guard"] = _static_contract_guard()
    if report["static_contract_guard"].get("status") != "observed":
        report["status"] = "static_contract_mismatch"
        report["errors"].append({"stage": "static_contract", "status": "unknown", "error": "relation profile or evidence hash mismatch"})
        report["cleanup"]["handle_close"] = _close_process_handle(None, None)
        report["completed"] = True
        return report
    kernel = None
    handle = None
    reader = None
    try:
        profile = _load_profile()
        layout = _profile_layout(profile)
        document = _load_installation(installation)
        kernel = _configure_kernel()
        pid = int(document["pid"])
        handle = kernel.OpenProcess(PROCESS_ACCESS, False, pid)
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
            report["errors"].append({"stage": "file_code_guard", "status": "unknown", "error": "relation code guard mismatch"})
        else:
            reader = AddressBoundedRPM(kernel, handle, module_base)
            budget = _ReadBudget(int(profile["limits"]["max_total_rpm"]))
            first = _pass(reader, budget, module_base, actor, recipient, selected, profile)
            report["before"] = first
            report["context_before"] = deepcopy(first.get("context"))
            if first.get("status") != "observed":
                report["status"] = "unknown"
                report["errors"].append({"stage": "before", "status": "unknown", "error": ";".join(first.get("unknown_conditions", []))})
            else:
                second = _pass(reader, budget, module_base, actor, recipient, selected, profile)
                report["after"] = second
                report["context_after"] = deepcopy(second.get("context"))
                report["doublepass"]["performed"] = True
                if second.get("status") != "observed":
                    report["doublepass"]["consistent"] = False
                    report["doublepass"]["mismatches"] = ["$.after.status"]
                    report["status"] = "doublepass_mismatch"
                else:
                    left = _without_volatile(first)
                    right = _without_volatile(second)
                    mismatches = _diff_paths(left, right)
                    if not _observation_dates_match(first.get("context"), second.get("context")):
                        mismatches.append("$.context.game_date")
                    report["doublepass"]["mismatches"] = mismatches[:256]
                    report["doublepass"]["consistent"] = not mismatches
                    if mismatches:
                        report["status"] = "doublepass_mismatch"
                        report["errors"].append({"stage": "doublepass", "status": "unknown", "error": "relation bytes or context changed", "paths": mismatches[:256]})
                    else:
                        report["status"] = "observed"
                        report["fields"] = deepcopy(second.get("fields", {}))
                        report["relation_row"] = deepcopy(second.get("relation_row"))
            before_guard = (report.get("before") or {}).get("runtime_code_guard", {})
            after_guard = (report.get("after") or {}).get("runtime_code_guard", {})
            report["runtime_code_guard"] = {"status": "observed" if before_guard.get("status") == "observed" and after_guard.get("status") == "observed" else "unknown", "passes": [before_guard, after_guard]}
            report["access"]["rpm_bytes_requested"] = reader.bytes_requested
            report["access"]["rpm_calls"] = reader.calls
    except Exception as exc:
        report["status"] = "error"
        report["errors"].append({"stage": "capture", "status": "unknown", "error": f"{type(exc).__name__}:{exc}"})
    finally:
        if reader is not None:
            report["access"]["rpm_bytes_requested"] = reader.bytes_requested
            report["access"]["rpm_calls"] = reader.calls
    cleanup = _close_process_handle(kernel, handle)
    report["cleanup"]["handle_close"] = cleanup
    report["completed"] = report.get("status") == "observed" and cleanup.get("closed") is True
    if not report["completed"]:
        _retract(report, "observation_not_completed")
    return report


def _network_context_snapshot(reader: Any, budget: _ReadBudget, module_base: int, actor: str, layout: Mapping[str, Any]) -> dict[str, Any]:
    """Read the shared game/database context and the complete bounded table."""
    context = _context_snapshot(reader, budget, module_base, actor, actor, layout)
    # _context_snapshot uses one requested tag for both endpoint arguments;
    # the network view publishes that one resolved actor and no recipient.
    context["recipient"] = None
    return context


def _project_cached_family(cached: Mapping[str, Any], relation_row: Mapping[str, Any], recipient_fullref: int, family: str, module_base: int) -> dict[str, Any]:
    """Project one recipient slot through a previously copied owner vector."""
    result = deepcopy(dict(cached))
    expected = _signed_i16(_slot_from_fullref(recipient_fullref))
    raw = result.get("raw")
    proof = result.get("proof")
    if not isinstance(raw, dict) or not isinstance(proof, dict):
        raise ProbeError("owner_vector_cache_shape_invalid")
    raw["recipient_fullref"] = deepcopy(relation_row["recipient_fullref"])
    raw["recipient_slot_signed_i16"] = expected
    elements = raw.get("elements")
    if not isinstance(elements, list):
        raise ProbeError("owner_vector_cache_elements_missing")
    matches = [item["index"] for item in elements if isinstance(item, Mapping) and item.get("first_dword") == (expected & 0xFFFFFFFF)]
    result["family"] = family
    result["value"] = bool(matches)
    proof["matching_element_indices"] = matches
    proof["owner_vector_cache_reused"] = True
    proof["leaf_va"] = _hex(module_base + int(proof["leaf_rva"], 0))
    return result


def _network_pass(reader: Any, budget: _ReadBudget, module_base: int, actor: str, families: Sequence[str], profile: Mapping[str, Any]) -> dict[str, Any]:
    layout = _profile_layout(profile)
    result: dict[str, Any] = {
        "status": "unknown",
        "runtime_code_guard": None,
        "context": None,
        "fields": {family: {"status": "unknown", "family": family, "value": [], "unknown_rows": [], "rows": [], "partial": True, "complete": False, "unit": "relation_state", "scale": 1, "period": "current"} for family in families},
        "targets": [],
        "owner_cache": {},
        "candidate_failures": [],
        "network_stats": {"candidate_count": 0, "known_rows": {family: 0 for family in families}, "unknown_rows": {family: 0 for family in families}},
        "read_budget": None,
        "read_log": [],
        "unknown_conditions": [],
        "complete": False,
    }
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
        result["candidate_failures"] = deepcopy(context.get("country_scan", {}).get("candidate_failures", []))
        actor_entry = context["actor"]
        actor_index = int(actor_entry["index"])
        entries = context.get("country_scan", {}).get("entries", [])
        if not isinstance(entries, list):
            raise ProbeError("network_country_entries_missing")
        targets: list[dict[str, Any]] = []
        for entry in entries:
            if not isinstance(entry, Mapping) or entry.get("status") in {"empty", "null_sentinel", "unknown"}:
                continue
            pointer = _as_int((entry.get("pointer") or {}).get("va"))
            fullref = _as_int((entry.get("fullref") or {}).get("value"))
            tag = entry.get("tag")
            slot = entry.get("slot")
            if entry.get("index") == actor_index or pointer is None or fullref is None or not _valid_tag(tag) or not isinstance(slot, int):
                continue
            targets.append({"index": int(entry["index"]), "country": tag, "country_pointer": deepcopy(entry.get("pointer")), "fullref": fullref, "fullref_hex": hex(fullref), "fullref_raw_hex": (entry.get("fullref") or {}).get("raw_hex"), "slot": int(slot)})
        result["network_stats"]["candidate_count"] = len(targets)
        result["targets"] = targets
        cache: dict[str, dict[str, Any]] = {}
        for target in targets:
            recipient_entry = {"pointer": target["country_pointer"], "fullref": {"value": target["fullref"], "raw_hex": target["fullref"].to_bytes(8, "little").hex()}}
            try:
                row = _relation_row(reader, budget, actor_entry, recipient_entry, layout, module_base)
                target["relation_row"] = row
                target["row_status"] = "observed"
            except Exception as exc:
                target["row_status"] = "unknown"
                target["row_reason"] = f"{type(exc).__name__}:{exc}"
                target["relation_row"] = None
        for family in families:
            field_rows: list[dict[str, Any]] = []
            active_rows: list[dict[str, Any]] = []
            unknown_rows: list[dict[str, Any]] = []
            for target in targets:
                row_item: dict[str, Any] = {"index": target["index"], "country": target["country"], "fullref_hex": target["fullref_hex"], "fullref_raw_hex": target.get("fullref_raw_hex"), "slot": target["slot"], "relation_row": deepcopy(target.get("relation_row")), "active": None, "status": "unknown", "predicate_cache_key": None}
                try:
                    if target.get("row_status") != "observed":
                        raise ProbeError(str(target.get("row_reason", "relation_row_unknown")))
                    row = target["relation_row"]
                    owner_ptr = _as_int((row.get("owner") or {}).get("va"))
                    if owner_ptr is None:
                        raise ProbeError("relation_row_owner_pointer_invalid")
                    cache_key = f"{owner_ptr:#x}:{family}"
                    if cache_key not in cache:
                        copied = _family_snapshot(reader, budget, family, row, target["fullref"], layout, module_base)
                        # A cache entry is owner-vector raw evidence.  The
                        # recipient-specific matching result is recomputed per
                        # target and is therefore not authoritative in cache.
                        cache_entry = deepcopy(copied)
                        cache_entry["raw"].pop("recipient_fullref", None)
                        cache_entry["raw"].pop("recipient_slot_signed_i16", None)
                        cache_entry["value"] = None
                        cache_entry["proof"]["matching_element_indices"] = []
                        cache_entry["proof"]["owner_vector_cache_key"] = cache_key
                        cache[cache_key] = cache_entry
                    projected = _project_cached_family(cache[cache_key], row, target["fullref"], family, module_base)
                    row_item["active"] = bool(projected["value"])
                    row_item["status"] = "known"
                    row_item["predicate_cache_key"] = cache_key
                    row_item["predicate"] = {"matching_element_indices": projected["proof"]["matching_element_indices"], "value": projected["value"]}
                    result["network_stats"]["known_rows"][family] += 1
                    if row_item["active"]:
                        active_rows.append({"country": target["country"], "fullref_hex": target["fullref_hex"], "slot": target["slot"], "active": True})
                except Exception as exc:
                    row_item["status"] = "unknown"
                    row_item["active"] = None
                    row_item["reason"] = f"{type(exc).__name__}:{exc}"
                    unknown_rows.append({"index": target["index"], "country": target["country"], "fullref_hex": target["fullref_hex"], "fullref_raw_hex": target.get("fullref_raw_hex"), "slot": target["slot"], "reason": row_item["reason"]})
                    result["network_stats"]["unknown_rows"][family] += 1
                field_rows.append(row_item)
            field_status = "known" if not unknown_rows else "partial"
            result["fields"][family] = {
                "status": field_status,
                "family": family,
                "value": active_rows,
                "unit": "relation_state",
                "scale": 1,
                "period": "current",
                "partial": True,
                "complete": False,
                "basis": "native_current_selected_pair_relation_predicate",
                "value_origin": "derived_from_copied_relation_row_and_owner_vector",
                "rows": field_rows,
                "unknown_rows": unknown_rows,
                "candidate_failures": deepcopy(result["candidate_failures"]),
                "candidate_count": len(targets),
                "expires_at": {"status": "unknown", "reason": "RELATION_EXPIRY_UNREAD"},
            }
        result["owner_cache"] = cache
        result["status"] = "observed"
        result["complete"] = all(item.get("status") == "known" for item in result["fields"].values())
    except Exception as exc:
        result["unknown_conditions"].append(f"{type(exc).__name__}:{exc}")
    finally:
        result["read_budget"] = budget.snapshot()
        result["read_log"] = deepcopy(budget.log[start:])
    return result


def _base_network_report(installation: Path, actor: str, families: Sequence[str]) -> dict[str, Any]:
    return {
        "schema": "information_relation_network_runtime.v1",
        "probe": "information-relation-network-current",
        "probe_version": 1,
        "probe_script": str(Path(__file__).resolve()),
        "probe_script_sha256": None,
        "read_only": True,
        "evidence_kind": "pure_runtime_observation_not_static_evidence",
        "profile": {"path": str(PROFILE_FILE), "profile_id": EXPECTED_PROFILE_ID, "sha256": EXPECTED_PROFILE_SHA256, "max_bytes": PROFILE_MAX_BYTES},
        "request": {"installation": str(installation), "actor": actor, "families": list(families)},
        "target_build": {"version": EXPECTED_VERSION, "expected_exe_sha256": EXPECTED_EXE_SHA256, "image_base": "0x140000000"},
        "static_contract_guard": None,
        "file_code_guard": None,
        "runtime_code_guard": None,
        "identity": {"installation_path": str(installation), "installation_pid": None, "installation_creation_filetime": None, "installation_session_id": None, "process_path": None, "process_path_sha256": None, "process_path_sha256_matches_expected": None, "process_creation_filetime": None, "process_creation_utc": None, "process_creation_matches_installation": None, "module_path": None, "module_path_matches_process": None, "binding_verified": False},
        "module_base": None,
        "context_before": None,
        "context_after": None,
        "fields": {family: {"status": "unknown", "family": family, "value": [], "unknown_rows": [], "rows": [], "partial": True, "complete": False} for family in families},
        "before": None,
        "after": None,
        "owner_cache": {},
        "network_stats": None,
        "doublepass": {"performed": False, "consistent": None, "mismatches": []},
        "access": {"open_process_mask": "QUERY_INFORMATION|VM_READ", "open_process_mask_hex": _hex(PROCESS_ACCESS), "rpm_total_limit": NETWORK_MAX_TOTAL_RPM, "rpm_single_read_limit": MAX_SINGLE_RPM, "rpm_bytes_requested": 0, "rpm_calls": 0, "native_game_calls": False, "target_memory_writes": False, "dll_injection": False, "private_heap_scan": False, "ui_control": False, "date_advance": False, "save_or_reload": False},
        "cleanup": {"handle_close": {"status": "unknown", "success": None, "closed": False}},
        "status": "starting",
        "errors": [],
        "completed": False,
    }


def capture_network(installation: Path, actor: str, families: Sequence[str] | None = None) -> dict[str, Any]:
    """Capture active selected-pair partners for one actor with shared vectors."""
    installation = Path(installation)
    try:
        selected = _normalize_families(families)
    except ProbeError as exc:
        selected = list(FIELDS) if families is None else []
        report = _base_network_report(installation, actor, selected)
        report["status"] = "invalid_request"
        report["errors"].append({"stage": "request", "status": "unknown", "error": str(exc)})
        report["cleanup"]["handle_close"] = _close_process_handle(None, None)
        report["completed"] = True
        return report
    report = _base_network_report(installation, actor, selected)
    try:
        report["probe_script_sha256"] = _sha256_file(Path(__file__).resolve())
    except OSError as exc:
        report["errors"].append({"stage": "probe_identity", "status": "unknown", "error": str(exc)})
    if not _valid_tag(actor):
        report["status"] = "unsupported_request"
        report["errors"].append({"stage": "request", "status": "unknown", "error": "actor must be a three-character country tag"})
        report["cleanup"]["handle_close"] = _close_process_handle(None, None)
        report["completed"] = True
        return report
    report["static_contract_guard"] = _static_contract_guard()
    if report["static_contract_guard"].get("status") != "observed":
        report["status"] = "static_contract_mismatch"
        report["cleanup"]["handle_close"] = _close_process_handle(None, None)
        report["completed"] = True
        return report
    kernel = None
    handle = None
    reader = None
    try:
        profile = _load_profile()
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
            reader = NetworkAddressBoundedRPM(kernel, handle, module_base)
            budget = _ReadBudget(NETWORK_MAX_TOTAL_RPM)
            first = _network_pass(reader, budget, module_base, actor, selected, profile)
            report["before"] = first
            report["context_before"] = deepcopy(first.get("context"))
            if first.get("status") != "observed":
                report["status"] = "unknown"
            else:
                second = _network_pass(reader, budget, module_base, actor, selected, profile)
                report["after"] = second
                report["context_after"] = deepcopy(second.get("context"))
                report["doublepass"]["performed"] = True
                if second.get("status") != "observed":
                    report["status"] = "doublepass_mismatch"
                    report["doublepass"]["consistent"] = False
                    report["doublepass"]["mismatches"] = ["$.after.status"]
                else:
                    mismatches = _diff_paths(_without_volatile(first), _without_volatile(second))
                    if not _observation_dates_match(first.get("context"), second.get("context")):
                        mismatches.append("$.context.game_date")
                    report["doublepass"]["mismatches"] = mismatches[:256]
                    report["doublepass"]["consistent"] = not mismatches
                    report["status"] = "observed" if not mismatches else "doublepass_mismatch"
                    if not mismatches:
                        report["fields"] = deepcopy(second.get("fields", {}))
                        report["owner_cache"] = deepcopy(second.get("owner_cache", {}))
                        report["network_stats"] = deepcopy(second.get("network_stats"))
            before_guard = (report.get("before") or {}).get("runtime_code_guard", {})
            after_guard = (report.get("after") or {}).get("runtime_code_guard", {})
            report["runtime_code_guard"] = {"status": "observed" if before_guard.get("status") == "observed" and after_guard.get("status") == "observed" else "unknown", "passes": [before_guard, after_guard]}
            report["access"]["rpm_bytes_requested"] = reader.bytes_requested
            report["access"]["rpm_calls"] = reader.calls
    except Exception as exc:
        report["status"] = "error"
        report["errors"].append({"stage": "capture_network", "status": "unknown", "error": f"{type(exc).__name__}:{exc}"})
    finally:
        if reader is not None:
            report["access"]["rpm_bytes_requested"] = reader.bytes_requested
            report["access"]["rpm_calls"] = reader.calls
    cleanup = _close_process_handle(kernel, handle)
    report["cleanup"]["handle_close"] = cleanup
    report["completed"] = report.get("status") == "observed" and cleanup.get("closed") is True
    if not report["completed"]:
        _retract_network(report, "observation_not_completed")
    return report


def _retract_network(report: dict[str, Any], reason: str) -> None:
    fields = report.get("fields")
    if isinstance(fields, Mapping):
        for family, field in fields.items():
            if isinstance(field, dict):
                field["status"] = "unknown"
                field["value"] = []
                field["unknown_rows"] = [{"reason": reason}]
                field["rows"] = []
                field["complete"] = False
    report["owner_cache"] = {}
    report["network_stats"] = None


def _validate_network_field(field: Mapping[str, Any], family: str, report: Mapping[str, Any], owner_cache: Mapping[str, Any], layout: Mapping[str, Any]) -> bool:
    if field.get("status") not in {"known", "partial"} or field.get("family") != family or not isinstance(field.get("value"), list) or not isinstance(field.get("rows"), list) or not isinstance(field.get("unknown_rows"), list) or not isinstance(field.get("candidate_failures"), list):
        return False
    rows = field["rows"]
    active: list[dict[str, Any]] = []
    unknown_records: list[dict[str, Any]] = []
    unknown_count = 0
    context = report.get("context_after") or report.get("context_before")
    actor_ptr = _as_int(((context or {}).get("actor") or {}).get("pointer", {}).get("va")) if isinstance(context, Mapping) else None
    if actor_ptr is None:
        return False
    country_scan = context.get("country_scan") if isinstance(context, Mapping) else None
    if not isinstance(country_scan, Mapping):
        return False
    if field.get("candidate_failures") != country_scan.get("candidate_failures", []):
        return False
    actor_index = _as_int(((context.get("actor") or {}).get("index"))) if isinstance(context, Mapping) else None
    if actor_index is None:
        return False
    expected_targets: set[tuple[int, str, str, int]] = set()
    for entry in country_scan.get("entries", []):
        if not isinstance(entry, Mapping) or entry.get("status") not in {"match", "other"} or entry.get("index") == actor_index:
            continue
        index = _as_int(entry.get("index"))
        tag = entry.get("tag")
        slot = entry.get("slot")
        fullref = (entry.get("fullref") or {}).get("value")
        fullref_raw_hex = (entry.get("fullref") or {}).get("raw_hex")
        if index is None or not _valid_tag(tag) or not isinstance(slot, int) or not isinstance(fullref, int) or not isinstance(fullref_raw_hex, str):
            return False
        expected_targets.add((index, tag, fullref_raw_hex, slot))
    if field.get("candidate_count") != len(expected_targets) or len(rows) != len(expected_targets):
        return False
    seen_targets: set[tuple[int, str, str, int]] = set()
    for row in rows:
        if not isinstance(row, Mapping) or not _valid_tag(row.get("country")):
            return False
        index = _as_int(row.get("index"))
        fullref = _as_int(row.get("fullref_hex"))
        fullref_raw_hex = row.get("fullref_raw_hex")
        slot = row.get("slot")
        if index is None or fullref is None or not isinstance(fullref_raw_hex, str) or not isinstance(slot, int) or slot != _slot_from_fullref(fullref):
            return False
        try:
            if fullref_raw_hex != fullref.to_bytes(8, "little").hex():
                return False
        except OverflowError:
            return False
        target_key = (index, row["country"], fullref_raw_hex, slot)
        if target_key not in expected_targets or target_key in seen_targets:
            return False
        seen_targets.add(target_key)
        relation_row = row.get("relation_row")
        if not isinstance(relation_row, Mapping):
            return False
        row_address = _as_int((relation_row.get("address") or {}).get("va"))
        relation_table = relation_row.get("relation_table")
        table_address = _as_int((relation_table or {}).get("address", {}).get("va")) if isinstance(relation_table, Mapping) else None
        table_pointer = _as_int((relation_table or {}).get("value")) if isinstance(relation_table, Mapping) else None
        table_raw_hex = relation_table.get("raw_hex") if isinstance(relation_table, Mapping) else None
        expected_table_address = actor_ptr + int(layout["relation_table_offset"])
        expected_row = table_pointer + slot * int(layout["relation_row_stride"]) if table_pointer is not None else None
        row_fullref = _as_int((relation_row.get("recipient_fullref") or {}).get("value"))
        row_fullref_raw_hex = (relation_row.get("recipient_fullref") or {}).get("raw_hex")
        if (table_address != expected_table_address or table_pointer is None or not _valid_pointer(table_pointer)
                or table_raw_hex != table_pointer.to_bytes(8, "little").hex()
                or row_address != expected_row or row_fullref != fullref or row_fullref_raw_hex != fullref_raw_hex):
            return False
        if row.get("status") == "unknown":
            if row.get("active") is not None or not isinstance(row.get("reason"), str):
                return False
            unknown_count += 1
            unknown_records.append({"index": index, "country": row["country"], "fullref_hex": row["fullref_hex"], "fullref_raw_hex": fullref_raw_hex, "slot": slot, "reason": row["reason"]})
            continue
        if row.get("status") != "known" or row.get("active") not in (True, False):
            return False
        key = row.get("predicate_cache_key")
        expected_key = f"{_as_int((relation_row.get('owner') or {}).get('va')):#x}:{family}" if _as_int((relation_row.get("owner") or {}).get("va")) is not None else None
        if key != expected_key:
            return False
        cached = owner_cache.get(key)
        if not isinstance(cached, Mapping):
            return False
        cached_raw = cached.get("raw") or {}
        elements = cached_raw.get("elements")
        vector_count = _as_int((cached_raw.get("vector_count") or {}).get("value"))
        vector_begin = _as_int((cached_raw.get("vector_begin") or {}).get("value"))
        owner = _as_int((relation_row.get("owner") or {}).get("va"))
        if owner is None or not isinstance(elements, list) or vector_count is None or len(elements) != vector_count or vector_count < 0 or vector_count > int(layout["max_vector_count"]):
            return False
        if _as_int((cached_raw.get("owner_pointer") or {}).get("va")) != owner or vector_begin is None:
            return False
        expected = _signed_i16(slot)
        matches = []
        for element in elements:
            if not isinstance(element, Mapping) or not isinstance(element.get("index"), int):
                return False
            chunk = element.get("raw_hex")
            if not isinstance(chunk, str) or len(chunk) != 32:
                return False
            try:
                raw_element = bytes.fromhex(chunk)
            except ValueError:
                return False
            address = _as_int((element.get("address") or {}).get("va"))
            first = int.from_bytes(raw_element[:4], "little")
            if address != vector_begin + element["index"] * 16 or element.get("first_dword") != first or element.get("first_dword_raw_hex") != raw_element[:4].hex() or element.get("unread_tail_raw_hex") != raw_element[4:].hex():
                return False
            if first == (expected & 0xffffffff):
                matches.append(element["index"])
        if bool(matches) != row.get("active"):
            return False
        if row.get("predicate", {}).get("matching_element_indices") != matches:
            return False
        if row.get("active"):
            active.append({"country": row["country"], "fullref_hex": row["fullref_hex"], "slot": slot, "active": True})
    if field.get("status") == "known" and unknown_count:
        return False
    if field.get("status") == "partial" and unknown_count == 0:
        return False
    if field.get("value") != active:
        return False
    if len(field.get("unknown_rows", [])) != unknown_count or field.get("unknown_rows") != unknown_records:
        return False
    if seen_targets != expected_targets:
        return False
    return True


def validate_network_capture(
    report: Mapping[str, Any],
    context: Mapping[str, Any] | None = None,
    creation_filetime: int | None = None,
    actor: str | None = None,
    families: Sequence[str] | None = None,
    *,
    offline_legacy_archive: bool = False,
) -> bool:
    """Validate a current v2 capture, or an explicitly selected retained v1 archive."""
    if not isinstance(report, Mapping):
        return False
    if type(offline_legacy_archive) is not bool:
        return False
    try:
        profile = _load_legacy_archive_profile() if offline_legacy_archive else _load_profile()
        expected_profile_sha = LEGACY_PROFILE_SHA256 if offline_legacy_archive else EXPECTED_PROFILE_SHA256
        expected_profile_path = LEGACY_PROFILE_FILE if offline_legacy_archive else PROFILE_FILE
        if report.get("schema") != "information_relation_network_runtime.v1" or report.get("status") != "observed" or report.get("completed") is not True:
            return False
        cleanup = report.get("cleanup", {}).get("handle_close", {})
        access = report.get("access", {})
        if cleanup.get("closed") is not True or access.get("native_game_calls") is not False or access.get("target_memory_writes") is not False:
            return False
        report_profile = report.get("profile")
        if not isinstance(report_profile, Mapping) or report_profile.get("profile_id") != EXPECTED_PROFILE_ID or report_profile.get("sha256") != expected_profile_sha or report.get("target_build", {}).get("expected_exe_sha256", "").lower() != EXPECTED_EXE_SHA256:
            return False
        if offline_legacy_archive and report_profile != {
            "path": str(expected_profile_path),
            "profile_id": EXPECTED_PROFILE_ID,
            "sha256": expected_profile_sha,
            "max_bytes": PROFILE_MAX_BYTES,
        }:
            return False
        static_guard = report.get("static_contract_guard")
        if offline_legacy_archive and static_guard != _static_contract_guard(offline_legacy_archive=True):
            return False
        if not isinstance(static_guard, Mapping) or static_guard.get("status") != "observed" or report.get("runtime_code_guard", {}).get("status") != "observed":
            return False
        identity = report.get("identity")
        if not isinstance(identity, Mapping) or identity.get("binding_verified") is not True or identity.get("process_path_sha256_matches_expected") is not True or identity.get("process_creation_matches_installation") is not True:
            return False
        if creation_filetime is not None and identity.get("process_creation_filetime") != creation_filetime:
            return False
        request = report.get("request")
        if not isinstance(request, Mapping):
            return False
        expected_actor = request.get("actor") if actor is None else actor
        selected = _normalize_families(request.get("families") if families is None else families)
        if not _valid_tag(expected_actor) or (actor is not None and actor != request.get("actor")):
            return False
        if set(request.get("families", [])) != set(selected) or len(request.get("families", [])) != len(selected):
            return False
        if report.get("doublepass", {}).get("performed") is not True or report.get("doublepass", {}).get("consistent") is not True:
            return False
        before, after = report.get("before"), report.get("after")
        if (not isinstance(before, Mapping) or not isinstance(after, Mapping)
                or _without_volatile(before) != _without_volatile(after)
                or not _observation_dates_match(before.get("context"), after.get("context"))):
            return False
        if report.get("context_before") != before.get("context") or report.get("context_after") != after.get("context") or report.get("fields") != after.get("fields") or report.get("owner_cache") != after.get("owner_cache") or report.get("network_stats") != after.get("network_stats"):
            return False
        if before.get("runtime_code_guard", {}).get("status") != "observed" or after.get("runtime_code_guard", {}).get("status") != "observed":
            return False
        context_after = report.get("context_after")
        if not isinstance(context_after, Mapping) or context_after.get("status") != "observed" or context_after.get("recipient") is not None:
            return False
        if context is not None:
            if not isinstance(context, Mapping):
                return False
            for key in ("session_id", "process_creation_filetime", "game_date", "actor"):
                if key in context:
                    if key == "game_date":
                        if not _observation_dates_match(before.get("context"), after.get("context"), context[key], anchor_present=True):
                            return False
                        continue
                    observed = identity.get("installation_session_id") if key == "session_id" else identity.get("process_creation_filetime") if key == "process_creation_filetime" else context_after.get("game_date", {}).get("value") if key == "game_date" else request.get("actor")
                    if observed != context[key]:
                        return False
        layout = _profile_layout(profile)
        fields = report.get("fields")
        owner_cache = report.get("owner_cache")
        if not isinstance(fields, Mapping) or set(fields) != set(selected) or not isinstance(owner_cache, Mapping):
            return False
        for family in selected:
            if not _validate_network_field(fields.get(family), family, report, owner_cache, layout):
                return False
        return True
    except (ProfileError, ProbeError, KeyError, TypeError, ValueError, AttributeError):
        return False


def _diff_paths(left: Any, right: Any, prefix: str = "$") -> list[str]:
    if type(left) is not type(right):
        return [prefix]
    if isinstance(left, Mapping):
        paths: list[str] = []
        for key in sorted(set(left) | set(right), key=str):
            if key not in left or key not in right:
                paths.append(f"{prefix}.{key}")
            else:
                first, second = left[key], right[key]
                if type(first) is type(second) and type(first) in _COMPARISON_SCALARS and first == second:
                    continue
                paths.extend(_diff_paths(first, second, f"{prefix}.{key}"))
        return paths
    if isinstance(left, list):
        paths = []
        for index in range(max(len(left), len(right))):
            if index >= len(left) or index >= len(right):
                paths.append(f"{prefix}[{index}]")
            else:
                first, second = left[index], right[index]
                if type(first) is type(second) and type(first) in _COMPARISON_SCALARS and first == second:
                    continue
                paths.extend(_diff_paths(first, second, f"{prefix}[{index}]"))
        return paths
    return [] if left == right else [prefix]


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


def _validate_field(field: Mapping[str, Any], family: str, report: Mapping[str, Any], layout: Mapping[str, Any]) -> bool:
    if field.get("status") == "unknown":
        return isinstance(field.get("reason"), str) and field.get("value") is None
    if field.get("status") != "known" or field.get("family") != family or field.get("value") not in (True, False):
        return False
    raw = field.get("raw")
    proof = field.get("proof")
    relation_row = report.get("relation_row")
    context = report.get("context_after") or report.get("context_before")
    if not isinstance(raw, Mapping) or not isinstance(proof, Mapping) or not isinstance(relation_row, Mapping) or not isinstance(context, Mapping):
        return False
    actor = context.get("actor")
    recipient = context.get("recipient")
    if not isinstance(actor, Mapping) or not isinstance(recipient, Mapping):
        return False
    actor_ptr = _as_int((actor.get("pointer") or {}).get("va"))
    owner_ptr = _as_int((raw.get("owner_pointer") or {}).get("va"))
    row_owner = _as_int((relation_row.get("owner") or {}).get("va"))
    row_address = _as_int((relation_row.get("address") or {}).get("va"))
    if actor_ptr is None or owner_ptr is None or row_owner is None or row_address is None or owner_ptr != row_owner or not _valid_pointer(owner_ptr):
        return False
    if raw.get("owner_pointer_raw_hex") != owner_ptr.to_bytes(8, "little").hex() or relation_row.get("owner_raw_hex") != row_owner.to_bytes(8, "little").hex():
        return False
    expected_recipient = _as_int((recipient.get("fullref") or {}).get("value"))
    rec_fullref = _as_int((raw.get("recipient_fullref") or {}).get("value"))
    row_fullref = _as_int((relation_row.get("recipient_fullref") or {}).get("value"))
    if expected_recipient is None or rec_fullref != expected_recipient or row_fullref != expected_recipient:
        return False
    if (raw.get("recipient_fullref") or {}).get("raw_hex") != expected_recipient.to_bytes(8, "little").hex() or (relation_row.get("recipient_fullref") or {}).get("raw_hex") != expected_recipient.to_bytes(8, "little").hex():
        return False
    relation_table = relation_row.get("relation_table")
    table_address = _as_int((relation_table or {}).get("address", {}).get("va")) if isinstance(relation_table, Mapping) else None
    table_pointer = _as_int((relation_table or {}).get("value")) if isinstance(relation_table, Mapping) else None
    table_raw_hex = relation_table.get("raw_hex") if isinstance(relation_table, Mapping) else None
    expected_table_address = actor_ptr + int(layout["relation_table_offset"])
    expected_row = table_pointer + _slot_from_fullref(expected_recipient) * int(layout["relation_row_stride"]) if table_pointer is not None else None
    if (table_address != expected_table_address or table_pointer is None or not _valid_pointer(table_pointer)
            or table_raw_hex != table_pointer.to_bytes(8, "little").hex() or row_address != expected_row):
        return False
    slot = _signed_i16(_slot_from_fullref(expected_recipient))
    if raw.get("recipient_slot_signed_i16") != slot:
        return False
    spec = layout["families"].get(family)
    if not isinstance(spec, Mapping) or proof.get("leaf_rva") != _hex(spec["leaf_rva"]) or proof.get("call_rva") != _hex(spec["call_rva"]) or proof.get("offer") is not False:
        return False
    begin_field = raw.get("vector_begin") or {}
    count_field = raw.get("vector_count") or {}
    begin_address = _as_int((begin_field.get("address") or {}).get("va"))
    begin = _as_int(begin_field.get("value"))
    vector_count = _as_int(count_field.get("value"))
    count_raw_hex = count_field.get("raw_hex")
    count_address = _as_int((count_field.get("address") or {}).get("va"))
    if begin_address != owner_ptr + int(spec["begin_offset"]) or count_address != owner_ptr + int(spec["count_offset"]) or begin is None or begin_field.get("raw_hex") != begin.to_bytes(8, "little").hex() or count_raw_hex != int(vector_count or 0).to_bytes(4, "little", signed=True).hex():
        return False
    elements = raw.get("elements")
    if vector_count is None or vector_count < 0 or vector_count > int(layout["max_vector_count"]) or not isinstance(elements, list) or len(elements) != vector_count:
        return False
    matching: list[int] = []
    for index, element in enumerate(elements):
        if not isinstance(element, Mapping) or element.get("index") != index:
            return False
        raw_hex = element.get("raw_hex")
        if not isinstance(raw_hex, str) or len(raw_hex) != 32:
            return False
        try:
            chunk = bytes.fromhex(raw_hex)
        except ValueError:
            return False
        first = int.from_bytes(chunk[:4], "little")
        address = _as_int((element.get("address") or {}).get("va"))
        if address is None or begin is None or address != begin + index * 16:
            return False
        if element.get("first_dword") != first or element.get("first_dword_raw_hex") != chunk[:4].hex() or element.get("unread_tail_raw_hex") != chunk[4:].hex() or element.get("unread_tail_semantics") != "+0x4..+0xf_unread_by_direct_leaf":
            return False
        if first == (slot & 0xFFFFFFFF):
            matching.append(index)
    if field.get("value") is not bool(matching) or proof.get("matching_element_indices") != matching:
        return False
    return True


def validate_capture(report: Mapping[str, Any], context: Mapping[str, Any] | None = None, creation_filetime: int | None = None, actor: str | None = None, recipient: str | None = None, families: Sequence[str] | None = None) -> bool:
    """Validate identity, two-pass raw binding, guards and pure predicates."""
    if not isinstance(report, Mapping):
        return False
    try:
        if report.get("schema") != "information_relation_current_runtime.v1" or report.get("status") != "observed" or report.get("completed") is not True:
            return False
        cleanup = report.get("cleanup", {}).get("handle_close", {})
        if cleanup.get("closed") is not True or report.get("access", {}).get("native_game_calls") is not False or report.get("access", {}).get("target_memory_writes") is not False:
            return False
        if report.get("profile", {}).get("profile_id") != EXPECTED_PROFILE_ID or report.get("profile", {}).get("sha256") != EXPECTED_PROFILE_SHA256:
            return False
        if report.get("static_contract_guard", {}).get("status") != "observed" or report.get("runtime_code_guard", {}).get("status") != "observed":
            return False
        if report.get("target_build", {}).get("expected_exe_sha256", "").lower() != EXPECTED_EXE_SHA256:
            return False
        identity = report.get("identity")
        if not isinstance(identity, Mapping) or identity.get("binding_verified") is not True or identity.get("process_path_sha256_matches_expected") is not True or identity.get("process_creation_matches_installation") is not True:
            return False
        if creation_filetime is not None and identity.get("process_creation_filetime") != creation_filetime:
            return False
        request = report.get("request")
        if not isinstance(request, Mapping):
            return False
        expected_actor = request.get("actor") if actor is None else actor
        expected_recipient = request.get("recipient") if recipient is None else recipient
        selected = _normalize_families(request.get("families") if families is None else families)
        if not _valid_tag(expected_actor) or not _valid_tag(expected_recipient) or expected_actor == expected_recipient:
            return False
        if actor is not None and request.get("actor") != actor:
            return False
        if recipient is not None and request.get("recipient") != recipient:
            return False
        if set(selected) != set(request.get("families", [])):
            return False
        if report.get("doublepass", {}).get("performed") is not True or report.get("doublepass", {}).get("consistent") is not True:
            return False
        before = report.get("before")
        after = report.get("after")
        if (not isinstance(before, Mapping) or not isinstance(after, Mapping)
                or _without_volatile(before) != _without_volatile(after)
                or not _observation_dates_match(before.get("context"), after.get("context"))):
            return False
        if report.get("fields") != after.get("fields") or report.get("relation_row") != after.get("relation_row"):
            return False
        if before.get("runtime_code_guard", {}).get("status") != "observed" or after.get("runtime_code_guard", {}).get("status") != "observed":
            return False
        if report.get("context_before") != before.get("context") or report.get("context_after") != after.get("context"):
            return False
        context_after = report.get("context_after")
        if not isinstance(context_after, Mapping) or context_after.get("status") != "observed":
            return False
        matches = context_after.get("country_scan", {}).get("matches", {})
        if not isinstance(matches, Mapping) or expected_actor not in matches or expected_recipient not in matches:
            return False
        if context is not None:
            if not isinstance(context, Mapping):
                return False
            for key in ("session_id", "process_creation_filetime", "game_date", "actor", "recipient"):
                if key in context:
                    if key == "game_date":
                        if not _observation_dates_match(before.get("context"), after.get("context"), context[key], anchor_present=True):
                            return False
                        continue
                    observed = identity.get("installation_session_id") if key == "session_id" else identity.get("process_creation_filetime") if key == "process_creation_filetime" else context_after.get("game_date", {}).get("value") if key == "game_date" else request.get(key)
                    if observed != context[key]:
                        return False
        layout = _profile_layout(_load_profile())
        fields_map = report.get("fields")
        if not isinstance(fields_map, Mapping):
            return False
        for family in selected:
            field = fields_map.get(family)
            if not isinstance(field, Mapping) or not _validate_field(field, family, report, layout):
                return False
        return True
    except (ProfileError, ProbeError, KeyError, TypeError, ValueError, AttributeError):
        return False


def retract_record(record: Mapping[str, Any], reason: str = "observation_retracted") -> dict[str, Any]:
    """Return a copy with all relation values withdrawn after context loss."""
    result = deepcopy(dict(record))
    fields = result.get("fields")
    if isinstance(fields, Mapping):
        result["fields"] = {family: _unknown_field(reason, family) for family in fields}
    result["status"] = "unknown"
    result["completed"] = False
    return result


__all__ = [
    "AddressBoundedRPM", "NetworkAddressBoundedRPM", "PROFILE_FILE", "PROFILE_MAX_BYTES", "EXPECTED_PROFILE_SHA256", "EXPECTED_EXE_SHA256", "EXPECTED_VERSION", "EXPECTED_COUNTRY", "FIELDS", "MAX_SINGLE_RPM", "MAX_TOTAL_RPM", "NETWORK_MAX_TOTAL_RPM", "MAX_USER_ADDRESS", "ProfileError", "ProbeError", "capture", "validate_capture", "retract_record", "capture_network", "validate_network_capture", "_load_profile", "_profile_layout", "_profile_code_guards", "_static_contract_guard", "_file_code_guard", "_runtime_code_guard", "_ReadBudget", "_family_snapshot", "_relation_row", "_country_scan",
]
