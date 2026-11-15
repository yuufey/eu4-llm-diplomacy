"""Bounded current-country diplomat-task record reader for EU4 1.37.4.

This child copies the country ``+0x1480`` diplomat record graph.  It never
calls an engine function and never writes target memory.  The default v2
profile pins the current query-only native source; v1 is restricted to an
explicit offline replay against its retained pre-change source bytes.  The low-level
record values stay raw unless the static/runtime contract proves the narrow
semantic facts already established for this build: entry state 0/1/2 and
selector ``0x3378`` (Build Spy Network).  Actor and recipient are published
as countries only after their complete packed fullref is matched against the
database country table; a three-byte tag alone is never accepted.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from . import country_resources_memory as _crm
from . import localization_memory as _loc
from . import mission_memory as _mm
from .observation_time import dates_match, active


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "diplomat-tasks-memory-1374-v2-sampling-r1.json"
LEGACY_PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "diplomat-tasks-memory-1374.json"
PROFILE_MAX_BYTES = 64 * 1024
EXPECTED_PROFILE_SHA256 = "d804fd91bd0ba05431db0b73afd161bff568bccd22d8a337b19d61ae6ddb40cc"
EXPECTED_PROFILE_ID = "diplomat-tasks-memory-1374-v2"
LEGACY_PROFILE_SHA256 = "cf9c0b9c40422635e6ffcfc01e7e409517b4f658352a8b5963290aab7dd6d119"
LEGACY_PROFILE_ID = "diplomat-tasks-memory-1374"
LEGACY_ARCHIVE_NATIVE_SOURCE = Path("work/runtime/information-debt-quote-query-20261101-001/root-before-001/work/native/alliance-query.inc")
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_VERSION = "1.37.4"
EXPECTED_COUNTRY = "FRA"

_PROFILE_PINS = {
    EXPECTED_PROFILE_ID: (EXPECTED_PROFILE_SHA256, PROFILE_FILE, 2),
    LEGACY_PROFILE_ID: (LEGACY_PROFILE_SHA256, LEGACY_PROFILE_FILE, 1),
}

FIELDS = ("diplomat_tasks",)
FIELD_KEY = "diplomat_tasks"
BASIS = "native_country_diplomat_task_records"
VALUE_ORIGIN = "copied_native_country_diplomat_task_records"
UNIT = "diplomat_task_records"
SCALE = 1
PERIOD = "current"
PARTIAL = True

MAX_SINGLE_RPM = 65_536
MAX_TOTAL_RPM = 512 * 1024
READ_BUDGET_BYTES = MAX_TOTAL_RPM // 2
MAX_USER_ADDRESS = _mm.MAX_USER_ADDRESS
PROCESS_ACCESS = _mm.PROCESS_ACCESS

KNOWN_STATE_NAMES = {0: "idle", 1: "returning", 2: "active"}
KNOWN_SELECTOR = 0x3378
KNOWN_SELECTOR_FAMILY = "build_spy_network"

AddressBoundedRPM = _crm.AddressBoundedRPM
ProbeError = _crm.ProbeError
_load_installation = _loc._load_installation
_configure_kernel = _loc._configure_kernel
_capture_identity = _loc._capture_identity
_close_process_handle = _loc._close_process_handle
_read_pe_rva_bytes = _loc._read_pe_rva_bytes
_address = _crm._address


class ProfileError(RuntimeError):
    """The pinned diplomat-task profile or source evidence is invalid."""


class ReadError(RuntimeError):
    """A bounded child read or raw-graph contract check failed."""


class OfflineArchiveSnapshotReader:
    """Immutable byte snapshot reader for explicit v1 archive replay only.

    It accepts copied byte segments, never a handle or read callback. Segments
    and individual reads stay within the same limits as the bounded RPM path.
    """

    __slots__ = ("_segments", "_byte_count")

    def __init__(self, segments: list[tuple[int, bytes]] | tuple[tuple[int, bytes], ...]):
        if type(segments) not in (list, tuple) or not segments or len(segments) > 4096:
            raise ValueError("offline_snapshot_segments_invalid")
        copied: list[tuple[int, bytes]] = []
        total = 0
        for item in segments:
            if type(item) is not tuple or len(item) != 2:
                raise ValueError("offline_snapshot_segment_invalid")
            address, raw = item
            if type(address) is not int or not 0x10000 <= address <= 0x800000000000:
                raise ValueError("offline_snapshot_address_invalid")
            if type(raw) is not bytes or not raw or len(raw) > MAX_SINGLE_RPM:
                raise ValueError("offline_snapshot_chunk_size_invalid")
            if address + len(raw) - 1 > 0x800000000000:
                raise ValueError("offline_snapshot_address_range_invalid")
            total += len(raw)
            if total > READ_BUDGET_BYTES:
                raise ValueError("offline_snapshot_total_size_exceeded")
            copied.append((address, bytes(raw)))
        copied.sort(key=lambda item: item[0])
        prior_end = None
        for address, raw in copied:
            if prior_end is not None and address < prior_end:
                raise ValueError("offline_snapshot_segments_overlap")
            prior_end = address + len(raw)
        object.__setattr__(self, "_segments", tuple(copied))
        object.__setattr__(self, "_byte_count", total)

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise AttributeError("offline snapshot reader is immutable")

    @property
    def byte_count(self) -> int:
        return self._byte_count

    def read(self, address: int, size: int, label: str) -> bytes:
        if type(address) is not int or not 0x10000 <= address <= 0x800000000000:
            raise ReadError("offline_snapshot_read_address_invalid")
        if type(size) is not int or not 1 <= size <= MAX_SINGLE_RPM:
            raise ReadError("offline_snapshot_read_size_invalid")
        if type(label) is not str or address + size - 1 > 0x800000000000:
            raise ReadError("offline_snapshot_read_range_invalid")
        cursor = address
        remaining = size
        out = bytearray()
        for segment_address, raw in self._segments:
            segment_end = segment_address + len(raw)
            if segment_end <= cursor:
                continue
            if segment_address > cursor:
                break
            offset = cursor - segment_address
            take = min(remaining, len(raw) - offset)
            out.extend(raw[offset:offset + take])
            cursor += take
            remaining -= take
            if remaining == 0:
                return bytes(out)
        raise ReadError("offline_snapshot_read_unmapped")

    read_code = read


def _copy_json(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False))


def _hex(value: int | None) -> str | None:
    return hex(value) if type(value) is int else None


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


def _workspace_root() -> Path:
    return Path(__file__).resolve().parents[2]


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
        raise ProfileError(f"{label}_read_size_changed:{label}")
    return raw


def _source_evidence(profile: Mapping[str, Any], *, offline_legacy_archive: bool = False) -> list[dict[str, Any]]:
    if type(offline_legacy_archive) is not bool:
        raise ProfileError("offline_archive_flag_invalid")
    items = profile.get("source_evidence")
    if not isinstance(items, list) or not items or len(items) > 8:
        raise ProfileError("source_evidence_shape_invalid")
    if offline_legacy_archive is not True and profile.get("profile_id") == LEGACY_PROFILE_ID:
        raise ProfileError("legacy_profile_offline_replay_only")
    if offline_legacy_archive is True and profile.get("profile_id") != LEGACY_PROFILE_ID:
        raise ProfileError("offline_archive_profile_identity_invalid")
    root = _workspace_root().resolve()
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, Mapping):
            raise ProfileError("source_evidence_item_invalid")
        relative = item.get("path")
        digest = item.get("sha256")
        size = item.get("bytes")
        if not isinstance(relative, str) or not relative or not isinstance(digest, str) or len(digest) != 64 or type(size) is not int or size <= 0 or size > 256 * 1024:
            raise ProfileError("source_evidence_item_invalid")
        verification_relative = relative
        if offline_legacy_archive and relative == "work/native/alliance-query.inc":
            verification_relative = LEGACY_ARCHIVE_NATIVE_SOURCE.as_posix()
        path = (root / verification_relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ProfileError("source_evidence_outside_workspace") from exc
        key = path.as_posix().lower()
        if key in seen:
            raise ProfileError("source_evidence_duplicate")
        raw = _bounded_file(path, 256 * 1024, "source_evidence")
        if len(raw) != size or hashlib.sha256(raw).hexdigest().lower() != digest.lower():
            raise ProfileError("source_evidence_sha256_mismatch")
        seen.add(key)
        entry = {"path": relative, "sha256": digest.lower(), "bytes": size, "role": item.get("role")}
        if verification_relative != relative:
            entry["verified_from_archive_path"] = verification_relative
        result.append(entry)
    return result


def _profile_layout(profile: Mapping[str, Any]) -> dict[str, int]:
    raw = profile.get("layout")
    if not isinstance(raw, Mapping):
        raise ProfileError("profile_layout_missing")
    expected = {
        "country_tasks_offset": 0x1480,
        "holder_manager_offset": 0x18,
        "vector_begin_offset": 0x20,
        "vector_end_offset": 0x28,
        "entry_stride": 8,
        "entry_record_offset": 0x10,
        "entry_state_offset": 0x18,
        "entry_id_offset": 0x44,
        "record_actor_offset": 0x80,
        "record_recipient_offset": 0x88,
        "record_selector_offset": 0xA8,
        "record_date_begin_offset": 0x20,
        "record_date_end_offset": 0x24,
        "record_raw_unknown_offset": 0x2C,
        "database_global_rva": 0x233D8B0,
        "database_table_offset": 0x118,
        "database_table_count_offset": 0x124,
        "database_max_slots": 4095,
        "country_fullref_offset": 0x20,
        "game_global_rva": 0x233FE58,
        "game_date_offset": 0x1DD0,
        "pointer_min": 0x10000,
        "pointer_max": MAX_USER_ADDRESS,
    }
    parsed: dict[str, int] = {}
    for key, expected_value in expected.items():
        value = _parse_int(raw.get(key), f"layout.{key}")
        if value != expected_value:
            raise ProfileError(f"profile_layout_value_invalid:{key}")
        parsed[key] = value
    return parsed


def _profile_code_guards(profile: Mapping[str, Any]) -> list[tuple[str, int, int, bytes]]:
    raw_guards = profile.get("code_guards")
    if not isinstance(raw_guards, list) or not raw_guards:
        raise ProfileError("profile_code_guards_shape_invalid")
    result: list[tuple[str, int, int, bytes]] = []
    names: set[str] = set()
    total = 0
    for item in raw_guards:
        if not isinstance(item, Mapping):
            raise ProfileError("profile_code_guard_invalid")
        name = item.get("name")
        if not isinstance(name, str) or not name or name in names:
            raise ProfileError("profile_code_guard_name_invalid")
        begin = _parse_int(item.get("rva"), f"code_guard.{name}.rva")
        end = _parse_int(item.get("rva_end_exclusive"), f"code_guard.{name}.end")
        try:
            raw = bytes.fromhex(str(item.get("hex", "")))
        except ValueError as exc:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}") from exc
        if not raw or end != begin + len(raw) or hashlib.sha256(raw).hexdigest().lower() != str(item.get("sha256", "")).lower() or item.get("aslr_invariant") is not True:
            raise ProfileError(f"profile_code_guard_range_or_sha_invalid:{name}")
        total += len(raw)
        if total > READ_BUDGET_BYTES:
            raise ProfileError("profile_code_guards_budget_invalid")
        names.add(name)
        result.append((name, begin, end, raw))
    return result


def _profile_spec(profile: Mapping[str, Any]) -> tuple[str, str, Path, int]:
    profile_id = profile.get("profile_id")
    spec = _PROFILE_PINS.get(profile_id) if isinstance(profile_id, str) else None
    if spec is None:
        raise ProfileError("profile_identity_unknown")
    expected_sha256, path, version = spec
    return profile_id, expected_sha256, path, version


def _validate_profile_shape(profile: Mapping[str, Any], *, offline_legacy_archive: bool = False) -> None:
    if type(offline_legacy_archive) is not bool:
        raise ProfileError("offline_archive_flag_invalid")
    profile_id, _expected_sha256, _path, profile_version = _profile_spec(profile)
    if profile_id == LEGACY_PROFILE_ID and offline_legacy_archive is not True:
        raise ProfileError("legacy_profile_offline_replay_only")
    if offline_legacy_archive is True and profile_id != LEGACY_PROFILE_ID:
        raise ProfileError("offline_archive_profile_identity_invalid")
    if profile.get("profile_version") != profile_version or profile.get("game_version") != EXPECTED_VERSION:
        raise ProfileError("profile_shape_invalid")
    exe = profile.get("executable")
    if not isinstance(exe, Mapping) or str(exe.get("sha256", "")).lower() != EXPECTED_EXE_SHA256:
        raise ProfileError("profile_executable_mismatch")
    _source_evidence(profile, offline_legacy_archive=offline_legacy_archive)
    layout = _profile_layout(profile)
    limits = profile.get("limits")
    if not isinstance(limits, Mapping) or _parse_int(limits.get("max_total_rpm"), "limits.max_total_rpm") != MAX_TOTAL_RPM or _parse_int(limits.get("max_single_rpm"), "limits.max_single_rpm") != MAX_SINGLE_RPM or _parse_int(limits.get("max_entries"), "limits.max_entries") != 256:
        raise ProfileError("profile_limits_invalid")
    semantics = profile.get("semantics")
    if not isinstance(semantics, Mapping) or semantics.get("field") != FIELD_KEY or semantics.get("basis") != BASIS or semantics.get("value_origin") != VALUE_ORIGIN or semantics.get("unit") != UNIT or semantics.get("scale") != SCALE or semantics.get("period") != PERIOD or semantics.get("complete") is not False or semantics.get("partial") is not True:
        raise ProfileError("profile_semantics_invalid")
    if semantics.get("known_selector", {}).get("value") != KNOWN_SELECTOR:
        raise ProfileError("profile_selector_semantics_invalid")
    _profile_code_guards(profile)
    if layout["vector_end_offset"] <= layout["vector_begin_offset"]:
        raise ProfileError("profile_vector_offsets_invalid")


def _read_pinned_profile(path: Path, expected: str, *, offline_legacy_archive: bool) -> dict[str, Any]:
    raw = _bounded_file(path, PROFILE_MAX_BYTES, "profile")
    if hashlib.sha256(raw).hexdigest().lower() != expected.lower():
        raise ProfileError("profile_sha256_mismatch")
    try:
        profile = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"profile_json_invalid:{exc}") from exc
    if not isinstance(profile, dict):
        raise ProfileError("profile_json_shape_invalid")
    profile_id, profile_sha256, expected_path, _profile_version = _profile_spec(profile)
    if profile_id == LEGACY_PROFILE_ID:
        if not offline_legacy_archive or path.resolve() != expected_path.resolve() or expected.lower() != profile_sha256.lower():
            raise ProfileError("legacy_profile_offline_replay_only")
    elif offline_legacy_archive or path.resolve() != expected_path.resolve() or expected.lower() != profile_sha256.lower():
        raise ProfileError("profile_selection_invalid")
    _validate_profile_shape(profile, offline_legacy_archive=offline_legacy_archive)
    profile["_validated_source_evidence"] = _source_evidence(profile, offline_legacy_archive=offline_legacy_archive)
    profile["_validated_profile_sha256"] = profile_sha256
    profile["_offline_legacy_archive"] = offline_legacy_archive
    return profile


def _load_profile(path: Path | None = None, expected_sha256: str | None = None) -> dict[str, Any]:
    selected_path = PROFILE_FILE if path is None else Path(path)
    expected = EXPECTED_PROFILE_SHA256 if expected_sha256 is None else expected_sha256
    if selected_path.resolve() != PROFILE_FILE.resolve() or not isinstance(expected, str) or expected.lower() != EXPECTED_PROFILE_SHA256.lower():
        raise ProfileError("profile_selection_invalid")
    return _read_pinned_profile(PROFILE_FILE, EXPECTED_PROFILE_SHA256, offline_legacy_archive=False)


def _load_legacy_archive_profile() -> dict[str, Any]:
    """Load v1 only against the retained pre-change source, for offline replay."""
    return _read_pinned_profile(LEGACY_PROFILE_FILE, LEGACY_PROFILE_SHA256, offline_legacy_archive=True)


def _prepare_profile(profile: Mapping[str, Any], *, offline_legacy_archive: bool = False) -> dict[str, Any]:
    if type(offline_legacy_archive) is not bool:
        raise ProfileError("offline_archive_flag_invalid")
    if not isinstance(profile, Mapping):
        raise ProfileError("profile_argument_invalid")
    profile_id, expected_sha256, path, _profile_version = _profile_spec(profile)
    if profile_id == LEGACY_PROFILE_ID:
        if offline_legacy_archive is not True or profile.get("_validated_profile_sha256") != expected_sha256 or profile.get("_offline_legacy_archive") is not True:
            raise ProfileError("legacy_profile_offline_replay_only")
    elif offline_legacy_archive is True or profile.get("_validated_profile_sha256") != expected_sha256 or profile.get("_offline_legacy_archive") is not False:
        raise ProfileError("profile_selection_invalid")
    pinned = _read_pinned_profile(path, expected_sha256, offline_legacy_archive=offline_legacy_archive)
    supplied_content = {key: value for key, value in profile.items() if not str(key).startswith("_")}
    pinned_content = {key: value for key, value in pinned.items() if not str(key).startswith("_")}
    if supplied_content != pinned_content:
        raise ProfileError("profile_content_mismatch")
    return pinned


def _static_contract_guard(profile: Mapping[str, Any] | None = None, *, offline_legacy_archive: bool = False) -> dict[str, Any]:
    loaded = None
    result: dict[str, Any] = {
        "status": "unknown",
        "evidence_kind": "ordinary_bounded_layout_and_selector_evidence",
        "profile": str(PROFILE_FILE),
        "profile_id": EXPECTED_PROFILE_ID,
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "source_evidence": [],
        "checks": {},
        "unknown_conditions": [],
    }
    try:
        if profile is None:
            if offline_legacy_archive:
                raise ProfileError("offline_archive_profile_must_be_explicit")
            loaded = _load_profile()
        else:
            loaded = _prepare_profile(profile, offline_legacy_archive=offline_legacy_archive)
        profile_id, profile_sha256, profile_path, profile_version = _profile_spec(loaded)
        result.update({"profile": str(profile_path), "profile_id": profile_id, "profile_sha256": profile_sha256})
        layout = _profile_layout(loaded)
        guards = _profile_code_guards(loaded)
        sources = loaded.get("_validated_source_evidence")
        if sources is None:
            sources = _source_evidence(loaded, offline_legacy_archive=offline_legacy_archive)
        result["source_evidence"] = _copy_json(sources)
        result["checks"] = {
            "profile_id": loaded.get("profile_id") == profile_id,
            "profile_version": loaded.get("profile_version") == profile_version,
            "game_version": loaded.get("game_version") == EXPECTED_VERSION,
            "game_sha256": str(loaded.get("executable", {}).get("sha256", "")).lower() == EXPECTED_EXE_SHA256,
            "layout": layout["country_tasks_offset"] == 0x1480 and layout["entry_record_offset"] == 0x10 and layout["entry_state_offset"] == 0x18 and layout["entry_id_offset"] == 0x44 and layout["record_actor_offset"] == 0x80 and layout["record_recipient_offset"] == 0x88 and layout["record_selector_offset"] == 0xA8,
            "fullref_table": layout["database_table_offset"] == 0x118 and layout["database_table_count_offset"] == 0x124 and layout["country_fullref_offset"] == 0x20 and layout["database_max_slots"] == 4095,
            "state_contract": loaded.get("semantics", {}).get("state_enum") == {"0": "idle", "1": "returning", "2": "active"},
            "selector_contract": loaded.get("semantics", {}).get("known_selector", {}).get("value") == KNOWN_SELECTOR,
            "code_guards": bool(guards),
            "source_evidence": bool(sources),
        }
        failed = [key for key, value in result["checks"].items() if value is not True]
        if failed:
            result["unknown_conditions"].append("profile_contract_failed:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except Exception as exc:
        result["unknown_conditions"].append(f"profile_contract_read_failed:{type(exc).__name__}:{exc}")
    return result


def _file_code_guard(path: Path, profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "path": str(path), "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        for name, rva, end, expected in _profile_code_guards(profile or _load_profile()):
            actual = _read_pe_rva_bytes(path, rva, len(expected))
            result["records"][name] = {"rva": hex(rva), "rva_end_exclusive": hex(end), "expected_hex": expected.hex(), "actual_hex": actual.hex(), "expected_sha256": hashlib.sha256(expected).hexdigest(), "actual_sha256": hashlib.sha256(actual).hexdigest()}
            result["checks"][name] = actual == expected
        if all(result["checks"].values()) and result["checks"]:
            result["status"] = "observed"
        else:
            result["unknown_conditions"].append("file_code_guard_mismatch")
    except Exception as exc:
        result["unknown_conditions"].append(f"file_code_guard_failed:{type(exc).__name__}:{exc}")
    return result


class _ReadBudget:
    def __init__(self, limit: int = READ_BUDGET_BYTES):
        self.limit = limit
        self.used = 0
        self.reads: list[dict[str, Any]] = []

    def reserve(self, size: int) -> None:
        if type(size) is not int or size <= 0 or self.used + size > self.limit:
            raise ReadError("read_budget_exceeded")
        self.used += size

    def snapshot(self) -> dict[str, Any]:
        return {"bytes_reserved": self.used, "limit": self.limit}


def _valid_address(value: Any, layout: Mapping[str, int]) -> bool:
    return type(value) is int and layout["pointer_min"] <= value <= layout["pointer_max"]


def _add_address(base: int, offset: int, layout: Mapping[str, int]) -> int:
    if not _valid_address(base, layout) or type(offset) is not int or offset < 0:
        raise ReadError("pointer_arithmetic_invalid")
    address = base + offset
    if not _valid_address(address, layout):
        raise ReadError("pointer_arithmetic_invalid")
    return address


def _reader_read(reader: Any, address: int, size: int, label: str, budget: _ReadBudget, layout: Mapping[str, int]) -> bytes:
    if not _valid_address(address, layout):
        raise ReadError(f"address_invalid:{label}")
    budget.reserve(size)
    method = getattr(reader, "read", None)
    if not callable(method):
        budget.reads.append({"address": _hex(address), "size": size, "label": label, "status": "failed"})
        raise ReadError("reader_read_method_missing")
    try:
        raw = method(address, size, label)
    except Exception as exc:
        budget.reads.append({"address": _hex(address), "size": size, "label": label, "status": "failed", "error": type(exc).__name__})
        raise ReadError(f"read_failed:{label}:{type(exc).__name__}:{exc}") from exc
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != size:
        budget.reads.append({"address": _hex(address), "size": size, "label": label, "status": "failed", "error": "short_or_invalid_read"})
        raise ReadError(f"short_or_invalid_read:{label}")
    raw = bytes(raw)
    budget.reads.append({"address": _hex(address), "size": size, "label": label, "status": "ok", "raw_hex": raw.hex(), "sha256": hashlib.sha256(raw).hexdigest()})
    return raw


def _read_u64(reader: Any, address: int, label: str, budget: _ReadBudget, layout: Mapping[str, int]) -> tuple[int, bytes]:
    raw = _reader_read(reader, address, 8, label, budget, layout)
    return int.from_bytes(raw, "little", signed=False), raw


def _read_i32(reader: Any, address: int, label: str, budget: _ReadBudget, layout: Mapping[str, int]) -> tuple[int, bytes]:
    raw = _reader_read(reader, address, 4, label, budget, layout)
    return int.from_bytes(raw, "little", signed=True), raw


def _runtime_code_guard(reader: Any, module_base: int, profile: Mapping[str, Any], budget: _ReadBudget) -> dict[str, Any]:
    start = len(budget.reads)
    result: dict[str, Any] = {"status": "unknown", "module_base": _hex(module_base), "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        if profile.get("profile_id") == LEGACY_PROFILE_ID and (type(reader) is not OfflineArchiveSnapshotReader or profile.get("_offline_legacy_archive") is not True):
            raise ProfileError("legacy_offline_snapshot_reader_required")
        layout = _profile_layout(profile)
        for name, rva, end, expected in _profile_code_guards(profile):
            address = _add_address(module_base, rva, layout)
            budget.reserve(len(expected))
            method = getattr(reader, "read_code", None) or getattr(reader, "read")
            raw = method(address, len(expected), f"diplomat_tasks.code.{name}")
            if not isinstance(raw, (bytes, bytearray)) or len(raw) != len(expected):
                raise ReadError(f"code_guard_short:{name}")
            raw = bytes(raw)
            budget.reads.append({"address": _hex(address), "size": len(expected), "label": f"diplomat_tasks.code.{name}", "status": "ok", "raw_hex": raw.hex(), "sha256": hashlib.sha256(raw).hexdigest()})
            result["records"][name] = {"rva": hex(rva), "rva_end_exclusive": hex(end), "address": _hex(address), "expected_hex": expected.hex(), "actual_hex": raw.hex(), "expected_sha256": hashlib.sha256(expected).hexdigest(), "actual_sha256": hashlib.sha256(raw).hexdigest()}
            result["checks"][name] = raw == expected
        failed = [name for name, ok in result["checks"].items() if ok is not True]
        if failed:
            result["unknown_conditions"].append("runtime_code_guard_mismatch:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except Exception as exc:
        result["unknown_conditions"].append(f"runtime_code_guard_failed:{type(exc).__name__}:{exc}")
    result["bytes_reserved"] = budget.used
    result["limit"] = budget.limit
    result["read_log"] = _copy_json(budget.reads[start:])
    return result


def _tag_from_fullref(fullref: int) -> str | None:
    raw = (fullref & 0xFFFFFF).to_bytes(3, "little")
    if not all(0x30 <= item <= 0x39 or 0x41 <= item <= 0x5A for item in raw):
        return None
    return raw.decode("ascii")


def _resolve_fullref(reader: Any, fullref: int, *, role: str, module_base: int, profile: Mapping[str, Any], budget: _ReadBudget, cache: dict[int, dict[str, Any]]) -> dict[str, Any]:
    if fullref in cache:
        cached = deepcopy(cache[fullref])
        cached["role"] = role
        return cached
    layout = _profile_layout(profile)
    result: dict[str, Any] = {"status": "unknown", "role": role, "raw": fullref, "raw_hex": fullref.to_bytes(8, "little").hex(), "slot": (fullref >> 32) & 0xFFFF, "tag_candidate": _tag_from_fullref(fullref), "country_pointer": None, "country_fullref_raw_hex": None, "reason": None}
    if fullref == 0:
        result["reason"] = "fullref_zero"
        cache[fullref] = result
        return deepcopy(result)
    slot = result["slot"]
    if slot > layout["database_max_slots"]:
        result["reason"] = "fullref_slot_out_of_range"
        cache[fullref] = result
        return deepcopy(result)
    try:
        database, database_raw = _read_u64(reader, _add_address(module_base, layout["database_global_rva"], layout), "diplomat_tasks.fullref.database", budget, layout)
        result["database_raw_hex"] = database_raw.hex()
        if not _valid_address(database, layout):
            result["reason"] = "database_pointer_invalid"
            cache[fullref] = result
            return deepcopy(result)
        table, table_raw = _read_u64(reader, _add_address(database, layout["database_table_offset"], layout), "diplomat_tasks.fullref.table", budget, layout)
        result["table_raw_hex"] = table_raw.hex()
        if not _valid_address(table, layout):
            result["reason"] = "country_table_pointer_invalid"
            cache[fullref] = result
            return deepcopy(result)
        country_count, country_count_raw = _read_i32(reader, _add_address(database, layout["database_table_count_offset"], layout), "diplomat_tasks.fullref.country_count", budget, layout)
        result["country_count"] = country_count
        result["country_count_raw_hex"] = country_count_raw.hex()
        if not 1 <= country_count <= layout["database_max_slots"] + 1:
            result["reason"] = "country_count_invalid"
            cache[fullref] = result
            return deepcopy(result)
        if slot >= country_count:
            result["reason"] = "fullref_slot_not_in_country_count"
            cache[fullref] = result
            return deepcopy(result)
        entry, entry_raw = _read_u64(reader, _add_address(table, slot * 8, layout), f"diplomat_tasks.fullref.slot[{slot}]", budget, layout)
        result["country_entry_raw_hex"] = entry_raw.hex()
        if not _valid_address(entry, layout):
            result["reason"] = "country_entry_pointer_invalid"
            cache[fullref] = result
            return deepcopy(result)
        country_fullref, country_fullref_raw = _read_u64(reader, _add_address(entry, layout["country_fullref_offset"], layout), "diplomat_tasks.fullref.country_fullref", budget, layout)
        result["country_pointer"] = _hex(entry)
        result["country_fullref_raw_hex"] = country_fullref_raw.hex()
        if country_fullref != fullref:
            result["reason"] = "country_fullref_mismatch"
            cache[fullref] = result
            return deepcopy(result)
        tag = result.get("tag_candidate")
        if not isinstance(tag, str):
            result["reason"] = "fullref_tag_candidate_invalid"
            cache[fullref] = result
            return deepcopy(result)
        result["status"] = "known"
        result["tag"] = tag
    except Exception as exc:
        result["reason"] = f"fullref_lookup_failed:{type(exc).__name__}:{exc}"
    cache[fullref] = result
    return deepcopy(result)


def _task_item(entry_address: int, entry_raw: bytes, record: int, record_raw: bytes, state: int, state_raw: bytes, raw_id: int, raw_id_bytes: bytes, *, reader: Any, module_base: int, profile: Mapping[str, Any], budget: _ReadBudget, fullref_cache: dict[int, dict[str, Any]], layout: Mapping[str, int]) -> dict[str, Any]:
    item: dict[str, Any] = {
        "status": "known",
        "entry_address": _hex(entry_address),
        "entry_pointer_raw_hex": entry_raw.hex(),
        "record_address": _hex(record) if record else None,
        "record_pointer_raw_hex": record_raw.hex(),
        "state_raw_18": state,
        "state_raw_18_hex": state_raw.hex(),
        "state": KNOWN_STATE_NAMES.get(state),
        "state_status": "known" if state in KNOWN_STATE_NAMES else "unknown",
        "raw_id_44": raw_id,
        "raw_id_44_hex": raw_id_bytes.hex(),
        "raw_action_type_a8": None,
        "raw_action_type_a8_hex": None,
        "task_family": None,
        "task_family_status": "unknown",
        "actor_fullref_raw": None,
        "actor_fullref_raw_hex": None,
        "recipient_fullref_raw": None,
        "recipient_fullref_raw_hex": None,
        "actor": None,
        "recipient": None,
        "actor_resolution": None,
        "recipient_resolution": None,
        "lifecycle_date_raw": None,
        "raw_2c": None,
        "raw_2c_hex": None,
        "raw_2c_semantics": "unknown",
    }
    if not record:
        return item
    actor, actor_raw = _read_u64(reader, _add_address(record, layout["record_actor_offset"], layout), "diplomat_tasks.record.actor", budget, layout)
    recipient, recipient_raw = _read_u64(reader, _add_address(record, layout["record_recipient_offset"], layout), "diplomat_tasks.record.recipient", budget, layout)
    selector, selector_raw = _read_i32(reader, _add_address(record, layout["record_selector_offset"], layout), "diplomat_tasks.record.selector", budget, layout)
    date_begin, date_begin_raw = _read_i32(reader, _add_address(record, layout["record_date_begin_offset"], layout), "diplomat_tasks.record.date_begin", budget, layout)
    date_end, date_end_raw = _read_i32(reader, _add_address(record, layout["record_date_end_offset"], layout), "diplomat_tasks.record.date_end", budget, layout)
    raw_2c, raw_2c_bytes = _read_i32(reader, _add_address(record, layout["record_raw_unknown_offset"], layout), "diplomat_tasks.record.raw_2c", budget, layout)
    actor_resolution = _resolve_fullref(reader, actor, role="actor", module_base=module_base, profile=profile, budget=budget, cache=fullref_cache)
    recipient_resolution = _resolve_fullref(reader, recipient, role="recipient", module_base=module_base, profile=profile, budget=budget, cache=fullref_cache)
    if actor_resolution.get("status") != "known" or recipient_resolution.get("status") != "known":
        raise ReadError("record_fullref_identity_unverified")
    item.update({
        "actor_fullref_raw": actor,
        "actor_fullref_raw_hex": actor_raw.hex(),
        "recipient_fullref_raw": recipient,
        "recipient_fullref_raw_hex": recipient_raw.hex(),
        "actor": actor_resolution.get("tag"),
        "recipient": recipient_resolution.get("tag"),
        "actor_resolution": actor_resolution,
        "recipient_resolution": recipient_resolution,
        "raw_action_type_a8": selector,
        "raw_action_type_a8_hex": selector_raw.hex(),
        "task_family": KNOWN_SELECTOR_FAMILY if selector == KNOWN_SELECTOR else None,
        "task_family_status": "known" if selector == KNOWN_SELECTOR else "unknown",
        "lifecycle_date_raw": {"raw_20": date_begin, "raw_20_hex": date_begin_raw.hex(), "raw_24": date_end, "raw_24_hex": date_end_raw.hex(), "semantics": "lifecycle_date_raw"},
        "raw_2c": raw_2c,
        "raw_2c_hex": raw_2c_bytes.hex(),
        "raw_2c_semantics": "unknown",
    })
    return item


def _raw_projection(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "entry_pointer_raw_hex": item.get("entry_pointer_raw_hex"),
        "record_pointer_raw_hex": item.get("record_pointer_raw_hex"),
        "state_raw_18_hex": item.get("state_raw_18_hex"),
        "raw_id_44_hex": item.get("raw_id_44_hex"),
        "raw_action_type_a8_hex": item.get("raw_action_type_a8_hex"),
        "actor_fullref_raw_hex": item.get("actor_fullref_raw_hex"),
        "recipient_fullref_raw_hex": item.get("recipient_fullref_raw_hex"),
        "raw_20_hex": (item.get("lifecycle_date_raw") or {}).get("raw_20_hex") if isinstance(item.get("lifecycle_date_raw"), Mapping) else None,
        "raw_24_hex": (item.get("lifecycle_date_raw") or {}).get("raw_24_hex") if isinstance(item.get("lifecycle_date_raw"), Mapping) else None,
        "raw_2c_hex": item.get("raw_2c_hex"),
    }


def _read_task_graph(reader: Any, module_base: int, country_pointer: int, profile: Mapping[str, Any], budget: _ReadBudget) -> dict[str, Any]:
    layout = _profile_layout(profile)
    root_address = _add_address(country_pointer, layout["country_tasks_offset"], layout)
    holder, holder_raw = _read_u64(reader, root_address, "diplomat_tasks.country.tasks_holder", budget, layout)
    if not _valid_address(holder, layout):
        raise ReadError("diplomat_tasks_holder_invalid")
    manager, manager_raw = _read_u64(reader, _add_address(holder, layout["holder_manager_offset"], layout), "diplomat_tasks.holder.manager", budget, layout)
    if not _valid_address(manager, layout):
        raise ReadError("diplomat_tasks_manager_invalid")
    begin, begin_raw = _read_u64(reader, _add_address(manager, layout["vector_begin_offset"], layout), "diplomat_tasks.vector.begin", budget, layout)
    end, end_raw = _read_u64(reader, _add_address(manager, layout["vector_end_offset"], layout), "diplomat_tasks.vector.end", budget, layout)
    if (begin == 0) != (end == 0) or begin and (not _valid_address(begin, layout) or not _valid_address(end, layout) or end < begin or (end - begin) % layout["entry_stride"] != 0 or (end - begin) // layout["entry_stride"] > 256):
        raise ReadError("diplomat_tasks_vector_invalid")
    count = 0 if begin == 0 else (end - begin) // layout["entry_stride"]
    entries: list[dict[str, Any]] = []
    fullref_cache: dict[int, dict[str, Any]] = {}
    for index in range(count):
        address = begin + index * layout["entry_stride"]
        entry, entry_raw = _read_u64(reader, address, f"diplomat_tasks.entry[{index}]", budget, layout)
        if entry == 0:
            raise ReadError("diplomat_tasks_entry_pointer_null")
        if not _valid_address(entry, layout):
            raise ReadError("diplomat_tasks_entry_pointer_invalid")
        record, record_raw = _read_u64(reader, _add_address(entry, layout["entry_record_offset"], layout), f"diplomat_tasks.entry[{index}].record", budget, layout)
        state_raw = _reader_read(reader, _add_address(entry, layout["entry_state_offset"], layout), 1, f"diplomat_tasks.entry[{index}].state", budget, layout)
        raw_id, raw_id_bytes = _read_i32(reader, _add_address(entry, layout["entry_id_offset"], layout), f"diplomat_tasks.entry[{index}].id", budget, layout)
        entries.append(_task_item(entry, entry_raw, record, record_raw, state_raw[0], state_raw, raw_id, raw_id_bytes, reader=reader, module_base=module_base, profile=profile, budget=budget, fullref_cache=fullref_cache, layout=layout))
    field = {"status": "known", "complete": False, "partial": True, "value": entries, "unit": UNIT, "scale": SCALE, "period": PERIOD, "basis": BASIS, "value_origin": VALUE_ORIGIN}
    compact = [{"entry_address": item.get("entry_address"), "record_address": item.get("record_address"), "state_raw_18_hex": item.get("state_raw_18_hex"), "raw_id_44_hex": item.get("raw_id_44_hex"), "raw_action_type_a8_hex": item.get("raw_action_type_a8_hex"), "actor_fullref_raw_hex": item.get("actor_fullref_raw_hex"), "recipient_fullref_raw_hex": item.get("recipient_fullref_raw_hex"), "raw_20_hex": (item.get("lifecycle_date_raw") or {}).get("raw_20_hex") if isinstance(item.get("lifecycle_date_raw"), Mapping) else None, "raw_24_hex": (item.get("lifecycle_date_raw") or {}).get("raw_24_hex") if isinstance(item.get("lifecycle_date_raw"), Mapping) else None, "raw_2c_hex": item.get("raw_2c_hex")} for item in entries]
    return {"status": "observed", "fields": {FIELD_KEY: field}, "values": {FIELD_KEY: entries}, "raw_hex": {FIELD_KEY: [_raw_projection(item) for item in entries]}, "raw_bytes_hex": {FIELD_KEY: [_raw_projection(item) for item in entries]}, "observation": {"country_tasks_address": _hex(root_address), "country_tasks_offset": hex(layout["country_tasks_offset"]), "holder": _hex(holder), "holder_raw_hex": holder_raw.hex(), "manager": _hex(manager), "manager_raw_hex": manager_raw.hex(), "vector_begin": _hex(begin) if begin else None, "vector_begin_raw_hex": begin_raw.hex(), "vector_end": _hex(end) if end else None, "vector_end_raw_hex": end_raw.hex(), "entry_count": count, "entries": compact, "read_budget": budget.snapshot(), "read_log": _copy_json(budget.reads)}, "instance_count_observed": count, "complete": False}


def read_fields(reader: Any, module_base: int, country_pointer: int, profile: Mapping[str, Any] | None = None, *, offline_legacy_archive: bool = False) -> dict[str, Any]:
    """Copy the bounded task graph; v1 is accepted only for explicit archive replay."""
    if type(offline_legacy_archive) is not bool:
        return _unknown_record("offline_archive_flag_invalid", module_base=module_base if type(module_base) is int else None, country_pointer=country_pointer if type(country_pointer) is int else None)
    legacy_requested = offline_legacy_archive or (isinstance(profile, Mapping) and profile.get("profile_id") == LEGACY_PROFILE_ID)
    if legacy_requested and type(reader) is not OfflineArchiveSnapshotReader:
        return _unknown_record("legacy_offline_snapshot_reader_required", module_base=module_base if type(module_base) is int else None, country_pointer=country_pointer if type(country_pointer) is int else None)
    module_value = module_base if type(module_base) is int else None
    country_value = country_pointer if type(country_pointer) is int else None
    loaded: dict[str, Any] | None = None
    try:
        if profile is None:
            if offline_legacy_archive:
                raise ProfileError("offline_archive_profile_must_be_explicit")
            loaded = _load_profile()
        else:
            loaded = _prepare_profile(profile, offline_legacy_archive=offline_legacy_archive)
        static_guard = _static_contract_guard(loaded, offline_legacy_archive=offline_legacy_archive)
    except Exception as exc:
        return _unknown_record(f"static_contract_guard_failed:{type(exc).__name__}:{exc}", module_base=module_value, country_pointer=country_value, profile=loaded)
    if static_guard.get("status") != "observed":
        return _unknown_record("static_contract_guard_failed", static_guard=static_guard, module_base=module_value, country_pointer=country_value, profile=loaded)
    profile_id, profile_sha256, _profile_path = _profile_identity(loaded)
    layout = _profile_layout(loaded)
    if not _valid_address(module_base, layout) or not _valid_address(country_pointer, layout):
        return _unknown_record("pointer_invalid", static_guard=static_guard, module_base=module_value, country_pointer=country_value, profile=loaded)
    budget = _ReadBudget()
    runtime_guard = _runtime_code_guard(reader, module_base, loaded, budget)
    if runtime_guard.get("status") != "observed":
        return _unknown_record("runtime_code_guard_failed", static_guard=static_guard, runtime_guard=runtime_guard, module_base=module_base, country_pointer=country_pointer, read_budget=budget.snapshot(), read_log=budget.reads, profile=loaded)
    try:
        result = _read_task_graph(reader, module_base, country_pointer, loaded, budget)
    except Exception as exc:
        return _unknown_record(f"task_graph_read_failed:{type(exc).__name__}:{exc}", static_guard=static_guard, runtime_guard=runtime_guard, module_base=module_base, country_pointer=country_pointer, read_budget=budget.snapshot(), read_log=budget.reads, profile=loaded)
    result.update({"profile_id": profile_id, "profile_sha256": profile_sha256, "module_base": _hex(module_base), "country_pointer": _hex(country_pointer), "static_contract_guard": static_guard, "runtime_code_guard": runtime_guard, "basis": BASIS, "unit": UNIT, "scale": SCALE, "period": PERIOD, "value_origin": VALUE_ORIGIN})
    result["observation"]["profile_id"] = profile_id
    result["observation"]["profile_sha256"] = profile_sha256
    result["observation"]["module_base"] = _hex(module_base)
    result["observation"]["country_pointer"] = _hex(country_pointer)
    result["observation"]["basis"] = BASIS
    result["observation"]["unit"] = UNIT
    result["observation"]["scale"] = SCALE
    result["observation"]["period"] = PERIOD
    result["observation"]["value_origin"] = VALUE_ORIGIN
    result["observation"]["static_contract_guard"] = _copy_json(static_guard)
    result["observation"]["runtime_code_guard"] = _copy_json(runtime_guard)
    return result


def _unknown_field(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason, "complete": False, "partial": True, "value": None, "unit": UNIT, "scale": SCALE, "period": PERIOD, "basis": BASIS, "value_origin": VALUE_ORIGIN}


def _profile_identity(profile: Mapping[str, Any] | None = None) -> tuple[str, str, Path]:
    if profile is None:
        return EXPECTED_PROFILE_ID, EXPECTED_PROFILE_SHA256, PROFILE_FILE
    profile_id, profile_sha256, path, _version = _profile_spec(profile)
    return profile_id, profile_sha256, path


def _unknown_record(reason: str, *, static_guard: Mapping[str, Any] | None = None, runtime_guard: Mapping[str, Any] | None = None, module_base: int | None = None, country_pointer: int | None = None, read_budget: Mapping[str, Any] | None = None, read_log: list[Mapping[str, Any]] | None = None, profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
    profile_id, profile_sha256, _profile_path = _profile_identity(profile)
    observation = {"profile_id": profile_id, "profile_sha256": profile_sha256, "module_base": _hex(module_base), "country_pointer": _hex(country_pointer), "basis": BASIS, "unit": UNIT, "scale": SCALE, "period": PERIOD, "value_origin": VALUE_ORIGIN, "static_contract_guard": _copy_json(static_guard) if isinstance(static_guard, Mapping) else None, "runtime_code_guard": _copy_json(runtime_guard) if isinstance(runtime_guard, Mapping) else None, "read_budget": _copy_json(read_budget) if isinstance(read_budget, Mapping) else {"bytes_reserved": 0, "limit": READ_BUDGET_BYTES}, "read_log": _copy_json(read_log) if isinstance(read_log, list) else []}
    return {"status": "unknown", "reason": reason, "profile_id": profile_id, "profile_sha256": profile_sha256, "module_base": _hex(module_base), "country_pointer": _hex(country_pointer), "static_contract_guard": _copy_json(static_guard) if isinstance(static_guard, Mapping) else None, "runtime_code_guard": _copy_json(runtime_guard) if isinstance(runtime_guard, Mapping) else None, "fields": {FIELD_KEY: _unknown_field(reason)}, "values": None, "raw_hex": None, "raw_bytes_hex": None, "basis": BASIS, "unit": UNIT, "scale": SCALE, "period": PERIOD, "value_origin": VALUE_ORIGIN, "observation": observation, "complete": False, "instance_count_observed": None}


def _find_country(reader: Any, module_base: int, country: str, profile: Mapping[str, Any], budget: _ReadBudget) -> tuple[int, dict[str, Any]]:
    layout = _profile_layout(profile)
    database, database_raw = _read_u64(reader, _add_address(module_base, layout["database_global_rva"], layout), "diplomat_tasks.country.database", budget, layout)
    if not _valid_address(database, layout):
        raise ReadError("country_database_invalid")
    table, table_raw = _read_u64(reader, _add_address(database, layout["database_table_offset"], layout), "diplomat_tasks.country.table", budget, layout)
    if not _valid_address(table, layout):
        raise ReadError("country_table_invalid")
    country_count, country_count_raw = _read_i32(reader, _add_address(database, layout["database_table_count_offset"], layout), "diplomat_tasks.country.count", budget, layout)
    if not 1 <= country_count <= layout["database_max_slots"] + 1:
        raise ReadError("country_count_invalid")
    matches: list[dict[str, Any]] = []
    for slot in range(country_count):
        ptr, ptr_raw = _read_u64(reader, _add_address(table, slot * 8, layout), f"diplomat_tasks.country.table[{slot}]", budget, layout)
        if not ptr:
            continue
        if not _valid_address(ptr, layout):
            raise ReadError("country_pointer_invalid")
        fullref, fullref_raw = _read_u64(reader, _add_address(ptr, layout["country_fullref_offset"], layout), f"diplomat_tasks.country.fullref[{slot}]", budget, layout)
        tag = _tag_from_fullref(fullref)
        if tag == country and ((fullref >> 32) & 0xFFFF) == slot:
            matches.append({"slot": slot, "pointer": _hex(ptr), "fullref_raw_hex": fullref_raw.hex(), "tag": tag, "table_entry_raw_hex": ptr_raw.hex()})
    if len(matches) != 1:
        raise ReadError("country_identity_match_count_invalid")
    return int(matches[0]["pointer"], 0), {"status": "observed", "database_raw_hex": database_raw.hex(), "table_raw_hex": table_raw.hex(), "country_count": country_count, "country_count_raw_hex": country_count_raw.hex(), "matches": matches, "entries": country_count}


def _snapshot(reader: Any, module_base: int, country_pointer: int, country: str, profile: Mapping[str, Any], static_guard: Mapping[str, Any], budget: _ReadBudget) -> dict[str, Any]:
    layout = _profile_layout(profile)
    runtime_guard = _runtime_code_guard(reader, module_base, profile, budget)
    if runtime_guard.get("status") != "observed":
        raise ReadError("runtime_code_guard_failed")
    game, game_raw = _read_u64(reader, _add_address(module_base, layout["game_global_rva"], layout), "diplomat_tasks.game", budget, layout)
    if not _valid_address(game, layout):
        raise ReadError("game_pointer_invalid")
    date_raw = _reader_read(reader, _add_address(game, layout["game_date_offset"], layout), 4, "diplomat_tasks.game_date", budget, layout)
    game_date = int.from_bytes(date_raw, "little", signed=True)
    graph = _read_task_graph(reader, module_base, country_pointer, profile, budget)
    profile_id, profile_sha256, _profile_path = _profile_identity(profile)
    record = {"status": "observed", "profile_id": profile_id, "profile_sha256": profile_sha256, "module_base": _hex(module_base), "country_pointer": _hex(country_pointer), "static_contract_guard": _copy_json(static_guard), "runtime_code_guard": _copy_json(runtime_guard), "fields": _copy_json(graph["fields"]), "values": _copy_json(graph["values"]), "raw_hex": _copy_json(graph["raw_hex"]), "raw_bytes_hex": _copy_json(graph["raw_bytes_hex"]), "basis": BASIS, "unit": UNIT, "scale": SCALE, "period": PERIOD, "value_origin": VALUE_ORIGIN, "observation": _copy_json(graph["observation"]), "complete": False, "instance_count_observed": graph["instance_count_observed"]}
    record["observation"].update({"profile_id": profile_id, "profile_sha256": profile_sha256, "module_base": _hex(module_base), "country_pointer": _hex(country_pointer), "game_pointer": {"value": _address(game, module_base), "raw_hex": game_raw.hex()}, "game_date": {"value": game_date, "raw_hex": date_raw.hex()}, "static_contract_guard": _copy_json(static_guard), "runtime_code_guard": _copy_json(runtime_guard), "read_budget": budget.snapshot(), "read_log": _copy_json(budget.reads)})
    return {"status": "observed", "country": country, "country_pointer": _hex(country_pointer), "game_date": {"value": game_date, "raw_hex": date_raw.hex()}, "country_scan": None, "runtime_code_guard": runtime_guard, "fields": _copy_json(graph["fields"]), "values": _copy_json(graph["values"]), "raw_hex": _copy_json(graph["raw_hex"]), "raw_bytes_hex": _copy_json(graph["raw_bytes_hex"]), "instance_count_observed": graph["instance_count_observed"], "complete": False, "record": record, "read_budget": budget.snapshot(), "read_log": _copy_json(budget.reads)}


def _unknown_snapshot(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "fields": {FIELD_KEY: _unknown_field(reason)}, "values": None, "raw_hex": None, "raw_bytes_hex": None, "instance_count_observed": None, "complete": False, "reason": reason}


def _compare_record(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: record.get(key) for key in ("status", "profile_id", "profile_sha256", "module_base", "country_pointer", "fields", "values", "raw_hex", "raw_bytes_hex", "basis", "unit", "scale", "period", "value_origin", "instance_count_observed", "complete")}


def _diff_paths(left: Any, right: Any, path: str = "$") -> list[str]:
    if type(left) is not type(right):
        return [path]
    if isinstance(left, Mapping):
        result: list[str] = []
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                result.append(f"{path}.{key}")
            else:
                result.extend(_diff_paths(left[key], right[key], f"{path}.{key}"))
        return result
    if isinstance(left, list):
        result = [] if len(left) == len(right) else [f"{path}.length"]
        for index, (a, b) in enumerate(zip(left, right)):
            result.extend(_diff_paths(a, b, f"{path}[{index}]"))
        return result
    return [] if left == right else [path]


def _module_base_hex(value: Any) -> str | None:
    """Normalize the capture address projection and child-record hex form."""
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping) and isinstance(value.get("va"), str):
        return value["va"]
    return None


def capture(installation: Path, country: str = EXPECTED_COUNTRY) -> dict[str, Any]:
    """Capture the current FRA diplomat record graph through bounded RPM."""
    installation = Path(installation)
    report: dict[str, Any] = {"probe": "information-diplomat-tasks-runtime", "probe_version": 1, "probe_script": str(Path(__file__).resolve()), "probe_script_sha256": None, "profile": {"path": str(PROFILE_FILE), "sha256": EXPECTED_PROFILE_SHA256, "profile_id": EXPECTED_PROFILE_ID, "max_bytes": PROFILE_MAX_BYTES}, "read_only": True, "native_function_invoked": False, "evidence_kind": "pure_runtime_observation_not_static_evidence", "captured_at": datetime.now(timezone.utc).isoformat(), "request": {"installation": str(installation), "country": country}, "country": country, "target_build": {"version": EXPECTED_VERSION, "expected_exe_sha256": EXPECTED_EXE_SHA256}, "static_contract_guard": None, "file_code_guard": None, "runtime_code_guard": None, "identity": {"installation_path": str(installation), "installation_pid": None, "installation_creation_filetime": None, "installation_session_id": None, "process_path": None, "process_path_sha256": None, "process_path_sha256_matches_expected": None, "process_creation_filetime": None, "process_creation_utc": None, "process_creation_matches_installation": None, "module_path": None, "module_path_matches_process": None, "binding_verified": False}, "module_base": None, "before": None, "after": None, "fields": {FIELD_KEY: _unknown_field("not_read")}, "values": None, "raw_hex": None, "raw_bytes_hex": None, "instance_count_observed": None, "complete": False, "doublepass": {"performed": False, "consistent": None, "mismatches": [], "atomic": False}, "access": {"open_process_mask": "QUERY_INFORMATION|VM_READ", "open_process_mask_hex": _hex(PROCESS_ACCESS), "rpm_total_limit": MAX_TOTAL_RPM, "rpm_single_read_limit": MAX_SINGLE_RPM, "rpm_bytes_requested": 0, "rpm_calls": 0, "native_game_calls": False, "target_memory_writes": False, "dll_injection": False, "private_heap_scan": False, "ui_control": False, "date_advance": False, "save_or_reload": False}, "cleanup": {"handle_close": {"status": "unknown", "success": None, "closed": False}}, "status": "starting", "errors": [], "completed": False}
    kernel = None
    handle = None
    reader = None
    try:
        report["probe_script_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        if country != EXPECTED_COUNTRY:
            report["status"] = "unsupported_country"
            report["errors"].append({"stage": "request", "status": "unknown", "error": "Only FRA is permitted"})
            return report
        profile = _load_profile()
        report["static_contract_guard"] = _static_contract_guard(profile)
        if report["static_contract_guard"].get("status") != "observed":
            report["status"] = "static_contract_mismatch"
            return report
        document = _load_installation(installation)
        kernel = _configure_kernel()
        handle = kernel.OpenProcess(PROCESS_ACCESS, False, int(document["pid"]))
        if not handle:
            raise OSError("OpenProcess failed")
        module_base = _capture_identity(report, document, kernel, handle)
        report["module_base"] = _address(module_base)
        process_path = Path(report["identity"]["process_path"])
        report["file_code_guard"] = _file_code_guard(process_path, profile)
        if report["file_code_guard"].get("status") != "observed":
            report["status"] = "file_code_mismatch"
            return report
        reader = AddressBoundedRPM(kernel, handle, module_base)
        country_budget = _ReadBudget()
        country_pointer, country_scan = _find_country(reader, module_base, country, profile, country_budget)
        report["country_pointer"] = _hex(country_pointer)
        first_budget = _ReadBudget()
        # Keep the country locator in the first snapshot's provenance while
        # retaining a separate child budget for the task graph itself.
        first = _snapshot(reader, module_base, country_pointer, country, profile, report["static_contract_guard"], first_budget)
        first["country_scan"] = country_scan
        report["before"] = first
        report["doublepass"]["performed"] = True
        second_budget = _ReadBudget()
        second = _snapshot(reader, module_base, country_pointer, country, profile, report["static_contract_guard"], second_budget)
        second["country_scan"] = country_scan
        report["after"] = second
        report["doublepass"]["mismatches"] = _diff_paths(_compare_record(first["record"]), _compare_record(second["record"]))
        if not dates_match(first['game_date']['value'], second['game_date']['value']):
            report['doublepass']['mismatches'].append('$.game_date')
        report["doublepass"]["consistent"] = not report["doublepass"]["mismatches"]
        report["runtime_code_guard"] = {"status": "observed", "passes": [first["runtime_code_guard"], second["runtime_code_guard"]]}
        if not report["doublepass"]["consistent"]:
            report["status"] = "doublepass_mismatch"
            report["errors"].append({"stage": "doublepass", "status": "unknown", "error": "Diplomat graph/date changed between passes", "paths": report["doublepass"]["mismatches"][:256]})
        else:
            report["status"] = "observed"
            report["fields"] = _copy_json(second["fields"])
            report["values"] = _copy_json(second["values"])
            report["raw_hex"] = _copy_json(second["raw_hex"])
            report["raw_bytes_hex"] = _copy_json(second["raw_bytes_hex"])
            report["instance_count_observed"] = second["instance_count_observed"]
            report["complete"] = False
    except Exception as exc:
        report["status"] = "error"
        report["errors"].append({"stage": "capture", "status": "unknown", "error": f"{type(exc).__name__}:{exc}"})
    finally:
        if reader is not None:
            report["access"]["rpm_bytes_requested"] = reader.bytes_requested
            report["access"]["rpm_calls"] = reader.calls
        outcome = _close_process_handle(kernel, handle)
        report["cleanup"]["handle_close"] = outcome
        if outcome.get("status") == "error":
            previous = report.get("status")
            report["status"] = "cleanup_error"
            report["errors"].append({"stage": "cleanup", "status": "error", "error": outcome.get("error", "CloseHandle failed"), "previous_status": previous})
            report["before"] = _unknown_snapshot("cleanup_failed") if report.get("before") is not None else None
            report["after"] = _unknown_snapshot("cleanup_failed") if report.get("after") is not None else None
            report["values"] = None
            report["raw_hex"] = None
            report["raw_bytes_hex"] = None
            report["fields"] = {FIELD_KEY: _unknown_field("cleanup_failed")}
    report["completed"] = report.get("status") == "observed" and report["cleanup"]["handle_close"].get("status") == "closed"
    if not report["completed"] and report.get("status") == "observed":
        report["status"] = "observation_not_completed"
        report["values"] = None
        report["fields"] = {FIELD_KEY: _unknown_field("observation_not_completed")}
    return report


def _runtime_guard_valid(guard: Any, profile: Mapping[str, Any], module_base: int) -> bool:
    if not isinstance(guard, Mapping) or guard.get("status") != "observed" or guard.get("module_base") != _hex(module_base):
        return False
    try:
        expected = {name: (begin, end, raw) for name, begin, end, raw in _profile_code_guards(profile)}
    except Exception:
        return False
    checks, records = guard.get("checks"), guard.get("records")
    if not isinstance(checks, Mapping) or not isinstance(records, Mapping) or set(checks) != set(expected) or set(records) != set(expected):
        return False
    for name, (begin, end, raw) in expected.items():
        item = records.get(name)
        if checks.get(name) is not True or not isinstance(item, Mapping) or item.get("rva") != hex(begin) or item.get("rva_end_exclusive") != hex(end) or item.get("address") != _hex(module_base + begin) or item.get("expected_hex") != raw.hex() or item.get("actual_hex") != raw.hex() or item.get("expected_sha256") != hashlib.sha256(raw).hexdigest() or item.get("actual_sha256") != hashlib.sha256(raw).hexdigest():
            return False
    logs = guard.get("read_log")
    return isinstance(logs, list) and type(guard.get("bytes_reserved")) is int and guard.get("bytes_reserved") == sum(len(raw) for _begin, _end, raw in expected.values()) and guard.get("limit") == READ_BUDGET_BYTES and all(isinstance(item, Mapping) and item.get("status") == "ok" for item in logs)


def _static_guard_valid(guard: Any, profile: Mapping[str, Any], *, offline_legacy_archive: bool = False) -> bool:
    return isinstance(guard, Mapping) and guard == _static_contract_guard(profile, offline_legacy_archive=offline_legacy_archive)


def _validate_resolution(item: Mapping[str, Any], role: str, fullref: int, layout: Mapping[str, int]) -> bool:
    resolution = item.get(f"{role}_resolution")
    if not isinstance(resolution, Mapping) or resolution.get("status") != "known" or resolution.get("role") != role or resolution.get("raw") != fullref or resolution.get("raw_hex") != fullref.to_bytes(8, "little").hex() or resolution.get("country_fullref_raw_hex") != resolution.get("raw_hex") or resolution.get("tag") != _tag_from_fullref(fullref) or resolution.get("country_pointer") is None:
        return False
    count = resolution.get("country_count")
    count_hex = resolution.get("country_count_raw_hex")
    if type(count) is not int or not 1 <= count <= layout["database_max_slots"] + 1 or fullref >> 32 & 0xFFFF >= count or not isinstance(count_hex, str) or count_hex != (count & 0xFFFFFFFF).to_bytes(4, "little").hex():
        return False
    try:
        pointer = int(str(resolution["country_pointer"]), 0)
    except (TypeError, ValueError):
        return False
    return _valid_address(pointer, layout)


def _validate_item(item: Any, layout: Mapping[str, int], module_base: int) -> bool:
    if not isinstance(item, Mapping) or item.get("status") != "known":
        return False
    try:
        entry = int(str(item.get("entry_address")), 0)
        record_raw = bytes.fromhex(str(item.get("record_pointer_raw_hex")))
        state_raw = bytes.fromhex(str(item.get("state_raw_18_hex")))
        id_raw = bytes.fromhex(str(item.get("raw_id_44_hex")))
    except (TypeError, ValueError):
        return False
    if len(record_raw) != 8 or len(state_raw) != 1 or len(id_raw) != 4 or not _valid_address(entry, layout):
        return False
    record = int.from_bytes(record_raw, "little")
    state = state_raw[0]
    if item.get("state_raw_18") != state or item.get("state") != KNOWN_STATE_NAMES.get(state) or item.get("state_status") != ("known" if state in KNOWN_STATE_NAMES else "unknown") or item.get("raw_id_44") != int.from_bytes(id_raw, "little", signed=True):
        return False
    if record == 0:
        return item.get("record_address") is None and item.get("raw_action_type_a8") is None and item.get("actor_fullref_raw") is None and item.get("recipient_fullref_raw") is None and item.get("lifecycle_date_raw") is None and item.get("raw_2c") is None
    try:
        record_address = int(str(item.get("record_address")), 0)
        actor_raw = bytes.fromhex(str(item.get("actor_fullref_raw_hex")))
        recipient_raw = bytes.fromhex(str(item.get("recipient_fullref_raw_hex")))
        selector_raw = bytes.fromhex(str(item.get("raw_action_type_a8_hex")))
        raw2c = bytes.fromhex(str(item.get("raw_2c_hex")))
        dates = item.get("lifecycle_date_raw")
    except (TypeError, ValueError):
        return False
    if not _valid_address(record_address, layout) or record_address != record or len(actor_raw) != 8 or len(recipient_raw) != 8 or len(selector_raw) != 4 or len(raw2c) != 4 or not isinstance(dates, Mapping):
        return False
    actor = int.from_bytes(actor_raw, "little")
    recipient = int.from_bytes(recipient_raw, "little")
    selector = int.from_bytes(selector_raw, "little", signed=True)
    raw2c_value = int.from_bytes(raw2c, "little", signed=True)
    try:
        date20 = bytes.fromhex(str(dates.get("raw_20_hex")))
        date24 = bytes.fromhex(str(dates.get("raw_24_hex")))
    except ValueError:
        return False
    if len(date20) != 4 or len(date24) != 4 or dates.get("raw_20") != int.from_bytes(date20, "little", signed=True) or dates.get("raw_24") != int.from_bytes(date24, "little", signed=True) or item.get("raw_action_type_a8") != selector or item.get("raw_2c") != raw2c_value or item.get("raw_2c_semantics") != "unknown" or item.get("task_family") != (KNOWN_SELECTOR_FAMILY if selector == KNOWN_SELECTOR else None) or item.get("task_family_status") != ("known" if selector == KNOWN_SELECTOR else "unknown"):
        return False
    return _validate_resolution(item, "actor", actor, layout) and _validate_resolution(item, "recipient", recipient, layout)


def validate_record(record: Any, *, profile: Mapping[str, Any] | None = None, offline_legacy_archive: bool = False) -> bool:
    """Validate one read_fields record without trusting its derived fields."""
    if type(offline_legacy_archive) is not bool:
        return False
    if not isinstance(record, Mapping) or record.get("status") != "observed":
        return False
    try:
        if profile is None:
            if record.get("profile_id") != EXPECTED_PROFILE_ID or record.get("profile_sha256") != EXPECTED_PROFILE_SHA256 or offline_legacy_archive:
                return False
            loaded = _load_profile()
        else:
            loaded = _prepare_profile(profile, offline_legacy_archive=offline_legacy_archive)
        expected_id, expected_sha256, _profile_path = _profile_identity(loaded)
        layout = _profile_layout(loaded)
        if record.get("profile_id") != expected_id or record.get("profile_sha256") != expected_sha256 or record.get("basis") != BASIS or record.get("unit") != UNIT or record.get("scale") != SCALE or record.get("period") != PERIOD or record.get("value_origin") != VALUE_ORIGIN:
            return False
        module_base = int(str(record.get("module_base")), 0)
        country_pointer = int(str(record.get("country_pointer")), 0)
        if not _valid_address(module_base, layout) or not _valid_address(country_pointer, layout) or not _static_guard_valid(record.get("static_contract_guard"), loaded, offline_legacy_archive=offline_legacy_archive) or not _runtime_guard_valid(record.get("runtime_code_guard"), loaded, module_base):
            return False
        fields, values, raw_hex, raw_bytes = record.get("fields"), record.get("values"), record.get("raw_hex"), record.get("raw_bytes_hex")
        if not all(isinstance(item, Mapping) for item in (fields, values, raw_hex, raw_bytes)) or set(fields) != {FIELD_KEY} or set(values) != {FIELD_KEY} or set(raw_hex) != {FIELD_KEY} or set(raw_bytes) != {FIELD_KEY}:
            return False
        field = fields[FIELD_KEY]; items = values[FIELD_KEY]
        if not isinstance(field, Mapping) or field.get("status") != "known" or field.get("complete") is not False or field.get("partial") is not True or field.get("value") != items or field.get("unit") != UNIT or field.get("scale") != SCALE or field.get("period") != PERIOD or field.get("basis") != BASIS or field.get("value_origin") != VALUE_ORIGIN or not isinstance(items, list):
            return False
        if record.get("instance_count_observed") != len(items) or raw_hex[FIELD_KEY] != [_raw_projection(item) for item in items] or raw_bytes[FIELD_KEY] != raw_hex[FIELD_KEY] or not all(_validate_item(item, layout, module_base) for item in items):
            return False
        observation = record.get("observation")
        if not isinstance(observation, Mapping) or observation.get("profile_id") != expected_id or observation.get("profile_sha256") != expected_sha256 or observation.get("module_base") != record.get("module_base") or observation.get("country_pointer") != record.get("country_pointer") or observation.get("static_contract_guard") != record.get("static_contract_guard") or observation.get("runtime_code_guard") != record.get("runtime_code_guard") or observation.get("entry_count") != len(items):
            return False
        budget = observation.get("read_budget"); logs = observation.get("read_log")
        if not isinstance(budget, Mapping) or budget.get("limit") != READ_BUDGET_BYTES or type(budget.get("bytes_reserved")) is not int or not isinstance(logs, list) or sum(int(item.get("size", 0)) for item in logs if isinstance(item, Mapping)) != budget.get("bytes_reserved") or any(not isinstance(item, Mapping) or item.get("status") != "ok" or type(item.get("size")) is not int or item.get("size") <= 0 for item in logs):
            return False
        return True
    except Exception:
        return False


def validate_capture(report: Any, context: Mapping[str, Any] | None, creation_filetime: int, country: str = EXPECTED_COUNTRY) -> bool:
    """Validate capture identity, date, cleanup and two-pass raw equality."""
    if not isinstance(report, Mapping) or report.get("status") != "observed" or report.get("completed") is not True or report.get("country") != country or country != EXPECTED_COUNTRY:
        return False
    if report.get("profile") != {"path": str(PROFILE_FILE), "sha256": EXPECTED_PROFILE_SHA256, "profile_id": EXPECTED_PROFILE_ID, "max_bytes": PROFILE_MAX_BYTES}:
        return False
    identity = report.get("identity")
    cleanup = report.get("cleanup", {}).get("handle_close") if isinstance(report.get("cleanup"), Mapping) else None
    double = report.get("doublepass")
    access = report.get("access")
    if not isinstance(identity, Mapping) or identity.get("binding_verified") is not True or identity.get("process_creation_matches_installation") is not True or identity.get("process_path_sha256_matches_expected") is not True or str(identity.get("process_path_sha256", "")).lower() != EXPECTED_EXE_SHA256 or cleanup != {"status": "closed", "success": True, "closed": True} or not isinstance(double, Mapping) or double.get("performed") is not True or double.get("consistent") is not True or report.get("read_only") is not True or report.get("native_function_invoked") is not False or not isinstance(access, Mapping) or access.get("native_game_calls") is not False or access.get("target_memory_writes") is not False:
        return False
    if type(creation_filetime) is not int or identity.get("installation_creation_filetime") != creation_filetime or identity.get("process_creation_filetime") != creation_filetime:
        return False
    if not isinstance(context, Mapping) or type(context.get("game_date")) is not int:
        return False
    expected_session = context.get("session_id", context.get("installation_session_id"))
    if expected_session is not None and identity.get("installation_session_id") != expected_session:
        return False
    expected_sha = context.get("game_sha256", context.get("expected_exe_sha256"))
    if expected_sha is not None and str(expected_sha).lower() != EXPECTED_EXE_SHA256:
        return False
    before, after = report.get("before"), report.get("after")
    if not isinstance(before, Mapping) or not isinstance(after, Mapping) or not isinstance(before.get("record"), Mapping) or not isinstance(after.get("record"), Mapping) or not validate_record(before["record"]) or not validate_record(after["record"]):
        return False
    if _diff_paths(_compare_record(before["record"]), _compare_record(after["record"])):
        return False
    before_date = before.get("game_date")
    after_date = after.get("game_date")
    if (not isinstance(before_date, Mapping) or not isinstance(after_date, Mapping)
            or not dates_match(context['game_date'], before_date.get('value'), after_date.get('value'))
            or (not active() and before_date != after_date)
            or before.get('country_pointer') != after.get('country_pointer')
            or before.get('status') != 'observed' or after.get('status') != 'observed'):
        return False
    for snapshot, date in ((before, before_date), (after, after_date)):
        if (date != snapshot['record'].get('observation', {}).get('game_date')
                or date.get('raw_hex') != (date['value'] & 0xFFFFFFFF).to_bytes(4, 'little').hex()):
            return False
    if _module_base_hex(report.get("module_base")) != after["record"].get("module_base") or report.get("country_pointer") != after["record"].get("country_pointer") or report.get("fields") != after.get("fields") or report.get("values") != after.get("values") or report.get("raw_hex") != after.get("raw_hex") or report.get("raw_bytes_hex") != after.get("raw_bytes_hex") or report.get("instance_count_observed") != after.get("instance_count_observed"):
        return False
    return True


def retract_record(record: Any, reason: str = "observation_retracted") -> dict[str, Any]:
    module_base = country_pointer = None
    if isinstance(record, Mapping):
        try:
            module_base = int(str(record.get("module_base")), 0)
        except (TypeError, ValueError):
            pass
        try:
            country_pointer = int(str(record.get("country_pointer")), 0)
        except (TypeError, ValueError):
            pass
    result = _unknown_record(reason, module_base=module_base, country_pointer=country_pointer)
    if isinstance(record, Mapping):
        for key in ("profile_id", "profile_sha256", "module_base", "country_pointer", "basis", "unit", "scale", "period", "value_origin", "static_contract_guard", "runtime_code_guard"):
            if key in record:
                result[key] = _copy_json(record[key])
                result["observation"][key] = _copy_json(record[key])
    return result


__all__ = [
    "PROFILE_FILE", "LEGACY_PROFILE_FILE", "PROFILE_MAX_BYTES", "EXPECTED_PROFILE_SHA256", "EXPECTED_PROFILE_ID", "LEGACY_PROFILE_SHA256", "LEGACY_PROFILE_ID", "LEGACY_ARCHIVE_NATIVE_SOURCE", "EXPECTED_EXE_SHA256", "EXPECTED_VERSION", "EXPECTED_COUNTRY", "FIELDS", "FIELD_KEY", "BASIS", "VALUE_ORIGIN", "UNIT", "SCALE", "PERIOD", "PARTIAL", "MAX_SINGLE_RPM", "MAX_TOTAL_RPM", "READ_BUDGET_BYTES", "ProfileError", "ReadError", "ProbeError", "AddressBoundedRPM", "OfflineArchiveSnapshotReader", "read_fields", "capture", "validate_record", "validate_capture", "retract_record", "_load_profile", "_load_legacy_archive_profile", "_prepare_profile", "_profile_layout", "_profile_code_guards", "_static_contract_guard", "_file_code_guard", "_runtime_code_guard", "_ReadBudget"
]
