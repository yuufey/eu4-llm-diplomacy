"""Bounded read-only native localisation lookup for the fixed 1.37.4 build.

The reader follows the small, audited lookup contract only.  It opens an
operator-owned process with ``QUERY_INFORMATION | VM_READ``, checks the
executable and both lookup code bodies, then reads the language header, the
sorted hash table, and NUL-terminated value bytes.  It never calls a game
function, writes memory, injects code, scans a private heap, or substitutes
EU4 ``$``/``[]`` template tokens.

``capture`` is intentionally a JSON-ready observation.  A missing key is an
explicit unknown result; the requested key is never used as a fallback value.
The outer/inner header retains the observed capacity fields.  The value-pool
capacity is checked because its loader semantics are evidenced; the hash-table
capacity is reported as an unverified raw observation because the available
evidence does not establish its bound semantics.  Table bounds therefore use
only the audited begin/end pointer range and hard RPM limits.
"""
from __future__ import annotations

import ctypes as C
from ctypes import wintypes as W
from datetime import datetime, timezone
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import mission_memory as _mm


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "localization-memory-1374.json"
PROFILE_MAX_BYTES = 64 * 1024
EXPECTED_PROFILE_SHA256 = "8052f51329598bb3baea137dd7694baba53ace7ecef970773a06cfafe0aef6cb"


class ProfileError(RuntimeError):
    """The bounded localisation profile is absent, oversized, or tampered."""


class ProbeError(RuntimeError):
    """A bounded read or contract check failed without a safe fallback."""


def _load_profile(
    path: Path = PROFILE_FILE,
    expected_sha256: str = EXPECTED_PROFILE_SHA256,
) -> dict[str, Any]:
    try:
        size = path.stat().st_size
        if size <= 0 or size > PROFILE_MAX_BYTES:
            raise ProfileError(f"profile_size_out_of_bound:{size}")
        raw = path.read_bytes()
    except (OSError, UnicodeError) as exc:
        raise ProfileError(f"profile_read_failed:{exc}") from exc
    if len(raw) != size or len(raw) > PROFILE_MAX_BYTES:
        raise ProfileError("profile_read_size_changed")
    actual = hashlib.sha256(raw).hexdigest()
    if actual.lower() != expected_sha256.lower():
        raise ProfileError("profile_sha256_mismatch")
    try:
        profile = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"profile_json_invalid:{exc}") from exc
    if not isinstance(profile, dict) or profile.get("profile_id") != "localization-memory-1374":
        raise ProfileError("profile_shape_invalid")
    return profile


PROFILE = _load_profile()


def _profile_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        parsed = None
    elif isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value, 0)
        except ValueError:
            parsed = None
    else:
        parsed = None
    if parsed is None or parsed < 0:
        raise ProfileError(f"profile_integer_invalid:{label}")
    return parsed


EXPECTED_EXE_SHA256 = str(PROFILE["executable"]["sha256"]).lower()
EXPECTED_VERSION = str(PROFILE["game_version"])
EXPECTED_COUNTRY = str(PROFILE["country"]["supported_country"])

DATABASE_RVA = _profile_int(PROFILE["globals"]["database_rva"], "database_rva")
GAME_RVA = _profile_int(PROFILE["globals"]["game_rva"], "game_rva")
GAME_DATE_OFFSET = _profile_int(PROFILE["globals"]["game_date_offset"], "game_date_offset")
LOCALIZATION_GLOBAL_CELL_RVA = _profile_int(
    PROFILE["globals"]["localization_global_cell_rva"], "localization_global_cell_rva"
)
COUNTRY_TABLE_OFFSET = _profile_int(PROFILE["country"]["table_offset"], "country.table_offset")
COUNTRY_HANDLE_OFFSET = _profile_int(PROFILE["country"]["handle_offset"], "country.handle_offset")
COUNTRY_SCAN_ENTRIES = _profile_int(PROFILE["country"]["country_scan_entries"], "country.country_scan_entries")

OUTER_INNER_OFFSET = _profile_int(PROFILE["localization"]["outer_inner_offset"], "outer_inner_offset")
OUTER_VALUE_POOL_OFFSET = _profile_int(PROFILE["localization"]["outer_value_pool_offset"], "outer_value_pool_offset")
POOL_BEGIN_OFFSET = _profile_int(PROFILE["localization"]["pool_begin_offset"], "pool_begin_offset")
POOL_END_OFFSET = _profile_int(PROFILE["localization"]["pool_end_offset"], "pool_end_offset")
POOL_CAPACITY_END_OFFSET = _profile_int(
    PROFILE["localization"]["pool_capacity_end_offset"], "pool_capacity_end_offset"
)
MAX_POOL_LENGTH = _profile_int(PROFILE["localization"]["max_pool_length_bytes"], "max_pool_length_bytes")
INNER_LANGUAGE_OFFSET = _profile_int(PROFILE["localization"]["inner_language_offset"], "inner_language_offset")
INNER_TABLE_BEGIN_OFFSET = _profile_int(PROFILE["localization"]["inner_table_begin_offset"], "inner_table_begin_offset")
INNER_TABLE_END_OFFSET = _profile_int(PROFILE["localization"]["inner_table_end_offset"], "inner_table_end_offset")
INNER_TABLE_CAPACITY_OFFSET = _profile_int(
    PROFILE["localization"]["inner_table_capacity_offset"], "inner_table_capacity_offset"
)
TABLE_ENTRY_STRIDE = _profile_int(PROFILE["localization"]["table_entry_stride"], "table_entry_stride")
TABLE_ENTRY_HASH_OFFSET = _profile_int(PROFILE["localization"]["table_entry_hash_offset"], "table_entry_hash_offset")
TABLE_ENTRY_OFFSET_OFFSET = _profile_int(
    PROFILE["localization"]["table_entry_offset_offset"], "table_entry_offset_offset"
)

FNV_SEED = _profile_int(PROFILE["hash"]["seed"], "hash.seed")
FNV_MULTIPLIER = _profile_int(PROFILE["hash"]["multiplier"], "hash.multiplier")
HASH_HELPER_RVA = _profile_int(PROFILE["hash"]["helper_rva"], "hash.helper_rva")
HASH_BODY_RVA = _profile_int(PROFILE["hash"]["hash_body_rva"], "hash.hash_body_rva")

PROCESS_ACCESS = _mm.PROCESS_ACCESS
MAX_TOTAL_RPM = _profile_int(PROFILE["limits"]["max_total_rpm"], "limits.max_total_rpm")
MAX_SINGLE_RPM = _profile_int(PROFILE["limits"]["max_single_rpm"], "limits.max_single_rpm")
MAX_KEYS = _profile_int(PROFILE["limits"]["max_keys"], "limits.max_keys")
MAX_KEY_BYTES = _profile_int(PROFILE["limits"]["max_key_bytes"], "limits.max_key_bytes")
MAX_VALUE_BYTES = _profile_int(PROFILE["limits"]["max_value_bytes"], "limits.max_value_bytes")
MAX_TABLE_ENTRIES = _profile_int(PROFILE["limits"]["max_table_entries"], "limits.max_table_entries")
MAX_TABLE_SPAN_BYTES = _profile_int(PROFILE["limits"]["max_table_span_bytes"], "limits.max_table_span_bytes")
MAX_LANGUAGE_ASCII_LENGTH = _profile_int(
    PROFILE["limits"]["max_language_ascii_length"], "limits.max_language_ascii_length"
)
MAX_STRING_CAPACITY = _profile_int(PROFILE["limits"]["max_string_capacity"], "limits.max_string_capacity")

# Re-export the narrow shared helpers as module-local seams.  Tests and the
# future native source adapter can replace these seams without monkey-patching
# unrelated modules.
BoundedRPM = _mm.BoundedRPM
_configure_kernel = _mm._configure_kernel
_load_installation = _mm._load_installation
_read_pe_rva_bytes = _mm._read_pe_rva_bytes
_valid_pointer = _mm._valid_pointer
_address = _mm._address
_parse_int = _mm._parse_int
_filetime_value = _mm._filetime_value
_filetime_iso = _mm._filetime_iso


def _hex(value: int | None) -> str | None:
    return hex(value) if isinstance(value, int) else None


def _valid_unaligned_pointer(value: int) -> bool:
    """Validate a process VA without imposing qword alignment.

    Character-pool end pointers and value addresses are byte pointers.  The
    shared mission reader's ``_valid_pointer`` intentionally requires qword
    alignment for object pointers, so it is not suitable for these fields.
    """
    return isinstance(value, int) and 0x10000 <= value < _mm.MAX_USER_ADDRESS


def _pool_range_valid(begin: int, end: int, capacity_end: int) -> bool:
    """Validate the loader's byte-pool range, including an empty null pool."""
    if begin == end == capacity_end == 0:
        return True
    return _valid_pointer(begin) and _valid_unaligned_pointer(end) and _valid_unaligned_pointer(capacity_end)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tag_and_slot(handle: int) -> tuple[str | None, int | None]:
    raw = (handle & 0xFFFFFF).to_bytes(3, "little")
    if not all(0x41 <= byte <= 0x5A or 0x30 <= byte <= 0x39 for byte in raw):
        return None, (handle >> 32) & 0xFFFF
    return raw.decode("ascii"), (handle >> 32) & 0xFFFF


def _profile_code_guards(profile: Mapping[str, Any] | None = None) -> list[tuple[str, int, bytes]]:
    profile = PROFILE if profile is None else profile
    guards: list[tuple[str, int, bytes]] = []
    for item in profile["code_guards"]:
        if not isinstance(item, Mapping):
            raise ProfileError("profile_code_guard_not_object")
        name = str(item["name"])
        rva = _profile_int(item["rva"], f"code_guard.{name}.rva")
        raw_hex = item.get("bytes")
        if not isinstance(raw_hex, str) or not raw_hex or len(raw_hex) % 2:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}")
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}") from exc
        if len(raw) > MAX_SINGLE_RPM:
            raise ProfileError(f"profile_code_guard_too_large:{name}")
        end = item.get("end_rva_exclusive")
        if end is not None and _profile_int(end, f"code_guard.{name}.end") != rva + len(raw):
            raise ProfileError(f"profile_code_guard_range_mismatch:{name}")
        expected_hash = item.get("sha256")
        if expected_hash and hashlib.sha256(raw).hexdigest() != str(expected_hash).lower():
            raise ProfileError(f"profile_code_guard_sha_mismatch:{name}")
        guards.append((name, rva, raw))
    return guards


def _static_contract_guard() -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "evidence_kind": "ordinary_static_file_analysis_plus_REA_Evidence_and_bounded_runtime_header",
        "profile": str(PROFILE_FILE),
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "source_evidence": dict(PROFILE.get("source_evidence", {})),
        "checks": {},
        "unknown_conditions": [],
    }
    try:
        profile = _load_profile()
        loc = profile["localization"]
        hashing = profile["hash"]
        result["checks"] = {
            "profile_sha256": True,
            "game_sha256": profile["executable"]["sha256"].lower() == EXPECTED_EXE_SHA256,
            "supported_country": profile["country"]["supported_country"] == "FRA",
            "global_cell": profile["globals"]["localization_global_cell_rva"] == "0x2357b00",
            "outer_inner": loc["outer_inner_offset"] == "0x0",
            "outer_value_pool": loc["outer_value_pool_offset"] == "0x20",
            "pool_begin": loc["pool_begin_offset"] == "0x20",
            "pool_end": loc["pool_end_offset"] == "0x28",
            "pool_capacity_end": loc["pool_capacity_end_offset"] == "0x30",
            "language_string32": loc["inner_language_offset"] == "0x0",
            "table_begin": loc["inner_table_begin_offset"] == "0x20",
            "table_end": loc["inner_table_end_offset"] == "0x28",
            "table_capacity_recorded": loc["inner_table_capacity_offset"] == "0x30",
            "table_stride": loc["table_entry_stride"] == 16,
            "table_bound": profile["limits"]["max_table_entries"] == 1048576 and profile["limits"]["max_table_span_bytes"] == 16777216,
            "table_hash_field": loc["table_entry_hash_offset"] == "0x0",
            "table_offset_field": loc["table_entry_offset_offset"] == "0x8",
            "hash_only_lookup": loc["lookup_semantics"] == "native_fnv1_32_hash_only",
            "secondary_records_not_read": loc["secondary_records_not_read"] is True,
            "primary_padding_not_used": loc["primary_entry_padding_offset"] == "0xc_not_used",
            "table_end_semantics": loc["table_end_semantics"] == "pointer_difference_end_exclusive_from_inner_plus_0x28",
            "table_capacity_semantics_unverified": loc["capacity_semantics"] == "raw_header_field_observed_only_not_used_for_bounds",
            "key_length_bound": profile["limits"]["max_key_bytes"] == 160,
            "pool_loader_semantics": loc["pool_semantics_status"] == "ordinary bounded loader plus REA Evidence prove begin/end/capacity-end pointers; end is exclusive; value offset must be below end-begin",
            "fnv1_algorithm": (
                hashing["algorithm"] == "FNV-1"
                and hashing["seed"] == "0x811c9dc5"
                and hashing["multiplier"] == "0x1000193"
                and hashing["helper_rva"] == "0x16faf60"
                and hashing["hash_body_rva"] == "0x14b33a0"
            ),
            "code_guards": len(_profile_code_guards(profile)) == 2,
            "source_refs": all(
                isinstance(item, Mapping) and isinstance(item.get("sha256"), str) and len(item["sha256"]) == 64
                for item in profile.get("source_evidence", {}).values()
            ),
        }
        failed = [key for key, value in result["checks"].items() if value is not True]
        if failed:
            result["unknown_conditions"].append("profile_contract_check_failed:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (ProfileError, KeyError, TypeError, ValueError) as exc:
        result["unknown_conditions"].append(f"profile_contract_read_failed:{exc}")
    return result


def _read_unaligned(reader: Any, address: int, size: int, label: str) -> bytes:
    method = getattr(reader, "read_code", None)
    if callable(method):
        return method(address, size, label)
    method = getattr(reader, "_read", None)
    if callable(method):
        return method(address, size, label, aligned=False)
    return reader.read(address, size, label)


def _file_code_guard(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "path": str(path), "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        for name, rva, expected in _profile_code_guards():
            actual = _read_pe_rva_bytes(path, rva, len(expected))
            result["records"][name] = {
                "rva": _hex(rva),
                "expected_hex": expected.hex(),
                "actual_hex": actual.hex(),
            }
            result["checks"][name] = actual == expected
        failed = [name for name, value in result["checks"].items() if value is not True]
        if failed:
            result["status"] = "mismatch"
            result["unknown_conditions"].append("file_code_guard_mismatch:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (OSError, ProbeError, ProfileError, KeyError, TypeError, ValueError) as exc:
        result["unknown_conditions"].append(str(exc))
    return result


def _runtime_code_guard(reader: Any, module_base: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "module_base": _address(module_base),
        "checks": {},
        "records": {},
        "unknown_conditions": [],
    }
    try:
        for name, rva, expected in _profile_code_guards():
            address = module_base + rva
            actual = _read_unaligned(reader, address, len(expected), f"code_guard.{name}")
            result["records"][name] = {
                "address": _address(address, module_base, known_rva=rva),
                "expected_hex": expected.hex(),
                "actual_hex": actual.hex(),
            }
            result["checks"][name] = actual == expected
        failed = [name for name, value in result["checks"].items() if value is not True]
        if failed:
            result["status"] = "mismatch"
            result["unknown_conditions"].append("runtime_code_guard_mismatch:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (ProbeError, ProfileError, KeyError, TypeError, ValueError, OSError) as exc:
        result["unknown_conditions"].append(str(exc))
    return result


def _fnv1_ascii(key: str) -> int:
    """Compute the audited 32-bit FNV-1 hash for one printable ASCII key."""
    if not isinstance(key, str):
        raise ValueError("key_not_string")
    raw = key.encode("ascii")
    if not raw or len(raw) > MAX_KEY_BYTES:
        raise ValueError("key_length_out_of_bound")
    if any(byte < 0x20 or byte > 0x7E for byte in raw):
        raise ValueError("key_not_printable_ascii")
    value = FNV_SEED
    for byte in raw:
        value = (value * FNV_MULTIPLIER) & 0xFFFFFFFF
        value ^= byte
    return value


# Descriptive alias used by source adapters that refer to the native helper
# by its hash-only role.
_fnv1_hash = _fnv1_ascii


def _unknown_entry(key: str, reason: str, hash_value: int | None = None) -> dict[str, Any]:
    return {
        "key": key,
        "status": "unknown",
        "hash": _hex(hash_value),
        "unknown_reason": reason,
        "reason": "not_found" if reason == "localization_key_not_found" else reason,
        "value": None,
        "raw_hex": None,
        "value_hex": None,
        "native_cached_template": False,
    }


def _field(reader: Any, address: int, raw: bytes, value: int, *, offset: int | None = None) -> dict[str, Any]:
    item: dict[str, Any] = {
        "address": _address(address, reader.module_base),
        "raw_hex": raw.hex(),
        "value": _hex(value),
        "value_address": _address(value, reader.module_base),
    }
    if offset is not None:
        item["field_offset"] = _hex(offset)
    return item


def _decode_language(reader: Any, address: int, header: bytes) -> dict[str, Any]:
    """Decode the observed inner String32 without widening the string bound."""
    if len(header) < 32:
        return {"status": "unknown", "complete": False, "header_hex": header.hex(), "unknown_reason": "language_header_short"}
    length = int.from_bytes(header[0x10:0x18], "little")
    capacity = int.from_bytes(header[0x18:0x20], "little")
    result: dict[str, Any] = {
        "status": "unknown",
        "complete": False,
        "address": _address(address, reader.module_base),
        "header_hex": header[:32].hex(),
        "length": length,
        "capacity": capacity,
        "storage": "inline" if capacity < 16 else "heap",
        "heap_pointer": None,
        "payload_hex": None,
        "text": None,
        "nul_terminator_observed": None,
        "unknown_reason": None,
    }
    if length > MAX_LANGUAGE_ASCII_LENGTH:
        result["unknown_reason"] = "language_length_out_of_bound"
        return result
    if capacity < length or capacity > MAX_STRING_CAPACITY:
        result["unknown_reason"] = "language_capacity_invalid"
        return result
    if capacity < 16:
        if length > 15:
            result["unknown_reason"] = "language_inline_length_out_of_bound"
            return result
        payload = header[:16]
        result["payload_hex"] = payload[: length + 1].hex()
    else:
        pointer = int.from_bytes(header[:8], "little")
        result["heap_pointer"] = _address(pointer, reader.module_base)
        if length and not _valid_pointer(pointer):
            result["unknown_reason"] = "language_heap_pointer_invalid"
            return result
        payload = reader.read(pointer, max(1, length + 1), "localization.language.payload") if length else b"\x00"
        result["payload_hex"] = payload.hex()
    if len(payload) <= length or payload[length] != 0:
        result["nul_terminator_observed"] = False
        result["unknown_reason"] = "language_nul_missing"
        return result
    result["nul_terminator_observed"] = True
    raw = payload[:length]
    if b"\x00" in raw or any(byte >= 0x80 for byte in raw):
        result["unknown_reason"] = "language_not_ascii"
        return result
    result.update({"status": "observed", "complete": True, "text": raw.decode("ascii")})
    return result


def _country_identity(reader: Any, database: int, requested_country: str) -> dict[str, Any]:
    """Read only the same bounded country table window as the mission source."""
    table_address = database + COUNTRY_TABLE_OFFSET
    table, table_raw = reader.qword(table_address, "database.country_table")
    result: dict[str, Any] = {
        "status": "unknown",
        "requested_country": requested_country,
        "table_field": _field(reader, table_address, table_raw, table, offset=COUNTRY_TABLE_OFFSET),
        "scanned_entries": 0,
        "tail_not_claimed": True,
        "matches": [],
        "country_pointer": None,
        "country_handle": None,
    }
    if not _valid_pointer(table):
        result["unknown_reason"] = "country_table_pointer_invalid"
        return result
    raw = reader.read(table, COUNTRY_SCAN_ENTRIES * 8, "country_table.first_bounded_window")
    matches: list[dict[str, Any]] = []
    for index in range(COUNTRY_SCAN_ENTRIES):
        pointer_raw = raw[index * 8:(index + 1) * 8]
        pointer = int.from_bytes(pointer_raw, "little")
        if pointer == 0 or not _valid_pointer(pointer):
            continue
        handle, handle_raw = reader.qword(pointer + COUNTRY_HANDLE_OFFSET, f"country[{index}].handle")
        tag, slot = _tag_and_slot(handle)
        if tag == requested_country and slot == index:
            matches.append({
                "table_index": index,
                "country_pointer": _address(pointer, reader.module_base),
                "country_handle": {
                    "address": _address(pointer + COUNTRY_HANDLE_OFFSET, reader.module_base),
                    "field_offset": _hex(COUNTRY_HANDLE_OFFSET),
                    "raw_hex": handle_raw.hex(),
                    "value": _hex(handle),
                    "tag": tag,
                    "slot": slot,
                },
            })
    result["scanned_entries"] = COUNTRY_SCAN_ENTRIES
    result["matches"] = matches
    if len(matches) == 1:
        result.update({
            "status": "observed",
            "country_pointer": matches[0]["country_pointer"],
            "country_handle": matches[0]["country_handle"],
        })
    elif len(matches) > 1:
        result["unknown_reason"] = "duplicate_tag_and_slot_matches"
    else:
        result["unknown_reason"] = "country_not_found_within_fixed_window"
    return result


def _read_value(reader: Any, address: int, key: str, pool_end: int) -> tuple[bytes, int]:
    """Read a bounded NUL-terminated native cache string.

    The doubling reads keep small values cheap while preserving the hard
    single-read and total-RPM limits.  The returned bytes exclude the NUL.
    """
    remaining = pool_end - address
    if remaining <= 0:
        raise ProbeError("localization_value_address_at_or_after_pool_end")
    size = min(256, remaining)
    while True:
        raw = _read_unaligned(reader, address, size, f"localization.value[{key}]")
        nul = raw.find(b"\x00")
        if nul >= 0:
            return raw[:nul], size
        if size >= MAX_VALUE_BYTES + 1 or size >= remaining:
            raise ProbeError("localization_value_nul_not_observed_within_8192")
        size = min(MAX_VALUE_BYTES + 1, size * 2, remaining)


def _lookup_key(
    reader: Any,
    outer: int,
    table_begin: int,
    table_end: int,
    key: str,
    hash_value: int,
    *,
    pool_begin: int | None = None,
    pool_end: int | None = None,
    pool_capacity_end: int | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Search by native hash and return the cached value bytes as hex only.

    The lookup table does not retain the source key text, and this reader has
    no authority to select a codec.  ``raw_hex``/``value_hex`` therefore remain
    the sole value representation; decoding belongs to the caller's explicit
    session codec layer.
    """
    count = (table_end - table_begin) // TABLE_ENTRY_STRIDE
    low = 0
    high = count
    trace: list[dict[str, Any]] = []

    def read_entry(index: int, suffix: str = "") -> tuple[int, int, bytes, dict[str, Any]]:
        entry_address = table_begin + index * TABLE_ENTRY_STRIDE
        raw = reader.read(entry_address, TABLE_ENTRY_STRIDE, f"localization.entry[{key}].{index}{suffix}")
        observed_hash = int.from_bytes(raw[TABLE_ENTRY_HASH_OFFSET:TABLE_ENTRY_HASH_OFFSET + 8], "little")
        raw_offset = int.from_bytes(raw[TABLE_ENTRY_OFFSET_OFFSET:TABLE_ENTRY_OFFSET_OFFSET + 8], "little")
        item = {
            "index": index,
            "address": _address(entry_address, reader.module_base),
            "raw_hex": raw.hex(),
            "hash": _hex(observed_hash),
            "offset_raw_hex": raw[TABLE_ENTRY_OFFSET_OFFSET:TABLE_ENTRY_OFFSET_OFFSET + 8].hex(),
            "offset": raw_offset & 0xFFFFFFFF,
        }
        return observed_hash, raw_offset & 0xFFFFFFFF, raw, item

    while low < high:
        mid = (low + high) // 2
        observed_hash, _raw_offset, _raw, item = read_entry(mid)
        trace.append(item)
        if observed_hash < hash_value:
            low = mid + 1
        else:
            high = mid
    hit = None
    lower_hash: int | None = None
    lower_raw_offset: int | None = None
    lower_raw: bytes | None = None
    if low < count:
        observed_hash, raw_offset, raw, item = read_entry(low, ".lower_bound")
        item["lower_bound"] = True
        trace.append(item)
        lower_hash, lower_raw_offset, lower_raw = observed_hash, raw_offset, raw
        if observed_hash == hash_value:
            hit = {"index": low, "raw_hex": raw.hex(), "offset": raw_offset & 0xFFFFFFFF}
    # The native helper is hash-only.  A repeated adjacent hash or a local
    # ordering violation is therefore ambiguous and is rejected without a
    # full-table scan.  Reading the two boundary neighbours also preserves
    # collision evidence around a lower_bound hit.
    boundary_hashes: dict[int, int] = {}
    if low < count:
        boundary_hashes[low] = lower_hash if lower_hash is not None else 0
        for neighbor, relation in ((low - 1, "previous"), (low + 1, "next")):
            if 0 <= neighbor < count:
                neighbor_hash, _neighbor_offset, _neighbor_raw, item = read_entry(neighbor, f".{relation}")
                item["boundary"] = relation
                trace.append(item)
                boundary_hashes[neighbor] = neighbor_hash
        if low - 1 in boundary_hashes and boundary_hashes[low - 1] >= boundary_hashes[low]:
            raise ProbeError("localization_table_order_or_duplicate_hash")
        if low + 1 in boundary_hashes and boundary_hashes[low + 1] <= boundary_hashes[low]:
            raise ProbeError("localization_table_order_or_duplicate_hash")
    compare: dict[str, Any] = {
        "key": key,
        "hash": hash_value,
        "search_trace": trace,
        "hit": hit,
    }
    if hit is None:
        return _unknown_entry(key, "localization_key_not_found", hash_value), compare
    if pool_begin is None or pool_end is None or pool_capacity_end is None:
        pool, pool_raw = reader.qword(outer + OUTER_VALUE_POOL_OFFSET, "localization.value_pool")
        pool_end, pool_end_raw = reader.qword(outer + POOL_END_OFFSET, "localization.value_pool_end")
        pool_capacity_end, pool_capacity_raw = reader.qword(outer + POOL_CAPACITY_END_OFFSET, "localization.value_pool_capacity_end")
        pool_begin = pool
    else:
        pool = pool_begin
        pool_raw = b""
        pool_end_raw = b""
        pool_capacity_raw = b""
    if not _pool_range_valid(pool, pool_end, pool_capacity_end):
        raise ProbeError("localization_value_pool_pointer_invalid")
    pool_length = pool_end - pool
    capacity_length = pool_capacity_end - pool
    if pool_end < pool or pool_capacity_end < pool_end or pool_length < 0 or pool_length > MAX_POOL_LENGTH or capacity_length < pool_length:
        raise ProbeError("localization_value_pool_bounds_invalid")
    offset = int(hit["offset"])
    if offset >= pool_length:
        raise ProbeError("localization_value_offset_out_of_pool_bounds")
    value_address = pool + offset
    if not _valid_unaligned_pointer(value_address):
        raise ProbeError("localization_value_address_invalid")
    value_bytes, requested = _read_value(reader, value_address, key, pool_end)
    result: dict[str, Any] = {
        "key": key,
        "status": "observed",
        "hash": _hex(hash_value),
        "offset": offset,
        "value_address": _address(value_address, reader.module_base),
        "value_read_bytes": requested,
        "raw_hex": value_bytes.hex(),
        "value_hex": value_bytes.hex(),
        "byte_length": len(value_bytes),
        "native_cached_template": True,
        "dynamic_tokens_not_substituted": True,
    }
    compare.update({
        "pool_raw_hex": pool_raw.hex(),
        "pool_end_raw_hex": pool_end_raw.hex(),
        "pool_capacity_end_raw_hex": pool_capacity_raw.hex(),
        "pool_end": pool_end,
        "pool_capacity_end": pool_capacity_end,
        "pool_length": pool_length,
        "pool": _address(pool, reader.module_base),
        "value_address": _address(value_address, reader.module_base),
        "value_raw_hex": value_bytes.hex(),
    })
    return result, compare


def _snapshot(reader: Any, module_base: int, country: str, keys: Sequence[str]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "unknown_conditions": [],
        "game_pointer": None,
        "database_pointer": None,
        "game_date": None,
        "country_scan": None,
        "localization": None,
        "entries": {},
    }
    try:
        game_address = module_base + GAME_RVA
        game, game_raw = reader.qword(game_address, "global.game_pointer")
        database_address = module_base + DATABASE_RVA
        database, database_raw = reader.qword(database_address, "global.database_pointer")
        result["game_pointer"] = _field(reader, game_address, game_raw, game, offset=GAME_RVA)
        result["database_pointer"] = _field(reader, database_address, database_raw, database, offset=DATABASE_RVA)
        if not _valid_pointer(game) or not _valid_pointer(database):
            result["unknown_conditions"].append("game_or_database_pointer_invalid")
            return result
        date_address = game + GAME_DATE_OFFSET
        date_raw = reader.read(date_address, 4, "game.raw_date")
        result["game_date"] = {
            "address": _address(date_address, module_base),
            "field_offset": _hex(GAME_DATE_OFFSET),
            "raw_hex": date_raw.hex(),
            "raw": int.from_bytes(date_raw, "little", signed=True),
        }
        country_scan = _country_identity(reader, database, country)
        result["country_scan"] = country_scan
        if country_scan.get("status") != "observed":
            result["unknown_conditions"].append(country_scan.get("unknown_reason", "country_identity_unknown"))
            return result
        country_pointer = _parse_int(str(country_scan["country_pointer"]["va"]))
        if country_pointer is None or not _valid_pointer(country_pointer):
            result["unknown_conditions"].append("country_pointer_invalid_after_scan")
            return result

        global_address = module_base + LOCALIZATION_GLOBAL_CELL_RVA
        outer, global_raw = reader.qword(global_address, "localization.global_cell")
        if not _valid_pointer(outer):
            result["unknown_conditions"].append("localization_outer_pointer_invalid")
            return result
        outer_header = reader.read(outer, 0x40, "localization.outer_header")
        inner_address = outer + OUTER_INNER_OFFSET
        inner, inner_raw = reader.qword(inner_address, "localization.outer.inner")
        if not _valid_pointer(inner):
            result["unknown_conditions"].append("localization_inner_pointer_invalid")
            return result
        inner_header = reader.read(inner, 0x40, "localization.inner_header")
        language = _decode_language(reader, inner + INNER_LANGUAGE_OFFSET, inner_header[INNER_LANGUAGE_OFFSET:INNER_LANGUAGE_OFFSET + 32])
        if language.get("status") != "observed":
            result["unknown_conditions"].append(language.get("unknown_reason", "language_unknown"))
            return result
        begin_raw = inner_header[INNER_TABLE_BEGIN_OFFSET:INNER_TABLE_BEGIN_OFFSET + 8]
        end_raw = inner_header[INNER_TABLE_END_OFFSET:INNER_TABLE_END_OFFSET + 8]
        capacity_raw = inner_header[INNER_TABLE_CAPACITY_OFFSET:INNER_TABLE_CAPACITY_OFFSET + 8]
        if len(begin_raw) != 8 or len(end_raw) != 8 or len(capacity_raw) != 8:
            result["unknown_conditions"].append("localization_table_header_short")
            return result
        table_begin = int.from_bytes(begin_raw, "little")
        table_end = int.from_bytes(end_raw, "little")
        table_capacity = int.from_bytes(capacity_raw, "little")
        span = table_end - table_begin
        table_header = {
            "inner_address": _address(inner, module_base),
            "begin": _field(reader, inner + INNER_TABLE_BEGIN_OFFSET, begin_raw, table_begin, offset=INNER_TABLE_BEGIN_OFFSET),
            "end": _field(reader, inner + INNER_TABLE_END_OFFSET, end_raw, table_end, offset=INNER_TABLE_END_OFFSET),
            "capacity": _field(reader, inner + INNER_TABLE_CAPACITY_OFFSET, capacity_raw, table_capacity, offset=INNER_TABLE_CAPACITY_OFFSET),
            "entry_stride": TABLE_ENTRY_STRIDE,
            "span_bytes": span,
            "count": None,
            "capacity_bounds_verified": False,
            "capacity_unknown_reason": "table_capacity_semantics_unverified",
        }
        if not ((table_begin == table_end == 0) or (_valid_pointer(table_begin) and _valid_unaligned_pointer(table_end))):
            result["unknown_conditions"].append("localization_table_pointer_invalid")
            result["localization"] = {"global": _field(reader, global_address, global_raw, outer, offset=LOCALIZATION_GLOBAL_CELL_RVA), "outer_header_hex": outer_header.hex(), "inner_header_hex": inner_header.hex(), "language": language, "table": table_header}
            return result
        if table_end < table_begin or span % TABLE_ENTRY_STRIDE:
            result["unknown_conditions"].append("localization_table_span_invalid")
            result["localization"] = {"global": _field(reader, global_address, global_raw, outer, offset=LOCALIZATION_GLOBAL_CELL_RVA), "outer_header_hex": outer_header.hex(), "inner_header_hex": inner_header.hex(), "language": language, "table": table_header}
            return result
        count = span // TABLE_ENTRY_STRIDE
        table_header["count"] = count
        if count > MAX_TABLE_ENTRIES or span > MAX_TABLE_SPAN_BYTES:
            result["unknown_conditions"].append("localization_table_count_out_of_bound")
            return result
        pool, pool_raw = reader.qword(outer + POOL_BEGIN_OFFSET, "localization.value_pool_begin")
        pool_end, pool_end_raw = reader.qword(outer + POOL_END_OFFSET, "localization.value_pool_end")
        pool_capacity_end, pool_capacity_raw = reader.qword(outer + POOL_CAPACITY_END_OFFSET, "localization.value_pool_capacity_end")
        pool_length = pool_end - pool
        pool_capacity_length = pool_capacity_end - pool
        if not _pool_range_valid(pool, pool_end, pool_capacity_end):
            result["unknown_conditions"].append("localization_value_pool_pointer_invalid")
            return result
        if pool_end < pool or pool_capacity_end < pool_end or pool_length < 0 or pool_length > MAX_POOL_LENGTH or pool_capacity_length < pool_length:
            result["unknown_conditions"].append("localization_value_pool_bounds_invalid")
            return result
        localization_compare: dict[str, Any] = {
            "global_raw_hex": global_raw.hex(),
            "outer": _address(outer, module_base),
            "outer_header_hex": outer_header.hex(),
            "inner": _address(inner, module_base),
            "inner_raw_hex": inner_raw.hex(),
            "inner_header_hex": inner_header.hex(),
            "language": {key: language.get(key) for key in ("status", "complete", "header_hex", "payload_hex", "text", "length", "capacity")},
            "table": {
                "begin_raw_hex": begin_raw.hex(), "end_raw_hex": end_raw.hex(), "capacity_raw_hex": capacity_raw.hex(),
                "begin": table_begin, "end": table_end, "capacity": table_capacity, "count": count,
                "capacity_bounds_verified": False,
                "capacity_unknown_reason": "table_capacity_semantics_unverified",
            },
            "pool_raw_hex": pool_raw.hex(),
            "pool_end_raw_hex": pool_end_raw.hex(),
            "pool_capacity_end_raw_hex": pool_capacity_raw.hex(),
            "pool": pool,
            "pool_end": pool_end,
            "pool_capacity_end": pool_capacity_end,
            "pool_length": pool_length,
            "entries": [],
        }
        entries: dict[str, Any] = {}
        for key in keys:
            hash_value = _fnv1_ascii(key)
            entry, compare = _lookup_key(
                reader,
                outer,
                table_begin,
                table_end,
                key,
                hash_value,
                pool_begin=pool,
                pool_end=pool_end,
                pool_capacity_end=pool_capacity_end,
            )
            entries[key] = entry
            localization_compare["entries"].append(compare)
        result["entries"] = entries
        result["localization"] = {
            "status": "observed",
            "selected_native_lookup_object_name": "inner_localization_object",
            "global": _field(reader, global_address, global_raw, outer, offset=LOCALIZATION_GLOBAL_CELL_RVA),
            "outer_header_hex": outer_header.hex(),
            "inner": _address(inner, module_base),
            "inner_header_hex": inner_header.hex(),
            "language": language,
            "table": table_header,
            "value_pool": {
                "begin": _field(reader, outer + POOL_BEGIN_OFFSET, pool_raw, pool, offset=POOL_BEGIN_OFFSET),
                "end": _field(reader, outer + POOL_END_OFFSET, pool_end_raw, pool_end, offset=POOL_END_OFFSET),
                "capacity_end": _field(reader, outer + POOL_CAPACITY_END_OFFSET, pool_capacity_raw, pool_capacity_end, offset=POOL_CAPACITY_END_OFFSET),
                "length_bytes": pool_length,
                "capacity_bytes": pool_capacity_length,
            },
            "entries": entries,
        }
        result["_compare"] = {
            "game_pointer": result["game_pointer"],
            "database_pointer": result["database_pointer"],
            "game_date": result["game_date"],
            "country": {
                "status": country_scan.get("status"),
                "country_pointer": country_scan.get("country_pointer"),
                "country_handle": country_scan.get("country_handle"),
            },
            "localization": localization_compare,
        }
        result["status"] = "observed"
        return result
    except Exception as exc:
        result["unknown_conditions"].append(f"localization_snapshot_failed:{exc}")
        return result


def _without_private(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _without_private(item) for key, item in value.items() if not key.startswith("_")}
    if isinstance(value, list):
        return [_without_private(item) for item in value]
    return value


def _diff_paths(left: Any, right: Any, path: str = "$") -> list[str]:
    if type(left) is not type(right):
        return [path]
    if isinstance(left, dict):
        paths: list[str] = []
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                paths.append(f"{path}.{key}")
            else:
                paths.extend(_diff_paths(left[key], right[key], f"{path}.{key}"))
        return paths
    if isinstance(left, list):
        paths = []
        if len(left) != len(right):
            paths.append(f"{path}.length")
        for index, (a, b) in enumerate(zip(left, right)):
            paths.extend(_diff_paths(a, b, f"{path}[{index}]"))
        return paths
    return [] if left == right else [path]


def _close_process_handle(kernel: Any, handle: Any) -> dict[str, Any]:
    if kernel is None or handle is None:
        return {"status": "not_opened", "success": None, "closed": False}
    try:
        if not bool(handle):
            return {"status": "not_opened", "success": None, "closed": False}
    except Exception as exc:
        return {"status": "error", "success": False, "closed": False, "error": str(exc)}
    try:
        closed = bool(kernel.CloseHandle(handle))
    except Exception as exc:
        return {"status": "error", "success": False, "closed": False, "error": str(exc)}
    if closed:
        return {"status": "closed", "success": True, "closed": True}
    return {"status": "error", "success": False, "closed": False, "error": f"CloseHandle returned false (last_error={C.get_last_error()})"}


def _base_report(installation: Path, country: str, keys: Sequence[str]) -> dict[str, Any]:
    return {
        "probe": "information-localization-runtime",
        "probe_version": 1,
        "probe_script": str(Path(__file__).resolve()),
        "probe_script_sha256": None,
        "profile": {"path": str(PROFILE_FILE), "sha256": EXPECTED_PROFILE_SHA256, "max_bytes": PROFILE_MAX_BYTES, "profile_id": PROFILE.get("profile_id")},
        "read_only": True,
        "evidence_kind": "pure_runtime_observation_not_static_evidence",
        "request": {"installation": str(installation), "country": country, "keys": list(keys), "max_keys": MAX_KEYS, "max_key_bytes": MAX_KEY_BYTES, "language": "observed_from_inner_String32"},
        "target_build": {"version": EXPECTED_VERSION, "expected_exe_sha256": EXPECTED_EXE_SHA256, "database_rva": _hex(DATABASE_RVA), "game_rva": _hex(GAME_RVA), "localization_global_cell_rva": _hex(LOCALIZATION_GLOBAL_CELL_RVA), "hash_body_rva": _hex(HASH_BODY_RVA), "hash_helper_rva": _hex(HASH_HELPER_RVA)},
        "static_contract_reference": {"profile_sha256": EXPECTED_PROFILE_SHA256, "source_evidence": dict(PROFILE.get("source_evidence", {})), "static_results_are_not_runtime_observation": True, "pool_capacity_semantics": PROFILE["localization"]["capacity_semantics"]},
        "static_contract_guard": None,
        "file_code_guard": None,
        "runtime_code_guard": None,
        "identity": {"installation_path": str(installation), "installation_pid": None, "installation_creation_filetime": None, "installation_session_id": None, "process_path": None, "process_path_sha256": None, "process_path_sha256_matches_expected": None, "process_creation_filetime": None, "process_creation_utc": None, "process_creation_matches_installation": None, "module_path": None, "module_path_matches_process": None, "selected_native_lookup_object_name": "inner_localization_object", "binding_verified": False},
        "module_base": None,
        "before": None,
        "after": None,
        "entries": _unknown_entries(keys, "not_read"),
        "doublepass": {"performed": False, "consistent": None, "mismatches": []},
        "language": {"status": "unknown", "text": None, "unknown_reason": "not_read"},
        "access": {"open_process_mask": "QUERY_INFORMATION|VM_READ", "open_process_mask_hex": _hex(PROCESS_ACCESS), "rpm_total_limit": MAX_TOTAL_RPM, "rpm_single_read_limit": MAX_SINGLE_RPM, "rpm_bytes_requested": 0, "rpm_calls": 0, "native_game_calls": False, "target_memory_writes": False, "dll_injection": False, "private_heap_scan": False, "ui_control": False, "date_advance": False, "save_or_reload": False},
        "cleanup": {"handle_close": {"status": "unknown", "success": None, "closed": False}},
        "status": "starting",
        "errors": [],
        "completed": False,
    }


def _unknown_entries(keys: Sequence[str], reason: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in keys:
        map_key = key if isinstance(key, str) else repr(key)
        result[map_key] = _unknown_entry(map_key, reason)
    return result


def _capture_identity(report: dict[str, Any], document: Mapping[str, Any], kernel: Any, handle: Any) -> int:
    pid = _parse_int(document.get("pid"))
    expected_creation = _parse_int(document.get("creation_filetime"))
    session_id = document.get("session_id")
    if pid is None or expected_creation is None:
        raise ProbeError("installation_pid_or_creation_invalid")
    if not isinstance(session_id, str) or not session_id:
        raise ProbeError("installation_session_id_missing")
    report["identity"].update({"installation_pid": pid, "installation_creation_filetime": expected_creation, "installation_session_id": session_id})
    process_path_buffer = C.create_unicode_buffer(32768)
    process_path_length = W.DWORD(len(process_path_buffer))
    if not kernel.QueryFullProcessImageNameW(handle, 0, process_path_buffer, C.byref(process_path_length)):
        raise C.WinError(C.get_last_error())
    process_path = Path(process_path_buffer.value).resolve()
    process_hash = _sha256_file(process_path)
    report["identity"].update({"process_path": str(process_path), "process_path_sha256": process_hash, "process_path_sha256_matches_expected": process_hash.lower() == EXPECTED_EXE_SHA256})
    creation = W.FILETIME(); exit_time = W.FILETIME(); kernel_time = W.FILETIME(); user_time = W.FILETIME()
    if not kernel.GetProcessTimes(handle, C.byref(creation), C.byref(exit_time), C.byref(kernel_time), C.byref(user_time)):
        raise C.WinError(C.get_last_error())
    process_creation = _filetime_value(creation)
    report["identity"].update({"process_creation_filetime": process_creation, "process_creation_utc": _filetime_iso(process_creation), "process_creation_matches_installation": process_creation == expected_creation})
    modules = (W.HMODULE * 1024)(); needed = W.DWORD()
    if not kernel.K32EnumProcessModulesEx(handle, modules, C.sizeof(modules), C.byref(needed), 3):
        raise C.WinError(C.get_last_error())
    if not needed.value or needed.value > C.sizeof(modules) or needed.value % C.sizeof(W.HMODULE):
        raise ProbeError("module_list_invalid")
    module_base = int(getattr(modules[0], "value", modules[0]))
    if module_base < 0x10000:
        raise ProbeError("module_base_invalid")
    module_name_buffer = C.create_unicode_buffer(32768)
    module_name_length = kernel._probe_get_module_name(handle, modules[0], module_name_buffer, len(module_name_buffer))
    module_path = Path(module_name_buffer.value).resolve() if module_name_length else None
    report["module_base"] = _address(module_base)
    report["identity"].update({"module_path": str(module_path) if module_path else None, "module_path_matches_process": module_path == process_path if module_path else False})
    identity_ok = report["identity"]["process_path_sha256_matches_expected"] is True and report["identity"]["process_creation_matches_installation"] is True and report["identity"]["module_path_matches_process"] is True and str(document.get("game_sha256", "")).lower() == EXPECTED_EXE_SHA256
    report["identity"]["binding_verified"] = identity_ok
    if not identity_ok:
        raise ProbeError("PID creation/path/SHA/module binding mismatch")
    return module_base


def capture(installation: Path, country: str, keys: Sequence[str]) -> dict[str, Any]:
    """Capture one bounded two-pass native localisation observation."""
    installation = Path(installation)
    requested = list(keys) if isinstance(keys, (list, tuple)) else []
    report = _base_report(installation, country, requested)
    handle = None; kernel = None; reader = None
    try:
        report["probe_script_sha256"] = _sha256_file(Path(__file__).resolve())
    except OSError as exc:
        report["errors"].append({"stage": "probe_identity", "status": "unknown", "error": str(exc)})
    # Validate request before opening a process.  This keeps invalid input
    # from consuming an RPM budget or creating a handle.
    if not isinstance(country, str) or re.fullmatch(r"[A-Z0-9]{3}", country) is None:
        report["status"] = "unsupported_country"
        report["entries"] = _unknown_entries(requested, "unsupported_country")
        report["errors"].append({"stage": "request", "status": "unknown", "error": "Invalid country tag"})
        report["cleanup"]["handle_close"] = _close_process_handle(None, None)
        report["completed"] = True
        return report
    if not isinstance(keys, (list, tuple)) or len(requested) > MAX_KEYS:
        report["status"] = "invalid_request"
        report["entries"] = _unknown_entries(requested[:MAX_KEYS], "key_count_out_of_bound")
        report["errors"].append({"stage": "request", "status": "unknown", "error": "keys must contain at most 128 entries"})
        report["cleanup"]["handle_close"] = _close_process_handle(None, None)
        report["completed"] = True
        return report
    invalid: list[tuple[str, str]] = []
    valid_keys: list[str] = []
    for key in requested:
        try:
            _fnv1_ascii(key)
            valid_keys.append(key)
        except (UnicodeEncodeError, ValueError, TypeError) as exc:
            invalid.append((str(key), str(exc)))
    if invalid:
        report["status"] = "invalid_request"
        report["entries"] = _unknown_entries(requested, "invalid_ascii_key")
        report["errors"].append({"stage": "request", "status": "unknown", "error": "keys must be printable ASCII strings of 1..160 bytes", "keys": [key for key, _ in invalid]})
        report["cleanup"]["handle_close"] = _close_process_handle(None, None)
        report["completed"] = True
        return report

    report["static_contract_guard"] = _static_contract_guard()
    if report["static_contract_guard"].get("status") != "observed":
        report["status"] = "static_contract_mismatch"
        report["entries"] = _unknown_entries(requested, "static_contract_mismatch")
        report["errors"].append({"stage": "static_contract", "status": "unknown", "error": "Localization profile/hash/table guards did not match"})
        report["cleanup"]["handle_close"] = _close_process_handle(None, None)
        report["completed"] = True
        return report

    try:
        document = _load_installation(installation)
        pid = _parse_int(document.get("pid")); expected_creation = _parse_int(document.get("creation_filetime"))
        if pid is None or expected_creation is None:
            raise ProbeError("installation_pid_or_creation_invalid")
        kernel = _configure_kernel()
        handle = kernel.OpenProcess(PROCESS_ACCESS, False, pid)
        if not handle:
            raise C.WinError(C.get_last_error())
        module_base = _capture_identity(report, document, kernel, handle)
        process_path = Path(report["identity"]["process_path"])
        report["file_code_guard"] = _file_code_guard(process_path)
        if report["file_code_guard"].get("status") != "observed":
            report["status"] = "file_code_mismatch"
            report["errors"].append({"stage": "file_code_guard", "status": "unknown", "error": "Profile localization code bytes did not match the executable"})
        else:
            reader = BoundedRPM(kernel, handle, module_base)
            report["runtime_code_guard"] = _runtime_code_guard(reader, module_base)
            if report["runtime_code_guard"].get("status") != "observed":
                report["status"] = "runtime_code_mismatch"
                report["errors"].append({"stage": "runtime_code_guard", "status": "unknown", "error": "Profile localization code bytes did not match process memory"})
            else:
                before = _snapshot(reader, module_base, country, valid_keys)
                report["before"] = _without_private(before)
                if before.get("status") != "observed":
                    report["status"] = "unknown"
                    report["entries"] = _unknown_entries(requested, "first_pass_unknown")
                    report["errors"].append({"stage": "before", "status": "unknown", "error": "Initial localization snapshot was not complete"})
                else:
                    after = _snapshot(reader, module_base, country, valid_keys)
                    report["after"] = _without_private(after)
                    report["doublepass"]["performed"] = True
                    left = before.get("_compare"); right = after.get("_compare") if after.get("status") == "observed" else None
                    mismatches = ["$.after.status"] if right is None else _diff_paths(left, right)
                    report["doublepass"]["mismatches"] = mismatches[:256]
                    report["doublepass"]["consistent"] = not mismatches
                    if mismatches:
                        report["status"] = "doublepass_mismatch"
                        report["entries"] = _unknown_entries(requested, "doublepass_mismatch")
                        report["errors"].append({"stage": "doublepass", "status": "unknown", "error": "Localization header/table/search/value bytes changed between passes", "paths": mismatches[:256]})
                    else:
                        report["status"] = "observed"
                        report["entries"] = _without_private(before.get("entries", {}))
                        language = (before.get("localization") or {}).get("language")
                        if isinstance(language, dict):
                            report["language"] = {
                                "status": language.get("status", "unknown"),
                                "text": language.get("text"),
                                "length": language.get("length"),
                                "header_hex": language.get("header_hex"),
                                "payload_hex": language.get("payload_hex"),
                            }
    except Exception as exc:
        report["status"] = "error"
        report["entries"] = _unknown_entries(requested, "capture_failed")
        report["errors"].append({"stage": "probe", "status": "unknown", "error": str(exc)})
    finally:
        if reader is not None:
            report["access"]["rpm_bytes_requested"] = reader.bytes_requested
            report["access"]["rpm_calls"] = reader.calls
        outcome = _close_process_handle(kernel, handle)
        report["cleanup"]["handle_close"] = outcome
        if outcome.get("status") == "error":
            previous_status = report.get("status")
            report["status"] = "cleanup_error"
            report["entries"] = _unknown_entries(requested, "handle_close_failed")
            outcome["previous_status"] = previous_status
            report["errors"].append({"stage": "cleanup", "status": "error", "error": outcome.get("error", "CloseHandle failed"), "previous_status": previous_status})
    report["completed"] = report["status"] in {"observed", "doublepass_mismatch", "unknown", "error", "invalid_request", "unsupported_country", "static_contract_mismatch", "file_code_mismatch", "runtime_code_mismatch", "cleanup_error"}
    return report


__all__ = [
    "PROFILE_FILE", "PROFILE", "EXPECTED_PROFILE_SHA256", "EXPECTED_EXE_SHA256", "BoundedRPM",
    "ProbeError", "ProfileError", "capture", "_fnv1_ascii", "_fnv1_hash", "_profile_code_guards", "_static_contract_guard",
    "_file_code_guard", "_runtime_code_guard", "_snapshot", "_lookup_key", "_diff_paths", "MAX_TOTAL_RPM", "MAX_SINGLE_RPM",
]
