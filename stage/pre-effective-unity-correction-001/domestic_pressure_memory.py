"""Bounded, read-only native capture for domestic-pressure scalars.

The profile is the source of every layout, unit, scale, and save-token key
value in this module.  A capture performs two independent bounded RPM passes
and publishes values only when the complete observations agree and the
process handle closes successfully.
"""
from __future__ import annotations

import ctypes as C
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import country_resources_memory as _crm
from . import localization_memory as _loc
from . import mission_memory as _mm


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "domestic-pressure-memory-1374.json"
PROFILE_MAX_BYTES = 64 * 1024
# This is the exact pin of the checked-in 1.37.4 domestic-pressure profile.
EXPECTED_PROFILE_SHA256 = "38aca9702b4c8d8cf90214a434b4259edb77257901542114864aa2d55fcc256b"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_VERSION = "1.37.4"
EXPECTED_COUNTRY = "FRA"

PROCESS_ACCESS = _mm.PROCESS_ACCESS
MAX_USER_ADDRESS = _mm.MAX_USER_ADDRESS
MAX_SINGLE_RPM = 65_536
MAX_TOTAL_RPM = 512 * 1024
GAME_DATE_WIDTH = 4
FIELDS = ("stability", "war_exhaustion", "corruption", "religious_unity")

# Keep the bounded reader and OS seams local to this module.  In particular,
# this reader never calls country_resources_memory.capture or its active
# monarch-point profile.
AddressBoundedRPM = _crm.AddressBoundedRPM
_load_installation = _loc._load_installation
_configure_kernel = _loc._configure_kernel
_capture_identity = _loc._capture_identity
_close_process_handle = _loc._close_process_handle
_read_pe_rva_bytes = _loc._read_pe_rva_bytes
_valid_pointer = _mm._valid_pointer
_address = _loc._address
_tag_and_slot = _loc._tag_and_slot
_decode_string32 = _mm._decode_string32

MAX_SAVE_TOKEN_KEY_ID = MAX_TOTAL_RPM // 32


class ProfileError(RuntimeError):
    """The domestic-pressure profile is absent or invalid."""


# Re-export the bounded reader's exception so callers/tests can catch one
# contract-level type even though the implementation is shared.
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


def _load_profile(path: Path | None = None, expected_sha256: str | None = None) -> dict[str, Any]:
    if path is None:
        path = PROFILE_FILE
    if expected_sha256 is None:
        expected_sha256 = EXPECTED_PROFILE_SHA256
    try:
        stat_size = path.stat().st_size
        if stat_size <= 0 or stat_size > PROFILE_MAX_BYTES:
            raise ProfileError(f"profile_size_out_of_bound:{stat_size}")
        raw = path.read_bytes()
    except (OSError, UnicodeError) as exc:
        raise ProfileError(f"profile_read_failed:{exc}") from exc
    if len(raw) != stat_size or len(raw) > PROFILE_MAX_BYTES:
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
    if not isinstance(profile, dict) or profile.get("profile_id") != "domestic-pressure-memory-1374":
        raise ProfileError("profile_shape_invalid")
    return profile


try:
    PROFILE: dict[str, Any] | None = _load_profile()
except ProfileError:
    PROFILE = None


def _hex(value: int | None) -> str | None:
    return hex(value) if isinstance(value, int) else None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _dependency_path(raw_path: str) -> Path:
    """Resolve only relative dependencies inside this repository."""
    path = Path(raw_path)
    if path.is_absolute():
        raise ProfileError(f"dependency_path_absolute:{raw_path}")
    workspace = Path(__file__).resolve().parents[2]
    resolved = (workspace / path).resolve()
    if resolved != workspace and workspace not in resolved.parents:
        raise ProfileError(f"dependency_outside_workspace:{raw_path}")
    return resolved


def _dependency_hash_checks(dependencies: Any) -> tuple[bool, dict[str, bool], list[str]]:
    if not isinstance(dependencies, list) or not dependencies:
        return False, {}, ["dependencies_missing_or_empty"]
    checks: dict[str, bool] = {}
    unknown: list[str] = []
    for item in dependencies:
        if not isinstance(item, Mapping):
            unknown.append("dependency_not_object")
            continue
        raw_path, expected = item.get("path"), item.get("sha256")
        if not isinstance(raw_path, str) or not raw_path:
            unknown.append("dependency_path_invalid")
            continue
        checks[raw_path] = False
        if not isinstance(expected, str) or len(expected) != 64:
            unknown.append(f"dependency_sha256_invalid:{raw_path}")
            continue
        try:
            path = _dependency_path(raw_path)
            if not path.is_file():
                raise OSError("dependency_not_regular_file")
            size = path.stat().st_size
            if size > 16 * 1024 * 1024:
                raise OSError(f"dependency_size_out_of_bound:{size}")
            actual = _sha256_file(path)
            if path.stat().st_size != size:
                raise OSError("dependency_changed_during_hash")
        except (OSError, ProfileError, ValueError) as exc:
            unknown.append(f"dependency_read_failed:{raw_path}:{exc}")
            continue
        checks[raw_path] = actual.lower() == expected.lower()
        if not checks[raw_path]:
            unknown.append(f"dependency_sha256_mismatch:{raw_path}")
    return bool(checks) and all(checks.values()) and not unknown, checks, unknown


def _profile_code_guards(profile: Mapping[str, Any] | None = None) -> list[tuple[str, int, bytes]]:
    if profile is None:
        profile = _load_profile()
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
        raw_hex = item.get("hex", item.get("bytes"))
        if not isinstance(raw_hex, str) or not raw_hex or len(raw_hex) % 2:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}")
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}") from exc
        if not raw or len(raw) > MAX_SINGLE_RPM:
            raise ProfileError(f"profile_code_guard_size_invalid:{name}")
        guards.append((name, rva, raw))
    return guards


def _profile_layout(profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if profile is None:
        profile = _load_profile()
    try:
        globals_ = profile["globals"]
        country = profile["country"]
        scalars = profile["scalars"]
        save_tokens = profile["save_tokens"]
        if (
            not isinstance(globals_, Mapping)
            or not isinstance(country, Mapping)
            or not isinstance(scalars, Mapping)
            or not isinstance(save_tokens, Mapping)
        ):
            raise ProfileError("profile_layout_not_object")
        supported = country.get("supported_country")
        if supported != EXPECTED_COUNTRY:
            raise ProfileError("profile_supported_country_invalid")
        if set(scalars) != set(FIELDS):
            raise ProfileError("profile_scalars_set_invalid")
        scalar_layout: dict[str, dict[str, Any]] = {}
        for field in FIELDS:
            item = scalars[field]
            if not isinstance(item, Mapping):
                raise ProfileError(f"profile_scalar_not_object:{field}")
            offset = _parse_int(item.get("offset"), f"scalars.{field}.offset")
            width = _parse_int(item.get("width"), f"scalars.{field}.width")
            scale = _parse_int(item.get("scale"), f"scalars.{field}.scale")
            unit = item.get("unit")
            if width != 4 or item.get("signed") is not True:
                raise ProfileError(f"profile_scalar_encoding_invalid:{field}")
            if scale <= 0 or not isinstance(unit, str) or not unit:
                raise ProfileError(f"profile_scalar_metadata_invalid:{field}")
            scalar_layout[field] = {"offset": offset, "width": width, "signed": True, "scale": scale, "unit": unit}
        if len({item["offset"] for item in scalar_layout.values()}) != len(FIELDS):
            raise ProfileError("profile_scalar_offsets_not_distinct")
        entries = _parse_int(country.get("country_scan_entries"), "country.country_scan_entries")
        if entries <= 0 or entries * 8 > MAX_SINGLE_RPM:
            raise ProfileError("profile_country_scan_bound_invalid")
        if set(save_tokens) != {"vector_rva", "tokens"}:
            raise ProfileError("profile_save_tokens_shape_invalid")
        token_items = save_tokens.get("tokens")
        if not isinstance(token_items, Mapping) or set(token_items) != set(FIELDS):
            raise ProfileError("profile_save_token_fields_invalid")
        token_layout: dict[str, dict[str, Any]] = {}
        for field in FIELDS:
            token = token_items[field]
            if not isinstance(token, Mapping) or set(token) != {"key_id", "name"}:
                raise ProfileError(f"profile_save_token_shape_invalid:{field}")
            key_id = _parse_int(token.get("key_id"), f"save_tokens.tokens.{field}.key_id")
            name = token.get("name")
            if key_id > MAX_SAVE_TOKEN_KEY_ID:
                raise ProfileError(f"profile_save_token_key_id_out_of_bound:{field}")
            if name != field:
                raise ProfileError(f"profile_save_token_name_mismatch:{field}")
            token_layout[field] = {"key_id": key_id, "name": name}
        if len({item["key_id"] for item in token_layout.values()}) != len(FIELDS):
            raise ProfileError("profile_save_token_key_ids_not_distinct")
        return {
            "database_rva": _parse_int(globals_.get("database_rva"), "globals.database_rva"),
            "game_rva": _parse_int(globals_.get("game_rva"), "globals.game_rva"),
            "game_date_offset": _parse_int(globals_.get("game_date_offset"), "globals.game_date_offset"),
            "supported_country": supported,
            "table_offset": _parse_int(country.get("table_offset"), "country.table_offset"),
            "handle_offset": _parse_int(country.get("handle_offset"), "country.handle_offset"),
            "country_scan_entries": entries,
            "scalars": scalar_layout,
            "save_tokens": {
                "vector_rva": _parse_int(save_tokens.get("vector_rva"), "save_tokens.vector_rva"),
                "tokens": token_layout,
            },
        }
    except (KeyError, TypeError) as exc:
        raise ProfileError(f"profile_layout_invalid:{exc}") from exc


def _static_contract_guard() -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "evidence_kind": "ordinary_static_file_analysis_plus_bounded_runtime_reader",
        "profile": str(PROFILE_FILE),
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "checks": {},
        "unknown_conditions": [],
    }
    try:
        profile = _load_profile()
        layout = _profile_layout(profile)
        executable = profile.get("executable")
        provenance = profile.get("provenance")
        dependencies = provenance.get("dependencies") if isinstance(provenance, Mapping) else None
        deps_ok, dep_checks, dep_unknown = _dependency_hash_checks(dependencies)
        result["source_dependencies"] = deepcopy(dependencies) if isinstance(dependencies, list) else []
        result["dependency_hash_checks"] = dep_checks
        result["unknown_conditions"].extend(dep_unknown)
        executable_sha = executable.get("sha256") if isinstance(executable, Mapping) else None
        guards = _profile_code_guards(profile)
        result["checks"] = {
            "profile_sha256": True,
            "profile_id": profile.get("profile_id") == "domestic-pressure-memory-1374",
            "game_version": profile.get("game_version") == EXPECTED_VERSION,
            "game_sha256": isinstance(executable_sha, str) and executable_sha.lower() == EXPECTED_EXE_SHA256,
            "supported_country": layout["supported_country"] == EXPECTED_COUNTRY,
            "globals": all(isinstance(layout[key], int) for key in ("database_rva", "game_rva", "game_date_offset")),
            "scalar_fields_exact": set(layout["scalars"]) == set(FIELDS),
            "scalar_widths": all(item["width"] == 4 for item in layout["scalars"].values()),
            "scalar_signed": all(item["signed"] is True for item in layout["scalars"].values()),
            "scalar_metadata": all(item["scale"] > 0 and isinstance(item["unit"], str) and bool(item["unit"]) for item in layout["scalars"].values()),
            "save_token_schema": set(layout["save_tokens"]["tokens"]) == set(FIELDS),
            "save_token_key_ids_bounded": all(0 <= item["key_id"] <= MAX_SAVE_TOKEN_KEY_ID for item in layout["save_tokens"]["tokens"].values()),
            "save_token_names": all(item["name"] == field for field, item in layout["save_tokens"]["tokens"].items()),
            "code_guards": bool(guards),
            "provenance_dependencies": deps_ok,
        }
        failed = [key for key, value in result["checks"].items() if value is not True]
        if failed:
            result["unknown_conditions"].append("profile_contract_check_failed:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (ProfileError, KeyError, TypeError, ValueError, AttributeError) as exc:
        result["unknown_conditions"].append(f"profile_contract_read_failed:{exc}")
    return result


def _safe_add(base: int, offset: int, label: str, *, aligned: bool = False) -> int:
    if not isinstance(base, int) or isinstance(base, bool) or not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ProbeError(f"invalid_address_arithmetic:{label}")
    value = base + offset
    if value < 0x10000 or value >= MAX_USER_ADDRESS:
        raise ProbeError(f"address_range_overflow:{label}")
    if aligned and value % 8:
        raise ProbeError(f"invalid_alignment:{label}")
    return value


def _va(value: Any) -> int | None:
    if isinstance(value, Mapping):
        value = value.get("va")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _country_identity(
    reader: AddressBoundedRPM,
    database: int,
    country: str,
    layout: Mapping[str, Any],
) -> dict[str, Any]:
    table_address = _safe_add(database, int(layout["table_offset"]), "database.country_table", aligned=True)
    table, table_raw = reader.qword(table_address, "database.country_table")
    result: dict[str, Any] = {
        "status": "unknown",
        "requested_country": country,
        "table_address": _address(table_address),
        "table_raw_hex": table_raw.hex(),
        "table": _address(table),
        "entries": int(layout["country_scan_entries"]),
        "matches": [],
        "country_pointer": None,
        "unknown_reason": None,
    }
    if not _valid_pointer(table):
        result["unknown_reason"] = "country_table_pointer_invalid"
        return result
    for index in range(int(layout["country_scan_entries"])):
        entry_address = _safe_add(table, index * 8, f"country_table.entry[{index}]", aligned=True)
        pointer, pointer_raw = reader.qword(entry_address, f"country_table.entry[{index}]")
        entry: dict[str, Any] = {"index": index, "address": _address(entry_address), "raw_hex": pointer_raw.hex(), "pointer": _address(pointer)}
        if pointer == 0:
            entry["status"] = "empty"
            continue
        if not _valid_pointer(pointer):
            entry["status"] = "invalid_pointer"
            continue
        handle_address = _safe_add(pointer, int(layout["handle_offset"]), f"country[{index}].handle", aligned=True)
        handle, handle_raw = reader.qword(handle_address, f"country[{index}].handle")
        tag, slot = _tag_and_slot(handle)
        entry.update({"handle_address": _address(handle_address), "handle_raw_hex": handle_raw.hex(), "tag": tag, "slot": slot})
        if tag == country and slot == index:
            entry["status"] = "match"
            cast_matches = result["matches"]
            assert isinstance(cast_matches, list)
            cast_matches.append(entry)
        else:
            entry["status"] = "other_country"
    matches = result["matches"]
    if not isinstance(matches, list) or len(matches) != 1:
        result["unknown_reason"] = "country_identity_match_count_invalid"
        return result
    result["status"] = "observed"
    result["country_pointer"] = matches[0]["pointer"]
    return result


def _unknown_fields(fields: Sequence[str], reason: str) -> dict[str, dict[str, Any]]:
    return {field: {"status": "unknown", "reason": reason} for field in fields}


def _save_token_guard(
    reader: AddressBoundedRPM,
    module_base: int,
    profile: Mapping[str, Any],
    fields: Sequence[str],
) -> dict[str, Any]:
    """Verify the live String32 names used by the save-token key vector.

    The vector and each header are ordinary bounded reads.  No resolver or
    save/native function is called.  A bad vector is a global failure; a bad
    individual key only makes that requested field unknown while preserving
    the guard evidence for the other fields.
    """

    layout = _profile_layout(profile)
    token_layout = layout["save_tokens"]
    result: dict[str, Any] = {
        "status": "unknown",
        "vector": None,
        "vector_raw_hex": None,
        "checks": {},
        "records": {},
        "unknown_conditions": [],
    }
    try:
        vector_address = _safe_add(module_base, int(token_layout["vector_rva"]), "save_tokens.vector")
        vector, vector_raw = reader.qword(vector_address, "save_tokens.vector")
        result["vector"] = {
            "address": _address(vector_address, module_base, known_rva=int(token_layout["vector_rva"])),
            "value": _address(vector, module_base),
        }
        result["vector_raw_hex"] = vector_raw.hex()
        if not _valid_pointer(vector):
            result["unknown_conditions"].append("save_token_vector_pointer_invalid")
            return result
    except Exception as exc:
        result["unknown_conditions"].append(f"save_token_vector_read_failed:{type(exc).__name__}:{exc}")
        return result

    for field in fields:
        token = token_layout["tokens"][field]
        key_id = int(token["key_id"])
        expected_name = str(token["name"])
        record: dict[str, Any] = {
            "key_id": key_id,
            "expected_name": expected_name,
            "status": "unknown",
            "address": None,
            "header_hex": None,
            "actual_name": None,
            "reason": None,
        }
        try:
            header_address = _safe_add(vector, key_id * 32, f"save_tokens.{field}.header", aligned=True)
            header = reader.read(header_address, 32, f"save_token.{field}.String32")
            record["address"] = _address(header_address)
            record["header_hex"] = header.hex()
            length_begin = int(_mm.STRING_LENGTH_OFFSET)
            length = int.from_bytes(header[length_begin:length_begin + 8], "little")
            record["length"] = length
            # Refuse to ask the generic decoder for more than the known token
            # name plus its terminating NUL.  This bounds heap payload reads.
            if length > len(expected_name):
                record["reason"] = "save_token_name_length_exceeds_expected"
                result["unknown_conditions"].append(f"{field}:{record['reason']}")
                result["checks"][field] = False
                result["records"][field] = record
                continue
            decoded = _decode_string32(reader, header_address, header, f"save_token.{field}.String32")
            record["decoded_status"] = decoded.get("status")
            record["capacity"] = decoded.get("capacity")
            record["payload_hex"] = decoded.get("payload_hex")
            record["nul_terminator_observed"] = decoded.get("nul_terminator_observed")
            record["actual_name"] = decoded.get("text")
            if decoded.get("status") != "observed":
                record["reason"] = decoded.get("unknown_reason") or "save_token_string32_unknown"
            elif decoded.get("text") != expected_name:
                record["reason"] = "save_token_name_mismatch"
            else:
                record["status"] = "observed"
            if record["status"] != "observed":
                result["unknown_conditions"].append(f"{field}:{record['reason']}")
            result["checks"][field] = record["status"] == "observed"
        except Exception as exc:
            record["reason"] = f"{type(exc).__name__}:{exc}"
            result["unknown_conditions"].append(f"{field}:{record['reason']}")
            result["checks"][field] = False
        result["records"][field] = record

    result["status"] = "observed" if all(result["checks"].values()) else "mismatch"
    return result


def _snapshot(
    reader: AddressBoundedRPM,
    module_base: int,
    country: str,
    profile: Mapping[str, Any],
    fields: Sequence[str],
) -> dict[str, Any]:
    layout = _profile_layout(profile)
    result: dict[str, Any] = {
        "status": "unknown",
        "game_pointer": None,
        "database_pointer": None,
        "game_date": None,
        "country_scan": None,
        "save_token_guard": None,
        "field_results": _unknown_fields(fields, "not_read"),
        "values": {},
        "complete": False,
    }
    game_address = _safe_add(module_base, int(layout["game_rva"]), "globals.game_pointer")
    game, game_raw = reader.qword(game_address, "globals.game_pointer")
    database_address = _safe_add(module_base, int(layout["database_rva"]), "globals.database_pointer")
    database, database_raw = reader.qword(database_address, "globals.database_pointer")
    result["game_pointer"] = {"address": _address(game_address, module_base, known_rva=int(layout["game_rva"])), "raw_hex": game_raw.hex(), "value": _address(game, module_base)}
    result["database_pointer"] = {"address": _address(database_address, module_base, known_rva=int(layout["database_rva"])), "raw_hex": database_raw.hex(), "value": _address(database, module_base)}
    # Do not add offsets to untrusted globals.  This check must precede date,
    # country-table, and scalar address arithmetic.
    if not _valid_pointer(game) or not _valid_pointer(database):
        raise ProbeError("game_or_database_pointer_invalid")
    date_address = _safe_add(game, int(layout["game_date_offset"]), "game.game_date")
    date_raw = reader.read(date_address, GAME_DATE_WIDTH, "game.game_date")
    game_date = int.from_bytes(date_raw, "little", signed=True)
    result["game_date"] = {"address": _address(date_address), "value": game_date, "raw_hex": date_raw.hex()}
    country_scan = _country_identity(reader, database, country, layout)
    result["country_scan"] = country_scan
    if country_scan.get("status") != "observed":
        raise ProbeError(f"country_identity:{country_scan.get('unknown_reason', 'unknown')}")
    country_pointer = _va(country_scan.get("country_pointer"))
    if country_pointer is None or not _valid_pointer(country_pointer):
        raise ProbeError("country_pointer_invalid")
    save_token_guard = _save_token_guard(reader, module_base, profile, fields)
    result["save_token_guard"] = save_token_guard
    if save_token_guard.get("status") == "unknown":
        raise ProbeError("save_token_vector_guard_failed")
    field_results: dict[str, dict[str, Any]] = {}
    values: dict[str, int] = {}
    for field in fields:
        if save_token_guard.get("checks", {}).get(field) is not True:
            field_results[field] = {"status": "unknown", "reason": "save_token_guard_failed"}
            continue
        item = layout["scalars"][field]
        try:
            address = _safe_add(country_pointer, int(item["offset"]), f"country.{field}")
            raw = reader.read(address, int(item["width"]), f"country.{field}")
            value = int.from_bytes(raw, "little", signed=True)
            field_results[field] = {
                "status": "known",
                "raw": value,
                "raw_hex": raw.hex(),
                "unit": item["unit"],
                "scale": int(item["scale"]),
            }
            values[field] = value
        except Exception as exc:
            field_results[field] = {"status": "unknown", "reason": f"{type(exc).__name__}:{exc}"}
    result.update({
        "status": "observed",
        "field_results": field_results,
        "values": values,
        "complete": all(item.get("status") == "known" for item in field_results.values()),
    })
    return result


def _file_code_guard(path: Path, profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "path": str(path), "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        for name, rva, expected in _profile_code_guards(profile):
            actual = _read_pe_rva_bytes(path, rva, len(expected))
            result["records"][name] = {"rva": _hex(rva), "expected_hex": expected.hex(), "actual_hex": actual.hex()}
            result["checks"][name] = actual == expected
        failed = [name for name, ok in result["checks"].items() if ok is not True]
        if failed:
            result["status"] = "mismatch"
            result["unknown_conditions"].append("file_code_guard_mismatch:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (OSError, ProbeError, ProfileError, KeyError, TypeError, ValueError) as exc:
        result["unknown_conditions"].append(str(exc))
    return result


def _runtime_code_guard(reader: AddressBoundedRPM, module_base: int, profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "module_base": _address(module_base), "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        for name, rva, expected in _profile_code_guards(profile):
            address = _safe_add(module_base, rva, f"code_guard.{name}")
            actual = reader.read_code(address, len(expected), f"code_guard.{name}")
            result["records"][name] = {"address": _address(address, module_base, known_rva=rva), "expected_hex": expected.hex(), "actual_hex": actual.hex()}
            result["checks"][name] = actual == expected
        failed = [name for name, ok in result["checks"].items() if ok is not True]
        if failed:
            result["status"] = "mismatch"
            result["unknown_conditions"].append("runtime_code_guard_mismatch:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (OSError, ProbeError, ProfileError, KeyError, TypeError, ValueError) as exc:
        result["unknown_conditions"].append(str(exc))
    return result


def _pass(reader: AddressBoundedRPM, module_base: int, country: str, profile: Mapping[str, Any], fields: Sequence[str], start: int) -> dict[str, Any]:
    runtime_guard = _runtime_code_guard(reader, module_base, profile)
    if runtime_guard.get("status") != "observed":
        return {"status": "unknown", "runtime_code_guard": runtime_guard, "read_log": deepcopy(reader.read_log[start:]), "field_results": _unknown_fields(fields, "runtime_code_guard_failed"), "values": {}, "complete": False, "unknown_reason": "runtime_code_guard_failed"}
    try:
        snapshot = _snapshot(reader, module_base, country, profile, fields)
    except Exception as exc:
        return {"status": "unknown", "runtime_code_guard": runtime_guard, "read_log": deepcopy(reader.read_log[start:]), "field_results": _unknown_fields(fields, f"snapshot_failed:{type(exc).__name__}:{exc}"), "values": {}, "complete": False, "unknown_reason": f"snapshot_failed:{type(exc).__name__}:{exc}"}
    snapshot["runtime_code_guard"] = runtime_guard
    snapshot["read_log"] = deepcopy(reader.read_log[start:])
    return snapshot


def _diff_paths(left: Any, right: Any, path: str = "$") -> list[str]:
    if type(left) is not type(right):
        return [path]
    if isinstance(left, dict):
        result: list[str] = []
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                result.append(f"{path}.{key}")
            else:
                result.extend(_diff_paths(left[key], right[key], f"{path}.{key}"))
        return result
    if isinstance(left, list):
        result = []
        if len(left) != len(right):
            result.append(f"{path}.length")
        for index, (a, b) in enumerate(zip(left, right)):
            result.extend(_diff_paths(a, b, f"{path}[{index}]"))
        return result
    return [] if left == right else [path]


def _compare_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": snapshot.get("status"),
        "runtime_code_guard": snapshot.get("runtime_code_guard"),
        "game_pointer": snapshot.get("game_pointer"),
        "database_pointer": snapshot.get("database_pointer"),
        "game_date": snapshot.get("game_date"),
        "country_scan": snapshot.get("country_scan"),
        "save_token_guard": snapshot.get("save_token_guard"),
        "field_results": snapshot.get("field_results"),
        "values": snapshot.get("values"),
        "read_log": snapshot.get("read_log"),
    }


def _base_report(installation: Path, country: str, fields: Sequence[str]) -> dict[str, Any]:
    captured_at = datetime.now(timezone.utc).isoformat()
    return {
        "probe": "information-domestic-pressure-runtime",
        "probe_version": 1,
        "probe_script": str(Path(__file__).resolve()),
        "probe_script_sha256": None,
        "profile": {"path": str(PROFILE_FILE), "sha256": EXPECTED_PROFILE_SHA256, "max_bytes": PROFILE_MAX_BYTES, "profile_id": "domestic-pressure-memory-1374"},
        "read_only": True,
        "native_function_invoked": False,
        "evidence_kind": "pure_runtime_observation_not_static_evidence",
        "captured_at": captured_at,
        "captured_at_utc": captured_at,
        "request": {"installation": str(installation), "country": country, "fields": list(fields)},
        "country": country,
        "target_build": {"version": EXPECTED_VERSION, "expected_exe_sha256": EXPECTED_EXE_SHA256},
        "static_contract_guard": None,
        "file_code_guard": None,
        "runtime_code_guard": None,
        "save_token_guard": None,
        "identity": {"installation_path": str(installation), "installation_pid": None, "installation_creation_filetime": None, "installation_session_id": None, "process_path": None, "process_path_sha256": None, "process_path_sha256_matches_expected": None, "process_creation_filetime": None, "process_creation_utc": None, "process_creation_matches_installation": None, "module_path": None, "module_path_matches_process": None, "binding_verified": False},
        "module_base": None,
        "before": None,
        "after": None,
        "field_results": _unknown_fields(fields, "not_read"),
        "values": None,
        "complete": False,
        "doublepass": {"performed": False, "consistent": None, "mismatches": [], "atomic": False, "atomic_main_thread_snapshot": False},
        "world_generation_verified": False,
        "access": {"open_process_mask": "QUERY_INFORMATION|VM_READ", "open_process_mask_hex": _hex(PROCESS_ACCESS), "rpm_total_limit": MAX_TOTAL_RPM, "rpm_single_read_limit": MAX_SINGLE_RPM, "rpm_bytes_requested": 0, "rpm_calls": 0, "native_game_calls": False, "target_memory_writes": False, "dll_injection": False, "private_heap_scan": False, "ui_control": False, "date_advance": False, "save_or_reload": False},
        "cleanup": {"handle_close": {"status": "unknown", "success": None, "closed": False}},
        "status": "starting",
        "errors": [],
        "completed": False,
    }


def _retract(report: dict[str, Any], reason: str = "observation_retracted") -> None:
    report["values"] = None
    report["complete"] = False
    fields = report.get("field_results")
    if isinstance(fields, Mapping):
        report["field_results"] = _unknown_fields(list(fields), reason)
    for key in ("before", "after"):
        snapshot = report.get(key)
        if isinstance(snapshot, dict):
            snapshot["values"] = None
            snapshot["complete"] = False
            existing = snapshot.get("field_results")
            if isinstance(existing, Mapping):
                snapshot["field_results"] = _unknown_fields(list(existing), reason)


def _apply_cleanup(report: dict[str, Any], kernel: Any, handle: Any) -> None:
    outcome = _close_process_handle(kernel, handle)
    report["cleanup"]["handle_close"] = outcome
    if outcome.get("status") == "error":
        previous = report.get("status")
        report["status"] = "cleanup_error"
        report["errors"].append({"stage": "cleanup", "status": "error", "error": outcome.get("error", "CloseHandle failed"), "previous_status": previous})
        _retract(report, "cleanup_failed")
    report["completed"] = report.get("status") == "observed" and outcome.get("status") == "closed"
    if not report["completed"]:
        _retract(report, "observation_not_completed")


def _normalize_fields(fields: Sequence[str] | None) -> list[str]:
    if fields is None:
        return list(FIELDS)
    if isinstance(fields, (str, bytes)) or not isinstance(fields, Sequence):
        raise ProbeError("fields_must_be_sequence")
    selected = list(fields)
    if not selected or len(selected) > len(FIELDS):
        raise ProbeError("fields_count_out_of_bound")
    if any(not isinstance(item, str) or item not in FIELDS for item in selected):
        raise ProbeError("field_not_supported")
    if len(set(selected)) != len(selected):
        raise ProbeError("duplicate_field")
    return selected


def capture(installation: Path, country: str, fields: Sequence[str] | None = None) -> dict[str, Any]:
    """Capture requested domestic-pressure scalars through pure bounded RPM."""
    installation = Path(installation)
    try:
        selected = _normalize_fields(fields)
    except ProbeError as exc:
        selected = list(FIELDS) if fields is None else []
        report = _base_report(installation, country, selected)
        report["status"] = "invalid_request"
        report["errors"].append({"stage": "request", "status": "unknown", "error": str(exc)})
        _apply_cleanup(report, None, None)
        return report
    report = _base_report(installation, country, selected)
    try:
        report["probe_script_sha256"] = _sha256_file(Path(__file__).resolve())
    except OSError as exc:
        report["errors"].append({"stage": "probe_identity", "status": "unknown", "error": str(exc)})
    if country != EXPECTED_COUNTRY:
        report["status"] = "unsupported_country"
        report["errors"].append({"stage": "request", "status": "unknown", "error": "Only FRA is permitted"})
        _apply_cleanup(report, None, None)
        return report

    contract = _static_contract_guard()
    report["static_contract_guard"] = contract
    if contract.get("status") != "observed":
        report["status"] = "static_contract_mismatch"
        report["errors"].append({"stage": "static_contract", "status": "unknown", "error": "Domestic-pressure profile or dependencies did not match"})
        _apply_cleanup(report, None, None)
        return report

    kernel = None
    handle = None
    reader: AddressBoundedRPM | None = None
    try:
        profile = _load_profile()
        layout = _profile_layout(profile)
        report["profile"]["profile_id"] = profile.get("profile_id")
        report["field_definitions"] = deepcopy(layout["scalars"])
        document = _load_installation(installation)
        pid = _parse_int(document.get("pid"), "installation.pid")
        kernel = _configure_kernel()
        handle = kernel.OpenProcess(PROCESS_ACCESS, False, pid)
        if not handle:
            raise C.WinError(C.get_last_error())
        module_base = _capture_identity(report, document, kernel, handle)
        if report["identity"].get("binding_verified") is not True:
            raise ProbeError("identity_binding_not_verified")
        if not _valid_pointer(module_base):
            raise ProbeError("module_base_invalid")
        report["module_base"] = _address(module_base)
        process_path = Path(report["identity"]["process_path"])
        report["file_code_guard"] = _file_code_guard(process_path, profile)
        if report["file_code_guard"].get("status") != "observed":
            report["status"] = "file_code_mismatch"
            report["errors"].append({"stage": "file_code_guard", "status": "unknown", "error": "Profile code bytes did not match executable"})
        else:
            reader = AddressBoundedRPM(kernel, handle, module_base)
            first = _pass(reader, module_base, country, profile, selected, len(reader.read_log))
            report["before"] = first
            if first.get("status") != "observed":
                report["status"] = "unknown"
                report["errors"].append({"stage": "before", "status": "unknown", "error": first.get("unknown_reason", "first_pass_unknown")})
            else:
                second = _pass(reader, module_base, country, profile, selected, len(reader.read_log))
                report["after"] = second
                report["doublepass"]["performed"] = True
                if second.get("status") != "observed":
                    report["doublepass"]["mismatches"] = ["$.after.status"]
                    report["doublepass"]["consistent"] = False
                    report["status"] = "doublepass_mismatch"
                    report["errors"].append({"stage": "doublepass", "status": "unknown", "error": second.get("unknown_reason", "second_pass_unknown")})
                else:
                    mismatches = _diff_paths(_compare_snapshot(first), _compare_snapshot(second))
                    report["doublepass"]["mismatches"] = mismatches[:256]
                    report["doublepass"]["consistent"] = not mismatches
                    if mismatches:
                        report["status"] = "doublepass_mismatch"
                        report["errors"].append({"stage": "doublepass", "status": "unknown", "error": "Runtime read logs, guards, identity, date or values changed", "paths": mismatches[:256]})
                    else:
                        report["status"] = "observed"
                        report["field_results"] = deepcopy(second.get("field_results", {}))
                        report["values"] = deepcopy(second.get("values", {}))
                        report["complete"] = bool(second.get("complete"))
            passes = [report.get("before"), report.get("after")]
            report["runtime_code_guard"] = {"status": "observed" if all(isinstance(item, Mapping) and isinstance(item.get("runtime_code_guard"), Mapping) and item["runtime_code_guard"].get("status") == "observed" for item in passes if item is not None) and report.get("after") is not None else "unknown", "passes": [(item or {}).get("runtime_code_guard") for item in passes]}
            report["save_token_guard"] = {
                "status": "observed" if all(
                    isinstance(item, Mapping)
                    and isinstance(item.get("save_token_guard"), Mapping)
                    and item["save_token_guard"].get("status") == "observed"
                    for item in passes if item is not None
                ) and report.get("after") is not None else "unknown",
                "passes": [(item or {}).get("save_token_guard") for item in passes],
            }
            report["access"]["rpm_bytes_requested"] = reader.bytes_requested
            report["access"]["rpm_calls"] = reader.calls
    except Exception as exc:
        report["status"] = "error"
        report["errors"].append({"stage": "capture", "status": "unknown", "error": f"{type(exc).__name__}:{exc}"})
    finally:
        if reader is not None:
            report["access"]["rpm_bytes_requested"] = reader.bytes_requested
            report["access"]["rpm_calls"] = reader.calls
    _apply_cleanup(report, kernel, handle)
    return report


__all__ = [
    "AddressBoundedRPM", "PROFILE_FILE", "PROFILE_MAX_BYTES", "EXPECTED_PROFILE_SHA256", "EXPECTED_EXE_SHA256", "EXPECTED_VERSION", "EXPECTED_COUNTRY", "FIELDS", "MAX_SINGLE_RPM", "MAX_TOTAL_RPM", "MAX_USER_ADDRESS", "ProfileError", "ProbeError", "capture", "_load_profile", "_static_contract_guard", "_profile_layout", "_profile_code_guards", "_file_code_guard", "_runtime_code_guard", "_snapshot", "_dependency_hash_checks",
]
