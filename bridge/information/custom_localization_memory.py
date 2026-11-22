"""Bounded read-only capture of the two country-root custom text methods.

This reader is deliberately separate from :mod:`localization_memory`.  The
native custom-localisation registry is a compiled object graph, so a capture
must validate every vector span before reading it and must compare both
passes byte-for-byte.  The reader never calls an EU4 function, evaluates a
predicate, or reads the UI context.  ``country`` is the explicit query
country and the result therefore carries ``ui_root_scope_verified=False``.

Only the two audited method names are accepted.  A method is published when
the current compiled registration contains exactly one option, its predicate
count is zero, its weight is positive and below ``2**31``, its modifier span
is empty, and the country built-in table proves that the same method name is
absent.  These are structural observations; they do not evaluate gameplay
state or dynamic ``Root`` substitutions.
"""
from __future__ import annotations

import ctypes as C
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence

from . import localization_memory as _loc
from . import mission_memory as _mm


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "custom-localization-memory-1374.json"
PROFILE_MAX_BYTES = 64 * 1024
EXPECTED_PROFILE_SHA256 = "de62ff14b90effd34c5a882fdb6d586a85d7314dbf12d55169117b81d96849e6"


class ProfileError(RuntimeError):
    """The frozen custom-localisation profile is absent or tampered with."""


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
    if not isinstance(profile, dict) or profile.get("profile_id") != "custom-localization-memory-1374":
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
CUSTOM_GLOBAL_RVA = _profile_int(PROFILE["globals"]["custom_global_rva"], "custom_global_rva")
BUILTIN_GLOBAL_RVA = _profile_int(PROFILE["globals"]["builtin_global_rva"], "builtin_global_rva")
BUILTIN_INIT_GUARD_RVA = _profile_int(PROFILE["globals"]["builtin_init_guard_rva"], "builtin_init_guard_rva")
COMMON_PROMOTIONS_RVA = _profile_int(PROFILE["globals"]["common_promotions_rva"], "common_promotions_rva")
COMMON_INIT_GUARD_RVA = _profile_int(PROFILE["globals"]["common_init_guard_rva"], "common_init_guard_rva")

COUNTRY_TABLE_OFFSET = _profile_int(PROFILE["country"]["table_offset"], "country.table_offset")
COUNTRY_HANDLE_OFFSET = _profile_int(PROFILE["country"]["handle_offset"], "country.handle_offset")
COUNTRY_SCAN_ENTRIES = _profile_int(PROFILE["country"]["country_scan_entries"], "country.country_scan_entries")

DEFINITION_NAME_OFFSET = _profile_int(PROFILE["layout"]["definition_name_string32_offset"], "definition_name_string32_offset")
DEFINITION_RANDOM_OFFSET = _profile_int(PROFILE["layout"]["definition_random_byte_offset"], "definition_random_byte_offset")
DEFINITION_OPTIONS_BEGIN = _profile_int(PROFILE["layout"]["options_begin_offset"], "options_begin_offset")
DEFINITION_OPTIONS_END = _profile_int(PROFILE["layout"]["options_end_offset"], "options_end_offset")
OPTION_KEY_OFFSET = _profile_int(PROFILE["layout"]["option_key_string32_offset"], "option_key_string32_offset")
OPTION_PREDICATE_POINTER_OFFSET = _profile_int(PROFILE["layout"]["predicate_pointer_offset"], "predicate_pointer_offset")
OPTION_PREDICATE_COUNT_OFFSET = _profile_int(PROFILE["layout"]["predicate_count_offset"], "predicate_count_offset")
OPTION_WEIGHT_OFFSET = _profile_int(PROFILE["layout"]["weight_dword_offset"], "weight_dword_offset")
OPTION_MODIFIERS_BEGIN = _profile_int(PROFILE["layout"]["modifiers_begin_offset"], "modifiers_begin_offset")
OPTION_MODIFIERS_END = _profile_int(PROFILE["layout"]["modifiers_end_offset"], "modifiers_end_offset")
BUILTIN_COUNT_HEADER_OFFSET = _profile_int(PROFILE["layout"]["builtin_count_header_offset"], "builtin_count_header_offset")
BUILTIN_STRIDE = _profile_int(PROFILE["layout"]["builtin_stride"], "builtin_stride")
COMMON_COUNT = _profile_int(PROFILE["layout"]["common_promotions_count"], "common_promotions_count")
COMMON_STRIDE = _profile_int(PROFILE["layout"]["common_promotions_stride"], "common_promotions_stride")
COMMON_ENUM_OFFSET = _profile_int(PROFILE["layout"]["common_promotion_enum_offset"], "common_promotion_enum_offset")
COMMON_ENUM_WIDTH = _profile_int(PROFILE["layout"].get("common_promotion_enum_width", 4), "common_promotion_enum_width")
INIT_STATE_WIDTH = _profile_int(PROFILE["layout"].get("init_state_width", 4), "init_state_width")
ROOT_PROMOTION_ENUM = _profile_int(PROFILE["layout"]["root_promotion_enum"], "root_promotion_enum")
COUNTRY_CONTEXT_ENUM = _profile_int(PROFILE["layout"]["country_context_enum"], "country_context_enum")
COUNTRY_BUILTIN_CALLBACK_RVA = _profile_int(PROFILE["layout"]["country_builtin_callback_rva"], "country_builtin_callback_rva")

STRING_LENGTH_OFFSET = _profile_int(PROFILE["string32"]["length_offset"], "string32.length_offset")
STRING_CAPACITY_OFFSET = _profile_int(PROFILE["string32"]["capacity_offset"], "string32.capacity_offset")
MAX_STRING_BYTES = _profile_int(PROFILE["string32"]["max_bytes"], "string32.max_bytes")
MAX_STRING_CAPACITY = _profile_int(PROFILE["string32"]["max_capacity"], "string32.max_capacity")

MAX_DEFINITIONS = _profile_int(PROFILE["limits"]["max_definitions"], "max_definitions")
MAX_OPTIONS = _profile_int(PROFILE["limits"]["max_options"], "max_options")
MAX_BUILTIN_NAMES = _profile_int(PROFILE["limits"]["max_builtin_names"], "max_builtin_names")
MAX_TOTAL_RPM = _profile_int(PROFILE["limits"]["max_total_rpm"], "max_total_rpm")
MAX_SINGLE_RPM = _profile_int(PROFILE["limits"]["max_single_rpm"], "max_single_rpm")

PROCESS_ACCESS = _mm.PROCESS_ACCESS
MAX_USER_ADDRESS = _mm.MAX_USER_ADDRESS
METHODS = ("GetSelectableMissionTitle", "GetSelectableMissionDescription")


# Stable seams make the native path testable without monkey-patching the old
# localisation snapshot.  The implementation remains independent of its
# private two-pass logic.
_configure_kernel = _mm._configure_kernel
_load_installation = _loc._load_installation
_capture_identity = _loc._capture_identity
_sha256_file = _loc._sha256_file
_read_pe_rva_bytes = _loc._read_pe_rva_bytes
_close_process_handle = _loc._close_process_handle
_country_identity = _loc._country_identity
_address = _loc._address
_parse_int = _loc._parse_int
_valid_pointer = _mm._valid_pointer


def _hex(value: int | None) -> str | None:
    return hex(value) if isinstance(value, int) else None


def _read_unaligned(reader: Any, address: int, size: int, label: str) -> bytes:
    method = getattr(reader, "read_code", None)
    if callable(method):
        return method(address, size, label)
    method = getattr(reader, "_read", None)
    if callable(method):
        return method(address, size, label, aligned=False)
    return reader.read(address, size, label)


class AddressBoundedRPM(_mm.BoundedRPM):
    """Shared RPM budget plus a full ``address + size`` user-range guard."""

    def __init__(self, kernel: Any, handle: Any, module_base: int):
        super().__init__(kernel, handle, module_base)
        self.read_log: list[dict[str, Any]] = []

    def clear_log(self) -> None:
        self.read_log.clear()

    def _read(self, address: int, size: int, label: str, *, aligned: bool) -> bytes:
        if not isinstance(address, int) or not isinstance(size, int) or size <= 0:
            raise ProbeError(f"invalid_bounded_read:{label}")
        if address < 0x10000 or address > MAX_USER_ADDRESS - size:
            raise ProbeError(f"invalid_bounded_read_span:{label}")
        if size > MAX_SINGLE_RPM:
            raise ProbeError(f"invalid_bounded_read:{label}")
        try:
            raw = super()._read(address, size, label, aligned=aligned)
        except _mm.ProbeError as exc:
            # Keep this module's public failure type stable even though the
            # byte-budget implementation is shared with the older reader.
            raise ProbeError(str(exc)) from exc
        self.read_log.append({"label": label, "address": _hex(address), "size": size, "raw_hex": raw.hex()})
        return raw


BoundedRPM = AddressBoundedRPM


def _profile_code_guards(profile: Mapping[str, Any] | None = None) -> list[tuple[str, int, bytes]]:
    profile = PROFILE if profile is None else profile
    guards: list[tuple[str, int, bytes]] = []
    for item in profile["code_guards"]:
        if not isinstance(item, Mapping):
            raise ProfileError("profile_code_guard_not_object")
        name = str(item.get("name"))
        rva = _profile_int(item.get("rva"), f"code_guard.{name}.rva")
        raw_hex = item.get("bytes")
        if not isinstance(raw_hex, str) or not raw_hex or len(raw_hex) % 2:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}")
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}") from exc
        if len(raw) != _profile_int(item.get("size"), f"code_guard.{name}.size"):
            raise ProfileError(f"profile_code_guard_size_mismatch:{name}")
        if hashlib.sha256(raw).hexdigest() != str(item.get("sha256", "")).lower():
            raise ProfileError(f"profile_code_guard_sha_mismatch:{name}")
        end = _profile_int(item.get("end_rva_exclusive"), f"code_guard.{name}.end")
        if end != rva + len(raw):
            raise ProfileError(f"profile_code_guard_range_mismatch:{name}")
        if len(raw) > MAX_SINGLE_RPM:
            raise ProfileError(f"profile_code_guard_too_large:{name}")
        guards.append((name, rva, raw))
    return guards


def _static_contract_guard() -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "evidence_kind": "frozen_machine_contract_join_not_native_execution",
        "profile": str(PROFILE_FILE),
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "contract_sha256": PROFILE.get("contract_sha256"),
        "source_evidence_sha256": {key: value.get("sha256") for key, value in PROFILE.get("source_evidence", {}).items() if isinstance(value, Mapping)},
        "checks": {},
        "unknown_conditions": [],
    }
    try:
        profile = _load_profile()
        layout = profile["layout"]
        policy = profile["selection_policy"]
        limits = profile["limits"]
        result["checks"] = {
            "profile_sha256": True,
            "game_sha256": profile["executable"]["sha256"].lower() == EXPECTED_EXE_SHA256,
            "contract_sha256": isinstance(profile.get("contract_sha256"), str) and len(profile["contract_sha256"]) == 64,
            "supported_country": profile["country"]["supported_country"] == "FRA",
            "custom_global": layout["custom_global_rva"] == "0x233d900",
            "definition_fields": (
                layout["definition_name_string32_offset"] == "0x18"
                and layout["definition_random_byte_offset"] == "0x10"
                and layout["options_begin_offset"] == "0x38"
                and layout["options_end_offset"] == "0x40"
            ),
            "option_fields": (
                layout["option_key_string32_offset"] == "0x10"
                and layout["predicate_pointer_offset"] == "0x38"
                and layout["predicate_count_offset"] == "0x44"
                and layout["weight_dword_offset"] == "0xb8"
                and layout["modifiers_begin_offset"] == "0xc0"
                and layout["modifiers_end_offset"] == "0xc8"
            ),
            "builtin_layout": (
                layout["builtin_global_rva"] == "0x245ac98"
                and layout["builtin_count_header_offset"] == "0xc"
                and layout["builtin_stride"] == 40
                and layout["builtin_init_guard_rva"] == "0x245ac8c"
            ),
            "common_layout": (
                layout["common_promotions_rva"] == "0x2327a20"
                and layout["common_promotions_count"] == 6
                and layout["common_promotions_stride"] == 40
                and layout["common_promotion_enum_offset"] == "0x20"
                and layout.get("common_promotion_enum_width") == 4
                and layout.get("init_state_width") == 4
                and layout["common_init_guard_rva"] == "0x245af84"
            ),
            "selection_policy": (
                policy["whitelist"] == list(METHODS)
                and policy["unique_name_required"] is True
                and policy["builtin_raw_exact_absence_required"] is True
                and policy["builtin_count_zero_is_unknown"] is True
                and policy["init_state_required"] == "signed DWORD at the profiled init-state RVA must not be 0 or -1"
                and policy["whole_template_only"] is False
                and policy["template_rule"] == "one supported Root placeholder with literal prefix and suffix; no other bracket or dollar markers"
                and policy["literal_surroundings_preserved"] is True
                and policy["engine_evaluation_invoked"] is False
                and policy["option_count_required"] == 1
                and policy["predicate_count_required"] == 0
                and policy["modifier_span_required"] == "begin == end, valid empty pointers"
            ),
            "limits": (
                limits["max_definitions"] == 2048
                and limits["max_options"] == 128
                and limits["max_builtin_names"] == 2048
                and limits["max_total_rpm"] == 524288
                and limits["max_single_rpm"] == 65536
                and limits["require_full_user_address_span"] is True
            ),
            "code_guards": len(_profile_code_guards(profile)) == 11,
            "source_refs": all(isinstance(v, Mapping) and isinstance(v.get("sha256"), str) and len(v["sha256"]) == 64 for v in profile.get("source_evidence", {}).values()),
        }
        failed = [key for key, value in result["checks"].items() if value is not True]
        if failed:
            result["unknown_conditions"].append("profile_contract_check_failed:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (ProfileError, KeyError, TypeError, ValueError) as exc:
        result["unknown_conditions"].append(f"profile_contract_read_failed:{exc}")
    return result


def _file_code_guard(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "path": str(path), "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        for name, rva, expected in _profile_code_guards():
            actual = _read_pe_rva_bytes(path, rva, len(expected))
            result["records"][name] = {"rva": _hex(rva), "expected_hex": expected.hex(), "actual_hex": actual.hex(), "sha256": hashlib.sha256(actual).hexdigest()}
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
    result: dict[str, Any] = {"status": "unknown", "module_base": _address(module_base), "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        for name, rva, expected in _profile_code_guards():
            address = module_base + rva
            actual = _read_unaligned(reader, address, len(expected), f"code_guard.{name}")
            result["records"][name] = {"rva": _hex(rva), "address": _address(address, module_base, known_rva=rva), "expected_hex": expected.hex(), "actual_hex": actual.hex(), "sha256": hashlib.sha256(actual).hexdigest()}
            result["checks"][name] = actual == expected
        failed = [name for name, value in result["checks"].items() if value is not True]
        if failed:
            result["status"] = "mismatch"
            result["unknown_conditions"].append("runtime_code_guard_mismatch:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (OSError, ProbeError, ProfileError, KeyError, TypeError, ValueError) as exc:
        result["unknown_conditions"].append(str(exc))
    return result


def _valid_full_span(begin: int, end: int, stride: int, maximum: int, label: str, *, allow_null: bool = True) -> int:
    if not isinstance(begin, int) or not isinstance(end, int) or not isinstance(stride, int) or stride <= 0:
        raise ProbeError(f"{label}_span_invalid")
    if allow_null and begin == end == 0:
        return 0
    if begin < 0x10000 or end < 0x10000 or begin % 8 or end % 8:
        raise ProbeError(f"{label}_pointer_invalid")
    if begin > MAX_USER_ADDRESS or end > MAX_USER_ADDRESS or end < begin:
        raise ProbeError(f"{label}_address_span_invalid")
    span = end - begin
    if span % stride:
        raise ProbeError(f"{label}_odd_span")
    count = span // stride
    if count > maximum:
        raise ProbeError(f"{label}_count_out_of_bound")
    if span > MAX_USER_ADDRESS - begin:
        raise ProbeError(f"{label}_address_span_invalid")
    return count


def _read_span(reader: Any, begin: int, size: int, label: str) -> bytes:
    if not isinstance(begin, int) or not isinstance(size, int) or size < 0:
        raise ProbeError(f"{label}_size_invalid")
    if size == 0:
        return b""
    if begin < 0x10000 or begin > MAX_USER_ADDRESS or size > MAX_USER_ADDRESS - begin:
        raise ProbeError(f"{label}_address_span_invalid")
    chunks: list[bytes] = []
    offset = 0
    while offset < size:
        chunk = min(MAX_SINGLE_RPM, size - offset)
        chunks.append(_read_unaligned(reader, begin + offset, chunk, f"{label}[{offset}:{offset + chunk}]"))
        offset += chunk
    return b"".join(chunks)


def _field(address: int, raw: bytes, value: int, module_base: int, offset: int | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"address": _address(address, module_base), "raw_hex": raw.hex(), "value": _hex(value), "value_address": _address(value, module_base)}
    if offset is not None:
        result["field_offset"] = _hex(offset)
    return result


def _read_string32(reader: Any, address: int, label: str) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "complete": False, "address": _address(address, reader.module_base), "header_hex": None, "length": None, "capacity": None, "storage": None, "heap_pointer": None, "payload_hex": None, "raw_hex": None, "nul_terminator_observed": None, "text": None, "unknown_reason": None, "read_label": label}
    try:
        if not _valid_pointer(address):
            result["unknown_reason"] = "string32_address_invalid"
            return result
        header = reader.read(address, 32, f"{label}.header")
        if len(header) != 32:
            result["unknown_reason"] = "string32_header_short"
            return result
        length = int.from_bytes(header[STRING_LENGTH_OFFSET:STRING_LENGTH_OFFSET + 8], "little")
        capacity = int.from_bytes(header[STRING_CAPACITY_OFFSET:STRING_CAPACITY_OFFSET + 8], "little")
        result.update({"header_hex": header.hex(), "length": length, "capacity": capacity, "storage": "inline" if capacity < 16 else "heap"})
        if length > MAX_STRING_BYTES or capacity < length or capacity > MAX_STRING_CAPACITY:
            result["unknown_reason"] = "string32_length_or_capacity_invalid"
            return result
        if capacity < 16:
            if length > 15:
                result["unknown_reason"] = "string32_inline_length_invalid"
                return result
            payload = header[:16]
        else:
            pointer = int.from_bytes(header[:8], "little")
            result["heap_pointer"] = _address(pointer, reader.module_base)
            if not _valid_pointer(pointer):
                result["unknown_reason"] = "string32_heap_pointer_invalid"
                return result
            payload = reader.read(pointer, length + 1, f"{label}.payload")
        if len(payload) <= length or payload[length] != 0 or b"\x00" in payload[:length]:
            result["nul_terminator_observed"] = False
            result["unknown_reason"] = "string32_nul_missing_or_embedded"
            return result
        raw = payload[:length]
        result.update({"payload_hex": payload[:length + 1].hex(), "raw_hex": raw.hex(), "nul_terminator_observed": True, "status": "observed", "complete": True})
        if raw and all(0x20 <= byte <= 0x7E for byte in raw):
            result["text"] = raw.decode("ascii")
        elif not raw:
            result["text"] = ""
        return result
    except Exception as exc:
        result["unknown_reason"] = f"string32_read_failed:{exc}"
        return result


def _method_unknown(name: str, reason: str) -> dict[str, Any]:
    return {"name": name, "status": "unknown", "text_key": None, "selection": {"status": "unknown", "unknown_reason": reason, "derived_for_query_country_root": False, "ui_root_scope_verified": False}, "unknown_reason": reason}


def _unknown_methods(methods: Sequence[str], reason: str) -> dict[str, Any]:
    return {method: _method_unknown(method, reason) for method in methods}


def _common_promotions(reader: Any, module_base: int) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "entries": [], "root_matches": [], "init_guard_raw_hex": None, "init_epoch": None, "init_state_address": None, "raw_hex": None, "unknown_reason": None}
    try:
        init_address = module_base + COMMON_INIT_GUARD_RVA
        init_raw = _read_unaligned(reader, init_address, INIT_STATE_WIDTH, "common_promotions.init_state")
        init_epoch = int.from_bytes(init_raw, "little", signed=True)
        result.update({"init_guard_raw_hex": init_raw.hex(), "init_epoch": init_epoch, "init_state_address": _address(init_address, module_base, known_rva=COMMON_INIT_GUARD_RVA)})
        if init_epoch in (0, -1):
            result["unknown_reason"] = "common_promotion_table_uninitialized_or_initializing"
            return result
        table = module_base + COMMON_PROMOTIONS_RVA
        raw = _read_span(reader, table, COMMON_COUNT * COMMON_STRIDE, "common_promotions.table")
        result["raw_hex"] = raw.hex()
        for index in range(COMMON_COUNT):
            record = raw[index * COMMON_STRIDE:(index + 1) * COMMON_STRIDE]
            address = table + index * COMMON_STRIDE
            name = _read_string32(reader, address, f"common_promotions[{index}].name")
            enum_raw = record[COMMON_ENUM_OFFSET:COMMON_ENUM_OFFSET + COMMON_ENUM_WIDTH]
            enum = int.from_bytes(enum_raw, "little")
            entry = {"index": index, "raw_hex": record.hex(), "name": name, "enum": enum, "enum_raw_hex": enum_raw.hex()}
            result["entries"].append(entry)
            if name.get("status") == "observed" and name.get("raw_hex") == b"Root".hex():
                result["root_matches"].append(entry)
        if any(entry["name"].get("status") != "observed" for entry in result["entries"]):
            result["unknown_reason"] = "common_promotion_name_unknown"
            return result
        if len(result["root_matches"]) != 1:
            result["unknown_reason"] = "root_promotion_not_unique"
            return result
        if result["root_matches"][0].get("enum") != ROOT_PROMOTION_ENUM:
            result["unknown_reason"] = "root_promotion_enum_mismatch"
            return result
        result["status"] = "observed"
        return result
    except Exception as exc:
        result["unknown_reason"] = f"common_promotion_read_failed:{exc}"
        return result


def _country_builtins(reader: Any, module_base: int, methods: Sequence[str]) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "global_rva": _hex(BUILTIN_GLOBAL_RVA), "init_guard_raw_hex": None, "init_epoch": None, "init_state_address": None, "header_hex": None, "pointer": None, "count": None, "entries": [], "requested_matches": {method: [] for method in methods}, "unknown_reason": None}
    try:
        init_address = module_base + BUILTIN_INIT_GUARD_RVA
        init_raw = _read_unaligned(reader, init_address, INIT_STATE_WIDTH, "country_builtins.init_state")
        init_epoch = int.from_bytes(init_raw, "little", signed=True)
        result.update({"init_guard_raw_hex": init_raw.hex(), "init_epoch": init_epoch, "init_state_address": _address(init_address, module_base, known_rva=BUILTIN_INIT_GUARD_RVA)})
        if init_epoch in (0, -1):
            result["unknown_reason"] = "country_builtin_table_uninitialized_or_initializing"
            return result
        header_address = module_base + BUILTIN_GLOBAL_RVA
        header = _read_unaligned(reader, header_address, 16, "country_builtins.header")
        pointer = int.from_bytes(header[:8], "little")
        count = int.from_bytes(header[BUILTIN_COUNT_HEADER_OFFSET:BUILTIN_COUNT_HEADER_OFFSET + 4], "little", signed=True)
        result.update({"header_hex": header.hex(), "pointer": _address(pointer, module_base), "count": count})
        if count < 0 or count > MAX_BUILTIN_NAMES:
            result["unknown_reason"] = "country_builtins_count_out_of_bound"
            return result
        if count == 0:
            result["unknown_reason"] = "country_builtins_count_zero_or_uninitialized"
            return result
        if not _valid_pointer(pointer):
            result["unknown_reason"] = "country_builtins_pointer_invalid"
            return result
        raw = _read_span(reader, pointer, count * BUILTIN_STRIDE, "country_builtins.records")
        for index in range(count):
            record = raw[index * BUILTIN_STRIDE:(index + 1) * BUILTIN_STRIDE]
            address = pointer + index * BUILTIN_STRIDE
            name = _read_string32(reader, address, f"country_builtins[{index}].name")
            entry = {"index": index, "raw_hex": record.hex(), "name": name}
            result["entries"].append(entry)
            raw_name = bytes.fromhex(str(name.get("raw_hex"))) if name.get("status") == "observed" else None
            for method in methods:
                if raw_name == method.encode("ascii"):
                    result["requested_matches"][method].append(index)
        if any(entry["name"].get("status") != "observed" for entry in result["entries"]):
            result["unknown_reason"] = "country_builtin_name_unknown"
            return result
        result["status"] = "observed"
        return result
    except Exception as exc:
        result["unknown_reason"] = f"country_builtins_read_failed:{exc}"
        return result


def _read_option(reader: Any, option_pointer: int, index: int) -> dict[str, Any]:
    raw = reader.read(option_pointer, 0xD0, f"customloc.option[{index}].object")
    key = _read_string32(reader, option_pointer + OPTION_KEY_OFFSET, f"customloc.option[{index}].key")
    predicate_pointer = int.from_bytes(raw[OPTION_PREDICATE_POINTER_OFFSET:OPTION_PREDICATE_POINTER_OFFSET + 8], "little")
    predicate_count = int.from_bytes(raw[OPTION_PREDICATE_COUNT_OFFSET:OPTION_PREDICATE_COUNT_OFFSET + 4], "little")
    weight = int.from_bytes(raw[OPTION_WEIGHT_OFFSET:OPTION_WEIGHT_OFFSET + 4], "little")
    modifiers_begin = int.from_bytes(raw[OPTION_MODIFIERS_BEGIN:OPTION_MODIFIERS_BEGIN + 8], "little")
    modifiers_end = int.from_bytes(raw[OPTION_MODIFIERS_END:OPTION_MODIFIERS_END + 8], "little")
    return {
        "index": index, "address": _address(option_pointer, reader.module_base), "raw_hex": raw.hex(), "key": key,
        "predicate_pointer": _address(predicate_pointer, reader.module_base), "predicate_pointer_raw_hex": raw[OPTION_PREDICATE_POINTER_OFFSET:OPTION_PREDICATE_POINTER_OFFSET + 8].hex(),
        "predicate_count": predicate_count, "predicate_count_raw_hex": raw[OPTION_PREDICATE_COUNT_OFFSET:OPTION_PREDICATE_COUNT_OFFSET + 4].hex(),
        "weight": weight, "weight_raw_hex": raw[OPTION_WEIGHT_OFFSET:OPTION_WEIGHT_OFFSET + 4].hex(),
        "modifiers_begin": _address(modifiers_begin, reader.module_base), "modifiers_end": _address(modifiers_end, reader.module_base),
        "modifiers_begin_raw_hex": raw[OPTION_MODIFIERS_BEGIN:OPTION_MODIFIERS_BEGIN + 8].hex(), "modifiers_end_raw_hex": raw[OPTION_MODIFIERS_END:OPTION_MODIFIERS_END + 8].hex(),
    }


def _selection_for_method(method: str, definition: dict[str, Any], options: list[dict[str, Any]], builtin: dict[str, Any], common: dict[str, Any]) -> dict[str, Any]:
    reason: str | None = None
    if len(options) != 1:
        reason = "option_count_not_one"
    elif definition.get("name", {}).get("status") != "observed":
        reason = "definition_name_unknown"
    elif builtin.get("status") != "observed":
        reason = "country_builtin_absence_unknown"
    elif builtin.get("requested_matches", {}).get(method):
        reason = "builtin_name_present"
    elif common.get("status") != "observed" or len(common.get("root_matches", [])) != 1:
        reason = "root_promotion_not_observed"
    elif definition.get("random_byte") not in (0, 1):
        reason = "random_flag_invalid"
    else:
        option = options[0]
        key = option.get("key", {})
        if key.get("status") != "observed":
            reason = "option_text_key_unknown"
        else:
            predicate_pointer = _parse_int(option.get("predicate_pointer", {}).get("va"))
            if predicate_pointer not in (None, 0) and not _valid_pointer(predicate_pointer):
                reason = "predicate_pointer_invalid"
        if reason is None and int(option.get("predicate_count", -1)) != 0:
            reason = "predicate_count_not_zero"
        elif reason is None and not (0 < int(option.get("weight", 0)) < 0x80000000):
            reason = "weight_not_positive_bounded"
        elif reason is None:
            begin = _parse_int(option.get("modifiers_begin", {}).get("va"))
            end = _parse_int(option.get("modifiers_end", {}).get("va"))
            if begin is None or end is None or begin != end or (begin and not _valid_pointer(begin)):
                reason = "modifiers_not_empty"
    if reason is not None:
        return {"status": "unknown", "unknown_reason": reason, "derived_for_query_country_root": False, "ui_root_scope_verified": False}
    option = options[0]
    key = option["key"]
    return {
        "status": "observed", "kind": "single_unconditional_positive_weight", "option_count": 1,
        "predicate_count": 0, "weight": option["weight"], "modifiers_empty": True, "random_flag": definition.get("random_byte"),
        "builtin_name_absent": True, "root_promotion_enum": ROOT_PROMOTION_ENUM,
        "derived_for_query_country_root": True, "ui_root_scope_verified": False,
        "option_index": option["index"], "option_address": option["address"], "text_key": key,
    }


def _custom_registry(reader: Any, module_base: int, methods: Sequence[str], builtin: dict[str, Any], common: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "global_rva": _hex(CUSTOM_GLOBAL_RVA), "global_raw_hex": None, "database_pointer": None, "database_header_hex": None, "count": None, "methods": {method: _method_unknown(method, "not_read") for method in methods}, "unknown_names": [], "scan_records": [], "unknown_reason": None}
    try:
        global_address = module_base + CUSTOM_GLOBAL_RVA
        global_raw = _read_unaligned(reader, global_address, 8, "customloc.global")
        database = int.from_bytes(global_raw, "little")
        result["global_raw_hex"] = global_raw.hex()
        result["database_pointer"] = _address(database, module_base)
        if not _valid_pointer(database):
            result["unknown_reason"] = "customloc_database_pointer_invalid"
            return result
        header = _read_unaligned(reader, database, 16, "customloc.vector.header")
        begin = int.from_bytes(header[:8], "little")
        end = int.from_bytes(header[8:16], "little")
        count = _valid_full_span(begin, end, 8, MAX_DEFINITIONS, "customloc.definition_vector")
        result["database_header_hex"] = header.hex()
        result["count"] = count
        pointer_raw = _read_span(reader, begin, count * 8, "customloc.definition_vector") if count else b""
        definitions: list[dict[str, Any]] = []
        matches: dict[str, list[dict[str, Any]]] = {method: [] for method in methods}
        for index in range(count):
            pointer_bytes = pointer_raw[index * 8:(index + 1) * 8]
            definition_pointer = int.from_bytes(pointer_bytes, "little")
            if not _valid_pointer(definition_pointer):
                result["unknown_names"].append({"index": index, "reason": "definition_pointer_invalid", "pointer_raw_hex": pointer_bytes.hex()})
                result["scan_records"].append({"index": index, "pointer_raw_hex": pointer_bytes.hex(), "status": "unknown", "unknown_reason": "definition_pointer_invalid"})
                continue
            header_raw = reader.read(definition_pointer, 0x48, f"customloc.definition[{index}].header")
            definition_name = _read_string32(reader, definition_pointer + DEFINITION_NAME_OFFSET, f"customloc.definition[{index}].name")
            result["scan_records"].append({"index": index, "pointer_raw_hex": pointer_bytes.hex(), "address": _address(definition_pointer, module_base), "header_hex": header_raw.hex(), "name": definition_name})
            definition: dict[str, Any] = {"index": index, "address": _address(definition_pointer, module_base), "pointer_raw_hex": pointer_bytes.hex(), "header_hex": header_raw.hex(), "name": definition_name, "random_byte": header_raw[DEFINITION_RANDOM_OFFSET], "options_begin_raw_hex": header_raw[DEFINITION_OPTIONS_BEGIN:DEFINITION_OPTIONS_BEGIN + 8].hex(), "options_end_raw_hex": header_raw[DEFINITION_OPTIONS_END:DEFINITION_OPTIONS_END + 8].hex(), "options": []}
            definitions.append(definition)
            if definition_name.get("status") != "observed":
                result["unknown_names"].append({"index": index, "reason": definition_name.get("unknown_reason"), "address": definition["address"]})
                continue
            raw_name = bytes.fromhex(str(definition_name["raw_hex"]))
            for method in methods:
                if raw_name == method.encode("ascii"):
                    matches[method].append(definition)
        if result["unknown_names"]:
            # Keep the scan records, but do not claim a unique target while an
            # unreadable registration could be a duplicate.
            for method in methods:
                result["methods"][method] = _method_unknown(method, "customloc_definition_name_unknown")
            result["unknown_reason"] = "customloc_definition_name_unknown"
            return result
        for method in methods:
            candidates = matches[method]
            if len(candidates) != 1:
                result["methods"][method] = _method_unknown(method, "customloc_method_not_found" if not candidates else "customloc_method_name_not_unique")
                continue
            definition = candidates[0]
            begin_options = int.from_bytes(bytes.fromhex(definition["options_begin_raw_hex"]), "little")
            end_options = int.from_bytes(bytes.fromhex(definition["options_end_raw_hex"]), "little")
            option_count = _valid_full_span(begin_options, end_options, 8, MAX_OPTIONS, f"customloc.options.{method}")
            option_raw = _read_span(reader, begin_options, option_count * 8, f"customloc.options.{method}.pointers") if option_count else b""
            options: list[dict[str, Any]] = []
            for index in range(option_count):
                option_pointer = int.from_bytes(option_raw[index * 8:(index + 1) * 8], "little")
                if not _valid_pointer(option_pointer):
                    raise ProbeError(f"customloc.option_pointer_invalid:{method}:{index}")
                options.append(_read_option(reader, option_pointer, index))
            definition["option_count"] = option_count
            definition["option_pointer_bytes_hex"] = option_raw.hex()
            definition["options"] = options
            definition["selection"] = _selection_for_method(method, definition, options, builtin, common)
            selected = definition["selection"]
            if selected.get("status") == "observed":
                option = options[0]
                text_key = option["key"]
                result["methods"][method] = {
                    "name": method, "status": "observed", "text_key": text_key,
                    "selection": selected, "definition": {key: definition[key] for key in ("index", "address", "header_hex", "random_byte", "name", "option_count", "options")},
                }
            else:
                result["methods"][method] = {"name": method, "status": "unknown", "text_key": None, "selection": selected, "unknown_reason": selected.get("unknown_reason")}
        result["definitions"] = [definition for definition in definitions if any(definition is candidate for candidate_list in matches.values() for candidate in candidate_list)]
        result["status"] = "observed"
        return result
    except Exception as exc:
        result["unknown_reason"] = f"customloc_registry_read_failed:{exc}"
        return result


def _snapshot(reader: Any, module_base: int, country: str, methods: Sequence[str], runtime_guard: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "unknown_conditions": [], "game_pointer": None, "database_pointer": None, "game_date": None, "country_scan": None, "common_promotions": None, "country_builtins": None, "custom_localization": None, "methods": _unknown_methods(methods, "not_read"), "runtime_code_guard": dict(runtime_guard or {}), "comparison": None}
    try:
        game_address = module_base + GAME_RVA
        game_raw = reader.read(game_address, 8, "global.game_pointer")
        game = int.from_bytes(game_raw, "little")
        database_address = module_base + DATABASE_RVA
        database_raw = reader.read(database_address, 8, "global.database_pointer")
        database = int.from_bytes(database_raw, "little")
        result["game_pointer"] = _field(game_address, game_raw, game, module_base, GAME_RVA)
        result["database_pointer"] = _field(database_address, database_raw, database, module_base, DATABASE_RVA)
        if not _valid_pointer(game) or not _valid_pointer(database):
            result["unknown_conditions"].append("game_or_database_pointer_invalid")
            return result
        date_address = game + GAME_DATE_OFFSET
        date_raw = reader.read(date_address, 4, "game.raw_date")
        result["game_date"] = {"address": _address(date_address, module_base), "field_offset": _hex(GAME_DATE_OFFSET), "raw_hex": date_raw.hex(), "raw": int.from_bytes(date_raw, "little", signed=True)}
        country_scan = _country_identity(reader, database, country)
        result["country_scan"] = country_scan
        if country_scan.get("status") != "observed":
            result["unknown_conditions"].append(country_scan.get("unknown_reason", "country_identity_unknown"))
            return result
        common = _common_promotions(reader, module_base)
        builtin = _country_builtins(reader, module_base, methods)
        custom = _custom_registry(reader, module_base, methods, builtin, common)
        result["common_promotions"] = common
        result["country_builtins"] = builtin
        result["custom_localization"] = custom
        result["methods"] = custom.get("methods", _unknown_methods(methods, "customloc_not_read"))
        if common.get("status") != "observed":
            result["unknown_conditions"].append(common.get("unknown_reason", "common_promotion_unknown"))
        if builtin.get("status") != "observed":
            result["unknown_conditions"].append(builtin.get("unknown_reason", "country_builtin_unknown"))
        if custom.get("status") != "observed":
            result["unknown_conditions"].append(custom.get("unknown_reason", "customloc_unknown"))
        result["status"] = "observed" if not result["unknown_conditions"] else "unknown"
        material = {key: result[key] for key in ("game_pointer", "database_pointer", "game_date", "country_scan", "common_promotions", "country_builtins", "custom_localization")}
        result["comparison"] = {"reads": list(getattr(reader, "read_log", [])), "material": material, "runtime_code_guard": dict((runtime_guard or {}).get("records", {}))}
        return result
    except Exception as exc:
        result["unknown_conditions"].append(f"customloc_snapshot_failed:{exc}")
        return result


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
        paths: list[str] = []
        if len(left) != len(right):
            paths.append(f"{path}.length")
        for index, (a, b) in enumerate(zip(left, right)):
            paths.extend(_diff_paths(a, b, f"{path}[{index}]"))
        return paths
    return [] if left == right else [path]


def _base_report(installation: Path, country: str, methods: Sequence[str]) -> dict[str, Any]:
    return {
        "probe": "information-custom-localization-runtime", "probe_version": 1,
        "probe_script": str(Path(__file__).resolve()), "probe_script_sha256": None,
        "profile": {"path": str(PROFILE_FILE), "sha256": EXPECTED_PROFILE_SHA256, "max_bytes": PROFILE_MAX_BYTES, "profile_id": PROFILE.get("profile_id")},
        "read_only": True, "evidence_kind": "pure_runtime_observation_not_static_evidence",
        "target_build": {"version": EXPECTED_VERSION, "expected_exe_sha256": EXPECTED_EXE_SHA256, "database_rva": _hex(DATABASE_RVA), "game_rva": _hex(GAME_RVA), "custom_global_rva": _hex(CUSTOM_GLOBAL_RVA)},
        "query_scope": {"country": country, "root_kind": "country", "binding": "explicit_query_observer", "ui_root_scope_verified": False},
        "root_scope": "query_observer_country",
        "static_contract_reference": {"contract_sha256": PROFILE.get("contract_sha256"), "source_evidence": dict(PROFILE.get("source_evidence", {})), "static_results_are_not_runtime_observation": True, "native_functions_invoked": False},
        "static_contract_guard": None, "file_code_guard": None, "runtime_code_guard": None,
        "request": {"installation": str(installation), "country": country, "methods": list(methods), "max_methods": len(METHODS)},
        "identity": {"installation_path": str(installation), "installation_pid": None, "installation_creation_filetime": None, "installation_session_id": None, "process_path": None, "process_path_sha256": None, "process_path_sha256_matches_expected": None, "process_creation_filetime": None, "process_creation_utc": None, "process_creation_matches_installation": None, "module_path": None, "module_path_matches_process": None, "binding_verified": False},
        "module_base": None, "before": None, "after": None,
        "methods": _unknown_methods(methods, "not_read"),
        "doublepass": {"performed": False, "consistent": None, "mismatches": []},
        "access": {"open_process_mask": "QUERY_INFORMATION|VM_READ", "open_process_mask_hex": _hex(PROCESS_ACCESS), "rpm_total_limit": MAX_TOTAL_RPM, "rpm_single_read_limit": MAX_SINGLE_RPM, "rpm_bytes_requested": 0, "rpm_calls": 0, "native_game_calls": False, "target_memory_writes": False, "dll_injection": False, "private_heap_scan": False, "ui_control": False, "date_advance": False, "save_or_reload": False},
        "cleanup": {"handle_close": {"status": "unknown", "success": None, "closed": False}}, "status": "starting", "errors": [], "completed": False,
    }


def _retract_methods(report: dict[str, Any], reason: str) -> None:
    requested = report.get("request", {}).get("methods", [])
    report["methods"] = _unknown_methods(requested, reason)


def _apply_cleanup(report: dict[str, Any], kernel: Any, handle: Any) -> None:
    outcome = _close_process_handle(kernel, handle)
    report["cleanup"]["handle_close"] = outcome
    if outcome.get("status") != "closed":
        _retract_methods(report, "handle_close_failed")
        report["status"] = "cleanup_error"


def _invalid_request_report(report: dict[str, Any], reason: str, status: str = "invalid_request") -> dict[str, Any]:
    report["status"] = status
    report["errors"].append({"stage": "request", "status": "unknown", "error": reason})
    _retract_methods(report, reason)
    report["cleanup"]["handle_close"] = _close_process_handle(None, None)
    report["completed"] = True
    return report


def _validate_methods_request(methods: Any) -> tuple[list[str], bool, str | None]:
    """Validate method values before using them as mapping keys or set items."""
    if not isinstance(methods, (list, tuple)):
        return [], False, "methods must contain one or two distinct whitelisted names"
    raw = list(methods)
    safe = [item for item in raw if isinstance(item, str)]
    if len(safe) != len(raw):
        return safe, False, "methods must contain only string names"
    if len(safe) == 0 or len(safe) > len(METHODS):
        return safe, False, "methods must contain one or two distinct whitelisted names"
    if any(item not in METHODS for item in safe):
        return safe, False, "unsupported_method"
    if len(set(safe)) != len(safe):
        return safe, False, "methods must contain distinct names"
    return safe, True, None


def capture(installation: Path, country: str, methods: Sequence[str]) -> dict[str, Any]:
    """Capture two bounded observations for selected custom-localisation methods."""
    installation = Path(installation)
    requested, request_valid, request_error = _validate_methods_request(methods)
    report = _base_report(installation, country, requested)
    try:
        report["probe_script_sha256"] = _sha256_file(Path(__file__).resolve())
    except OSError as exc:
        report["errors"].append({"stage": "probe_identity", "status": "unknown", "error": str(exc)})
    if not isinstance(country, str) or re.fullmatch(r"[A-Z0-9]{3}", country) is None:
        return _invalid_request_report(report, "Invalid country tag", "unsupported_country")
    if not request_valid:
        return _invalid_request_report(report, request_error or "invalid_method_request")
    handle = None
    kernel = None
    reader: AddressBoundedRPM | Any | None = None
    try:
        document = _load_installation(installation)
        kernel = _configure_kernel()
        pid = _parse_int(document.get("pid"))
        if pid is None:
            raise ProbeError("installation_pid_invalid")
        handle = kernel.OpenProcess(PROCESS_ACCESS, False, pid)
        if not handle:
            raise C.WinError(C.get_last_error())
        module_base = _capture_identity(report, document, kernel, handle)
        report["static_contract_guard"] = _static_contract_guard()
        if report["static_contract_guard"].get("status") != "observed":
            report["status"] = "static_contract_unknown"
            return report
        process_path = report["identity"].get("process_path")
        if not process_path:
            raise ProbeError("process_path_missing")
        report["file_code_guard"] = _file_code_guard(Path(process_path))
        if report["file_code_guard"].get("status") != "observed":
            report["status"] = "file_code_mismatch"
            return report
        reader = BoundedRPM(kernel, handle, module_base)
        passes: list[dict[str, Any]] = []
        for pass_index in range(2):
            if hasattr(reader, "clear_log"):
                reader.clear_log()
            runtime_guard = _runtime_code_guard(reader, module_base)
            if pass_index == 0:
                report["runtime_code_guard"] = runtime_guard
            if runtime_guard.get("status") != "observed":
                report["status"] = "runtime_code_mismatch"
                report["errors"].append({"stage": f"runtime_code_guard_{pass_index + 1}", "status": "unknown", "error": runtime_guard.get("unknown_conditions")})
                return report
            if hasattr(reader, "clear_log"):
                reader.clear_log()
            snapshot = _snapshot(reader, module_base, country, requested, runtime_guard)
            passes.append(snapshot)
            if pass_index == 0:
                report["before"] = snapshot
            else:
                report["after"] = snapshot
            if snapshot.get("status") != "observed":
                report["status"] = "unknown"
                report["errors"].append({"stage": f"snapshot_{pass_index + 1}", "status": "unknown", "error": snapshot.get("unknown_conditions")})
                return report
        report["doublepass"]["performed"] = True
        mismatches = _diff_paths(passes[0].get("comparison"), passes[1].get("comparison"))
        report["doublepass"]["mismatches"] = mismatches
        report["doublepass"]["consistent"] = not mismatches
        if mismatches:
            report["status"] = "doublepass_mismatch"
            _retract_methods(report, "doublepass_mismatch")
        else:
            report["methods"] = passes[1].get("methods", _unknown_methods(requested, "methods_not_read"))
            report["status"] = "observed"
        report["completed"] = True
        return report
    except Exception as exc:
        report["errors"].append({"stage": "capture", "status": "unknown", "error": str(exc)})
        _retract_methods(report, "capture_failed")
        report["status"] = "error"
        report["completed"] = True
        return report
    finally:
        if reader is not None:
            report["access"]["rpm_bytes_requested"] = int(getattr(reader, "bytes_requested", 0))
            report["access"]["rpm_calls"] = int(getattr(reader, "calls", 0))
        if handle is not None or kernel is not None:
            _apply_cleanup(report, kernel, handle)
        elif report["cleanup"]["handle_close"].get("status") == "unknown":
            report["cleanup"]["handle_close"] = _close_process_handle(None, None)
        report["completed"] = True


__all__ = ["capture", "AddressBoundedRPM", "BoundedRPM", "ProbeError", "ProfileError"]
