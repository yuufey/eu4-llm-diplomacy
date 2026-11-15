"""Bounded, read-only projection of the current country war index.

This leaf validates the target country's cached opponent index against the
war-side vectors and reciprocal index entries.  It does not open a process,
invoke game code, establish global war membership, or observe UI rendering.
The caller owns process/profile/session checks, code guards, role selection,
and before/after consistency.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import re
from typing import Any

from . import country_faith_memory as _faith
from . import country_scale_development_memory as _scale
from . import foreign_country_memory as _shared
from . import foreign_technology_capture as _foreign_capture
from . import observer_registry_memory as _observer_registry
from . import province_state_memory as _province


SCHEMA = "information.country_wars_memory.v1"
FIELD_WARS = "F01.wars"
FIELDS = (FIELD_WARS,)

AT_WAR_OFFSET = 0x289B
WAR_INDEX_POINTER_OFFSET = 0x1548
WAR_INDEX_COUNT_OFFSET = 0x1554
WAR_INDEX_STRIDE = 16
WAR_INDEX_SLOT_OFFSET = 0
WAR_INDEX_WAR_POINTER_OFFSET = 8

WAR_VTABLE_RVA = 0x1D1F6F0
WAR_MARKER_OFFSET = 8
WAR_MARKER = 0x165
WAR_PREFIX_SIZE = 0x90
SIDE_A_VECTOR_OFFSET = 0x48
SIDE_B_VECTOR_OFFSET = 0x78
VECTOR_HEADER_SIZE = 24

MAX_COUNTRY_SLOTS = 4096
MAX_INDEX_ENTRIES = 256
MAX_WARS = 32
MAX_SIDE_MEMBERS = 256
MAX_VECTOR_CAPACITY = 4096
MAX_REGISTRY_ENTRIES = 256

MIN_USER_ADDRESS = _shared.MIN_USER_ADDRESS
MAX_USER_ADDRESS_EXCLUSIVE = _shared.MAX_USER_ADDRESS_EXCLUSIVE
MAX_U64 = 0xFFFFFFFFFFFFFFFF
_TAG = re.compile(r"[A-Z0-9]{3}\Z")
_WAR_ID = re.compile(r"war_([0-9a-f]{16})_([0-9a-f]{8})\Z")
_NATIVE_REFERENCE = re.compile(r"0x[0-9a-f]{1,16}\Z")


class _LeafFailure(Exception):
    """A bounded-read or graph-integrity failure that makes the field unknown."""


class _ReaderAdapter:
    """Normalize a callable or .read() provider for the shared limiter."""

    def __init__(self, source: Any):
        self.source = source

    def read(self, address: int, size: int, label: str) -> bytes:
        method = getattr(self.source, "read", None)
        try:
            if callable(method):
                raw = method(address, size, label)
            elif callable(self.source):
                raw = self.source(address, size, label)
            else:
                raise TypeError("reader_not_callable_or_readable")
        except Exception as exc:
            raise ValueError("country_wars_reader_failed") from exc
        if not isinstance(raw, (bytes, bytearray, memoryview)):
            raise ValueError("country_wars_reader_invalid_type")
        return bytes(raw)


def _is_user_address(value: Any) -> bool:
    return (type(value) is int and MIN_USER_ADDRESS <= value < MAX_USER_ADDRESS_EXCLUSIVE
            and value <= MAX_U64)


def _checked_add(address: int, offset: int, size: int, label: str) -> int:
    if (not _is_user_address(address) or type(offset) is not int or offset < 0
            or type(size) is not int or size <= 0 or address > MAX_U64 - offset):
        raise _LeafFailure(f"ADDRESS_RANGE_INVALID:{label}")
    result = address + offset
    if (not _is_user_address(result) or result > MAX_U64 - (size - 1)
            or result + size > MAX_USER_ADDRESS_EXCLUSIVE):
        raise _LeafFailure(f"ADDRESS_RANGE_INVALID:{label}")
    return result


def _checked_range(address: int, size: int, label: str) -> tuple[int, int]:
    if (not _is_user_address(address) or type(size) is not int or size <= 0
            or address > MAX_U64 - (size - 1)
            or address + size > MAX_USER_ADDRESS_EXCLUSIVE):
        raise _LeafFailure(f"ADDRESS_RANGE_INVALID:{label}")
    return address, address + size


def _overlaps(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def _pointer(value: Any, label: str, *, nullable: bool = False) -> int:
    if type(value) is not int or not 0 <= value <= MAX_U64:
        raise _LeafFailure(f"POINTER_INVALID:{label}")
    if value == 0 and nullable:
        return 0
    if not _is_user_address(value) or value & 7:
        raise _LeafFailure(f"POINTER_INVALID:{label}")
    return value


def _read_exact(limiter: _shared._BoundedReader, address: int,
                size: int, label: str) -> bytes:
    if (type(size) is not int or size <= 0 or size > _shared.MAX_SINGLE_READ_BYTES
            or not _is_user_address(address) or address > MAX_USER_ADDRESS_EXCLUSIVE - size):
        raise _LeafFailure(f"READ_RANGE_INVALID:{label}")
    try:
        raw = limiter.read(address, size, label)
    except Exception as exc:
        message = str(exc).lower()
        if "short" in message:
            code = "READ_SHORT"
        elif "budget" in message:
            code = "READ_BUDGET_EXCEEDED"
        else:
            code = "READ_FAILED"
        raise _LeafFailure(f"{code}:{label}") from exc
    if not isinstance(raw, bytes) or len(raw) != size:
        raise _LeafFailure(f"READ_SHORT:{label}")
    return raw


def _u32(raw: bytes) -> int:
    return int.from_bytes(raw, "little", signed=False)


def _i32(raw: bytes) -> int:
    return int.from_bytes(raw, "little", signed=True)


def _u64(raw: bytes) -> int:
    return int.from_bytes(raw, "little", signed=False)


def _binding_from_resolution(resolution: Mapping[str, Any], label: str) -> dict[str, Any]:
    raw = resolution.get("raw_inputs")
    if resolution.get("status") != "known" or not isinstance(raw, Mapping):
        raise _LeafFailure(f"COUNTRY_REFERENCE_UNKNOWN:{label}")
    try:
        tag = resolution["value"]
        fullref = int(raw["fullref"], 0)
        slot = raw["slot"]
        pointer = int(raw["country_pointer"], 0)
        database = int(raw["database"], 0)
        table = int(raw["table"], 0)
        count = raw["count"]
        table_entry = int(raw["table_entry_address"], 0)
        canonical_address = int(raw["canonical_fullref_address"], 0)
        table_entry_raw = raw["table_entry_raw_hex"]
        canonical_raw = raw["canonical_fullref_raw_hex"]
    except (KeyError, TypeError, ValueError) as exc:
        raise _LeafFailure(f"COUNTRY_REFERENCE_EVIDENCE_INVALID:{label}") from exc
    if (not isinstance(tag, str) or not _TAG.fullmatch(tag)
            or type(slot) is not int or not 0 <= slot < MAX_COUNTRY_SLOTS
            or type(count) is not int or not 1 <= count <= MAX_COUNTRY_SLOTS
            or slot >= count or fullref >> 56 == 0 or (fullref >> 48) & 0xFF == 7
            or ((fullref >> 32) & 0xFFFF) != slot
            or (fullref & 0xFFFFFF).to_bytes(3, "little").decode("ascii", "ignore") != tag
            or not _is_user_address(pointer) or pointer & 7
            or not _is_user_address(database) or database & 7
            or not _is_user_address(table) or table & 7
            or table_entry != table + slot * 8
            or canonical_address != pointer + _province.COUNTRY_FULLREF_OFFSET
            or canonical_raw != fullref.to_bytes(8, "little").hex()
            or table_entry_raw != pointer.to_bytes(8, "little").hex()):
        raise _LeafFailure(f"COUNTRY_REFERENCE_BINDING_INVALID:{label}")
    return {
        "tag": tag, "slot": slot, "country_pointer": hex(pointer),
        "fullref": hex(fullref), "fullref_raw_hex": fullref.to_bytes(8, "little").hex(),
        "country_fullref_address": hex(canonical_address),
        "table_entry_address": hex(table_entry), "table_entry_raw_hex": table_entry_raw,
        "database": hex(database), "table": hex(table), "count": count,
        "resolution": deepcopy(dict(resolution)),
    }


def _validate_binding(limiter: _shared._BoundedReader, base: int,
                      pointer: int, binding: Mapping[str, Any], label: str) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        evidence = _scale._validate_target_binding(limiter, base, pointer, binding)
    except Exception as exc:
        raise _LeafFailure(f"BINDING_DATABASE_MISMATCH:{label}") from exc
    resolution = evidence.get("fullref_resolution")
    if not isinstance(resolution, Mapping):
        raise _LeafFailure(f"BINDING_RESOLUTION_MISSING:{label}")
    normalized = _binding_from_resolution(resolution, label)
    if (normalized["tag"] != binding.get("tag")
            or normalized["slot"] != binding.get("slot")
            or normalized["country_pointer"] != hex(pointer)
            or normalized["fullref"] != str(binding.get("fullref")).lower()):
        raise _LeafFailure(f"BINDING_IDENTITY_MISMATCH:{label}")
    return normalized, evidence


def _select_complete_scan(scan: Any, observer: Mapping[str, Any],
                          member: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Select FRA and one revalidated member from a real complete scan."""
    if not isinstance(scan, Mapping) or scan.get("status") != "observed":
        raise _LeafFailure("ADMISSION_COUNTRY_SCAN_UNAVAILABLE")
    if scan.get("basis") != "country_manager_table_tag_slot_binding":
        raise _LeafFailure("ADMISSION_COUNTRY_SCAN_BASIS_INVALID")
    rows = scan.get("rows")
    count = scan.get("count")
    if type(count) is not int or not 1 <= count <= MAX_COUNTRY_SLOTS \
            or not isinstance(rows, list) or len(rows) != count:
        raise _LeafFailure("ADMISSION_COUNTRY_SCAN_SHAPE_INVALID")
    try:
        database = int(scan.get("database"), 0)
        table = int(scan.get("table"), 0)
    except (TypeError, ValueError) as exc:
        raise _LeafFailure("ADMISSION_COUNTRY_SCAN_POINTER_INVALID") from exc
    if not _is_user_address(database) or database & 7 or not _is_user_address(table) or table & 7:
        raise _LeafFailure("ADMISSION_COUNTRY_SCAN_POINTER_INVALID")

    selected_rows: dict[str, dict[str, Any]] = {}
    selected_bindings: dict[str, dict[str, Any]] = {}
    for binding in (observer, member):
        tag = binding["tag"]
        slot = binding["slot"]
        pointer = int(binding["country_pointer"], 0)
        fullref = int(binding["fullref"], 0)
        if (binding["database"] != hex(database) or binding["table"] != hex(table)
                or binding["count"] != count or not 0 <= slot < count):
            raise _LeafFailure(f"ADMISSION_BINDING_SCAN_MISMATCH:{tag}")
        matching_tags = [row for row in rows
                         if isinstance(row, Mapping) and row.get("tag") == tag]
        if len(matching_tags) != 1:
            raise _LeafFailure(f"ADMISSION_SCAN_TAG_NOT_UNIQUE:{tag}")
        row = rows[slot]
        if not isinstance(row, Mapping):
            raise _LeafFailure(f"ADMISSION_SCAN_ROW_INVALID:{tag}")
        expected = {
            "slot": slot, "fullref_slot": slot, "tag": tag,
            "country_pointer": hex(pointer), "fullref": hex(fullref),
            "fullref_raw_hex": binding["fullref_raw_hex"],
            "table_entry_address": binding["table_entry_address"],
            "table_entry_raw_hex": binding["table_entry_raw_hex"],
            "fullref_address": binding["country_fullref_address"],
        }
        for key, value in expected.items():
            actual = row.get(key)
            if key in ("country_pointer", "fullref", "table_entry_address", "fullref_address"):
                actual = actual.lower() if isinstance(actual, str) else actual
                value = value.lower() if isinstance(value, str) else value
            elif key in ("fullref_raw_hex", "table_entry_raw_hex"):
                actual = actual.lower() if isinstance(actual, str) else actual
                value = value.lower() if isinstance(value, str) else value
            if type(actual) is not type(value) or actual != value:
                raise _LeafFailure(f"ADMISSION_SCAN_ROW_MISMATCH:{tag}:{key}")
        selected_rows[tag] = deepcopy(dict(row))
        selected_bindings[tag] = {
            "tag": tag, "slot": slot, "country_pointer": hex(pointer),
            "fullref": hex(fullref), "fullref_raw_hex": binding["fullref_raw_hex"],
            "country_fullref_address": binding["country_fullref_address"],
            "table_entry_address": binding["table_entry_address"],
            "table_entry_raw_hex": binding["table_entry_raw_hex"],
        }
    selected = dict(scan)  # preserve the caller's actual full rows without copying them
    selected["requested"] = dict(selected_bindings)
    selected["selector_basis"] = "revalidated_member_from_complete_observed_scan"
    return selected, {"selector_basis": selected["selector_basis"],
                      "selected_rows": selected_rows}


def _read_country_cache(limiter: _shared._BoundedReader, country_pointer: int,
                        label: str) -> dict[str, Any]:
    at_war_address = _checked_add(country_pointer, AT_WAR_OFFSET, 1, f"{label}.at_war")
    ptr_address = _checked_add(country_pointer, WAR_INDEX_POINTER_OFFSET, 8,
                               f"{label}.war_index_pointer")
    count_address = _checked_add(country_pointer, WAR_INDEX_COUNT_OFFSET, 4,
                                 f"{label}.war_index_count")
    at_war_raw = _read_exact(limiter, at_war_address, 1, f"country_wars.{label}.at_war")
    pointer_raw = _read_exact(limiter, ptr_address, 8, f"country_wars.{label}.index_pointer")
    count_raw = _read_exact(limiter, count_address, 4, f"country_wars.{label}.index_count")
    pointer = _pointer(_u64(pointer_raw), f"{label}.war_index", nullable=True)
    count = _i32(count_raw)
    if not 0 <= count <= MAX_INDEX_ENTRIES:
        raise _LeafFailure(f"WAR_INDEX_COUNT_INVALID:{label}")
    if count and not pointer:
        raise _LeafFailure(f"WAR_INDEX_POINTER_NULL:{label}")
    if pointer:
        _checked_range(pointer, max(1, count * WAR_INDEX_STRIDE), f"{label}.war_index_range")
    return {
        "at_war_address": hex(at_war_address), "at_war_raw_hex": at_war_raw.hex(),
        "at_war": at_war_raw[0] != 0,
        "index_pointer_address": hex(ptr_address), "index_pointer_raw_hex": pointer_raw.hex(),
        "index_pointer": hex(pointer) if pointer else None,
        "index_count_address": hex(count_address), "index_count_raw_hex": count_raw.hex(),
        "index_count": count,
    }


def _parse_war_index(limiter: _shared._BoundedReader, cache: Mapping[str, Any],
                     label: str) -> tuple[list[dict[str, Any]], bytes]:
    count = cache["index_count"]
    pointer = int(cache["index_pointer"], 0) if cache["index_pointer"] else 0
    if count == 0:
        return [], b""
    raw = _read_exact(limiter, pointer, count * WAR_INDEX_STRIDE,
                      f"country_wars.{label}.index_rows")
    rows = []
    for index in range(count):
        item = raw[index * WAR_INDEX_STRIDE:(index + 1) * WAR_INDEX_STRIDE]
        slot_raw = item[WAR_INDEX_SLOT_OFFSET:WAR_INDEX_SLOT_OFFSET + 4]
        pointer_raw = item[WAR_INDEX_WAR_POINTER_OFFSET:WAR_INDEX_WAR_POINTER_OFFSET + 8]
        slot = _u32(slot_raw)
        war_pointer = _pointer(_u64(pointer_raw), f"{label}.index[{index}].war_pointer")
        if slot >= MAX_COUNTRY_SLOTS:
            raise _LeafFailure(f"WAR_INDEX_SLOT_INVALID:{label}:{index}")
        rows.append({"ordinal": index, "slot": slot, "slot_raw_hex": slot_raw.hex(),
                     "war_pointer": war_pointer, "war_pointer_raw_hex": pointer_raw.hex(),
                     "raw_hex": item.hex()})
    return rows, raw


def _read_side_vector(limiter: _shared._BoundedReader, war_pointer: int,
                      prefix: bytes, vector_offset: int, label: str,
                      *, body_range: tuple[int, int], occupied_ranges: list[tuple[int, int]],
                      index_range: tuple[int, int]) -> dict[str, Any]:
    header = prefix[vector_offset:vector_offset + VECTOR_HEADER_SIZE]
    if len(header) != VECTOR_HEADER_SIZE:
        raise _LeafFailure(f"WAR_VECTOR_HEADER_TRUNCATED:{label}")
    begin_raw, end_raw, cap_raw = header[:8], header[8:16], header[16:24]
    begin_value, end_value, cap_value = _u64(begin_raw), _u64(end_raw), _u64(cap_raw)
    begin = _pointer(begin_value, f"{label}.begin")
    end = _pointer(end_value, f"{label}.end")
    capacity_end = _pointer(cap_value, f"{label}.capacity_end")
    if not begin <= end <= capacity_end:
        raise _LeafFailure(f"WAR_VECTOR_POINTER_ORDER_INVALID:{label}")
    used_bytes = end - begin
    capacity_bytes = capacity_end - begin
    if used_bytes == 0 or used_bytes % 8 or capacity_bytes % 8:
        raise _LeafFailure(f"WAR_VECTOR_LENGTH_INVALID:{label}")
    used = used_bytes // 8
    capacity = capacity_bytes // 8
    if not 1 <= used <= MAX_SIDE_MEMBERS or not used <= capacity <= MAX_VECTOR_CAPACITY:
        raise _LeafFailure(f"WAR_VECTOR_COUNT_INVALID:{label}")
    used_range = _checked_range(begin, used_bytes, f"{label}.used_range")
    capacity_range = _checked_range(begin, capacity_bytes, f"{label}.capacity_range")
    if (_overlaps(capacity_range, body_range) or _overlaps(capacity_range, index_range)
            or _overlaps(used_range, index_range)):
        raise _LeafFailure(f"WAR_VECTOR_ALIAS:{label}")
    if any(_overlaps(capacity_range, prior) for prior in occupied_ranges):
        raise _LeafFailure(f"WAR_VECTOR_ALIAS:{label}")
    raw = _read_exact(limiter, begin, used_bytes, f"country_wars.{label}.fullrefs")
    return {
        "begin": begin, "end": end, "capacity_end": capacity_end,
        "begin_raw_hex": begin_raw.hex(), "end_raw_hex": end_raw.hex(),
        "capacity_end_raw_hex": cap_raw.hex(), "used": used,
        "capacity": capacity, "used_bytes": used_bytes,
        "raw_hex": raw.hex(), "raw": raw,
        "used_range": used_range, "capacity_range": capacity_range,
    }


def _war_header(limiter: _shared._BoundedReader, base: int, war_pointer: int,
                index_range: tuple[int, int], prior_body_ranges: list[tuple[int, int]],
                prior_vector_ranges: list[tuple[int, int]], label: str) -> dict[str, Any]:
    pointer = _pointer(war_pointer, f"{label}.war_pointer")
    body_range = _checked_range(pointer, WAR_PREFIX_SIZE, f"{label}.prefix")
    if _overlaps(body_range, index_range) or any(_overlaps(body_range, item)
                                                  for item in prior_body_ranges + prior_vector_ranges):
        raise _LeafFailure(f"WAR_OBJECT_ALIAS:{label}")
    prefix = _read_exact(limiter, pointer, WAR_PREFIX_SIZE, f"country_wars.{label}.prefix")
    vtable_raw = prefix[:8]
    marker_raw = prefix[WAR_MARKER_OFFSET:WAR_MARKER_OFFSET + 4]
    expected_vtable = _checked_add(base, WAR_VTABLE_RVA, 8, "war_vtable")
    if _u64(vtable_raw) != expected_vtable:
        raise _LeafFailure(f"WAR_VTABLE_MISMATCH:{label}")
    if _u32(marker_raw) != WAR_MARKER:
        raise _LeafFailure(f"WAR_MARKER_MISMATCH:{label}")
    return {"pointer": pointer, "prefix": prefix, "body_range": body_range,
            "vtable_raw_hex": vtable_raw.hex(), "vtable": hex(_u64(vtable_raw)),
            "marker_raw_hex": marker_raw.hex(), "marker": _u32(marker_raw)}


def _resolve_ref(limiter: _shared._BoundedReader, base: int, ref: bytes,
                 label: str, cache: dict[int, dict[str, Any]]) -> dict[str, Any]:
    if len(ref) != 8:
        raise _LeafFailure(f"COUNTRY_FULLREF_WIDTH_INVALID:{label}")
    fullref = _u64(ref)
    prior = cache.get(fullref)
    if prior is not None:
        return prior
    try:
        resolution = _scale._resolve_bound_reference(limiter, base, ref, label)
    except Exception as exc:
        raise _LeafFailure(f"COUNTRY_REFERENCE_FAILED:{label}") from exc
    binding = _binding_from_resolution(resolution, label)
    value = {"resolution": deepcopy(resolution), "binding": binding,
             "fullref_raw_hex": ref.hex(), "fullref": fullref}
    cache[fullref] = value
    return value


def _reverse_index(limiter: _shared._BoundedReader, country: Mapping[str, Any],
                   target_slot: int, war_pointer: int, cache: dict[int, dict[str, Any]],
                   label: str) -> dict[str, Any]:
    binding = country["binding"]
    fullref = country["fullref"]
    pointer = int(binding["country_pointer"], 0)
    prior = cache.get(fullref)
    if prior is None:
        cache_raw = _read_country_cache(limiter, pointer, label)
        rows, raw = _parse_war_index(limiter, cache_raw, label)
        if not cache_raw["at_war"] or cache_raw["index_count"] == 0:
            raise _LeafFailure(f"REVERSE_WAR_CACHE_EMPTY:{label}")
        target_rows = [row for row in rows if row["slot"] == target_slot]
        if len(target_rows) != 1:
            raise _LeafFailure(f"REVERSE_TARGET_ROW_NOT_UNIQUE:{label}")
        prior = {"cache": cache_raw, "rows": rows, "rows_raw_hex": raw.hex(),
                 "target_rows": target_rows}
        cache[fullref] = prior
    else:
        target_rows = [row for row in prior["rows"] if row["slot"] == target_slot]
        if len(target_rows) != 1:
            raise _LeafFailure(f"REVERSE_TARGET_ROW_NOT_UNIQUE:{label}")
    row = target_rows[0]
    if row["war_pointer"] != war_pointer:
        raise _LeafFailure(f"REVERSE_WAR_POINTER_MISMATCH:{label}")
    return {"country_fullref": hex(fullref), "target_slot": target_slot,
            "war_pointer": hex(war_pointer), "cache": deepcopy(prior["cache"]),
            "rows_raw_hex": prior["rows_raw_hex"],
            "matching_row": deepcopy(row)}


def _registry_snapshot(registry_reader: Any, limiter: _shared._BoundedReader,
                       base: int) -> tuple[dict[str, Any], dict[int, tuple[str, int]]]:
    if registry_reader is None:
        return {"status": "unknown", "reason": "REGISTRY_READER_UNAVAILABLE"}, {}
    try:
        result = registry_reader(limiter, base)
    except Exception as exc:
        return {"status": "unknown", "reason": "REGISTRY_READ_FAILED",
                "error_type": type(exc).__name__}, {}
    if not isinstance(result, Mapping):
        return {"status": "unknown", "reason": "REGISTRY_RESULT_INVALID"}, {}
    if result.get("status") != "known":
        raw_copy = deepcopy(dict(result))
        return {"status": "unknown", "reason": "REGISTRY_NOT_KNOWN",
                "raw_result": raw_copy}, {}
    entries = result.get("entries")
    count = result.get("count")
    allocated_count = result.get("allocated_count", count)
    serial_scope = result.get("serial_scope", "slot")
    raw_inputs = result.get("raw_inputs")
    required_flags = (result.get("creation_matches") is True
                      and result.get("lifetime_binding_verified") is False)
    if (not isinstance(entries, list) or type(count) is not int
            or not 0 <= count <= MAX_REGISTRY_ENTRIES or len(entries) != count
            or type(allocated_count) is not int or not count <= allocated_count <= MAX_REGISTRY_ENTRIES
            or serial_scope not in ("slot", "observer_lifetime")
            or not isinstance(raw_inputs, Mapping) or not required_flags):
        raw_copy = {key: deepcopy(value) for key, value in result.items()
                    if key in {"status", "count", "creation_matches",
                               "lifetime_binding_verified", "raw_inputs"}}
        return {"status": "unknown", "reason": "REGISTRY_ENTRIES_INVALID",
                "raw_result": raw_copy}, {}
    creation_raw_hex = raw_inputs.get("creation_raw_hex")
    if (not isinstance(creation_raw_hex, str) or len(creation_raw_hex) != 16
            or not re.fullmatch(r"[0-9a-fA-F]{16}", creation_raw_hex)):
        return {"status": "unknown", "reason": "REGISTRY_CREATION_EVIDENCE_INVALID",
                "raw_result": deepcopy({"status": result.get("status"),
                                         "count": count,
                                         "creation_matches": result.get("creation_matches"),
                                         "lifetime_binding_verified": result.get("lifetime_binding_verified"),
                                         "raw_inputs": dict(raw_inputs)})}, {}
    creation = int.from_bytes(bytes.fromhex(creation_raw_hex), "little")
    if creation == 0:
        return {"status": "unknown", "reason": "REGISTRY_CREATION_EVIDENCE_INVALID",
                "raw_result": deepcopy(dict(result))}, {}
    expected_epoch = _observer_registry.epoch(creation)
    expected_epoch_hex = f"{expected_epoch:016x}"
    by_reference: dict[int, tuple[str, int]] = {}
    seen_serials: set[int] = set()
    invalid = False
    previous_serial = 0
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping) or set(entry) != {"native_reference", "war_id", "serial"}:
            invalid = True
            break
        reference = entry.get("native_reference")
        war_id = entry.get("war_id")
        serial = entry.get("serial")
        if (not isinstance(reference, str) or not _NATIVE_REFERENCE.fullmatch(reference)
                or not isinstance(war_id, str) or not _WAR_ID.fullmatch(war_id)
                or type(serial) is not int or not 1 <= serial <= (
                    0xffffffff if serial_scope == "observer_lifetime" else MAX_REGISTRY_ENTRIES)):
            invalid = True
            break
        ref_value = int(reference, 16)
        if hex(ref_value) != reference:
            invalid = True
            break
        try:
            _pointer(ref_value, "registry.native_reference")
        except _LeafFailure:
            invalid = True
            break
        match = _WAR_ID.fullmatch(war_id)
        if (match is None or match.group(1) != expected_epoch_hex
                or int(match.group(2), 16) != serial or serial <= previous_serial
                or (serial_scope == "slot" and serial > allocated_count)
                or serial in seen_serials or ref_value in by_reference):
            invalid = True
            break
        seen_serials.add(serial)
        previous_serial = serial
        normalized = (war_id, serial)
        by_reference[ref_value] = normalized
    if invalid:
        return {"status": "unknown", "reason": "REGISTRY_ENTRY_BINDING_INVALID",
                "raw_result": deepcopy(dict(result))}, {}
    return {"status": "known", "raw_result": deepcopy(dict(result)),
            "count": count, "creation_matches": True,
            "lifetime_binding_verified": False,
            "epoch_hex": expected_epoch_hex}, by_reference


def _member_gate(reader: _shared._BoundedReader, base: int, observer: dict[str, Any],
                 member: dict[str, Any], gate_reader: Any, admission_bindings: Any,
                 cache: dict[int, dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    fullref = member["fullref"]
    if fullref in cache:
        return deepcopy(cache[fullref]["descriptor"]), deepcopy(cache[fullref]["raw"])
    member_binding = member["binding"]
    target_tag = member_binding["tag"]
    selector_evidence: dict[str, Any] = {"selector_basis": "unavailable"}
    if admission_bindings is not None:
        try:
            pair_bindings, selector_evidence = _select_complete_scan(
                admission_bindings, observer, member_binding)
        except Exception as exc:
            raw_gate = {"status": "unknown", "reason": "ADMISSION_SCAN_REVALIDATION_FAILED",
                        "error_type": type(exc).__name__}
            descriptor = {"status": "unknown", "reason": "MEMBER_ADMISSION_UNKNOWN"}
            cache[fullref] = {"descriptor": deepcopy(descriptor), "raw": raw_gate,
                              "selector": selector_evidence}
            return descriptor, raw_gate
    else:
        pair_bindings = None
    gate_func = gate_reader or _foreign_capture._bound_admission
    if gate_reader is None and pair_bindings is None:
        raw_gate = {"status": "unknown", "reason": "ADMISSION_SCAN_UNAVAILABLE"}
        descriptor = {"status": "unknown", "reason": "MEMBER_ADMISSION_UNKNOWN"}
        cache[fullref] = {"descriptor": deepcopy(descriptor), "raw": raw_gate,
                          "selector": selector_evidence}
        return descriptor, raw_gate
    try:
        gate = gate_func(reader, base, pair_bindings, "FRA", target_tag)
    except Exception as exc:
        raw_gate = {"status": "unknown", "reason": "MEMBER_ADMISSION_FAILED",
                    "error_type": type(exc).__name__}
    else:
        raw_gate = deepcopy(dict(gate)) if isinstance(gate, Mapping) else {
            "status": "unknown", "reason": "MEMBER_ADMISSION_RESULT_INVALID"}
    role = raw_gate.get("observer_nonplayer_role")
    role_verified = isinstance(role, Mapping) and role.get("verified") is True
    if (role_verified and raw_gate.get("status") == "known"
            and raw_gate.get("admitted") is True):
        descriptor = {"status": "known", "country": target_tag}
    elif (role_verified and raw_gate.get("status") == "known"
          and raw_gate.get("admitted") is False):
        descriptor = {"status": "invisible", "reason": "NOT_ADMITTED"}
    else:
        descriptor = {"status": "unknown", "reason": "MEMBER_ADMISSION_UNKNOWN"}
    cache[fullref] = {"descriptor": deepcopy(descriptor), "raw": raw_gate,
                      "selector": selector_evidence}
    return descriptor, raw_gate


def _unknown(reason: str, raw_inputs: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "reason": reason}
    if raw_inputs:
        result["raw_inputs"] = deepcopy(dict(raw_inputs))
    return result


def _read_wars(limiter: _shared._BoundedReader, base: int,
               target_pointer: int, target_binding: Mapping[str, Any],
               observer_binding: Mapping[str, Any], observer_resolution: Mapping[str, Any],
               target_resolution: Mapping[str, Any], registry_reader: Any,
               member_admission_reader: Any, admission_bindings: Any) -> dict[str, Any]:
    raw_inputs: dict[str, Any] = {
        "target_binding": deepcopy(dict(target_binding)),
        "observer_binding": deepcopy(dict(observer_binding)),
        "observer_reference_resolution": deepcopy(dict(observer_resolution)),
        "target_reference_resolution": deepcopy(dict(target_resolution)),
        "country_index": {}, "index_rows_raw_hex": None,
        "war_objects": [], "country_references": {}, "reverse_indexes": [],
        "admission_results": [], "registry": None,
        "source_scope": "current_country_opponent_index",
    }
    try:
        target_slot = target_binding["slot"]
        target_fullref = int(target_binding["fullref"], 0)
        observer_binding_normal = _binding_from_resolution(observer_resolution, "observer")
        target_binding_normal = _binding_from_resolution(target_resolution, "target")
        if (target_binding_normal["slot"] != target_slot
                or target_binding_normal["country_pointer"] != hex(target_pointer)):
            raise _LeafFailure("TARGET_BINDING_RESOLUTION_MISMATCH")

        country_cache = _read_country_cache(limiter, target_pointer, "target")
        raw_inputs["country_index"] = deepcopy(country_cache)
        if not country_cache["at_war"] and country_cache["index_count"] > 0:
            raise _LeafFailure("AT_WAR_CACHE_CONTRADICTION")
        if country_cache["at_war"] and country_cache["index_count"] == 0:
            raise _LeafFailure("AT_WAR_CACHE_CONTRADICTION")

        index_rows, index_raw = _parse_war_index(limiter, country_cache, "target")
        raw_inputs["index_rows_raw_hex"] = index_raw.hex()
        index_range = (_checked_range(int(country_cache["index_pointer"], 0), len(index_raw),
                                      "target_index") if index_raw else (0, 0))
        target_country_range = _checked_range(target_pointer,
                                              _province.COUNTRY_FULLREF_OFFSET + 8,
                                              "target_country_record")
        observer_pointer = int(observer_binding_normal["country_pointer"], 0)
        observer_country_range = _checked_range(observer_pointer,
                                                 _province.COUNTRY_FULLREF_OFFSET + 8,
                                                 "observer_country_record")
        if index_raw and (_overlaps(index_range, target_country_range)
                          or _overlaps(index_range, observer_country_range)):
            raise _LeafFailure("WAR_INDEX_COUNTRY_ALIAS")
        index_by_slot: dict[int, int] = {}
        war_slots: dict[int, list[int]] = {}
        for row in index_rows:
            slot = row["slot"]
            war_pointer = row["war_pointer"]
            if slot == target_slot:
                raise _LeafFailure("WAR_INDEX_CONTAINS_TARGET")
            prior = index_by_slot.get(slot)
            if prior is not None:
                if prior != war_pointer:
                    raise _LeafFailure("WAR_INDEX_COUNTERPART_CONFLICT")
                raise _LeafFailure("WAR_INDEX_COUNTERPART_DUPLICATE")
            index_by_slot[slot] = war_pointer
            war_slots.setdefault(war_pointer, []).append(slot)
        if len(war_slots) > MAX_WARS:
            raise _LeafFailure("WAR_UNIQUE_COUNT_EXCEEDED")

        registry_status, registry_by_pointer = _registry_snapshot(registry_reader, limiter, base)
        raw_inputs["registry"] = deepcopy(registry_status)
        if not index_rows:
            return {
                "status": "known", "value": {
                    "at_war": False, "war_count": 0, "wars": [],
                    "enumeration_scope": "current_country_opponent_index",
                    "global_membership_verified": False, "lifetime_verified": False,
                }, "unit": "native_country_wars", "scale": 1,
                "partial": True, "complete": False,
                "basis": "current_country_war_index_and_side_vector_projection",
                "raw_inputs": raw_inputs,
            }

        resolutions: dict[int, dict[str, Any]] = {
            target_fullref: {"resolution": deepcopy(dict(target_resolution)),
                             "binding": target_binding_normal,
                             "fullref_raw_hex": target_fullref.to_bytes(8, "little").hex(),
                             "fullref": target_fullref},
            int(observer_binding_normal["fullref"], 0): {
                "resolution": deepcopy(dict(observer_resolution)),
                "binding": observer_binding_normal,
                "fullref_raw_hex": int(observer_binding_normal["fullref"], 0).to_bytes(8, "little").hex(),
                "fullref": int(observer_binding_normal["fullref"], 0)},
        }
        war_raw_by_pointer: dict[int, dict[str, Any]] = {}
        body_ranges: list[tuple[int, int]] = []
        vector_ranges: list[tuple[int, int]] = []
        all_member_slots: set[int] = set()
        member_country_ranges: dict[int, tuple[int, int]] = {}
        target_occurrences: dict[int, list[str]] = {}
        for ordinal, war_pointer in enumerate(war_slots):
            war = _war_header(limiter, base, war_pointer, index_range,
                              body_ranges, vector_ranges, f"war[{ordinal}]")
            body_range = war["body_range"]
            if (_overlaps(body_range, target_country_range)
                    or _overlaps(body_range, observer_country_range)):
                raise _LeafFailure("WAR_OBJECT_COUNTRY_ALIAS")
            side_a = _read_side_vector(limiter, war_pointer, war["prefix"],
                                       SIDE_A_VECTOR_OFFSET, f"war[{ordinal}].side_a",
                                       body_range=body_range,
                                       occupied_ranges=vector_ranges + [target_country_range,
                                                                        observer_country_range],
                                       index_range=index_range)
            vector_ranges.append(side_a["capacity_range"])
            side_b = _read_side_vector(limiter, war_pointer, war["prefix"],
                                       SIDE_B_VECTOR_OFFSET, f"war[{ordinal}].side_b",
                                       body_range=body_range,
                                       occupied_ranges=vector_ranges + [target_country_range,
                                                                        observer_country_range],
                                       index_range=index_range)
            vector_ranges.append(side_b["capacity_range"])
            body_ranges.append(body_range)
            war["side_a_vector"] = {k: v for k, v in side_a.items() if k != "raw"}
            war["side_b_vector"] = {k: v for k, v in side_b.items() if k != "raw"}
            for vector_meta in (war["side_a_vector"], war["side_b_vector"]):
                for range_key in ("used_range", "capacity_range"):
                    vector_meta[range_key] = list(vector_meta[range_key])
            war["side_a_raw_hex"] = side_a["raw_hex"]
            war["side_b_raw_hex"] = side_b["raw_hex"]
            side_members: dict[str, list[dict[str, Any]]] = {"side_a": [], "side_b": []}
            seen_in_war: set[int] = set()
            for side_name, vector in (("side_a", side_a), ("side_b", side_b)):
                for member_index in range(vector["used"]):
                    ref = vector["raw"][member_index * 8:(member_index + 1) * 8]
                    fullref = _u64(ref)
                    resolution = _resolve_ref(limiter, base, ref,
                                              f"war[{ordinal}].{side_name}[{member_index}]",
                                              resolutions)
                    member_binding = resolution["binding"]
                    slot = member_binding["slot"]
                    member_pointer = int(member_binding["country_pointer"], 0)
                    member_range = _checked_range(
                        member_pointer, _province.COUNTRY_FULLREF_OFFSET + 8,
                        f"war[{ordinal}].{side_name}[{member_index}].country_record")
                    if (_overlaps(member_range, body_range)
                            or _overlaps(member_range, index_range)
                            or any(_overlaps(member_range, vector_range)
                                   for vector_range in vector_ranges)):
                        raise _LeafFailure(f"WAR_MEMBER_STORAGE_ALIAS:{ordinal}:{member_index}")
                    for prior_pointer, prior_range in member_country_ranges.items():
                        if _overlaps(member_range, prior_range) and prior_pointer != member_pointer:
                            raise _LeafFailure("WAR_MEMBER_COUNTRY_POINTER_ALIAS")
                    member_country_ranges[member_pointer] = member_range
                    if slot in seen_in_war:
                        raise _LeafFailure(f"WAR_SIDE_SLOT_DUPLICATE:{ordinal}")
                    seen_in_war.add(slot)
                    all_member_slots.add(slot)
                    if fullref == target_fullref:
                        target_occurrences.setdefault(war_pointer, []).append(side_name)
                    side_members[side_name].append({
                        "fullref": fullref, "fullref_raw_hex": ref.hex(),
                        "slot": slot, "binding": member_binding,
                        "resolution": resolution["resolution"],
                        "country_pointer": member_pointer,
                        "index": member_index,
                    })
            if not target_occurrences.get(war_pointer) or len(target_occurrences[war_pointer]) != 1:
                raise _LeafFailure(f"WAR_TARGET_NOT_EXACTLY_ONCE:{ordinal}")
            if side_members["side_a"] and side_members["side_b"]:
                side_a_slots = {member["slot"] for member in side_members["side_a"]}
                side_b_slots = {member["slot"] for member in side_members["side_b"]}
                if side_a_slots & side_b_slots:
                    raise _LeafFailure(f"WAR_SLOT_ON_BOTH_SIDES:{ordinal}")
            target_side = target_occurrences[war_pointer][0]
            opponent_side = "side_b" if target_side == "side_a" else "side_a"
            opposite_slots = {member["slot"] for member in side_members[opponent_side]}
            if not opposite_slots:
                raise _LeafFailure(f"WAR_OPPOSITE_SIDE_EMPTY:{ordinal}")
            expected_for_war = set(war_slots[war_pointer])
            if opposite_slots != expected_for_war:
                raise _LeafFailure(f"WAR_INDEX_SIDE_SET_MISMATCH:{ordinal}")
            war["members"] = side_members
            war["target_side"] = target_side
            war["opponent_side"] = opponent_side
            war["opponent_slots"] = sorted(opposite_slots)
            war["pointer_key"] = war_pointer
            war_raw_by_pointer[war_pointer] = war
            raw_inputs["war_objects"].append({
                "ordinal": ordinal, "native_pointer": hex(war_pointer),
                "vtable_raw_hex": war["vtable_raw_hex"],
                "marker_raw_hex": war["marker_raw_hex"],
                "prefix_raw_hex": war["prefix"].hex(),
                "body_range": [hex(body_range[0]), hex(body_range[1])],
                "side_a_vector": deepcopy(war["side_a_vector"]),
                "side_b_vector": deepcopy(war["side_b_vector"]),
                "side_a_raw_hex": war["side_a_raw_hex"],
                "side_b_raw_hex": war["side_b_raw_hex"],
                "target_side": target_side,
                "opponent_slots": sorted(opposite_slots),
            })

        if set(index_by_slot) != {slot for war in war_raw_by_pointer.values()
                                  for slot in war["opponent_slots"]}:
            raise _LeafFailure("WAR_INDEX_OPPONENT_UNION_MISMATCH")
        for slot, war_pointer in index_by_slot.items():
            if war_pointer not in war_raw_by_pointer or slot not in war_raw_by_pointer[war_pointer]["opponent_slots"]:
                raise _LeafFailure("WAR_INDEX_ROW_NOT_IN_OPPOSITE_SIDE")

        target_slot = target_binding_normal["slot"]
        reverse_cache: dict[int, dict[str, Any]] = {}
        unique_opponents: dict[int, dict[str, Any]] = {}
        for war_pointer, war in war_raw_by_pointer.items():
            for member in war["members"][war["opponent_side"]]:
                unique_opponents[member["fullref"]] = member
                evidence = _reverse_index(limiter, member, target_slot, war_pointer,
                                          reverse_cache,
                                          f"reverse_{member['binding']['tag']}_{war_pointer:x}")
                raw_inputs["reverse_indexes"].append(evidence)

        member_descriptors: dict[int, dict[str, Any]] = {}
        admission_cache: dict[int, dict[str, Any]] = {}
        admission_errors: list[dict[str, Any]] = []
        all_members: dict[int, dict[str, Any]] = {}
        for war in war_raw_by_pointer.values():
            for side_name in ("side_a", "side_b"):
                for member in war["members"][side_name]:
                    all_members[member["fullref"]] = member
        for fullref, member in all_members.items():
            member_descriptor, gate_raw = _member_gate(
                limiter, base, observer_binding_normal, member,
                member_admission_reader, admission_bindings, admission_cache)
            member_descriptors[fullref] = member_descriptor
            admission_errors.append({"fullref": hex(fullref), "tag": member["binding"]["tag"],
                                     "gate": gate_raw,
                                     "selector": admission_cache.get(fullref, {}).get("selector"),
                                     "descriptor": deepcopy(member_descriptor)})
        raw_inputs["admission_results"] = admission_errors
        raw_inputs["country_references"] = {
            hex(fullref): deepcopy(value["resolution"])
            for fullref, value in resolutions.items()
        }

        public_wars = []
        for war_pointer, war in war_raw_by_pointer.items():
            id_entry = registry_by_pointer.get(war_pointer)
            if id_entry is None:
                if registry_status.get("status") != "known":
                    id_reason = "WAR_ID_REGISTRY_UNKNOWN"
                elif war_pointer in registry_by_pointer:
                    id_reason = "WAR_ID_REGISTRY_CONFLICT"
                else:
                    id_reason = "WAR_ID_REGISTRY_NO_MATCH"
                war_id = {"status": "unknown", "reason": id_reason}
            else:
                war_id = {"status": "known", "value": id_entry[0],
                          "identity_scope": "observer_session", "lifetime_verified": False}
            side_public: dict[str, list[dict[str, Any]]] = {}
            for side_name in ("side_a", "side_b"):
                side_public[side_name] = []
                for member in war["members"][side_name]:
                    descriptor = deepcopy(member_descriptors[member["fullref"]])
                    side_public[side_name].append(descriptor)
            public_wars.append({
                "war_id": war_id,
                "target_side": war["target_side"],
                "side_a": side_public["side_a"],
                "side_b": side_public["side_b"],
                "membership_complete": True,
                "identities_complete": all(
                    item["status"] == "known"
                    for side in (side_public["side_a"], side_public["side_b"])
                    for item in side),
                "roles_verified": False,
            })
        raw_inputs["reference_slot_union"] = sorted(all_member_slots)
        raw_inputs["target_slot"] = target_slot
        raw_inputs["target_side_occurrences"] = {
            hex(pointer): list(sides) for pointer, sides in target_occurrences.items()}
        return {
            "status": "known", "value": {
                "at_war": True, "war_count": len(public_wars), "wars": public_wars,
                "enumeration_scope": "current_country_opponent_index",
                "global_membership_verified": False, "lifetime_verified": False,
            }, "unit": "native_country_wars", "scale": 1,
            "partial": True, "complete": False,
            "basis": "current_country_war_index_and_side_vector_projection",
            "raw_inputs": raw_inputs,
        }
    except _LeafFailure as exc:
        raw_inputs["read_failure"] = str(exc)
        return _unknown(str(exc), raw_inputs)
    except Exception as exc:
        raw_inputs["read_failure"] = f"INTERNAL_VALIDATION_ERROR:{type(exc).__name__}"
        return _unknown("WARS_VALIDATION_FAILED", raw_inputs)


def read_fields(reader: Any, base: int, binding: Mapping[str, Any],
                fields: tuple[str, ...] | list[str], *,
                observer_binding: Mapping[str, Any] | None = None,
                registry_reader: Any = None,
                member_admission_reader: Any = None,
                admission_bindings: Mapping[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    """Read only ``F01.wars`` using the supplied bounded memory provider.

    ``binding`` and ``observer_binding`` are canonical per-country entries
    from the caller's already observed country scan.  The observer must be
    FRA.  The leaf independently resolves and rechecks their full references.
    An admission callback, when supplied, has the same signature as
    ``foreign_technology_capture._bound_admission``.  This helper constructs
    ``admission_bindings`` is the complete observed country scan from the
    parent. The leaf shallow-copies its top-level selector, preserves the
    original full rows, and replaces only ``requested`` with FRA and one
    independently revalidated member.
    """
    if not isinstance(fields, (tuple, list)) or len(fields) > 16:
        return {}
    if any(not isinstance(field, str) for field in fields):
        return {}
    requested: dict[str, dict[str, Any]] = {}
    supported: list[str] = []
    for field in fields:
        if field in requested:
            requested[field] = _unknown("DUPLICATE_FIELD_REQUESTED")
        elif field not in FIELDS:
            requested[field] = _unknown("UNSUPPORTED_FIELD_READER")
        else:
            requested[field] = {}
            supported.append(field)
    if not supported:
        return requested
    if FIELD_WARS in requested and requested[FIELD_WARS].get("status") == "unknown":
        return requested

    try:
        module_base, target_pointer, target = _scale._parse_target(base, binding)
    except Exception as exc:
        return {FIELD_WARS: _unknown(f"TARGET_BINDING_INVALID:{type(exc).__name__}")}
    if not isinstance(observer_binding, Mapping):
        return {FIELD_WARS: _unknown("OBSERVER_BINDING_MISSING")}
    try:
        observer_pointer, observer = _faith._binding(observer_binding)
    except Exception as exc:
        return {FIELD_WARS: _unknown(f"OBSERVER_BINDING_INVALID:{type(exc).__name__}")}
    if observer.get("tag") != "FRA":
        return {FIELD_WARS: _unknown("OBSERVER_MUST_BE_FRA")}

    limiter = _shared._BoundedReader(_ReaderAdapter(reader))
    try:
        target_normal, target_evidence = _validate_binding(
            limiter, module_base, target_pointer, target, "target")
        observer_normal, observer_evidence = _validate_binding(
            limiter, module_base, observer_pointer, observer, "observer")
        if (target_normal["database"] != observer_normal["database"]
                or target_normal["table"] != observer_normal["table"]
                or target_normal["count"] != observer_normal["count"]):
            raise _LeafFailure("COUNTRY_SCAN_METADATA_CHANGED")
        result = _read_wars(
            limiter, module_base, target_pointer, target_normal, observer_normal,
            observer_evidence["fullref_resolution"], target_evidence["fullref_resolution"],
            registry_reader, member_admission_reader, admission_bindings)
        result.setdefault("raw_inputs", {})["target_binding_validation"] = target_evidence
        result.setdefault("raw_inputs", {})["observer_binding_validation"] = observer_evidence
    except _LeafFailure as exc:
        result = _unknown(str(exc), {"target_binding": target_normal if "target_normal" in locals() else None,
                                     "observer_binding": observer_normal if "observer_normal" in locals() else None})
    except Exception as exc:
        result = _unknown(f"WARS_SETUP_FAILED:{type(exc).__name__}")
    for field in supported:
        requested[field] = deepcopy(result)
    return requested


__all__ = ["FIELD_WARS", "FIELDS", "SCHEMA", "read_fields"]
