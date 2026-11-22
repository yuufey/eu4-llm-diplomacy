"""Bounded two-pass projection of discovered province owner/controller tags.

This reader composes the country and province identity leaves with the
existing logical-FRA role/admission check. It supports only a positively
observed discovery bit; a clear bit remains unknown and is never interpreted
as invisibility. The result is private raw evidence, not a UI or public-field
qualification, and the two passes do not make a native atomic snapshot.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import math
from typing import Any

from . import country_reference_memory as _country
from . import foreign_country_memory as _shared
from . import foreign_technology_capture as _owner
from . import province_reference_memory as _province


SCHEMA = "information.province_state_memory.v1"
FIELDS = ("G02.owner", "G02.controller")
DATABASE_GLOBAL_RVA = 0x233D8B0
DATABASE_TABLE_OFFSET = 0x118
DATABASE_COUNT_OFFSET = 0x124
COUNTRY_FULLREF_OFFSET = 0x20
DISCOVERY_BITSET_POINTER_OFFSET = 0x5E0
OWNER_FULLREF_OFFSET = 0x468
CONTROLLER_FULLREF_OFFSET = 0x470
DISCOVERY_WORD_STRIDE = 4
MAX_COUNTRY_SLOTS = _country.MAX_COUNTRY_SLOTS
MIN_USER_ADDRESS = _shared.MIN_USER_ADDRESS
MAX_USER_ADDRESS_EXCLUSIVE = _shared.MAX_USER_ADDRESS_EXCLUSIVE


class _ReaderAdapter:
    """Adapt either the normal callable reader or an object with .read()."""

    def __init__(self, source: Any):
        self.source = source

    def read(self, address: int, size: int, label: str) -> bytes:
        try:
            method = getattr(self.source, "read", None)
            if callable(method):
                return method(address, size, label)
            if callable(self.source):
                return self.source(address, size, label)
            raise TypeError("reader_not_callable_or_readable")
        except Exception as exc:
            # Keep the bounded-reader and replay-visible exception class
            # independent of the underlying RPM wrapper's concrete error.
            raise ValueError("province_state_reader_failed") from exc


class _ReadFailure(Exception):
    pass


def _is_user_address(value: Any) -> bool:
    return (type(value) is int and MIN_USER_ADDRESS <= value < MAX_USER_ADDRESS_EXCLUSIVE
            and value <= 0xFFFFFFFFFFFFFFFF)


def _checked_add(address: int, offset: int, label: str) -> int:
    if (not _is_user_address(address) or type(offset) is not int or offset < 0
            or address > 0xFFFFFFFFFFFFFFFF - offset):
        raise _ReadFailure(f"address_arithmetic_invalid:{label}")
    result = address + offset
    if not _is_user_address(result):
        raise _ReadFailure(f"address_arithmetic_invalid:{label}")
    return result


def _checked_range(address: int, size: int, label: str) -> tuple[int, int]:
    if (not _is_user_address(address) or type(size) is not int or size <= 0
            or address > MAX_USER_ADDRESS_EXCLUSIVE - size):
        raise _ReadFailure(f"address_range_invalid:{label}")
    end = address + size
    if end > MAX_USER_ADDRESS_EXCLUSIVE:
        raise _ReadFailure(f"address_range_invalid:{label}")
    return address, end


def _overlaps(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def _read_exact(limiter: _shared._BoundedReader, address: int, size: int,
                label: str) -> bytes:
    if (not _is_user_address(address) or type(size) is not int or size <= 0
            or size > _shared.MAX_SINGLE_READ_BYTES
            or address > MAX_USER_ADDRESS_EXCLUSIVE - size):
        raise _ReadFailure(f"address_range_invalid:{label}")
    try:
        raw = limiter.read(address, size, label)
    except Exception as exc:
        raise _ReadFailure(f"read_failed:{label}:{type(exc).__name__}") from exc
    if len(raw) != size:
        raise _ReadFailure(f"short_read:{label}")
    return raw


def _unknown(reason: str, raw_inputs: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "reason": reason}
    if raw_inputs:
        result["raw_inputs"] = deepcopy(dict(raw_inputs))
    return result


def _binding(scan: Mapping[str, Any] | None, tag: str) -> dict[str, Any] | None:
    requested = scan.get("requested") if isinstance(scan, Mapping) else None
    item = requested.get(tag) if isinstance(requested, Mapping) else None
    return deepcopy(dict(item)) if isinstance(item, Mapping) else None


def _province_binding(scan: Mapping[str, Any] | None, province_id: int) -> dict[str, Any] | None:
    requested = scan.get("requested") if isinstance(scan, Mapping) else None
    item = requested.get(str(province_id)) if isinstance(requested, Mapping) else None
    return deepcopy(dict(item)) if isinstance(item, Mapping) else None


def _read_discovery(limiter: _shared._BoundedReader, record: int,
                    observer_slot: Any) -> dict[str, Any]:
    raw_inputs: dict[str, Any] = {"record_pointer": hex(record)}
    if type(observer_slot) is not int or not 0 <= observer_slot < MAX_COUNTRY_SLOTS:
        return _unknown("OBSERVER_SLOT_OUT_OF_RANGE", raw_inputs)
    try:
        pointer_address = _checked_add(record, DISCOVERY_BITSET_POINTER_OFFSET,
                                      "province_discovery_bitset_pointer")
        pointer_raw = _read_exact(limiter, pointer_address, 8,
                                  "province_state.discovery.bitset_pointer")
        bitset = int.from_bytes(pointer_raw, "little", signed=False)
        raw_inputs.update({"bitset_pointer_address": hex(pointer_address),
                           "bitset_pointer_raw_hex": pointer_raw.hex(),
                           "bitset_pointer": hex(bitset)})
        if (not _is_user_address(bitset) or bitset & 3
                or bitset == record or bitset == pointer_address):
            return _unknown("PROVINCE_DISCOVERY_POINTER_INVALID", raw_inputs)
        word_index = observer_slot >> 5
        bit_index = observer_slot & 0x1F
        word_address = _checked_add(bitset, word_index * DISCOVERY_WORD_STRIDE,
                                    "province_discovery_word")
        if word_address & 3:
            return _unknown("PROVINCE_DISCOVERY_WORD_ALIGNMENT_INVALID", raw_inputs)
        word_raw = _read_exact(limiter, word_address, 4,
                               "province_state.discovery.word_u32")
        word = int.from_bytes(word_raw, "little", signed=False)
        bit_value = (word >> bit_index) & 1
        raw_inputs.update({"observer_slot": observer_slot,
                           "word_index": word_index, "bit_index": bit_index,
                           "word_address": hex(word_address),
                           "word_raw_hex": word_raw.hex(), "word_u32": word,
                           "bit_value": bit_value})
        return {"status": "known", "value": bool(bit_value),
                "basis": "province_discovery_bitset_for_observer_slot",
                "raw_inputs": raw_inputs}
    except _ReadFailure as exc:
        return _unknown(str(exc), raw_inputs)


def _resolve_country_reference(limiter: _shared._BoundedReader, module_base: int,
                               reference_raw: bytes, label_prefix: str) -> dict[str, Any]:
    raw_inputs: dict[str, Any] = {"fullref_raw_hex": reference_raw.hex()}
    if len(reference_raw) != 8:
        return _unknown("COUNTRY_FULLREF_WIDTH_INVALID", raw_inputs)
    fullref = int.from_bytes(reference_raw, "little", signed=False)
    raw_inputs["fullref"] = hex(fullref)
    high_byte = (fullref >> 56) & 0xFF
    byte48 = (fullref >> 48) & 0xFF
    slot = (fullref >> 32) & 0xFFFF
    low32 = (fullref & 0xFFFFFFFF).to_bytes(4, "little")
    raw_inputs.update({"high_byte": high_byte, "byte48": byte48,
                       "slot": slot, "low32_raw_hex": low32.hex()})
    if high_byte == 0:
        return _unknown("COUNTRY_FULLREF_HIGH_BYTE_ZERO", raw_inputs)
    if byte48 == 7:
        return _unknown("COUNTRY_FULLREF_BYTE48_SEVEN", raw_inputs)
    if low32[3] != 0 or not all(
            0x30 <= value <= 0x39 or 0x41 <= value <= 0x5A for value in low32[:3]):
        return _unknown("COUNTRY_FULLREF_TAG_INVALID", raw_inputs)
    tag = low32[:3].decode("ascii")
    raw_inputs["tag"] = tag

    try:
        global_address = _checked_add(module_base, DATABASE_GLOBAL_RVA,
                                      f"{label_prefix}.database_global")
        database_raw = _read_exact(limiter, global_address, 8,
                                   f"province_state.{label_prefix}.database_global")
        database = int.from_bytes(database_raw, "little", signed=False)
        raw_inputs.update({"database_global_address": hex(global_address),
                           "database_global_raw_hex": database_raw.hex(),
                           "database": hex(database)})
        if not _is_user_address(database) or database & 7:
            return _unknown("COUNTRY_DATABASE_POINTER_INVALID", raw_inputs)
        if database in (module_base, global_address):
            return _unknown("COUNTRY_DATABASE_POINTER_ALIAS", raw_inputs)

        table_cell = _checked_add(database, DATABASE_TABLE_OFFSET,
                                  f"{label_prefix}.table_cell")
        table_raw = _read_exact(limiter, table_cell, 8,
                                f"province_state.{label_prefix}.table_pointer")
        table = int.from_bytes(table_raw, "little", signed=False)
        count_cell = _checked_add(database, DATABASE_COUNT_OFFSET,
                                  f"{label_prefix}.count_cell")
        count_raw = _read_exact(limiter, count_cell, 4,
                                f"province_state.{label_prefix}.count_i32")
        count = int.from_bytes(count_raw, "little", signed=True)
        raw_inputs.update({"table_cell_address": hex(table_cell),
                           "table_raw_hex": table_raw.hex(), "table": hex(table),
                           "count_cell_address": hex(count_cell),
                           "count_raw_hex": count_raw.hex(), "count": count})
        if not _is_user_address(table) or table & 7:
            return _unknown("COUNTRY_TABLE_POINTER_INVALID", raw_inputs)
        if table in (module_base, database, global_address):
            return _unknown("COUNTRY_TABLE_POINTER_ALIAS", raw_inputs)
        if not 1 <= count <= MAX_COUNTRY_SLOTS:
            return _unknown("COUNTRY_TABLE_COUNT_OUT_OF_RANGE", raw_inputs)
        global_range = _checked_range(global_address, 8,
                                     f"{label_prefix}.database_global_range")
        table_cell_range = _checked_range(table_cell, 8,
                                          f"{label_prefix}.table_cell_range")
        count_cell_range = _checked_range(count_cell, 4,
                                          f"{label_prefix}.count_cell_range")
        if _overlaps(table_cell_range, count_cell_range):
            return _unknown("COUNTRY_DATABASE_METADATA_ALIAS", raw_inputs)
        table_range = _checked_range(table, count * 8,
                                     f"{label_prefix}.table_range")
        if any(_overlaps(table_range, region) for region in
               (global_range, table_cell_range, count_cell_range)):
            return _unknown("COUNTRY_TABLE_METADATA_ALIAS", raw_inputs)
        if slot >= count:
            return _unknown("COUNTRY_FULLREF_SLOT_OUT_OF_RANGE", raw_inputs)

        table_entry = _checked_add(table, slot * 8,
                                  f"{label_prefix}.table_entry")
        pointer_raw = _read_exact(limiter, table_entry, 8,
                                  f"province_state.{label_prefix}.country_pointer")
        country_pointer = int.from_bytes(pointer_raw, "little", signed=False)
        raw_inputs.update({"table_entry_address": hex(table_entry),
                           "table_entry_raw_hex": pointer_raw.hex(),
                           "country_pointer": hex(country_pointer)})
        if not _is_user_address(country_pointer) or country_pointer & 7:
            return _unknown("COUNTRY_POINTER_INVALID", raw_inputs)
        if country_pointer in (module_base, database, table, global_address):
            return _unknown("COUNTRY_POINTER_ALIAS", raw_inputs)
        ref_probe_range = _checked_range(country_pointer, COUNTRY_FULLREF_OFFSET + 8,
                                         f"{label_prefix}.country_record_range")
        if _overlaps(ref_probe_range, table_range):
            return _unknown("COUNTRY_POINTER_TABLE_ALIAS", raw_inputs)

        fullref_address = _checked_add(country_pointer, COUNTRY_FULLREF_OFFSET,
                                       f"{label_prefix}.country_fullref")
        canonical_raw = _read_exact(limiter, fullref_address, 8,
                                    f"province_state.{label_prefix}.canonical_fullref")
        canonical = int.from_bytes(canonical_raw, "little", signed=False)
        raw_inputs.update({"canonical_fullref_address": hex(fullref_address),
                           "canonical_fullref_raw_hex": canonical_raw.hex(),
                           "canonical_fullref": hex(canonical)})
        if canonical != fullref:
            return _unknown("COUNTRY_FULLREF_ECHO_MISMATCH", raw_inputs)
        return {"status": "known", "value": tag,
                "basis": "province_discovery_bit_one_canonical_country_fullref",
                "raw_inputs": raw_inputs}
    except _ReadFailure as exc:
        return _unknown(str(exc), raw_inputs)
    except Exception as exc:
        return _unknown(f"COUNTRY_REFERENCE_READ_FAILED:{type(exc).__name__}", raw_inputs)


def _read_fields(limiter: _shared._BoundedReader, module_base: int,
                 province_binding: Mapping[str, Any],
                 fields: tuple[str, ...] = FIELDS) -> dict[str, Any]:
    record_value = province_binding.get("record_pointer")
    try:
        record = int(record_value, 0) if isinstance(record_value, str) else record_value
    except (TypeError, ValueError):
        return {field: _unknown("PROVINCE_RECORD_POINTER_INVALID") for field in fields}
    if not _is_user_address(record) or record & 7:
        return {field: _unknown("PROVINCE_RECORD_POINTER_INVALID") for field in fields}

    result: dict[str, Any] = {}
    offsets = {"G02.owner": OWNER_FULLREF_OFFSET,
               "G02.controller": CONTROLLER_FULLREF_OFFSET}
    for field in fields:
        offset = offsets.get(field)
        if offset is None:
            result[field] = _unknown("UNSUPPORTED_FIELD_READER")
            continue
        raw_inputs: dict[str, Any] = {"province_record_pointer": hex(record),
                                     "reference_offset": hex(offset)}
        try:
            address = _checked_add(record, offset, f"{field}.fullref")
            raw = _read_exact(limiter, address, 8,
                              f"province_state.{field}.province_fullref")
            raw_inputs.update({"reference_address": hex(address),
                               "reference_raw_hex": raw.hex()})
            result[field] = _resolve_country_reference(
                limiter, module_base, raw, field.replace(".", "_"))
            result[field].setdefault("raw_inputs", {}).update(raw_inputs)
        except _ReadFailure as exc:
            result[field] = _unknown(str(exc), raw_inputs)
        except Exception as exc:
            result[field] = _unknown(f"COUNTRY_REFERENCE_READ_FAILED:{type(exc).__name__}", raw_inputs)
    return result


def _not_read_fields(reason: str, discovery: Mapping[str, Any] | None = None,
                     fields: tuple[str, ...] = FIELDS) -> dict[str, Any]:
    raw_inputs = {"discovery": deepcopy(dict(discovery))} if isinstance(discovery, Mapping) else None
    return {field: _unknown(reason, raw_inputs) for field in fields}


def _valid_field_ids(fields: Any) -> tuple[str, ...] | None:
    if not isinstance(fields, (list, tuple)) or not fields or len(fields) > _shared.MAX_FIELDS:
        return None
    normalized: list[str] = []
    seen: set[str] = set()
    for field in fields:
        if (type(field) is not str or len(field) > _shared.MAX_FIELD_ID_LENGTH
                or not field.isascii() or not field.startswith("G02.")):
            return None
        suffix = field[4:]
        if not suffix or any(not ("A" <= char <= "Z" or "a" <= char <= "z"
                                  or "0" <= char <= "9" or char == "_")
                             for char in suffix):
            return None
        if field in seen:
            return None
        seen.add(field)
        normalized.append(field)
    return tuple(normalized)


def _json_value(value: Any, depth: int = 0, seen: set[int] | None = None) -> bool:
    if depth > 32:
        return False
    if value is None or type(value) in (str, bool, int):
        return True
    if type(value) is float:
        return math.isfinite(value)
    if seen is None:
        seen = set()
    if type(value) in (list, dict):
        marker = id(value)
        if marker in seen:
            return False
        seen.add(marker)
        try:
            if type(value) is list:
                return all(_json_value(item, depth + 1, seen) for item in value)
            return (all(type(key) is str for key in value)
                    and all(_json_value(item, depth + 1, seen) for item in value.values()))
        finally:
            seen.remove(marker)
    return False


def _normalize_field_results(raw: Any, fields: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        return {field: _unknown("FIELD_READER_RESULT_INVALID") for field in fields}
    result: dict[str, Any] = {}
    for field in fields:
        item = raw.get(field)
        if not isinstance(item, Mapping):
            result[field] = _unknown("FIELD_RESULT_MISSING" if field not in raw
                                     else "FIELD_RESULT_INVALID")
            continue
        status = item.get("status")
        try:
            copied = deepcopy(dict(item))
        except Exception:
            result[field] = _unknown("FIELD_RESULT_INVALID")
            continue
        if (not _json_value(copied) or status not in ("known", "unknown")
                or (status == "known" and "value" not in copied)
                or (status == "unknown" and "value" in copied)):
            result[field] = _unknown("FIELD_RESULT_INVALID")
            continue
        result[field] = copied
    return result


def _default_read_fields(limiter: _shared._BoundedReader, module_base: int,
                         province_binding: Mapping[str, Any],
                         fields: tuple[str, ...]) -> dict[str, Any]:
    supported = tuple(field for field in fields if field in FIELDS)
    unsupported = {field: _unknown("UNSUPPORTED_FIELD_READER")
                   for field in fields if field not in FIELDS}
    if supported:
        unsupported.update(_read_fields(limiter, module_base, province_binding, supported))
    return unsupported


def _read_pass(number: int, limiter: _shared._BoundedReader, module_base: int,
               province_id: int, observer: str, fields: tuple[str, ...],
               read_fields: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "pass": number, "status": "unknown", "errors": [],
        "country_scan": None, "province_scan": None,
        "observer_binding": None, "province_binding": None,
        "admission": {"status": "unknown", "admitted": None,
                      "reason": "identity_binding_unavailable",
                      "observer_nonplayer_role": {
                          "observer": observer, "verified": False,
                          "basis": "copied_native_controller_array_not_UI_current_country"}},
        "discovery": {"status": "unknown", "reason": "identity_binding_unavailable"},
        "fields_raw": {field: _unknown("IDENTITY_BINDING_UNAVAILABLE") for field in fields},
    }
    try:
        result["country_scan"] = _country.resolve_countries(
            limiter.read, module_base, [observer])
    except Exception as exc:
        result["errors"].append({"code": "country_resolution_failed",
                                 "detail": f"{type(exc).__name__}:{exc}"})
    result["province_scan"] = _province.resolve_provinces(
        limiter, module_base, [province_id])

    country_scan = result["country_scan"]
    province_scan = result["province_scan"]
    observer_binding = _binding(country_scan, observer)
    province_binding = _province_binding(province_scan, province_id)
    result["observer_binding"] = observer_binding
    result["province_binding"] = province_binding
    if (not isinstance(country_scan, Mapping) or country_scan.get("status") != "observed"
            or observer_binding is None):
        result["errors"].append({"code": "observer_binding_unavailable"})
        return result
    if (not isinstance(province_scan, Mapping) or province_scan.get("status") != "observed"
            or province_binding is None):
        result["errors"].append({"code": "province_binding_unavailable",
                                 "detail": (province_scan.get("reason")
                                            if isinstance(province_scan, Mapping) else None)})
        return result

    try:
        admission = _owner._bound_admission(
            limiter.read, module_base, country_scan, observer, observer)
        if not isinstance(admission, Mapping):
            raise TypeError("admission_result_not_mapping")
        admission = deepcopy(dict(admission))
    except Exception as exc:
        result["admission"] = {
            "status": "unknown", "admitted": None,
            "reason": f"admission_reader_failed:{type(exc).__name__}",
            "observer_nonplayer_role": {
                "observer": observer, "verified": False,
                "reason": "ADMISSION_READ_FAILED",
                "basis": "copied_native_controller_array_not_UI_current_country"},
        }
        result["errors"].append({"code": "admission_reader_failed",
                                 "detail": f"{type(exc).__name__}:{exc}"})
        return result
    if not isinstance(admission.get("observer_nonplayer_role"), Mapping):
        admission["observer_nonplayer_role"] = {
            "observer": observer, "verified": False,
            "reason": "ROLE_EVIDENCE_MISSING",
            "basis": "copied_native_controller_array_not_UI_current_country"}
    result["admission"] = admission

    role = admission.get("observer_nonplayer_role")
    role_verified = isinstance(role, Mapping) and role.get("verified") is True
    admitted = (admission.get("status") == "known"
                and type(admission.get("admitted")) is bool
                and admission.get("admitted") is True)
    if not role_verified:
        result["discovery"] = {"status": "not_read", "reason": "OBSERVER_ROLE_NOT_VERIFIED"}
        result["fields_raw"] = {field: _unknown("OBSERVER_ROLE_NOT_VERIFIED") for field in fields}
        result["status"] = "observed"
        return result
    if not admitted:
        result["discovery"] = {"status": "not_read", "reason": "PROVINCE_SELF_ADMISSION_NOT_ESTABLISHED"}
        result["fields_raw"] = {field: _unknown("PROVINCE_SELF_ADMISSION_NOT_ESTABLISHED")
                                 for field in fields}
        result["status"] = "observed"
        return result

    try:
        record = int(province_binding["record_pointer"], 0)
    except Exception:
        result["discovery"] = {"status": "unknown", "reason": "PROVINCE_RECORD_POINTER_INVALID"}
        result["fields_raw"] = {field: _unknown("PROVINCE_RECORD_POINTER_INVALID")
                                 for field in fields}
        result["status"] = "observed"
        return result
    discovery = _read_discovery(limiter, record, observer_binding.get("slot"))
    result["discovery"] = discovery
    if discovery.get("status") != "known":
        reason = str(discovery.get("reason", "PROVINCE_DISCOVERY_UNKNOWN"))
        raw_inputs = {"discovery": deepcopy(dict(discovery))}
        result["fields_raw"] = {field: _unknown(reason, raw_inputs) for field in fields}
        result["status"] = "observed"
        return result
    if discovery.get("value") is not True:
        raw_inputs = {"discovery": deepcopy(dict(discovery))}
        result["fields_raw"] = {field: _unknown("PROVINCE_DISCOVERY_NOT_ESTABLISHED", raw_inputs)
                                 for field in fields}
        result["status"] = "observed"
        return result

    try:
        raw_fields = read_fields(limiter, module_base, province_binding, fields)
    except Exception as exc:
        result["errors"].append({"code": "field_reader_failed",
                                 "detail": type(exc).__name__})
        raw_fields = {field: _unknown("FIELD_READER_FAILED") for field in fields}
    result["fields_raw"] = _normalize_field_results(raw_fields, fields)
    result["status"] = "observed"
    return result


def _base_result(province_id: Any, observer: Any,
                 fields: tuple[str, ...] = FIELDS, *, observer_scoped=False) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": "unknown",
        "observer": {"tag": observer if _shared._tag_ok(observer) and (observer_scoped or observer == "FRA") else None,
                     "fullref": None,
                     "bindings_by_pass": {"pass1": None, "pass2": None}},
        "targets": [{
            "province_id": province_id if type(province_id) is int else None,
            "bindings_by_pass": {"pass1": None, "pass2": None},
            "admission_by_pass": {"pass1": None, "pass2": None},
            "discovery_by_pass": {"pass1": None, "pass2": None},
            "fields": {field: {"status": "unknown", "reason": "not_read"} for field in fields},
            "field_consistency": {field: {"status": "unknown", "reason": "not_read"}
                                  for field in fields},
        }],
        "pass_evidence": {"pass1": None, "pass2": None},
        "consistency": {"status": "unknown", "shared_mismatch_paths": []},
        "budget": {"calls": 0, "bytes_requested": 0, "bytes_returned": 0,
                    "rejected_bytes": 0, "max_single_read": 0,
                    "max_calls": _shared.MAX_READ_CALLS,
                    "limit_bytes": _shared.MAX_TOTAL_READ_BYTES,
                    "limit_single_read_bytes": _shared.MAX_SINGLE_READ_BYTES},
        "visibility": {"status": "unknown", "reason": "PROVINCE_UI_VISIBILITY_NOT_PROVEN"},
        "complete": False,
        "public_export_ready": False,
        "errors": [],
    }


def read_two_pass(reader: Any, base: int, province_id: int, *,
                  observer: str = "FRA", fields: list[str] | tuple[str, ...] = FIELDS,
                  read_fields: Any = None, observer_scoped=False) -> dict[str, Any]:
    """Read selected G02 fields independently for a positively discovered ID.

    Each pass resolves the observer and province, validates the observer's role,
    and reads the province+0x5e0 discovery bit for the observer slot. Owner
    and controller fullrefs are then validated independently against the
    bounded country database; no per-reference full database scan is done.
    """
    selected_fields = _valid_field_ids(fields)
    if selected_fields is None:
        result = _base_result(province_id, observer, observer_scoped=observer_scoped)
        result["errors"].append({"code": "field_scope_invalid"})
        return result
    result = _base_result(province_id, observer, selected_fields, observer_scoped=observer_scoped)
    if read_fields is not None and not callable(read_fields):
        result["errors"].append({"code": "field_reader_invalid"})
        return result
    if not _shared._tag_ok(observer) or (not observer_scoped and observer != "FRA"):
        result["errors"].append({"code": "observer_scope_invalid", "reason": "OBSERVER_TAG_INVALID" if observer_scoped else "FRA_ONLY"})
        return result
    if type(province_id) is not int or province_id < 1:
        result["errors"].append({"code": "province_id_invalid"})
        return result
    if not callable(reader) and not callable(getattr(reader, "read", None)):
        result["errors"].append({"code": "reader_not_callable_or_readable"})
        return result
    if (type(base) is not int or not MIN_USER_ADDRESS <= base < MAX_USER_ADDRESS_EXCLUSIVE
            or base & 7):
        result["errors"].append({"code": "module_base_invalid"})
        return result

    limiter = _shared._BoundedReader(_ReaderAdapter(reader))
    field_reader = _default_read_fields if read_fields is None else read_fields
    passes = [_read_pass(index, limiter, base, province_id, observer,
                         selected_fields, field_reader)
              for index in (1, 2)]
    result["pass_evidence"] = {f"pass{item['pass']}": item for item in passes}
    result["budget"] = limiter.summary()
    result["errors"] = [*limiter.errors,
                         *(error for item in passes for error in item["errors"])]
    result["observer"]["bindings_by_pass"] = {
        f"pass{item['pass']}": deepcopy(item.get("observer_binding")) for item in passes}
    if all(isinstance(item.get("observer_binding"), Mapping) for item in passes):
        left, right = (item["observer_binding"] for item in passes)
        if _shared._same_raw(left, right):
            result["observer"]["fullref"] = right.get("fullref")

    target = result["targets"][0]
    target["bindings_by_pass"] = {
        f"pass{item['pass']}": {
            "observer": deepcopy(item.get("observer_binding")),
            "province": deepcopy(item.get("province_binding")),
            "world": deepcopy(item.get("province_scan", {}).get("world")
                               if isinstance(item.get("province_scan"), Mapping) else None),
            "header": deepcopy(item.get("province_scan", {}).get("header")
                                if isinstance(item.get("province_scan"), Mapping) else None),
        } for item in passes}
    target["admission_by_pass"] = {
        f"pass{item['pass']}": deepcopy(item.get("admission")) for item in passes}
    target["discovery_by_pass"] = {
        f"pass{item['pass']}": deepcopy(item.get("discovery")) for item in passes}

    mismatch_paths: list[str] = []
    incomplete_paths: list[str] = []
    # The complete country scan remains in private pass evidence, but unrelated
    # rows are not shared identity. The requested FRA binding plus the province,
    # admission and discovery evidence are the cross-pass invariants.
    shared_keys = ("observer_binding", "province_scan", "admission", "discovery")
    for key in shared_keys:
        first, second = (item.get(key) for item in passes)
        if first is None or second is None:
            incomplete_paths.append(key)
        elif not _shared._same_raw(first, second):
            mismatch_paths.append(key)
    if any(item.get("status") != "observed" for item in passes):
        incomplete_paths.append("pass_evidence")

    if mismatch_paths:
        result["status"] = "unknown"
        result["consistency"] = {"status": "changed",
                                 "shared_mismatch_paths": mismatch_paths}
        for field in selected_fields:
            target["fields"][field] = _unknown("SHARED_EVIDENCE_CHANGED")
            target["field_consistency"][field] = {
                "status": "unknown", "reason": "SHARED_EVIDENCE_CHANGED"}
        result["errors"].append({"code": "shared_evidence_changed",
                                 "paths": mismatch_paths})
        return result
    if incomplete_paths:
        result["status"] = "unknown"
        result["consistency"] = {"status": "unknown",
                                 "shared_mismatch_paths": sorted(set(incomplete_paths))}
        for field in selected_fields:
            target["fields"][field] = _unknown("SHARED_EVIDENCE_UNKNOWN")
            target["field_consistency"][field] = {
                "status": "unknown", "reason": "SHARED_EVIDENCE_UNKNOWN"}
        return result

    result["status"] = "observed"
    result["consistency"] = {"status": "stable", "shared_mismatch_paths": []}
    raw1, raw2 = (item["fields_raw"] for item in passes)
    for field in selected_fields:
        first = raw1.get(field) if isinstance(raw1, Mapping) else None
        second = raw2.get(field) if isinstance(raw2, Mapping) else None
        if not _shared._same_raw(first, second):
            target["fields"][field] = _unknown("FIELD_RAW_DATA_CHANGED")
            target["field_consistency"][field] = {"status": "changed"}
        elif (isinstance(second, Mapping) and second.get("status") == "known"
              and "value" in second and _json_value(second.get("value"))):
            target["fields"][field] = deepcopy(dict(second))
            target["field_consistency"][field] = {"status": "stable"}
        elif isinstance(second, Mapping) and second.get("status") == "unknown":
            target["fields"][field] = deepcopy(dict(second))
            target["field_consistency"][field] = {
                "status": "unknown", "reason": second.get("reason", "field_unknown")}
        else:
            target["fields"][field] = _unknown("FIELD_RESULT_INVALID")
            target["field_consistency"][field] = {
                "status": "unknown", "reason": "FIELD_RESULT_INVALID"}
    return result


__all__ = ["SCHEMA", "FIELDS", "read_two_pass"]
