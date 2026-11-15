"""Bounded raw country development and weighted subject-scale reads.

This is a private memory-reader leaf. It assumes its caller has already
validated the process/profile/session and owns role, visibility and two-pass
stability checks. The subject vector is the native vector encountered by the
tooltip path; it is not asserted to be a complete list of all dependencies.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from . import country_faith_memory as _faith
from . import foreign_country_memory as _shared
from . import province_state_memory as _province


SCHEMA = "information.country_scale_development_memory.v1"
FIELD_DEVELOPMENT = "F01.development"
FIELD_SUBJECT_SCALE = "F01.subject_scale"
FIELDS = (FIELD_DEVELOPMENT, FIELD_SUBJECT_SCALE)

OWN_DEVELOPMENT_OFFSET = 0xE1C
SUBJECT_VECTOR_BEGIN_OFFSET = 0x1A18
SUBJECT_VECTOR_END_OFFSET = 0x1A20
OVERLORD_FULLREF_OFFSET = 0x18F0
RELATION_TABLE_POINTER_OFFSET = 0x1510
RELATION_ROW_STRIDE = 0x48
RELATION_ROW_OWNER_OFFSET = 0x00
RELATION_ROW_RECIPIENT_OFFSET = 0x10
OWNER_ASSOCIATIONS_POINTER_OFFSET = 0x128
OWNER_ASSOCIATIONS_COUNT_OFFSET = 0x134
ASSOCIATION_ENTRY_STRIDE = 16
ASSOCIATION_TYPE_POINTER_OFFSET = 0x40
TYPE_FLAG_OFFSETS = (0x11B, 0x14B, 0x121, 0x13E, 0x151, 0x148)
WEIGHT_GLOBAL_RVA = 0x233F8AC
DEVELOPMENT_SCALE = 1000
MAX_SUBJECTS = 256
MAX_RELATION_ENTRIES = 4096
MAX_TOTAL_READ_BYTES = _shared.MAX_TOTAL_READ_BYTES
MAX_SINGLE_READ_BYTES = _shared.MAX_SINGLE_READ_BYTES
MAX_READ_CALLS = _shared.MAX_READ_CALLS
MIN_USER_ADDRESS = _shared.MIN_USER_ADDRESS
MAX_USER_ADDRESS_EXCLUSIVE = _shared.MAX_USER_ADDRESS_EXCLUSIVE
MAX_U64 = 0xFFFFFFFFFFFFFFFF


class _ReaderAdapter:
    """Normalize the parent's callable or .read() reader for the shared cap."""

    def __init__(self, source: Any):
        self.source = source

    def read(self, address: int, size: int, label: str) -> bytes:
        try:
            method = getattr(self.source, "read", None)
            if callable(method):
                raw = method(address, size, label)
            elif callable(self.source):
                raw = self.source(address, size, label)
            else:
                raise TypeError("reader_not_callable_or_readable")
        except Exception as exc:
            raise ValueError("country_scale_reader_failed") from exc
        if not isinstance(raw, (bytes, bytearray, memoryview)):
            raise ValueError("country_scale_reader_result_invalid")
        return bytes(raw)


class _LeafFailure(Exception):
    pass


def _is_user_address(value: Any) -> bool:
    return (type(value) is int and MIN_USER_ADDRESS <= value < MAX_USER_ADDRESS_EXCLUSIVE
            and value <= MAX_U64)


def _checked_add(address: int, offset: int, size: int, label: str) -> int:
    if (not _is_user_address(address) or type(offset) is not int or offset < 0
            or type(size) is not int or size <= 0 or offset > MAX_U64 - address):
        raise _LeafFailure(f"address_arithmetic_invalid:{label}")
    result = address + offset
    if (not _is_user_address(result) or result > MAX_USER_ADDRESS_EXCLUSIVE - size
            or result > MAX_U64 - (size - 1)):
        raise _LeafFailure(f"address_range_invalid:{label}")
    return result


def _checked_pointer(value: Any, label: str, *, allow_null: bool = False) -> int:
    if type(value) is not int or not 0 <= value <= MAX_U64:
        raise _LeafFailure(f"pointer_invalid:{label}")
    if value == 0 and allow_null:
        return 0
    if not _is_user_address(value) or value & 7:
        raise _LeafFailure(f"pointer_invalid:{label}")
    return value


def _checked_range(address: int, size: int, label: str) -> tuple[int, int]:
    start = _checked_add(address, 0, size, label)
    return start, start + size


def _overlaps(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def _read_exact(limiter: _shared._BoundedReader, address: int,
                size: int, label: str) -> bytes:
    if (not _is_user_address(address) or type(size) is not int or size <= 0
            or size > MAX_SINGLE_READ_BYTES
            or address > MAX_USER_ADDRESS_EXCLUSIVE - size):
        raise _LeafFailure(f"address_range_invalid:{label}")
    try:
        raw = limiter.read(address, size, label)
    except Exception as exc:
        message = str(exc)
        if "reader_short_read" in message or "short_or_invalid_read" in message:
            raise _LeafFailure(f"short_read:{label}") from exc
        if "read_budget_exceeded" in message or "read_call_budget_exceeded" in message:
            raise _LeafFailure(f"read_budget_exceeded:{label}") from exc
        raise _LeafFailure(f"read_failed:{label}") from exc
    if len(raw) != size:
        raise _LeafFailure(f"short_read:{label}")
    return raw


def _u64(raw: bytes) -> int:
    return int.from_bytes(raw, "little", signed=False)


def _i32(raw: bytes) -> int:
    return int.from_bytes(raw, "little", signed=True)


def _wrap_i32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _trunc_div(numerator: int, denominator: int) -> int:
    quotient = abs(numerator) // denominator
    return -quotient if numerator < 0 else quotient


def _unknown(reason: str, raw_inputs: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "reason": reason}
    if raw_inputs:
        result["raw_inputs"] = deepcopy(dict(raw_inputs))
    return result


def _parse_target(base: Any, binding: Any) -> tuple[int, int, dict[str, Any]]:
    if type(base) is not int or not _is_user_address(base) or base & 7:
        raise ValueError("module_base_invalid")
    pointer, retained = _faith._binding(binding)
    if not _is_user_address(pointer) or pointer & 7:
        raise ValueError("target_country_pointer_invalid")
    fullref = int(retained["fullref"], 0)
    if ((fullref >> 56) & 0xFF) == 0 or ((fullref >> 48) & 0xFF) == 7:
        raise ValueError("target_fullref_invalid")
    return base, pointer, retained


def _resolve_bound_reference(limiter: _shared._BoundedReader, base: int,
                              fullref_raw: bytes, label: str) -> dict[str, Any]:
    try:
        result = _province._resolve_country_reference(limiter, base, fullref_raw, label)
    except Exception as exc:
        raise _LeafFailure(f"country_reference_failed:{label}") from exc
    if not isinstance(result, Mapping) or result.get("status") != "known":
        raise _LeafFailure(f"country_reference_unknown:{label}")
    return dict(result)


def _validate_target_binding(limiter: _shared._BoundedReader, base: int,
                             target_pointer: int,
                             target: Mapping[str, Any]) -> dict[str, Any]:
    fullref_raw = bytes.fromhex(str(target["fullref_raw_hex"]))
    resolved = _resolve_bound_reference(limiter, base, fullref_raw, "target")
    evidence = resolved.get("raw_inputs")
    if not isinstance(evidence, Mapping):
        raise _LeafFailure("target_reference_evidence_missing")
    try:
        resolved_pointer = int(evidence["country_pointer"], 0)
        resolved_fullref = int(evidence["canonical_fullref"], 0)
    except (KeyError, TypeError, ValueError) as exc:
        raise _LeafFailure("target_reference_evidence_invalid") from exc
    fullref = int(target["fullref"], 0)
    if (resolved_pointer != target_pointer or resolved_fullref != fullref
            or resolved.get("value") != target["tag"]):
        raise _LeafFailure("target_binding_database_mismatch")
    return {"binding": deepcopy(dict(target)),
            "fullref_resolution": deepcopy(dict(resolved))}


def _read_development(limiter: _shared._BoundedReader, country_pointer: int,
                      target_evidence: Mapping[str, Any]) -> dict[str, Any]:
    raw_inputs: dict[str, Any] = {"target_binding": deepcopy(dict(target_evidence))}
    try:
        address = _checked_add(country_pointer, OWN_DEVELOPMENT_OFFSET, 4,
                               "own_development")
        raw = _read_exact(limiter, address, 4, "country_scale.development.own_i32")
        value = _i32(raw)
        raw_inputs.update({"own_development_address": hex(address),
                           "own_development_raw_hex": raw.hex(),
                           "own_development_i32": value})
        return {"status": "known", "value": value, "scale": DEVELOPMENT_SCALE,
                "unit": "development_raw", "basis": "country_own_development_cache",
                "raw_inputs": raw_inputs}
    except _LeafFailure as exc:
        return _unknown(str(exc), raw_inputs)


def _read_subject_weight(limiter: _shared._BoundedReader, base: int,
                         child_pointer: int, child_ref: bytes,
                         child_tag: str, child_slot: int,
                         raw_inputs: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    """Return (included, evidence) for one native subject-vector entry."""
    evidence: dict[str, Any] = {
        "subject_fullref_raw_hex": child_ref.hex(),
        "subject_tag": child_tag,
        "subject_slot": child_slot,
        "subject_country_pointer": hex(child_pointer),
        "branch": "include",
        "relation_flags": [],
        "weighted_development_raw": 0,
    }
    child_dev_address = _checked_add(child_pointer, OWN_DEVELOPMENT_OFFSET, 4,
                                    "subject_own_development")
    child_dev_raw = _read_exact(limiter, child_dev_address, 4,
                                f"country_scale.subject[{child_slot}].development_i32")
    child_development = _i32(child_dev_raw)
    evidence.update({"own_development_address": hex(child_dev_address),
                     "own_development_raw_hex": child_dev_raw.hex(),
                     "own_development_i32": child_development})

    overlord_address = _checked_add(child_pointer, OVERLORD_FULLREF_OFFSET, 8,
                                    "subject_overlord_fullref")
    overlord_raw = _read_exact(limiter, overlord_address, 8,
                               f"country_scale.subject[{child_slot}].overlord_fullref")
    evidence.update({"overlord_fullref_address": hex(overlord_address),
                     "overlord_fullref_raw_hex": overlord_raw.hex()})
    overlord_fullref = _u64(overlord_raw)
    overlord_high_byte = (overlord_fullref >> 56) & 0xFF
    evidence["overlord_high_byte"] = overlord_high_byte
    if overlord_high_byte == 0:
        evidence["branch"] = "include_no_overlord_high_byte_zero"
        return True, evidence

    overlord = _resolve_bound_reference(limiter, base, overlord_raw,
                                        f"subject[{child_slot}].overlord")
    overlord_raw_inputs = overlord.get("raw_inputs")
    if not isinstance(overlord_raw_inputs, Mapping):
        raise _LeafFailure("overlord_reference_evidence_missing")
    try:
        overlord_pointer = int(overlord_raw_inputs["country_pointer"], 0)
        overlord_tag = str(overlord["value"])
        overlord_slot = int(overlord_raw_inputs["slot"])
    except (KeyError, TypeError, ValueError) as exc:
        raise _LeafFailure("overlord_reference_evidence_invalid") from exc
    evidence["overlord_binding"] = deepcopy(dict(overlord))

    relation_pointer_address = _checked_add(child_pointer,
                                            RELATION_TABLE_POINTER_OFFSET, 8,
                                            "subject_relation_table_pointer")
    relation_pointer_raw = _read_exact(
        limiter, relation_pointer_address, 8,
        f"country_scale.subject[{child_slot}].relation_table_pointer")
    relation_table = _checked_pointer(_u64(relation_pointer_raw),
                                      "subject_relation_table")
    evidence.update({"relation_table_pointer_address": hex(relation_pointer_address),
                     "relation_table_pointer_raw_hex": relation_pointer_raw.hex(),
                     "relation_table_pointer": hex(relation_table),
                     "overlord_tag": overlord_tag, "overlord_slot": overlord_slot})
    row_offset = overlord_slot * RELATION_ROW_STRIDE
    row_address = _checked_add(relation_table, row_offset,
                               RELATION_ROW_RECIPIENT_OFFSET + 8,
                               "subject_relation_row")
    row_raw = _read_exact(limiter, row_address,
                          RELATION_ROW_RECIPIENT_OFFSET + 8,
                          f"country_scale.subject[{child_slot}].relation_row")
    owner_pointer_raw = row_raw[RELATION_ROW_OWNER_OFFSET:RELATION_ROW_OWNER_OFFSET + 8]
    recipient_raw = row_raw[RELATION_ROW_RECIPIENT_OFFSET:RELATION_ROW_RECIPIENT_OFFSET + 8]
    recipient = _u64(recipient_raw)
    evidence.update({"relation_row_address": hex(row_address),
                     "relation_row_raw_hex": row_raw.hex(),
                     "relation_owner_pointer_raw_hex": owner_pointer_raw.hex(),
                     "relation_recipient_fullref_raw_hex": recipient_raw.hex()})
    if recipient != _u64(overlord_raw):
        raise _LeafFailure("relation_recipient_fullref_mismatch")
    owner_pointer = _checked_pointer(_u64(owner_pointer_raw), "relation_owner")
    evidence["relation_owner_pointer"] = hex(owner_pointer)

    owner_fields_address = _checked_add(owner_pointer,
                                        OWNER_ASSOCIATIONS_POINTER_OFFSET, 16,
                                        "relation_owner_associations")
    owner_fields_raw = _read_exact(
        limiter, owner_fields_address, 16,
        f"country_scale.subject[{child_slot}].owner_associations_header")
    entries_pointer_raw = owner_fields_raw[:8]
    count_raw = owner_fields_raw[OWNER_ASSOCIATIONS_COUNT_OFFSET
                                 - OWNER_ASSOCIATIONS_POINTER_OFFSET:
                                 OWNER_ASSOCIATIONS_COUNT_OFFSET
                                 - OWNER_ASSOCIATIONS_POINTER_OFFSET + 4]
    entries_pointer = _u64(entries_pointer_raw)
    entry_count = _i32(count_raw)
    evidence.update({"owner_associations_header_address": hex(owner_fields_address),
                     "owner_associations_header_raw_hex": owner_fields_raw.hex(),
                     "association_entries_pointer_raw_hex": entries_pointer_raw.hex(),
                     "association_entries_pointer": hex(entries_pointer) if entries_pointer else None,
                     "association_count_raw_hex": count_raw.hex(),
                     "association_count_i32": entry_count})
    if not 0 <= entry_count <= MAX_RELATION_ENTRIES:
        raise _LeafFailure("relation_association_count_out_of_range")
    if entry_count == 0:
        evidence["branch"] = "include_no_associations"
        return True, evidence
    entries_pointer = _checked_pointer(entries_pointer, "association_entries")
    entries_size = entry_count * ASSOCIATION_ENTRY_STRIDE
    entries_range = _checked_range(entries_pointer, entries_size,
                                    "relation_association_entries")
    owner_range = _checked_range(owner_pointer,
                                 OWNER_ASSOCIATIONS_COUNT_OFFSET + 4,
                                 "relation_owner_header")
    if _overlaps(entries_range, owner_range):
        raise _LeafFailure("association_entries_owner_alias")
    entries_raw = _read_exact(
        limiter, entries_pointer, entries_size,
        f"country_scale.subject[{child_slot}].association_entries")
    evidence.update({"association_entries_raw_hex": entries_raw.hex(),
                     "association_entry_count_read": entry_count})

    selected: dict[str, Any] | None = None
    for index in range(entry_count):
        offset = index * ASSOCIATION_ENTRY_STRIDE
        slot_raw = entries_raw[offset:offset + 4]
        association_raw = entries_raw[offset + 8:offset + 16]
        other_slot = _i32(slot_raw)
        entry = {"index": index, "raw_hex": entries_raw[offset:offset + 16].hex(),
                 "other_slot_i32": other_slot,
                 "association_pointer_raw_hex": association_raw.hex(),
                 "association_pointer": (hex(_u64(association_raw))
                                          if _u64(association_raw) else None)}
        if other_slot == overlord_slot:
            selected = entry
            break
    evidence["selected_association_entry"] = selected
    if selected is None:
        evidence["branch"] = "include_no_matching_association"
        return True, evidence

    association_pointer_value = int(selected["association_pointer"] or "0", 0)
    if association_pointer_value == 0:
        evidence["branch"] = "include_null_association"
        return True, evidence
    association_pointer = _checked_pointer(association_pointer_value,
                                            "association_object")
    type_pointer_address = _checked_add(association_pointer,
                                       ASSOCIATION_TYPE_POINTER_OFFSET, 8,
                                       "association_type_pointer")
    type_pointer_raw = _read_exact(
        limiter, type_pointer_address, 8,
        f"country_scale.subject[{child_slot}].association_type_pointer")
    type_pointer_value = _u64(type_pointer_raw)
    evidence.update({"association_object_pointer": hex(association_pointer),
                     "association_type_pointer_address": hex(type_pointer_address),
                     "association_type_pointer_raw_hex": type_pointer_raw.hex(),
                     "association_type_pointer": (hex(type_pointer_value)
                                                   if type_pointer_value else None)})
    if type_pointer_value == 0:
        evidence["branch"] = "include_null_type_definition"
        return True, evidence
    type_pointer = _checked_pointer(type_pointer_value, "association_type_definition")
    flags: list[dict[str, Any]] = []
    expected = ("nonzero", "nonzero", "zero", "zero", "zero", "nonzero")
    for index, offset in enumerate(TYPE_FLAG_OFFSETS):
        flag_address = _checked_add(type_pointer, offset, 1,
                                    f"association_type_flag_{index}")
        flag_raw = _read_exact(
            limiter, flag_address, 1,
            f"country_scale.subject[{child_slot}].type_flag_{offset:x}")
        flag_value = flag_raw[0]
        matched = (flag_value != 0) if expected[index] == "nonzero" else (flag_value == 0)
        flags.append({"offset": hex(offset), "address": hex(flag_address),
                      "raw_hex": flag_raw.hex(), "value": flag_value,
                      "expected": expected[index], "matched": matched})
        if not matched:
            evidence["relation_flags"] = flags
            evidence["branch"] = "include_type_flags_not_exclusion_pattern"
            return True, evidence
    evidence["relation_flags"] = flags
    evidence["branch"] = "exclude_type_flags_match"
    return False, evidence


def _read_subject_scale(limiter: _shared._BoundedReader, base: int,
                        country_pointer: int,
                        target_evidence: Mapping[str, Any]) -> dict[str, Any]:
    raw_inputs: dict[str, Any] = {"target_binding": deepcopy(dict(target_evidence)),
                                 "subjects": []}
    try:
        vector_header_address = _checked_add(country_pointer,
                                             SUBJECT_VECTOR_BEGIN_OFFSET, 16,
                                             "subject_vector_header")
        vector_header = _read_exact(limiter, vector_header_address, 16,
                                    "country_scale.subject_vector_header")
        begin_raw, end_raw = vector_header[:8], vector_header[8:]
        begin, end = _u64(begin_raw), _u64(end_raw)
        raw_inputs.update({"subject_vector_header_address": hex(vector_header_address),
                           "subject_vector_header_raw_hex": vector_header.hex(),
                           "subject_vector_begin_raw_hex": begin_raw.hex(),
                           "subject_vector_end_raw_hex": end_raw.hex(),
                           "subject_vector_begin": hex(begin) if begin else None,
                           "subject_vector_end": hex(end) if end else None})
        if end < begin:
            raise _LeafFailure("subject_vector_end_before_begin")
        delta = end - begin
        if delta % 8:
            raise _LeafFailure("subject_vector_size_not_u64_aligned")
        count = delta // 8
        if count > MAX_SUBJECTS:
            raise _LeafFailure("subject_vector_count_out_of_range")
        raw_inputs["reference_count"] = count
        if count == 0:
            if begin != 0:
                _checked_pointer(begin, "empty_subject_vector")
            refs_raw = b""
        else:
            begin = _checked_pointer(begin, "subject_vector_begin")
            end_exclusive = _checked_add(begin, delta, 1, "subject_vector_end")
            if end_exclusive != end:
                raise _LeafFailure("subject_vector_range_invalid")
            refs_range = _checked_range(begin, delta, "subject_vector")
            country_range = _checked_range(country_pointer,
                                           SUBJECT_VECTOR_END_OFFSET + 8,
                                           "target_country_subject_header")
            if _overlaps(refs_range, country_range):
                raise _LeafFailure("subject_vector_country_alias")
            refs_raw = _read_exact(limiter, begin, delta,
                                   "country_scale.subject_vector_fullrefs")
        raw_inputs["subject_vector_raw_hex"] = refs_raw.hex()
        weight_address = _checked_add(base, WEIGHT_GLOBAL_RVA, 4,
                                      "subject_scale_weight_global")
        weight_raw = _read_exact(limiter, weight_address, 4,
                                 "country_scale.subject_scale_weight_i32")
        weight = _i32(weight_raw)
        raw_inputs.update({"weight_global_address": hex(weight_address),
                           "weight_raw_hex": weight_raw.hex(), "weight_i32": weight})

        included = excluded = weighted_sum = 0
        seen_country_pointers: dict[int, str] = {}
        for index in range(count):
            ref = refs_raw[index * 8:(index + 1) * 8]
            resolution = _resolve_bound_reference(
                limiter, base, ref, f"subject[{index}]")
            ref_evidence = resolution.get("raw_inputs")
            if not isinstance(ref_evidence, Mapping):
                raise _LeafFailure(f"subject_reference_evidence_missing:{index}")
            try:
                child_pointer = int(ref_evidence["country_pointer"], 0)
                child_tag = str(resolution["value"])
                child_slot = int(ref_evidence["slot"])
                canonical_ref = int(ref_evidence["canonical_fullref"], 0)
            except (KeyError, TypeError, ValueError) as exc:
                raise _LeafFailure(f"subject_reference_evidence_invalid:{index}") from exc
            if canonical_ref != _u64(ref):
                raise _LeafFailure(f"subject_reference_not_canonical:{index}")
            previous = seen_country_pointers.get(child_pointer)
            if previous is not None and previous != ref.hex():
                raise _LeafFailure(f"subject_country_pointer_alias:{index}")
            seen_country_pointers[child_pointer] = ref.hex()
            is_included, subject_evidence = _read_subject_weight(
                limiter, base, child_pointer, ref, child_tag, child_slot, raw_inputs)
            subject_evidence["country_binding"] = deepcopy(dict(resolution))
            if is_included:
                child_dev = int(subject_evidence["own_development_i32"])
                quotient = _trunc_div(child_dev * weight, DEVELOPMENT_SCALE)
                contribution = _wrap_i32(quotient)
                weighted_sum = _wrap_i32(weighted_sum + contribution)
                included += 1
                subject_evidence["weighted_development_raw"] = contribution
                subject_evidence["weighted_quotient_before_i32"] = quotient
            else:
                excluded += 1
            raw_inputs["subjects"].append(subject_evidence)

        value = {"reference_count": count,
                 "included_count": included,
                 "excluded_count": excluded,
                 "weighted_development_raw": weighted_sum,
                 "development_scale": DEVELOPMENT_SCALE,
                 "weight_raw": weight,
                 "weight_scale": DEVELOPMENT_SCALE}
        return {"status": "known", "value": value,
                "basis": "native_subject_vector_weighted_development",
                "raw_inputs": raw_inputs}
    except _LeafFailure as exc:
        return _unknown(str(exc), raw_inputs)
    except Exception as exc:
        return _unknown(f"subject_scale_read_failed:{type(exc).__name__}", raw_inputs)


def read_fields(reader: Any, base: int, binding: Mapping[str, Any],
                fields: tuple[str, ...] | list[str]) -> dict[str, dict[str, Any]]:
    """Read requested own-development and native weighted subject-scale fields.

    The target binding must come from the parent's already checked country
    resolution. This leaf rechecks its full reference against the exact DB
    slot, but does not open a process or make visibility/public-API claims.
    """
    if not isinstance(fields, (tuple, list)) or len(fields) > 16:
        return {}
    if any(not isinstance(field, str) for field in fields):
        return {}
    result: dict[str, dict[str, Any]] = {}
    seen: set[str] = set()
    for field in fields:
        if field in seen:
            result[field] = _unknown("duplicate_field_requested")
        else:
            seen.add(field)
            if field not in FIELDS:
                result[field] = _unknown("unsupported_field")
    supported = [field for field in dict.fromkeys(fields) if field in FIELDS]
    if not supported:
        return result
    try:
        module_base, country_pointer, target = _parse_target(base, binding)
    except Exception as exc:
        for field in supported:
            result[field] = _unknown(f"target_binding_invalid:{str(exc)[:120]}")
        return result

    limiter = _shared._BoundedReader(_ReaderAdapter(reader))
    try:
        target_evidence = _validate_target_binding(limiter, module_base,
                                                   country_pointer, target)
    except Exception as exc:
        reason = str(exc)[:180] or type(exc).__name__
        for field in supported:
            result[field] = _unknown(f"target_binding_unverified:{reason}")
        return result

    for field in supported:
        if field in result:  # duplicate request already diagnosed above
            continue
        if field == FIELD_DEVELOPMENT:
            result[field] = _read_development(limiter, country_pointer,
                                               target_evidence)
        else:
            result[field] = _read_subject_scale(limiter, module_base,
                                                country_pointer, target_evidence)
    return result


__all__ = ["FIELD_DEVELOPMENT", "FIELD_SUBJECT_SCALE", "FIELDS", "SCHEMA",
           "read_fields"]
