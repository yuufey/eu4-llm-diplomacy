"""Private bounded reader for one explicit FRA-target subsidy pair.

This leaf performs one bounded scan of each selected country's bilateral
subsidy vector. It does not enumerate other countries, evaluate visibility,
call native code, or claim that a nominal subsidy is currently being paid.
The copied subsidy object exposes signed native terms only; payment state,
the byte at +0x28, and the legal range of those terms remain unknown.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from . import foreign_quality_visibility_memory as _common
from .engine_dates import project_engine_date


SCHEMA = "information.bilateral_subsidies_memory.v1"
BASIS = "native_explicit_bilateral_subsidies_relation"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
PREFERRED_IMAGE_BASE = 0x140000000

SUBSIDY_CREATOR_RVA = 0x5478B0
SUBSIDY_PAIR_REGISTRATION_RVA = 0xA69610
SUBSIDY_PAIR_GETTER_RVA = 0xA69760
SUBSIDY_VTABLE_RVA = 0x1C815D8
SUBSIDY_MARKER = 0x165

SUBSIDY_RELATION_ROWS_OFFSET = 0x1510
SUBSIDY_ROW_STRIDE = 0x48
SUBSIDY_ROW_SIZE = 0x18
SUBSIDY_ROW_OWNER_OFFSET = 0x00
SUBSIDY_ROW_SELF_FULLREF_OFFSET = 0x08
SUBSIDY_ROW_OTHER_FULLREF_OFFSET = 0x10
SUBSIDY_ROW_OWNER_COUNTRY_OFFSET = 0x14F8

OWNER_SUBSIDY_VECTOR_OFFSET = 0x108
VECTOR_DATA_OFFSET = 0x08
VECTOR_CAPACITY_OFFSET = 0x10
VECTOR_COUNT_OFFSET = 0x14
VECTOR_HEADER_SIZE = 0x10
VECTOR_ITEM_STRIDE = 0x10
VECTOR_ITEM_SLOT_OFFSET = 0x00
VECTOR_ITEM_POINTER_OFFSET = 0x08

SUBSIDY_OBJECT_SIZE = 0x48
SUBSIDY_PAYER_OFFSET = 0x10
SUBSIDY_RECIPIENT_OFFSET = 0x18
SUBSIDY_START_DATE_OFFSET = 0x20
SUBSIDY_FLAG_0X28_OFFSET = 0x28
SUBSIDY_MONTHLY_AMOUNT_OFFSET = 0x40
SUBSIDY_DURATION_YEARS_OFFSET = 0x44
SUBSIDY_START_DATE_SENTINEL = 0x029C77F8
TICKS_PER_SUBSIDY_YEAR = 0x2238  # 8760 hours, confirmed by the native tooltip composer.

MAX_RELATION_SLOTS = _common.MAX_COUNTRY_SLOTS
MAX_VECTOR_ITEMS = 4096
MAX_SINGLE_READ_BYTES = 1024
MAX_TOTAL_READ_BYTES = 160 * 1024
MAX_READ_CALLS = 256
VECTOR_CHUNK_BYTES = 1024
UINT32_MASK = 0xFFFFFFFF
INT32_SIGN = 0x80000000
UINT32_MODULUS = 0x100000000
INT32_MIN = -(1 << 31)
INT32_MAX = (1 << 31) - 1

ORDINARY_HELPER_REPORT_PATH = (
    "work/runtime/information-subsidies-contracts-20261031-001/"
    "ordinary-subsidy-getters-001/ordinary-subsidy-getters-002.json"
)
ORDINARY_HELPER_REPORT_SHA256 = "c4a0be08aeb8d1aebe09b4e9237f7a0e7cbf9a8994f346fbbbcede6037fe231a"

_STATIC_EVIDENCE = {
    "executable_sha256": EXPECTED_EXE_SHA256,
    "preferred_image_base": hex(PREFERRED_IMAGE_BASE),
    "creator": {
        "evidence_id": "ev_0d4ad3e7b134ed16ff1fba2aeae999e7b8bdc5fddc0852b5954d0a9e50175fcf",
        "rva": hex(SUBSIDY_CREATOR_RVA),
        "alloc_size": hex(SUBSIDY_OBJECT_SIZE),
        "object_vtable_rva": hex(SUBSIDY_VTABLE_RVA),
        "marker": SUBSIDY_MARKER,
    },
    "pair_registration": {
        "evidence_id": "ev_96dc841d58d5bb9cae01f27a3f80a1ce24253fb87c9baafbfc602d74837a5cde",
        "rva": hex(SUBSIDY_PAIR_REGISTRATION_RVA),
        "row_owner_vector_offset": hex(OWNER_SUBSIDY_VECTOR_OFFSET),
    },
    "pair_lookup_getter": {
        "evidence_id": "ev_7f5215a6ec29b98bd9e4806aebf1e8330e12d3c344a3aad4ac6b668711295e99",
        "rva": hex(SUBSIDY_PAIR_GETTER_RVA),
        "role": "slot_lookup_getter; this leaf scans copied bytes and does not call it",
        "vector_item_stride": hex(VECTOR_ITEM_STRIDE),
    },
    "bounded_helper_report": {
        "path": ORDINARY_HELPER_REPORT_PATH,
        "sha256": ORDINARY_HELPER_REPORT_SHA256,
        "duration_value_rva": "0x00862830",
        "date_value_rva": "0x00129280",
        "amount_value_rva": "0x00730000",
        "tooltip_date_composition_rva": "0x000cf4c0",
        "annual_hour_multiplier": TICKS_PER_SUBSIDY_YEAR,
        "helpers_followed_at_runtime": False,
    },
    "object_fields": {
        "payer_fullref": hex(SUBSIDY_PAYER_OFFSET),
        "recipient_fullref": hex(SUBSIDY_RECIPIENT_OFFSET),
        "start_date_i32": hex(SUBSIDY_START_DATE_OFFSET),
        "uninterpreted_flag": hex(SUBSIDY_FLAG_0X28_OFFSET),
        "monthly_amount_i32": hex(SUBSIDY_MONTHLY_AMOUNT_OFFSET),
        "duration_years_i32": hex(SUBSIDY_DURATION_YEARS_OFFSET),
    },
}


class _Unknown(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _checked_add(address: int, offset: int, size: int = 1) -> int:
    try:
        return _common._checked_add(address, offset, size)
    except Exception as exc:
        raise _Unknown("ADDRESS_INVALID") from exc


def _pointer(value: Any, label: str, *, alignment: int = 8,
             allow_null: bool = False) -> int:
    try:
        return _common._pointer(value, label, alignment=alignment,
                                allow_null=allow_null)
    except Exception as exc:
        reason = getattr(exc, "reason", None)
        raise _Unknown(reason if isinstance(reason, str) else f"{label}_POINTER_INVALID") from exc


def _parse_binding(value: Any, label: str) -> dict[str, Any]:
    try:
        return _common._parse_binding(value, label)
    except Exception as exc:
        reason = getattr(exc, "reason", None)
        raise _Unknown(reason if isinstance(reason, str) else f"{label.upper()}_BINDING_INVALID") from exc


class _Trace:
    """Ordered exact reads with per-read, call-count, and total-byte limits."""

    def __init__(self, reader: Any):
        method = getattr(reader, "read", None)
        self._read = method if callable(method) else reader if callable(reader) else None
        self.reads: list[dict[str, Any]] = []
        self.calls = 0
        self.bytes_requested = 0

    def exact(self, address: int, size: int, label: str) -> bytes:
        if self._read is None:
            raise _Unknown("READER_INVALID")
        address = _checked_add(address, 0, size)
        if type(size) is not int or not 0 < size <= MAX_SINGLE_READ_BYTES:
            raise _Unknown(f"SINGLE_READ_LIMIT:{label}")
        if (self.calls + 1 > MAX_READ_CALLS
                or self.bytes_requested + size > MAX_TOTAL_READ_BYTES):
            self.reads.append({
                "ordinal": self.calls + 1, "address": hex(address), "size": size,
                "label": label, "status": "rejected", "reason": "READ_BUDGET_EXCEEDED",
            })
            raise _Unknown("READ_BUDGET_EXCEEDED")
        self.calls += 1
        self.bytes_requested += size
        entry: dict[str, Any] = {
            "ordinal": self.calls, "address": hex(address), "size": size,
            "label": label, "pointer_checked": True, "status": "requested",
        }
        self.reads.append(entry)
        try:
            raw = self._read(address, size, label)
        except Exception as exc:
            entry.update({"status": "failed", "error_type": type(exc).__name__})
            raise _Unknown(f"READ_FAILED:{label}") from exc
        if not isinstance(raw, (bytes, bytearray, memoryview)) or len(raw) != size:
            entry.update({"status": "failed", "error_type": "SHORT_OR_INVALID_READ"})
            raise _Unknown(f"READ_FAILED:{label}")
        data = bytes(raw)
        entry.update({"status": "ok", "raw_hex": data.hex()})
        return data

    def u64(self, address: int, label: str) -> int:
        value = int.from_bytes(self.exact(address, 8, label), "little", signed=False)
        self.reads[-1].update({"decode": "u64", "value": hex(value)})
        return value

    def i32(self, address: int, label: str) -> int:
        value = int.from_bytes(self.exact(address, 4, label), "little", signed=True)
        self.reads[-1].update({"decode": "i32", "value": value})
        return value

    def summary(self) -> dict[str, int]:
        return {
            "calls": self.calls,
            "bytes_requested": self.bytes_requested,
            "max_calls": MAX_READ_CALLS,
            "max_bytes": MAX_TOTAL_READ_BYTES,
            "max_single_read_bytes": MAX_SINGLE_READ_BYTES,
            "max_vector_items": MAX_VECTOR_ITEMS,
            "vector_chunk_bytes": VECTOR_CHUNK_BYTES,
        }


def _pair_echo(trace: _Trace, binding: Mapping[str, Any], role: str) -> None:
    address = _checked_add(binding["country_pointer"], _common.COUNTRY_FULLREF_OFFSET, 8)
    actual = trace.u64(address, f"binding.{role}.fullref_echo")
    if actual != binding["fullref"]:
        raise _Unknown(f"{role.upper()}_FULLREF_ECHO_MISMATCH")


def _signed16_from_fullref(fullref: int) -> int:
    raw = (fullref >> 32) & 0xFFFF
    return raw - 0x10000 if raw & 0x8000 else raw


def _read_pair_row(trace: _Trace, subject: Mapping[str, Any],
                   other: Mapping[str, Any], label: str) -> dict[str, Any]:
    if subject["slot"] >= MAX_RELATION_SLOTS or other["slot"] >= MAX_RELATION_SLOTS:
        raise _Unknown("COUNTRY_RELATION_SLOT_UNSUPPORTED")
    rows_cell = _checked_add(subject["country_pointer"], SUBSIDY_RELATION_ROWS_OFFSET, 8)
    rows_pointer = _pointer(trace.u64(rows_cell, f"pair.{label}.rows_pointer"),
                            f"{label.upper()}_ROWS")
    row_address = _checked_add(rows_pointer, other["slot"] * SUBSIDY_ROW_STRIDE,
                               SUBSIDY_ROW_SIZE)
    raw = trace.exact(row_address, SUBSIDY_ROW_SIZE, f"pair.{label}.row")
    owner_raw = int.from_bytes(raw[SUBSIDY_ROW_OWNER_OFFSET:SUBSIDY_ROW_OWNER_OFFSET + 8],
                               "little", signed=False)
    self_ref = int.from_bytes(raw[SUBSIDY_ROW_SELF_FULLREF_OFFSET:
                                  SUBSIDY_ROW_SELF_FULLREF_OFFSET + 8], "little", signed=False)
    other_ref = int.from_bytes(raw[SUBSIDY_ROW_OTHER_FULLREF_OFFSET:
                                   SUBSIDY_ROW_OTHER_FULLREF_OFFSET + 8], "little", signed=False)
    owner = _pointer(owner_raw, f"{label.upper()}_ROW_OWNER")
    expected_owner = _checked_add(subject["country_pointer"], SUBSIDY_ROW_OWNER_COUNTRY_OFFSET)
    other_slot_signed16 = _signed16_from_fullref(other_ref)
    trace.reads[-1].update({
        "decode": "subsidy_pair_row",
        "owner": hex(owner), "expected_owner": hex(expected_owner),
        "self_fullref": hex(self_ref), "other_fullref": hex(other_ref),
        "other_slot_signed16": other_slot_signed16,
    })
    if owner != expected_owner:
        raise _Unknown(f"{label.upper()}_ROW_OWNER_MISMATCH")
    if self_ref != subject["fullref"] or other_ref != other["fullref"]:
        raise _Unknown(f"{label.upper()}_ROW_FULLREF_MISMATCH")
    if other_slot_signed16 != other["slot"]:
        raise _Unknown(f"{label.upper()}_ROW_OTHER_SLOT_MISMATCH")
    return {
        "label": label,
        "rows_pointer": rows_pointer,
        "row_address": row_address,
        "raw": raw,
        "owner": owner,
        "self_fullref": self_ref,
        "other_fullref": other_ref,
        "other_slot_signed16": other_slot_signed16,
    }


def _scan_owner_vector(trace: _Trace, row: Mapping[str, Any],
                       label: str) -> dict[str, Any]:
    owner = row["owner"]
    vector_base = _checked_add(owner, OWNER_SUBSIDY_VECTOR_OFFSET, VECTOR_HEADER_SIZE)
    header_address = _checked_add(vector_base, VECTOR_DATA_OFFSET, VECTOR_HEADER_SIZE)
    header = trace.exact(header_address, VECTOR_HEADER_SIZE,
                         f"pair.{label}.vector_header")
    data_raw = int.from_bytes(header[0:8], "little", signed=False)
    capacity = int.from_bytes(header[8:12], "little", signed=True)
    count = int.from_bytes(header[12:16], "little", signed=True)
    trace.reads[-1].update({
        "decode": "vector_header",
        "vector_base": hex(vector_base), "data_pointer": hex(data_raw),
        "capacity": capacity, "count": count,
    })
    if (capacity < 0 or count < 0 or capacity > MAX_VECTOR_ITEMS
            or count > MAX_VECTOR_ITEMS or count > capacity):
        raise _Unknown(f"{label.upper()}_VECTOR_BOUNDS_INVALID")
    if data_raw == 0:
        if capacity != 0 or count != 0:
            raise _Unknown(f"{label.upper()}_VECTOR_NULL_DATA_INCONSISTENT")
        data_pointer = 0
    else:
        data_pointer = _pointer(data_raw, f"{label.upper()}_VECTOR_DATA")
        if capacity == 0:
            raise _Unknown(f"{label.upper()}_VECTOR_CAPACITY_INVALID")

    target_slot = row["other_slot_signed16"]
    seen_slots: set[int] = set()
    match_count = 0
    target_pointer: int | None = None
    bytes_read = 0
    byte_count = count * VECTOR_ITEM_STRIDE
    if byte_count:
        _checked_add(data_pointer, 0, byte_count)
    while bytes_read < byte_count:
        chunk_size = min(VECTOR_CHUNK_BYTES, byte_count - bytes_read)
        if chunk_size % VECTOR_ITEM_STRIDE:
            raise _Unknown(f"{label.upper()}_VECTOR_CHUNK_INVALID")
        chunk_address = _checked_add(data_pointer, bytes_read, chunk_size)
        first_item = bytes_read // VECTOR_ITEM_STRIDE
        after_item = first_item + chunk_size // VECTOR_ITEM_STRIDE
        chunk = trace.exact(chunk_address, chunk_size,
                            f"pair.{label}.items[{first_item}:{after_item}]")
        trace.reads[-1]["item_count"] = chunk_size // VECTOR_ITEM_STRIDE
        for offset in range(0, chunk_size, VECTOR_ITEM_STRIDE):
            slot = int.from_bytes(chunk[offset + VECTOR_ITEM_SLOT_OFFSET:
                                         offset + VECTOR_ITEM_SLOT_OFFSET + 4],
                                  "little", signed=True)
            candidate_raw = int.from_bytes(
                chunk[offset + VECTOR_ITEM_POINTER_OFFSET:
                      offset + VECTOR_ITEM_POINTER_OFFSET + 8],
                "little", signed=False)
            if not 0 <= slot < MAX_RELATION_SLOTS:
                raise _Unknown(f"{label.upper()}_VECTOR_SLOT_INVALID")
            if slot in seen_slots:
                raise _Unknown(f"{label.upper()}_VECTOR_DUPLICATE_SLOT")
            seen_slots.add(slot)
            candidate = _pointer(candidate_raw, f"{label.upper()}_VECTOR_ITEM")
            if slot == target_slot:
                match_count += 1
                target_pointer = candidate
        bytes_read += chunk_size
    if match_count > 1:
        raise _Unknown(f"{label.upper()}_VECTOR_DUPLICATE_TARGET")
    return {
        "label": label,
        "row_address": hex(row["row_address"]),
        "owner": hex(owner),
        "vector_base": hex(vector_base),
        "data_pointer": hex(data_pointer),
        "capacity": capacity,
        "count": count,
        "target_slot_signed16": target_slot,
        "target_match_count": match_count,
        "target_pointer": hex(target_pointer) if target_pointer is not None else None,
    }


def _decode_subsidy_object(trace: _Trace, module_base: int, object_pointer: int,
                           observer: Mapping[str, Any],
                           target: Mapping[str, Any]) -> dict[str, Any]:
    object_pointer = _pointer(object_pointer, "SUBSIDY_RELATION")
    raw = trace.exact(object_pointer, SUBSIDY_OBJECT_SIZE, "contract.relation_object")
    vtable = int.from_bytes(raw[0:8], "little", signed=False)
    marker = int.from_bytes(raw[8:12], "little", signed=False)
    payer = int.from_bytes(raw[SUBSIDY_PAYER_OFFSET:SUBSIDY_PAYER_OFFSET + 8],
                           "little", signed=False)
    recipient = int.from_bytes(raw[SUBSIDY_RECIPIENT_OFFSET:SUBSIDY_RECIPIENT_OFFSET + 8],
                               "little", signed=False)
    start = int.from_bytes(raw[SUBSIDY_START_DATE_OFFSET:SUBSIDY_START_DATE_OFFSET + 4],
                           "little", signed=True)
    amount = int.from_bytes(raw[SUBSIDY_MONTHLY_AMOUNT_OFFSET:
                                SUBSIDY_MONTHLY_AMOUNT_OFFSET + 4], "little", signed=True)
    duration = int.from_bytes(raw[SUBSIDY_DURATION_YEARS_OFFSET:
                                  SUBSIDY_DURATION_YEARS_OFFSET + 4], "little", signed=True)
    expected_vtable = _pointer(_checked_add(module_base, SUBSIDY_VTABLE_RVA, 1),
                               "SUBSIDY_VTABLE")
    trace.reads[-1].update({
        "decode": "subsidy_relation_object",
        "vtable": hex(vtable), "marker": marker,
        "payer_fullref": hex(payer), "recipient_fullref": hex(recipient),
        "start_date_raw_i32": start, "monthly_amount_raw_i32": amount,
        "duration_years_raw_i32": duration,
        "flag_0x28": {"status": "unknown", "reason": "SUBSIDY_FLAG_0X28_SEMANTICS_UNCLOSED"},
    })
    if vtable != expected_vtable:
        raise _Unknown("SUBSIDY_VTABLE_MISMATCH")
    if marker != SUBSIDY_MARKER:
        raise _Unknown("SUBSIDY_MARKER_MISMATCH")
    if (payer, recipient) not in {
            (observer["fullref"], target["fullref"]),
            (target["fullref"], observer["fullref"]),
    }:
        raise _Unknown("SUBSIDY_PARTY_FULLREF_MISMATCH")
    if start == SUBSIDY_START_DATE_SENTINEL:
        raise _Unknown("SUBSIDY_START_DATE_SENTINEL")
    return {
        "pointer": object_pointer,
        "vtable": vtable,
        "marker": marker,
        "payer": payer,
        "recipient": recipient,
        "start_date_raw": start,
        "monthly_amount_raw": amount,
        "duration_years_raw": duration,
    }


def _signed32(value: int) -> int:
    value &= UINT32_MASK
    return value - UINT32_MODULUS if value & INT32_SIGN else value


def _party(binding: Mapping[str, Any], fullref: int) -> dict[str, Any]:
    return {
        "tag": binding["tag"],
        "fullref": hex(fullref),
        "fullref_raw_hex": fullref.to_bytes(8, "little", signed=False).hex(),
    }


def _public_contract(decoded: Mapping[str, Any], observer: Mapping[str, Any],
                     target: Mapping[str, Any]) -> dict[str, Any]:
    payer = decoded["payer"]
    recipient = decoded["recipient"]
    payer_binding = observer if payer == observer["fullref"] else target
    recipient_binding = observer if recipient == observer["fullref"] else target
    duration = decoded["duration_years_raw"]
    start = decoded["start_date_raw"]
    product_raw = _signed32(duration * TICKS_PER_SUBSIDY_YEAR)
    displayed_end_raw = _signed32(start + product_raw)
    return {
        "status": "known",
        "present": True,
        "scope": "explicit_observer_target_pair_only",
        "payer": _party(payer_binding, payer),
        "recipient": _party(recipient_binding, recipient),
        "observer_role": "payer" if payer == observer["fullref"] else "recipient",
        "monthly_nominal_amount": {
            "raw": decoded["monthly_amount_raw"],
            "value": decoded["monthly_amount_raw"] / 1000.0,
            "unit": "ducats", "scale": 1000, "period": "month",
            "basis": "native_subsidy_object_monthly_amount",
        },
        "start_date": {
            "raw": start, "raw_hex": start.to_bytes(4, "little", signed=True).hex(),
            "unit": "eu4_hour_tick", "scale": 1,
            "calendar": project_engine_date(start),
        },
        "duration_years": {
            "raw": duration,
            "raw_hex": duration.to_bytes(4, "little", signed=True).hex(),
            "unit": "years", "scale": 1,
        },
        "displayed_end_date": {
            "raw": displayed_end_raw,
            "raw_hex": displayed_end_raw.to_bytes(4, "little", signed=True).hex(),
            "unit": "eu4_hour_tick", "scale": 1,
            "calendar": project_engine_date(displayed_end_raw),
            "derivation": {
                "status": "derived_from_native_tooltip_date_composition",
                "formula": "signed32_wrap(start_raw + signed32_wrap(duration_years_raw * 8760))",
                "duration_product_raw_i32": product_raw,
                "ticks_per_subsidy_year": TICKS_PER_SUBSIDY_YEAR,
                "intermediate_and_final_wrap": "low_32_bits_interpreted_as_signed_i32",
                "static_evidence_id": "ev_e0253c163eeb06480ec3c8f15e82a5a8530c3ca7676d03f6fc30a0bbc84ef581",
            },
        },
        "active_payment_obligation": {
            "status": "unknown", "reason": "SUBSIDY_PAYMENT_OBLIGATION_SEMANTICS_NOT_CAPTURED",
        },
        "relation_flag_0x28": {
            "status": "unknown", "reason": "SUBSIDY_FLAG_0X28_SEMANTICS_UNCLOSED",
        },
        "term_legality": {
            "status": "unknown", "reason": "SUBSIDY_AMOUNT_OR_DURATION_LEGALITY_NOT_CAPTURED",
        },
    }


def _recheck_pair(trace: _Trace, row: Mapping[str, Any]) -> None:
    label = row["label"]
    subject_pointer = row["subject_pointer"]
    rows_cell = _checked_add(subject_pointer, SUBSIDY_RELATION_ROWS_OFFSET, 8)
    rows_after = _pointer(trace.u64(rows_cell, f"pair.{label}.rows_pointer_after"),
                          f"{label.upper()}_ROWS_AFTER")
    if rows_after != row["rows_pointer"]:
        raise _Unknown(f"{label.upper()}_ROWS_POINTER_CHANGED")
    raw_after = trace.exact(row["row_address"], SUBSIDY_ROW_SIZE,
                            f"pair.{label}.row_after")
    owner = int.from_bytes(raw_after[SUBSIDY_ROW_OWNER_OFFSET:
                                     SUBSIDY_ROW_OWNER_OFFSET + 8], "little", signed=False)
    self_ref = int.from_bytes(raw_after[SUBSIDY_ROW_SELF_FULLREF_OFFSET:
                                        SUBSIDY_ROW_SELF_FULLREF_OFFSET + 8], "little", signed=False)
    other_ref = int.from_bytes(raw_after[SUBSIDY_ROW_OTHER_FULLREF_OFFSET:
                                         SUBSIDY_ROW_OTHER_FULLREF_OFFSET + 8], "little", signed=False)
    trace.reads[-1].update({
        "decode": "subsidy_pair_row_recheck",
        "owner": hex(owner), "self_fullref": hex(self_ref), "other_fullref": hex(other_ref),
    })
    if raw_after != row["raw"]:
        raise _Unknown(f"{label.upper()}_ROW_CHANGED_AFTER_VECTOR_READ")


def _empty_result(reason: str, trace: _Trace, raw_inputs: Mapping[str, Any],
                  observed_pair: Mapping[str, Any] | None = None) -> dict[str, Any]:
    inputs = deepcopy(dict(raw_inputs))
    inputs["ordered_read_trace"] = deepcopy(trace.reads)
    inputs["read_budget"] = trace.summary()
    return {
        "schema": SCHEMA,
        "status": "unknown",
        "reason": reason,
        "basis": BASIS,
        "partial": True,
        "complete": False,
        "observed_pair": deepcopy(dict(observed_pair)) if observed_pair is not None else None,
        "contract": {"status": "unknown", "reason": reason},
        "complete_country_contracts": False,
        "visibility_evaluated": False,
        "raw_inputs": inputs,
    }


def read_state(reader: Any, module_base: Any, observer_binding: Any,
               target_binding: Any, *, logical_observer="FRA") -> dict[str, Any]:
    """Read the explicitly selected FRA/target subsidy pair once and fail closed.

    ``status=known`` describes a bounded, single-pass observation of this pair.
    It does not establish visibility, actual payment, payment obligations, or
    that the target has no subsidies involving other countries.
    """
    trace = _Trace(reader)
    raw_inputs: dict[str, Any] = {
        "module_base": None,
        "static_evidence": deepcopy(_STATIC_EVIDENCE),
        "country_relation_rows_offset": hex(SUBSIDY_RELATION_ROWS_OFFSET),
        "country_relation_row_stride": hex(SUBSIDY_ROW_STRIDE),
        "country_relation_row_owner_offset": hex(SUBSIDY_ROW_OWNER_COUNTRY_OFFSET),
        "owner_pair_vector_offset": hex(OWNER_SUBSIDY_VECTOR_OFFSET),
        "vector_data_offset": hex(VECTOR_DATA_OFFSET),
        "vector_capacity_offset": hex(VECTOR_CAPACITY_OFFSET),
        "vector_count_offset": hex(VECTOR_COUNT_OFFSET),
        "vector_item_stride": hex(VECTOR_ITEM_STRIDE),
        "atomic_snapshot": False,
        "visibility_evaluated": False,
    }
    observed_pair: dict[str, Any] | None = None
    try:
        base = _pointer(module_base, "MODULE_BASE", alignment=0x1000)
        observer = _parse_binding(observer_binding, "observer")
        target = _parse_binding(target_binding, "target")
        if observer["tag"] != logical_observer:
            raise _Unknown("OBSERVER_MUST_BE_FRA" if logical_observer == "FRA" else "OBSERVER_BINDING_MISMATCH")
        if target["tag"] == logical_observer:
            raise _Unknown("TARGET_MUST_DIFFER_FROM_FRA" if logical_observer == "FRA" else "FOREIGN_TARGET_REQUIRED")
        if (observer["country_pointer"] == target["country_pointer"]
                or observer["slot"] == target["slot"]
                or observer["fullref"] == target["fullref"]):
            raise _Unknown("BILATERAL_BINDINGS_ALIAS")
        if (observer["slot"] >= MAX_RELATION_SLOTS
                or target["slot"] >= MAX_RELATION_SLOTS):
            raise _Unknown("COUNTRY_RELATION_SLOT_UNSUPPORTED")

        raw_inputs["module_base"] = hex(base)
        raw_inputs["bindings"] = {
            role: {
                "tag": binding["tag"], "slot": binding["slot"],
                "country_pointer": hex(binding["country_pointer"]),
                "fullref": hex(binding["fullref"]),
                "fullref_raw_hex": binding["fullref_raw_hex"],
            }
            for role, binding in (("observer", observer), ("target", target))
        }
        observed_pair = {
            "observer": deepcopy(raw_inputs["bindings"]["observer"]),
            "target": deepcopy(raw_inputs["bindings"]["target"]),
            "fullref_echo_verified": False,
        }

        # Bind and validate both relation rows completely before touching either
        # owner vector. This keeps row/owner/ref errors from causing vector reads.
        _pair_echo(trace, observer, "observer")
        _pair_echo(trace, target, "target")
        forward = _read_pair_row(trace, observer, target, "observer_to_target")
        reverse = _read_pair_row(trace, target, observer, "target_to_observer")
        forward["subject_pointer"] = observer["country_pointer"]
        reverse["subject_pointer"] = target["country_pointer"]
        raw_inputs["pair_directions"] = [
            {key: (hex(value) if type(value) is int else value)
             for key, value in row.items() if key != "raw"}
            for row in (forward, reverse)
        ]

        forward_vector = _scan_owner_vector(trace, forward, "observer_to_target")
        reverse_vector = _scan_owner_vector(trace, reverse, "target_to_observer")
        raw_inputs["owner_vectors"] = [forward_vector, reverse_vector]
        forward_pointer = forward_vector["target_pointer"]
        reverse_pointer = reverse_vector["target_pointer"]
        if forward_pointer is None and reverse_pointer is None:
            contract: dict[str, Any] = {
                "status": "absent",
                "present": False,
                "scope": "explicit_observer_target_pair_only",
                "reason": "NO_MATCHING_PAIR_ENTRY",
                "active_payment_obligation": {
                    "status": "unknown",
                    "reason": "SUBSIDY_PAYMENT_OBLIGATION_SEMANTICS_NOT_CAPTURED",
                },
                "relation_flag_0x28": {
                    "status": "unknown", "reason": "SUBSIDY_FLAG_0X28_SEMANTICS_UNCLOSED",
                },
            }
        elif forward_pointer is None or reverse_pointer is None:
            raise _Unknown("ASYMMETRIC_PAIR_SUBSIDY")
        elif forward_pointer != reverse_pointer:
            raise _Unknown("BILATERAL_SUBSIDY_POINTER_MISMATCH")
        else:
            decoded = _decode_subsidy_object(trace, base, int(forward_pointer, 16),
                                             observer, target)
            contract = _public_contract(decoded, observer, target)

        # The vectors are read once. Recheck both country refs, table pointers,
        # and pair-row bytes before returning a known present/absent result.
        _pair_echo(trace, observer, "observer_after")
        _pair_echo(trace, target, "target_after")
        _recheck_pair(trace, forward)
        _recheck_pair(trace, reverse)
        observed_pair["fullref_echo_verified"] = True
        return {
            "schema": SCHEMA,
            "status": "known",
            "basis": BASIS,
            "partial": True,
            "complete": False,
            "observed_pair": observed_pair,
            "contract": contract,
            "complete_country_contracts": False,
            "visibility_evaluated": False,
            "raw_inputs": {
                **raw_inputs,
                "ordered_read_trace": deepcopy(trace.reads),
                "read_budget": trace.summary(),
            },
        }
    except _Unknown as exc:
        return _empty_result(exc.reason, trace, raw_inputs, observed_pair)
    except Exception as exc:
        return _empty_result(f"INTERNAL_READ_ERROR:{type(exc).__name__}",
                             trace, raw_inputs, observed_pair)


__all__ = ["SCHEMA", "BASIS", "EXPECTED_EXE_SHA256", "PREFERRED_IMAGE_BASE", "read_state"]
