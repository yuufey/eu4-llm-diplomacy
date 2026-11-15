"""Private bounded reader for one explicit FRA-country reparations pair.

This leaf reads only the selected observer/target pair from the current
country relation rows. It does not enumerate country contracts, determine F03
visibility, read the payment amount or percentage, or assign semantics to the
relation byte at +0x28. The parent must independently enforce session identity,
country-view and page visibility before publishing any result.

Static basis: EU4 1.37.4, B23 EXE SHA-256
``b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77``.
The retained REA creator (RVA 0x9b6270) establishes the treaty vtable and
party/date fields. The retained pair-registration/mutator evidence (RVA
0xa68c40 -> 0x28d840) establishes the owner+0x90 vector path. The pair lookup
function is a mutator, so this module searches copied vector bytes and never
calls it or any game function.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from . import foreign_quality_visibility_memory as _common
from .engine_dates import project_engine_date


SCHEMA = "information.bilateral_reparations_memory.v1"
BASIS = "native_explicit_bilateral_reparations_relation"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
PREFERRED_IMAGE_BASE = 0x140000000

CREATOR_RVA = 0x9B6270
PAIR_REGISTRATION_RVA = 0xA68C40
PAIR_LOOKUP_MUTATOR_RVA = 0x28D840
RELATION_TABLE_RVA = 0x1CDDEE0
RELATION_MARKER = 0x165

CREATOR_EVIDENCE_ID = "ev_fbbb21b5017abc29d6c58554f7cd5954d171734307d22a5d5f40479fe02ecb36"
PAIR_REGISTRATION_EVIDENCE_ID = "ev_aa53d3b0caea525bed6ebf330d42b2f3d908dad295cb4a45dc578a803089260f"
PAIR_LOOKUP_EVIDENCE_ID = "ev_75bda2678ecc401746d567d959db6ebd0b99f0abf0d2615779cfa1c40d1982ae"

COUNTRY_FULLREF_OFFSET = _common.COUNTRY_FULLREF_OFFSET
COUNTRY_RELATION_ROWS_OFFSET = 0x1510
PAIR_ROW_STRIDE = 0x48
PAIR_ROW_SIZE = 0x18
PAIR_OWNER_OFFSET = 0x00
PAIR_SELF_FULLREF_OFFSET = 0x08
PAIR_OTHER_FULLREF_OFFSET = 0x10

OWNER_PAIR_VECTOR_OFFSET = 0x90
VECTOR_DATA_OFFSET = 0x08
VECTOR_CAPACITY_OFFSET = 0x10
VECTOR_COUNT_OFFSET = 0x14
VECTOR_HEADER_SIZE = 0x18
VECTOR_ITEM_STRIDE = 0x10
VECTOR_ITEM_SLOT_OFFSET = 0x00
VECTOR_ITEM_POINTER_OFFSET = 0x08

RELATION_OBJECT_MIN_SIZE = 0x28
RELATION_PAYER_OFFSET = 0x10
RELATION_CLAIMANT_OFFSET = 0x18
RELATION_START_DATE_OFFSET = 0x20
RELATION_END_DATE_OFFSET = 0x24

MAX_RELATION_SLOTS = _common.MAX_COUNTRY_SLOTS
MAX_VECTOR_ITEMS = 4096
MAX_SINGLE_READ_BYTES = 1024
MAX_TOTAL_READ_BYTES = 160 * 1024
MAX_READ_CALLS = 256
VECTOR_CHUNK_BYTES = 1024
INT32_MIN = -(1 << 31)
INT32_MAX = (1 << 31) - 1

_STATIC_EVIDENCE = {
    "executable_sha256": EXPECTED_EXE_SHA256,
    "preferred_image_base": hex(PREFERRED_IMAGE_BASE),
    "creator": {
        "evidence_id": CREATOR_EVIDENCE_ID,
        "va": "0x1409b6270",
        "rva": hex(CREATOR_RVA),
    },
    "pair_registration": {
        "evidence_id": PAIR_REGISTRATION_EVIDENCE_ID,
        "va": "0x140a68c40",
        "rva": hex(PAIR_REGISTRATION_RVA),
    },
    "pair_lookup_mutator": {
        "evidence_id": PAIR_LOOKUP_EVIDENCE_ID,
        "va": "0x14028d840",
        "rva": hex(PAIR_LOOKUP_MUTATOR_RVA),
        "role": "insert_or_remove_mutator_not_getter",
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
    """Ordered exact-read trace with bounded size, calls and user addresses."""

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

    def u32(self, address: int, label: str) -> int:
        value = int.from_bytes(self.exact(address, 4, label), "little", signed=False)
        self.reads[-1].update({"decode": "u32", "value": value})
        return value

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
            "vector_chunk_bytes": VECTOR_CHUNK_BYTES,
        }


def _pair_echo(trace: _Trace, binding: Mapping[str, Any], role: str) -> None:
    address = _checked_add(binding["country_pointer"], COUNTRY_FULLREF_OFFSET, 8)
    actual = trace.u64(address, f"binding.{role}.fullref_echo")
    if actual != binding["fullref"]:
        raise _Unknown(f"{role.upper()}_FULLREF_ECHO_MISMATCH")


def _row_vector(trace: _Trace, subject: Mapping[str, Any],
                other: Mapping[str, Any], label: str) -> dict[str, Any]:
    if subject["slot"] >= MAX_RELATION_SLOTS or other["slot"] >= MAX_RELATION_SLOTS:
        raise _Unknown("COUNTRY_RELATION_SLOT_UNSUPPORTED")
    country_rows_cell = _checked_add(subject["country_pointer"],
                                     COUNTRY_RELATION_ROWS_OFFSET, 8)
    rows_pointer = _pointer(trace.u64(country_rows_cell, f"pair.{label}.rows_pointer"),
                            f"{label.upper()}_ROWS")
    row_offset = other["slot"] * PAIR_ROW_STRIDE
    row_address = _checked_add(rows_pointer, row_offset, PAIR_ROW_SIZE)
    row = trace.exact(row_address, PAIR_ROW_SIZE, f"pair.{label}.row")
    owner_raw = int.from_bytes(row[PAIR_OWNER_OFFSET:PAIR_OWNER_OFFSET + 8], "little")
    self_ref = int.from_bytes(row[PAIR_SELF_FULLREF_OFFSET:PAIR_SELF_FULLREF_OFFSET + 8], "little")
    other_ref = int.from_bytes(row[PAIR_OTHER_FULLREF_OFFSET:PAIR_OTHER_FULLREF_OFFSET + 8], "little")
    owner = _pointer(owner_raw, f"{label.upper()}_ROW_OWNER")
    trace.reads[-1].update({
        "decode": "pair_row",
        "owner": hex(owner),
        "self_fullref": hex(self_ref),
        "other_fullref": hex(other_ref),
    })
    if self_ref != subject["fullref"] or other_ref != other["fullref"]:
        raise _Unknown(f"{label.upper()}_ROW_FULLREF_MISMATCH")

    vector_address = _checked_add(owner, OWNER_PAIR_VECTOR_OFFSET, VECTOR_HEADER_SIZE)
    header_address = _checked_add(vector_address, VECTOR_DATA_OFFSET, 16)
    header = trace.exact(header_address, 16,
                         f"pair.{label}.vector_header")
    data_raw = int.from_bytes(header[0:8], "little", signed=False)
    capacity = int.from_bytes(header[8:12], "little", signed=True)
    count = int.from_bytes(header[12:16], "little", signed=True)
    trace.reads[-1].update({
        "decode": "vector_header",
        "data_pointer": hex(data_raw),
        "capacity": capacity,
        "count": count,
    })
    if (capacity < 0 or count < 0 or capacity > MAX_VECTOR_ITEMS
            or count > MAX_VECTOR_ITEMS or count > capacity):
        raise _Unknown(f"{label.upper()}_VECTOR_BOUNDS_INVALID")
    if data_raw == 0:
        if capacity != 0 or count != 0:
            raise _Unknown(f"{label.upper()}_VECTOR_POINTER_INVALID")
        data_pointer = 0
    else:
        data_pointer = _pointer(data_raw, f"{label.upper()}_VECTOR_DATA")
        if capacity == 0:
            raise _Unknown(f"{label.upper()}_VECTOR_CAPACITY_INVALID")
    if count == 0:
        return {
            "label": label,
            "row_address": hex(row_address),
            "owner": hex(owner),
            "vector_address": hex(vector_address),
            "data_pointer": hex(data_pointer),
            "capacity": capacity,
            "count": count,
            "target_match_count": 0,
            "target_pointer": None,
        }

    byte_count = count * VECTOR_ITEM_STRIDE
    _checked_add(data_pointer, 0, byte_count)
    seen_slots: set[int] = set()
    target_pointer: int | None = None
    matches = 0
    bytes_read = 0
    while bytes_read < byte_count:
        chunk_size = min(VECTOR_CHUNK_BYTES, byte_count - bytes_read)
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
            if slot == other["slot"]:
                matches += 1
                target_pointer = candidate
        bytes_read += chunk_size
    if matches > 1:
        raise _Unknown(f"{label.upper()}_VECTOR_DUPLICATE_TARGET")
    return {
        "label": label,
        "row_address": hex(row_address),
        "owner": hex(owner),
        "vector_address": hex(vector_address),
        "data_pointer": hex(data_pointer),
        "capacity": capacity,
        "count": count,
        "target_match_count": matches,
        "target_pointer": hex(target_pointer) if target_pointer is not None else None,
    }


def _relation_contract(trace: _Trace, module_base: int, treaty_pointer: int,
                       observer: Mapping[str, Any], target: Mapping[str, Any],
                       date_raw: int) -> dict[str, Any]:
    treaty_pointer = _pointer(treaty_pointer, "TREATY")
    object_raw = trace.exact(treaty_pointer, RELATION_OBJECT_MIN_SIZE,
                             "contract.relation_object")
    vtable = int.from_bytes(object_raw[0:8], "little", signed=False)
    marker = int.from_bytes(object_raw[8:12], "little", signed=False)
    payer = int.from_bytes(object_raw[RELATION_PAYER_OFFSET:
                                      RELATION_PAYER_OFFSET + 8], "little", signed=False)
    claimant = int.from_bytes(object_raw[RELATION_CLAIMANT_OFFSET:
                                         RELATION_CLAIMANT_OFFSET + 8], "little", signed=False)
    start = int.from_bytes(object_raw[RELATION_START_DATE_OFFSET:
                                      RELATION_START_DATE_OFFSET + 4], "little", signed=True)
    end = int.from_bytes(object_raw[RELATION_END_DATE_OFFSET:
                                    RELATION_END_DATE_OFFSET + 4], "little", signed=True)
    expected_vtable = _pointer(_checked_add(module_base, RELATION_TABLE_RVA, 1),
                               "RELATION_VTABLE")
    trace.reads[-1].update({
        "decode": "reparations_relation_object",
        "vtable": hex(vtable),
        "marker": marker,
        "payer_fullref": hex(payer),
        "claimant_fullref": hex(claimant),
        "start_date_raw": start,
        "end_date_raw": end,
    })
    if vtable != expected_vtable:
        raise _Unknown("TREATY_VTABLE_MISMATCH")
    if marker != RELATION_MARKER:
        raise _Unknown("TREATY_MARKER_MISMATCH")
    allowed = {
        (observer["fullref"], target["fullref"]),
        (target["fullref"], observer["fullref"]),
    }
    if (payer, claimant) not in allowed:
        raise _Unknown("TREATY_PAIR_MISMATCH")
    if end <= start:
        raise _Unknown("TREATY_DATE_WINDOW_INVALID")
    return {
        "status": "known",
        "present": True,
        "payer": {
            "tag": observer["tag"] if payer == observer["fullref"] else target["tag"],
            "fullref": hex(payer),
            "fullref_raw_hex": payer.to_bytes(8, "little").hex(),
        },
        "claimant": {
            "tag": observer["tag"] if claimant == observer["fullref"] else target["tag"],
            "fullref": hex(claimant),
            "fullref_raw_hex": claimant.to_bytes(8, "little").hex(),
        },
        "start_date": {
            "raw": start, "unit": "eu4_hour_tick", "scale": 1,
            "calendar": project_engine_date(start),
        },
        "end_date": {
            "raw": end, "unit": "eu4_hour_tick", "scale": 1,
            "calendar": project_engine_date(end),
        },
        "date_window_contains_observed_date": start <= date_raw < end,
        "active_payment_obligation": {
            "status": "unknown", "reason": "PAYMENT_OBLIGATION_SEMANTICS_NOT_CAPTURED",
        },
        "payment_amount": {
            "status": "unknown", "reason": "PAYMENT_AMOUNT_OR_PERCENTAGE_NOT_CAPTURED",
        },
        "relation_flag_0x28": {
            "status": "unknown", "reason": "RELATION_FLAG_0X28_SEMANTICS_UNCLOSED",
        },
    }


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
        "raw_inputs": inputs,
    }


def read_state(reader: Any, module_base: Any, observer_binding: Any,
               target_binding: Any, date_raw: Any) -> dict[str, Any]:
    """Read one exact FRA-target pair without calling native game code.

    ``status=known`` means the selected pair was read consistently enough for
    the bounded single-pass contract below. It does not mean the target has no
    other reparations with third countries, that the relation is F03-visible,
    or that a payment is currently due.
    """
    trace = _Trace(reader)
    raw_inputs: dict[str, Any] = {
        "module_base": None,
        "date_raw": date_raw if type(date_raw) is int else None,
        "static_evidence": deepcopy(_STATIC_EVIDENCE),
        "country_relation_rows_offset": hex(COUNTRY_RELATION_ROWS_OFFSET),
        "pair_row_stride": hex(PAIR_ROW_STRIDE),
        "owner_pair_vector_offset": hex(OWNER_PAIR_VECTOR_OFFSET),
        "vector_item_stride": hex(VECTOR_ITEM_STRIDE),
        "atomic_snapshot": False,
        "visibility_evaluated": False,
    }
    observed_pair: dict[str, Any] | None = None
    try:
        base = _pointer(module_base, "MODULE_BASE", alignment=0x1000)
        if type(date_raw) is not int or not INT32_MIN <= date_raw <= INT32_MAX:
            raise _Unknown("DATE_RAW_INVALID")
        observer = _parse_binding(observer_binding, "observer")
        target = _parse_binding(target_binding, "target")
        if observer["tag"] != "FRA":
            raise _Unknown("OBSERVER_MUST_BE_FRA")
        if target["tag"] == "FRA":
            raise _Unknown("TARGET_MUST_DIFFER_FROM_FRA")
        if (observer["country_pointer"] == target["country_pointer"]
                or observer["slot"] == target["slot"]
                or observer["fullref"] == target["fullref"]):
            raise _Unknown("BILATERAL_BINDINGS_ALIAS")
        if (observer["slot"] >= MAX_RELATION_SLOTS
                or target["slot"] >= MAX_RELATION_SLOTS):
            raise _Unknown("COUNTRY_RELATION_SLOT_UNSUPPORTED")

        raw_inputs["module_base"] = hex(base)
        raw_inputs["bindings"] = {
            "observer": {
                "tag": observer["tag"], "slot": observer["slot"],
                "country_pointer": hex(observer["country_pointer"]),
                "fullref": hex(observer["fullref"]),
                "fullref_raw_hex": observer["fullref_raw_hex"],
            },
            "target": {
                "tag": target["tag"], "slot": target["slot"],
                "country_pointer": hex(target["country_pointer"]),
                "fullref": hex(target["fullref"]),
                "fullref_raw_hex": target["fullref_raw_hex"],
            },
        }
        observed_pair = {
            "observer": deepcopy(raw_inputs["bindings"]["observer"]),
            "target": deepcopy(raw_inputs["bindings"]["target"]),
            "fullref_echo_verified": False,
        }

        _pair_echo(trace, observer, "observer")
        _pair_echo(trace, target, "target")
        forward = _row_vector(trace, observer, target, "observer_to_target")
        reverse = _row_vector(trace, target, observer, "target_to_observer")
        raw_inputs["pair_directions"] = [forward, reverse]
        forward_pointer = forward["target_pointer"]
        reverse_pointer = reverse["target_pointer"]
        if forward_pointer is None and reverse_pointer is None:
            contract: dict[str, Any] = {
                "status": "absent",
                "present": False,
                "scope": "explicit_observer_target_pair_only",
                "reason": "NO_MATCHING_PAIR_ENTRY",
                "active_payment_obligation": {
                    "status": "unknown", "reason": "PAYMENT_OBLIGATION_SEMANTICS_NOT_CAPTURED",
                },
                "payment_amount": {
                    "status": "unknown", "reason": "PAYMENT_AMOUNT_OR_PERCENTAGE_NOT_CAPTURED",
                },
            }
        elif forward_pointer is None or reverse_pointer is None:
            raise _Unknown("ASYMMETRIC_PAIR_RELATION")
        elif forward_pointer != reverse_pointer:
            raise _Unknown("BILATERAL_RELATION_POINTER_MISMATCH")
        else:
            treaty_pointer = int(forward_pointer, 16)
            contract = _relation_contract(trace, base, treaty_pointer,
                                          observer, target, date_raw)

        # Echo identities after the pair walk. The relation vectors themselves
        # are read once, so the result remains a non-atomic bounded observation.
        _pair_echo(trace, observer, "observer_after")
        _pair_echo(trace, target, "target_after")
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


__all__ = [
    "SCHEMA", "BASIS", "EXPECTED_EXE_SHA256", "PREFERRED_IMAGE_BASE",
    "read_state",
]
