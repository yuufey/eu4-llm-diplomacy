"""Project EU4's country-view admission predicate onto a bound observer row.

This is a pure, bounded RPM leaf.  It only calls the supplied
``read(address, size, label) -> bytes`` callback and never opens a process,
file, game API, or MCP connection.  The caller must pin the B23 executable and
installation/session, validate the SetCountry code guard, and run/compare its
own before/after passes.  This module deliberately performs one predicate
pass and does not claim an actual UI observation.

Static basis: retained REA evidence ``ev_12ff55717e16b8adfecfb7eee6c4468cfa5c314b447f63e3ef50383aa9d3b32c``
 (evidence JSON SHA-256 ``ce2d13f88c6eebb7ae0453b2ff043839232b51966ee5926aa2615a3608c9ab78``,
 1,430,581 bytes)
for B23 SHA-256 ``b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77``;
SetCountry VA ``0x140f016e0`` / RVA ``0x00f016e0``, body
``[0x00f016e0, 0x00f01c2e)`` (1358 bytes).  Its normal observer is selected
from a process-global UI context.  This leaf instead projects the same
relation/capital predicate onto the explicitly supplied observer tag in a
complete ``country_reference_memory.resolve_countries`` scan.  It does not
read or equate that tag with the physical player's current country.

The field-level conclusion is limited to this native country-view predicate
used by the ``mil_value`` path.  A positive result is not a runtime UI,
rendering, or foreign-information visibility observation.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any


DATABASE_GLOBAL_RVA = 0x233D8B0
SPECIAL_TARGET_SLOT_RVAS = (
    ("DAT_14233d884", 0x233D884),
    ("DAT_14233d8b8", 0x233D8B8),
    ("DAT_14233d8bc", 0x233D8BC),
)

COUNTRY_TABLE_OFFSET = 0x118
COUNTRY_TABLE_COUNT_OFFSET = 0x124
COUNTRY_FULLREF_OFFSET = 0x20
RELATION_TABLE_OFFSET = 0x1510
RELATION_ROW_STRIDE = 0x48
RELATION_ROW_OWNER_OFFSET = 0x00
RELATION_ROW_RECIPIENT_FULLREF_OFFSET = 0x10
RELATION_OWNER_COUNTERS_OFFSET = 0x38
RELATION_COUNTER_FIRST_OFFSET = 0x14
RELATION_COUNTER_STRIDE = 0x18
COUNTRY_CAPITAL_OFFSET = 0x14B0
CAPITAL_VIEW_FLAGS_OFFSET = 0x959
CAPITAL_OBSERVER_BITSET_OFFSET = 0x5E0
CAPITAL_OBSERVER_BITSET_WORD_STRIDE = 4
CAPITAL_VIEW_FLAG_BIT = 0x10

MAX_COUNTRY_SLOTS = 4096
MAX_TOTAL_RPM_BYTES = 4096
MAX_SINGLE_RPM_BYTES = 8
MAX_RPM_CALLS = 16
MIN_USER_ADDRESS = 0x10000
MAX_USER_ADDRESS_EXCLUSIVE = 0x800000000000
MAX_U64 = 0xFFFFFFFFFFFFFFFF

BASIS = "native_country_view_predicate_projected_to_observer"


class _Unknown(Exception):
    """A malformed binding or unsafe/incomplete read prevents a result."""


def _tag_ok(value: Any) -> bool:
    return (isinstance(value, str) and len(value) == 3
            and all("A" <= char <= "Z" or "0" <= char <= "9" for char in value))


def _as_int(value: Any, label: str) -> int:
    if type(value) is int:
        result = value
    elif isinstance(value, str):
        try:
            result = int(value, 0)
        except ValueError as exc:
            raise _Unknown(f"{label}_invalid") from exc
    else:
        raise _Unknown(f"{label}_invalid")
    if type(result) is not int or not 0 <= result <= MAX_U64:
        raise _Unknown(f"{label}_out_of_range")
    return result


def _is_user_address(value: Any) -> bool:
    return (type(value) is int and MIN_USER_ADDRESS <= value < MAX_USER_ADDRESS_EXCLUSIVE
            and value <= MAX_U64)


def _checked_add(base: int, offset: int, label: str, *, aligned: bool = False) -> int:
    if (not _is_user_address(base) or type(offset) is not int or offset < 0
            or base > MAX_U64 - offset):
        raise _Unknown(f"address_arithmetic_invalid:{label}")
    result = base + offset
    if not _is_user_address(result) or (aligned and result & 7):
        raise _Unknown(f"address_out_of_range:{label}")
    return result


def _checked_range(address: int, size: int, label: str) -> None:
    if (not _is_user_address(address) or type(size) is not int or size <= 0
            or address > MAX_U64 - (size - 1)):
        raise _Unknown(f"address_range_invalid:{label}")
    if not _is_user_address(address + size - 1):
        raise _Unknown(f"address_range_invalid:{label}")


def _signed_i16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def _tag_from_fullref(fullref: int) -> str | None:
    raw = (fullref & 0xFFFFFF).to_bytes(3, "little")
    if not all(0x30 <= byte <= 0x39 or 0x41 <= byte <= 0x5A for byte in raw):
        return None
    return raw.decode("ascii")


def _binding_entry(bindings: Mapping[str, Any], tag: str) -> dict[str, Any]:
    """Validate one requested row against the complete bounded country scan."""
    if bindings.get("status") != "observed":
        raise _Unknown("country_scan_not_observed")
    if bindings.get("basis") != "country_manager_table_tag_slot_binding":
        raise _Unknown("country_scan_basis_invalid")

    count = bindings.get("count")
    rows = bindings.get("rows")
    requested = bindings.get("requested")
    if (type(count) is not int or not 1 <= count <= MAX_COUNTRY_SLOTS
            or not isinstance(rows, list) or len(rows) != count
            or not isinstance(requested, Mapping)):
        raise _Unknown("country_scan_shape_invalid")

    table = _as_int(bindings.get("table"), "country_scan_table")
    database = _as_int(bindings.get("database"), "country_scan_database")
    if not _is_user_address(table) or table & 7 or not _is_user_address(database) or database & 7:
        raise _Unknown("country_scan_pointer_invalid")
    _checked_range(table, count * 8, "country_scan_table")

    entry = requested.get(tag)
    if not isinstance(entry, Mapping) or entry.get("tag") != tag:
        raise _Unknown(f"country_binding_missing:{tag}")
    slot = entry.get("slot")
    if type(slot) is not int or not 0 <= slot < count:
        raise _Unknown(f"country_binding_slot_invalid:{tag}")

    pointer = _as_int(entry.get("country_pointer"), f"country_binding_pointer:{tag}")
    if not _is_user_address(pointer) or pointer & 7:
        raise _Unknown(f"country_binding_pointer_invalid:{tag}")

    fullref = _as_int(entry.get("fullref"), f"country_binding_fullref:{tag}")
    raw_hex = entry.get("fullref_raw_hex")
    if (not isinstance(raw_hex, str) or len(raw_hex) != 16
            or raw_hex.lower() != fullref.to_bytes(8, "little").hex()):
        raise _Unknown(f"country_binding_fullref_raw_mismatch:{tag}")
    ref_slot = _signed_i16(fullref >> 32)
    if ref_slot != slot or _tag_from_fullref(fullref) != tag:
        raise _Unknown(f"country_binding_fullref_identity_mismatch:{tag}")

    scan_row = rows[slot]
    if (not isinstance(scan_row, Mapping) or scan_row.get("slot") != slot
            or scan_row.get("tag") != tag or scan_row.get("fullref_slot") != slot):
        raise _Unknown(f"country_scan_row_mismatch:{tag}")
    if scan_row.get("country_pointer") != hex(pointer):
        raise _Unknown(f"country_scan_pointer_mismatch:{tag}")
    if scan_row.get("fullref") != hex(fullref):
        raise _Unknown(f"country_scan_fullref_mismatch:{tag}")
    if scan_row.get("fullref_raw_hex") != raw_hex.lower():
        raise _Unknown(f"country_scan_fullref_raw_mismatch:{tag}")
    expected_table_entry = _checked_add(table, slot * 8, f"country_scan_entry:{tag}", aligned=True)
    expected_ref_address = _checked_add(pointer, COUNTRY_FULLREF_OFFSET,
                                       f"country_scan_ref_address:{tag}", aligned=True)
    if scan_row.get("table_entry_address") != hex(expected_table_entry):
        raise _Unknown(f"country_scan_entry_address_mismatch:{tag}")
    if scan_row.get("table_entry_raw_hex") != pointer.to_bytes(8, "little").hex():
        raise _Unknown(f"country_scan_entry_raw_mismatch:{tag}")
    if scan_row.get("fullref_address") != hex(expected_ref_address):
        raise _Unknown(f"country_scan_ref_address_mismatch:{tag}")

    return {
        "tag": tag,
        "slot": slot,
        "slot_signed_i16": ref_slot,
        "fullref": fullref,
        "fullref_hex": hex(fullref),
        "fullref_raw_hex": raw_hex.lower(),
        "country_pointer": pointer,
        "country_pointer_hex": hex(pointer),
    }


class _ReadTrace:
    def __init__(self, read: Callable[[int, int, str], bytes]) -> None:
        self.read = read
        self.operands: list[dict[str, Any]] = []
        self.calls = 0
        self.bytes_requested = 0

    def integer(self, address: int, size: int, label: str, *, signed: bool = False) -> int:
        _checked_range(address, size, label)
        if not 1 <= size <= MAX_SINGLE_RPM_BYTES:
            raise _Unknown(f"single_read_budget_exceeded:{label}")
        if self.calls + 1 > MAX_RPM_CALLS or self.bytes_requested + size > MAX_TOTAL_RPM_BYTES:
            raise _Unknown("read_budget_exceeded")

        self.calls += 1
        self.bytes_requested += size
        item: dict[str, Any] = {
            "ordinal": self.calls,
            "native_operand": label,
            "address": hex(address),
            "size": size,
            "decode": "signed_i32" if signed and size == 4 else (
                "unsigned_integer" if not signed else f"signed_i{size * 8}"
            ),
            "status": "requested",
        }
        self.operands.append(item)
        try:
            raw = self.read(address, size, label)
        except Exception as exc:
            item.update({"status": "failed", "error_type": type(exc).__name__})
            raise _Unknown(f"rpm_read_failed:{label}:{type(exc).__name__}") from exc
        if not isinstance(raw, (bytes, bytearray, memoryview)) or len(raw) != size:
            item.update({"status": "failed", "error_type": "short_or_invalid_read"})
            raise _Unknown(f"rpm_short_read:{label}")
        raw = bytes(raw)
        value = int.from_bytes(raw, "little", signed=signed)
        item.update({"status": "ok", "raw_hex": raw.hex(), "value": value})
        return value


def _base_result(observer_tag: Any, target_tag: Any) -> dict[str, Any]:
    return {
        "schema": "information_country_view_admission.v1",
        "native_source": {
            "evidence_id": "ev_12ff55717e16b8adfecfb7eee6c4468cfa5c314b447f63e3ef50383aa9d3b32c",
            "evidence_json_sha256": "ce2d13f88c6eebb7ae0453b2ff043839232b51966ee5926aa2615a3608c9ab78",
            "exe_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
            "function_va": "0x140f016e0",
            "function_rva": "0xf016e0",
            "body_rva_start": "0xf016e0",
            "body_rva_end_exclusive": "0xf01c2e",
            "body_bytes": 1358,
            "code_guard_owner": "caller",
        },
        "status": "unknown",
        "admitted": None,
        "basis": BASIS,
        "admission_scope": "mil_value_native_country_selection_predicate_only",
        "observer": {"tag": observer_tag if _tag_ok(observer_tag) else None, "binding": None},
        "target": {"tag": target_tag if _tag_ok(target_tag) else None, "binding": None},
        "country_scan": None,
        "module_base": None,
        "refs": {},
        "predicate_path": [],
        "raw_operands": [],
        "budget": {
            "calls": 0,
            "bytes_requested": 0,
            "max_calls": MAX_RPM_CALLS,
            "max_total_bytes": MAX_TOTAL_RPM_BYTES,
            "max_single_read_bytes": MAX_SINGLE_RPM_BYTES,
            "max_country_slots": MAX_COUNTRY_SLOTS,
        },
        "actual_UI_observed": False,
        "current_client_predicate_executed": False,
        "physical_global_observer_checked": False,
        "projected_observer_view": True,
        "reason": None,
    }


def read_country_view_admission(read: Callable[[int, int, str], bytes], module_base: int,
                                bindings: Mapping[str, Any], observer: str,
                                target: str) -> dict[str, Any]:
    """Read the fixed B23 country-view predicate for explicitly bound tags.

    ``bindings`` must be the complete observed output of
    :func:`country_reference_memory.resolve_countries`, requesting both tags.
    The supplied observer tag is used as the logical viewpoint for the
    predicate projection. It is not compared to the physical game's global
    current-country value.  Nonordinary observer fullrefs yield ``unknown``
    rather than using the native invalid-observer bypass.

    Every RPM request is at most 8 bytes, at most 16 reads/4096 requested
    bytes. The native code guard, process/installation identity, session,
    source mode, and before/after consistency are the caller's responsibility.
    No memory write or native call is performed here.
    """
    result = _base_result(observer, target)
    trace = _ReadTrace(read) if callable(read) else None

    def finish() -> dict[str, Any]:
        if trace is not None:
            result["raw_operands"] = trace.operands
            result["budget"].update({"calls": trace.calls,
                                     "bytes_requested": trace.bytes_requested})
        return result

    def unknown(reason: str) -> dict[str, Any]:
        result["status"] = "unknown"
        result["admitted"] = None
        result["reason"] = reason
        result["predicate_path"].append(f"unknown:{reason}")
        return finish()

    def decide(admitted: bool, step: str) -> dict[str, Any]:
        result["status"] = "known"
        result["admitted"] = admitted
        result["reason"] = None
        result["predicate_path"].append(step)
        return finish()

    try:
        if trace is None:
            raise _Unknown("reader_not_callable")
        if not _is_user_address(module_base) or module_base & 7:
            raise _Unknown("module_base_invalid")
        result["module_base"] = hex(module_base)
        if not _tag_ok(observer) or not _tag_ok(target):
            raise _Unknown("country_tag_invalid")
        if not isinstance(bindings, Mapping):
            raise _Unknown("country_scan_shape_invalid")

        observer_binding = _binding_entry(bindings, observer)
        result["observer"]["binding"] = observer_binding
        target_binding = _binding_entry(bindings, target)
        result["target"]["binding"] = target_binding
        if observer != target and observer_binding["country_pointer"] == target_binding["country_pointer"]:
            raise _Unknown("observer_target_pointer_alias")

        result["country_scan"] = {
            "basis": bindings.get("basis"),
            "count": bindings.get("count"),
            "database": hex(_as_int(bindings.get("database"), "country_scan_database")),
            "table": hex(_as_int(bindings.get("table"), "country_scan_table")),
        }
        refs = result["observer"]["binding"]["fullref"]
        observer_high_byte = (refs >> 56) & 0xFF
        observer_byte48 = (refs >> 48) & 0xFF
        if observer_high_byte == 0 or observer_byte48 == 7:
            raise _Unknown("observer_fullref_not_ordinary")
        result["predicate_path"].append("observer_binding_is_ordinary_fullref")

        target_ref = target_binding["fullref"]
        target_high_byte = (target_ref >> 56) & 0xFF
        target_byte48 = (target_ref >> 48) & 0xFF
        target_slot = target_binding["slot_signed_i16"]
        result["target"].update({
            "native_high_byte": target_high_byte,
            "native_byte48": target_byte48,
            "native_slot_signed_i16": target_slot,
        })
        if target_high_byte == 0:
            return decide(False, "target_high_byte_zero_rejected")
        result["predicate_path"].append("target_high_byte_nonzero")
        if target_byte48 == 7:
            return decide(False, "target_byte48_seven_rejected")
        result["predicate_path"].append("target_byte48_not_seven")

        for name, rva in SPECIAL_TARGET_SLOT_RVAS:
            address = _checked_add(module_base, rva, f"{name}_global")
            special_slot = trace.integer(address, 4, name, signed=True)
            trace.operands[-1]["rva"] = hex(rva)
            trace.operands[-1]["preferred_va"] = hex(0x140000000 + rva)
            if target_slot == special_slot:
                result["refs"] = {"target_special_slot_name": name,
                                  "target_special_slot_signed_i32": special_slot}
                return decide(False, f"target_slot_matches_{name}_rejected")
            result["predicate_path"].append(f"target_slot_differs_from_{name}")

        relation_table_cell = _checked_add(observer_binding["country_pointer"],
                                           RELATION_TABLE_OFFSET,
                                           "observer_relation_table_cell", aligned=True)
        relation_table = trace.integer(relation_table_cell, 8,
                                       "observer.relation_table_pointer")
        if not _is_user_address(relation_table) or relation_table & 7:
            raise _Unknown("relation_table_pointer_invalid")
        if relation_table in (module_base, observer_binding["country_pointer"],
                              target_binding["country_pointer"]):
            raise _Unknown("relation_table_pointer_alias")
        result["predicate_path"].append("observer_relation_table_pointer_valid")

        target_row_offset = target_slot * RELATION_ROW_STRIDE
        row_address = _checked_add(relation_table, target_row_offset,
                                   "observer_target_relation_row", aligned=True)
        _checked_range(row_address, RELATION_ROW_RECIPIENT_FULLREF_OFFSET + 8,
                       "observer_target_relation_row")
        result["refs"]["observer_relation_table_pointer"] = hex(relation_table)
        result["target"]["relation_row_address"] = hex(row_address)

        row_fullref_address = _checked_add(row_address,
                                           RELATION_ROW_RECIPIENT_FULLREF_OFFSET,
                                           "relation_row_recipient_fullref")
        row_fullref = trace.integer(row_fullref_address, 8,
                                    "relation_row.recipient_fullref")
        result["refs"].update({
            "observer_relation_table_pointer": hex(relation_table),
            "target_relation_row_address": hex(row_address),
            "row_recipient_fullref": hex(row_fullref),
            "target_binding_fullref": hex(target_ref),
        })
        if row_fullref != target_ref:
            raise _Unknown("relation_row_recipient_fullref_mismatch")
        row_recipient_slot = _signed_i16(row_fullref >> 32)
        if row_recipient_slot != target_slot:
            raise _Unknown("relation_row_recipient_slot_mismatch")
        result["predicate_path"].append("relation_row_exact_target_fullref")

        row_owner_address = _checked_add(row_address, RELATION_ROW_OWNER_OFFSET,
                                         "relation_row_owner")
        row_owner = trace.integer(row_owner_address, 8, "relation_row.owner_pointer")
        if not _is_user_address(row_owner) or row_owner & 7:
            raise _Unknown("relation_row_owner_pointer_invalid")
        result["refs"].update({"relation_row_owner_pointer": hex(row_owner)})

        counters_cell = _checked_add(row_owner, RELATION_OWNER_COUNTERS_OFFSET,
                                     "relation_owner_counters_cell", aligned=True)
        counters = trace.integer(counters_cell, 8, "relation_owner.counters_pointer")
        if not _is_user_address(counters) or counters & 7:
            raise _Unknown("relation_owner_counters_pointer_invalid")
        result["refs"].update({"relation_owner_counters_pointer": hex(counters)})

        counter_offset = (RELATION_COUNTER_FIRST_OFFSET
                          + row_recipient_slot * RELATION_COUNTER_STRIDE)
        counter_address = _checked_add(counters, counter_offset,
                                       "relation_recipient_counter")
        counter = trace.integer(counter_address, 4,
                                "relation_recipient.counter_signed_i32", signed=True)
        result["target"]["relation_counter_address"] = hex(counter_address)
        result["target"]["relation_counter_signed_i32"] = counter
        if counter >= 1:
            return decide(True, "relation_counter_ge_one_admitted")
        result["predicate_path"].append("relation_counter_lt_one_capital_fallback")

        capital_cell = _checked_add(target_binding["country_pointer"],
                                    COUNTRY_CAPITAL_OFFSET,
                                    "target_country_capital_cell", aligned=True)
        capital = trace.integer(capital_cell, 8, "target_country.capital_pointer")
        if not _is_user_address(capital) or capital & 7:
            raise _Unknown("target_capital_pointer_invalid")
        result["refs"]["target_capital_pointer"] = hex(capital)

        view_flags_address = _checked_add(capital, CAPITAL_VIEW_FLAGS_OFFSET,
                                          "target_capital_view_flags")
        view_flags = trace.integer(view_flags_address, 1,
                                   "target_capital.view_flags_u8")
        result["target"]["capital_view_flags_u8"] = view_flags
        if view_flags & CAPITAL_VIEW_FLAG_BIT == 0:
            return decide(True, "capital_view_flag_bit10_clear_admitted")
        result["predicate_path"].append("capital_view_flag_bit10_set_observer_bitset_fallback")

        observer_slot = observer_binding["slot_signed_i16"]
        if not 0 <= observer_slot < MAX_COUNTRY_SLOTS:
            raise _Unknown("observer_slot_out_of_bound")
        bitset_cell = _checked_add(capital, CAPITAL_OBSERVER_BITSET_OFFSET,
                                   "target_capital_observer_bitset_cell", aligned=True)
        bitset = trace.integer(bitset_cell, 8,
                               "target_capital.observer_bitset_pointer")
        if not _is_user_address(bitset) or bitset & 7:
            raise _Unknown("target_observer_bitset_pointer_invalid")
        result["refs"]["target_observer_bitset_pointer"] = hex(bitset)

        word_index = observer_slot >> 5
        bit_index = observer_slot & 0x1F
        word_address = _checked_add(bitset, word_index * CAPITAL_OBSERVER_BITSET_WORD_STRIDE,
                                    "target_observer_bitset_word", aligned=False)
        if word_address & 3:
            raise _Unknown("target_observer_bitset_word_alignment_invalid")
        word = trace.integer(word_address, 4, "target_capital.observer_bitset_word_u32")
        bit = (word >> bit_index) & 1
        result["observer"].update({
            "bitset_word_index": word_index,
            "bitset_bit_index": bit_index,
            "bitset_word_address": hex(word_address),
            "bitset_word_u32": word,
            "bit_value": bit,
        })
        return decide(bool(bit), "observer_bit_set_admitted" if bit else "observer_bit_clear_rejected")
    except _Unknown as exc:
        return unknown(str(exc))
    except Exception as exc:
        # Keep malformed caller input and callback contract errors as unknown;
        # never expose an exception as an admission decision.
        return unknown(f"unexpected_reader_error:{type(exc).__name__}")
