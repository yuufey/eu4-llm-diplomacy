"""Bounded projection of the native quality-ledger row visibility predicate.

This is a private, read-only leaf.  It does not open a process, invoke game
code, inspect the UI, validate a ROM profile, or establish FRA's role.  The
parent must supply already-resolved country bindings and independently enforce
installation/session, ROM, role, country-view, and two-pass requirements.

The result describes the retained native ledger predicate projected onto the
explicit observer/target pair.  It does not establish that a row was rendered
or that all quality information is available.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from . import country_faith_memory as _faith
from . import country_ledger_membership_memory as _ledger_membership


SCHEMA = "information.foreign_quality_visibility_memory.v2"
BASIS = "native_quality_ledger_visibility_predicate_projected"

DATABASE_GLOBAL_RVA = 0x233D8B0
DATABASE_TABLE_OFFSET = 0x118
DATABASE_COUNT_OFFSET = 0x124
COUNTRY_FULLREF_OFFSET = 0x20
MAX_COUNTRY_SLOTS = 4096

WORLD_GLOBAL_RVA = 0x233FE58
WORLD_OPTIONS_POINTER_OFFSET = 0x2150
OPTIONS_QUALITY_INDEX = 0x17
OPTIONS_U32_STRIDE = 4
WORLD_PAGE_ENABLE_RVA = 0x233FF04
WORLD_PAGE_TLS_RVA = 0x233FEB6

SPECIAL_TARGET_SLOT_RVAS = (
    ("special_target_a", 0x233D884),
    ("special_target_b", 0x233D8B8),
    ("special_target_c", 0x233D8BC),
)
COUNTRY_CAPITAL_OFFSET = 0x14B0
CAPITAL_QUALITY_FLAGS_OFFSET = 0x959
CAPITAL_OBSERVER_BITSET_OFFSET = 0x5E0
OBSERVER_BITSET_WORD_STRIDE = 4
QUALITY_FLAG_BIT = 0x10

MAX_TOTAL_READ_BYTES = 64 * 1024
MAX_READ_CALLS = 128
MAX_SINGLE_READ_BYTES = 1024
MIN_USER_ADDRESS = 0x10000
MAX_USER_ADDRESS_EXCLUSIVE = 0x800000000000
MAX_U64 = 0xFFFFFFFFFFFFFFFF


class _Unknown(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _checked_add(address: int, offset: int, size: int = 1) -> int:
    if (type(address) is not int or type(offset) is not int or type(size) is not int
            or address < MIN_USER_ADDRESS or address >= MAX_USER_ADDRESS_EXCLUSIVE
            or offset < 0 or size <= 0 or address > MAX_U64 - offset):
        raise _Unknown("ADDRESS_INVALID")
    result = address + offset
    if (result < MIN_USER_ADDRESS or result >= MAX_USER_ADDRESS_EXCLUSIVE
            or result > MAX_U64 - (size - 1)
            or result + size > MAX_USER_ADDRESS_EXCLUSIVE):
        raise _Unknown("ADDRESS_INVALID")
    return result


def _pointer(value: Any, label: str, *, alignment: int = 8,
             allow_null: bool = False) -> int:
    if type(value) is not int or not 0 <= value <= MAX_U64:
        raise _Unknown(f"{label}_POINTER_INVALID")
    if value == 0 and allow_null:
        return 0
    if (value < MIN_USER_ADDRESS or value >= MAX_USER_ADDRESS_EXCLUSIVE
            or alignment <= 0 or value % alignment):
        raise _Unknown(f"{label}_POINTER_INVALID")
    return value


def _parse_binding(value: Any, label: str) -> dict[str, Any]:
    try:
        pointer, row = _faith._binding(value)
    except Exception as exc:
        raise _Unknown(f"{label.upper()}_BINDING_INVALID") from exc
    if not isinstance(value, Mapping):
        raise _Unknown(f"{label.upper()}_BINDING_INVALID")
    slot = row.get("slot")
    fullref = int(str(row.get("fullref")), 0)
    tag = row.get("tag")
    expected_raw = fullref.to_bytes(8, "little").hex()
    supplied_raw = value.get("fullref_raw_hex")
    if (type(slot) is not int or not 0 <= slot < MAX_COUNTRY_SLOTS
            or not isinstance(tag, str)
            or not isinstance(supplied_raw, str)
            or supplied_raw.lower() != expected_raw
            or ((fullref >> 32) & 0xFFFF) != slot
            or ((fullref >> 24) & 0xFF) != 0):
        raise _Unknown(f"{label.upper()}_BINDING_INVALID")
    if value.get("country_fullref_address") is not None:
        try:
            given_address = int(str(value["country_fullref_address"]), 0)
        except (ValueError, TypeError):
            raise _Unknown(f"{label.upper()}_BINDING_INVALID")
        if given_address != pointer + COUNTRY_FULLREF_OFFSET:
            raise _Unknown(f"{label.upper()}_BINDING_INVALID")
    table_entry_address = value.get("table_entry_address")
    if table_entry_address is not None:
        try:
            if int(str(table_entry_address), 0) < MIN_USER_ADDRESS:
                raise ValueError
        except (ValueError, TypeError):
            raise _Unknown(f"{label.upper()}_BINDING_INVALID")
    table_entry_raw = value.get("table_entry_raw_hex")
    if table_entry_raw is not None:
        if (not isinstance(table_entry_raw, str) or len(table_entry_raw) != 16
                or table_entry_raw.lower() != pointer.to_bytes(8, "little").hex()):
            raise _Unknown(f"{label.upper()}_BINDING_INVALID")
    return {
        "tag": tag,
        "slot": slot,
        "country_pointer": pointer,
        "fullref": fullref,
        "fullref_raw_hex": expected_raw,
        "binding_table_entry_address": table_entry_address,
        "table_entry_raw_hex": table_entry_raw,
    }


class _Trace:
    def __init__(self, reader: Any):
        method = getattr(reader, "read", None)
        self._read = method if callable(method) else reader if callable(reader) else None
        self.reads: list[dict[str, Any]] = []
        self.calls = 0
        self.bytes_requested = 0

    def exact(self, address: int, size: int, label: str) -> bytes:
        if self._read is None:
            raise _Unknown("READER_INVALID")
        try:
            address = _checked_add(address, 0, size)
        except _Unknown as exc:
            raise _Unknown(f"ADDRESS_INVALID:{label}") from exc
        if type(size) is not int or not 0 < size <= MAX_SINGLE_READ_BYTES:
            raise _Unknown(f"SINGLE_READ_LIMIT:{label}")
        if self.calls + 1 > MAX_READ_CALLS or self.bytes_requested + size > MAX_TOTAL_READ_BYTES:
            self.reads.append({"ordinal": self.calls + 1, "address": hex(address),
                               "size": size, "label": label, "status": "rejected",
                               "reason": "READ_BUDGET_EXCEEDED"})
            raise _Unknown("READ_BUDGET_EXCEEDED")
        self.calls += 1
        self.bytes_requested += size
        row: dict[str, Any] = {"ordinal": self.calls, "address": hex(address),
                               "size": size, "label": label, "status": "requested"}
        self.reads.append(row)
        try:
            raw = self._read(address, size, label)
        except Exception as exc:
            row.update({"status": "failed", "error_type": type(exc).__name__})
            raise _Unknown(f"READ_FAILED:{label}") from exc
        if not isinstance(raw, (bytes, bytearray, memoryview)) or len(raw) != size:
            row.update({"status": "failed", "error_type": "SHORT_OR_INVALID_READ"})
            raise _Unknown(f"READ_FAILED:{label}")
        data = bytes(raw)
        row.update({"status": "ok", "raw_hex": data.hex()})
        return data

    def u8(self, address: int, label: str) -> int:
        value = int.from_bytes(self.exact(address, 1, label), "little")
        self.reads[-1]["decode"] = "u8"
        self.reads[-1]["value"] = value
        return value

    def u32(self, address: int, label: str) -> int:
        value = int.from_bytes(self.exact(address, 4, label), "little")
        self.reads[-1]["decode"] = "u32"
        self.reads[-1]["value"] = value
        return value

    def i32(self, address: int, label: str) -> int:
        value = int.from_bytes(self.exact(address, 4, label), "little", signed=True)
        self.reads[-1]["decode"] = "i32"
        self.reads[-1]["value"] = value
        return value

    def u64(self, address: int, label: str) -> int:
        value = int.from_bytes(self.exact(address, 8, label), "little")
        self.reads[-1]["decode"] = "u64"
        self.reads[-1]["value"] = hex(value)
        return value

    def summary(self) -> dict[str, int]:
        return {"calls": self.calls, "bytes_requested": self.bytes_requested,
                "max_calls": MAX_READ_CALLS, "max_bytes": MAX_TOTAL_READ_BYTES,
                "max_single_read_bytes": MAX_SINGLE_READ_BYTES}


def _signed_i16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def _binding_evidence(trace: _Trace, base: int,
                      observer: Mapping[str, Any], target: Mapping[str, Any]) -> dict[str, Any]:
    global_cell = _checked_add(base, DATABASE_GLOBAL_RVA, 8)
    database = _pointer(trace.u64(global_cell, "bindings.database_global"),
                        "DATABASE")
    table_cell = _checked_add(database, DATABASE_TABLE_OFFSET, 8)
    count_cell = _checked_add(database, DATABASE_COUNT_OFFSET, 4)
    table = _pointer(trace.u64(table_cell, "bindings.country_table"), "COUNTRY_TABLE")
    count = trace.i32(count_cell, "bindings.country_count")
    if not 1 <= count <= MAX_COUNTRY_SLOTS:
        raise _Unknown("COUNTRY_COUNT_INVALID")
    bound: dict[str, Any] = {
        "database_global_address": hex(global_cell),
        "database": hex(database),
        "table_address": hex(table_cell),
        "table": hex(table),
        "count_address": hex(count_cell),
        "count": count,
        "observer": {},
        "target": {},
    }
    for name, item in (("observer", observer), ("target", target)):
        slot = item["slot"]
        pointer = item["country_pointer"]
        fullref = item["fullref"]
        if slot >= count:
            raise _Unknown(f"{name.upper()}_SLOT_OUT_OF_RANGE")
        table_entry = _checked_add(table, slot * 8, 8)
        current_pointer = _pointer(trace.u64(table_entry, f"bindings.{name}.table_entry"),
                                   f"{name.upper()}_TABLE_ENTRY")
        if current_pointer != pointer:
            raise _Unknown(f"{name.upper()}_POINTER_MISMATCH")
        fullref_address = _checked_add(pointer, COUNTRY_FULLREF_OFFSET, 8)
        current_fullref = trace.u64(fullref_address, f"bindings.{name}.fullref")
        if current_fullref != fullref:
            raise _Unknown(f"{name.upper()}_FULLREF_MISMATCH")
        table_entry_raw = pointer.to_bytes(8, "little").hex()
        given_entry = item.get("binding_table_entry_address")
        if given_entry is not None and str(given_entry).lower() != hex(table_entry).lower():
            raise _Unknown(f"{name.upper()}_TABLE_ENTRY_ADDRESS_MISMATCH")
        # The saved row fields are evidence from the parent's country scan;
        # compare them when present without treating them as memory reads.
        if item.get("table_entry_raw_hex") not in (None, table_entry_raw):
            raise _Unknown(f"{name.upper()}_TABLE_ENTRY_RAW_MISMATCH")
        bound[name] = {
            "tag": item["tag"], "slot": slot,
            "country_pointer": hex(pointer), "fullref": hex(fullref),
            "fullref_raw_hex": item["fullref_raw_hex"],
            "table_entry_address": hex(table_entry),
            "table_entry_raw_hex": table_entry_raw,
            "fullref_address": hex(fullref_address),
            "live_fullref_raw_hex": fullref.to_bytes(8, "little").hex(),
        }
    return bound


def _initial_result(observer_binding: Any, target_binding: Any) -> dict[str, Any]:
    def label(binding: Any) -> dict[str, Any]:
        if isinstance(binding, Mapping):
            tag = binding.get("tag") if isinstance(binding.get("tag"), str) else None
            slot = binding.get("slot") if type(binding.get("slot")) is int else None
            fullref = binding.get("fullref")
            if isinstance(fullref, str):
                try:
                    fullref_value = int(fullref, 0)
                except ValueError:
                    fullref_value = None
            elif type(fullref) is int:
                fullref_value = fullref
            else:
                fullref_value = None
            return {"tag": tag, "slot": slot,
                    "fullref": hex(fullref_value) if fullref_value is not None else None,
                    "fullref_raw_hex": binding.get("fullref_raw_hex")}
        return {"tag": None, "slot": None, "fullref": None, "fullref_raw_hex": None}

    return {
        "schema": SCHEMA,
        "status": "unknown",
        "admitted": None,
        "mode": "unknown",
        "reason": None,
        "basis": BASIS,
        "observer": label(observer_binding),
        "target": label(target_binding),
        "raw_inputs": {
            "module_base": None,
            "observer_binding_validation": None,
            "target_binding_validation": None,
            "world": None,
            "ledger_membership": None,
            "gates": {},
            "special_target_slots": [],
            "predicate_path": [],
            "reads": [],
            "budget": {"calls": 0, "bytes_requested": 0,
                       "max_calls": MAX_READ_CALLS,
                       "max_bytes": MAX_TOTAL_READ_BYTES,
                       "max_single_read_bytes": MAX_SINGLE_READ_BYTES},
        },
        "actual_UI_observed": False,
        "rendering_observed": False,
        "complete": False,
    }


def read_permission(reader: Any, module_base: int, observer_binding: Any,
                    target_binding: Any) -> dict[str, Any]:
    """Read the native quality ledger's explicit observer/target permission.

    The caller owns ROM/session/role checks and the broader country-view gate.
    This leaf validates only the supplied bindings against the live country DB
    and evaluates the retained ledger-specific gates. It also requires the
    target pointer to occur in the live world's country-row candidate array;
    that check does not reproduce the later slot/discovery filters. In
    particular, this leaf does not use relation counters or time-limited
    espionage entries.
    """
    result = _initial_result(observer_binding, target_binding)
    trace = _Trace(reader)
    raw_inputs = result["raw_inputs"]

    def finish() -> dict[str, Any]:
        raw_inputs["reads"] = deepcopy(trace.reads)
        raw_inputs["budget"] = trace.summary()
        return result

    def unknown(reason: str) -> dict[str, Any]:
        result.update({"status": "unknown", "admitted": None,
                       "mode": "unknown", "reason": reason})
        raw_inputs["predicate_path"].append(f"unknown:{reason}")
        return finish()

    def decision(admitted: bool, reason: str, step: str) -> dict[str, Any]:
        result.update({"status": "known", "admitted": admitted,
                       "mode": "projected_quality_ledger_gate" if admitted else "denied",
                       "reason": None if admitted else reason})
        raw_inputs["predicate_path"].append(step)
        return finish()

    try:
        if type(module_base) is not int or not MIN_USER_ADDRESS <= module_base < MAX_USER_ADDRESS_EXCLUSIVE or module_base & 7:
            raise _Unknown("MODULE_BASE_INVALID")
        raw_inputs["module_base"] = hex(module_base)
        observer = _parse_binding(observer_binding, "observer")
        target = _parse_binding(target_binding, "target")
        result["observer"].update({"tag": observer["tag"], "slot": observer["slot"],
                                   "fullref": hex(observer["fullref"]),
                                   "fullref_raw_hex": observer["fullref_raw_hex"]})
        result["target"].update({"tag": target["tag"], "slot": target["slot"],
                                 "fullref": hex(target["fullref"]),
                                 "fullref_raw_hex": target["fullref_raw_hex"]})
        if (observer["country_pointer"] == target["country_pointer"]
                and (observer["slot"] != target["slot"]
                     or observer["fullref"] != target["fullref"])):
            raise _Unknown("BINDING_ALIAS")
        raw_inputs["observer_binding_validation"] = None
        raw_inputs["target_binding_validation"] = None
        binding_evidence = _binding_evidence(trace, module_base, observer, target)
        raw_inputs["observer_binding_validation"] = binding_evidence["observer"]
        raw_inputs["target_binding_validation"] = binding_evidence["target"]
        raw_inputs["country_database"] = {
            key: value for key, value in binding_evidence.items()
            if key not in ("observer", "target")
        }

        world_cell = _checked_add(module_base, WORLD_GLOBAL_RVA, 8)
        world = _pointer(trace.u64(world_cell, "world.global_pointer"), "WORLD")
        if world in (module_base, observer["country_pointer"], target["country_pointer"]):
            raise _Unknown("WORLD_POINTER_ALIAS")
        raw_inputs["world"] = {"global_cell": hex(world_cell), "pointer": hex(world)}

        membership = _ledger_membership.read_membership(
            lambda address, size, label: trace.exact(address, size, label),
            world, target_binding)
        raw_inputs["ledger_membership"] = deepcopy(membership)
        if not _ledger_membership.validate_membership(membership):
            raise _Unknown("LEDGER_MEMBERSHIP_RECORD_INVALID")
        if membership.get("status") != "known":
            raise _Unknown("LEDGER_CANDIDATE_MEMBERSHIP_UNKNOWN")
        if membership.get("member") is not True:
            return decision(False, "TARGET_NOT_LEDGER_CANDIDATE",
                            "target_not_in_world_country_candidate_array")
        raw_inputs["predicate_path"].append("target_in_world_country_candidate_array")

        observer_byte6 = (observer["fullref"] >> 48) & 0xFF
        outer_gate: dict[str, Any] = {
            "observer_fullref_byte6": observer_byte6,
            "observer_fullref_raw_hex": observer["fullref_raw_hex"],
            "options_pointer_cell": hex(_checked_add(world, WORLD_OPTIONS_POINTER_OFFSET, 8)),
            "option_index": OPTIONS_QUALITY_INDEX,
            "option_stride": OPTIONS_U32_STRIDE,
            "option_value": None,
            "passed": None,
            "selected_branch": None,
        }
        if observer_byte6 == 7:
            outer_gate.update({"passed": True, "selected_branch": "observer_byte6_is_7"})
        else:
            options_pointer = _pointer(
                trace.u64(_checked_add(world, WORLD_OPTIONS_POINTER_OFFSET, 8),
                          "world.quality_options_pointer"), "OPTIONS")
            if options_pointer in (module_base, world, observer["country_pointer"],
                                   target["country_pointer"]):
                raise _Unknown("OPTIONS_POINTER_ALIAS")
            option_address = _checked_add(options_pointer,
                                          OPTIONS_QUALITY_INDEX * OPTIONS_U32_STRIDE, 4)
            option_value = trace.u32(option_address, "options.quality_option_17_u32")
            outer_gate.update({"options_pointer": hex(options_pointer),
                               "option_address": hex(option_address),
                               "option_value": option_value,
                               "option_raw_hex": option_value.to_bytes(4, "little").hex(),
                               "passed": option_value == 0,
                               "selected_branch": "option_17_zero" if option_value == 0
                               else "option_17_nonzero"})
        raw_inputs["gates"]["outer"] = outer_gate
        if not outer_gate["passed"]:
            return decision(False, "OUTER_QUALITY_GATE_DENIED", "outer_gate_false")
        raw_inputs["predicate_path"].append(f"outer_gate:{outer_gate['selected_branch']}")

        page_enable_address = _checked_add(module_base, WORLD_PAGE_ENABLE_RVA, 1)
        tls_state_address = _checked_add(module_base, WORLD_PAGE_TLS_RVA, 1)
        page_enable = trace.u8(page_enable_address, "quality.global_page_enable_u8")
        tls_state = trace.u8(tls_state_address, "quality.global_tls_state_u8")
        page_gate = {
            "enable_address": hex(page_enable_address), "enable_u8": page_enable,
            "tls_state_address": hex(tls_state_address), "tls_state_u8": tls_state,
            "passed": page_enable != 0 and tls_state == 0,
            "known_positive_only": True,
        }
        raw_inputs["gates"]["global_page"] = page_gate
        if not page_gate["passed"]:
            raise _Unknown("GLOBAL_PAGE_GATE_REQUIRES_TLS")
        raw_inputs["predicate_path"].append("global_page_gate_positive")

        for name, rva in SPECIAL_TARGET_SLOT_RVAS:
            address = _checked_add(module_base, rva, 4)
            special_slot = trace.i32(address, f"quality.{name}.slot_i32")
            item = {"name": name, "rva": hex(rva), "address": hex(address),
                    "slot_i32": special_slot}
            raw_inputs["special_target_slots"].append(item)
            if target["slot"] == special_slot:
                return decision(False, "TARGET_SPECIAL_SLOT_DENIED",
                                f"target_matches_{name}")
            raw_inputs["predicate_path"].append(f"target_differs_from_{name}")

        capital_cell = _checked_add(target["country_pointer"], COUNTRY_CAPITAL_OFFSET, 8)
        capital = _pointer(trace.u64(capital_cell, "target.capital_pointer"), "TARGET_CAPITAL")
        if capital in (module_base, world, target["country_pointer"],
                       observer["country_pointer"]):
            raise _Unknown("TARGET_CAPITAL_POINTER_ALIAS")
        flags_address = _checked_add(capital, CAPITAL_QUALITY_FLAGS_OFFSET, 1)
        flags = trace.u8(flags_address, "target.capital.quality_flags_u8")
        capital_gate = {"pointer_cell": hex(capital_cell), "pointer": hex(capital),
                        "flags_address": hex(flags_address), "flags_u8": flags,
                        "flag_bit": QUALITY_FLAG_BIT,
                        "flag_set": bool(flags & QUALITY_FLAG_BIT)}
        raw_inputs["gates"]["target_capital"] = capital_gate
        if flags & QUALITY_FLAG_BIT == 0:
            capital_gate.update({"observer_fallback": "not_needed", "passed": True})
            raw_inputs["predicate_path"].append("capital_quality_flag_clear")
            return decision(True, "", "quality_permission_admitted")
        raw_inputs["predicate_path"].append("capital_quality_flag_set_observer_fallback")

        observer_ref_high32 = (observer["fullref"] >> 32) & 0xFFFFFFFF
        high32_byte24 = (observer_ref_high32 >> 24) & 0xFF
        high32_byte16 = (observer_ref_high32 >> 16) & 0xFF
        ref_bypass = high32_byte24 == 0 or high32_byte16 == 7
        capital_gate["observer_ref_fallback"] = {
            "high32": hex(observer_ref_high32),
            "high32_byte24": high32_byte24,
            "high32_byte16": high32_byte16,
            "passed": ref_bypass,
        }
        if ref_bypass:
            capital_gate.update({"observer_fallback": "native_observer_ref", "passed": True})
            raw_inputs["predicate_path"].append("observer_ref_fallback_admitted")
            return decision(True, "", "quality_permission_admitted")

        observer_slot = _signed_i16((observer["fullref"] >> 32) & 0xFFFF)
        capital_gate["observer_slot_signed_i16"] = observer_slot
        if not 0 <= observer_slot < MAX_COUNTRY_SLOTS:
            raise _Unknown("OBSERVER_SLOT_OUT_OF_RANGE")
        bitset_cell = _checked_add(capital, CAPITAL_OBSERVER_BITSET_OFFSET, 8)
        bitset = _pointer(trace.u64(bitset_cell,
                                   "target.capital.quality_observer_bitset_pointer"),
                          "QUALITY_OBSERVER_BITSET", alignment=4)
        if bitset in (module_base, world, capital, target["country_pointer"],
                      observer["country_pointer"], bitset_cell):
            raise _Unknown("QUALITY_OBSERVER_BITSET_POINTER_ALIAS")
        word_index = observer_slot >> 5
        bit_index = observer_slot & 31
        word_address = _checked_add(bitset, word_index * OBSERVER_BITSET_WORD_STRIDE, 4)
        if word_address & 3:
            raise _Unknown("QUALITY_OBSERVER_BITSET_WORD_ALIGNMENT_INVALID")
        word = trace.u32(word_address, "target.capital.quality_observer_bitset_word_u32")
        bit = (word >> bit_index) & 1
        capital_gate.update({
            "observer_fallback": "capital_discovery_bitset",
            "bitset_pointer_cell": hex(bitset_cell),
            "bitset_pointer": hex(bitset),
            "word_index": word_index,
            "bit_index": bit_index,
            "word_address": hex(word_address),
            "word_u32": word,
            "bit_value": bit,
            "passed": bool(bit),
        })
        if bit:
            raw_inputs["predicate_path"].append("capital_observer_bit_set")
            return decision(True, "", "quality_permission_admitted")
        raw_inputs["predicate_path"].append("capital_observer_bit_clear")
        return decision(False, "CAPITAL_OBSERVER_BIT_CLEAR", "quality_permission_denied")
    except _Unknown as exc:
        return unknown(exc.reason)
    except Exception as exc:
        return unknown(f"INTERNAL_ERROR:{type(exc).__name__}")


def _json_value(value: Any) -> bool:
    if value is None or type(value) in (str, bool, int):
        return True
    if isinstance(value, list):
        return all(_json_value(item) for item in value)
    if isinstance(value, dict):
        return all(type(key) is str and _json_value(item) for key, item in value.items())
    return False


def validate_permission(record: Any) -> bool:
    """Strictly validate this leaf's JSON-safe evidence and decision shape.

    This validates internal trace arithmetic, not ROM, role, UI rendering, or
    the truth of memory contents outside the supplied trace.
    """
    if not isinstance(record, Mapping) or not _json_value(dict(record)):
        return False
    if record.get("schema") != SCHEMA or record.get("basis") != BASIS:
        return False
    if record.get("actual_UI_observed") is not False or record.get("rendering_observed") is not False:
        return False
    if record.get("complete") is not False:
        return False
    status = record.get("status")
    admitted = record.get("admitted")
    mode = record.get("mode")
    reason = record.get("reason")
    if status == "known":
        if type(admitted) is not bool:
            return False
        if admitted:
            if mode != "projected_quality_ledger_gate" or reason is not None:
                return False
        elif mode != "denied" or not isinstance(reason, str) or not reason:
            return False
    elif status == "unknown":
        if admitted is not None or mode != "unknown" or not isinstance(reason, str) or not reason:
            return False
    else:
        return False

    raw = record.get("raw_inputs")
    if not isinstance(raw, Mapping):
        return False
    reads = raw.get("reads")
    budget = raw.get("budget")
    if not isinstance(reads, list) or not isinstance(budget, Mapping):
        return False
    calls = budget.get("calls")
    requested = budget.get("bytes_requested")
    if type(calls) is not int or type(requested) is not int:
        return False
    if (calls < 0 or requested < 0 or calls > MAX_READ_CALLS
            or requested > MAX_TOTAL_READ_BYTES or calls != sum(
                1 for row in reads if isinstance(row, Mapping)
                and row.get("status") in ("ok", "failed"))):
        return False
    if requested != sum(row.get("size", -1) for row in reads
                        if isinstance(row, Mapping)
                        and row.get("status") in ("ok", "failed")):
        return False
    if budget.get("max_calls") != MAX_READ_CALLS or type(budget.get("max_calls")) is not int:
        return False
    if budget.get("max_bytes") != MAX_TOTAL_READ_BYTES or type(budget.get("max_bytes")) is not int:
        return False
    if (budget.get("max_single_read_bytes") != MAX_SINGLE_READ_BYTES
            or type(budget.get("max_single_read_bytes")) is not int):
        return False
    for index, row in enumerate(reads, 1):
        if not isinstance(row, Mapping):
            return False
        if (type(row.get("ordinal")) is not int or row.get("ordinal") != index
                or type(row.get("size")) is not int
                or not 0 < row["size"] <= MAX_SINGLE_READ_BYTES
                or not isinstance(row.get("address"), str)
                or not isinstance(row.get("label"), str)):
            return False
        try:
            address = int(row["address"], 16)
        except (ValueError, TypeError):
            return False
        if (address < MIN_USER_ADDRESS or address + row["size"] > MAX_USER_ADDRESS_EXCLUSIVE):
            return False
        if row.get("status") == "ok":
            raw_hex = row.get("raw_hex")
            if not isinstance(raw_hex, str) or len(raw_hex) != row["size"] * 2:
                return False
            try:
                bytes.fromhex(raw_hex)
            except ValueError:
                return False
            decode = row.get("decode")
            value = row.get("value")
            if decode in ("u8", "u32", "u64", "i32"):
                expected_size = {"u8": 1, "u32": 4, "u64": 8, "i32": 4}[decode]
                if row["size"] != expected_size:
                    return False
                if decode == "u64":
                    if type(value) is not str:
                        return False
                    try:
                        parsed = int(value, 16)
                    except ValueError:
                        return False
                    if parsed != int.from_bytes(bytes.fromhex(raw_hex), "little"):
                        return False
                else:
                    if type(value) is not int:
                        return False
                    parsed = int.from_bytes(bytes.fromhex(raw_hex), "little",
                                            signed=(decode == "i32"))
                    if parsed != value:
                        return False
        elif row.get("status") == "failed":
            if not isinstance(row.get("error_type"), str):
                return False
        elif row.get("status") == "rejected":
            # Rejected budget requests are evidence, not actual RPM calls.
            if row.get("reason") != "READ_BUDGET_EXCEEDED":
                return False
        else:
            return False

    # A known decision must have a complete local trace for the branch it used.
    # Unknown records may stop early, but may never claim a passed gate without
    # its exact operand evidence.
    gates = raw.get("gates")
    if not isinstance(gates, Mapping):
        return False
    # Unknown is intentionally non-authorizing.  Its trace and byte arithmetic
    # were checked above; a short/error path may legitimately stop before the
    # current gate has been fully materialized.
    if status == "unknown":
        return admitted is None and mode == "unknown" and isinstance(reason, str) and bool(reason)
    by_label: dict[str, Mapping[str, Any]] = {}
    for row in reads:
        label = row.get("label")
        if label in by_label:
            return False
        by_label[label] = row

    def decoded(label: str, kind: str) -> int | None:
        row = by_label.get(label)
        if not isinstance(row, Mapping) or row.get("status") != "ok" or row.get("decode") != kind:
            return None
        value = row.get("value")
        return value if type(value) is int else None

    def address_is(label: str, address: int) -> bool:
        row = by_label.get(label)
        return isinstance(row, Mapping) and row.get("address") == hex(address)

    try:
        base_text = raw.get("module_base")
        if not isinstance(base_text, str):
            return False
        base = int(base_text, 16)
        observer = record.get("observer")
        target = record.get("target")
        if not isinstance(observer, Mapping) or not isinstance(target, Mapping):
            return False
        observer_ref = int(observer.get("fullref"), 16)
        target_ref = int(target.get("fullref"), 16)
        observer_slot = observer.get("slot")
        target_slot = target.get("slot")
        if (type(observer_slot) is not int or type(target_slot) is not int
                or not isinstance(observer.get("tag"), str)
                or not isinstance(target.get("tag"), str)):
            return False
        for binding, ref, slot in ((observer, observer_ref, observer_slot),
                                   (target, target_ref, target_slot)):
            raw_hex = binding.get("fullref_raw_hex")
            if (not isinstance(raw_hex, str)
                    or raw_hex.lower() != ref.to_bytes(8, "little").hex()
                    or ((ref >> 32) & 0xFFFF) != slot
                    or ((ref >> 24) & 0xFF) != 0
                    or (ref & 0xFFFFFF).to_bytes(3, "little").decode("ascii", "ignore")
                    != binding.get("tag")):
                return False

        # The known binding validation reads must form an exact live table and
        # fullref echo for both supplied rows.
        binding_validation = (raw.get("observer_binding_validation"),
                              raw.get("target_binding_validation"))
        for role, binding, expected_ref in zip(("observer", "target"),
                                               binding_validation,
                                               (observer_ref, target_ref)):
            if not isinstance(binding, Mapping):
                return False
            slot = observer_slot if role == "observer" else target_slot
            row = by_label.get(f"bindings.{role}.fullref")
            table_row = by_label.get(f"bindings.{role}.table_entry")
            if (not isinstance(row, Mapping) or row.get("status") != "ok"
                    or row.get("value") != hex(expected_ref)
                    or not isinstance(table_row, Mapping) or table_row.get("status") != "ok"
                    or table_row.get("value") != binding.get("country_pointer")
                    or binding.get("slot") != slot
                    or binding.get("tag") != record[role].get("tag")
                    or binding.get("fullref") != hex(expected_ref)
                    or binding.get("fullref_raw_hex") != expected_ref.to_bytes(8, "little").hex()):
                return False
            pointer = int(str(binding.get("country_pointer")), 16)
            table = raw.get("country_database")
            if not isinstance(table, Mapping):
                return False
            table_ptr = int(str(table.get("table")), 16)
            if not address_is(f"bindings.{role}.table_entry", table_ptr + slot * 8):
                return False
            if not address_is(f"bindings.{role}.fullref", pointer + COUNTRY_FULLREF_OFFSET):
                return False
        db_global = by_label.get("bindings.database_global")
        table_read = by_label.get("bindings.country_table")
        count_read = by_label.get("bindings.country_count")
        database_summary = raw.get("country_database")
        if (not isinstance(db_global, Mapping) or not isinstance(table_read, Mapping)
                or not isinstance(count_read, Mapping) or not isinstance(database_summary, Mapping)
                or not address_is("bindings.database_global", base + DATABASE_GLOBAL_RVA)):
            return False
        db_ptr = int(str(db_global.get("value")), 16)
        table_ptr = int(str(table_read.get("value")), 16)
        count_value = count_read.get("value")
        if (type(count_value) is not int or not 1 <= count_value <= MAX_COUNTRY_SLOTS
                or database_summary.get("database") != hex(db_ptr)
                or database_summary.get("table") != hex(table_ptr)
                or database_summary.get("count") != count_value
                or type(database_summary.get("count")) is not int
                or table_ptr < MIN_USER_ADDRESS or table_ptr >= MAX_USER_ADDRESS_EXCLUSIVE):
            return False
        if (not address_is("bindings.country_table", db_ptr + DATABASE_TABLE_OFFSET)
                or not address_is("bindings.country_count", db_ptr + DATABASE_COUNT_OFFSET)):
            return False
        if observer_slot >= count_value or target_slot >= count_value:
            return False

        world = raw.get("world")
        world_row = by_label.get("world.global_pointer")
        if (not isinstance(world, Mapping) or not isinstance(world_row, Mapping)
                or not address_is("world.global_pointer", base + WORLD_GLOBAL_RVA)
                or world_row.get("value") != world.get("pointer")):
            return False
        world_ptr = int(str(world.get("pointer")), 16)

        # Membership is a separate prerequisite: the target must be present
        # in the same live world country-row candidate array. Validate the
        # nested leaf by replay and bind every nested raw read to this outer
        # permission trace before accepting either a positive or negative
        # known decision.
        membership = raw.get("ledger_membership")
        if (not isinstance(membership, Mapping)
                or not _ledger_membership.validate_membership(membership)
                or membership.get("status") != "known"):
            return False
        member_world = membership.get("world")
        member_target = membership.get("target")
        target_validation = raw.get("target_binding_validation")
        if (not isinstance(member_world, Mapping)
                or member_world.get("pointer") != hex(world_ptr)
                or not isinstance(member_target, Mapping)
                or not isinstance(target_validation, Mapping)
                or member_target.get("tag") != target.get("tag")
                or member_target.get("slot") != target_slot
                or member_target.get("fullref") != hex(target_ref)
                or member_target.get("fullref_raw_hex") != target_ref.to_bytes(8, "little").hex()
                or member_target.get("country_pointer") != target_validation.get("country_pointer")
                or member_target.get("country_fullref_address") != target_validation.get("fullref_address")):
            return False
        membership_raw = membership.get("raw_inputs")
        membership_reads = membership_raw.get("reads") if isinstance(membership_raw, Mapping) else None
        if not isinstance(membership_reads, list):
            return False
        membership_labels = [row.get("label") for row in membership_reads
                             if isinstance(row, Mapping)]
        if (len(membership_labels) != len(membership_reads)
                or len(set(membership_labels)) != len(membership_labels)):
            return False
        outer_labels = [row.get("label") for row in reads]
        positions = [index for index, label in enumerate(outer_labels)
                     if label in set(membership_labels)]
        if positions and positions != list(range(positions[0], positions[0] + len(positions))):
            return False
        if len(positions) != len(membership_reads):
            return False
        if positions and outer_labels[positions[0]:positions[0] + len(positions)] != membership_labels:
            return False
        for member_row in membership_reads:
            outer_row = by_label.get(member_row.get("label"))
            if not isinstance(outer_row, Mapping):
                return False
            # The nested leaf decodes u64/i32 after the shared outer trace has
            # recorded the same exact bytes, so compare raw read identity and
            # bytes here; nested replay independently validates its decodes.
            for key in ("address", "size", "label", "status", "raw_hex",
                        "reason", "error_type"):
                if key in member_row and outer_row.get(key) != member_row.get(key):
                    return False
        if membership.get("member") is False:
            gate_reads = [row for row in reads if isinstance(row, Mapping)
                          and (str(row.get("label", "")).startswith("quality.")
                               or str(row.get("label", "")).startswith("options.quality_option")
                               or str(row.get("label", "")).startswith("target.capital."))]
            return (status == "known" and admitted is False
                    and reason == "TARGET_NOT_LEDGER_CANDIDATE" and not gate_reads)
        if membership.get("member") is not True:
            return False

        outer = gates.get("outer")
        if not isinstance(outer, Mapping) or type(outer.get("passed")) is not bool:
            return False
        if outer.get("observer_fullref_raw_hex") != observer_ref.to_bytes(8, "little").hex():
            return False
        byte6 = (observer_ref >> 48) & 0xFF
        if outer.get("observer_fullref_byte6") != byte6 or type(outer.get("observer_fullref_byte6")) is not int:
            return False
        if outer.get("options_pointer_cell") != hex(world_ptr + WORLD_OPTIONS_POINTER_OFFSET):
            return False
        if outer.get("option_index") != OPTIONS_QUALITY_INDEX or type(outer.get("option_index")) is not int:
            return False
        if outer.get("option_stride") != OPTIONS_U32_STRIDE or type(outer.get("option_stride")) is not int:
            return False
        if not address_is("world.quality_options_pointer", world_ptr + WORLD_OPTIONS_POINTER_OFFSET):
            if byte6 != 7 or "world.quality_options_pointer" in by_label:
                return False
        if byte6 == 7:
            if (outer.get("passed") is not True
                    or outer.get("selected_branch") != "observer_byte6_is_7"
                    or "options.quality_option_17_u32" in by_label
                    or outer.get("option_value") is not None):
                return False
        else:
            options_read = by_label.get("world.quality_options_pointer")
            option_read = by_label.get("options.quality_option_17_u32")
            if not isinstance(options_read, Mapping):
                return False
            options_ptr = int(str(options_read.get("value")), 16)
            option_value = decoded("options.quality_option_17_u32", "u32")
            if (option_value is None or outer.get("options_pointer") != hex(options_ptr)
                    or outer.get("option_value") != option_value
                    or outer.get("option_raw_hex") != option_value.to_bytes(4, "little").hex()
                    or not address_is("world.quality_options_pointer", world_ptr + WORLD_OPTIONS_POINTER_OFFSET)
                    or not address_is("options.quality_option_17_u32",
                                      options_ptr + OPTIONS_QUALITY_INDEX * OPTIONS_U32_STRIDE)
                    or outer.get("passed") is not (option_value == 0)
                    or outer.get("selected_branch") != ("option_17_zero" if option_value == 0
                                                         else "option_17_nonzero")):
                return False
        if not outer["passed"]:
            return admitted is False and reason == "OUTER_QUALITY_GATE_DENIED"

        page = gates.get("global_page")
        if not isinstance(page, Mapping):
            return False
        enable = decoded("quality.global_page_enable_u8", "u8")
        tls = decoded("quality.global_tls_state_u8", "u8")
        if (enable is None or tls is None
                or not address_is("quality.global_page_enable_u8", base + WORLD_PAGE_ENABLE_RVA)
                or not address_is("quality.global_tls_state_u8", base + WORLD_PAGE_TLS_RVA)
                or page.get("enable_u8") != enable or type(page.get("enable_u8")) is not int
                or page.get("tls_state_u8") != tls or type(page.get("tls_state_u8")) is not int
                or page.get("enable_address") != hex(base + WORLD_PAGE_ENABLE_RVA)
                or page.get("tls_state_address") != hex(base + WORLD_PAGE_TLS_RVA)
                or page.get("passed") is not (enable != 0 and tls == 0)):
            return False
        if not page["passed"]:
            return False

        special = raw.get("special_target_slots")
        if not isinstance(special, list):
            return False
        for index, (name, rva) in enumerate(SPECIAL_TARGET_SLOT_RVAS):
            label = f"quality.{name}.slot_i32"
            value = decoded(label, "i32")
            if value is None or not address_is(label, base + rva):
                return False
            if index >= len(special) or not isinstance(special[index], Mapping):
                return False
            item = special[index]
            if (item.get("name") != name or item.get("rva") != hex(rva)
                    or item.get("address") != hex(base + rva)
                    or item.get("slot_i32") != value or type(item.get("slot_i32")) is not int):
                return False
            if target_slot == value:
                return (status == "known" and admitted is False
                        and reason == "TARGET_SPECIAL_SLOT_DENIED"
                        and not any(label.startswith("target.capital") for label in by_label))
        if len(special) != len(SPECIAL_TARGET_SLOT_RVAS):
            return False
        cap = gates.get("target_capital")
        if not isinstance(cap, Mapping):
            return False
        target_binding_check = raw.get("target_binding_validation")
        target_ptr = int(str(target_binding_check.get("country_pointer")), 16)
        cap_read = by_label.get("target.capital_pointer")
        flags_read = by_label.get("target.capital.quality_flags_u8")
        flags_value = decoded("target.capital.quality_flags_u8", "u8")
        if not isinstance(cap_read, Mapping):
            return False
        capital_pointer = int(str(cap_read.get("value")), 16)
        expected_flags_address = capital_pointer + CAPITAL_QUALITY_FLAGS_OFFSET
        if (not isinstance(cap_read, Mapping) or not isinstance(flags_read, Mapping)
                or cap_read.get("address") != hex(target_ptr + COUNTRY_CAPITAL_OFFSET)
                or capital_pointer < MIN_USER_ADDRESS
                or capital_pointer >= MAX_USER_ADDRESS_EXCLUSIVE
                or flags_read.get("address") != hex(expected_flags_address)
                or not isinstance(flags_value, int)
                or cap.get("pointer_cell") != hex(target_ptr + COUNTRY_CAPITAL_OFFSET)
                or cap.get("pointer") != hex(capital_pointer)
                or cap.get("flags_address") != flags_read.get("address")
                or cap.get("flags_address") != hex(expected_flags_address)
                or cap.get("flags_u8") != flags_value or type(cap.get("flags_u8")) is not int
                or cap.get("flag_bit") != QUALITY_FLAG_BIT or type(cap.get("flag_bit")) is not int
                or cap.get("flag_set") is not bool(flags_value & QUALITY_FLAG_BIT)):
            return False
        if flags_value & QUALITY_FLAG_BIT == 0:
            return (status == "known" and admitted is True and reason is None
                    and cap.get("passed") is True
                    and cap.get("observer_fallback") == "not_needed")
        if admitted is True and reason is not None:
            return False
        if admitted is False and reason == "CAPITAL_OBSERVER_BIT_CLEAR":
            bit_value = cap.get("bit_value")
            return (type(bit_value) is int and bit_value == 0 and cap.get("passed") is False
                    and cap.get("observer_fallback") == "capital_discovery_bitset")
        fallback = cap.get("observer_ref_fallback")
        if isinstance(fallback, Mapping):
            expected_high32 = (observer_ref >> 32) & 0xFFFFFFFF
            byte24 = (expected_high32 >> 24) & 0xFF
            byte16 = (expected_high32 >> 16) & 0xFF
            if (fallback.get("high32") != hex(expected_high32)
                    or fallback.get("high32_byte24") != byte24
                    or type(fallback.get("high32_byte24")) is not int
                    or fallback.get("high32_byte16") != byte16
                    or type(fallback.get("high32_byte16")) is not int
                    or fallback.get("passed") is not (byte24 == 0 or byte16 == 7)):
                return False
            if fallback.get("passed") is True:
                return admitted is True and reason is None
        bitset_read = by_label.get("target.capital.quality_observer_bitset_pointer")
        bit_read = by_label.get("target.capital.quality_observer_bitset_word_u32")
        bitset_ptr = cap.get("bitset_pointer")
        word = decoded("target.capital.quality_observer_bitset_word_u32", "u32")
        slot = _signed_i16((observer_ref >> 32) & 0xFFFF)
        if not 0 <= slot < MAX_COUNTRY_SLOTS:
            return False
        if (not isinstance(bitset_read, Mapping) or not isinstance(bit_read, Mapping)
                or bitset_read.get("address") != hex(int(str(cap.get("pointer")), 16)
                                                       + CAPITAL_OBSERVER_BITSET_OFFSET)
                or cap.get("observer_slot_signed_i16") != slot
                or type(cap.get("observer_slot_signed_i16")) is not int
                or cap.get("word_index") != (slot >> 5)
                or type(cap.get("word_index")) is not int
                or cap.get("bit_index") != (slot & 31)
                or type(cap.get("bit_index")) is not int
                or type(word) is not int):
            return False
        try:
            word_address = int(str(cap.get("word_address")), 16)
            bitset_pointer = int(str(bitset_ptr), 16)
        except (TypeError, ValueError):
            return False
        bit = (word >> (slot & 31)) & 1
        if (bitset_read.get("value") != hex(bitset_pointer)
                or bit_read.get("address") != hex(word_address)
                or word_address != bitset_pointer + (slot >> 5) * 4
                or cap.get("word_u32") != word or type(cap.get("word_u32")) is not int
                or cap.get("bit_value") != bit or type(cap.get("bit_value")) is not int
                or cap.get("passed") is not bool(bit)):
            return False
        return status == "known" and admitted is bool(bit) and reason == (
            None if bit else "CAPITAL_OBSERVER_BIT_CLEAR")
    except (KeyError, TypeError, ValueError, OverflowError):
        return False
    # Do not let an unknown record smuggle a positive public permission.
    return True


__all__ = ["SCHEMA", "BASIS", "read_permission", "validate_permission"]
