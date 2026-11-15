"""Bounded, read-only pair-scoped retained-result observations.

This module is deliberately a research reader.  It never calls a game
function, constructs a peace offer, hooks an entry point, or publishes an
InformationService value.  It follows the already audited country relation
layout and the bounded retained-result layouts from the fixed 1.37.4 build.

The result of :func:`capture` is an observation of a retained native subset.
It is not a global war list, a complete battle history, a visibility claim,
or a stable public war identifier.  Native pointers and raw bytes are kept in
this work-stage report so a later reviewer can audit them; callers must not
expose them as API identifiers.
"""
from __future__ import annotations

import copy
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence

if __package__ in (None, ""):
    # Keep the standalone research CLI usable from the repository root.  The
    # production bridge modules remain imported normally when run as a module.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bridge.information import localization_memory as _loc
from bridge.information import mission_memory as _mm


EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_VERSION = "1.37.4"
EXPECTED_ACTOR = "FRA"
EXPECTED_DLL_SHA256 = "d80ef39d66d263788c0af4df0892b4ff781e5e3b3f9aea7ebe33759327e457db"
PROCESS_ACCESS = _mm.PROCESS_ACCESS  # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
MAX_USER_ADDRESS = _mm.MAX_USER_ADDRESS
MAX_TOTAL_RPM = 4 * 1024 * 1024
MAX_SINGLE_RPM = 64 * 1024
MAX_RESULTS = 128
MAX_WAR_REFERENCES = 32
MAX_RELATION_ROWS = 256
MAX_SIDE_MEMBERS = 256
MAX_VECTOR_ENTRIES = 4096
MAX_HISTORY_NODES = 2048
MAX_HISTORY_DEPTH = 16
MAX_SSO_CAPACITY = 128 * 1024
MAX_LOADED_MODULES = 1024
GAME_RVA = _loc.GAME_RVA
DATABASE_RVA = _loc.DATABASE_RVA
GAME_DATE_OFFSET = _loc.GAME_DATE_OFFSET
COUNTRY_TABLE_OFFSET = 0x118
COUNTRY_HANDLE_OFFSET = 0x20
COUNTRY_RELATION_ROWS_OFFSET = 0x1548
COUNTRY_RELATION_COUNT_OFFSET = 0x1554
RELATION_ROW_STRIDE = 16
RELATION_ROW_COUNTERPART_OFFSET = 0
RELATION_ROW_REFERENCE_OFFSET = 8

# The fixed-build result and history contracts.  These are PE RVAs, never
# runtime addresses.  The bytes were read from the checked 1.37.4 PE and are
# also checked in process memory on every snapshot.
RESULT_RETAIN_RVA = 0xD89A80
HISTORY_DATE_RVA = 0x7E7FB0
RESULT_INIT_RVA = 0xD8FF10
RESULT_VTABLE_RVA = 0x1C448D0
SIDE_VTABLE_RVA = 0x1C44910
RESULT_RETAIN_GUARD = bytes.fromhex(
    "4584c00f84ab00000048895c24084889542410574883ec20488bd9488bfa4881"
)
HISTORY_DATE_GUARD = bytes.fromhex(
    "4889742410574883ec20488b01488bfa488bf1ff909000000084c0753c48895c"
)
RESULT_INIT_GUARD = bytes.fromhex(
    "48895c241048896c2418565741564883ec204c8bf1498bf8b940000000488beae8fb32ca00488bd84889442440c74008"
)
CODE_GUARDS: tuple[tuple[str, int, bytes], ...] = (
    ("result_retainer_d89a80", RESULT_RETAIN_RVA, RESULT_RETAIN_GUARD),
    ("history_date_setter_7e7fb0", HISTORY_DATE_RVA, HISTORY_DATE_GUARD),
    ("retained_result_initializer_d8ff10", RESULT_INIT_RVA, RESULT_INIT_GUARD),
)

# The pause/speed reader is an already recorded pure-RPM accessor.  It is a
# state guard only; the reader never calls the getter.  The getter bytes are
# checked to ensure that the two indirect fields below are interpreted only in
# the audited build.
CONTROL_GETTER_RVA = 0x802500
CONTROL_GETTER_GUARD = bytes.fromhex(
    "488b8118040000c3cccccccccccccccc0fb68188050000c3cccccccccccccccc"
)
CONTROL_SERVER_OFFSET = 0x1E00
CONTROL_SERVER_VTABLE_SPEED_OFFSET = 0x100
CONTROL_SERVER_PAUSE_OFFSET = 0x418
CONTROL_SPEED_OFFSET = 0x1E08
CONTROL_PAUSE_FLAG_OFFSET = 0x48

RESULT_SIZE = 0x138
RESULT_SIDE_A_OFFSET = 0x10
RESULT_SIDE_B_OFFSET = 0x88
RESULT_FLAG_OFFSET = 0x108
RESULT_AUX0_OFFSET = 0x100
RESULT_AUX1_OFFSET = 0x104
RESULT_PROVINCE_OFFSET = 0x110
RESULT_NAME_OFFSET = 0x118
RESULT_NAME_LENGTH_OFFSET = 0x128
RESULT_NAME_CAPACITY_OFFSET = 0x130
SIDE_SIZE = 0x78
SIDE_COUNTRY_OFFSET = 0x10
SIDE_COMMANDER_OFFSET = 0x18
SIDE_SCALAR_OFFSETS: tuple[tuple[str, int], ...] = (
    ("infantry", 0x38),
    ("cavalry", 0x3C),
    ("artillery", 0x40),
    ("heavy", 0x44),
    ("light", 0x48),
    ("galley", 0x4C),
    ("transport", 0x50),
    ("losses", 0x54),
    ("war_goal", 0x74),
)

HISTORY_ROOT_OFFSET = 0x108
HISTORY_HEADER_SIZE = 0x40
HISTORY_DATE_OFFSET = 0x10
HISTORY_CHILDREN_OFFSET = 0x20
HISTORY_VTABLE_GROUP_RVA = 0x1D21400
HISTORY_VTABLE_EVENT_RVA = 0x1D20CB0
HISTORY_ROOT_VTABLE_RVA = 0x1D20BE0
HISTORY_ROOT_SLOT_RVAS = {
    0x90: 0x8F440,
    0x98: 0x7E7CC0,
    0xA0: 0x7E7D00,
}
HISTORY_NODE_CHILD_OFFSET = 0x0
HISTORY_NODE_NEXT_OFFSET = 0x10
HISTORY_CHILD_DATE_OFFSET = 0x10
HISTORY_EVENT_OWNER_OFFSET = 0x38
HISTORY_EVENT_RESULT_OFFSET = 0x40


class ProbeError(RuntimeError):
    """A bounded observation cannot be completed safely."""


class ProfileError(RuntimeError):
    """Compatibility name used by the other information readers."""


# Re-export the existing process seams.  They are intentionally module-local
# aliases so tests and a future adapter can replace this reader's seam without
# monkey-patching an unrelated production module.
_load_installation = _loc._load_installation
_configure_kernel = _loc._configure_kernel
_capture_identity = _loc._capture_identity
_close_process_handle = _loc._close_process_handle
_read_pe_rva_bytes = _loc._read_pe_rva_bytes
_sha256_file = _loc._sha256_file
_country_scan = _mm._country_scan


def _hex(value: int | None) -> str | None:
    return hex(value) if isinstance(value, int) else None


def _address(value: int | None, module_base: int | None = None, *, rva: int | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"va": _hex(value), "rva": _hex(rva), "rva_identity": "contract_module_rva" if rva is not None else "not_applicable"}
    if rva is None and isinstance(value, int) and isinstance(module_base, int) and module_base <= value < module_base + 0x40000000:
        result.update(rva=hex(value - module_base), rva_identity="module_relative_candidate")
    elif rva is None and isinstance(value, int):
        result["rva_identity"] = "runtime_va_or_heap"
    return result


def _valid_pointer(value: Any, *, aligned: bool = True) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0x10000 <= value < MAX_USER_ADDRESS
        and (not aligned or value % 8 == 0)
    )


def _tag(value: int) -> str | None:
    raw = (value & 0xFFFFFF).to_bytes(3, "little")
    if all(0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A or 0x30 <= b <= 0x39 for b in raw):
        return raw.decode("ascii")
    return None


def _parse_installation_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ProbeError(f"{label}_invalid")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise ProbeError(f"{label}_invalid") from exc
    raise ProbeError(f"{label}_invalid")


class AddressBoundedRPM:
    """ReadProcessMemory wrapper with address and 4 MiB total limits."""

    def __init__(self, kernel: Any, handle: Any, module_base: int):
        self.kernel = kernel
        self.handle = handle
        self.module_base = module_base
        self.bytes_requested = 0
        self.calls = 0
        self.read_log: list[dict[str, Any]] = []

    def read(self, address: int, size: int, label: str, *, aligned: bool = False) -> bytes:
        if not isinstance(address, int) or isinstance(address, bool) or address < 0x10000:
            raise ProbeError(f"invalid_address:{label}")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0 or size > MAX_SINGLE_RPM:
            raise ProbeError(f"invalid_size:{label}")
        if aligned and address % 8:
            raise ProbeError(f"invalid_alignment:{label}")
        if address + size > MAX_USER_ADDRESS:
            raise ProbeError(f"address_range_overflow:{label}")
        if self.bytes_requested + size > MAX_TOTAL_RPM:
            raise ProbeError("RPM_TOTAL_BUDGET_EXCEEDED")
        self.bytes_requested += size
        self.calls += 1
        entry: dict[str, Any] = {"label": label, "address": hex(address), "size": size, "status": "requested"}
        self.read_log.append(entry)
        buffer = C.create_string_buffer(size)
        actual = C.c_size_t()
        try:
            ok = self.kernel.ReadProcessMemory(self.handle, C.c_void_p(address), buffer, size, C.byref(actual))
        except Exception as exc:
            entry.update(status="error", error=f"{type(exc).__name__}:{exc}")
            raise
        if not ok:
            entry.update(status="error", error="ReadProcessMemory_failed")
            raise C.WinError(C.get_last_error())
        if actual.value != size:
            entry.update(status="error", error=f"short_read:{actual.value}/{size}")
            raise ProbeError(f"short_read:{label}:{actual.value}/{size}")
        raw = buffer.raw
        entry.update(status="observed", raw_hex=raw.hex())
        return raw

    def read_code(self, address: int, size: int, label: str) -> bytes:
        return self.read(address, size, label)

    def qword(self, address: int, label: str) -> tuple[int, bytes]:
        raw = self.read(address, 8, label, aligned=True)
        return int.from_bytes(raw, "little"), raw

    def dword(self, address: int, label: str, *, signed: bool = False) -> tuple[int, bytes]:
        raw = self.read(address, 4, label, aligned=False)
        return int.from_bytes(raw, "little", signed=signed), raw


def _module_base(identity_report: Mapping[str, Any], returned: Any = None) -> int:
    """Extract the runtime module base through a replaceable seam."""
    if isinstance(returned, int) and _valid_pointer(returned):
        return returned
    item = identity_report.get("module_base") if isinstance(identity_report, Mapping) else None
    if isinstance(item, Mapping):
        raw = item.get("va")
    else:
        raw = item
    if isinstance(raw, int) and _valid_pointer(raw):
        return raw
    if isinstance(raw, str):
        try:
            value = int(raw, 0)
        except ValueError:
            value = 0
        if _valid_pointer(value):
            return value
    raise ProbeError("module_base_invalid")


def _diff_paths(left: Any, right: Any, path: str = "$") -> list[str]:
    if type(left) is not type(right):
        return [path]
    if isinstance(left, dict):
        out: list[str] = []
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                out.append(f"{path}.{key}")
            else:
                out.extend(_diff_paths(left[key], right[key], f"{path}.{key}"))
        return out
    if isinstance(left, list):
        out = []
        if len(left) != len(right):
            out.append(f"{path}.length")
        for index, (a, b) in enumerate(zip(left, right)):
            out.extend(_diff_paths(a, b, f"{path}[{index}]"))
        return out
    return [] if left == right else [path]


def _static_contract_guard() -> dict[str, Any]:
    checks = {
        "result_retain_rva": RESULT_RETAIN_RVA == 0xD89A80,
        "history_date_rva": HISTORY_DATE_RVA == 0x7E7FB0,
        "result_init_rva": RESULT_INIT_RVA == 0xD8FF10,
        "result_vtable_rva": RESULT_VTABLE_RVA == 0x1C448D0,
        "side_vtable_rva": SIDE_VTABLE_RVA == 0x1C44910,
        "country_table_offset": COUNTRY_TABLE_OFFSET == 0x118,
        "country_relation_layout": (COUNTRY_RELATION_ROWS_OFFSET, COUNTRY_RELATION_COUNT_OFFSET, RELATION_ROW_STRIDE) == (0x1548, 0x1554, 16),
        "result_size": RESULT_SIZE == 0x138,
        "result_side_a_embedded": RESULT_SIDE_A_OFFSET == 0x10,
        "result_side_b_embedded": RESULT_SIDE_B_OFFSET == 0x88,
        "side_embedded_size": SIDE_SIZE == 0x78,
        "side_commander_embedded_sso": SIDE_COMMANDER_OFFSET == 0x18,
        "history_root_embedded": HISTORY_ROOT_OFFSET == 0x108,
        "history_root_vtable_rva": HISTORY_ROOT_VTABLE_RVA == 0x1D20BE0,
        "history_root_slot_90_true": HISTORY_ROOT_SLOT_RVAS.get(0x90) == 0x8F440,
        "sso_capacity_limit": MAX_SSO_CAPACITY == 128 * 1024,
        "side_members_limit": MAX_SIDE_MEMBERS == 256,
    }
    failed = [key for key, value in checks.items() if value is not True]
    return {
        "status": "observed" if not failed else "mismatch",
        "checks": checks,
        "guards": [{"name": name, "rva": hex(rva), "bytes": raw.hex(), "sha256": hashlib.sha256(raw).hexdigest()} for name, rva, raw in CODE_GUARDS],
        "result_vtable_rva": hex(RESULT_VTABLE_RVA),
        "side_vtable_rva": hex(SIDE_VTABLE_RVA),
        "unknown_conditions": ["static_contract_check_failed:" + ",".join(failed)] if failed else [],
        "evidence_kind": "ordinary_static_contract_and_bounded_REA_layout_separate_from_runtime",
    }


def _file_code_guard(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "path": str(path), "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        for name, rva, expected in CODE_GUARDS:
            actual = _read_pe_rva_bytes(path, rva, len(expected))
            result["records"][name] = {"rva": hex(rva), "expected_hex": expected.hex(), "actual_hex": actual.hex(), "sha256": hashlib.sha256(actual).hexdigest()}
            result["checks"][name] = actual == expected
        failed = [key for key, ok in result["checks"].items() if ok is not True]
        result["status"] = "observed" if not failed else "mismatch"
        if failed:
            result["unknown_conditions"].append("file_code_guard_mismatch:" + ",".join(failed))
    except Exception as exc:
        result["unknown_conditions"].append(f"file_code_guard_read_failed:{type(exc).__name__}:{exc}")
    return result


def _runtime_code_guard(reader: AddressBoundedRPM, module_base: int) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "module_base": _address(module_base), "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        for name, rva, expected in CODE_GUARDS:
            address = module_base + rva
            actual = reader.read_code(address, len(expected), f"code_guard.{name}")
            result["records"][name] = {"address": _address(address, module_base, rva=rva), "expected_hex": expected.hex(), "actual_hex": actual.hex(), "sha256": hashlib.sha256(actual).hexdigest()}
            result["checks"][name] = actual == expected
        failed = [key for key, ok in result["checks"].items() if ok is not True]
        result["status"] = "observed" if not failed else "mismatch"
        if failed:
            result["unknown_conditions"].append("runtime_code_guard_mismatch:" + ",".join(failed))
    except Exception as exc:
        result["unknown_conditions"].append(f"runtime_code_guard_read_failed:{type(exc).__name__}:{exc}")
    return result


def _control_state(reader: AddressBoundedRPM, module_base: int, game: int) -> dict[str, Any]:
    """Read only the audited speed/pause fields; never invoke the getter."""
    result: dict[str, Any] = {"status": "unknown", "game": _address(game, module_base), "speed": None, "paused": None, "server": None, "unknown_reason": None}
    try:
        server, server_raw = reader.qword(game + CONTROL_SERVER_OFFSET, "game.control.server")
        if not _valid_pointer(server):
            result["unknown_reason"] = "server_pointer_invalid"
            return result
        vtable, vtable_raw = reader.qword(server, "game.control.server_vtable")
        if not _valid_pointer(vtable):
            result["unknown_reason"] = "server_vtable_invalid"
            return result
        getter, getter_raw = reader.qword(vtable + CONTROL_SERVER_VTABLE_SPEED_OFFSET, "game.control.pause_getter")
        if getter != module_base + CONTROL_GETTER_RVA:
            result["unknown_reason"] = "pause_getter_rva_mismatch"
            result["getter"] = _address(getter, module_base)
            return result
        getter_bytes = reader.read_code(getter, len(CONTROL_GETTER_GUARD), "game.control.pause_getter_code")
        if getter_bytes != CONTROL_GETTER_GUARD:
            result["unknown_reason"] = "pause_getter_code_mismatch"
            result["getter_code_raw_hex"] = getter_bytes.hex()
            return result
        speed, speed_raw = reader.dword(game + CONTROL_SPEED_OFFSET, "game.control.speed", signed=True)
        pause_object, pause_raw = reader.qword(server + CONTROL_SERVER_PAUSE_OFFSET, "game.control.pause_object")
        if not _valid_pointer(pause_object):
            result["unknown_reason"] = "pause_object_invalid"
            return result
        paused_raw = reader.read(pause_object + CONTROL_PAUSE_FLAG_OFFSET, 1, "game.control.paused_flag")
        paused = paused_raw[0]
        result.update({
            "status": "observed",
            "server": {"address": _address(game + CONTROL_SERVER_OFFSET, module_base), "raw_hex": server_raw.hex(), "value": _address(server, module_base)},
            "server_vtable": {"address": _address(server, module_base), "raw_hex": vtable_raw.hex(), "value": _address(vtable, module_base)},
            "getter": _address(getter, module_base, rva=CONTROL_GETTER_RVA),
            "getter_code_raw_hex": getter_bytes.hex(),
            "speed": {"value": speed, "raw_hex": speed_raw.hex(), "address": _address(game + CONTROL_SPEED_OFFSET, module_base)},
            "paused": {"value": paused == 1, "raw": paused, "raw_hex": paused_raw.hex(), "address": _address(pause_object + CONTROL_PAUSE_FLAG_OFFSET, module_base)},
            "pause_object": {"address": _address(server + CONTROL_SERVER_PAUSE_OFFSET, module_base), "raw_hex": pause_raw.hex(), "value": _address(pause_object, module_base)},
        })
        return result
    except Exception as exc:
        result["unknown_reason"] = f"control_read_failed:{type(exc).__name__}:{exc}"
        return result


def _read_country_by_handle(reader: AddressBoundedRPM, database: int, handle: int, label: str) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "handle": _hex(handle), "country_pointer": None, "tag": _tag(handle), "unknown_reason": None}
    if not isinstance(handle, int) or not handle or handle < 0:
        result["unknown_reason"] = "country_handle_invalid"
        return result
    slot = (handle >> 32) & 0xFFFF
    try:
        table, table_raw = reader.qword(database + COUNTRY_TABLE_OFFSET, f"{label}.table")
        if not _valid_pointer(table):
            result["unknown_reason"] = "country_table_pointer_invalid"
            return result
        pointer, pointer_raw = reader.qword(table + slot * 8, f"{label}.table_entry[{slot}]")
        if not _valid_pointer(pointer):
            result["unknown_reason"] = "country_pointer_invalid"
            return result
        identity, identity_raw = reader.qword(pointer + COUNTRY_HANDLE_OFFSET, f"{label}.handle")
        result.update({
            "slot": slot,
            "table": {"address": _address(database + COUNTRY_TABLE_OFFSET, reader.module_base), "raw_hex": table_raw.hex(), "value": _address(table, reader.module_base)},
            "table_entry_raw_hex": pointer_raw.hex(),
            "country_pointer": _address(pointer, reader.module_base),
            "identity_raw_hex": identity_raw.hex(),
            "identity": _hex(identity),
        })
        if identity != handle:
            result["unknown_reason"] = "country_handle_identity_mismatch"
            return result
        result["status"] = "observed"
        return result
    except Exception as exc:
        result["unknown_reason"] = f"country_lookup_failed:{type(exc).__name__}:{exc}"
        return result


def _read_pair_references(reader: AddressBoundedRPM, country_pointer: int, other_handle: int, label: str) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "rows": None, "count": None, "references": [], "complete": False, "truncated": False, "unknown_reason": None}
    try:
        rows, rows_raw = reader.qword(country_pointer + COUNTRY_RELATION_ROWS_OFFSET, f"{label}.rows")
        count, count_raw = reader.dword(country_pointer + COUNTRY_RELATION_COUNT_OFFSET, f"{label}.count", signed=True)
        result.update({"rows": {"address": _address(country_pointer + COUNTRY_RELATION_ROWS_OFFSET, reader.module_base), "raw_hex": rows_raw.hex(), "value": _address(rows, reader.module_base)}, "count": {"address": _address(country_pointer + COUNTRY_RELATION_COUNT_OFFSET, reader.module_base), "raw_hex": count_raw.hex(), "value": count}})
        if count < 0 or count > MAX_RELATION_ROWS:
            result["unknown_reason"] = "relation_count_out_of_bound"
            return result
        if count and not _valid_pointer(rows):
            result["unknown_reason"] = "relation_rows_pointer_invalid"
            return result
        if count == 0:
            result.update(status="observed", complete=True)
            return result
        raw = reader.read(rows, count * RELATION_ROW_STRIDE, f"{label}.rows_window")
        other_slot = (other_handle >> 32) & 0xFFFF
        refs: list[int] = []
        row_records: list[dict[str, Any]] = []
        for index in range(count):
            base = index * RELATION_ROW_STRIDE
            counterpart = int.from_bytes(raw[base:base + 4], "little", signed=True)
            reference = int.from_bytes(raw[base + 8:base + 16], "little")
            row_records.append({"index": index, "counterpart_raw_hex": raw[base:base + 4].hex(), "counterpart": counterpart, "reference_raw_hex": raw[base + 8:base + 16].hex(), "reference": _hex(reference)})
            if counterpart != other_slot:
                continue
            if not reference:
                result["unknown_reason"] = "matched_relation_null_reference"
                return result
            if reference in refs:
                continue
            if len(refs) >= MAX_WAR_REFERENCES:
                result["truncated"] = True
                continue
            refs.append(reference)
        result["row_records"] = row_records
        result["references"] = [{"reference": _address(reference, reader.module_base), "native_reference": _hex(reference)} for reference in refs]
        result["complete"] = not result["truncated"]
        result["status"] = "observed" if result["complete"] else "observed_truncated"
        return result
    except Exception as exc:
        result["unknown_reason"] = f"relation_read_failed:{type(exc).__name__}:{exc}"
        return result


def _decode_sso32(reader: AddressBoundedRPM, address: int, label: str, *, max_length: int = 4096) -> dict[str, Any]:
    """Read an observed String32 without guessing its text encoding."""
    result: dict[str, Any] = {
        "status": "unknown",
        "complete": False,
        "address": _address(address, reader.module_base),
        "header_raw_hex": None,
        "length": None,
        "capacity": None,
        "storage": None,
        "heap_pointer": None,
        "payload_raw_hex": None,
        "nul_terminator_observed": None,
        "text": None,
        "unknown_reason": None,
    }
    try:
        header = reader.read(address, 32, f"{label}.header")
        length = int.from_bytes(header[0x10:0x18], "little")
        capacity = int.from_bytes(header[0x18:0x20], "little")
        result.update({"header_raw_hex": header.hex(), "length": length, "capacity": capacity, "storage": "inline" if capacity < 16 else "heap"})
        if length > max_length:
            result["unknown_reason"] = "string_length_oversize"
            return result
        if capacity > MAX_SSO_CAPACITY:
            result["unknown_reason"] = "string_capacity_oversize"
            return result
        if capacity < length:
            result["unknown_reason"] = "string_capacity_below_length"
            return result
        if capacity >= 16 and capacity < length:
            result["unknown_reason"] = "string_heap_capacity_invalid"
            return result
        if capacity < 16:
            if length > 15:
                result["unknown_reason"] = "string_inline_length_exceeds_15"
                return result
            payload_with_nul = header[:16]
        else:
            heap = int.from_bytes(header[:8], "little")
            result["heap_pointer"] = _address(heap, reader.module_base)
            if not _valid_pointer(heap, aligned=False):
                result["unknown_reason"] = "string_heap_pointer_invalid"
                return result
            # Empty heap strings still require a bounded RPM read of their
            # terminator; manufacturing a NUL would hide a stale pointer.
            payload_with_nul = reader.read(heap, length + 1, f"{label}.payload")
        if len(payload_with_nul) <= length:
            result["unknown_reason"] = "string_nul_not_readable"
            return result
        result["payload_raw_hex"] = payload_with_nul.hex()
        result["nul_terminator_observed"] = payload_with_nul[length] == 0
        if payload_with_nul[length] != 0:
            result["unknown_reason"] = "string_nul_missing"
            return result
        payload = payload_with_nul[:length]
        if b"\x00" in payload:
            result["unknown_reason"] = "string_embedded_nul"
            return result
        # Keep native bytes.  Latin/UTF-8/engine escape decoding is outside the
        # reader contract, so text is intentionally left null even when bytes
        # look printable.
        result.update({"status": "observed", "complete": True, "bytes_hex": payload.hex()})
        return result
    except Exception as exc:
        result["unknown_reason"] = f"string_read_failed:{type(exc).__name__}:{exc}"
        return result


def _read_side(reader: AddressBoundedRPM, module_base: int, database: int, side_pointer: int, label: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "complete": False,
        "address": _address(side_pointer, module_base),
        "vtable": None,
        "country": None,
        "commander": None,
        "fields": {},
        "raw_hex": None,
        "unknown_conditions": [],
    }
    if not _valid_pointer(side_pointer):
        result["unknown_conditions"].append("side_pointer_invalid")
        return result
    try:
        raw = reader.read(side_pointer, SIDE_SIZE, f"{label}.object")
        result["raw_hex"] = raw.hex()
        vtable = int.from_bytes(raw[0:8], "little")
        result["vtable"] = {"address": _address(side_pointer, module_base), "raw_hex": raw[:8].hex(), "value": _address(vtable, module_base, rva=SIDE_VTABLE_RVA if vtable == module_base + SIDE_VTABLE_RVA else None), "matches_expected": vtable == module_base + SIDE_VTABLE_RVA}
        if vtable != module_base + SIDE_VTABLE_RVA:
            result["unknown_conditions"].append("side_vtable_mismatch")
            return result
        country_handle = int.from_bytes(raw[SIDE_COUNTRY_OFFSET:SIDE_COUNTRY_OFFSET + 8], "little")
        country = _read_country_by_handle(reader, database, country_handle, f"{label}.country")
        result["country"] = country
        if country.get("status") != "observed":
            result["unknown_conditions"].append("side_country_identity_unknown")
        for field, offset in SIDE_SCALAR_OFFSETS:
            value = int.from_bytes(raw[offset:offset + 4], "little", signed=True)
            result["fields"][field] = {"raw": value, "raw_hex": raw[offset:offset + 4].hex(), "offset": hex(offset), "signed": True}
        # The commander String32 is embedded at side+0x18.  The first qword
        # there is String32 storage (or inline bytes), not an object pointer.
        commander_address = side_pointer + SIDE_COMMANDER_OFFSET
        result["commander_address"] = _address(commander_address, module_base)
        result["commander"] = _decode_sso32(reader, commander_address, f"{label}.commander")
        if result["country"].get("status") != "observed":
            return result
        if result["commander"].get("status") != "observed":
            result["unknown_conditions"].append("commander_unknown")
            return result
        result["status"] = "observed"
        result["complete"] = True
        return result
    except Exception as exc:
        result["unknown_conditions"].append(f"side_read_failed:{type(exc).__name__}:{exc}")
        return result


def _read_result(reader: AddressBoundedRPM, module_base: int, database: int, result_pointer: int, label: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "complete": False,
        "address": _address(result_pointer, module_base),
        "vtable": None,
        "raw_hex": None,
        "flag": None,
        "aux": None,
        "province_pointer": None,
        "province_id": None,
        "name": None,
        "side_a": None,
        "side_b": None,
        "timeline_date": None,
        "unknown_conditions": [],
    }
    if not _valid_pointer(result_pointer):
        result["unknown_conditions"].append("result_pointer_invalid")
        return result
    try:
        raw = reader.read(result_pointer, RESULT_SIZE, f"{label}.object")
        result["raw_hex"] = raw.hex()
        vtable = int.from_bytes(raw[0:8], "little")
        result["vtable"] = {"raw_hex": raw[:8].hex(), "value": _address(vtable, module_base, rva=RESULT_VTABLE_RVA if vtable == module_base + RESULT_VTABLE_RVA else None), "matches_expected": vtable == module_base + RESULT_VTABLE_RVA}
        if vtable != module_base + RESULT_VTABLE_RVA:
            result["unknown_conditions"].append("result_vtable_mismatch")
            return result
        result["flag"] = {"raw": raw[RESULT_FLAG_OFFSET], "raw_hex": raw[RESULT_FLAG_OFFSET:RESULT_FLAG_OFFSET + 1].hex(), "offset": hex(RESULT_FLAG_OFFSET)}
        result["aux"] = {
            "first": {"raw": int.from_bytes(raw[RESULT_AUX0_OFFSET:RESULT_AUX0_OFFSET + 4], "little", signed=True), "raw_hex": raw[RESULT_AUX0_OFFSET:RESULT_AUX0_OFFSET + 4].hex(), "offset": hex(RESULT_AUX0_OFFSET)},
            "second": {"raw": int.from_bytes(raw[RESULT_AUX1_OFFSET:RESULT_AUX1_OFFSET + 4], "little", signed=True), "raw_hex": raw[RESULT_AUX1_OFFSET:RESULT_AUX1_OFFSET + 4].hex(), "offset": hex(RESULT_AUX1_OFFSET)},
        }
        province_pointer = int.from_bytes(raw[RESULT_PROVINCE_OFFSET:RESULT_PROVINCE_OFFSET + 8], "little")
        result["province_pointer"] = _address(province_pointer, module_base)
        if province_pointer:
            if _valid_pointer(province_pointer):
                province_raw = reader.read(province_pointer + 0x20, 4, f"{label}.province_id")
                result["province_id"] = {"raw": int.from_bytes(province_raw, "little", signed=True), "raw_hex": province_raw.hex(), "offset": hex(0x20), "private_pointer_only": True}
            else:
                result["unknown_conditions"].append("province_pointer_invalid")
        result["name"] = _decode_sso32(reader, result_pointer + RESULT_NAME_OFFSET, f"{label}.name")
        # Both sides are embedded objects in the result.  Reading a qword at
        # +0x10/+0x88 would mistake the side vtable for a heap pointer.
        side_a_pointer = result_pointer + RESULT_SIDE_A_OFFSET
        side_b_pointer = result_pointer + RESULT_SIDE_B_OFFSET
        result["side_a_address"] = _address(side_a_pointer, module_base)
        result["side_b_address"] = _address(side_b_pointer, module_base)
        result["side_a"] = _read_side(reader, module_base, database, side_a_pointer, f"{label}.side_a")
        result["side_b"] = _read_side(reader, module_base, database, side_b_pointer, f"{label}.side_b")
        if result["name"].get("status") != "observed":
            result["unknown_conditions"].append("result_name_unknown")
        if result["side_a"].get("status") != "observed" or result["side_b"].get("status") != "observed":
            result["unknown_conditions"].append("result_side_unknown")
        if not result["unknown_conditions"]:
            result["status"] = "observed"
            result["complete"] = True
        return result
    except Exception as exc:
        result["unknown_conditions"].append(f"result_read_failed:{type(exc).__name__}:{exc}")
        return result


def _read_member_vector(reader: AddressBoundedRPM, database: int, object_pointer: int, begin_offset: int, end_offset: int, capacity_offset: int, label: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "complete": False,
        "begin": None,
        "end": None,
        "capacity": None,
        "count": None,
        "members": [],
        "raw_header_hex": None,
        "unknown_reason": None,
    }
    try:
        begin, begin_raw = reader.qword(object_pointer + begin_offset, f"{label}.begin")
        end, end_raw = reader.qword(object_pointer + end_offset, f"{label}.end")
        capacity, capacity_raw = reader.qword(object_pointer + capacity_offset, f"{label}.capacity")
        result.update({
            "begin": {"address": _address(object_pointer + begin_offset, reader.module_base), "raw_hex": begin_raw.hex(), "value": _address(begin, reader.module_base)},
            "end": {"address": _address(object_pointer + end_offset, reader.module_base), "raw_hex": end_raw.hex(), "value": _address(end, reader.module_base)},
            "capacity": {"address": _address(object_pointer + capacity_offset, reader.module_base), "raw_hex": capacity_raw.hex(), "value": _address(capacity, reader.module_base)},
            "raw_header_hex": (begin_raw + end_raw + capacity_raw).hex(),
        })
        if end < begin or capacity < end or (end - begin) % 8:
            result["unknown_reason"] = "member_vector_bounds_invalid"
            return result
        count = (end - begin) // 8
        result["count"] = count
        if count > MAX_SIDE_MEMBERS:
            result["unknown_reason"] = "member_vector_count_out_of_bound"
            return result
        if count and not _valid_pointer(begin):
            result["unknown_reason"] = "member_vector_begin_invalid"
            return result
        if count == 0:
            result.update(status="observed", complete=True)
            return result
        raw = reader.read(begin, count * 8, f"{label}.members")
        members: list[dict[str, Any]] = []
        seen_handles: set[int] = set()
        for index in range(count):
            member_raw = raw[index * 8:(index + 1) * 8]
            handle = int.from_bytes(member_raw, "little")
            if handle in seen_handles:
                result["unknown_reason"] = "member_vector_duplicate_full_handle"
                result["members"] = members
                return result
            seen_handles.add(handle)
            lookup = _read_country_by_handle(reader, database, handle, f"{label}.member[{index}]")
            members.append({"index": index, "raw_hex": member_raw.hex(), "handle": _hex(handle), "tag": _tag(handle), "country_lookup": lookup})
            if lookup.get("status") != "observed":
                result["unknown_reason"] = "member_country_lookup_unknown"
                result["members"] = members
                return result
        result.update(status="observed", complete=True, members=members)
        return result
    except Exception as exc:
        result["unknown_reason"] = f"member_vector_read_failed:{type(exc).__name__}:{exc}"
        return result


def _handles(vector: Mapping[str, Any]) -> list[int]:
    out: list[int] = []
    for item in vector.get("members", []) if isinstance(vector, Mapping) else []:
        if isinstance(item, Mapping):
            raw = item.get("handle")
            if isinstance(raw, str):
                try:
                    out.append(int(raw, 0))
                except ValueError:
                    pass
    return out


def _read_result_collection(reader: AddressBoundedRPM, module_base: int, database: int, context_pointer: int, limit: int, label: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "complete": False,
        "context": _address(context_pointer, module_base),
        "vector": None,
        "result_pointers": [],
        "results": [],
        "truncated": False,
        "unknown_reason": None,
    }
    if not _valid_pointer(context_pointer):
        result["unknown_reason"] = "history_context_invalid"
        return result
    try:
        begin, begin_raw = reader.qword(context_pointer + 0xF0, f"{label}.vector.begin")
        end, end_raw = reader.qword(context_pointer + 0xF8, f"{label}.vector.end")
        capacity, capacity_raw = reader.qword(context_pointer + 0x100, f"{label}.vector.capacity")
        if end < begin or capacity < end or (end - begin) % 8:
            result["unknown_reason"] = "result_vector_bounds_invalid"
            return result
        count = (end - begin) // 8
        if count > MAX_VECTOR_ENTRIES:
            result["unknown_reason"] = "result_vector_count_out_of_bound"
            return result
        result["vector"] = {
            "begin": {"address": _address(context_pointer + 0xF0, module_base), "raw_hex": begin_raw.hex(), "value": _address(begin, module_base)},
            "end": {"address": _address(context_pointer + 0xF8, module_base), "raw_hex": end_raw.hex(), "value": _address(end, module_base)},
            "capacity": {"address": _address(context_pointer + 0x100, module_base), "raw_hex": capacity_raw.hex(), "value": _address(capacity, module_base)},
            "count": count,
            "max_entries": MAX_VECTOR_ENTRIES,
            "limit": limit,
        }
        count_to_read = min(count, limit)
        result["truncated"] = count > limit
        if count_to_read and not _valid_pointer(begin):
            result["unknown_reason"] = "result_vector_begin_invalid"
            return result
        pointer_bytes = reader.read(begin, count_to_read * 8, f"{label}.vector.entries") if count_to_read else b""
        pointers: list[int] = []
        for index in range(count_to_read):
            raw = pointer_bytes[index * 8:(index + 1) * 8]
            pointer = int.from_bytes(raw, "little")
            pointers.append(pointer)
            result["result_pointers"].append({"index": index, "raw_hex": raw.hex(), "address": _address(pointer, module_base)})
        result["results"] = [_read_result(reader, module_base, database, pointer, f"{label}.result[{index}]") for index, pointer in enumerate(pointers)]
        result["status"] = "observed_truncated" if result["truncated"] else "observed"
        result["complete"] = not result["truncated"] and all(item.get("complete") is True for item in result["results"])
        return result
    except Exception as exc:
        result["unknown_reason"] = f"result_collection_read_failed:{type(exc).__name__}:{exc}"
        return result


def _read_history(reader: AddressBoundedRPM, module_base: int, war_pointer: int, history_root_pointer: int, result_pointers: Sequence[int], label: str) -> dict[str, Any]:
    """Best-effort history traversal guarded by the three audited root slots."""
    result: dict[str, Any] = {
        "status": "unknown",
        "supported": False,
        "root": _address(history_root_pointer, module_base),
        "root_header_raw_hex": None,
        "root_vtable": None,
        "root_date": None,
        "children": [],
        "bound_result_dates": {},
        "ambiguous_result_dates": {},
        "nodes_read": 0,
        "unknown_conditions": [],
    }
    if not _valid_pointer(history_root_pointer):
        result["unknown_conditions"].append("history_root_invalid")
        return result
    try:
        header = reader.read(history_root_pointer, HISTORY_HEADER_SIZE, f"{label}.root_header")
        result["root_header_raw_hex"] = header.hex()
        root_vtable = int.from_bytes(header[0:8], "little")
        result["root_vtable"] = {"raw_hex": header[:8].hex(), "value": _address(root_vtable, module_base)}
        if not _valid_pointer(root_vtable):
            result["unknown_conditions"].append("history_root_vtable_invalid")
            return result
        if root_vtable != module_base + HISTORY_ROOT_VTABLE_RVA:
            result["unknown_conditions"].append("history_root_vtable_rva_mismatch")
            return result
        result["root_vtable"]["expected_rva"] = hex(HISTORY_ROOT_VTABLE_RVA)
        result["root_vtable"]["matches"] = True
        slots: dict[str, Any] = {}
        for offset, target_rva in HISTORY_ROOT_SLOT_RVAS.items():
            value, raw = reader.qword(root_vtable + offset, f"{label}.root_vtable_slot_{offset:x}")
            slots[hex(offset)] = {"raw_hex": raw.hex(), "value": _address(value, module_base, rva=target_rva if value == module_base + target_rva else None), "expected_rva": hex(target_rva), "matches": value == module_base + target_rva}
        result["root_vtable"]["slots"] = slots
        if not all(item["matches"] for item in slots.values()):
            result["unknown_conditions"].append("history_root_vtable_slots_unsupported")
            return result
        root_date = int.from_bytes(header[HISTORY_DATE_OFFSET:HISTORY_DATE_OFFSET + 4], "little", signed=True)
        child_head = int.from_bytes(header[HISTORY_CHILDREN_OFFSET:HISTORY_CHILDREN_OFFSET + 8], "little")
        result.update({"supported": True, "root_date": {"raw": root_date, "raw_hex": header[HISTORY_DATE_OFFSET:HISTORY_DATE_OFFSET + 4].hex(), "offset": hex(HISTORY_DATE_OFFSET)}, "child_head": _address(child_head, module_base)})
        result_ptr_set = set(result_pointers)
        seen_nodes: set[int] = set()
        seen_objects: set[int] = set()

        def visit_list(head: int, depth: int, parent: str) -> None:
            if depth > MAX_HISTORY_DEPTH:
                result["unknown_conditions"].append("history_depth_limit")
                return
            node = head
            while node:
                if result["nodes_read"] >= MAX_HISTORY_NODES:
                    result["unknown_conditions"].append("history_node_limit")
                    return
                if not _valid_pointer(node):
                    result["unknown_conditions"].append("history_node_pointer_invalid")
                    return
                if node in seen_nodes:
                    result["unknown_conditions"].append("history_node_cycle")
                    return
                seen_nodes.add(node)
                result["nodes_read"] += 1
                child, child_raw = reader.qword(node + HISTORY_NODE_CHILD_OFFSET, f"{parent}.node[{result['nodes_read']}].child")
                next_node, next_raw = reader.qword(node + HISTORY_NODE_NEXT_OFFSET, f"{parent}.node[{result['nodes_read']}].next")
                item: dict[str, Any] = {"node": _address(node, module_base), "child": _address(child, module_base), "child_raw_hex": child_raw.hex(), "next": _address(next_node, module_base), "next_raw_hex": next_raw.hex(), "depth": depth}
                if not _valid_pointer(child):
                    item["status"] = "unknown"
                    item["unknown_reason"] = "history_child_invalid"
                    result["unknown_conditions"].append("history_child_invalid")
                    result["children"].append(item)
                    return
                if child in seen_objects:
                    item["status"] = "unknown"
                    item["unknown_reason"] = "history_object_cycle"
                    result["unknown_conditions"].append("history_object_cycle")
                    result["children"].append(item)
                    node = next_node
                    continue
                seen_objects.add(child)
                child_vtable, child_vtable_raw = reader.qword(child, f"{parent}.child_vtable")
                child_date_raw = reader.read(child + HISTORY_CHILD_DATE_OFFSET, 4, f"{parent}.child_date")
                child_date = int.from_bytes(child_date_raw, "little", signed=True)
                child_rva = (
                    HISTORY_VTABLE_GROUP_RVA
                    if child_vtable == module_base + HISTORY_VTABLE_GROUP_RVA
                    else HISTORY_VTABLE_EVENT_RVA
                    if child_vtable == module_base + HISTORY_VTABLE_EVENT_RVA
                    else None
                )
                item.update({
                    "vtable": {"raw_hex": child_vtable_raw.hex(), "value": _address(child_vtable, module_base, rva=child_rva)},
                    "date": {"raw": child_date, "raw_hex": child_date_raw.hex(), "offset": hex(HISTORY_CHILD_DATE_OFFSET)},
                })
                if child_vtable == module_base + HISTORY_VTABLE_GROUP_RVA:
                    nested_head, nested_raw = reader.qword(child + HISTORY_CHILDREN_OFFSET, f"{parent}.group_children")
                    item.update(status="observed", kind="group", children_head=_address(nested_head, module_base), children_head_raw_hex=nested_raw.hex())
                    result["children"].append(item)
                    visit_list(nested_head, depth + 1, parent + ".group")
                elif child_vtable == module_base + HISTORY_VTABLE_EVENT_RVA:
                    owner, owner_raw = reader.qword(child + HISTORY_EVENT_OWNER_OFFSET, f"{parent}.event_owner")
                    event_result, event_result_raw = reader.qword(child + HISTORY_EVENT_RESULT_OFFSET, f"{parent}.event_result")
                    item.update({"status": "observed", "kind": "battlehistoryevent", "owner": _address(owner, module_base), "owner_raw_hex": owner_raw.hex(), "result": _address(event_result, module_base), "result_raw_hex": event_result_raw.hex()})
                    if owner == war_pointer and event_result in result_ptr_set:
                        key = _hex(event_result) or "unknown"
                        bound = {"raw": child_date, "raw_hex": child_date_raw.hex(), "event": _address(child, module_base)}
                        if key in result["bound_result_dates"]:
                            prior = result["bound_result_dates"].pop(key)
                            result.setdefault("ambiguous_result_dates", {}).setdefault(key, [prior]).append(bound)
                            result["unknown_conditions"].append("history_result_date_ambiguous")
                        elif key in result.get("ambiguous_result_dates", {}):
                            result["ambiguous_result_dates"][key].append(bound)
                        else:
                            result["bound_result_dates"][key] = bound
                    result["children"].append(item)
                else:
                    item.update(status="unknown", unknown_reason="history_child_vtable_unknown")
                    result["unknown_conditions"].append("history_child_vtable_unknown")
                    result["children"].append(item)
                node = next_node

        visit_list(child_head, 0, label)
        result["status"] = "observed" if result["supported"] and not result["unknown_conditions"] else "unknown"
        return result
    except Exception as exc:
        result["unknown_conditions"].append(f"history_read_failed:{type(exc).__name__}:{exc}")
        return result


def _read_war(reader: AddressBoundedRPM, module_base: int, database: int, war_reference: int, actor_handle: int, recipient_handle: int, limit: int, label: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "complete": False,
        "native_reference": _hex(war_reference),
        "war": _address(war_reference, module_base),
        "side_a": None,
        "side_b": None,
        "actor_side": None,
        "recipient_side": None,
        "history": None,
        "results": None,
        "unknown_conditions": [],
    }
    if not _valid_pointer(war_reference):
        result["unknown_conditions"].append("war_reference_invalid")
        return result
    try:
        side_a = _read_member_vector(reader, database, war_reference, 0x48, 0x50, 0x58, f"{label}.side_a")
        side_b = _read_member_vector(reader, database, war_reference, 0x78, 0x80, 0x88, f"{label}.side_b")
        result["side_a"] = side_a
        result["side_b"] = side_b
        if side_a.get("status") != "observed" or side_b.get("status") != "observed":
            result["unknown_conditions"].append("war_side_members_unknown")
            return result
        handles_a = _handles(side_a)
        handles_b = _handles(side_b)
        if len(handles_a) != len(set(handles_a)) or len(handles_b) != len(set(handles_b)):
            result["unknown_conditions"].append("war_side_duplicate_full_handle")
            return result
        if set(handles_a).intersection(handles_b):
            result["unknown_conditions"].append("war_side_member_overlap")
            return result
        actor_a = actor_handle in handles_a
        actor_b = actor_handle in handles_b
        recipient_a = recipient_handle in handles_a
        recipient_b = recipient_handle in handles_b
        actor_count = int(actor_a) + int(actor_b)
        recipient_count = int(recipient_a) + int(recipient_b)
        if actor_count != 1 or recipient_count != 1 or actor_a == recipient_a:
            result["unknown_conditions"].append("war_pair_side_membership_not_exactly_once_opposite")
            return result
        result["actor_side"] = "A" if actor_a else "B"
        result["recipient_side"] = "A" if recipient_a else "B"
        # D89A80 receives the war object itself.  Its retained-result vector
        # is embedded at war+F0/F8/100; war+108 is a separate embedded
        # history root whose first qword is its vtable.
        context_pointer = war_reference
        history_root_pointer = war_reference + HISTORY_ROOT_OFFSET
        collection = _read_result_collection(reader, module_base, database, context_pointer, limit, f"{label}.retained")
        result["results"] = collection
        result_pointers = []
        for item in collection.get("result_pointers", []):
            address = item.get("address", {}) if isinstance(item, Mapping) else {}
            value = address.get("va") if isinstance(address, Mapping) else None
            if isinstance(value, str):
                try:
                    result_pointers.append(int(value, 0))
                except ValueError:
                    pass
        history = _read_history(reader, module_base, war_reference, history_root_pointer, result_pointers, f"{label}.history")
        result["history"] = history
        bound = history.get("bound_result_dates", {}) if isinstance(history, Mapping) else {}
        for item in collection.get("results", []) if isinstance(collection, Mapping) else []:
            address = item.get("address", {}).get("va") if isinstance(item, Mapping) and isinstance(item.get("address"), Mapping) else None
            if address in bound:
                item["timeline_date"] = bound[address]
        result["history_root"] = {
            "address": _address(history_root_pointer, module_base),
            "storage": "embedded_object",
            "value": _address(history_root_pointer, module_base),
        }
        collection_status = collection.get("status")
        if collection_status not in {"observed", "observed_truncated"}:
            result["unknown_conditions"].append("war_retained_results_unknown")
            result["status"] = "unknown"
        else:
            result["status"] = "observed"
        result["complete"] = collection.get("complete") is True and history.get("status") == "observed"
        if collection.get("truncated"):
            result["complete"] = False
        return result
    except Exception as exc:
        result["unknown_conditions"].append(f"war_read_failed:{type(exc).__name__}:{exc}")
        return result


def _value_from_address(item: Any) -> int | None:
    if isinstance(item, Mapping):
        value = item.get("va")
    else:
        value = item
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _snapshot(reader: AddressBoundedRPM, module_base: int, actor: str, recipient: str, limit: int, pass_index: int) -> dict[str, Any]:
    snapshot: dict[str, Any] = {
        "status": "unknown",
        "pass": pass_index,
        "runtime_code_guard": None,
        "game_pointer": None,
        "database_pointer": None,
        "game_date": None,
        "control": None,
        "actor_country": None,
        "recipient_country": None,
        "pair_references": None,
        "wars": [],
        "partial": False,
        "unknown_conditions": [],
        "read_log": [],
    }
    start_log = len(reader.read_log)
    try:
        snapshot["runtime_code_guard"] = _runtime_code_guard(reader, module_base)
        if snapshot["runtime_code_guard"].get("status") != "observed":
            snapshot["unknown_conditions"].append("runtime_code_guard_mismatch")
            snapshot["read_log"] = copy.deepcopy(reader.read_log[start_log:])
            return snapshot
        game_address = module_base + GAME_RVA
        game, game_raw = reader.qword(game_address, "globals.game")
        if not _valid_pointer(game):
            snapshot["unknown_conditions"].append("game_pointer_invalid")
            snapshot["read_log"] = copy.deepcopy(reader.read_log[start_log:])
            return snapshot
        database_address = module_base + DATABASE_RVA
        database, database_raw = reader.qword(database_address, "globals.database")
        if not _valid_pointer(database):
            snapshot["unknown_conditions"].append("database_pointer_invalid")
            snapshot["read_log"] = copy.deepcopy(reader.read_log[start_log:])
            return snapshot
        date_raw = reader.read(game + GAME_DATE_OFFSET, 4, "game.raw_date")
        date_value = int.from_bytes(date_raw, "little", signed=True)
        control = _control_state(reader, module_base, game)
        snapshot.update({
            "game_pointer": {"address": _address(game_address, module_base, rva=GAME_RVA), "raw_hex": game_raw.hex(), "value": _address(game, module_base)},
            "database_pointer": {"address": _address(database_address, module_base, rva=DATABASE_RVA), "raw_hex": database_raw.hex(), "value": _address(database, module_base)},
            "game_date": {"address": _address(game + GAME_DATE_OFFSET, module_base), "raw_hex": date_raw.hex(), "raw": date_value, "offset": hex(GAME_DATE_OFFSET)},
            "control": control,
        })
        if control.get("status") != "observed":
            snapshot["unknown_conditions"].append("pause_speed_state_unknown")
            snapshot["read_log"] = copy.deepcopy(reader.read_log[start_log:])
            return snapshot
        if control.get("speed", {}).get("value") != 0 or control.get("paused", {}).get("value") is not True:
            snapshot["unknown_conditions"].append("runtime_not_paused_speed_zero")
            snapshot["read_log"] = copy.deepcopy(reader.read_log[start_log:])
            return snapshot
        actor_scan = _country_scan(reader, database, actor)
        recipient_scan = _country_scan(reader, database, recipient)
        snapshot["actor_country"] = actor_scan
        snapshot["recipient_country"] = recipient_scan
        if actor_scan.get("status") != "observed" or recipient_scan.get("status") != "observed":
            snapshot["unknown_conditions"].append("pair_country_identity_unknown")
            snapshot["read_log"] = copy.deepcopy(reader.read_log[start_log:])
            return snapshot
        actor_handle = _value_from_address((actor_scan.get("country_handle") or {}).get("value"))
        recipient_handle = _value_from_address((recipient_scan.get("country_handle") or {}).get("value"))
        actor_pointer = _value_from_address((actor_scan.get("country_pointer") or {}).get("va"))
        recipient_pointer = _value_from_address((recipient_scan.get("country_pointer") or {}).get("va"))
        if not all(isinstance(item, int) and item for item in (actor_handle, recipient_handle, actor_pointer, recipient_pointer)):
            snapshot["unknown_conditions"].append("pair_country_handle_missing")
            snapshot["read_log"] = copy.deepcopy(reader.read_log[start_log:])
            return snapshot
        left = _read_pair_references(reader, actor_pointer, recipient_handle, "pair.actor_to_recipient")
        right = _read_pair_references(reader, recipient_pointer, actor_handle, "pair.recipient_to_actor")
        snapshot["pair_references"] = {"actor_to_recipient": left, "recipient_to_actor": right, "sets_equal": None, "complete": False}
        left_refs = [_value_from_address(item.get("reference")) for item in left.get("references", []) if isinstance(item, Mapping)]
        right_refs = [_value_from_address(item.get("reference")) for item in right.get("references", []) if isinstance(item, Mapping)]
        left_refs = [item for item in left_refs if isinstance(item, int)]
        right_refs = [item for item in right_refs if isinstance(item, int)]
        sets_equal = left.get("complete") is True and right.get("complete") is True and set(left_refs) == set(right_refs) and len(left_refs) == len(right_refs)
        snapshot["pair_references"].update({"sets_equal": sets_equal, "complete": sets_equal})
        if not sets_equal:
            snapshot["unknown_conditions"].append("pair_reference_sets_not_equal_or_incomplete")
            snapshot["read_log"] = copy.deepcopy(reader.read_log[start_log:])
            return snapshot
        for index, reference in enumerate(left_refs):
            war = _read_war(reader, module_base, database, reference, actor_handle, recipient_handle, limit, f"war[{index}]")
            snapshot["wars"].append(war)
            if war.get("status") != "observed":
                snapshot["unknown_conditions"].append(f"war[{index}]_unknown")
            if war.get("complete") is not True:
                snapshot["partial"] = True
        if any(war.get("status") != "observed" for war in snapshot["wars"] if isinstance(war, Mapping)):
            snapshot["status"] = "unknown"
        else:
            snapshot["status"] = "observed"
        snapshot["complete"] = snapshot["status"] == "observed" and not snapshot["unknown_conditions"] and not snapshot["partial"]
        snapshot["read_log"] = copy.deepcopy(reader.read_log[start_log:])
        return snapshot
    except Exception as exc:
        snapshot["unknown_conditions"].append(f"snapshot_failed:{type(exc).__name__}:{exc}")
        snapshot["read_log"] = copy.deepcopy(reader.read_log[start_log:])
        return snapshot


def _dll_installation_check(document: Mapping[str, Any], phase: str) -> dict[str, Any]:
    expected = str(document.get("dll_sha256", "")).lower()
    modules = document.get("modules_after_install") or document.get("modules") or []
    if not isinstance(modules, list):
        modules = []
    records: list[dict[str, Any]] = []
    for item in modules:
        if not isinstance(item, Mapping):
            continue
        records.append({"name": item.get("name"), "path": item.get("path"), "sha256": str(item.get("sha256", "")).lower()})
    matches = [item for item in records if item.get("sha256") == expected and item.get("sha256")]
    status = bool(expected == EXPECTED_DLL_SHA256 and len(matches) == 1)
    return {
        "phase": phase,
        "status": "observed" if status else "unknown",
        "installation_dll_sha256": expected or None,
        "expected_v22_dll_sha256": EXPECTED_DLL_SHA256,
        "modules": records,
        "matching_modules": matches,
        "unknown_reason": None if status else "installation_dll_sha_or_module_record_unavailable_or_unexpected",
    }


def _loaded_dll_check(kernel: Any, handle: Any, document: Mapping[str, Any], phase: str) -> dict[str, Any]:
    """Verify the expected observer DLL among modules of the open process.

    The installation manifest is only a historical/static prerequisite.  This
    helper performs the actual same-handle module enumeration and hashes only
    loaded modules whose path or basename can be the expected observer DLL.
    """
    result: dict[str, Any] = {
        "phase": phase,
        "status": "unknown",
        "expected_sha256": EXPECTED_DLL_SHA256,
        "expected_path": None,
        "expected_name": None,
        "loaded_module_count": None,
        "modules": [],
        "matching_modules": [],
        "unknown_conditions": [],
    }
    modules_manifest = document.get("modules_after_install") or document.get("modules") or []
    expected_items = [
        item for item in modules_manifest
        if isinstance(item, Mapping) and str(item.get("sha256", "")).lower() == EXPECTED_DLL_SHA256
    ] if isinstance(modules_manifest, list) else []
    if len(expected_items) != 1:
        result["unknown_conditions"].append("expected_loaded_dll_manifest_record_not_unique")
        return result
    expected_item = expected_items[0]
    expected_path_raw = expected_item.get("path")
    expected_name_raw = expected_item.get("name")
    if not isinstance(expected_path_raw, str) or not expected_path_raw:
        result["unknown_conditions"].append("expected_loaded_dll_path_missing")
        return result
    expected_path = Path(expected_path_raw).resolve()
    expected_path_key = os.path.normcase(os.path.normpath(str(expected_path)))
    expected_name = Path(expected_name_raw).name if isinstance(expected_name_raw, str) and expected_name_raw else expected_path.name
    result["expected_path"] = str(expected_path)
    result["expected_name"] = expected_name
    try:
        enum_modules = getattr(kernel, "K32EnumProcessModulesEx")
        get_name = getattr(kernel, "_probe_get_module_name")
        modules = (W.HMODULE * MAX_LOADED_MODULES)()
        needed = W.DWORD()
        if not enum_modules(handle, modules, C.sizeof(modules), C.byref(needed), 3):
            raise C.WinError(C.get_last_error())
        if not needed.value:
            result["loaded_module_count"] = 0
            result["unknown_conditions"].append("expected_observer_dll_not_loaded_or_hash_mismatch")
            return result
        if needed.value % C.sizeof(W.HMODULE):
            raise ProbeError("loaded_module_list_invalid")
        count = needed.value // C.sizeof(W.HMODULE)
        if count > MAX_LOADED_MODULES:
            raise ProbeError("loaded_module_list_out_of_bound")
        result["loaded_module_count"] = count
        for index in range(count):
            module_handle = int(getattr(modules[index], "value", modules[index]))
            name_buffer = C.create_unicode_buffer(32768)
            name_length = int(get_name(handle, modules[index], name_buffer, len(name_buffer)))
            if name_length <= 0 or name_length >= len(name_buffer):
                result["modules"].append({"index": index, "module": _hex(module_handle), "status": "unknown", "unknown_reason": "module_path_unavailable"})
                continue
            module_path = Path(name_buffer.value).resolve()
            module_path_key = os.path.normcase(os.path.normpath(str(module_path)))
            record: dict[str, Any] = {"index": index, "module": _hex(module_handle), "path": str(module_path), "path_matches_expected": module_path_key == expected_path_key, "name_matches_expected": module_path.name.casefold() == str(expected_name).casefold()}
            if record["path_matches_expected"] or record["name_matches_expected"]:
                try:
                    actual_sha = _sha256_file(module_path).lower()
                    record["sha256"] = actual_sha
                    record["sha256_matches_expected"] = actual_sha == EXPECTED_DLL_SHA256
                except Exception as exc:
                    record["sha256"] = None
                    record["sha256_matches_expected"] = False
                    record["unknown_reason"] = f"module_hash_read_failed:{type(exc).__name__}:{exc}"
            else:
                record["sha256"] = None
                record["sha256_matches_expected"] = None
            result["modules"].append(record)
            if record.get("path_matches_expected") is True and record.get("sha256_matches_expected") is True:
                result["matching_modules"].append(record)
        if len(result["matching_modules"]) == 1:
            result["status"] = "observed"
        elif not result["matching_modules"]:
            result["unknown_conditions"].append("expected_observer_dll_not_loaded_or_hash_mismatch")
        else:
            result["unknown_conditions"].append("expected_observer_dll_loaded_multiple_times")
    except Exception as exc:
        result["unknown_conditions"].append(f"loaded_module_check_failed:{type(exc).__name__}:{exc}")
    return result


def _loaded_dll_for_compare(value: Any) -> Any:
    """Compare the same-handle module observation without its pass label."""
    result = copy.deepcopy(value)
    if isinstance(result, dict):
        result.pop("phase", None)
    return result


def _base_report(installation: Path, actor: str, recipient: str, limit: int) -> dict[str, Any]:
    return {
        "probe": "information-battle-war-memory",
        "probe_version": 1,
        "probe_script": str(Path(__file__).resolve()),
        "probe_script_sha256": None,
        "read_only": True,
        "native_function_invoked": False,
        "evidence_kind": "pure_runtime_observation_not_static_evidence",
        "source_semantics": "native_retained_subset/query_only",
        "retained_subset_only": True,
        "all_battles_captured": False,
        "public_war_id_available": False,
        "target_build": {"version": EXPECTED_VERSION, "expected_exe_sha256": EXPECTED_EXE_SHA256, "expected_dll_sha256": EXPECTED_DLL_SHA256, "image_base": "0x140000000", "database_rva": hex(DATABASE_RVA), "game_rva": hex(GAME_RVA), "result_vtable_rva": hex(RESULT_VTABLE_RVA), "side_vtable_rva": hex(SIDE_VTABLE_RVA)},
        "request": {"installation": str(installation), "actor": actor, "recipient": recipient, "limit": limit, "max_limit": MAX_RESULTS},
        "static_contract_guard": None,
        "file_code_guard": None,
        "runtime_code_guard": None,
        "dll_installation": None,
        "identity": {"installation_path": str(installation), "installation_pid": None, "installation_creation_filetime": None, "installation_session_id": None, "process_path": None, "process_path_sha256": None, "process_path_sha256_matches_expected": None, "process_creation_filetime": None, "process_creation_utc": None, "process_creation_matches_installation": None, "module_path": None, "module_path_matches_process": None, "binding_verified": False},
        "identity_before": None,
        "identity_after": None,
        "module_base": None,
        "before": None,
        "after": None,
        "wars": None,
        "doublepass": {"performed": False, "consistent": None, "mismatches": [], "atomic": False, "all_read_bytes_compared": True},
        "results": None,
        "results_truncated": False,
        "complete": False,
        "visibility": False,
        "battle_complete": False,
        "access": {"open_process_mask": "QUERY_INFORMATION|VM_READ", "open_process_mask_hex": hex(PROCESS_ACCESS), "rpm_total_limit": MAX_TOTAL_RPM, "rpm_single_read_limit": MAX_SINGLE_RPM, "rpm_bytes_requested": 0, "rpm_calls": 0, "native_game_calls": False, "target_memory_writes": False, "dll_injection": False, "private_heap_scan": False, "ui_control": False, "date_advance": False, "save_or_reload": False},
        "cleanup": {"handle_close": {"status": "unknown", "success": None, "closed": False}},
        "status": "starting",
        "errors": [],
        "completed": False,
    }


def _retract(report: dict[str, Any]) -> None:
    report["results"] = None
    report["wars"] = None
    report["results_truncated"] = False
    report["retained_observation_complete"] = False
    report["complete"] = False


def _snapshot_for_compare(snapshot: Any) -> Any:
    """Remove only the pass ordinal; retain every observed byte and field."""
    value = copy.deepcopy(snapshot)
    if isinstance(value, dict):
        value.pop("pass", None)
    return value


def _flatten_results(wars: Sequence[Any]) -> tuple[list[dict[str, Any]], bool]:
    """Expose retained result objects with their native war reference context."""
    flattened: list[dict[str, Any]] = []
    truncated = False
    for war_index, war in enumerate(wars):
        if not isinstance(war, Mapping):
            continue
        retained = war.get("results") if isinstance(war.get("results"), Mapping) else {}
        if retained.get("truncated"):
            truncated = True
        for result_index, item in enumerate(retained.get("results", [])):
            flattened.append({
                "war_index": war_index,
                "war_reference": war.get("native_reference"),
                "result_index": result_index,
                "result": copy.deepcopy(item),
            })
    return flattened, truncated


def _unknown_report(report: dict[str, Any], status: str, stage: str, error: str) -> None:
    report["status"] = status
    report["errors"].append({"stage": stage, "status": "unknown", "error": error})


def _identity_view(item: Any) -> Any:
    return copy.deepcopy(item)


def _request_error(report: dict[str, Any], error: str) -> dict[str, Any]:
    report["status"] = "invalid_request"
    report["errors"].append({"stage": "request", "status": "unknown", "error": error})
    report["completed"] = True
    return report


def _identity_mismatches(before: Any, after: Any) -> list[str]:
    """Compare identity fields while retaining the exact field paths."""
    return _diff_paths(_identity_view(before), _identity_view(after))


def capture(installation: Path, actor: str = EXPECTED_ACTOR, recipient: str = "ENG", limit: int = MAX_RESULTS) -> dict[str, Any]:
    """Capture one bounded, read-only, pair-scoped two-pass observation.

    The returned ``results`` are native retained-result objects observed through
    the already audited vectors.  They are deliberately opaque and remain
    research-stage data; this function never invokes a game function, writes
    process memory, constructs an offer, or publishes an InformationService
    value.
    """
    installation = Path(installation)
    report = _base_report(installation, actor, recipient, limit)
    try:
        report["probe_script_sha256"] = _sha256_file(Path(__file__).resolve())
    except Exception as exc:
        report["errors"].append({"stage": "probe_identity", "status": "unknown", "error": f"{type(exc).__name__}:{exc}"})

    if not isinstance(actor, str) or actor != EXPECTED_ACTOR:
        return _request_error(report, "actor must be the verified observer country FRA")
    if (
        not isinstance(recipient, str)
        or len(recipient) != 3
        or recipient.upper() != recipient
        or not recipient.isascii()
        or not recipient.isalnum()
        or recipient == actor
    ):
        return _request_error(report, "recipient must be a distinct three-character ASCII country tag")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_RESULTS:
        return _request_error(report, f"limit must be an integer in 1..{MAX_RESULTS}")

    report["static_contract_guard"] = _static_contract_guard()
    if report["static_contract_guard"].get("status") != "observed":
        _unknown_report(report, "static_contract_mismatch", "static_contract", "fixed result/history layout contract did not validate")
        report["completed"] = True
        return report

    handle: Any = None
    kernel: Any = None
    reader: AddressBoundedRPM | None = None
    document: Mapping[str, Any] | None = None
    try:
        document = _load_installation(installation)
        installation_record = _dll_installation_check(document, "installation")
        report["dll_installation"] = {
            "installation_record": installation_record,
            "before": None,
            "after": None,
        }
        if installation_record.get("status") != "observed":
            _unknown_report(report, "dll_installation_mismatch", "dll_installation", "installed observer DLL is absent or does not match the fixed v22 hash")
        else:
            kernel = _configure_kernel()
            pid = _parse_installation_int(document.get("pid"), "installation_pid")
            handle = kernel.OpenProcess(PROCESS_ACCESS, False, pid)
            if not handle:
                raise C.WinError(C.get_last_error())

            identity_return = _capture_identity(report, document, kernel, handle)
            module_base = _module_base(report, identity_return)
            report["identity_before"] = _identity_view(report["identity"])
            report["module_base"] = _address(module_base)
            process_path = Path(report["identity"].get("process_path", ""))
            report["file_code_guard"] = _file_code_guard(process_path)
            if report["file_code_guard"].get("status") != "observed":
                _unknown_report(report, "file_code_mismatch", "file_code_guard", "fixed result/history code bytes did not match the executable file")
            else:
                reader = AddressBoundedRPM(kernel, handle, module_base)
                loaded_before = _loaded_dll_check(kernel, handle, document, "before")
                report["dll_installation"]["before"] = _identity_view(loaded_before)
                if loaded_before.get("status") != "observed":
                    _unknown_report(report, "dll_runtime_mismatch", "dll_installation.before", "expected observer DLL was not observed in the opened process")
                else:
                    before = _snapshot(reader, module_base, actor, recipient, limit, 1)
                    report["before"] = _identity_view(before)
                    report["runtime_code_guard"] = copy.deepcopy(before.get("runtime_code_guard"))
                    if before.get("status") != "observed":
                        _unknown_report(report, "unknown", "before", "initial pair-scoped retained-result pass did not reach an observed identity")
                    else:
                        after = _snapshot(reader, module_base, actor, recipient, limit, 2)
                        report["after"] = _identity_view(after)
                        report["doublepass"]["performed"] = True
                        report["doublepass"]["all_read_bytes_compared"] = True
                        if after.get("status") != "observed":
                            mismatches = ["$.after.status"]
                        else:
                            mismatches = _diff_paths(_snapshot_for_compare(before), _snapshot_for_compare(after))

                        after_identity_probe: dict[str, Any] = {"identity": copy.deepcopy(report["identity"])}
                        after_identity_return = _capture_identity(after_identity_probe, document, kernel, handle)
                        after_module_base = _module_base(after_identity_probe, after_identity_return)
                        report["identity_after"] = _identity_view(after_identity_probe["identity"])
                        identity_mismatches = _identity_mismatches(report["identity_before"], report["identity_after"])
                        if after_module_base != module_base:
                            identity_mismatches.append("$.module_base")

                        loaded_after = _loaded_dll_check(kernel, handle, document, "after")
                        report["dll_installation"]["after"] = _identity_view(loaded_after)
                        if loaded_after.get("status") != "observed":
                            mismatches.append("$.dll_installation.after.status")
                        else:
                            mismatches.extend(_diff_paths(_loaded_dll_for_compare(loaded_before), _loaded_dll_for_compare(loaded_after), "$.dll_installation"))
                        report["doublepass"]["mismatches"] = (mismatches + [f"$.identity_after{item[1:]}" for item in identity_mismatches])[:256]
                        report["doublepass"]["consistent"] = not report["doublepass"]["mismatches"]

                        if report["doublepass"]["consistent"]:
                            report["status"] = "observed"
                            report["wars"] = copy.deepcopy(after.get("wars", []))
                            flattened, truncated = _flatten_results(after.get("wars", []))
                            report["results"] = flattened
                            report["results_truncated"] = truncated
                            report["retained_observation_complete"] = after.get("complete") is True
                            # A retained vector is not a complete battle/war
                            # history even when every selected read is valid.
                            report["complete"] = False
                        else:
                            report["status"] = "doublepass_mismatch"
                            report["errors"].append({"stage": "doublepass", "status": "unknown", "error": "runtime identity, date, pair, code, DLL, or retained-result bytes changed between passes", "paths": report["doublepass"]["mismatches"]})
    except ProbeError as exc:
        message = str(exc)
        status = "identity_mismatch" if "binding" in message or "installation_" in message else "error"
        _unknown_report(report, status, "probe", message)
    except Exception as exc:
        _unknown_report(report, "error", "probe", f"{type(exc).__name__}:{exc}")
    finally:
        if reader is not None:
            report["access"]["rpm_bytes_requested"] = reader.bytes_requested
            report["access"]["rpm_calls"] = reader.calls
        outcome = _close_process_handle(kernel, handle)
        report["cleanup"]["handle_close"] = outcome
        if outcome.get("status") == "error":
            previous_status = report.get("status")
            _retract(report)
            report["status"] = "cleanup_error"
            outcome["previous_status"] = previous_status
            report["errors"].append({"stage": "cleanup", "status": "error", "error": outcome.get("error", "CloseHandle failed"), "previous_status": previous_status})
    report["completed"] = True
    return report


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Read a bounded pair-scoped retained battle-result subset")
    parser.add_argument("--installation", required=True, type=Path)
    parser.add_argument("--actor", default=EXPECTED_ACTOR)
    parser.add_argument("--recipient", default="ENG")
    parser.add_argument("--limit", type=int, default=MAX_RESULTS)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    report = capture(args.installation, args.actor, args.recipient, args.limit)
    payload = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        try:
            with args.output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(payload)
        except FileExistsError:
            print(f"output already exists: {args.output}", file=sys.stderr)
            return 2
    else:
        print(payload, end="")
    return 0 if report.get("status") == "observed" else 2


__all__ = [
    "EXPECTED_EXE_SHA256", "EXPECTED_DLL_SHA256", "EXPECTED_VERSION", "AddressBoundedRPM",
    "ProbeError", "ProfileError", "capture", "main", "_snapshot", "_read_war",
    "_read_result", "_read_history", "_read_result_collection", "_read_pair_references",
    "_decode_sso32", "_static_contract_guard", "_file_code_guard", "_runtime_code_guard",
    "_diff_paths", "_loaded_dll_check", "MAX_TOTAL_RPM", "MAX_SINGLE_RPM", "MAX_RESULTS",
    "MAX_SSO_CAPACITY", "MAX_LOADED_MODULES", "HISTORY_ROOT_VTABLE_RVA",
]


if __name__ == "__main__":
    raise SystemExit(main())
