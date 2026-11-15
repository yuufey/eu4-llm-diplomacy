"""Private bounded reader for the B23 current-interest helper inputs.

Only the null modifier-processor path is reproduced.  No native function is
called, and this leaf does not decide disclosure, visibility, or APR semantics.
The caller owns process/ROM/date/role binding.  Two matching reads reduce the
chance of returning mixed inputs but do not provide an atomic snapshot.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from . import foreign_quality_visibility_memory as _common


SCHEMA = "information.bankruptcy_interest_memory.v1"
BASIS = "native_current_interest_null_processor_branch"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
PREFERRED_IMAGE_BASE = 0x140000000

BASE_GLOBAL_RVA = 0x233E128
FLOOR_GLOBAL_RVA = 0x233E124
MODIFIER_MANAGER_GLOBAL_RVA = 0x2358060
MODIFIER_PROCESSOR_SLOT_OFFSET = 0xB80  # 0x1E * 0x60 + 0x40

COUNTRY_CACHE_STATE_OFFSET = 0x28C8
COUNTRY_MODIFIER_OBJECT_OFFSET = 0x28D0
MODIFIER_DENSE_FLAG_OFFSET = 0x10
MODIFIER_ENTRIES_POINTER_OFFSET = 0x58
MODIFIER_SPARSE_COUNT_OFFSET = 0x64
MODIFIER_DENSE_VALUE_OFFSET = 0xF4  # 4 + modifier id 0x1E * 8
MODIFIER_ID = 0x1E
SPARSE_ENTRY_SIZE = 8
SPARSE_ENTRY_KEY_OFFSET = 0
SPARSE_ENTRY_VALUE_OFFSET = 4

MAX_SPARSE_ENTRIES = 256
MAX_TOTAL_READ_BYTES = 16 * 1024
MAX_READ_CALLS = 128
MAX_SINGLE_READ_BYTES = 1024
UINT32_MASK = 0xFFFFFFFF
UINT32_SIGN = 0x80000000
UINT32_MODULUS = 0x100000000


class _Unknown(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _add(address: int, offset: int, size: int = 1) -> int:
    try:
        return _common._checked_add(address, offset, size)
    except Exception as exc:
        raise _Unknown("ADDRESS_INVALID") from exc


def _pointer(value: Any, label: str, *, allow_null: bool = False) -> int:
    try:
        return _common._pointer(value, label, alignment=8, allow_null=allow_null)
    except Exception as exc:
        reason = getattr(exc, "reason", None)
        raise _Unknown(reason if isinstance(reason, str) else f"{label}_POINTER_INVALID") from exc


class _Trace:
    """Child-local budget and trace layered over the caller's bounded reader."""

    def __init__(self, reader: Any):
        method = getattr(reader, "read", None)
        self._read = method if callable(method) else reader if callable(reader) else None
        self.rows: list[dict[str, Any]] = []
        self.calls = 0
        self.bytes_requested = 0

    def exact(self, address: int, size: int, label: str) -> bytes:
        if self._read is None:
            raise _Unknown("READER_INVALID")
        if type(size) is not int or not 0 < size <= MAX_SINGLE_READ_BYTES:
            raise _Unknown(f"SINGLE_READ_LIMIT:{label}")
        address = _add(address, 0, size)
        if (self.calls + 1 > MAX_READ_CALLS
                or self.bytes_requested + size > MAX_TOTAL_READ_BYTES):
            self.rows.append({
                "address": hex(address), "size": size, "raw_hex": None,
                "status": "rejected", "label": label,
                "reason": "READ_BUDGET_EXCEEDED",
            })
            raise _Unknown("READ_BUDGET_EXCEEDED")

        self.calls += 1
        self.bytes_requested += size
        row = {"address": hex(address), "size": size, "raw_hex": None,
               "status": "requested", "label": label}
        self.rows.append(row)
        try:
            raw = self._read(address, size, label)
        except Exception as exc:
            row.update(status="failed", error_type=type(exc).__name__)
            raise _Unknown(f"READ_FAILED:{label}") from exc
        if not isinstance(raw, (bytes, bytearray, memoryview)) or len(raw) != size:
            row.update(status="failed", error_type="SHORT_OR_INVALID_READ")
            raise _Unknown(f"READ_FAILED:{label}")
        data = bytes(raw)
        row.update(status="ok", raw_hex=data.hex())
        return data

    def u8(self, address: int, label: str) -> int:
        value = int.from_bytes(self.exact(address, 1, label), "little", signed=False)
        self.rows[-1].update(decode="u8", value=value)
        return value

    def u32(self, address: int, label: str) -> int:
        value = int.from_bytes(self.exact(address, 4, label), "little", signed=False)
        self.rows[-1].update(decode="u32", value=value)
        return value

    def i32(self, address: int, label: str) -> int:
        value = int.from_bytes(self.exact(address, 4, label), "little", signed=True)
        self.rows[-1].update(decode="i32", value=value)
        return value

    def u64(self, address: int, label: str) -> int:
        value = int.from_bytes(self.exact(address, 8, label), "little", signed=False)
        self.rows[-1].update(decode="u64", value=hex(value))
        return value

    def summary(self) -> dict[str, int]:
        return {
            "calls": self.calls,
            "bytes_requested": self.bytes_requested,
            "max_calls": MAX_READ_CALLS,
            "max_bytes": MAX_TOTAL_READ_BYTES,
            "max_single_read_bytes": MAX_SINGLE_READ_BYTES,
            "max_sparse_entries": MAX_SPARSE_ENTRIES,
        }


def _signed32(value: int) -> int:
    word = value & UINT32_MASK
    return word - UINT32_MODULUS if word & UINT32_SIGN else word


def _sparse_modifier(trace: _Trace, entries: int, count: int, phase: str) -> tuple[int, int]:
    if count < 0 or count > MAX_SPARSE_ENTRIES:
        raise _Unknown("SPARSE_COUNT_OUT_OF_BOUNDS")
    if count == 0:
        return 0, 0

    entries = _pointer(entries, "MODIFIER_ENTRIES")
    first_value: int | None = None
    match_count = 0
    index = 0
    # Read in chunks capped at 1024 bytes, while preserving native first-match
    # semantics. Continuing the bounded scan also lets us reject duplicate keys.
    max_entries_per_read = MAX_SINGLE_READ_BYTES // SPARSE_ENTRY_SIZE
    while index < count:
        chunk_count = min(max_entries_per_read, count - index)
        chunk_address = _add(entries, index * SPARSE_ENTRY_SIZE,
                             chunk_count * SPARSE_ENTRY_SIZE)
        chunk = trace.exact(chunk_address, chunk_count * SPARSE_ENTRY_SIZE,
                            f"{phase}.sparse_entries[{index}:{index + chunk_count}]")
        for offset in range(0, len(chunk), SPARSE_ENTRY_SIZE):
            key = int.from_bytes(
                chunk[offset + SPARSE_ENTRY_KEY_OFFSET:
                       offset + SPARSE_ENTRY_KEY_OFFSET + 4],
                "little", signed=False,
            )
            if key == MODIFIER_ID:
                value_raw = chunk[offset + SPARSE_ENTRY_VALUE_OFFSET:
                                   offset + SPARSE_ENTRY_VALUE_OFFSET + 4]
                value = int.from_bytes(value_raw, "little", signed=True)
                match_count += 1
                if first_value is None:
                    first_value = value
        index += chunk_count

    if match_count > 1:
        raise _Unknown("SPARSE_MODIFIER_KEY_DUPLICATE")
    return (first_value if first_value is not None else 0), match_count


def _capture_pass(trace: _Trace, module_base: int, country_pointer: int,
                  phase: str) -> dict[str, Any]:
    start = len(trace.rows)
    base_raw = trace.i32(_add(module_base, BASE_GLOBAL_RVA, 4), f"{phase}.base_i32")
    floor_raw = trace.i32(_add(module_base, FLOOR_GLOBAL_RVA, 4), f"{phase}.floor_i32")
    cache_state = trace.i32(_add(country_pointer, COUNTRY_CACHE_STATE_OFFSET, 4),
                            f"{phase}.cache_state_i32")
    result: dict[str, Any] = {
        "phase": phase,
        "base_raw_i32": base_raw,
        "floor_raw_i32": floor_raw,
        "cache_state_i32": cache_state,
    }
    if cache_state == 1:
        result.update(branch="cache_calculating", reason="CACHE_CALCULATING_STATE")
        result["read_bytes"] = _comparable_rows(trace.rows[start:])
        return result

    modifier_object = _add(country_pointer, COUNTRY_MODIFIER_OBJECT_OFFSET, 1)
    dense_flag = trace.u8(_add(modifier_object, MODIFIER_DENSE_FLAG_OFFSET, 1),
                          f"{phase}.dense_flag_u8")
    result["dense_flag_u8"] = dense_flag
    if dense_flag not in (0, 1):
        result.update(branch="invalid_dense_flag", reason="DENSE_FLAG_INVALID")
        result["read_bytes"] = _comparable_rows(trace.rows[start:])
        return result

    entries_cell = _add(modifier_object, MODIFIER_ENTRIES_POINTER_OFFSET, 8)
    entries = _pointer(trace.u64(entries_cell, f"{phase}.entries_pointer_u64"),
                       "MODIFIER_ENTRIES", allow_null=True)
    result["entries_pointer"] = hex(entries) if entries else None

    if dense_flag == 1:
        entries = _pointer(entries, "MODIFIER_ENTRIES")
        value_address = _add(entries, MODIFIER_DENSE_VALUE_OFFSET, 4)
        modifier_raw = trace.i32(value_address, f"{phase}.dense_modifier_i32")
        result.update(branch="dense", modifier_raw_i32=modifier_raw,
                      sparse_match_count=0)
    else:
        count_address = _add(modifier_object, MODIFIER_SPARSE_COUNT_OFFSET, 4)
        count = trace.i32(count_address, f"{phase}.sparse_count_i32")
        result["sparse_count_i32"] = count
        if count < 0 or count > MAX_SPARSE_ENTRIES:
            result.update(branch="invalid_sparse_count", reason="SPARSE_COUNT_OUT_OF_BOUNDS")
            result["read_bytes"] = _comparable_rows(trace.rows[start:])
            return result
        modifier_raw, match_count = _sparse_modifier(trace, entries, count, phase)
        result.update(branch="sparse", modifier_raw_i32=modifier_raw,
                      sparse_match_count=match_count)

    manager_cell = _add(module_base, MODIFIER_MANAGER_GLOBAL_RVA, 8)
    manager = _pointer(trace.u64(manager_cell, f"{phase}.modifier_manager_pointer_u64"),
                       "MODIFIER_MANAGER")
    processor_cell = _add(manager, MODIFIER_PROCESSOR_SLOT_OFFSET, 8)
    processor = _pointer(trace.u64(processor_cell,
                                  f"{phase}.modifier_1e_processor_pointer_u64"),
                         "MODIFIER_PROCESSOR", allow_null=True)
    result.update(
        manager_pointer=hex(manager),
        processor_slot_address=hex(processor_cell),
        processor_pointer=hex(processor) if processor else None,
        reason="NON_NULL_PROCESSOR_UNSUPPORTED" if processor else None,
    )
    result["read_bytes"] = _comparable_rows(trace.rows[start:])
    return result


def _comparable_rows(rows: list[dict[str, Any]]) -> list[tuple[str, int, str | None, str]]:
    return [(row["address"], row["size"], row.get("raw_hex"), row["status"])
            for row in rows]


def _same_pass_inputs(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return ({key: value for key, value in left.items() if key != "phase"}
            == {key: value for key, value in right.items() if key != "phase"})


def _trace_inputs(trace: _Trace, raw_inputs: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(raw_inputs)
    # Keep the child trace simple and compatible with the enclosing forecast
    # reader, which replays exact address/size/bytes tuples from this list.
    result["ordered_read_trace"] = [
        {key: row.get(key) for key in ("address", "size", "raw_hex", "status")}
        for row in trace.rows
    ]
    result["read_budget"] = trace.summary()
    return result


def _unknown(trace: _Trace, raw_inputs: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": "unknown",
        "reason": reason,
        "basis": BASIS,
        "publication_admitted": False,
        "visibility_evaluated": False,
        "raw_inputs": _trace_inputs(trace, raw_inputs),
    }


def read_state(reader: Any, module_base: Any, country_pointer: Any) -> dict[str, Any]:
    """Capture the signed32 base+modifier branch, only when the processor is null."""
    trace = _Trace(reader)
    raw_inputs: dict[str, Any] = {
        "module_base": None,
        "country_pointer": None,
        "layout": {
            "base_global_rva_i32": hex(BASE_GLOBAL_RVA),
            "floor_global_rva_i32": hex(FLOOR_GLOBAL_RVA),
            "modifier_manager_global_rva_u64": hex(MODIFIER_MANAGER_GLOBAL_RVA),
            "modifier_1e_processor_slot_offset": hex(MODIFIER_PROCESSOR_SLOT_OFFSET),
            "country_cache_state_i32_offset": hex(COUNTRY_CACHE_STATE_OFFSET),
            "country_modifier_object_offset": hex(COUNTRY_MODIFIER_OBJECT_OFFSET),
            "dense_flag_u8_offset": hex(MODIFIER_DENSE_FLAG_OFFSET),
            "entries_pointer_u64_offset": hex(MODIFIER_ENTRIES_POINTER_OFFSET),
            "sparse_count_i32_offset": hex(MODIFIER_SPARSE_COUNT_OFFSET),
            "dense_modifier_i32_offset": hex(MODIFIER_DENSE_VALUE_OFFSET),
            "modifier_id": MODIFIER_ID,
            "sparse_entry_size": SPARSE_ENTRY_SIZE,
            "sparse_key_offset": SPARSE_ENTRY_KEY_OFFSET,
            "sparse_value_i32_offset": SPARSE_ENTRY_VALUE_OFFSET,
        },
        "limits": {
            "max_sparse_entries": MAX_SPARSE_ENTRIES,
            "max_bytes": MAX_TOTAL_READ_BYTES,
            "max_calls": MAX_READ_CALLS,
            "max_single_read_bytes": MAX_SINGLE_READ_BYTES,
        },
        "atomic_snapshot": False,
        "native_function_invoked": False,
        "processor_callback_invoked": False,
        "publication_admitted": False,
        "visibility_evaluated": False,
    }
    try:
        base = _pointer(module_base, "MODULE_BASE")
        if base % 0x1000:
            raise _Unknown("MODULE_BASE_INVALID")
        country = _pointer(country_pointer, "COUNTRY")
        raw_inputs.update(module_base=hex(base), country_pointer=hex(country))

        before = _capture_pass(trace, base, country, "before")
        after = _capture_pass(trace, base, country, "after")
        raw_inputs["input_passes"] = [before, after]
        if not _same_pass_inputs(before, after):
            raise _Unknown("INPUTS_CHANGED_AFTER_READ")
        if before.get("reason"):
            raise _Unknown(before["reason"])
        if before.get("branch") not in ("dense", "sparse"):
            raise _Unknown("MODIFIER_BRANCH_UNSUPPORTED")
        if before.get("processor_pointer") is not None:
            raise _Unknown("NON_NULL_PROCESSOR_UNSUPPORTED")

        base_raw = before["base_raw_i32"]
        modifier_raw = before["modifier_raw_i32"]
        floor_raw = before["floor_raw_i32"]
        summed_raw = _signed32(base_raw + modifier_raw)
        helper_return = max(summed_raw, floor_raw)
        raw_inputs["selected_branch"] = before["branch"]
        raw_inputs["sparse_match_count"] = before.get("sparse_match_count")
        raw_inputs["inputs_rechecked"] = True
        return {
            "schema": SCHEMA,
            "status": "known",
            "basis": BASIS,
            "publication_admitted": False,
            "visibility_evaluated": False,
            "value": {
                "helper_return_i32": helper_return,
                "base_raw_i32": base_raw,
                "modifier_raw_i32": modifier_raw,
                "floor_raw_i32": floor_raw,
            },
            "raw_inputs": _trace_inputs(trace, raw_inputs),
        }
    except _Unknown as exc:
        return _unknown(trace, raw_inputs, exc.reason)
    except Exception as exc:
        return _unknown(trace, raw_inputs, f"INTERNAL_READ_ERROR:{type(exc).__name__}")


__all__ = [
    "SCHEMA", "BASIS", "EXPECTED_EXE_SHA256", "PREFERRED_IMAGE_BASE",
    "MAX_SPARSE_ENTRIES", "MAX_TOTAL_READ_BYTES", "MAX_READ_CALLS",
    "MAX_SINGLE_READ_BYTES", "read_state",
]
