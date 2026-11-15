"""Bounded reader for membership in the world's country-row candidate array.

This helper does not open a process or invoke native code.  It confirms only
that a validated country binding's pointer is present in the current
world+0x1d08 pointer array and that the bound row still has the same fullref.
It does not evaluate the later slot/discovery filters or prove UI rendering.
The caller owns process/session identity, ROM guards, observer role, and any
field-specific permission checks.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from . import country_faith_memory as _faith

SCHEMA = "information.country_ledger_membership.v1"
BASIS = "world_country_row_candidate_array_membership"

WORLD_COUNTRY_POINTERS_OFFSET = 0x1D08
WORLD_COUNTRY_COUNT_OFFSET = 0x1D14
COUNTRY_FULLREF_OFFSET = 0x20
MAX_COUNTRY_CANDIDATES = 4096
MAX_READ_CALLS = 128
MAX_TOTAL_READ_BYTES = 64 * 1024
MAX_SINGLE_READ_BYTES = 1024
MIN_USER_ADDRESS = 0x10000
MAX_USER_ADDRESS_EXCLUSIVE = 0x800000000000
MAX_U64 = 0xFFFFFFFFFFFFFFFF


class _Unknown(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _is_json(value: Any) -> bool:
    if value is None or type(value) in (str, bool, int):
        return True
    if isinstance(value, list):
        return all(_is_json(item) for item in value)
    if isinstance(value, dict):
        return all(type(key) is str and _is_json(item) for key, item in value.items())
    return False


def _address(value: Any, label: str, *, alignment: int = 8,
             allow_null: bool = False) -> int:
    if type(value) is not int or not 0 <= value <= MAX_U64:
        raise _Unknown(f"{label}_POINTER_INVALID")
    if value == 0 and allow_null:
        return 0
    if (value < MIN_USER_ADDRESS or value >= MAX_USER_ADDRESS_EXCLUSIVE
            or alignment <= 0 or value % alignment):
        raise _Unknown(f"{label}_POINTER_INVALID")
    return value


def _checked_add(address: int, offset: int, size: int) -> int:
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


def _parse_uint(value: Any, label: str) -> int:
    if type(value) is int:
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value, 0)
        except ValueError as exc:
            raise _Unknown(f"{label}_INVALID") from exc
    else:
        raise _Unknown(f"{label}_INVALID")
    if not 0 <= parsed <= MAX_U64:
        raise _Unknown(f"{label}_INVALID")
    return parsed


def _parse_target(binding: Any) -> tuple[int, dict[str, Any]]:
    try:
        pointer, retained = _faith._binding(binding)
    except Exception as exc:
        raise _Unknown("TARGET_BINDING_INVALID") from exc
    fullref = int(retained["fullref"], 16)
    if ((fullref >> 24) & 0xFF) != 0:
        raise _Unknown("TARGET_FULLREF_KIND_UNSUPPORTED")
    if retained["fullref_raw_hex"] != fullref.to_bytes(8, "little").hex():
        raise _Unknown("TARGET_FULLREF_RAW_INVALID")
    fullref_address = pointer + COUNTRY_FULLREF_OFFSET
    if fullref_address >= MAX_USER_ADDRESS_EXCLUSIVE - 7:
        raise _Unknown("TARGET_FULLREF_ADDRESS_INVALID")

    given_fullref_address = binding.get("country_fullref_address")
    if given_fullref_address is not None:
        if _parse_uint(given_fullref_address, "TARGET_FULLREF_ADDRESS") != fullref_address:
            raise _Unknown("TARGET_FULLREF_ADDRESS_MISMATCH")
    table_entry = binding.get("table_entry_address")
    if table_entry is not None:
        table_entry_value = _parse_uint(table_entry, "TARGET_TABLE_ENTRY_ADDRESS")
        if (table_entry_value < MIN_USER_ADDRESS
                or table_entry_value >= MAX_USER_ADDRESS_EXCLUSIVE - 7
                or table_entry_value & 7):
            raise _Unknown("TARGET_TABLE_ENTRY_ADDRESS_INVALID")
    table_entry_raw = binding.get("table_entry_raw_hex")
    expected_pointer_raw = pointer.to_bytes(8, "little").hex()
    if table_entry_raw is not None and (
            not isinstance(table_entry_raw, str)
            or table_entry_raw.lower() != expected_pointer_raw):
        raise _Unknown("TARGET_TABLE_ENTRY_RAW_MISMATCH")
    normalized = {
        "tag": retained["tag"],
        "slot": retained["slot"],
        "country_pointer": hex(pointer),
        "fullref": hex(fullref),
        "fullref_raw_hex": fullref.to_bytes(8, "little").hex(),
        "country_fullref_address": hex(fullref_address),
        "table_entry_address": table_entry,
        "table_entry_raw_hex": expected_pointer_raw if table_entry_raw is not None else None,
    }
    return pointer, normalized


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
        address = _checked_add(address, 0, size)
        if type(size) is not int or not 0 < size <= MAX_SINGLE_READ_BYTES:
            raise _Unknown("SINGLE_READ_LIMIT")
        if (self.calls + 1 > MAX_READ_CALLS
                or self.bytes_requested + size > MAX_TOTAL_READ_BYTES):
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

    def u64(self, address: int, label: str) -> int:
        raw = self.exact(address, 8, label)
        value = int.from_bytes(raw, "little")
        self.reads[-1].update({"decode": "u64", "value": hex(value)})
        return value

    def i32(self, address: int, label: str) -> int:
        raw = self.exact(address, 4, label)
        value = int.from_bytes(raw, "little", signed=True)
        self.reads[-1].update({"decode": "i32", "value": value})
        return value

    def summary(self) -> dict[str, int]:
        return {"calls": self.calls, "bytes_requested": self.bytes_requested,
                "max_calls": MAX_READ_CALLS, "max_bytes": MAX_TOTAL_READ_BYTES,
                "max_single_read_bytes": MAX_SINGLE_READ_BYTES}


def _initial(world_pointer: Any, target_binding: Any) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": "unknown",
        "member": None,
        "reason": None,
        "basis": BASIS,
        "world": {"pointer": None, "candidate_array_pointer": None,
                  "candidate_count": None},
        "target": None,
        "matching_indices": [],
        "actual_UI_observed": False,
        "complete": False,
        "raw_inputs": {
            "world_pointer_input": hex(world_pointer) if type(world_pointer) is int else None,
            "target_binding": None,
            "array_header": None,
            "target_fullref_validation": None,
            "reads": [],
            "budget": {"calls": 0, "bytes_requested": 0,
                       "max_calls": MAX_READ_CALLS,
                       "max_bytes": MAX_TOTAL_READ_BYTES,
                       "max_single_read_bytes": MAX_SINGLE_READ_BYTES},
        },
    }


def read_membership(reader: Any, world_pointer: Any, target_binding: Any) -> dict[str, Any]:
    """Read and trace membership in world+0x1d08's country pointer array.

    Every array pointer is checked, but its remaining country object is opaque.
    Only a pointer match plus the target's live +0x20 fullref echo can produce a
    known membership result. This is a candidate-array check, not a replay of
    the later slot/discovery filters.
    """
    result = _initial(world_pointer, target_binding)
    trace = _Trace(reader)
    raw = result["raw_inputs"]

    def finish() -> dict[str, Any]:
        raw["reads"] = deepcopy(trace.reads)
        raw["budget"] = trace.summary()
        return result

    def unknown(reason: str) -> dict[str, Any]:
        result.update({"status": "unknown", "member": None, "reason": reason,
                       "matching_indices": []})
        return finish()

    try:
        world = _address(world_pointer, "WORLD")
        raw["world_pointer_input"] = hex(world)
        target_pointer, target = _parse_target(target_binding)
        raw["target_binding"] = deepcopy(target)
        result["world"]["pointer"] = hex(world)
        result["target"] = deepcopy(target)

        pointer_cell = _checked_add(world, WORLD_COUNTRY_POINTERS_OFFSET, 8)
        count_cell = _checked_add(world, WORLD_COUNTRY_COUNT_OFFSET, 4)
        if not (pointer_cell + 8 <= count_cell or count_cell + 4 <= pointer_cell):
            raise _Unknown("WORLD_ARRAY_HEADER_OVERLAP")
        array_pointer = _address(trace.u64(pointer_cell, "ledger_membership.array_pointer"),
                                 "COUNTRY_ARRAY", allow_null=True)
        count = trace.i32(count_cell, "ledger_membership.array_count_i32")
        raw["array_header"] = {
            "pointer_cell": hex(pointer_cell),
            "pointer": hex(array_pointer) if array_pointer else None,
            "count_cell": hex(count_cell),
            "count_i32": count,
            "count_raw_hex": count.to_bytes(4, "little", signed=True).hex(),
        }
        result["world"].update({"candidate_array_pointer": hex(array_pointer) if array_pointer else None,
                                "candidate_count": count})
        if not 0 <= count <= MAX_COUNTRY_CANDIDATES:
            raise _Unknown("COUNTRY_CANDIDATE_COUNT_INVALID")
        if count == 0:
            if array_pointer not in (0,) and array_pointer in (world, pointer_cell, count_cell):
                raise _Unknown("COUNTRY_ARRAY_POINTER_ALIAS")
            total_bytes = 0
        else:
            if array_pointer == 0:
                raise _Unknown("COUNTRY_ARRAY_POINTER_INVALID")
            total_bytes = count * 8
            if total_bytes > MAX_TOTAL_READ_BYTES:
                raise _Unknown("COUNTRY_ARRAY_SIZE_LIMIT")
            if (array_pointer > MAX_U64 - total_bytes
                    or array_pointer + total_bytes > MAX_USER_ADDRESS_EXCLUSIVE):
                raise _Unknown("COUNTRY_ARRAY_RANGE_INVALID")
            array_range = (array_pointer, array_pointer + total_bytes)
            if (array_range[0] < pointer_cell + 8 and pointer_cell < array_range[1]) or (
                    array_range[0] < count_cell + 4 and count_cell < array_range[1]):
                raise _Unknown("COUNTRY_ARRAY_HEADER_ALIAS")
            if array_range[0] < world + 1 and world < array_range[1]:
                raise _Unknown("COUNTRY_ARRAY_WORLD_ALIAS")
            fullref_address = _checked_add(target_pointer, COUNTRY_FULLREF_OFFSET, 8)
            if array_range[0] < fullref_address + 8 and fullref_address < array_range[1]:
                raise _Unknown("COUNTRY_ARRAY_TARGET_FULLREF_ALIAS")

        matching: list[int] = []
        # Chunk at 1024 bytes (128 pointers) so the largest permitted array
        # takes 32 calls and never exceeds the leaf's byte/call budget.
        chunk_entries = MAX_SINGLE_READ_BYTES // 8
        for start in range(0, count, chunk_entries):
            amount = min(chunk_entries, count - start)
            chunk_address = _checked_add(array_pointer, start * 8, amount * 8)
            chunk = trace.exact(chunk_address, amount * 8,
                                f"ledger_membership.array_chunk[{start}:{start+amount}]")
            for offset in range(amount):
                index = start + offset
                candidate = int.from_bytes(chunk[offset * 8:(offset + 1) * 8], "little")
                candidate = _address(candidate, f"COUNTRY_ROW_{index}")
                if candidate in (world, array_pointer, pointer_cell, count_cell):
                    raise _Unknown("COUNTRY_ROW_POINTER_ALIAS")
                if candidate == target_pointer:
                    matching.append(index)

        target_ref_address = _checked_add(target_pointer, COUNTRY_FULLREF_OFFSET, 8)
        target_ref = trace.u64(target_ref_address, "ledger_membership.target_fullref_u64")
        expected_ref = int(target["fullref"], 16)
        raw["target_fullref_validation"] = {
            "address": hex(target_ref_address),
            "expected_fullref": hex(expected_ref),
            "expected_raw_hex": target["fullref_raw_hex"],
            "observed_fullref": hex(target_ref),
            "observed_raw_hex": target_ref.to_bytes(8, "little").hex(),
            "matches_binding": target_ref == expected_ref,
        }
        if target_ref != expected_ref:
            raise _Unknown("TARGET_FULLREF_MISMATCH")
        result.update({"status": "known", "member": bool(matching), "reason": None,
                       "matching_indices": list(matching)})
        return finish()
    except _Unknown as exc:
        return unknown(exc.reason)
    except Exception as exc:
        return unknown(f"INTERNAL_ERROR:{type(exc).__name__}")


def _same(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(_same(value, right[key]) for key, value in left.items())
    if isinstance(left, list):
        return len(left) == len(right) and all(_same(a, b) for a, b in zip(left, right))
    return left == right


def validate_membership(record: Any) -> bool:
    """Validate shape and replay the exact trace for any authorizing result."""
    if not isinstance(record, Mapping) or not _is_json(dict(record)):
        return False
    if (record.get("schema") != SCHEMA or record.get("basis") != BASIS
            or record.get("actual_UI_observed") is not False
            or record.get("complete") is not False):
        return False
    status = record.get("status")
    if status not in ("known", "unknown"):
        return False
    if status == "unknown":
        return (record.get("member") is None and isinstance(record.get("reason"), str)
                and bool(record.get("reason")) and record.get("matching_indices") == [])
    if type(record.get("member")) is not bool or record.get("reason") is not None:
        return False
    raw = record.get("raw_inputs")
    target = raw.get("target_binding") if isinstance(raw, Mapping) else None
    world = record.get("world")
    if (not isinstance(target, Mapping) or not isinstance(world, Mapping)
            or not isinstance(world.get("pointer"), str)):
        return False
    reads = raw.get("reads")
    budget = raw.get("budget")
    if not isinstance(reads, list) or not isinstance(budget, Mapping):
        return False
    try:
        calls = budget.get("calls")
        byte_count = budget.get("bytes_requested")
        if (type(calls) is not int or type(byte_count) is not int
                or not 0 <= calls <= MAX_READ_CALLS
                or not 0 <= byte_count <= MAX_TOTAL_READ_BYTES
                or budget.get("max_calls") != MAX_READ_CALLS
                or type(budget.get("max_calls")) is not int
                or budget.get("max_bytes") != MAX_TOTAL_READ_BYTES
                or type(budget.get("max_bytes")) is not int
                or budget.get("max_single_read_bytes") != MAX_SINGLE_READ_BYTES
                or type(budget.get("max_single_read_bytes")) is not int):
            return False
        consumed = [row for row in reads if isinstance(row, Mapping)
                    and row.get("status") in ("ok", "failed")]
        if calls != len(consumed) or byte_count != sum(row.get("size", -1) for row in consumed):
            return False
        for ordinal, row in enumerate(reads, 1):
            if (not isinstance(row, Mapping) or row.get("ordinal") != ordinal
                    or type(row.get("ordinal")) is not int
                    or type(row.get("size")) is not int
                    or not 0 < row["size"] <= MAX_SINGLE_READ_BYTES
                    or not isinstance(row.get("address"), str)
                    or not isinstance(row.get("label"), str)):
                return False
            address = int(row["address"], 16)
            if address < MIN_USER_ADDRESS or address + row["size"] > MAX_USER_ADDRESS_EXCLUSIVE:
                return False
            if row.get("status") == "ok":
                raw_hex = row.get("raw_hex")
                if not isinstance(raw_hex, str) or len(raw_hex) != row["size"] * 2:
                    return False
                bytes.fromhex(raw_hex)
            elif row.get("status") == "failed":
                if not isinstance(row.get("error_type"), str):
                    return False
            elif row.get("status") == "rejected":
                if row.get("reason") != "READ_BUDGET_EXCEEDED":
                    return False
            else:
                return False

        class _Replay:
            def __init__(self, rows):
                self.rows = list(rows)
                self.index = 0

            def read(self, address: int, size: int, label: str) -> bytes:
                if self.index >= len(self.rows):
                    raise AssertionError("replay_exhausted")
                row = self.rows[self.index]
                self.index += 1
                if (row.get("address") != hex(address) or row.get("size") != size
                        or row.get("label") != label):
                    raise AssertionError("replay_order_mismatch")
                if row.get("status") == "failed":
                    raise OSError("replayed recorded read failure")
                if row.get("status") != "ok":
                    raise AssertionError("replay_status_invalid")
                return bytes.fromhex(row["raw_hex"])

        replay = _Replay(reads)
        rebuilt = read_membership(replay, int(world["pointer"], 16), target)
        if replay.index != len(reads):
            return False
        return _same(dict(record), rebuilt)
    except (AssertionError, KeyError, TypeError, ValueError, OverflowError):
        return False


__all__ = ["SCHEMA", "BASIS", "read_membership", "validate_membership",
           "WORLD_COUNTRY_POINTERS_OFFSET", "WORLD_COUNTRY_COUNT_OFFSET",
           "MAX_COUNTRY_CANDIDATES", "MAX_READ_CALLS", "MAX_TOTAL_READ_BYTES",
           "MAX_SINGLE_READ_BYTES", "COUNTRY_FULLREF_OFFSET"]
