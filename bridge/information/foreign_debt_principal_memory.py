"""Private bounded reader for a target country's loan-list principal sums.

This leaf observes one bound target list and never reads lender identity,
interest, due dates, or other record fields.  It reproduces two distinct
signed-32-bit native arithmetic paths: the unscaled principal sum and the
per-record principal-times-1000 sum used by the diplomatic loan display.
The result is not admitted for publication and does not evaluate visibility.
The parent remains responsible for fresh process/database/ROM/date/role
binding.  Reads are repeated before return, but the observation is not an
atomic snapshot.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from . import foreign_quality_visibility_memory as _common


SCHEMA = "information.foreign_debt_principal_memory.v1"
BASIS = "native_target_loan_list_principal_arithmetic"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
PREFERRED_IMAGE_BASE = 0x140000000

TARGET_LOAN_HEAD_OFFSET = 0xDE8
TARGET_LOAN_COUNT_OFFSET = 0xDF8
LOAN_NODE_SIZE = 0x18
LOAN_NODE_RECORD_OFFSET = 0x00
LOAN_NODE_NEXT_OFFSET = 0x10
LOAN_RECORD_PRINCIPAL_OFFSET = 0x2C

MAX_NODES = 64
MAX_TOTAL_READ_BYTES = 32 * 1024
MAX_READ_CALLS = 384
MAX_SINGLE_READ_BYTES = 1024

UINT32_MASK = 0xFFFFFFFF
UINT32_MODULUS = 0x100000000
INT32_SIGN = 0x80000000
INT32_MIN = -(1 << 31)
INT32_MAX = (1 << 31) - 1


class _Unknown(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _checked_add(address: int, offset: int, size: int = 1) -> int:
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


def _parse_binding(value: Any, label: str) -> dict[str, Any]:
    try:
        return _common._parse_binding(value, label)
    except Exception as exc:
        reason = getattr(exc, "reason", None)
        raise _Unknown(reason if isinstance(reason, str) else f"{label.upper()}_BINDING_INVALID") from exc


class _Trace:
    """Ordered exact reads with explicit call, byte, and single-read limits."""

    def __init__(self, reader: Any):
        method = getattr(reader, "read", None)
        self._read = method if callable(method) else reader if callable(reader) else None
        self.reads: list[dict[str, Any]] = []
        self.calls = 0
        self.bytes_requested = 0

    def exact(self, address: int, size: int, label: str) -> bytes:
        if self._read is None:
            raise _Unknown("READER_INVALID")
        if type(size) is not int or not 0 < size <= MAX_SINGLE_READ_BYTES:
            raise _Unknown(f"SINGLE_READ_LIMIT:{label}")
        address = _checked_add(address, 0, size)
        if (self.calls + 1 > MAX_READ_CALLS
                or self.bytes_requested + size > MAX_TOTAL_READ_BYTES):
            self.reads.append({
                "ordinal": self.calls + 1,
                "address": hex(address),
                "size": size,
                "label": label,
                "status": "rejected",
                "reason": "READ_BUDGET_EXCEEDED",
            })
            raise _Unknown("READ_BUDGET_EXCEEDED")
        self.calls += 1
        self.bytes_requested += size
        row: dict[str, Any] = {
            "ordinal": self.calls,
            "address": hex(address),
            "size": size,
            "label": label,
            "pointer_checked": True,
            "status": "requested",
        }
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
            "read_events": len(self.reads),
            "bytes_requested": self.bytes_requested,
            "max_calls": MAX_READ_CALLS,
            "max_bytes": MAX_TOTAL_READ_BYTES,
            "max_single_read_bytes": MAX_SINGLE_READ_BYTES,
            "max_nodes": MAX_NODES,
        }


def _binding_echo(trace: _Trace, binding: Mapping[str, Any], label: str) -> bytes:
    address = _checked_add(binding["country_pointer"], _common.COUNTRY_FULLREF_OFFSET, 8)
    raw = trace.exact(address, 8, f"binding.{label}.fullref_echo")
    if raw.hex() != binding["fullref_raw_hex"]:
        raise _Unknown(f"{label.upper()}_FULLREF_ECHO_MISMATCH")
    trace.reads[-1].update({"decode": "country_fullref", "value": hex(binding["fullref"])})
    return raw


def _signed32(value: int) -> int:
    word = value & UINT32_MASK
    return word - UINT32_MODULUS if word & INT32_SIGN else word


def _sum_principals(principals: list[int]) -> tuple[int, bool, int, bool]:
    principal_total = 0
    principal_overflowed = False
    diplomatic_total = 0
    diplomatic_overflowed = False
    for principal in principals:
        wide_principal_total = principal_total + principal
        principal_total = _signed32(wide_principal_total)
        if not INT32_MIN <= wide_principal_total <= INT32_MAX:
            principal_overflowed = True

        wide_product = principal * 1000
        scaled_principal = _signed32(wide_product)
        if not INT32_MIN <= wide_product <= INT32_MAX:
            diplomatic_overflowed = True
        wide_diplomatic_total = diplomatic_total + scaled_principal
        diplomatic_total = _signed32(wide_diplomatic_total)
        if not INT32_MIN <= wide_diplomatic_total <= INT32_MAX:
            diplomatic_overflowed = True
    return principal_total, principal_overflowed, diplomatic_total, diplomatic_overflowed


def _read_target_header(trace: _Trace, target: Mapping[str, Any], phase: str) -> tuple[bytes, bytes, int, int]:
    head_address = _checked_add(target["country_pointer"], TARGET_LOAN_HEAD_OFFSET, 8)
    count_address = _checked_add(target["country_pointer"], TARGET_LOAN_COUNT_OFFSET, 4)
    head_raw = trace.exact(head_address, 8, f"target.loan_head_{phase}")
    head = int.from_bytes(head_raw, "little", signed=False)
    head = _pointer(head, f"LOAN_HEAD_{phase.upper()}", allow_null=True)
    trace.reads[-1].update({"decode": "u64_pointer", "value": hex(head)})
    count_raw = trace.exact(count_address, 4, f"target.loan_count_{phase}")
    count = int.from_bytes(count_raw, "little", signed=True)
    trace.reads[-1].update({"decode": "i32", "value": count})
    return head_raw, count_raw, head, count


def _walk_list(trace: _Trace, head: int, count: int) -> tuple[list[dict[str, Any]], list[int]]:
    if count < 0 or count > MAX_NODES:
        raise _Unknown("LOAN_COUNT_OUT_OF_BOUNDS")
    if (count == 0) != (head == 0):
        raise _Unknown("LOAN_HEAD_COUNT_MISMATCH")
    if count == 0:
        return [], []

    rows: list[dict[str, Any]] = []
    principals: list[int] = []
    visited_nodes: set[int] = set()
    visited_records: set[int] = set()
    node = head
    for ordinal in range(count):
        if node == 0:
            raise _Unknown("LOAN_CHAIN_SHORTER_THAN_COUNT")
        node = _pointer(node, f"LOAN_NODE_{ordinal}")
        if node in visited_nodes:
            raise _Unknown("LOAN_NODE_CYCLE")
        visited_nodes.add(node)
        node_raw = trace.exact(node, LOAN_NODE_SIZE, f"loan.node[{ordinal}].before")
        record_raw = node_raw[LOAN_NODE_RECORD_OFFSET:LOAN_NODE_RECORD_OFFSET + 8]
        record = _pointer(int.from_bytes(record_raw, "little", signed=False),
                          f"LOAN_RECORD_{ordinal}")
        if record in visited_records:
            raise _Unknown("LOAN_RECORD_DUPLICATE")
        visited_records.add(record)
        next_raw = node_raw[LOAN_NODE_NEXT_OFFSET:LOAN_NODE_NEXT_OFFSET + 8]
        next_node = _pointer(int.from_bytes(next_raw, "little", signed=False),
                             f"LOAN_NEXT_{ordinal}", allow_null=True)
        principal_address = _checked_add(record, LOAN_RECORD_PRINCIPAL_OFFSET, 4)
        principal_raw = trace.exact(principal_address, 4,
                                    f"loan.record_principal[{ordinal}].before")
        principal = int.from_bytes(principal_raw, "little", signed=True)
        trace.reads[-1].update({"decode": "i32", "value": principal})
        rows.append({
            "ordinal": ordinal,
            "node": node,
            "node_raw": node_raw,
            "record": record,
            "principal_raw": principal_raw,
            "principal": principal,
            "next_node": next_node,
        })
        principals.append(principal)
        if ordinal + 1 < count:
            if next_node == 0:
                raise _Unknown("LOAN_CHAIN_SHORTER_THAN_COUNT")
            if next_node in visited_nodes:
                raise _Unknown("LOAN_NODE_CYCLE")
        elif next_node != 0:
            if next_node in visited_nodes:
                raise _Unknown("LOAN_NODE_CYCLE")
            raise _Unknown("LOAN_CHAIN_LONGER_THAN_COUNT")
        node = next_node
    return rows, principals


def _recheck(trace: _Trace, observer: Mapping[str, Any], target: Mapping[str, Any],
             expected_echoes: tuple[bytes, bytes], expected_header: tuple[bytes, bytes],
             rows: list[dict[str, Any]]) -> None:
    observer_after = _binding_echo(trace, observer, "observer_after")
    target_after = _binding_echo(trace, target, "target_after")
    if observer_after != expected_echoes[0] or target_after != expected_echoes[1]:
        raise _Unknown("COUNTRY_FULLREF_CHANGED_AFTER_READ")

    head_after, count_after, _head, _count = _read_target_header(trace, target, "after")
    if head_after != expected_header[0] or count_after != expected_header[1]:
        raise _Unknown("LOAN_HEAD_OR_COUNT_CHANGED_AFTER_READ")

    for row in rows:
        ordinal = row["ordinal"]
        node_after = trace.exact(row["node"], LOAN_NODE_SIZE,
                                 f"loan.node[{ordinal}].after")
        if node_after != row["node_raw"]:
            raise _Unknown("LOAN_NODE_CHANGED_AFTER_READ")
        principal_address = _checked_add(row["record"], LOAN_RECORD_PRINCIPAL_OFFSET, 4)
        principal_after = trace.exact(principal_address, 4,
                                      f"loan.record_principal[{ordinal}].after")
        if principal_after != row["principal_raw"]:
            raise _Unknown("LOAN_PRINCIPAL_CHANGED_AFTER_READ")


def _trace_inputs(trace: _Trace, raw_inputs: Mapping[str, Any]) -> dict[str, Any]:
    result = deepcopy(dict(raw_inputs))
    result["ordered_read_trace"] = deepcopy(trace.reads)
    result["read_budget"] = trace.summary()
    return result


def _unknown(trace: _Trace, raw_inputs: Mapping[str, Any], reason: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": "unknown",
        "reason": reason,
        "basis": BASIS,
        "complete_loan_list": False,
        "publication_admitted": False,
        "visibility": {"status": "unknown", "reason": "PARENT_VISIBILITY_NOT_EVALUATED"},
        "raw_inputs": _trace_inputs(trace, raw_inputs),
    }


def read_state(reader: Any, module_base: Any, observer_binding: Any,
               target_binding: Any) -> dict[str, Any]:
    """Return two bounded principal totals for one explicitly bound target.

    ``complete_loan_list`` means the target's signed count and linked list
    agreed and every selected node/principal byte matched its immediate
    readback. The two totals cover that physical list's principal words.
    The parent separately establishes public visibility and publication
    permission; remaining interest and payoff quotations are other values.
    Repeated reads do not establish an atomic engine snapshot.
    """
    trace = _Trace(reader)
    raw_inputs: dict[str, Any] = {
        "module_base": None,
        "layout": {
            "country_fullref_offset": hex(_common.COUNTRY_FULLREF_OFFSET),
            "target_loan_head_offset": hex(TARGET_LOAN_HEAD_OFFSET),
            "target_loan_count_offset_i32": hex(TARGET_LOAN_COUNT_OFFSET),
            "loan_node_size": hex(LOAN_NODE_SIZE),
            "loan_node_record_offset": hex(LOAN_NODE_RECORD_OFFSET),
            "loan_node_next_offset": hex(LOAN_NODE_NEXT_OFFSET),
            "loan_record_principal_i32_offset": hex(LOAN_RECORD_PRINCIPAL_OFFSET),
        },
        "limits": {
            "max_nodes": MAX_NODES,
            "max_bytes": MAX_TOTAL_READ_BYTES,
            "max_calls": MAX_READ_CALLS,
            "max_single_read_bytes": MAX_SINGLE_READ_BYTES,
        },
        "atomic_snapshot": False,
        "publication_admitted": False,
        "visibility_evaluated": False,
        "parent_context_required": [
            "fresh_process_and_database_binding",
            "ROM_identity_and_date_binding",
            "observer_role_and_country_view_admission",
        ],
        "interest_or_due_date_read": False,
        "lender_identity_read": False,
    }
    try:
        base = _pointer(module_base, "MODULE_BASE")
        if base % 0x1000:
            raise _Unknown("MODULE_BASE_INVALID")
        observer = _parse_binding(observer_binding, "observer")
        target = _parse_binding(target_binding, "target")
        if (observer["country_pointer"] == target["country_pointer"]
                or observer["slot"] == target["slot"]
                or observer["fullref"] == target["fullref"]):
            raise _Unknown("OBSERVER_TARGET_BINDINGS_ALIAS")
        raw_inputs["module_base"] = hex(base)
        raw_inputs["bindings"] = {
            role: {
                "tag": binding["tag"],
                "slot": binding["slot"],
                "country_pointer": hex(binding["country_pointer"]),
                "fullref": hex(binding["fullref"]),
                "fullref_raw_hex": binding["fullref_raw_hex"],
            }
            for role, binding in (("observer", observer), ("target", target))
        }

        observer_echo = _binding_echo(trace, observer, "observer_before")
        target_echo = _binding_echo(trace, target, "target_before")
        head_raw, count_raw, head, count = _read_target_header(trace, target, "before")
        raw_inputs["target_list_header"] = {
            "head": hex(head), "count_signed_i32": count,
            "head_raw_hex": head_raw.hex(), "count_raw_hex": count_raw.hex(),
        }
        rows, principals = _walk_list(trace, head, count)
        _recheck(trace, observer, target, (observer_echo, target_echo),
                 (head_raw, count_raw), rows)

        principal_total, principal_overflowed, diplomatic_total, diplomatic_overflowed = (
            _sum_principals(principals)
        )
        raw_inputs["verified_loan_count"] = count
        raw_inputs["verified_nodes_rechecked"] = len(rows)
        return {
            "schema": SCHEMA,
            "status": "known",
            "basis": BASIS,
            "complete_loan_list": True,
            "publication_admitted": False,
            "visibility": {"status": "unknown", "reason": "PARENT_VISIBILITY_NOT_EVALUATED"},
            "value": {
                "loan_count": count,
                "principal_total": {
                    "status": "known",
                    "raw": principal_total,
                    "value": principal_total,
                    "unit": "ducats",
                    "scale": 1,
                    "signed_bits": 32,
                    "overflowed": principal_overflowed,
                    "arithmetic": "signed32_wrap_after_each_principal_add",
                },
                "diplomatic_principal_total": {
                    "status": "known",
                    "raw": diplomatic_total,
                    "value": diplomatic_total / 1000.0,
                    "unit": "ducats",
                    "scale": 1000,
                    "signed_bits": 32,
                    "overflowed": diplomatic_overflowed,
                    "arithmetic": "signed32_wrap_each_principal_times_1000_then_signed32_add",
                },
            },
            "raw_inputs": _trace_inputs(trace, raw_inputs),
        }
    except _Unknown as exc:
        return _unknown(trace, raw_inputs, exc.reason)
    except Exception as exc:
        return _unknown(trace, raw_inputs, f"INTERNAL_READ_ERROR:{type(exc).__name__}")


__all__ = [
    "SCHEMA", "BASIS", "EXPECTED_EXE_SHA256", "PREFERRED_IMAGE_BASE",
    "MAX_NODES", "MAX_TOTAL_READ_BYTES", "MAX_READ_CALLS",
    "MAX_SINGLE_READ_BYTES", "read_state",
]
