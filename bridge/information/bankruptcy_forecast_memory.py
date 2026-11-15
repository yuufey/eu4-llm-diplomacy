"""Private, bounded input capture for the B23 bankruptcy forecast model.

This child never calls the engine, changes the game, or evaluates foreign
disclosure. Its result is a calculation under the math module's declared SSE
assumptions, not an observed execution of the native forecast. The enclosing
capture must establish ROM/process/database/date/role binding and the native
floating-point environment before treating the model as a native result.
Two matching observations are required; they are not an atomic snapshot.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from . import bankruptcy_forecast_math as arithmetic
from . import bankruptcy_interest_memory as interest
from . import foreign_quality_visibility_memory as common

SCHEMA = "information.bankruptcy_forecast_memory.v1"
BASIS = "private_b23_bankruptcy_forecast_model"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
MAX_NODES = 64
MAX_READ_CALLS = 1024
MAX_TOTAL_READ_BYTES = 64 * 1024
MAX_SINGLE_READ_BYTES = 1024

# Exact fields in 2F0F90, including the two separately subtracted ledger cells.
LEDGER_OFFSETS = (
    0x770, 0x774, 0x778, 0x77C, 0x780, 0x784, 0x788, 0x78C,
    0x790, 0x7AC, 0x7B0, 0x7B4, 0x7B8, 0x7BC, 0x7C4, 0x7C8,
    0x7CC, 0x7D0, 0x7D4, 0x7D8, 0x7DC, 0x7E0, 0x7E4,
    0x824, 0x828, 0x834,
)


class _Unknown(Exception):
    pass


def _add(address: int, offset: int, size: int = 1) -> int:
    try:
        return common._checked_add(address, offset, size)
    except Exception as exc:
        raise _Unknown("ADDRESS_INVALID") from exc


def _pointer(value: Any, label: str, *, allow_null: bool = False) -> int:
    try:
        return common._pointer(value, label, alignment=8, allow_null=allow_null)
    except Exception as exc:
        raise _Unknown(f"{label}_POINTER_INVALID") from exc


class _Trace:
    def __init__(self, reader: Any):
        read = getattr(reader, "read", None)
        self._read = read if callable(read) else reader if callable(reader) else None
        self.rows: list[dict[str, Any]] = []
        self.calls = 0
        self.bytes_requested = 0

    def read(self, address: int, size: int, label: str) -> bytes:
        if self._read is None:
            raise _Unknown("READER_INVALID")
        if type(size) is not int or not 0 < size <= MAX_SINGLE_READ_BYTES:
            raise _Unknown("SINGLE_READ_LIMIT")
        address = _add(address, 0, size)
        if self.calls >= MAX_READ_CALLS or self.bytes_requested + size > MAX_TOTAL_READ_BYTES:
            raise _Unknown("READ_BUDGET_EXCEEDED")
        self.calls += 1
        self.bytes_requested += size
        row = {"ordinal": self.calls, "address": hex(address), "size": size,
               "label": label, "status": "requested"}
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

    def integer(self, address: int, size: int, label: str, *, signed: bool = False) -> int:
        return int.from_bytes(self.read(address, size, label), "little", signed=signed)

    def summary(self) -> dict[str, int]:
        return {"calls": self.calls, "bytes_requested": self.bytes_requested,
                "max_calls": MAX_READ_CALLS, "max_bytes": MAX_TOTAL_READ_BYTES,
                "max_single_read_bytes": MAX_SINGLE_READ_BYTES, "max_nodes": MAX_NODES}


def _echo(trace: _Trace, binding: Mapping[str, Any], phase: str, role: str) -> str:
    raw = trace.read(_add(binding["country_pointer"], common.COUNTRY_FULLREF_OFFSET, 8),
                     8, f"{phase}.{role}.fullref")
    if raw.hex() != binding["fullref_raw_hex"]:
        raise _Unknown(f"{role.upper()}_FULLREF_ECHO_MISMATCH")
    return raw.hex()


def _snapshot(trace: _Trace, base: int, observer: Mapping[str, Any],
              target: Mapping[str, Any], phase: str) -> dict[str, Any]:
    echoes = {role: _echo(trace, binding, phase, role)
              for role, binding in (("observer", observer), ("target", target))}
    country = target["country_pointer"]
    head = trace.integer(_add(country, 0xDE8, 8), 8, f"{phase}.loan_head")
    head = _pointer(head, "LOAN_HEAD", allow_null=True)
    count = trace.integer(_add(country, 0xDF8, 4), 4, f"{phase}.loan_count", signed=True)
    if not 0 <= count <= MAX_NODES:
        raise _Unknown("LOAN_COUNT_OUT_OF_BOUNDS")
    if (head == 0) != (count == 0):
        raise _Unknown("LOAN_HEAD_COUNT_MISMATCH")
    ledger = {offset: trace.integer(_add(country, offset, 4), 4,
                                   f"{phase}.ledger.{offset:x}", signed=True)
              for offset in LEDGER_OFFSETS}
    treasury = trace.integer(_add(country, 0xBB0, 4), 4, f"{phase}.treasury", signed=True)
    factor_u8 = trace.integer(_add(country, 0x1105), 1, f"{phase}.factor_u8")
    factor_raw = trace.integer(_add(country, 0xE3C, 4), 4, f"{phase}.factor_i32", signed=True)

    rows = []
    loans = []
    nodes: set[int] = set()
    records: set[int] = set()
    node = head
    for index in range(count):
        node = _pointer(node, "LOAN_NODE")
        if node in nodes:
            raise _Unknown("LOAN_NODE_CYCLE")
        nodes.add(node)
        record_raw = trace.read(node, 8, f"{phase}.node.{index}.record")
        next_raw = trace.read(_add(node, 0x10, 8), 8, f"{phase}.node.{index}.next")
        record = _pointer(int.from_bytes(record_raw, "little"), "LOAN_RECORD")
        if record in records:
            raise _Unknown("LOAN_RECORD_DUPLICATE")
        records.add(record)
        following = _pointer(int.from_bytes(next_raw, "little"),
                             "LOAN_NEXT", allow_null=True)
        loan = {
            "marker27": trace.integer(_add(record, 0x27), 1, f"{phase}.loan.{index}.marker27"),
            "stored_rate": trace.integer(_add(record, 0x28, 4), 4,
                                         f"{phase}.loan.{index}.stored_rate", signed=True),
            "principal": trace.integer(_add(record, 0x2C, 4), 4,
                                       f"{phase}.loan.{index}.principal", signed=True),
            "flag35": trace.integer(_add(record, 0x35), 1, f"{phase}.loan.{index}.flag35"),
        }
        rows.append({"node": hex(node), "record": hex(record),
                     "record_raw_hex": record_raw.hex(), "next_raw_hex": next_raw.hex()})
        loans.append(loan)
        if index + 1 < count and not following:
            raise _Unknown("LOAN_CHAIN_SHORTER_THAN_COUNT")
        if index + 1 == count and following:
            raise _Unknown("LOAN_CHAIN_LONGER_THAN_COUNT")
        node = following

    child = interest.read_state(trace, base, country)
    if child.get("status") != "known":
        raise _Unknown("HELPER_UNAVAILABLE:" + str(child.get("reason", "UNKNOWN")))
    # Compare all child reads as well as its numerical output; equal final sums
    # cannot hide a changed manager, representation, global, or processor slot.
    child_trace = child.get("raw_inputs", {}).get("ordered_read_trace")
    if not isinstance(child_trace, list) or not child_trace:
        raise _Unknown("HELPER_TRACE_INVALID")
    child_bytes = [(row["address"], row["size"], row["raw_hex"]) for row in child_trace
                   if row.get("status") == "ok"]
    if len(child_bytes) != len(child_trace):
        raise _Unknown("HELPER_TRACE_INVALID")
    return {"fullref_echoes": echoes, "head": hex(head), "count": count,
            "ledger_words": ledger, "treasury_raw_i32": treasury, "factor_u8": factor_u8,
            "factor_raw_i32": factor_raw, "nodes": rows, "loans": loans,
            "helper": deepcopy(child["value"]), "helper_input_bytes": child_bytes}


def read_state(reader: Any, module_base: Any, observer_binding: Any,
               target_binding: Any) -> dict[str, Any]:
    """Capture and calculate one private model; never grants publication.

    ``status=known`` describes model inputs and calculation under the declared
    SSE assumptions. Actual native execution/environment and foreign visibility
    are explicitly unverified, including when the calculated warning is false.
    """
    trace = _Trace(reader)
    inputs: dict[str, Any] = {
        "publication_admitted": False, "atomic_snapshot": False,
        "native_execution_observed": False, "native_fp_environment_verified": False,
        "parent_context_required": ["fresh_process_and_database_binding", "ROM_identity",
                                    "date_and_nonplayer_observer_binding", "foreign_disclosure",
                                    "native_SSE_rounding_and_exception_environment"],
        "model_limitations": ["null_modifier_processor_only", "cache_state_1_rejected",
                              "no_predicted_calendar_date", "no_already_bankrupt_inference"],
    }
    value = None
    reason = None
    try:
        base = _pointer(module_base, "MODULE_BASE")
        if base % 0x1000:
            raise _Unknown("MODULE_BASE_INVALID")
        observer = common._parse_binding(observer_binding, "observer")
        target = common._parse_binding(target_binding, "target")
        if any(observer[key] == target[key] for key in ("country_pointer", "slot", "fullref")):
            raise _Unknown("OBSERVER_TARGET_BINDINGS_ALIAS")
        inputs.update(module_base=hex(base), bindings={"observer": observer, "target": target})
        first = _snapshot(trace, base, observer, target, "before")
        inputs["before"] = first
        second = _snapshot(trace, base, observer, target, "after")
        inputs["after"] = second
        if first != second:
            raise _Unknown("FORECAST_INPUTS_CHANGED_AFTER_READ")
        value = arithmetic.evaluate(
            ledger_words=first["ledger_words"], loans=first["loans"],
            helper_return_i32=first["helper"]["helper_return_i32"],
            treasury_raw_i32=first["treasury_raw_i32"], factor_u8=first["factor_u8"],
            factor_raw_i32=first["factor_raw_i32"])
        if value.get("conversion_invalid") is not False:
            value = None
            raise _Unknown("NATIVE_FLOAT_CONVERSION_INVALID")
    except _Unknown as exc:
        reason = str(exc)
    except Exception as exc:
        reason = "INTERNAL_READ_ERROR:" + type(exc).__name__
        value = None
    inputs.update(ordered_read_trace=deepcopy(trace.rows), read_budget=trace.summary())
    result = {"schema": SCHEMA, "status": "known" if value is not None else "unknown",
              "basis": BASIS, "publication_admitted": False,
              "visibility": {"status": "unknown", "reason": "FOREIGN_DISCLOSURE_NOT_EVALUATED"},
              "native_execution_observed": False, "native_fp_environment_verified": False,
              "raw_inputs": inputs}
    if value is not None:
        result["value"] = value
    else:
        result["reason"] = reason
    return result
