"""Bounded raw claim-value and threshold projection for a person object.

The getter is identified by an exact vtable function pointer and is never
called. This leaf copies its backing signed integer plus the two signed global
thresholds used by the formatter; it does not predict inheritance or any
other game outcome.
"""
from __future__ import annotations

from typing import Any


SCHEMA = "information.person_claim_memory.v1"
BASIS = "projected_a52350_claim_formatter_thresholds"
MAX_USER_ADDRESS = 0x00007FFFFFFFFFFF
MIN_USER_ADDRESS = 0x10000
MAX_READ_CALLS = 8
MAX_TOTAL_READ_BYTES = 64
MAX_SINGLE_READ_BYTES = 8

PERSON_CLAIM_GETTER_RVA = 0xA559C0
PERSON_CLAIM_GETTER_VTABLE_OFFSET = 0x98
PERSON_CLAIM_RAW_OFFSET = 0x148
WEAK_THRESHOLD_RVA = 0x233E1C4
STRONG_THRESHOLD_RVA = 0x233F76C
CLAIM_SCALE = 1000


class _LeafFailure(ValueError):
    pass


def _parse_u64(value: Any, label: str, *, nonzero: bool = False) -> int:
    if type(value) is int:
        parsed = value
    elif isinstance(value, str) and 1 <= len(value) <= 20:
        try:
            parsed = int(value, 0)
        except ValueError as exc:
            raise _LeafFailure(f"{label}_invalid") from exc
    else:
        raise _LeafFailure(f"{label}_invalid")
    if not 0 <= parsed <= 0xFFFFFFFFFFFFFFFF or (nonzero and parsed == 0):
        raise _LeafFailure(f"{label}_out_of_range")
    return parsed


def _user_pointer(value: int, label: str, *, aligned: bool = False) -> int:
    if not MIN_USER_ADDRESS <= value <= MAX_USER_ADDRESS:
        raise _LeafFailure(f"{label}_invalid")
    if aligned and value & 7:
        raise _LeafFailure(f"{label}_unaligned")
    return value


def _checked_range(address: int, size: int, label: str) -> None:
    if type(address) is not int or type(size) is not int or size <= 0:
        raise _LeafFailure(f"{label}_range_invalid")
    end = address + size - 1
    if address < MIN_USER_ADDRESS or end > MAX_USER_ADDRESS or end < address:
        raise _LeafFailure(f"{label}_range_out_of_bounds")


def _unknown(reason: str, raw_inputs: dict[str, Any]) -> dict[str, Any]:
    raw_inputs.setdefault("read_budget", {
        "calls": 0,
        "bytes_requested": 0,
        "max_single_read": 0,
        "limit_calls": MAX_READ_CALLS,
        "limit_bytes": MAX_TOTAL_READ_BYTES,
        "limit_single_read": MAX_SINGLE_READ_BYTES,
    })
    return {
        "schema": SCHEMA,
        "status": "unknown",
        "reason": reason,
        "raw_inputs": raw_inputs,
        "basis": BASIS,
    }


def read_claim(limiter: Any, base: Any, person_pointer: Any) -> dict[str, Any]:
    """Read and classify a person claim component without invoking the getter.

    ``limiter`` must provide ``read(address, size, label)``. Only the exact
    getter at ``base+0xa559c0`` is accepted from person.vtable+0x98. The raw
    field and both threshold globals are signed 32-bit values and remain in
    the result so callers can audit the formatter's ordered comparisons.
    """
    raw: dict[str, Any] = {"read_trace": [], "read_failures": []}
    budget = {
        "calls": 0,
        "bytes_requested": 0,
        "max_single_read": 0,
        "limit_calls": MAX_READ_CALLS,
        "limit_bytes": MAX_TOTAL_READ_BYTES,
        "limit_single_read": MAX_SINGLE_READ_BYTES,
    }
    raw["read_budget"] = budget

    def read_exact(address: int, size: int, label: str) -> bytes:
        _checked_range(address, size, label)
        if size > MAX_SINGLE_READ_BYTES:
            raise _LeafFailure(f"{label}_read_size_out_of_bound")
        if budget["calls"] + 1 > MAX_READ_CALLS:
            raise _LeafFailure("read_call_budget_exceeded")
        if budget["bytes_requested"] + size > MAX_TOTAL_READ_BYTES:
            raise _LeafFailure("read_byte_budget_exceeded")
        budget["calls"] += 1
        budget["bytes_requested"] += size
        budget["max_single_read"] = max(budget["max_single_read"], size)
        row = {"address": hex(address), "size": size, "label": label}
        try:
            method = getattr(limiter, "read", None)
            if not callable(method):
                raise TypeError("limiter_read_unavailable")
            result = method(address, size, label)
            if not isinstance(result, (bytes, bytearray, memoryview)):
                raise TypeError("read_result_not_bytes")
            data = bytes(result)
            if len(data) != size:
                raise ValueError(f"short_read:{len(data)}:{size}")
        except Exception as exc:
            row.update({"status": "failed", "error": f"{type(exc).__name__}:{str(exc)[:160]}"})
            raw["read_trace"].append(row)
            raw["read_failures"].append(dict(row))
            raise _LeafFailure(f"{label}_read_failed") from exc
        row.update({"status": "observed", "raw_hex": data.hex()})
        raw["read_trace"].append(row)
        return data

    try:
        module_base = _user_pointer(_parse_u64(base, "module_base"), "module_base")
        person = _user_pointer(
            _parse_u64(person_pointer, "person_pointer", nonzero=True),
            "person_pointer", aligned=True)
        raw["module_base"] = hex(module_base)
        raw["person_pointer"] = hex(person)

        vtable_raw = read_exact(person, 8, "person.vtable_pointer")
        vtable = int.from_bytes(vtable_raw, "little")
        raw["person_vtable_pointer_raw_hex"] = vtable_raw.hex()
        raw["person_vtable_pointer"] = hex(vtable) if vtable else None
        if vtable == 0:
            raise _LeafFailure("person_vtable_null")
        try:
            _user_pointer(vtable, "person_vtable_pointer", aligned=True)
        except _LeafFailure as exc:
            raise _LeafFailure(str(exc)) from exc

        method_slot = vtable + PERSON_CLAIM_GETTER_VTABLE_OFFSET
        _checked_range(method_slot, 8, "person.claim_getter_slot")
        method_raw = read_exact(method_slot, 8, "person.claim_getter_slot")
        method = int.from_bytes(method_raw, "little")
        expected_method = module_base + PERSON_CLAIM_GETTER_RVA
        _checked_range(expected_method, 1, "person.claim_getter_expected")
        raw["claim_getter_slot_address"] = hex(method_slot)
        raw["claim_getter_pointer_raw_hex"] = method_raw.hex()
        raw["claim_getter_pointer"] = hex(method)
        raw["claim_getter_expected_pointer"] = hex(expected_method)
        raw["claim_getter_matches_expected"] = method == expected_method
        if method != expected_method:
            raise _LeafFailure("person_claim_getter_unrecognized")

        claim_address = person + PERSON_CLAIM_RAW_OFFSET
        _checked_range(claim_address, 4, "person.claim_raw")
        claim_bytes = read_exact(claim_address, 4, "person.claim_raw")
        claim_raw = int.from_bytes(claim_bytes, "little", signed=True)
        raw["claim_raw_address"] = hex(claim_address)
        raw["claim_raw_i32_hex"] = claim_bytes.hex()
        raw["claim_raw_i32"] = claim_raw

        weak_address = module_base + WEAK_THRESHOLD_RVA
        strong_address = module_base + STRONG_THRESHOLD_RVA
        _checked_range(weak_address, 4, "claim.weak_threshold")
        _checked_range(strong_address, 4, "claim.strong_threshold")
        weak_bytes = read_exact(weak_address, 4, "claim.weak_threshold")
        strong_bytes = read_exact(strong_address, 4, "claim.strong_threshold")
        weak_threshold = int.from_bytes(weak_bytes, "little", signed=True)
        strong_threshold = int.from_bytes(strong_bytes, "little", signed=True)
        raw["weak_threshold_address"] = hex(weak_address)
        raw["weak_threshold_raw_hex"] = weak_bytes.hex()
        raw["weak_threshold_raw_i32"] = weak_threshold
        raw["strong_threshold_address"] = hex(strong_address)
        raw["strong_threshold_raw_hex"] = strong_bytes.hex()
        raw["strong_threshold_raw_i32"] = strong_threshold

        if claim_raw < weak_threshold:
            category = "weak"
        elif claim_raw < strong_threshold:
            category = "average"
        else:
            category = "strong"
        raw["read_budget"] = budget
        return {
            "schema": SCHEMA,
            "status": "known",
            "value": {
                "raw": claim_raw,
                "scale": CLAIM_SCALE,
                "category": category,
                "weak_threshold_raw": weak_threshold,
                "strong_threshold_raw": strong_threshold,
            },
            "raw_inputs": raw,
            "basis": BASIS,
        }
    except _LeafFailure as exc:
        raw["read_budget"] = budget
        return _unknown(str(exc), raw)
    except Exception as exc:
        raw["read_budget"] = budget
        return _unknown(f"leaf_failure:{type(exc).__name__}", raw)


__all__ = ["read_claim"]
