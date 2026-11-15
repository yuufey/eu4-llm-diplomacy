"""Bounded internal reader for the current province trade-power cache.

The parent supplies the canonical province binding and owns observer role,
admission, discovery, profile/session checks, and two-pass stability.  This
leaf cross-checks the province-indexed trade-power manager against that
canonical record before copying the signed cache value.  It opens no process,
calls no game function, and does not predict an acquisition delta.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from . import province_identity_memory as _identity


FIELD_PROVINCE_TRADE_POWER = "G02.province_trade_power"
SUPPORTED_FIELDS = (FIELD_PROVINCE_TRADE_POWER,)

TRADE_POWER_MANAGER_GLOBAL_RVA = 0x233FEB8
MANAGER_HEADER_BEGIN_OFFSET = 0x6F0
MANAGER_HEADER_END_OFFSET = 0x6F8
MANAGER_HEADER_OFFSET = MANAGER_HEADER_BEGIN_OFFSET
MANAGER_HEADER_WIDTH = 0x10
PROVINCE_RECORD_STRIDE = 0x2E10
PROVINCE_ID_OFFSET = 0x20
PROVINCE_TRADE_POWER_OFFSET = 0x890
PROVINCE_ID_WIDTH = 4
TRADE_POWER_WIDTH = 4
POINTER_WIDTH = 8
MIN_PROVINCE_ID = 1
MAX_PROVINCE_ID = 0xFFFF
MAX_MANAGER_RECORDS = 0x10000
MAX_READ_BYTES = 128
MAX_READ_CALLS = 16

READ_MANAGER_GLOBAL = "province_trade_power.manager_global"
READ_MANAGER_HEADER = "province_trade_power.manager_header"
READ_PROVINCE_ID = "province_trade_power.record_id_echo"
READ_TRADE_POWER = "province_trade_power.cache_i32"
READ_MANAGER_GLOBAL_RECHECK = "province_trade_power.manager_global_recheck"
READ_MANAGER_HEADER_RECHECK = "province_trade_power.manager_header_recheck"

_BASIS = "native_province_trade_power_trigger_cache"
_GAPS = [
    "PROVINCE_VIEW_ADMISSION_AND_DISCOVERY_ARE_PARENT_OWNED",
    "PARENT_TWO_PASS_CONTEXT_AND_FIELD_STABILITY_ARE_PARENT_OWNED",
    "SESSION_PROFILE_AND_CODE_GUARDS_ARE_PARENT_OWNED",
    "CACHE_REFRESH_TIMING_AND_UI_RENDERING_ARE_NOT_PROVEN",
    "NODE_AGGREGATE_TP_PROVINCE_POWER_IS_NOT_THIS_PROVINCE_CACHE",
    "ACQUISITION_CAUSAL_DELTA_IS_NOT_PROVEN",
]


class _ReadFailure(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _BoundedReader:
    """Count exact RPM requests and fail closed before exceeding leaf limits."""

    def __init__(self, reader: Any) -> None:
        self.reader = reader
        self.bytes_requested = 0
        self.calls = 0
        self.failures: list[dict[str, Any]] = []

    def read(self, address: int, size: int, label: str) -> bytes:
        if (self.calls + 1 > MAX_READ_CALLS
                or self.bytes_requested + size > MAX_READ_BYTES):
            raise _ReadFailure("read_budget_exceeded")
        self.calls += 1
        self.bytes_requested += size
        try:
            return _identity._read_exact(self.reader, address, size, label)
        except Exception as exc:
            self.failures.append({
                "label": label,
                "address": hex(address) if type(address) is int else None,
                "size": size,
                "error": f"{type(exc).__name__}:{str(exc)[:160]}",
            })
            raise _ReadFailure(f"read_failed:{label}:{type(exc).__name__}:{str(exc)[:160]}") from exc

    def summary(self) -> dict[str, int]:
        return {
            "bytes_requested": self.bytes_requested,
            "calls": self.calls,
            "max_bytes": MAX_READ_BYTES,
            "max_calls": MAX_READ_CALLS,
        }


def _unknown(reason: str, raw_inputs: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "status": "unknown",
        "complete": False,
        "reason": reason,
        "raw_inputs": raw_inputs if raw_inputs is not None else {},
        "basis": _BASIS,
        "period": "current",
        "gaps": list(_GAPS),
    }


def _known(raw_value: int, raw_inputs: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "known",
        "complete": False,
        "value": {"raw": raw_value, "scale": 1000, "unit": "trade_power"},
        "raw_inputs": raw_inputs,
        "basis": _BASIS,
        "period": "current",
        "gaps": list(_GAPS),
    }


def _raw_binding(module_base: Any, province_binding: Any) -> dict[str, Any]:
    keys = ("province_id", "record_id", "record_pointer", "id_address", "id_raw_hex")
    return {
        "module_base": _identity._raw_scalar(module_base),
        "province_binding": {
            key: _identity._raw_scalar(province_binding.get(key))
            for key in keys
        } if isinstance(province_binding, Mapping) else _identity._raw_scalar(province_binding),
    }


def _read_field(reader: Any, module_base: Any, province_binding: Any) -> dict[str, Any]:
    trace: dict[str, Any] = {
        **_raw_binding(module_base, province_binding),
        "field": FIELD_PROVINCE_TRADE_POWER,
        "read_failures": [],
        "validation_errors": [],
    }
    budget = _BoundedReader(reader)
    reason: str | None = None
    raw_value: int | None = None
    try:
        base, canonical_record, binding = _identity._validate_binding(
            module_base, province_binding
        )
        province_id = binding["province_id"]
        if not MIN_PROVINCE_ID <= province_id <= MAX_PROVINCE_ID:
            raise _ReadFailure("province_id_out_of_supported_range")
        trace.update({
            "module_base": hex(base),
            "province_id": province_id,
            "canonical_record_address": hex(canonical_record),
            "canonical_binding_echo": dict(binding),
            "manager_global_rva": hex(TRADE_POWER_MANAGER_GLOBAL_RVA),
            "manager_header_begin_offset": hex(MANAGER_HEADER_BEGIN_OFFSET),
            "manager_header_end_offset": hex(MANAGER_HEADER_END_OFFSET),
            "record_stride": hex(PROVINCE_RECORD_STRIDE),
            "province_trade_power_offset": hex(PROVINCE_TRADE_POWER_OFFSET),
        })

        global_address = base + TRADE_POWER_MANAGER_GLOBAL_RVA
        _identity._checked_user_range(global_address, POINTER_WIDTH,
                                      "province_trade_power_manager_global")
        global_raw = budget.read(global_address, POINTER_WIDTH, READ_MANAGER_GLOBAL)
        manager = int.from_bytes(global_raw, "little", signed=False)
        _identity._user_pointer(manager, "province_trade_power_manager", aligned=True)
        header_address = manager + MANAGER_HEADER_OFFSET
        _identity._checked_user_range(header_address, MANAGER_HEADER_WIDTH,
                                      "province_trade_power_manager_header")
        header_raw = budget.read(header_address, MANAGER_HEADER_WIDTH,
                                 READ_MANAGER_HEADER)
        begin = int.from_bytes(
            header_raw[MANAGER_HEADER_BEGIN_OFFSET - MANAGER_HEADER_OFFSET:
                       MANAGER_HEADER_BEGIN_OFFSET - MANAGER_HEADER_OFFSET + POINTER_WIDTH],
            "little", signed=False,
        )
        end = int.from_bytes(
            header_raw[MANAGER_HEADER_END_OFFSET - MANAGER_HEADER_OFFSET:
                       MANAGER_HEADER_END_OFFSET - MANAGER_HEADER_OFFSET + POINTER_WIDTH],
            "little", signed=False,
        )
        if end < begin:
            raise _ReadFailure("manager_span_negative")
        span = end - begin
        if span % PROVINCE_RECORD_STRIDE:
            raise _ReadFailure("manager_span_not_stride_multiple")
        count = span // PROVINCE_RECORD_STRIDE
        if not 1 <= count <= MAX_MANAGER_RECORDS:
            raise _ReadFailure("manager_record_count_out_of_bounds")
        if province_id >= count:
            raise _ReadFailure("province_id_out_of_manager_count")
        _identity._checked_user_range(begin, span, "province_trade_power_record_array")
        _identity._user_pointer(begin, "province_trade_power_record_array", aligned=True)

        manager_record = begin + province_id * PROVINCE_RECORD_STRIDE
        _identity._checked_user_range(manager_record, PROVINCE_RECORD_STRIDE,
                                      "province_trade_power_manager_record")
        trace.update({
            "manager_global_address": hex(global_address),
            "manager_global_raw_hex": global_raw.hex(),
            "manager_pointer": hex(manager),
            "manager_header_address": hex(header_address),
            "manager_header_raw_hex": header_raw.hex(),
            "records_begin": hex(begin),
            "records_end": hex(end),
            "record_count": count,
            "province_record_index": province_id,
            "manager_record_address": hex(manager_record),
        })
        if manager_record != canonical_record:
            raise _ReadFailure("manager_record_canonical_binding_mismatch")

        id_address = manager_record + PROVINCE_ID_OFFSET
        _identity._checked_user_range(id_address, PROVINCE_ID_WIDTH,
                                      "province_trade_power_record_id")
        id_raw = budget.read(id_address, PROVINCE_ID_WIDTH, READ_PROVINCE_ID)
        id_value = int.from_bytes(id_raw, "little", signed=True)
        trace.update({
            "record_id_echo_address": hex(id_address),
            "record_id_echo_raw_hex": id_raw.hex(),
            "record_id_echo": id_value,
        })
        if id_value != province_id:
            raise _ReadFailure("manager_record_id_echo_mismatch")

        value_address = manager_record + PROVINCE_TRADE_POWER_OFFSET
        _identity._checked_user_range(value_address, TRADE_POWER_WIDTH,
                                      "province_trade_power_cache")
        value_raw = budget.read(value_address, TRADE_POWER_WIDTH, READ_TRADE_POWER)
        raw_value = int.from_bytes(value_raw, "little", signed=True)
        trace.update({
            "trade_power_address": hex(value_address),
            "trade_power_raw_hex": value_raw.hex(),
            "trade_power_raw_signed": raw_value,
        })

        global_recheck = budget.read(global_address, POINTER_WIDTH,
                                     READ_MANAGER_GLOBAL_RECHECK)
        header_recheck = budget.read(header_address, MANAGER_HEADER_WIDTH,
                                     READ_MANAGER_HEADER_RECHECK)
        trace.update({
            "manager_global_recheck_raw_hex": global_recheck.hex(),
            "manager_header_recheck_raw_hex": header_recheck.hex(),
        })
        if global_recheck != global_raw:
            raise _ReadFailure("manager_global_changed_during_read")
        if header_recheck != header_raw:
            raise _ReadFailure("manager_header_changed_during_read")
    except _ReadFailure as exc:
        reason = exc.reason
    except Exception as exc:
        reason = str(exc)[:200] or type(exc).__name__
        trace["validation_errors"].append({"error": reason})
    finally:
        trace["read_failures"] = list(budget.failures)
        trace["read_budget"] = budget.summary()

    if reason is not None or raw_value is None:
        return _unknown(reason or "trade_power_raw_unavailable", trace)
    return _known(raw_value, trace)


def read_fields(
    reader: Any,
    module_base: Any,
    province_binding: Any,
    fields: tuple[str, ...] | list[str],
) -> dict[str, dict[str, Any]]:
    """Read only the internal current province trade-power cache field."""
    if not isinstance(fields, (tuple, list)) or len(fields) > _identity.MAX_FIELDS:
        return {}
    if any(not isinstance(field, str) for field in fields):
        return {}
    unique_fields = tuple(dict.fromkeys(fields))
    if len(unique_fields) != len(fields):
        return {field: _unknown("duplicate_field_requested") for field in unique_fields}
    if not unique_fields:
        return {}

    unsupported = {
        field: _unknown("unsupported_field")
        for field in unique_fields if field not in SUPPORTED_FIELDS
    }
    if FIELD_PROVINCE_TRADE_POWER not in unique_fields:
        return unsupported
    result = dict(unsupported)
    result[FIELD_PROVINCE_TRADE_POWER] = _read_field(
        reader, module_base, province_binding
    )
    return result


__all__ = [
    "FIELD_PROVINCE_TRADE_POWER",
    "MAX_MANAGER_RECORDS",
    "MAX_PROVINCE_ID",
    "PROVINCE_RECORD_STRIDE",
    "PROVINCE_TRADE_POWER_OFFSET",
    "READ_MANAGER_GLOBAL",
    "READ_MANAGER_HEADER",
    "READ_MANAGER_GLOBAL_RECHECK",
    "READ_MANAGER_HEADER_RECHECK",
    "READ_PROVINCE_ID",
    "READ_TRADE_POWER",
    "SUPPORTED_FIELDS",
    "TRADE_POWER_MANAGER_GLOBAL_RVA",
    "read_fields",
]
