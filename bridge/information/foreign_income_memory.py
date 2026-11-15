"""Bounded reader for the foreign country-income comparison cache.

This private leaf consumes an independently validated income-page permission
record and an already-resolved country binding. It performs one exact 76-byte
read at country+0x770; it does not open a process, evaluate native code, or
infer current payment obligations from the previous-month income cache.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from . import country_faith_memory as _faith
from . import foreign_economy_visibility_memory as _permission

SCHEMA = "information.foreign_income_memory.v1"
BASIS = "native_country_income_comparison_cache"
FIELD_INCOME = "F03.income"
FIELD_REPARATIONS = "F03.reparations"
FIELD_SUBSIDIES = "F03.subsidies"
FIELDS = (FIELD_INCOME, FIELD_REPARATIONS, FIELD_SUBSIDIES)

COUNTRY_INCOME_CACHE_OFFSET = 0x770
INCOME_CATEGORY_COUNT = 19
INCOME_CATEGORY_BYTES = INCOME_CATEGORY_COUNT * 4
NATIVE_TOTAL_INDICES = (0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 14, 15, 16, 17, 18)
VISIBLE_CATEGORY_KEYS = (
    (0, "INCOMETAX"),
    (1, "INCOMEPROD"),
    (2, "INCOMETRADE"),
    (3, "INCOMEGOLD"),
    (4, "INCOMETARRIFFS"),
    (5, "INCOMEVASSAL"),
    (6, "INCOMEHARBORFEES"),
    (7, "INCOMESUBS"),
    (8, "INCOME_WAR_REPARATION"),
    (12, "SPOILS_OF_WAR_ECOVIEW"),
    (15, "CONDOTTIERI"),
    (16, "KNOWLEDGE_SHARING"),
    (17, "INC_BLOCKADES"),
    (18, "INC_LOOTING"),
)
REPARATIONS_INDEX = 8
SUBSIDIES_INDEX = 7

MIN_USER_ADDRESS = 0x10000
MAX_USER_ADDRESS_EXCLUSIVE = 0x800000000000
MAX_U64 = 0xFFFFFFFFFFFFFFFF
MAX_READ_CALLS = 128
MAX_TOTAL_READ_BYTES = 64 * 1024
MAX_SINGLE_READ_BYTES = 1024


class _Unknown(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _is_user_address(value: Any) -> bool:
    return (type(value) is int and MIN_USER_ADDRESS <= value < MAX_USER_ADDRESS_EXCLUSIVE
            and value <= MAX_U64)


def _checked_add(address: int, offset: int, size: int) -> int:
    if (type(address) is not int or type(offset) is not int or type(size) is not int
            or not _is_user_address(address) or offset < 0 or size <= 0
            or address > MAX_U64 - offset):
        raise _Unknown("ADDRESS_INVALID")
    result = address + offset
    if (not _is_user_address(result) or result > MAX_U64 - (size - 1)
            or result + size > MAX_USER_ADDRESS_EXCLUSIVE):
        raise _Unknown("ADDRESS_INVALID")
    return result


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

    def summary(self) -> dict[str, int]:
        return {"calls": self.calls, "bytes_requested": self.bytes_requested,
                "max_calls": MAX_READ_CALLS, "max_bytes": MAX_TOTAL_READ_BYTES,
                "max_single_read_bytes": MAX_SINGLE_READ_BYTES}


def _unknown_field(reason: str, permission: Any, target_binding: Any,
                   base: Any, trace: _Trace, *, raw: Mapping[str, Any] | None = None
                   ) -> dict[str, Any]:
    evidence = dict(raw or {})
    evidence.setdefault("schema", SCHEMA)
    evidence.setdefault("module_base", hex(base) if type(base) is int else None)
    evidence.setdefault("target_binding", deepcopy(dict(target_binding))
                        if isinstance(target_binding, Mapping) else None)
    evidence.setdefault("permission", deepcopy(dict(permission))
                        if isinstance(permission, Mapping) else None)
    evidence.setdefault("permission_validation", {"status": "unknown", "reason": None})
    evidence.setdefault("target_binding_validation", None)
    evidence["reads"] = deepcopy(trace.reads)
    evidence["read_budget"] = trace.summary()
    return {"status": "unknown", "reason": reason,
            "basis": BASIS, "partial": True, "complete": False,
            "raw_inputs": evidence}


def _amount(value: int) -> dict[str, Any]:
    return {"value": value, "raw": value, "unit": "ducats", "scale": 1000,
            "period": "month", "reference": "previous_month"}


def _wrap_i32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _requested_fields(fields: Any) -> tuple[list[str], dict[str, dict[str, Any]]]:
    if not isinstance(fields, (tuple, list)):
        return [], {FIELD_INCOME: _request_error("FIELDS_SHAPE_INVALID")}
    if any(not isinstance(field, str) for field in fields):
        return [], {FIELD_INCOME: _request_error("FIELDS_SHAPE_INVALID")}
    requested = list(fields)
    if len(requested) != len(set(requested)):
        return [], {field: _request_error("DUPLICATE_FIELD_REQUESTED") for field in set(requested)}
    unsupported = {field: _request_error("FIELD_UNSUPPORTED") for field in requested
                   if field not in FIELDS}
    return [field for field in requested if field in FIELDS], unsupported


def _request_error(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason, "basis": BASIS,
            "partial": True, "complete": False, "raw_inputs": {}}


def _same_country_binding(left: Any, right: Any) -> bool:
    try:
        left_pointer, left_row = _faith._binding(left)
        right_pointer, right_row = _faith._binding(right)
    except Exception:
        return False
    return (left_pointer == right_pointer
            and left_row.get("tag") == right_row.get("tag")
            and left_row.get("slot") == right_row.get("slot")
            and left_row.get("fullref") == right_row.get("fullref")
            and left_row.get("fullref_raw_hex") == right_row.get("fullref_raw_hex"))


def _validate_permission(permission: Any, base: Any, target_binding: Any) -> tuple[str, str | None, dict[str, Any] | None]:
    if not _permission.validate_permission(permission, page=_permission.INCOME_PAGE):
        return "unknown", "INCOME_PERMISSION_INVALID", None
    if (not isinstance(permission, Mapping)
            or permission.get("status") != "known"
            or type(permission.get("admitted")) is not bool):
        return "unknown", "INCOME_PERMISSION_UNKNOWN", None
    if permission.get("admitted") is not True:
        return "denied", "INCOME_PERMISSION_NOT_ADMITTED", None
    if type(base) is not int or not _is_user_address(base) or base & 0xFFF:
        return "unknown", "MODULE_BASE_INVALID", None
    try:
        permission_base = int(permission.get("module_base"), 16)
    except (TypeError, ValueError):
        return "unknown", "INCOME_PERMISSION_MODULE_BASE_INVALID", None
    if permission_base != base:
        return "unknown", "INCOME_PERMISSION_MODULE_BASE_MISMATCH", None
    if not _same_country_binding(permission.get("target_binding"), target_binding):
        return "unknown", "INCOME_PERMISSION_TARGET_MISMATCH", None
    try:
        pointer, target = _faith._binding(target_binding)
    except Exception:
        return "unknown", "TARGET_BINDING_INVALID", None
    if ((int(target["fullref"], 16) >> 24) & 0xFF) != 0:
        return "unknown", "TARGET_FULLREF_KIND_UNSUPPORTED", None
    if not isinstance(permission.get("target_binding"), Mapping):
        return "unknown", "INCOME_PERMISSION_TARGET_BINDING_INVALID", None
    target.update({"country_pointer": hex(pointer)})
    return "admitted", None, target


def read_fields(reader: Any, base: int, target_binding: Any, fields: Any, *,
                permission: Any) -> dict[str, dict[str, Any]]:
    """Read selected previous-month income values after strict page permission.

    The single native cache block has nineteen signed-i32 entries. The public
    value projection exports the native total and only the fourteen displayed
    categories; index 14 contributes to the native total but is not emitted as
    an independent category.
    """
    selected, request_errors = _requested_fields(fields)
    if not selected:
        return request_errors

    trace = _Trace(reader)
    permission_state, permission_reason, target = _validate_permission(
        permission, base, target_binding)
    raw_base: dict[str, Any] = {
        "schema": SCHEMA,
        "module_base": hex(base) if type(base) is int else None,
        "target_binding": deepcopy(target) if target is not None else None,
        "permission": deepcopy(dict(permission)) if isinstance(permission, Mapping) else None,
        "permission_validation": {"status": permission_state, "reason": permission_reason},
        "cache_slice": None,
    }
    if permission_state != "admitted" or target is None:
        reason = permission_reason or "INCOME_PERMISSION_NOT_ADMITTED"
        result = {field: _unknown_field(reason, permission, target_binding, base, trace,
                                       raw=raw_base) for field in selected}
        result.update(request_errors)
        return result

    try:
        country_pointer = int(target["country_pointer"], 16)
        address = _checked_add(country_pointer, COUNTRY_INCOME_CACHE_OFFSET,
                                INCOME_CATEGORY_BYTES)
        raw_bytes = trace.exact(address, INCOME_CATEGORY_BYTES,
                                "income.previous_month_i32_categories_0_18")
        values = [int.from_bytes(raw_bytes[index * 4:(index + 1) * 4],
                                 "little", signed=True)
                  for index in range(INCOME_CATEGORY_COUNT)]
        total = _wrap_i32(sum(values[index] for index in NATIVE_TOTAL_INDICES))
        raw_base["cache_slice"] = {
            "address": hex(address), "bytes": INCOME_CATEGORY_BYTES,
            "raw_hex": raw_bytes.hex(), "category_count": INCOME_CATEGORY_COUNT,
            "native_i32_values_by_index": [
                {"index": index, "raw_hex": raw_bytes[index * 4:(index + 1) * 4].hex(),
                 "value_i32": value}
                for index, value in enumerate(values)
            ],
            "native_total_indices": list(NATIVE_TOTAL_INDICES),
            "visible_category_indices": [index for index, _key in VISIBLE_CATEGORY_KEYS],
            "native_total_raw_i32": total,
        }
    except _Unknown as exc:
        result = {field: _unknown_field("INCOME_CACHE_READ_FAILED", permission,
                                       target_binding, base, trace,
                                       raw={**raw_base, "read_failure": exc.reason})
                  for field in selected}
        result.update(request_errors)
        return result
    except Exception as exc:
        result = {field: _unknown_field("INCOME_CACHE_READ_FAILED", permission,
                                       target_binding, base, trace,
                                       raw={**raw_base, "read_failure": type(exc).__name__})
                  for field in selected}
        result.update(request_errors)
        return result

    raw_base["reads"] = deepcopy(trace.reads)
    raw_base["read_budget"] = trace.summary()
    categories = [
        {"index": index, "localization_key": key, "amount": _amount(values[index])}
        for index, key in VISIBLE_CATEGORY_KEYS
    ]
    total_amount = _amount(total)

    def field_result(value: Any) -> dict[str, Any]:
        return {"status": "known", "value": deepcopy(value),
                "unit": "ducats", "scale": 1000,
                "period": "month", "reference": "previous_month",
                "basis": BASIS, "partial": True, "complete": False,
                "raw_inputs": deepcopy(raw_base)}

    result: dict[str, dict[str, Any]] = {}
    for field in selected:
        if field == FIELD_INCOME:
            value = {"native_ledger_total": total_amount,
                     "visible_categories": categories,
                     "total_includes_additional_native_terms": True}
        elif field == FIELD_REPARATIONS:
            value = {
                "received_previous_month": _amount(values[REPARATIONS_INDEX]),
                "current_payment_obligations": {
                    "status": "unknown", "reason": "CURRENT_REPARATION_OBLIGATIONS_NOT_CAPTURED"},
                "active_contracts": {
                    "status": "unknown", "reason": "ACTIVE_REPARATION_CONTRACTS_NOT_CAPTURED"},
            }
        else:
            value = {
                "received_previous_month": _amount(values[SUBSIDIES_INDEX]),
                "current_payment_obligations": {
                    "status": "unknown", "reason": "CURRENT_SUBSIDY_OBLIGATIONS_NOT_CAPTURED"},
                "active_contracts": {
                    "status": "unknown", "reason": "ACTIVE_SUBSIDY_CONTRACTS_NOT_CAPTURED"},
            }
        result[field] = field_result(value)
    result.update(request_errors)
    return result


__all__ = ["SCHEMA", "BASIS", "FIELDS", "FIELD_INCOME", "FIELD_REPARATIONS",
           "FIELD_SUBSIDIES", "COUNTRY_INCOME_CACHE_OFFSET", "INCOME_CATEGORY_COUNT",
           "INCOME_CATEGORY_BYTES", "NATIVE_TOTAL_INDICES", "VISIBLE_CATEGORY_KEYS",
           "read_fields"]
