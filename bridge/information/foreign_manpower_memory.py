"""Bounded raw leaf for the selected foreign country's manpower statistic.

The parent owns process/session identity, the full country scan, the country
view admission predicate, and before/after consistency.  This leaf accepts an
already resolved country binding and a parent-produced admission result; it
does not open a process, run a game function, or infer UI formatting.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import json
from typing import Any

from . import country_scale_development_memory as _country_binding


FIELD_ID = "F02.manpower"
BASIS = "native_manpower_statistic"
UNIT = "native_manpower_statistic"
SCALE = 1
PERIOD = "current"
COMPLETE = False
PARTIAL = True

MANPOWER_OFFSETS = (0x10B8, 0x10BA, 0x10BC)
DEFINITION_POINTER_OFFSETS = (0xD48, 0xD50, 0xD58)
DEFINITION_COST_OFFSET = 0x54
RESERVE_OFFSET = 0xDB8

MIN_USER_ADDRESS = 0x10000
MAX_USER_ADDRESS_EXCLUSIVE = 0x800000000000
MAX_READ_CALLS = 256
MAX_TOTAL_READ_BYTES = 16_384
MAX_SINGLE_READ_BYTES = 8_192
MAX_U64 = 0xFFFFFFFFFFFFFFFF

GAPS = (
    "DISPLAY_UNIT_AND_FORMATTING_NOT_VERIFIED",
    "COMPONENT_CATEGORY_NAMES_NOT_VERIFIED",
    "COUNTRY_VIEW_PERMISSION_IS_PARENT_SUPPLIED",
    "TWO_PASS_AND_SESSION_VALIDATION_ARE_PARENT_OWNED",
)


class _LeafReadError(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _json_copy(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, ensure_ascii=False))
    except (TypeError, ValueError, OverflowError):
        return {"unserializable_type": type(value).__name__}


def _empty_raw(target_binding: Any, permission: Any) -> dict[str, Any]:
    return {
        "target_binding": _json_copy(target_binding),
        "permission": _json_copy(permission),
        "binding_revalidation": None,
        "field_addresses": None,
        "components": [],
        "reserve": None,
        "read_log": [],
        "budget": {
            "calls": 0,
            "bytes_requested": 0,
            "max_calls": MAX_READ_CALLS,
            "max_total_bytes": MAX_TOTAL_READ_BYTES,
            "max_single_read_bytes": MAX_SINGLE_READ_BYTES,
        },
    }


def _field(status: str, *, reason: str | None = None,
           value: Mapping[str, Any] | None = None,
           raw_inputs: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": status,
        "complete": COMPLETE,
        "partial": PARTIAL,
        "basis": BASIS,
        "unit": UNIT,
        "scale": SCALE,
        "period": PERIOD,
        "gaps": list(GAPS),
    }
    if reason is not None:
        result["reason"] = reason
    if value is not None:
        result["value"] = dict(value)
    if raw_inputs is not None:
        result["raw_inputs"] = _json_copy(raw_inputs)
    return result


def _unknown(reason: str, raw_inputs: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return _field("unknown", reason=reason, raw_inputs=raw_inputs)


def _tag_from_fullref(fullref: int) -> str | None:
    raw = (fullref & 0xFFFFFF).to_bytes(3, "little")
    if not all(0x30 <= byte <= 0x39 or 0x41 <= byte <= 0x5A for byte in raw):
        return None
    return raw.decode("ascii")


def _identity(binding: Mapping[str, Any]) -> tuple[str, int, int, int]:
    tag = binding.get("tag")
    slot = binding.get("slot")
    pointer = int(str(binding.get("country_pointer")), 0)
    fullref = int(str(binding.get("fullref")), 0)
    return tag, slot, pointer, fullref


class _BudgetReader:
    """Callable-source adapter enforcing this leaf's local RPM budget."""

    def __init__(self, source: Any):
        self.source = source
        self.calls = 0
        self.bytes_requested = 0
        self.max_single = 0
        self.read_log: list[dict[str, Any]] = []
        self.failure_reason: str | None = None

    def read(self, address: int, size: int, label: str) -> bytes:
        valid = (
            type(address) is int
            and MIN_USER_ADDRESS <= address < MAX_USER_ADDRESS_EXCLUSIVE
            and type(size) is int
            and 0 < size <= MAX_SINGLE_READ_BYTES
            and address <= MAX_USER_ADDRESS_EXCLUSIVE - size
            and isinstance(label, str)
            and bool(label)
        )
        if not valid:
            self.failure_reason = "READ_REQUEST_INVALID"
            self.read_log.append({"address": hex(address) if type(address) is int else None,
                                  "size": size if type(size) is int else None,
                                  "label": label if isinstance(label, str) else None,
                                  "status": "rejected", "reason": self.failure_reason})
            raise _LeafReadError(self.failure_reason)
        if self.calls >= MAX_READ_CALLS or self.bytes_requested + size > MAX_TOTAL_READ_BYTES:
            self.failure_reason = "READ_BUDGET_EXCEEDED"
            self.read_log.append({"address": hex(address), "size": size, "label": label,
                                  "status": "rejected", "reason": self.failure_reason})
            raise _LeafReadError(self.failure_reason)

        self.calls += 1
        self.bytes_requested += size
        self.max_single = max(self.max_single, size)
        try:
            method = getattr(self.source, "read", None)
            raw = method(address, size, label) if callable(method) else self.source(address, size, label)
        except Exception as exc:
            self.failure_reason = "READ_FAILED"
            self.read_log.append({"address": hex(address), "size": size, "label": label,
                                  "status": "failed", "error_type": type(exc).__name__})
            raise _LeafReadError(self.failure_reason) from exc
        if not isinstance(raw, (bytes, bytearray, memoryview)) or len(raw) != size:
            self.failure_reason = "READ_FAILED"
            actual = len(raw) if isinstance(raw, (bytes, bytearray, memoryview)) else None
            self.read_log.append({"address": hex(address), "size": size, "label": label,
                                  "status": "failed", "error_type": "short_or_invalid_read",
                                  "actual_size": actual})
            raise _LeafReadError(self.failure_reason)
        data = bytes(raw)
        self.read_log.append({"address": hex(address), "size": size, "label": label,
                              "status": "ok", "raw_hex": data.hex()})
        return data

    def summary(self) -> dict[str, int]:
        return {"calls": self.calls, "bytes_requested": self.bytes_requested,
                "max_single_read": self.max_single, "max_calls": MAX_READ_CALLS,
                "max_total_bytes": MAX_TOTAL_READ_BYTES,
                "max_single_read_bytes": MAX_SINGLE_READ_BYTES}


def _checked_add(base: int, offset: int, size: int, label: str) -> int:
    if (type(base) is not int or not MIN_USER_ADDRESS <= base < MAX_USER_ADDRESS_EXCLUSIVE
            or type(offset) is not int or offset < 0 or type(size) is not int or size <= 0
            or base > MAX_U64 - offset):
        raise _LeafReadError("TARGET_ADDRESS_INVALID")
    address = base + offset
    if (not MIN_USER_ADDRESS <= address < MAX_USER_ADDRESS_EXCLUSIVE
            or address > MAX_USER_ADDRESS_EXCLUSIVE - size):
        raise _LeafReadError("TARGET_ADDRESS_INVALID")
    return address


def _user_pointer(value: int, label: str) -> int:
    if (type(value) is not int or not MIN_USER_ADDRESS <= value < MAX_USER_ADDRESS_EXCLUSIVE
            or value > MAX_U64 or value & 7):
        raise _LeafReadError("DEFINITION_POINTER_INVALID")
    return value


def _u16(raw: bytes) -> int:
    return int.from_bytes(raw, "little", signed=False)


def _i32(raw: bytes) -> int:
    return int.from_bytes(raw, "little", signed=True)


def _wrap_i32(value: int) -> int:
    low = value & 0xFFFFFFFF
    return low - 0x100000000 if low & 0x80000000 else low


def _permission_result(permission: Any, base: int,
                       target: Mapping[str, Any]) -> tuple[str, str | None]:
    if not isinstance(permission, Mapping):
        return "unknown", "COUNTRY_VIEW_PERMISSION_REQUIRED"
    if permission.get("status") == "unknown":
        return "unknown", "COUNTRY_VIEW_PERMISSION_UNKNOWN"
    if (permission.get("schema") != "information.foreign_military_visibility_memory.v1"
            or permission.get("status") != "known"
            or type(permission.get("admitted")) is not bool):
        return "unknown", "COUNTRY_VIEW_PERMISSION_INVALID"

    def checked_permission_binding(role: str) -> tuple[dict[str, Any] | None, str | None]:
        public = permission.get(role)
        inputs = permission.get("raw_inputs")
        if not isinstance(public, Mapping) or not isinstance(inputs, Mapping):
            return None, "COUNTRY_VIEW_PERMISSION_INVALID"
        raw_binding = inputs.get(role + "_binding")
        validation = inputs.get(role + "_binding_validation")
        try:
            parsed_base, _, permission_binding = _country_binding._parse_target(base, raw_binding)
            if parsed_base != base:
                return None, "COUNTRY_VIEW_PERMISSION_INVALID"
            if (public.get("tag") != permission_binding.get("tag")
                    or type(public.get("slot")) is not int
                    or public.get("slot") != permission_binding.get("slot")):
                return None, "COUNTRY_VIEW_PERMISSION_TARGET_MISMATCH"
            if not isinstance(validation, Mapping):
                return None, "COUNTRY_VIEW_PERMISSION_INVALID"
            validated_binding = validation.get("binding")
            _, _, validated = _country_binding._parse_target(base, validated_binding)
            if _identity(validated) != _identity(permission_binding):
                return None, "COUNTRY_VIEW_PERMISSION_TARGET_MISMATCH"
            resolution = validation.get("fullref_resolution")
            evidence = resolution.get("raw_inputs") if isinstance(resolution, Mapping) else None
            if (not isinstance(resolution, Mapping) or resolution.get("status") != "known"
                    or resolution.get("value") != permission_binding.get("tag")
                    or not isinstance(evidence, Mapping)):
                return None, "COUNTRY_VIEW_PERMISSION_INVALID"
            resolved_pointer = int(str(evidence.get("country_pointer")), 0)
            resolved_fullref = int(str(evidence.get("canonical_fullref")), 0)
            if (resolved_pointer != int(permission_binding["country_pointer"], 0)
                    or resolved_fullref != int(permission_binding["fullref"], 0)):
                return None, "COUNTRY_VIEW_PERMISSION_TARGET_MISMATCH"
            return permission_binding, None
        except Exception:
            return None, "COUNTRY_VIEW_PERMISSION_INVALID"

    observer, observer_error = checked_permission_binding("observer")
    if observer_error is not None:
        return "unknown", observer_error
    if observer is None or observer.get("tag") != "FRA":
        return "unknown", "COUNTRY_VIEW_OBSERVER_NOT_FRA"
    permission_target, target_error = checked_permission_binding("target")
    if target_error is not None:
        return "unknown", target_error
    if permission_target is None or permission_target.get("tag") == "FRA":
        return "unknown", "COUNTRY_VIEW_PERMISSION_TARGET_MISMATCH"
    if _identity(permission_target) != _identity(target):
        return "unknown", "COUNTRY_VIEW_PERMISSION_TARGET_MISMATCH"
    if permission["admitted"] is False:
        return "invisible", "COUNTRY_VIEW_NOT_ADMITTED"
    return "admitted", None


def _read_manpower(reader: _BudgetReader, base: int, target_pointer: int,
                    target: Mapping[str, Any], permission: Any,
                    raw_inputs: dict[str, Any]) -> dict[str, Any]:
    addresses = {
        "component_addresses": [
            {"count_address": hex(_checked_add(target_pointer, count_offset, 2,
                                                f"count_{index}")),
             "definition_pointer_address": hex(_checked_add(
                 target_pointer, pointer_offset, 8, f"definition_pointer_{index}")),
             "definition_cost_offset": hex(DEFINITION_COST_OFFSET)}
            for index, (count_offset, pointer_offset) in enumerate(
                zip(MANPOWER_OFFSETS, DEFINITION_POINTER_OFFSETS))
        ],
        "reserve_address": hex(_checked_add(target_pointer, RESERVE_OFFSET, 4, "reserve")),
    }
    raw_inputs["field_addresses"] = addresses
    components: list[dict[str, Any]] = []
    raw_component_rows: list[dict[str, Any]] = []
    recruited_total_raw = 0

    for index, (count_offset, pointer_offset) in enumerate(
            zip(MANPOWER_OFFSETS, DEFINITION_POINTER_OFFSETS)):
        count_address = _checked_add(target_pointer, count_offset, 2, f"count_{index}")
        pointer_address = _checked_add(target_pointer, pointer_offset, 8,
                                       f"definition_pointer_{index}")
        count_raw = reader.read(count_address, 2, f"foreign_manpower.component[{index}].count_u16")
        count = _u16(count_raw)
        raw_row: dict[str, Any] = {
            "index": index,
            "count_address": hex(count_address),
            "count_raw_hex": count_raw.hex(),
            "count_u16": count,
            "definition_pointer_address": hex(pointer_address),
        }
        if count == 0:
            cost: dict[str, Any] = {"status": "not_applicable"}
            contribution = 0
            raw_row.update({"definition_pointer_read": False,
                            "definition_cost_status": "not_applicable",
                            "contribution_raw": contribution})
        else:
            pointer_raw = reader.read(pointer_address, 8,
                                      f"foreign_manpower.component[{index}].definition_pointer_u64")
            definition = int.from_bytes(pointer_raw, "little", signed=False)
            raw_row.update({"definition_pointer_raw_hex": pointer_raw.hex(),
                            "definition_pointer": hex(definition) if definition else None,
                            "definition_pointer_read": True})
            try:
                _user_pointer(definition, f"definition_{index}")
                cost_address = _checked_add(definition, DEFINITION_COST_OFFSET, 4,
                                            f"definition_cost_{index}")
            except _LeafReadError:
                raw_component_rows.append(raw_row)
                raw_inputs["components"] = raw_component_rows
                raise
            cost_raw = reader.read(cost_address, 4,
                                   f"foreign_manpower.component[{index}].definition_cost_i32")
            definition_cost = _i32(cost_raw)
            contribution = _wrap_i32(count * definition_cost)
            cost = {"status": "known", "raw": definition_cost}
            raw_row.update({"definition_cost_address": hex(cost_address),
                            "definition_cost_raw_hex": cost_raw.hex(),
                            "definition_cost_i32": definition_cost,
                            "contribution_raw": contribution})
        recruited_total_raw = _wrap_i32(recruited_total_raw + contribution)
        components.append({"count": count, "definition_cost": cost,
                           "contribution_raw": contribution})
        raw_component_rows.append(raw_row)

    raw_inputs["components"] = raw_component_rows
    reserve_address = _checked_add(target_pointer, RESERVE_OFFSET, 4, "reserve")
    reserve_raw_bytes = reader.read(reserve_address, 4,
                                    "foreign_manpower.reserve_i32")
    reserve_raw = _i32(reserve_raw_bytes)
    raw_inputs["reserve"] = {"address": hex(reserve_address),
                              "raw_hex": reserve_raw_bytes.hex(),
                              "i32": reserve_raw}
    total_raw = _wrap_i32(reserve_raw + recruited_total_raw)
    raw_inputs["calculation"] = {
        "arithmetic": "signed_i32_low32_wrap",
        "recruited_total_raw": recruited_total_raw,
        "reserve_raw": reserve_raw,
        "total_raw": total_raw,
    }
    value = {"reserve_raw": reserve_raw, "components": components,
             "recruited_total_raw": recruited_total_raw, "total_raw": total_raw}
    return _field("known", value=value, raw_inputs=raw_inputs)


def read_fields(reader: Any, base: int, target_binding: Mapping[str, Any],
                fields: tuple[str, ...] | list[str], *,
                permission: Mapping[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    """Read only ``F02.manpower`` for a parent-bound and admitted target.

    Country-table resolution is rechecked through the existing bounded pure
    resolver.  The caller remains responsible for its full scan, permission
    provenance, session identity, code guards, and two-pass comparison.
    """
    if not isinstance(fields, (tuple, list)) or len(fields) > 16 or any(
            not isinstance(field, str) for field in fields):
        return {FIELD_ID: _unknown("FIELDS_SHAPE_INVALID")}
    if len(set(fields)) != len(fields):
        return {FIELD_ID: _unknown("DUPLICATE_FIELD_REQUESTED")}
    result: dict[str, dict[str, Any]] = {}
    for field in fields:
        if field != FIELD_ID:
            result[field] = _unknown("UNSUPPORTED_FIELD")
            continue
        result[field] = _read_one(reader, base, target_binding, permission)
    return result


def _read_one(reader: Any, base: int, target_binding: Mapping[str, Any],
              permission: Mapping[str, Any] | None) -> dict[str, Any]:
    raw_inputs = _empty_raw(target_binding, permission)
    try:
        base_value, target_pointer, retained = _country_binding._parse_target(base, target_binding)
    except Exception:
        return _unknown("TARGET_BINDING_INVALID", raw_inputs)
    raw_inputs["module_base"] = hex(base_value)
    raw_inputs["target_binding"] = _json_copy(retained)

    permission_status, permission_reason = _permission_result(permission, base_value, retained)
    if permission_status != "admitted":
        return _field(permission_status, reason=permission_reason, raw_inputs=raw_inputs)

    limiter = _BudgetReader(reader)
    try:
        revalidation = _country_binding._validate_target_binding(
            limiter, base_value, target_pointer, retained)
    except Exception as exc:
        raw_inputs["binding_revalidation"] = {
            "status": "failed", "error_type": type(exc).__name__}
        raw_inputs["read_log"] = limiter.read_log
        raw_inputs["budget"] = limiter.summary()
        reason = limiter.failure_reason or "TARGET_BINDING_REVALIDATION_FAILED"
        return _unknown(reason, raw_inputs)
    raw_inputs["binding_revalidation"] = {"status": "known", **revalidation}
    try:
        result = _read_manpower(limiter, base_value, target_pointer, retained,
                                permission, raw_inputs)
    except _LeafReadError as exc:
        reason = exc.reason
        result = _unknown(reason, raw_inputs)
    except Exception:
        result = _unknown("TARGET_MANPOWER_READ_FAILED", raw_inputs)
    raw_inputs["read_log"] = limiter.read_log
    raw_inputs["budget"] = limiter.summary()
    # `_read_manpower` returns a copy before this post-read summary is attached.
    if result.get("status") == "known":
        result["raw_inputs"] = _json_copy(raw_inputs)
    else:
        result["raw_inputs"] = _json_copy(raw_inputs)
    return result


__all__ = [
    "FIELD_ID", "BASIS", "UNIT", "SCALE", "PERIOD", "MANPOWER_OFFSETS",
    "DEFINITION_POINTER_OFFSETS", "DEFINITION_COST_OFFSET", "RESERVE_OFFSET",
    "MAX_READ_CALLS", "MAX_TOTAL_READ_BYTES", "MAX_SINGLE_READ_BYTES",
    "read_fields",
]
