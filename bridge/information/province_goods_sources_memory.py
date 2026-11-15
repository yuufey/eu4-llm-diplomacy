"""Candidate leaf for one cached province goods modifier component.

The parent owns province discovery/admission, session and code guards, and the
outer two-pass identity check. This leaf reads a ready cache container, its
cached modifier component and the merged aggregate. It reports only those raw
values and their signed-i32 residual; the definition key is not proof that this
is the only runtime source of the aggregate.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from . import foreign_quality_memory as _foreign
from . import modifier_storage as _modifier_storage
from . import province_identity_memory as _identity


FIELD_GOODS_SOURCE = "G02.province_goods_modifier_source"
SUPPORTED_FIELDS = (FIELD_GOODS_SOURCE,)

PROVINCE_CACHE_CONTAINER_OFFSET = 0x988
PROVINCE_AGGREGATE_MODIFIER_OFFSET = 0x998
PROVINCE_SCALE_INPUT_OFFSET = 0x42C
PROVINCE_CACHED_COMPONENT_OFFSET = 0x1120  # cache + 0x798
SOURCE_KEY_STRING32_OFFSET = 0x158
STRING32_SIZE = 0x20
STRING32_LENGTH_OFFSET = 0x10
STRING32_CAPACITY_OFFSET = 0x18
MAX_STRING_LENGTH = 255
MAX_STRING_CAPACITY = 1 << 20
MAX_PROVINCE_ID = 0xFFFF
CACHE_READY_STATE = 2
MODIFIER_INDEX = 21
MODIFIER_KEY = "trade_goods_size_modifier"
MODIFIER_UNIT = "raw_i32"

MAX_TOTAL_READ_BYTES = 128 * 1024
MAX_READ_CALLS = 4096
MAX_SINGLE_READ_BYTES = _foreign.MAX_SINGLE_READ_BYTES
_MAX_PRIMARY_READ_BYTES = MAX_TOTAL_READ_BYTES // 2
_MAX_PRIMARY_READ_CALLS = (MAX_READ_CALLS - 1) // 2

BASIS = "native_cached_province_modifier_component_candidate"
_BASIS = BASIS
_GAPS = [
    "PROVINCE_VIEW_ADMISSION_AND_DISCOVERY_ARE_PARENT_OWNED",
    "SESSION_PROFILE_CODE_AND_OUTER_TWO_PASS_GUARDS_ARE_PARENT_OWNED",
    "SOURCE_KEY_NAMES_A_CACHED_DEFINITION_NOT_A_UNIQUE_RUNTIME_CAUSE",
    "OTHER_PROVINCE_MODIFIER_CALLBACKS_AND_FULL_SOURCE_COVERAGE_NOT_READ",
    "RESIDUAL_MAY_INCLUDE_OTHER_CALLBACKS_OR_CACHE_PHASE_DIFFERENCES",
    "CURRENT_CACHE_COMPONENT_IS_NOT_A_FUTURE_ACQUISITION_DELTA",
]


class _LeafFailure(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class _BudgetRejected(Exception):
    pass


class _BudgetedSource:
    """Enforce a 128 KiB total budget while reserving space for rechecks."""

    def __init__(self, source: Any):
        method = getattr(source, "read", None)
        self._read = method if callable(method) else source if callable(source) else None
        self.verifying = False
        self.budget_rejected = False
        self.calls = 0
        self.bytes_requested = 0
        self.primary_calls = 0
        self.primary_bytes_requested = 0
        self.verification_calls = 0
        self.verification_bytes_requested = 0

    def read(self, address: int, size: int, label: str) -> bytes:
        if self._read is None:
            raise _LeafFailure("reader_invalid")
        if not self.verifying:
            if (self.primary_calls + 1 > _MAX_PRIMARY_READ_CALLS
                    or self.primary_bytes_requested + size > _MAX_PRIMARY_READ_BYTES):
                self.budget_rejected = True
                raise _BudgetRejected("leaf_read_budget_exceeded")
        if (self.calls + 1 > MAX_READ_CALLS
                or self.bytes_requested + size > MAX_TOTAL_READ_BYTES):
            self.budget_rejected = True
            raise _BudgetRejected("leaf_read_budget_exceeded")

        self.calls += 1
        self.bytes_requested += size
        if self.verifying:
            self.verification_calls += 1
            self.verification_bytes_requested += size
        else:
            self.primary_calls += 1
            self.primary_bytes_requested += size
        return self._read(address, size, label)

    def budget(self, trace: _foreign._TraceReader) -> dict[str, Any]:
        return {
            "calls": self.calls,
            "bytes_requested": self.bytes_requested,
            "max_calls": MAX_READ_CALLS,
            "max_bytes": MAX_TOTAL_READ_BYTES,
            "max_single_read_bytes": MAX_SINGLE_READ_BYTES,
            "primary_calls": self.primary_calls,
            "primary_bytes_requested": self.primary_bytes_requested,
            "verification_calls": self.verification_calls,
            "verification_bytes_requested": self.verification_bytes_requested,
            "adapter_attempted_calls": trace.calls,
            "adapter_attempted_bytes": trace.bytes_requested,
            "budget_rejected": self.budget_rejected,
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


def _known(value: dict[str, Any], raw_inputs: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "known",
        "complete": False,
        "value": value,
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
        } if isinstance(province_binding, Mapping)
        else _identity._raw_scalar(province_binding),
    }


def _failure_reason(exc: BaseException) -> str:
    if isinstance(exc, _foreign._Failure):
        return exc.reason
    if isinstance(exc, _LeafFailure):
        return exc.reason
    if isinstance(exc, _BudgetRejected):
        return "read_budget_exceeded"
    if isinstance(exc, ValueError) and str(exc):
        return str(exc)[:160]
    return f"READ_FAILED:{type(exc).__name__}"


def _checked_province(
    module_base: Any,
    province_binding: Any,
) -> tuple[int, int, dict[str, Any]]:
    base, record, binding = _identity._validate_binding(module_base, province_binding)
    if not 1 <= binding["province_id"] <= MAX_PROVINCE_ID:
        raise _LeafFailure("province_id_out_of_supported_range")
    return base, record, binding


def _read_source_key(
    trace: _foreign._TraceReader,
    component_address: int,
    raw_inputs: dict[str, Any],
    forbidden_pointers: tuple[int, ...],
) -> tuple[str, int | None, int]:
    header_address = _foreign._add(
        component_address, SOURCE_KEY_STRING32_OFFSET, STRING32_SIZE
    )
    header = trace.exact(
        header_address, STRING32_SIZE,
        "province_goods_sources.cached_component.source_key_header",
    )
    length = int.from_bytes(
        header[STRING32_LENGTH_OFFSET:STRING32_LENGTH_OFFSET + 8], "little"
    )
    capacity = int.from_bytes(
        header[STRING32_CAPACITY_OFFSET:STRING32_CAPACITY_OFFSET + 8], "little"
    )
    metadata: dict[str, Any] = {
        "header_address": hex(header_address),
        "header_raw_hex": header.hex(),
        "length": length,
        "capacity": capacity,
        "storage": None,
        "pointer": None,
        "payload_address": None,
        "payload_raw_hex": None,
    }
    raw_inputs["source_key_string32"] = metadata

    if length > MAX_STRING_LENGTH:
        raise _LeafFailure("source_key_length_out_of_range")
    if capacity < length or capacity > MAX_STRING_CAPACITY:
        raise _LeafFailure("source_key_capacity_invalid")

    if capacity < 16:
        if length > 15:
            raise _LeafFailure("source_key_inline_length_invalid")
        payload_address = header_address
        payload = header[:length + 1]
        pointer = None
        storage = "inline"
    else:
        pointer = int.from_bytes(header[:8], "little", signed=False)
        pointer = _foreign._valid_pointer(
            pointer, "SOURCE_KEY", alignment=1
        )
        metadata["pointer"] = hex(pointer)
        if pointer in forbidden_pointers:
            raise _LeafFailure("source_key_pointer_alias")
        payload_address = _foreign._add(pointer, 0, length + 1)
        payload = trace.exact(
            payload_address, length + 1,
            "province_goods_sources.cached_component.source_key_bytes",
        )
        storage = "heap"

    metadata.update({
        "storage": storage,
        "pointer": hex(pointer) if pointer is not None else None,
        "payload_address": hex(payload_address),
        "payload_raw_hex": payload.hex(),
    })
    if len(payload) != length + 1 or payload[-1:] != b"\0":
        raise _LeafFailure("source_key_terminator_invalid")
    if b"\0" in payload[:-1]:
        raise _LeafFailure("source_key_embedded_nul")
    try:
        decoded = payload[:-1].decode("ascii")
    except UnicodeDecodeError as exc:
        raise _LeafFailure("source_key_not_ascii") from exc
    if not decoded:
        raise _LeafFailure("source_key_empty")
    return decoded, pointer, payload_address


def _i32(value: int) -> int:
    wrapped = value & 0xFFFFFFFF
    return wrapped - 0x100000000 if wrapped & 0x80000000 else wrapped


def _recheck_used_bytes(
    trace: _foreign._TraceReader,
    budgeted: _BudgetedSource,
    raw_inputs: dict[str, Any],
) -> str | None:
    initial_reads = deepcopy(trace.reads)
    budgeted.verifying = True
    changed = False
    failed: str | None = None
    for row in initial_reads:
        if row.get("status") != "ok" or not isinstance(row.get("raw_hex"), str):
            continue
        try:
            address = int(row["address"], 16)
            current = trace.exact(
                address,
                int(row["size"]),
                f"{row['label']}.verify",
            )
            if current.hex() != row["raw_hex"]:
                changed = True
        except Exception as exc:
            failed = failed or _failure_reason(exc)

    if changed:
        raw_inputs["recheck_result"] = "changed"
        return "leaf_input_changed_during_recheck"
    if failed is not None:
        raw_inputs["recheck_result"] = "failed"
        return f"leaf_input_recheck_failed:{failed}"
    raw_inputs["recheck_result"] = "all_used_bytes_match"
    return None


def _read_candidate(
    reader: Any,
    module_base: Any,
    province_binding: Any,
) -> dict[str, Any]:
    budgeted = _BudgetedSource(reader)
    trace = _foreign._TraceReader(budgeted)
    raw_inputs: dict[str, Any] = {
        **_raw_binding(module_base, province_binding),
        "field": FIELD_GOODS_SOURCE,
        "modifier_index": MODIFIER_INDEX,
        "modifier_key": MODIFIER_KEY,
        "validation_errors": [],
        "read_failures": [],
        "full_source_coverage": False,
    }
    reason: str | None = None
    value: dict[str, Any] | None = None

    try:
        base, record, binding = _checked_province(module_base, province_binding)
        province_id = binding["province_id"]
        cache_container = _foreign._add(record, PROVINCE_CACHE_CONTAINER_OFFSET, 4)
        state_address = cache_container
        raw_inputs.update({
            "module_base": hex(base),
            "province_id": province_id,
            "canonical_record_address": hex(record),
            "canonical_binding_echo": dict(binding),
            "cache_container_address": hex(cache_container),
            "cache_state_address": hex(state_address),
            "cache_state_size": 4,
        })
        state = trace.u32(
            state_address, "province_goods_sources.cache_state_u32"
        )
        raw_inputs["cache_state_raw"] = state
        if state != CACHE_READY_STATE:
            reason = "province_modifier_cache_not_ready"
        else:
            scale_address = _foreign._add(
                record, PROVINCE_SCALE_INPUT_OFFSET, 4
            )
            scale_input = trace.i32(
                scale_address, "province_goods_sources.scale_input_i32"
            )
            raw_inputs.update({
                "province_scale_input_address": hex(scale_address),
                "province_scale_input_raw": scale_input,
            })
            if scale_input <= 0:
                reason = "province_scale_input_not_positive"
            else:
                component_address = _foreign._add(
                    record, PROVINCE_CACHED_COMPONENT_OFFSET, 0x68
                )
                key_address = _foreign._add(
                    component_address, SOURCE_KEY_STRING32_OFFSET, STRING32_SIZE
                )
                aggregate_address = _foreign._add(
                    record, PROVINCE_AGGREGATE_MODIFIER_OFFSET, 0x68
                )
                key_forbidden = (
                    base, record, cache_container, component_address,
                    aggregate_address, key_address,
                )
                source_key, source_pointer, source_payload_address = _read_source_key(
                    trace, component_address, raw_inputs, key_forbidden
                )
                raw_inputs.update({
                    "cached_component_object_address": hex(component_address),
                    "cached_component_modifier_offset": hex(PROVINCE_CACHED_COMPONENT_OFFSET),
                    "cached_component_source_key_address": hex(key_address),
                })

                forbidden = tuple(address for address in (
                    base,
                    record,
                    cache_container,
                    component_address,
                    aggregate_address,
                    key_address,
                    source_pointer,
                    source_payload_address,
                ) if type(address) is int)
                component = _modifier_storage.read_raw_modifier_object(
                    trace,
                    component_address,
                    MODIFIER_INDEX,
                    MODIFIER_UNIT,
                    name="province_goods_sources.cached_component",
                    forbidden_pointers=forbidden,
                )
                raw_inputs["cached_component_storage"] = deepcopy(component)
                component_raw = component.get("raw") if isinstance(component, Mapping) else None
                if not isinstance(component, Mapping) or component.get("status") != "known":
                    reason = str(
                        component.get("reason") if isinstance(component, Mapping) else None
                    ) or "cached_component_modifier_unknown"
                elif budgeted.budget_rejected:
                    reason = "read_budget_exceeded"
                elif (type(component_raw) is not int
                        or not -(1 << 31) <= component_raw < (1 << 31)
                        or component.get("unit") != MODIFIER_UNIT
                        or component.get("scale") != 1000):
                    reason = "cached_component_modifier_result_invalid"
                else:
                    aggregate = _modifier_storage.read_raw_modifier_object(
                        trace,
                        aggregate_address,
                        MODIFIER_INDEX,
                        MODIFIER_UNIT,
                        name="province_goods_sources.aggregate",
                        forbidden_pointers=forbidden,
                    )
                    raw_inputs["aggregate_storage"] = deepcopy(aggregate)
                    aggregate_raw = aggregate.get("raw") if isinstance(aggregate, Mapping) else None
                    if not isinstance(aggregate, Mapping) or aggregate.get("status") != "known":
                        reason = str(
                            aggregate.get("reason") if isinstance(aggregate, Mapping) else None
                        ) or "aggregate_modifier_unknown"
                    elif (type(aggregate_raw) is not int
                            or not -(1 << 31) <= aggregate_raw < (1 << 31)
                            or aggregate.get("unit") != MODIFIER_UNIT
                            or aggregate.get("scale") != 1000):
                        reason = "aggregate_modifier_result_invalid"
                    else:
                        residual = _i32(aggregate_raw - component_raw)
                        value = {
                            "province_id": province_id,
                            "modifier_index": MODIFIER_INDEX,
                            "modifier_key": MODIFIER_KEY,
                            "source_key": source_key,
                            "aggregate_raw": aggregate_raw,
                            "cached_component_raw": component_raw,
                            "residual_raw": residual,
                            "province_scale_input_raw": scale_input,
                            "scale": 1000,
                            "current_only": True,
                            "full_source_coverage": False,
                        }
    except Exception as exc:
        reason = _failure_reason(exc)
        raw_inputs["validation_errors" if not trace.reads else "read_failures"].append({
            "error": reason,
        })

    recheck_reason = _recheck_used_bytes(trace, budgeted, raw_inputs)
    if recheck_reason is not None:
        reason = recheck_reason
        value = None
    elif budgeted.budget_rejected:
        reason = "read_budget_exceeded"
        value = None

    raw_inputs["reads"] = deepcopy(trace.reads)
    raw_inputs["read_budget"] = budgeted.budget(trace)
    if reason is not None or value is None:
        return _unknown(reason or "province_goods_modifier_candidate_unknown", raw_inputs)
    return _known(value, raw_inputs)


def read_fields(
    reader: Any,
    module_base: Any,
    province_binding: Any,
    fields: tuple[str, ...] | list[str],
) -> dict[str, dict[str, Any]]:
    """Read the single cached province-goods candidate through canonical ID binding."""
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
    if FIELD_GOODS_SOURCE not in unique_fields:
        return unsupported
    return {
        **unsupported,
        FIELD_GOODS_SOURCE: _read_candidate(reader, module_base, province_binding),
    }


__all__ = [
    "FIELD_GOODS_SOURCE",
    "BASIS",
    "MODIFIER_INDEX",
    "MODIFIER_KEY",
    "PROVINCE_AGGREGATE_MODIFIER_OFFSET",
    "PROVINCE_CACHE_CONTAINER_OFFSET",
    "PROVINCE_CACHED_COMPONENT_OFFSET",
    "PROVINCE_SCALE_INPUT_OFFSET",
    "SUPPORTED_FIELDS",
    "read_fields",
]
