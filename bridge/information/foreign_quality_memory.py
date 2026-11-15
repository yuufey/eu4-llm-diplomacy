"""Read-only projection of selected native foreign military-quality values.

The caller owns process/session identity, ROM guards, the full country scan,
observer-role checks, and two-pass stability.  This leaf accepts only an
admitted quality-ledger permission record, rechecks the target country binding,
and reads bounded target-local cache components.  It never opens a process,
calls a native game function, or claims that the UI rendered these values.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import importlib
import math
from typing import Any

from . import country_scale_development_memory as _country_binding
from . import foreign_quality_visibility_memory as _quality_permission
from . import military_effective_memory as _discipline


SCHEMA = "information.foreign_quality_memory.v1"
FIELD_ID = "F02.military_quality"
FIELDS = (FIELD_ID,)
BASIS = "native_cached_quality_components_and_projected_modifiers"

MIN_USER_ADDRESS = 0x10000
MAX_USER_ADDRESS_EXCLUSIVE = 0x800000000000
MAX_U64 = 0xFFFFFFFFFFFFFFFF

MAX_TOTAL_READ_BYTES = 256 * 1024
MAX_READ_CALLS = 4096
MAX_SINGLE_READ_BYTES = 16 * 1024

COUNTRY_CACHE_STATE_OFFSET = 0x28C8
COUNTRY_MODIFIER_OBJECT_OFFSET = 0x28D0  # Inline object, not a pointer cell.
MODIFIER_DENSE_FLAG_OFFSET = 0x10
MODIFIER_VALUES_POINTER_OFFSET = 0x58
MODIFIER_SPARSE_COUNT_OFFSET = 0x64
MODIFIER_PROCESSOR_GLOBAL_RVA = 0x2358060
MODIFIER_PROCESSOR_STRIDE = 0x60
MODIFIER_PROCESSOR_OFFSET = 0x40
MAX_SPARSE_ENTRIES = 8192
SPARSE_CHUNK_BYTES = 16 * 1024

DIRECT_COMPONENTS = {
    "army.morale": (0x9874, "i32", "morale", 1000),
    "navy.morale": (0x987C, "i32", "morale", 1000),
    "army.professionalism": (0x0050, "i64", "ratio", 32768),
    "army.tradition": (0x0E40, "i32", "tradition_points", 1000),
    "navy.tradition": (0x0E44, "i32", "tradition_points", 1000),
}
MODIFIER_COMPONENTS = {
    "army.siege_ability": (182, "army", "ratio_modifier"),
    "army.defensiveness": (127, "army", "ratio_modifier"),
    "navy.ship_durability": (200, "navy", "ratio_modifier"),
}
MODEL_COMPONENTS = (
    "navy.heavy_ship_model",
    "navy.light_ship_model",
    "navy.galley_model",
)
COMPONENTS = tuple(DIRECT_COMPONENTS) + tuple(MODIFIER_COMPONENTS) + ("army.discipline",) + MODEL_COMPONENTS


class _Failure(Exception):
    def __init__(self, reason: str, *, shared_budget: bool = False):
        super().__init__(reason)
        self.reason = reason
        self.shared_budget = shared_budget


def _hex(value: int | None) -> str | None:
    return None if value is None else hex(value)


def _add(base: int, offset: int, size: int = 1) -> int:
    if (type(base) is not int or type(offset) is not int or type(size) is not int
            or base < MIN_USER_ADDRESS or base >= MAX_USER_ADDRESS_EXCLUSIVE
            or offset < 0 or size <= 0 or base > MAX_U64 - offset):
        raise _Failure("ADDRESS_INVALID")
    result = base + offset
    if (result < MIN_USER_ADDRESS or result >= MAX_USER_ADDRESS_EXCLUSIVE
            or result > MAX_U64 - (size - 1)
            or result + size > MAX_USER_ADDRESS_EXCLUSIVE):
        raise _Failure("ADDRESS_INVALID")
    return result


def _valid_pointer(value: Any, label: str, *, alignment: int = 8,
                   allow_null: bool = False) -> int:
    if type(value) is not int or not 0 <= value <= MAX_U64:
        raise _Failure(f"{label}_POINTER_INVALID")
    if value == 0 and allow_null:
        return 0
    if (value < MIN_USER_ADDRESS or value >= MAX_USER_ADDRESS_EXCLUSIVE
            or alignment <= 0 or value % alignment):
        raise _Failure(f"{label}_POINTER_INVALID")
    return value


def _trunc_zero(numerator: int, denominator: int) -> int:
    quotient = abs(numerator) // denominator
    return -quotient if numerator < 0 else quotient


class _TraceReader:
    """Reader adapter with an independent 256 KiB/4096-call leaf budget."""

    def __init__(self, source: Any):
        method = getattr(source, "read", None)
        self._read = method if callable(method) else source if callable(source) else None
        self.reads: list[dict[str, Any]] = []
        self.calls = 0
        self.bytes_requested = 0
        self.budget_failed = False

    def read(self, address: int, size: int, label: str) -> bytes:
        if self._read is None:
            raise _Failure("READER_INVALID")
        if (type(address) is not int or type(size) is not int or size <= 0
                or address < MIN_USER_ADDRESS or address >= MAX_USER_ADDRESS_EXCLUSIVE
                or address > MAX_U64 - (size - 1)
                or address + size > MAX_USER_ADDRESS_EXCLUSIVE):
            raise _Failure(f"ADDRESS_INVALID:{label}")
        if size > MAX_SINGLE_READ_BYTES:
            self.reads.append({"ordinal": self.calls + 1, "address": hex(address),
                               "size": size, "label": label, "status": "rejected",
                               "reason": "SINGLE_READ_LIMIT"})
            raise _Failure(f"SINGLE_READ_LIMIT:{label}")
        if (self.calls + 1 > MAX_READ_CALLS
                or self.bytes_requested + size > MAX_TOTAL_READ_BYTES):
            self.budget_failed = True
            self.reads.append({"ordinal": self.calls + 1, "address": hex(address),
                               "size": size, "label": label, "status": "rejected",
                               "reason": "SHARED_READ_BUDGET_EXCEEDED"})
            raise _Failure("SHARED_READ_BUDGET_EXCEEDED", shared_budget=True)
        self.calls += 1
        self.bytes_requested += size
        row: dict[str, Any] = {"ordinal": self.calls, "address": hex(address),
                               "size": size, "label": label, "status": "requested"}
        self.reads.append(row)
        try:
            raw = self._read(address, size, label)
        except Exception as exc:
            row.update({"status": "failed", "error_type": type(exc).__name__})
            raise ValueError("foreign_quality_read_failed") from exc
        if not isinstance(raw, (bytes, bytearray, memoryview)) or len(raw) != size:
            row.update({"status": "failed", "error_type": "SHORT_OR_INVALID_READ"})
            raise ValueError("foreign_quality_read_failed")
        data = bytes(raw)
        row.update({"status": "ok", "raw_hex": data.hex()})
        return data

    def exact(self, address: int, size: int, label: str) -> bytes:
        try:
            return self.read(address, size, label)
        except _Failure:
            raise
        except Exception as exc:
            if self.budget_failed:
                raise _Failure("SHARED_READ_BUDGET_EXCEEDED", shared_budget=True) from exc
            raise _Failure(f"READ_FAILED:{label}") from exc

    def u8(self, address: int, label: str) -> int:
        result = int.from_bytes(self.exact(address, 1, label), "little")
        self.reads[-1].update({"decode": "u8", "value": result})
        return result

    def u32(self, address: int, label: str) -> int:
        result = int.from_bytes(self.exact(address, 4, label), "little")
        self.reads[-1].update({"decode": "u32", "value": result})
        return result

    def i32(self, address: int, label: str) -> int:
        result = int.from_bytes(self.exact(address, 4, label), "little", signed=True)
        self.reads[-1].update({"decode": "i32", "value": result})
        return result

    def i64(self, address: int, label: str) -> int:
        result = int.from_bytes(self.exact(address, 8, label), "little", signed=True)
        self.reads[-1].update({"decode": "i64", "value": str(result)})
        return result

    def u64(self, address: int, label: str) -> int:
        result = int.from_bytes(self.exact(address, 8, label), "little")
        self.reads[-1].update({"decode": "u64", "value": hex(result)})
        return result

    def budget(self) -> dict[str, int]:
        return {"calls": self.calls, "bytes_requested": self.bytes_requested,
                "max_calls": MAX_READ_CALLS, "max_bytes": MAX_TOTAL_READ_BYTES,
                "max_single_read_bytes": MAX_SINGLE_READ_BYTES}


def _empty_component(reason: str, raw_inputs: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "reason": reason}
    if raw_inputs:
        result["raw_inputs"] = deepcopy(dict(raw_inputs))
    return result


def _known_component(value: Any, raw: Any, unit: str, scale: int,
                     raw_inputs: Mapping[str, Any]) -> dict[str, Any]:
    return {"status": "known", "value": value, "raw": raw,
            "unit": unit, "scale": scale,
            "raw_inputs": deepcopy(dict(raw_inputs))}


def _unknown_field(reason: str, *, target_binding: Any = None,
                   permission: Any = None, module_base: Any = None,
                   trace: _TraceReader | None = None,
                   raw: Mapping[str, Any] | None = None) -> dict[str, Any]:
    inputs: dict[str, Any] = dict(raw or {})
    inputs.setdefault("module_base", _hex(module_base) if type(module_base) is int else None)
    inputs.setdefault("target_binding", deepcopy(dict(target_binding))
                      if isinstance(target_binding, Mapping) else None)
    inputs.setdefault("permission_validation", None)
    inputs.setdefault("target_binding_revalidation", None)
    if not inputs.get("components"):
        inputs["components"] = _empty_components(reason)
    inputs["reads"] = deepcopy(trace.reads) if trace is not None else []
    inputs["budget"] = trace.budget() if trace is not None else {
        "calls": 0, "bytes_requested": 0, "max_calls": MAX_READ_CALLS,
        "max_bytes": MAX_TOTAL_READ_BYTES,
        "max_single_read_bytes": MAX_SINGLE_READ_BYTES,
    }
    return {"status": "unknown", "reason": reason, "complete": False,
            "partial": True, "basis": BASIS, "raw_inputs": inputs}


def _permission_matches(permission: Any, retained: Mapping[str, Any]) -> bool:
    if not _quality_permission.validate_permission(permission):
        return False
    if (not isinstance(permission, Mapping) or permission.get("status") != "known"
            or permission.get("admitted") is not True):
        return False
    target = permission.get("target")
    if not isinstance(target, Mapping):
        return False
    try:
        fullref = int(str(retained["fullref"]), 0)
    except (KeyError, TypeError, ValueError):
        return False
    return (target.get("tag") == retained.get("tag")
            and type(target.get("slot")) is int
            and target.get("slot") == retained.get("slot")
            and target.get("fullref") == hex(fullref)
            and target.get("fullref_raw_hex") == fullref.to_bytes(8, "little").hex())


def _component_read_slice(trace: _TraceReader, start: int) -> list[dict[str, Any]]:
    return deepcopy(trace.reads[start:])


def _attach_component_reads(component: dict[str, Any], trace: _TraceReader,
                            start: int) -> dict[str, Any]:
    raw_inputs = component.get("raw_inputs")
    if not isinstance(raw_inputs, dict):
        raw_inputs = {}
        component["raw_inputs"] = raw_inputs
    raw_inputs["reads"] = _component_read_slice(trace, start)
    return component


def _read_direct(trace: _TraceReader, country_pointer: int, name: str,
                 offset: int, kind: str, unit: str, scale: int) -> dict[str, Any]:
    start = len(trace.reads)
    address = _add(country_pointer, offset, 8 if kind == "i64" else 4)
    inputs: dict[str, Any] = {"country_offset": hex(offset), "address": hex(address)}
    try:
        value = trace.i64(address, f"quality.{name}.cache_i64") if kind == "i64" \
            else trace.i32(address, f"quality.{name}.cache_i32")
        raw_hex = trace.reads[-1]["raw_hex"]
        inputs.update({"raw_hex": raw_hex, "decoded_raw": str(value) if kind == "i64" else value})
        if name == "army.professionalism":
            float_value = value / 32768.0
            if not math.isfinite(float_value):
                raise _Failure("PROFESSIONALISM_VALUE_NONFINITE")
            inputs["numeric_encoding"] = "signed_i64_divided_by_32768"
            return _known_component(float_value, str(value), unit, scale, inputs)
        if name in ("army.tradition", "navy.tradition"):
            display_raw = _trunc_zero(value * 1000, 100000)
            inputs["native_row_encoding"] = {
                "raw": display_raw, "unit": "ratio", "scale": 1000,
                "formula": "trunc_zero(signed_i32_raw*1000/100000)",
            }
        return _known_component(value, value, unit, scale, inputs)
    except Exception as exc:
        reason = exc.reason if isinstance(exc, _Failure) else f"READ_FAILED:{name}"
        inputs["reads"] = _component_read_slice(trace, start)
        return _empty_component(reason, inputs)
    finally:
        inputs["reads"] = _component_read_slice(trace, start)


def _read_modifier(trace: _TraceReader, country_pointer: int, manager: int,
                   cache_state: int, name: str, modifier_id: int,
                   unit: str) -> dict[str, Any]:
    start = len(trace.reads)
    inputs: dict[str, Any] = {
        "modifier_id": modifier_id,
        "cache_state": cache_state,
        "cache_state_address": hex(country_pointer + COUNTRY_CACHE_STATE_OFFSET),
        "modifier_object_storage": "inline",
        "modifier_object_address": hex(country_pointer + COUNTRY_MODIFIER_OBJECT_OFFSET),
        "processor_manager": hex(manager),
    }
    try:
        processor_cell = _add(manager, modifier_id * MODIFIER_PROCESSOR_STRIDE
                              + MODIFIER_PROCESSOR_OFFSET, 8)
        processor = _valid_pointer(trace.u64(processor_cell,
                                             f"quality.{name}.processor_pointer"),
                                   "MODIFIER_PROCESSOR", allow_null=True)
        inputs.update({"processor_cell_address": hex(processor_cell),
                       "processor_pointer": hex(processor)})
        if processor != 0:
            raise _Failure("MODIFIER_PROCESSOR_PRESENT")

        if cache_state == 1:
            raise _Failure("MILITARY_CACHE_CALCULATING")
        modifier = _add(country_pointer, COUNTRY_MODIFIER_OBJECT_OFFSET, 0x68)
        dense_address = _add(modifier, MODIFIER_DENSE_FLAG_OFFSET, 1)
        values_cell = _add(modifier, MODIFIER_VALUES_POINTER_OFFSET, 8)
        count_address = _add(modifier, MODIFIER_SPARSE_COUNT_OFFSET, 4)
        dense_flag = trace.u8(dense_address, f"quality.{name}.dense_flag_u8")
        values_pointer = trace.u64(values_cell, f"quality.{name}.values_pointer")
        count = trace.u32(count_address, f"quality.{name}.sparse_count_u32")
        inputs.update({"dense_flag_address": hex(dense_address), "dense_flag": dense_flag,
                       "values_pointer_cell": hex(values_cell),
                       "values_pointer": hex(values_pointer),
                       "count_address": hex(count_address), "count": count})
        if dense_flag not in (0, 1):
            raise _Failure("MODIFIER_DENSE_FLAG_INVALID")
        if count > MAX_SPARSE_ENTRIES:
            raise _Failure("MODIFIER_COUNT_OUT_OF_RANGE")

        if dense_flag == 1:
            values = _valid_pointer(values_pointer, "MODIFIER_VALUES")
            if values in (country_pointer, modifier, manager, processor_cell):
                raise _Failure("MODIFIER_VALUES_POINTER_ALIAS")
            value_address = _add(values, modifier_id * 8 + 4, 4)
            value = trace.i32(value_address, f"quality.{name}.dense_value_i32")
            inputs.update({"mode": "dense", "storage_address": hex(value_address),
                           "storage_raw_hex": trace.reads[-1]["raw_hex"],
                           "first_match_index": None, "modifier_raw": value})
            return _known_component(value, value, unit, 1000, inputs)

        if count == 0:
            inputs.update({"mode": "sparse", "first_match_index": None,
                           "entries_examined": [], "blocks": []})
            return _known_component(0, 0, unit, 1000, inputs)
        values = _valid_pointer(values_pointer, "MODIFIER_VALUES")
        if values in (country_pointer, modifier, manager, processor_cell):
            raise _Failure("MODIFIER_VALUES_POINTER_ALIAS")
        blocks: list[dict[str, Any]] = []
        examined: list[dict[str, Any]] = []
        first_index: int | None = None
        modifier_raw = 0
        index = 0
        max_entries_per_chunk = SPARSE_CHUNK_BYTES // 8
        while index < count:
            chunk_entries = min(max_entries_per_chunk, count - index)
            chunk_address = _add(values, index * 8, chunk_entries * 8)
            chunk = trace.exact(chunk_address, chunk_entries * 8,
                                f"quality.{name}.sparse_entries[{index}:{index + chunk_entries}]")
            blocks.append({"start_index": index, "entry_count": chunk_entries,
                           "address": hex(chunk_address), "raw_hex": chunk.hex()})
            for within in range(chunk_entries):
                entry_index = index + within
                raw_entry = chunk[within * 8:(within + 1) * 8]
                entry_id = int.from_bytes(raw_entry[:4], "little", signed=True)
                entry_value = int.from_bytes(raw_entry[4:], "little", signed=True)
                examined.append({"index": entry_index, "id": entry_id,
                                 "id_raw_hex": raw_entry[:4].hex(),
                                 "value": entry_value,
                                 "value_raw_hex": raw_entry[4:].hex()})
                if entry_id == modifier_id:
                    first_index = entry_index
                    modifier_raw = entry_value
                    break
            if first_index is not None:
                break
            index += chunk_entries
        inputs.update({"mode": "sparse", "storage_address": hex(values),
                       "first_match_index": first_index,
                       "modifier_raw": modifier_raw,
                       "entries_examined": examined, "blocks": blocks})
        return _known_component(modifier_raw, modifier_raw, unit, 1000, inputs)
    except Exception as exc:
        reason = exc.reason if isinstance(exc, _Failure) else f"READ_FAILED:{name}"
        inputs["reads"] = _component_read_slice(trace, start)
        return _empty_component(reason, inputs)
    finally:
        inputs["reads"] = _component_read_slice(trace, start)


def _read_discipline(trace: _TraceReader, base: int, country_pointer: int,
                     model_profile: Any) -> dict[str, Any]:
    start = len(trace.reads)
    inputs: dict[str, Any] = {"helper": "military_effective_memory.read_fields",
                              "helper_scope_is_not_target_proof": True,
                              "target_binding_validated_by_parent_leaf": True}
    try:
        profile = None
        if isinstance(model_profile, Mapping):
            candidate = model_profile.get("discipline_profile")
            if isinstance(candidate, Mapping):
                profile = candidate
        record = _discipline.read_fields(trace, base, country_pointer, profile=profile)
        inputs["helper_record"] = deepcopy(record)
        item = record.get("fields", {}).get("discipline") if isinstance(record, Mapping) else None
        if (not isinstance(record, Mapping) or record.get("status") != "observed"
                or not isinstance(item, Mapping) or item.get("status") != "known"
                or type(item.get("value")) is not int
                or type(item.get("raw")) is not int
                or item.get("unit") != "ratio" or item.get("scale") != 1000):
            reason = record.get("reason", "DISCIPLINE_HELPER_CONTRACT_UNSUPPORTED") \
                if isinstance(record, Mapping) else "DISCIPLINE_HELPER_CONTRACT_UNSUPPORTED"
            return _empty_component(f"DISCIPLINE_HELPER_UNKNOWN:{reason}", inputs)
        inputs.update({"helper_scope_note": "Only the computed numeric component is projected; helper country/scope labels are not inherited as target proof.",
                       "helper_field_basis": item.get("basis"),
                       "helper_field_raw_hex": item.get("raw_hex")})
        return _known_component(item["value"], item["raw"], "ratio", 1000, inputs)
    except Exception as exc:
        return _empty_component(f"DISCIPLINE_HELPER_ERROR:{type(exc).__name__}", inputs)
    finally:
        inputs["reads"] = _component_read_slice(trace, start)


def _read_models(trace: _TraceReader, base: int, target_binding: Any,
                 model_profile: Any) -> dict[str, dict[str, Any]]:
    start = len(trace.reads)

    def trace_reference(end: int) -> dict[str, int]:
        """Reference the single whole-field trace without copying it per model."""
        return {"start_index": start, "end_index": end,
                "read_count": max(0, end - start)}

    if model_profile is None:
        return {name: _empty_component("MODEL_GETTER_CONTRACT_PENDING", {
            "model_profile_used": False,
            "reason_scope": "No model getter profile was supplied.",
            "reads": [], "wholefield_trace_slice": trace_reference(start)})
                for name in MODEL_COMPONENTS}
    try:
        helper = importlib.import_module(f"{__package__}.foreign_quality_models_memory")
        read_models = getattr(helper, "read_models", None)
        if not callable(read_models):
            raise _Failure("MODEL_HELPER_API_UNAVAILABLE")
        result = read_models(trace, base, target_binding, model_profile=model_profile)
        if not isinstance(result, Mapping):
            raise _Failure("MODEL_HELPER_RESULT_INVALID")
        end = len(trace.reads)
        shared_reference = trace_reference(end)
        output: dict[str, dict[str, Any]] = {}
        for name in MODEL_COMPONENTS:
            component = result.get(name)
            if not isinstance(component, Mapping):
                output[name] = _empty_component("MODEL_HELPER_COMPONENT_MISSING", {
                    "reads": [], "wholefield_trace_slice": deepcopy(shared_reference)})
                continue
            if component.get("status") == "known":
                value = component.get("value")
                raw_value = component.get("raw")
                if (not isinstance(value, Mapping)
                        or not isinstance(value.get("localization_key"), str)
                        or not isinstance(value.get("name"), Mapping)
                        or component.get("unit") != "ship_model"
                        or type(component.get("scale")) is not int
                        or component.get("scale") != 1
                        or not isinstance(raw_value, str)):
                    helper_raw = (deepcopy(dict(component.get("raw_inputs", {})))
                                  if isinstance(component.get("raw_inputs"), Mapping) else {})
                    local_reads = helper_raw.get("reads")
                    if not isinstance(local_reads, list):
                        helper_raw["reads"] = []
                        helper_raw["wholefield_trace_slice"] = deepcopy(shared_reference)
                    helper_raw.pop("helper_reads", None)
                    output[name] = _empty_component("MODEL_HELPER_COMPONENT_SHAPE_INVALID", {
                        "helper_raw_inputs": helper_raw})
                    continue
                raw_inputs = deepcopy(dict(component.get("raw_inputs", {}))) \
                    if isinstance(component.get("raw_inputs"), Mapping) else {}
                local_reads = raw_inputs.get("reads")
                if not isinstance(local_reads, list):
                    raw_inputs["reads"] = []
                    raw_inputs["wholefield_trace_slice"] = deepcopy(shared_reference)
                raw_inputs.pop("helper_reads", None)
                output[name] = {"status": "known", "value": deepcopy(dict(value)),
                                "raw": raw_value, "unit": "ship_model", "scale": 1,
                                "basis": component.get("basis", "native_quality_model_getter_projected"),
                                "raw_inputs": raw_inputs}
            else:
                raw_inputs = deepcopy(dict(component.get("raw_inputs", {}))) \
                    if isinstance(component.get("raw_inputs"), Mapping) else {}
                local_reads = raw_inputs.get("reads")
                if not isinstance(local_reads, list):
                    raw_inputs["reads"] = []
                    raw_inputs["wholefield_trace_slice"] = deepcopy(shared_reference)
                raw_inputs.pop("helper_reads", None)
                output[name] = _empty_component(
                    str(component.get("reason", "MODEL_HELPER_COMPONENT_UNKNOWN")), raw_inputs)
        return output
    except Exception as exc:
        reason = exc.reason if isinstance(exc, _Failure) else f"MODEL_HELPER_ERROR:{type(exc).__name__}"
        shared_reference = trace_reference(len(trace.reads))
        return {name: _empty_component(reason, {
                    "reads": [], "wholefield_trace_slice": deepcopy(shared_reference)})
                for name in MODEL_COMPONENTS}


def _empty_components(reason: str, *, raw: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {name: _empty_component(reason, raw) for name in COMPONENTS}


def read_fields(reader: Any, base: int, target_binding: Any, fields: Any, *,
                permission: Any, model_profile: Any = None) -> dict[str, dict[str, Any]]:
    """Read the one supported F02 quality field after a quality-specific gate.

    The permission leaf must have returned a valid known/admitted record for
    the same target fullref.  This function rechecks the target against the
    country database before touching quality caches.  Component failures are
    isolated, except a shared binding or total RPM budget failure, which
    withdraws the entire field.
    """
    if not isinstance(fields, (tuple, list)) or len(fields) > 16:
        return {FIELD_ID: _unknown_field("FIELDS_SHAPE_INVALID", target_binding=target_binding,
                                        permission=permission, module_base=base)}
    if any(not isinstance(field, str) for field in fields):
        return {FIELD_ID: _unknown_field("FIELDS_SHAPE_INVALID", target_binding=target_binding,
                                        permission=permission, module_base=base)}
    if len(set(fields)) != len(fields):
        return {FIELD_ID: _unknown_field("DUPLICATE_FIELD_REQUESTED", target_binding=target_binding,
                                        permission=permission, module_base=base)}
    if FIELD_ID not in fields:
        return {}

    trace = _TraceReader(reader)
    raw: dict[str, Any] = {
        "schema": SCHEMA,
        "module_base": _hex(base) if type(base) is int else None,
        "target_binding": deepcopy(dict(target_binding)) if isinstance(target_binding, Mapping) else None,
        "permission": deepcopy(permission) if isinstance(permission, Mapping) else None,
        "permission_validation": {"status": "unknown", "reason": None},
        "target_binding_revalidation": None,
        "components": {},
        "reads": [],
        "budget": trace.budget(),
    }

    try:
        if type(base) is not int or base < MIN_USER_ADDRESS or base >= MAX_USER_ADDRESS_EXCLUSIVE or base & 7:
            return {FIELD_ID: _unknown_field("MODULE_BASE_INVALID", target_binding=target_binding,
                                            permission=permission, module_base=base, trace=trace, raw=raw)}
        try:
            parsed_base, target_pointer, retained = _country_binding._parse_target(base, target_binding)
            if parsed_base != base:
                raise ValueError("module_base_mismatch")
        except Exception:
            return {FIELD_ID: _unknown_field("TARGET_BINDING_INVALID", target_binding=target_binding,
                                            permission=permission, module_base=base, trace=trace, raw=raw)}
        raw["target_binding"] = deepcopy(retained)

        if not _quality_permission.validate_permission(permission):
            raw["permission_validation"] = {"status": "unknown", "reason": "PERMISSION_RECORD_INVALID"}
            return {FIELD_ID: _unknown_field("QUALITY_PERMISSION_INVALID", target_binding=retained,
                                            permission=permission, module_base=base, trace=trace, raw=raw)}
        permission_target = permission.get("target") if isinstance(permission, Mapping) else None
        if (not isinstance(permission_target, Mapping)
                or permission.get("status") != "known"
                or permission.get("admitted") is not True
                or not _permission_matches(permission, retained)):
            state = "denied" if isinstance(permission, Mapping) and permission.get("status") == "known" and permission.get("admitted") is False else "unknown"
            raw["permission_validation"] = {"status": state,
                                            "reason": "QUALITY_PERMISSION_DENIED" if state == "denied" else "QUALITY_PERMISSION_NOT_ADMITTED"}
            return {FIELD_ID: _unknown_field("QUALITY_PERMISSION_NOT_ADMITTED",
                                            target_binding=retained, permission=permission,
                                            module_base=base, trace=trace, raw=raw)}
        raw["permission_validation"] = {"status": "admitted", "reason": None,
                                        "target_fullref": retained["fullref"],
                                        "basis": permission.get("basis")}

        try:
            target_validation = _country_binding._validate_target_binding(
                trace, base, target_pointer, retained)
            raw["target_binding_revalidation"] = {
                "status": "known", "evidence": deepcopy(target_validation)}
        except Exception as exc:
            if trace.budget_failed:
                raw["target_binding_revalidation"] = {
                    "status": "failed", "reason": "SHARED_READ_BUDGET_EXCEEDED"}
                return {FIELD_ID: _unknown_field("SHARED_READ_BUDGET_EXCEEDED",
                                                target_binding=retained,
                                                permission=permission,
                                                module_base=base, trace=trace, raw=raw)}
            raw["target_binding_revalidation"] = {
                "status": "failed", "reason": type(exc).__name__}
            return {FIELD_ID: _unknown_field("TARGET_BINDING_REVALIDATION_FAILED",
                                            target_binding=retained, permission=permission,
                                            module_base=base, trace=trace, raw=raw)}
        if trace.budget_failed:
            return {FIELD_ID: _unknown_field("SHARED_READ_BUDGET_EXCEEDED",
                                            target_binding=retained, permission=permission,
                                            module_base=base, trace=trace, raw=raw)}

        components: dict[str, dict[str, Any]] = {}
        for name, (offset, kind, unit, scale) in DIRECT_COMPONENTS.items():
            start = len(trace.reads)
            components[name] = _attach_component_reads(
                _read_direct(trace, target_pointer, name, offset, kind, unit, scale),
                trace, start)
            if trace.budget_failed:
                break

        modifier_names = tuple(MODIFIER_COMPONENTS)
        if not trace.budget_failed:
            cache_state: int | None = None
            cache_state_error: str | None = None
            try:
                cache_state_address = _add(target_pointer, COUNTRY_CACHE_STATE_OFFSET, 4)
                cache_state = trace.i32(cache_state_address, "quality.modifier.cache_state_i32")
                raw["modifier_cache_state"] = {"address": hex(cache_state_address),
                                               "value": cache_state,
                                               "raw_hex": trace.reads[-1]["raw_hex"]}
            except Exception as exc:
                cache_state_error = exc.reason if isinstance(exc, _Failure) else "CACHE_STATE_READ_FAILED"
            manager: int | None = None
            manager_error: str | None = None
            if cache_state_error is None and cache_state != 1:
                try:
                    manager_cell = _add(base, MODIFIER_PROCESSOR_GLOBAL_RVA, 8)
                    manager = _valid_pointer(trace.u64(manager_cell,
                                                      "quality.modifier_processor_manager"),
                                             "MODIFIER_PROCESSOR_MANAGER")
                    raw["modifier_processor_manager"] = {"cell": hex(manager_cell),
                                                        "pointer": hex(manager)}
                except Exception as exc:
                    manager_error = exc.reason if isinstance(exc, _Failure) else "PROCESSOR_MANAGER_READ_FAILED"
            for name, (modifier_id, group, unit) in MODIFIER_COMPONENTS.items():
                if cache_state_error is not None:
                    component = _empty_component(cache_state_error, {
                        "cache_state": "unavailable", "modifier_id": modifier_id})
                elif cache_state == 1:
                    component = _empty_component("MILITARY_CACHE_CALCULATING", {
                        "cache_state": 1, "cache_state_address": hex(target_pointer + COUNTRY_CACHE_STATE_OFFSET),
                        "modifier_id": modifier_id, "modifier_object_storage": "inline"})
                elif manager_error is not None or manager is None:
                    component = _empty_component(manager_error or "PROCESSOR_MANAGER_UNAVAILABLE", {
                        "cache_state": cache_state, "modifier_id": modifier_id})
                else:
                    start = len(trace.reads)
                    component = _read_modifier(trace, target_pointer, manager, cache_state,
                                               name, modifier_id, unit)
                    component = _attach_component_reads(component, trace, start)
                components[name] = component
                if trace.budget_failed:
                    break

        if not trace.budget_failed:
            start = len(trace.reads)
            components["army.discipline"] = _attach_component_reads(
                _read_discipline(trace, base, target_pointer, model_profile), trace, start)
        else:
            components["army.discipline"] = _empty_component("SHARED_READ_BUDGET_EXCEEDED")

        model_components = _read_models(trace, base, retained, model_profile)
        for name in MODEL_COMPONENTS:
            component = model_components[name]
            component_raw = component.get("raw_inputs")
            if not isinstance(component_raw, dict):
                component_raw = {}
                component["raw_inputs"] = component_raw
            component_raw.setdefault("reads", [])
            components[name] = component

        if trace.budget_failed:
            components = _empty_components("SHARED_READ_BUDGET_EXCEEDED", raw={
                "shared_failure": "the leaf-wide read budget was exhausted"})
            field_status = "unknown"
            field_reason = "SHARED_READ_BUDGET_EXCEEDED"
        else:
            field_status = "known" if any(
                component.get("status") == "known" for component in components.values()) else "unknown"
            field_reason = None if field_status == "known" else "NO_QUALITY_COMPONENT_KNOWN"
        raw["components"] = deepcopy(components)
        raw["reads"] = deepcopy(trace.reads)
        raw["budget"] = trace.budget()
        if field_status == "unknown":
            field = {"status": "unknown", "reason": field_reason,
                     "complete": False, "partial": True, "basis": BASIS,
                     "raw_inputs": raw}
        else:
            value = {
                "army": {name.removeprefix("army."): components[name]
                         for name in components if name.startswith("army.")},
                "navy": {name.removeprefix("navy."): components[name]
                         for name in components if name.startswith("navy.")},
            }
            field = {"status": "known", "value": value,
                     "unit": "native_military_quality_components", "scale": 1,
                     "basis": BASIS, "partial": True, "complete": False,
                     "raw_inputs": raw}
        return {FIELD_ID: field}
    except Exception as exc:
        reason = exc.reason if isinstance(exc, _Failure) else f"INTERNAL_READ_FAILURE:{type(exc).__name__}"
        return {FIELD_ID: _unknown_field(reason, target_binding=target_binding,
                                        permission=permission, module_base=base,
                                        trace=trace, raw=raw)}


__all__ = ["SCHEMA", "FIELD_ID", "FIELDS", "read_fields", "MAX_TOTAL_READ_BYTES",
           "MAX_READ_CALLS", "MAX_SINGLE_READ_BYTES", "MAX_SPARSE_ENTRIES"]
