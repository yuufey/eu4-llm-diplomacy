"""Bounded projection of three selected naval model localization keys.

The parent owns process/session identity, the country scan, quality admission,
ROM/profile loading, and two-pass stability. This leaf only revalidates the
already-bound target's fullref, checks the pinned B23 model getter bytes and
vtable slot, then reads the three cached model keys and their existing
localization-cache snapshots. It never opens a process or calls native code.
The cached name bytes remain raw; this module does not decode or render them.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import re
from typing import Any

from . import country_scale_development_memory as _country_binding
from . import province_resource_localization_memory as _localization_name


SCHEMA = "information.foreign_quality_model_name_memory.v1"
PROFILE_SCHEMA = "information.foreign_quality_model_profile.v1"
EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
VT_RVA = 0x01CE3700
VT_SLOT_OFFSET = 0x40
METHOD_RVA = 0x00AD8C10
METHOD_END_RVA_EXCLUSIVE = 0x00AD8CCD
METHOD_BYTES = METHOD_END_RVA_EXCLUSIVE - METHOD_RVA
METHOD_CODE_SHA256 = "490fcba6edcf3852feb6f1fefb6fc58dbd435fe9a2e8e8c98d9ac2885b473544"
COUNTRY_FULLREF_OFFSET = 0x20
MODEL_VTABLE_OFFSET = 0x00
MODEL_KEY_OFFSET = 0x60
MODEL_KEY_HEADER_BYTES = 0x20
MODEL_KEY_LENGTH_OFFSET = 0x10
MODEL_KEY_CAPACITY_OFFSET = 0x18
MAX_MODEL_KEY_BYTES = 128
MAX_STRING_CAPACITY = 1024 * 1024
MAX_TOTAL_READ_BYTES = 256 * 1024
MAX_READ_CALLS = 4096
MAX_SINGLE_READ_BYTES = 16 * 1024
MIN_USER_ADDRESS = 0x10000
MAX_USER_ADDRESS_EXCLUSIVE = 0x800000000000
MAX_U64 = 0xFFFFFFFFFFFFFFFF

MODEL_POINTER_OFFSETS = {
    "navy.heavy_ship_model": 0x0D60,
    "navy.light_ship_model": 0x0D68,
    "navy.galley_model": 0x0D70,
}
MODEL_KEY_RE = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z", re.ASCII)
LANGUAGE_RE = re.compile(r"l_[A-Za-z0-9_]{1,63}\Z", re.ASCII)
LOWER_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
SAFE_REASON_RE = re.compile(r"[A-Z0-9_]{1,64}\Z", re.ASCII)
_PROFILE_KEYS = {
    "schema", "executable_sha256", "vt_rva", "method_rva",
    "method_end_rva_exclusive", "method_code_hex", "method_code_sha256",
    "source_pins",
}


class _LeafFailure(Exception):
    def __init__(self, reason: str, *, budget: bool = False):
        super().__init__(reason)
        self.reason = reason
        self.budget = budget


class _BudgetReader:
    """One shared budget across object reads and all localization snapshots."""

    def __init__(self, source: Any, module_base: int):
        method = getattr(source, "read", None)
        self._read = method if callable(method) else source if callable(source) else None
        self.module_base = module_base
        self.calls = 0
        self.bytes_requested = 0
        self.max_single = 0
        self.budget_failed = False
        self.reads: list[dict[str, Any]] = []

    def read(self, address: int, size: int, label: str) -> bytes:
        if self._read is None:
            raise _LeafFailure("READER_INVALID")
        if (type(address) is not int or type(size) is not int or size <= 0
                or size > MAX_SINGLE_READ_BYTES
                or address < MIN_USER_ADDRESS
                or address >= MAX_USER_ADDRESS_EXCLUSIVE
                or address > MAX_U64 - (size - 1)
                or address + size > MAX_USER_ADDRESS_EXCLUSIVE
                or not isinstance(label, str) or not label):
            raise _LeafFailure("READ_RANGE_INVALID")
        if self.calls >= MAX_READ_CALLS or self.bytes_requested + size > MAX_TOTAL_READ_BYTES:
            self.budget_failed = True
            self.reads.append({"ordinal": self.calls + 1, "address": hex(address),
                               "size": size, "label": label, "status": "rejected",
                               "reason": "LOCAL_BUDGET_EXCEEDED"})
            raise _LeafFailure("LOCAL_BUDGET_EXCEEDED", budget=True)
        self.calls += 1
        self.bytes_requested += size
        self.max_single = max(self.max_single, size)
        row: dict[str, Any] = {"ordinal": self.calls, "address": hex(address),
                               "size": size, "label": label, "status": "requested"}
        self.reads.append(row)
        try:
            raw = self._read(address, size, label)
        except Exception as exc:
            row.update({"status": "failed", "error_type": type(exc).__name__})
            raise _LeafFailure("READ_FAILED") from exc
        if not isinstance(raw, (bytes, bytearray, memoryview)):
            row.update({"status": "failed", "error_type": "READ_NOT_BYTES"})
            raise _LeafFailure("READ_NOT_BYTES")
        data = bytes(raw)
        if len(data) != size:
            row.update({"status": "failed", "error_type": "SHORT_READ",
                        "actual_bytes": len(data)})
            raise _LeafFailure("SHORT_READ")
        row.update({"status": "ok", "raw_hex": data.hex()})
        return data

    def summary(self) -> dict[str, int | bool]:
        return {"calls": self.calls, "bytes_requested": self.bytes_requested,
                "max_single_read": self.max_single,
                "max_calls": MAX_READ_CALLS,
                "max_total_bytes": MAX_TOTAL_READ_BYTES,
                "max_single_read_bytes": MAX_SINGLE_READ_BYTES,
                "budget_failed": self.budget_failed}


def _safe_reason(value: Any, fallback: str = "MODEL_READ_UNKNOWN") -> str:
    if isinstance(value, str) and SAFE_REASON_RE.fullmatch(value):
        return value
    return fallback


def _unknown(reason: str, raw_inputs: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "reason": _safe_reason(reason)}
    if raw_inputs:
        try:
            result["raw_inputs"] = deepcopy(dict(raw_inputs))
        except Exception:
            result["raw_inputs"] = {"private_evidence_copy": "failed"}
    return result


def _add(address: int, offset: int, size: int, label: str) -> int:
    if (type(address) is not int or type(offset) is not int or type(size) is not int
            or address < MIN_USER_ADDRESS or address >= MAX_USER_ADDRESS_EXCLUSIVE
            or offset < 0 or size <= 0 or address > MAX_U64 - offset):
        raise _LeafFailure(f"ADDRESS_INVALID_{label.upper()}")
    result = address + offset
    if (result < MIN_USER_ADDRESS or result >= MAX_USER_ADDRESS_EXCLUSIVE
            or result > MAX_U64 - (size - 1)
            or result + size > MAX_USER_ADDRESS_EXCLUSIVE):
        raise _LeafFailure(f"ADDRESS_RANGE_INVALID_{label.upper()}")
    return result


def _user_pointer(value: Any, label: str, *, allow_null: bool = False,
                  aligned: bool = True) -> int:
    if type(value) is not int or not 0 <= value <= MAX_U64:
        raise _LeafFailure(f"{label}_POINTER_INVALID")
    if value == 0 and allow_null:
        return value
    if (value < MIN_USER_ADDRESS or value >= MAX_USER_ADDRESS_EXCLUSIVE
            or (aligned and value & 7)):
        raise _LeafFailure(f"{label}_POINTER_INVALID")
    return value


def _read_exact(trace: _BudgetReader, address: int, size: int, label: str) -> bytes:
    return trace.read(address, size, label)


def _parse_profile(model_profile: Any) -> dict[str, Any]:
    if not isinstance(model_profile, Mapping) or set(model_profile) != _PROFILE_KEYS:
        raise _LeafFailure("MODEL_PROFILE_SHAPE_INVALID")
    profile = dict(model_profile)
    if (profile.get("schema") != PROFILE_SCHEMA
            or profile.get("executable_sha256") != EXE_SHA256
            or profile.get("vt_rva") != hex(VT_RVA)
            or profile.get("method_rva") != hex(METHOD_RVA)
            or profile.get("method_end_rva_exclusive") != hex(METHOD_END_RVA_EXCLUSIVE)):
        raise _LeafFailure("MODEL_PROFILE_IDENTITY_MISMATCH")
    code_hex = profile.get("method_code_hex")
    digest = profile.get("method_code_sha256")
    if (not isinstance(code_hex, str) or len(code_hex) != METHOD_BYTES * 2
            or re.fullmatch(r"(?:[0-9a-f]{2})*", code_hex, re.ASCII) is None
            or not isinstance(digest, str) or LOWER_SHA256_RE.fullmatch(digest) is None):
        raise _LeafFailure("MODEL_PROFILE_CODE_GUARD_INVALID")
    code = bytes.fromhex(code_hex)
    if digest != METHOD_CODE_SHA256 or hashlib.sha256(code).hexdigest() != digest:
        raise _LeafFailure("MODEL_PROFILE_CODE_HASH_MISMATCH")
    pins = profile.get("source_pins")
    if not isinstance(pins, list) or not pins or len(pins) > 16:
        raise _LeafFailure("MODEL_PROFILE_SOURCE_PINS_INVALID")
    for row in pins:
        pin_path = row.get("path") if isinstance(row, Mapping) else None
        if (not isinstance(row, Mapping) or set(row) != {"path", "bytes", "sha256"}
                or not isinstance(pin_path, str)
                or re.fullmatch(r"(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+", pin_path, re.ASCII) is None
                or any(part in {".", ".."} for part in pin_path.split("/"))
                or type(row.get("bytes")) is not int or row["bytes"] <= 0
                or not isinstance(row.get("sha256"), str)
                or LOWER_SHA256_RE.fullmatch(row["sha256"]) is None):
            raise _LeafFailure("MODEL_PROFILE_SOURCE_PIN_INVALID")
    return {**profile, "_method_code": code}


def _unknown_all(reason: str, common: Mapping[str, Any],
                 trace: _BudgetReader) -> dict[str, dict[str, Any]]:
    shared = dict(common)
    shared["shared_reads"] = deepcopy(trace.reads)
    shared["budget"] = trace.summary()
    return {name: _unknown(reason, shared) for name in MODEL_POINTER_OFFSETS}


def _read_model_key(trace: _BudgetReader, model_pointer: int,
                    label: str) -> tuple[str, dict[str, Any]]:
    header_address = _add(model_pointer, MODEL_KEY_OFFSET,
                          MODEL_KEY_HEADER_BYTES, f"{label}_key_header")
    header = _read_exact(trace, header_address, MODEL_KEY_HEADER_BYTES,
                         f"quality_model.{label}.string32_header")
    length = int.from_bytes(header[MODEL_KEY_LENGTH_OFFSET:MODEL_KEY_LENGTH_OFFSET + 8],
                            "little", signed=False)
    capacity = int.from_bytes(header[MODEL_KEY_CAPACITY_OFFSET:MODEL_KEY_CAPACITY_OFFSET + 8],
                              "little", signed=False)
    details: dict[str, Any] = {
        "model_pointer": hex(model_pointer),
        "string32_header_address": hex(header_address),
        "string32_header_raw_hex": header.hex(),
        "length": length,
        "length_raw_hex": header[MODEL_KEY_LENGTH_OFFSET:MODEL_KEY_LENGTH_OFFSET + 8].hex(),
        "capacity": capacity,
        "capacity_raw_hex": header[MODEL_KEY_CAPACITY_OFFSET:MODEL_KEY_CAPACITY_OFFSET + 8].hex(),
    }
    if not 1 <= length <= MAX_MODEL_KEY_BYTES:
        raise _LeafFailure("MODEL_KEY_LENGTH_INVALID")
    if capacity < length or capacity > MAX_STRING_CAPACITY:
        raise _LeafFailure("MODEL_KEY_CAPACITY_INVALID")
    if capacity < 16:
        payload_address = header_address
        storage = "inline"
        payload = header[:length + 1]
    else:
        pointer = int.from_bytes(header[:8], "little", signed=False)
        pointer = _user_pointer(pointer, "MODEL_KEY_DATA", aligned=False)
        payload_address = pointer
        storage = "heap"
        payload = _read_exact(trace, pointer, length + 1,
                              f"quality_model.{label}.string32_heap_payload")
        details["heap_pointer"] = hex(pointer)
    details.update({"storage": storage, "payload_address": hex(payload_address),
                    "payload_raw_hex": payload.hex()})
    if len(payload) != length + 1 or payload[-1] != 0:
        raise _LeafFailure("MODEL_KEY_NUL_TERMINATOR_INVALID")
    key_bytes = payload[:-1]
    if not key_bytes or 0 in key_bytes:
        raise _LeafFailure("MODEL_KEY_CONTENT_INVALID")
    try:
        key = key_bytes.decode("ascii", "strict")
    except UnicodeDecodeError as exc:
        raise _LeafFailure("MODEL_KEY_NOT_ASCII") from exc
    if MODEL_KEY_RE.fullmatch(key) is None:
        raise _LeafFailure("MODEL_KEY_GRAMMAR_INVALID")
    details["key"] = key
    return key, details


def _name_status(trace: _BudgetReader, base: int, key: str,
                 cache: dict[str, dict[str, Any]], observer: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if key in cache:
        result = deepcopy(cache[key])
        return result["public"], {"cache_reused": True, "lookup": result["private"]}
    try:
        found = _localization_name.read_cached_name(trace, base, key, observer=observer)
    except Exception as exc:
        found = {"status": "unknown", "reason": "LOCALIZATION_LOOKUP_FAILED",
                 "raw_inputs": {"error_type": type(exc).__name__}}
    private = deepcopy(dict(found)) if isinstance(found, Mapping) else {
        "status": "unknown", "reason": "LOCALIZATION_RESULT_INVALID"}
    if private.get("status") == "known":
        raw_hex = private.get("raw_hex")
        language = private.get("language")
        valid_hex = (isinstance(raw_hex, str) and len(raw_hex) % 2 == 0
                     and len(raw_hex) <= 16_384
                     and re.fullmatch(r"(?:[0-9a-f]{2})*", raw_hex, re.ASCII) is not None)
        if not valid_hex or not isinstance(language, str) or LANGUAGE_RE.fullmatch(language) is None:
            public = {"status": "unknown", "reason": "LOCALIZATION_RESULT_INVALID"}
        else:
            public = {"status": "known", "raw_hex": raw_hex,
                      "language": language}
    else:
        public = {"status": "unknown",
                  "reason": _safe_reason(private.get("reason"), "LOCALIZATION_LOOKUP_UNKNOWN")}
    cache[key] = {"public": deepcopy(public), "private": private}
    return public, {"cache_reused": False, "lookup": private}


def read_models(reader: Any, base: int, target_binding: Any, *,
                model_profile: Any, observer: str = "FRA") -> dict[str, dict[str, Any]]:
    """Read selected naval model keys and raw localized-name cache values.

    Shared target/profile/method/vtable failures withdraw all three components.
    A null or malformed model object withdraws only its own component. Unknown
    localization preserves the already verified model key.
    """
    base_raw = hex(base) if type(base) is int else None
    common: dict[str, Any] = {
        "schema": SCHEMA,
        "module_base": base_raw,
        "target_binding": deepcopy(dict(target_binding)) if isinstance(target_binding, Mapping) else None,
        "model_profile_schema": model_profile.get("schema") if isinstance(model_profile, Mapping) else None,
        "target_fullref_revalidation": None,
        "method_guard": None,
        "vtable_slot_guard": None,
    }
    if (type(base) is not int or base < MIN_USER_ADDRESS
            or base >= MAX_USER_ADDRESS_EXCLUSIVE or base & 7):
        return {name: _unknown("MODULE_BASE_INVALID", common)
                for name in MODEL_POINTER_OFFSETS}
    trace = _BudgetReader(reader, base)
    try:
        profile = _parse_profile(model_profile)
    except Exception as exc:
        reason = exc.reason if isinstance(exc, _LeafFailure) else "MODEL_PROFILE_INVALID"
        common["profile_error"] = type(exc).__name__
        return _unknown_all(reason, common, trace)

    try:
        parsed_base, target_pointer, retained = _country_binding._parse_target(base, target_binding)
        if parsed_base != base:
            raise _LeafFailure("TARGET_MODULE_BASE_MISMATCH")
        common["target_binding"] = deepcopy(retained)
        fullref_address = _add(target_pointer, COUNTRY_FULLREF_OFFSET, 8,
                               "target_fullref")
        current_fullref_raw = _read_exact(trace, fullref_address, 8,
                                          "quality_model.target.fullref")
        current_fullref = int.from_bytes(current_fullref_raw, "little", signed=False)
        expected_raw = bytes.fromhex(retained["fullref_raw_hex"])
        common["target_fullref_revalidation"] = {
            "address": hex(fullref_address),
            "expected_raw_hex": expected_raw.hex(),
            "current_raw_hex": current_fullref_raw.hex(),
            "current_fullref": hex(current_fullref),
            "status": "known" if current_fullref_raw == expected_raw else "mismatch",
        }
        if current_fullref_raw != expected_raw:
            raise _LeafFailure("TARGET_FULLREF_CHANGED")
    except Exception as exc:
        reason = exc.reason if isinstance(exc, _LeafFailure) else "TARGET_BINDING_INVALID"
        common.setdefault("target_error_type", type(exc).__name__)
        return _unknown_all(reason, common, trace)

    try:
        method_address = _add(base, METHOD_RVA, len(profile["_method_code"]),
                              "method_guard")
        runtime_code = _read_exact(trace, method_address, len(profile["_method_code"]),
                                   "quality_model.method_code_guard")
        code_hash = hashlib.sha256(runtime_code).hexdigest()
        common["method_guard"] = {
            "address": hex(method_address), "rva": hex(METHOD_RVA),
            "bytes": len(runtime_code), "runtime_sha256": code_hash,
            "expected_sha256": profile["method_code_sha256"],
            "status": "known" if runtime_code == profile["_method_code"] else "mismatch",
            "base_relocations_intersecting": [],
        }
        if runtime_code != profile["_method_code"]:
            raise _LeafFailure("MODEL_METHOD_CODE_GUARD_MISMATCH")
        vtable_slot_address = _add(base, VT_RVA + VT_SLOT_OFFSET, 8,
                                   "vtable_method_slot")
        slot_raw = _read_exact(trace, vtable_slot_address, 8,
                               "quality_model.vtable.method_slot")
        slot_value = int.from_bytes(slot_raw, "little", signed=False)
        expected_slot = _add(base, METHOD_RVA, 1, "expected_method_pointer")
        common["vtable_slot_guard"] = {
            "address": hex(vtable_slot_address), "rva": hex(VT_RVA + VT_SLOT_OFFSET),
            "raw_hex": slot_raw.hex(), "runtime_pointer": hex(slot_value),
            "expected_runtime_pointer": hex(expected_slot),
            "status": "known" if slot_value == expected_slot else "mismatch",
            "file_pointer_is_relocated": True,
        }
        if slot_value != expected_slot:
            raise _LeafFailure("MODEL_VTABLE_SLOT_GUARD_MISMATCH")
    except Exception as exc:
        reason = exc.reason if isinstance(exc, _LeafFailure) else "MODEL_METHOD_GUARD_READ_FAILED"
        common.setdefault("guard_error_type", type(exc).__name__)
        return _unknown_all(reason, common, trace)

    output: dict[str, dict[str, Any]] = {}
    name_cache: dict[str, dict[str, Any]] = {}
    for component, offset in MODEL_POINTER_OFFSETS.items():
        start = len(trace.reads)
        inputs: dict[str, Any] = {
            "target_binding": deepcopy(retained),
            "target_fullref_revalidation": deepcopy(common["target_fullref_revalidation"]),
            "method_guard": deepcopy(common["method_guard"]),
            "vtable_slot_guard": deepcopy(common["vtable_slot_guard"]),
            "country_model_pointer_address": None,
            "model_pointer": None,
            "model_vtable": None,
            "model_key": None,
            "localization_cache": None,
        }
        try:
            pointer_cell = _add(target_pointer, offset, 8,
                                component.replace(".", "_") + "_pointer")
            inputs["country_model_pointer_address"] = hex(pointer_cell)
            pointer_raw = _read_exact(trace, pointer_cell, 8,
                                      f"quality_model.{component}.object_pointer")
            model_pointer_value = int.from_bytes(pointer_raw, "little", signed=False)
            inputs["country_model_pointer_raw_hex"] = pointer_raw.hex()
            if model_pointer_value == 0:
                raise _LeafFailure("MODEL_POINTER_NULL")
            model_pointer = _user_pointer(model_pointer_value, "MODEL_OBJECT")
            inputs["model_pointer"] = hex(model_pointer)
            vtable_address = _add(model_pointer, MODEL_VTABLE_OFFSET, 8,
                                  "model_vtable")
            vtable_raw = _read_exact(trace, vtable_address, 8,
                                     f"quality_model.{component}.vtable")
            model_vtable = int.from_bytes(vtable_raw, "little", signed=False)
            expected_vtable = _add(base, VT_RVA, 1, "expected_model_vtable")
            inputs["model_vtable"] = {
                "address": hex(vtable_address), "raw_hex": vtable_raw.hex(),
                "runtime_pointer": hex(model_vtable),
                "expected_runtime_pointer": hex(expected_vtable),
                "status": "known" if model_vtable == expected_vtable else "mismatch",
            }
            if model_vtable != expected_vtable:
                raise _LeafFailure("MODEL_VTABLE_MISMATCH")
            key, key_evidence = _read_model_key(trace, model_pointer, component)
            inputs["model_key"] = key_evidence
            name, name_evidence = _name_status(trace, base, key, name_cache, observer)
            inputs["localization_cache"] = name_evidence
            inputs["reads"] = deepcopy(trace.reads[start:])
            inputs["budget"] = trace.summary()
            output[component] = {
                "status": "known",
                "value": {"localization_key": key, "name": name},
                "raw": key,
                "unit": "ship_model",
                "scale": 1,
                "raw_inputs": inputs,
            }
        except Exception as exc:
            reason = exc.reason if isinstance(exc, _LeafFailure) else "MODEL_COMPONENT_READ_FAILED"
            inputs["reads"] = deepcopy(trace.reads[start:])
            inputs["budget"] = trace.summary()
            inputs["error_type"] = type(exc).__name__
            output[component] = _unknown(reason, inputs)
    return output


__all__ = ["read_models"]
