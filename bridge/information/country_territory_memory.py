"""Bounded leaf for the country's native ``num_of_cities`` cache.

The caller owns process/session/profile checks, role and visibility admission,
read budgets across fields, and two-pass comparison.  This leaf re-resolves
the supplied target through the country database before reading ``country+
0x1fc8``.  The country-scope ``num_of_cities`` number encoder multiplies the
signed cache by 1000 for script-number encoding. A separate tooltip path
formats the raw cache integer, so this multiplier is not a displayed-value
claim. This is not a complete owned-province census and does not establish the
cache writer or freshness.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from . import country_faith_memory as _faith
from . import foreign_country_memory as _shared
from . import province_state_memory as _province


SCHEMA = "information.country_territory_memory.v1"
FIELD_ID = "F01.territory"
FIELDS = (FIELD_ID,)
CITY_COUNT_CACHE_OFFSET = 0x1FC8
SCRIPT_MULTIPLIER = 1000
MAX_EXPORTED_CITY_COUNT = 65535
MAX_FIELD_COUNT = 16
MIN_USER_ADDRESS = _shared.MIN_USER_ADDRESS
MAX_USER_ADDRESS_EXCLUSIVE = _shared.MAX_USER_ADDRESS_EXCLUSIVE
MAX_U64 = 0xFFFFFFFFFFFFFFFF

_GAPS = [
    "COMPLETE_OWNED_PROVINCE_COUNT_AND_LIST_NOT_READ",
    "COUNTRY_CITY_COUNT_CACHE_WRITER_AND_FRESHNESS_NOT_ESTABLISHED",
    "SCRIPT_NUMBER_ENCODING_IS_NOT_TOOLTIP_RENDERING",
    "CALLER_ROLE_VISIBILITY_AND_TWO_PASS_CHECKS_ARE_PARENT_OWNED",
]


class _ReaderAdapter:
    """Adapt a callable or ``.read`` object to the shared bounded reader."""

    def __init__(self, source: Any):
        self.source = source

    def read(self, address: int, size: int, label: str) -> bytes:
        try:
            method = getattr(self.source, "read", None)
            if callable(method):
                raw = method(address, size, label)
            elif callable(self.source):
                raw = self.source(address, size, label)
            else:
                raise TypeError("reader_not_callable_or_readable")
        except Exception as exc:
            raise ValueError("country_territory_reader_failed") from exc
        if not isinstance(raw, (bytes, bytearray, memoryview)):
            raise ValueError("country_territory_reader_result_invalid")
        return bytes(raw)


class _LeafFailure(Exception):
    pass


def _is_user_address(value: Any) -> bool:
    return (type(value) is int and MIN_USER_ADDRESS <= value < MAX_USER_ADDRESS_EXCLUSIVE
            and value <= MAX_U64)


def _checked_add(address: Any, offset: Any, size: Any, label: str) -> int:
    if (not _is_user_address(address) or type(offset) is not int or offset < 0
            or type(size) is not int or size <= 0 or offset > MAX_U64 - address):
        raise _LeafFailure(f"address_arithmetic_invalid:{label}")
    result = address + offset
    if (not _is_user_address(result) or result > MAX_USER_ADDRESS_EXCLUSIVE - size
            or result > MAX_U64 - (size - 1)):
        raise _LeafFailure(f"address_range_invalid:{label}")
    return result


def _read_exact(limiter: _shared._BoundedReader, address: int,
                size: int, label: str) -> bytes:
    if (not _is_user_address(address) or type(size) is not int or size <= 0
            or size > _shared.MAX_SINGLE_READ_BYTES
            or address > MAX_USER_ADDRESS_EXCLUSIVE - size):
        raise _LeafFailure(f"address_range_invalid:{label}")
    try:
        raw = limiter.read(address, size, label)
    except Exception as exc:
        message = str(exc)
        if "reader_short_read" in message or "short_or_invalid_read" in message:
            reason = "short_read"
        elif "read_budget_exceeded" in message or "read_call_budget_exceeded" in message:
            reason = "read_budget_exceeded"
        else:
            reason = "read_failed"
        raise _LeafFailure(f"{reason}:{label}") from exc
    if len(raw) != size:
        raise _LeafFailure(f"short_read:{label}")
    return raw


def _wrap_i32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _unknown(reason: str, raw_inputs: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "reason": reason,
        "unit": "native_city_count",
        "scale": 1,
        "partial": True,
        "complete": False,
        "basis": "bounded_country_num_of_cities_cache_i32",
        "gaps": list(_GAPS),
    }
    if raw_inputs is not None:
        result["raw_inputs"] = deepcopy(dict(raw_inputs))
    return result


def _parse_target(base: Any, binding: Any) -> tuple[int, int, dict[str, Any]]:
    if type(base) is not int or not _is_user_address(base) or base & 7:
        raise ValueError("module_base_invalid")
    country_pointer, retained = _faith._binding(binding)
    if not _is_user_address(country_pointer) or country_pointer & 7:
        raise ValueError("target_country_pointer_invalid")
    try:
        fullref = int(retained["fullref"], 0)
        slot = retained["slot"]
        tag = retained["tag"]
        raw_hex = retained["fullref_raw_hex"]
        fullref_raw = bytes.fromhex(raw_hex)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("target_fullref_binding_invalid") from exc
    if len(fullref_raw) != 8 or int.from_bytes(fullref_raw, "little") != fullref:
        raise ValueError("target_fullref_raw_mismatch")
    if type(slot) is not int or not 0 <= slot < _province.MAX_COUNTRY_SLOTS:
        raise ValueError("target_fullref_slot_invalid")
    if ((fullref >> 32) & 0xFFFF) != slot:
        raise ValueError("target_fullref_slot_mismatch")
    if (fullref & 0xFFFFFF).to_bytes(3, "little").decode("ascii") != tag:
        raise ValueError("target_fullref_tag_mismatch")
    if ((fullref >> 56) & 0xFF) == 0:
        raise ValueError("target_fullref_high_byte_zero")
    if ((fullref >> 48) & 0xFF) == 7:
        raise ValueError("target_fullref_byte48_seven_unsupported")
    return base, country_pointer, retained


def _validate_target_binding(limiter: _shared._BoundedReader, base: int,
                             country_pointer: int, target: Mapping[str, Any],
                             evidence: dict[str, Any]) -> None:
    fullref_raw = bytes.fromhex(str(target["fullref_raw_hex"]))
    resolved = _province._resolve_country_reference(
        limiter, base, fullref_raw, "country_territory.target")
    evidence["country_reference_resolution"] = deepcopy(resolved)
    if not isinstance(resolved, Mapping) or resolved.get("status") != "known":
        raise _LeafFailure("target_country_fullref_unresolved")
    resolution_raw = resolved.get("raw_inputs")
    if not isinstance(resolution_raw, Mapping):
        raise _LeafFailure("target_country_reference_evidence_missing")
    try:
        resolved_pointer = int(resolution_raw["country_pointer"], 0)
        canonical_fullref = int(resolution_raw["canonical_fullref"], 0)
        resolved_slot = resolution_raw["slot"]
    except (KeyError, TypeError, ValueError) as exc:
        raise _LeafFailure("target_country_reference_evidence_invalid") from exc
    supplied_fullref = int(str(target["fullref"]), 0)
    if (resolved_pointer != country_pointer
            or canonical_fullref != supplied_fullref
            or resolved_slot != target["slot"]
            or resolved.get("value") != target["tag"]):
        raise _LeafFailure("target_country_binding_database_mismatch")


def _read_city_count(limiter: _shared._BoundedReader, country_pointer: int,
                     target_evidence: Mapping[str, Any]) -> dict[str, Any]:
    raw_inputs: dict[str, Any] = {"target_evidence": deepcopy(dict(target_evidence))}
    try:
        address = _checked_add(country_pointer, CITY_COUNT_CACHE_OFFSET, 4,
                               "country_city_count_cache")
        raw_inputs["city_count_cache_address"] = hex(address)
        cache_raw = _read_exact(
            limiter, address, 4, "country_territory.city_count.cache_i32")
        city_count = int.from_bytes(cache_raw, "little", signed=True)
        multiplied = city_count * SCRIPT_MULTIPLIER
        raw_inputs.update({
            "city_count_cache_raw_hex": cache_raw.hex(),
            "city_count_cache_i32": city_count,
            "native_script_multiply_input_i32": city_count,
            "native_script_multiplier": SCRIPT_MULTIPLIER,
            "native_script_multiply_unwrapped": multiplied,
            "native_script_multiply_wrapped_i32": _wrap_i32(multiplied),
        })
        if not 0 <= city_count <= MAX_EXPORTED_CITY_COUNT:
            return _unknown("city_count_cache_out_of_supported_range", raw_inputs)
        return {
            "status": "known",
            "value": {"city_count": city_count},
            "unit": "native_city_count",
            "scale": 1,
            "partial": True,
            "complete": False,
            "basis": "bounded_country_num_of_cities_cache_i32",
            "gaps": list(_GAPS),
            "raw_inputs": raw_inputs,
        }
    except _LeafFailure as exc:
        return _unknown(str(exc), raw_inputs)
    except Exception as exc:
        return _unknown(f"country_city_count_read_failed:{type(exc).__name__}", raw_inputs)


def read_fields(reader: Any, base: int, binding: Mapping[str, Any],
                fields: tuple[str, ...]) -> dict[str, dict[str, Any]]:
    """Read only ``F01.territory`` from a verified country binding.

    A known result is the signed ``country+0x1fc8`` cache when it lies in the
    agreed nonnegative 16-bit range. It does not claim a full province count,
    province list, cache writer or freshness. Parent code owns process/profile
    validation, role/visibility gates, shared read budget and two-pass checks.
    """
    if (not isinstance(fields, tuple) or len(fields) > MAX_FIELD_COUNT
            or any(not isinstance(field, str) for field in fields)):
        return {FIELD_ID: _unknown("fields_shape_invalid")}
    if len(set(fields)) != len(fields):
        return {field: _unknown("duplicate_field_requested")
                for field in dict.fromkeys(fields)}

    result: dict[str, dict[str, Any]] = {}
    supported = []
    for field in fields:
        if field == FIELD_ID:
            supported.append(field)
        else:
            result[field] = {"status": "unknown", "reason": "unsupported_field",
                             "partial": True, "complete": False}
    if not supported:
        return result

    try:
        module_base, country_pointer, target = _parse_target(base, binding)
    except Exception as exc:
        result[FIELD_ID] = _unknown(f"target_binding_invalid:{str(exc)[:120]}")
        return result

    limiter = _shared._BoundedReader(_ReaderAdapter(reader))
    target_evidence: dict[str, Any] = {"country_binding": deepcopy(target)}
    try:
        _validate_target_binding(limiter, module_base, country_pointer,
                                 target, target_evidence)
    except Exception as exc:
        result[FIELD_ID] = _unknown(
            f"target_binding_unverified:{str(exc)[:160] or type(exc).__name__}",
            target_evidence,
        )
        return result

    result[FIELD_ID] = _read_city_count(limiter, country_pointer, target_evidence)
    return result


__all__ = ["FIELD_ID", "FIELDS", "SCHEMA", "CITY_COUNT_CACHE_OFFSET", "read_fields"]
