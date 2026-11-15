"""Bounded reader for the country diplomacy-view great-power feature flag.

This leaf projects the already established country binding through the inputs
used by the B23 feature predicate. It does not infer rank membership, call a
native function, resolve caller/UI visibility, perform role admission, or open
a process. Negative outcomes whose result depends on the unresolved TLS branch
remain unknown.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from . import country_faith_memory as _country_binding


FIELD_ID = "F01.major_power"
COUNTRY_GREAT_POWER_FLAG_OFFSET = 0x288F
COUNTRY_FEATURE_QUALIFIER_OFFSET = 0x1344
COUNTRY_OVERLORD_FULLREF_OFFSET = 0x18F0
FEATURE_GLOBAL_A_RVA = 0x233FF00
FEATURE_GLOBAL_B_RVA = 0x233FEB6
FEATURE_GLOBAL_C_RVA = 0x233FF24

MAX_USER_ADDRESS = _country_binding.MAX_USER_ADDRESS
MIN_USER_ADDRESS = _country_binding.MIN_USER_ADDRESS
MAX_U64 = (1 << 64) - 1

_BASIS = "bounded_great_power_feature_predicate_inputs"
_GAPS = [
    "GREAT_POWER_FEATURE_FLAG_IS_NOT_RANK_MEMBERSHIP",
    "COUNTRY_RANKING_OR_GREAT_POWER_MEMBERSHIP_NOT_READ",
    "NEGATIVE_GLOBAL_BRANCH_DEPENDS_ON_UNRESOLVED_TLS",
    "UI_RENDERING_AND_VISIBILITY_NOT_OBSERVED",
    "CALLER_ROLE_AND_ADMISSION_ARE_PARENT_OWNED",
]


class _LeafUnknown(Exception):
    pass


def _unknown(reason: str, raw_inputs: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "status": "unknown",
        "complete": False,
        "reason": reason,
        "raw_inputs": raw_inputs if raw_inputs is not None else {},
        "basis": _BASIS,
        "gaps": list(_GAPS),
        "ui_observed": False,
        "ranking_membership_observed": False,
    }


def _known(value: bool, raw_inputs: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "known",
        "complete": False,
        "value": value,
        "raw_inputs": raw_inputs,
        "basis": _BASIS,
        "gaps": list(_GAPS),
        "ui_observed": False,
        "ranking_membership_observed": False,
    }


def _checked_add(base: int, offset: int, label: str, size: int) -> int:
    if (type(base) is not int or type(offset) is not int or offset < 0
            or type(size) is not int or size < 1 or base > MAX_U64 - offset):
        raise _LeafUnknown(f"address_arithmetic_invalid:{label}")
    address = base + offset
    if (address < MIN_USER_ADDRESS or address > MAX_USER_ADDRESS
            or address > MAX_USER_ADDRESS - (size - 1)):
        raise _LeafUnknown(f"address_out_of_user_range:{label}")
    return address


def _validated_binding(binding: Any, raw_inputs: dict[str, Any]) -> tuple[int, int]:
    if not isinstance(binding, Mapping):
        raise _LeafUnknown("country_binding_invalid")
    raw_hex = binding.get("fullref_raw_hex")
    if not isinstance(raw_hex, str) or len(raw_hex) != 16:
        raise _LeafUnknown("country_binding_fullref_raw_missing_or_invalid")
    try:
        bytes.fromhex(raw_hex)
        country_pointer, retained = _country_binding._binding(binding)
        fullref = int(retained["fullref"], 0)
    except Exception as exc:
        raise _LeafUnknown(f"country_binding_invalid:{type(exc).__name__}:{str(exc)[:96]}") from exc
    expected_raw = fullref.to_bytes(8, "little").hex()
    if raw_hex.lower() != expected_raw:
        raise _LeafUnknown("country_binding_fullref_raw_mismatch")
    if fullref >> 56 == 0:
        raise _LeafUnknown("country_binding_fullref_high_byte_zero")
    if ((fullref >> 48) & 0xFF) == 7:
        # This tagged/special reference can take a separate native path. It is
        # intentionally outside the ordinary-country leaf contract.
        raise _LeafUnknown("country_binding_special_byte48_7")
    raw_inputs["country_binding"] = retained
    raw_inputs["country_binding"]["fullref_byte48"] = (fullref >> 48) & 0xFF
    raw_inputs["country_binding"]["fullref_high_byte"] = (fullref >> 56) & 0xFF
    return country_pointer, fullref


def _read_operand(reader: Any, address: int, size: int, label: str,
                  raw_inputs: dict[str, Any]) -> bytes:
    try:
        data = _country_binding._read_exact(reader, address, size, label)
    except Exception as exc:
        raw_inputs["read_failures"].append(
            {"operand": label, "address": hex(address), "size": size,
             "error_type": type(exc).__name__, "error": str(exc)[:160]}
        )
        raise _LeafUnknown(f"native_read_failed:{label}:{type(exc).__name__}") from exc
    raw_inputs["reads"].append(
        {"operand": label, "address": hex(address), "size": size, "raw_hex": data.hex()}
    )
    return data


def _read_major_power(reader: Any, base: Any, binding: Any) -> dict[str, Any]:
    raw_inputs: dict[str, Any] = {
        "module_base": None,
        "predicate_path": [],
        "reads": [],
        "read_failures": [],
        "native_operands": {},
    }
    try:
        parsed_base = _country_binding._parse_uint(base, "module_base")
        _country_binding._user_pointer(parsed_base, "module_base")
        raw_inputs["module_base"] = hex(parsed_base)
        country_pointer, fullref = _validated_binding(binding, raw_inputs)
        raw_inputs["native_operands"]["bound_country_fullref"] = {
            "value_hex": f"0x{fullref:016x}",
            "raw_hex": fullref.to_bytes(8, "little").hex(),
        }

        flag_address = _checked_add(
            country_pointer, COUNTRY_GREAT_POWER_FLAG_OFFSET,
            "country_great_power_flag", 1,
        )
        flag_raw = _read_operand(reader, flag_address, 1,
                                 "country_great_power_flag", raw_inputs)
        flag = flag_raw[0]
        raw_inputs["native_operands"]["country_great_power_flag"] = {
            "address": hex(flag_address), "raw_hex": flag_raw.hex(), "unsigned": flag,
        }
        if flag == 0:
            raw_inputs["predicate_path"].append("target_flag_zero")
            return _known(False, raw_inputs)
        raw_inputs["predicate_path"].append("target_flag_nonzero")

        qualifier_address = _checked_add(
            country_pointer, COUNTRY_FEATURE_QUALIFIER_OFFSET,
            "country_feature_qualifier", 4,
        )
        qualifier_raw = _read_operand(reader, qualifier_address, 4,
                                      "country_feature_qualifier", raw_inputs)
        qualifier = int.from_bytes(qualifier_raw, "little", signed=True)
        raw_inputs["native_operands"]["country_feature_qualifier"] = {
            "address": hex(qualifier_address), "raw_hex": qualifier_raw.hex(),
            "signed_i32": qualifier,
        }
        if qualifier == 0:
            raw_inputs["predicate_path"].append("country_feature_qualifier_zero")
            return _known(False, raw_inputs)
        raw_inputs["predicate_path"].append("country_feature_qualifier_nonzero")

        # The ordinary native path also checks the stored overlord fullref.
        # A zero qualifier above already decides the result and must not be
        # overturned by a later, unnecessary read failure.
        overlord_address = _checked_add(
            country_pointer, COUNTRY_OVERLORD_FULLREF_OFFSET,
            "country_overlord_fullref", 8,
        )
        overlord_raw = _read_operand(reader, overlord_address, 8,
                                     "country_overlord_fullref", raw_inputs)
        overlord = int.from_bytes(overlord_raw, "little")
        overlord_high_byte = (overlord >> 56) & 0xFF
        raw_inputs["native_operands"]["country_overlord_fullref"] = {
            "address": hex(overlord_address), "raw_hex": overlord_raw.hex(),
            "fullref_hex": f"0x{overlord:016x}",
            "high_byte": overlord_high_byte,
        }

        if overlord_high_byte != 0:
            raw_inputs["predicate_path"].append("overlord_fullref_high_byte_nonzero")
            return _known(False, raw_inputs)
        raw_inputs["predicate_path"].append("overlord_fullref_high_byte_zero")

        globals_spec = (
            ("feature_global_A", FEATURE_GLOBAL_A_RVA),
            ("feature_global_B", FEATURE_GLOBAL_B_RVA),
            ("feature_global_C", FEATURE_GLOBAL_C_RVA),
        )
        values: dict[str, int] = {}
        for label, rva in globals_spec:
            address = _checked_add(parsed_base, rva, label, 1)
            operand_raw = _read_operand(reader, address, 1, label, raw_inputs)
            operand_value = operand_raw[0]
            values[label] = operand_value
            raw_inputs["native_operands"][label] = {
                "rva": hex(rva), "address": hex(address),
                "raw_hex": operand_raw.hex(), "unsigned": operand_value,
            }

        a = values["feature_global_A"]
        b = values["feature_global_B"]
        c = values["feature_global_C"]
        raw_inputs["predicate_path"].append(
            f"global_predicate:A_nonzero={a != 0},B_zero={b == 0},C_nonzero={c != 0}"
        )
        if (a != 0 or c != 0) and b == 0:
            raw_inputs["predicate_path"].append("global_predicate_positive")
            return _known(True, raw_inputs)
        raw_inputs["predicate_path"].append("global_negative_tls_unresolved")
        return _unknown("GREAT_POWER_TLS_PREDICATE_UNRESOLVED", raw_inputs)
    except _LeafUnknown as exc:
        raw_inputs["predicate_path"].append("leaf_unknown")
        return _unknown(str(exc), raw_inputs)
    except Exception as exc:
        raw_inputs["predicate_path"].append("leaf_unknown")
        return _unknown(f"leaf_read_failed:{type(exc).__name__}:{str(exc)[:120]}", raw_inputs)


def read_fields(reader: Any, base: Any, binding: Mapping[str, Any],
                fields: tuple[str, ...]) -> dict[str, dict[str, Any]]:
    """Read only ``F01.major_power`` from an already resolved country row.

    The parent owns process/ROM guards, country-scan consistency, view
    admission, role identity, read budgets, and two-pass stability. This leaf
    only uses the supplied reader and never opens or calls a process/native
    function.
    """
    if not isinstance(fields, tuple) or any(not isinstance(field, str) for field in fields):
        return {FIELD_ID: _unknown("fields_shape_invalid")}
    if len(set(fields)) != len(fields):
        return {field: _unknown("duplicate_field_requested") for field in dict.fromkeys(fields)}
    result: dict[str, dict[str, Any]] = {}
    for field in fields:
        if field != FIELD_ID:
            result[field] = _unknown("unsupported_field")
        else:
            result[field] = _read_major_power(reader, base, binding)
    return result


__all__ = [
    "FIELD_ID",
    "COUNTRY_GREAT_POWER_FLAG_OFFSET",
    "COUNTRY_FEATURE_QUALIFIER_OFFSET",
    "COUNTRY_OVERLORD_FULLREF_OFFSET",
    "FEATURE_GLOBAL_A_RVA",
    "FEATURE_GLOBAL_B_RVA",
    "FEATURE_GLOBAL_C_RVA",
    "read_fields",
]
