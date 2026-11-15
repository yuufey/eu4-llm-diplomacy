"""Read native effective province-development components for G02.development.

The fixed-B23 REA evidence records the total caller and three effective
helpers: the older a0cff0 procedure is ``ev_9e21cbee8d77a45cdfa9df5e2c063277431b73cc74b35b8da76f413e974407ec``;
the tax, production, and manpower helpers are respectively
``ev_82ccadc8e9f10b6fd74aedbb84c643448c336edb697576cc06b3a34b393c850e``,
``ev_1ed6e159d8d66b32afe06cf977201f3c5d5e75a728e15477315fe3b4a5c03710``,
and ``ev_5af952692baa2cbcfc80857e3e102ec51312aa5a4306468ae2dba5a01a35dbeb``.
This leaf uses a previously resolved province binding and the existing
canonical country-reference resolver. Admission, discovery, process access,
budgets, and two-pass comparison belong to its caller.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from . import province_identity_memory as _identity
from . import province_state_memory as _state


FIELD_ID = "G02.development"
MAX_PROVINCE_ID = 0xFFFF
MAX_FIELDS = 16
TAX_BASE_OFFSET = 0x3E4
PRODUCTION_BASE_OFFSET = 0x3E8
MANPOWER_BASE_OFFSET = 0x3E0
OWNER_FULLREF_OFFSET = 0x468
COUNTRY_TRIBAL_POINTER_OFFSET = 0x9A78
COUNTRY_PROVINCE_ID_OFFSET = 0x14B8
TRIBAL_TAX_OFFSET = 0x1C
TRIBAL_PRODUCTION_OFFSET = 0x20
TRIBAL_MANPOWER_OFFSET = 0x24
SCALE = 1000

_COMPONENTS = (
    ("tax", TAX_BASE_OFFSET, TRIBAL_TAX_OFFSET),
    ("production", PRODUCTION_BASE_OFFSET, TRIBAL_PRODUCTION_OFFSET),
    ("manpower", MANPOWER_BASE_OFFSET, TRIBAL_MANPOWER_OFFSET),
)
_BASIS = "native_province_development_effective_total_signed_i32"


class _Unknown(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _CountryReaderAdapter:
    """Give the state resolver a .read interface without replacing its limiter."""

    def __init__(self, source: Any):
        self.source = source

    def read(self, address: int, size: int, label: str) -> bytes:
        return _identity._read_exact(self.source, address, size, label)


def _unknown(reason: str, raw_inputs: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {
        "status": "unknown",
        "reason": reason,
        "basis": _BASIS,
        "scale": SCALE,
        "period": "current",
        "partial": True,
        "complete": False,
        "raw_inputs": deepcopy(dict(raw_inputs)) if isinstance(raw_inputs, Mapping) else {},
    }


def _wrap_i32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _trunc_div_1000(value: int) -> int:
    """C++ signed integer division truncates toward zero."""
    return value // 1000 if value >= 0 else -((-value) // 1000)


def _read_exact(reader: Any, address: int, size: int, label: str) -> bytes:
    return _identity._read_exact(reader, address, size, label)


def _read_u64(reader: Any, address: int, label: str) -> tuple[int, bytes]:
    raw = _read_exact(reader, address, 8, label)
    return int.from_bytes(raw, "little", signed=False), raw


def _read_i32(reader: Any, address: int, label: str) -> tuple[int, bytes]:
    raw = _read_exact(reader, address, 4, label)
    return int.from_bytes(raw, "little", signed=True), raw


def _add(base: int, offset: int, label: str) -> int:
    address = base + offset
    _identity._checked_user_range(address, 1, label)
    return address


def _validate_binding(module_base: Any, binding: Any) -> tuple[int, int, dict[str, Any]]:
    base, record, normalized = _identity._validate_binding(module_base, binding)
    province_id = normalized["province_id"]
    if type(province_id) is not int or not 1 <= province_id <= MAX_PROVINCE_ID:
        raise ValueError("province_id_out_of_supported_range")
    return base, record, normalized


def _fields_list(fields: Any) -> tuple[str, ...] | None:
    if not isinstance(fields, (list, tuple)) or len(fields) > MAX_FIELDS:
        return None
    if any(type(field) is not str or len(field) > 128 for field in fields):
        return None
    return tuple(fields)


def _resolve_owner(reader: Any, base: int, record: int,
                   raw_inputs: dict[str, Any]) -> tuple[dict[str, Any], int]:
    owner_address = _add(record, OWNER_FULLREF_OFFSET, "owner_fullref")
    owner_raw = _read_exact(reader, owner_address, 8, "province_development.owner_fullref")
    raw_inputs.update({
        "owner_fullref_address": hex(owner_address),
        "owner_fullref_raw_hex": owner_raw.hex(),
    })
    resolved = _state._resolve_country_reference(
        _CountryReaderAdapter(reader), base, owner_raw, "development_owner")
    raw_inputs["owner_resolution"] = deepcopy(resolved)
    if resolved.get("status") != "known":
        raise _Unknown(f"owner_reference_unknown:{resolved.get('reason', 'unknown')}")
    resolver_raw = resolved.get("raw_inputs")
    if not isinstance(resolver_raw, Mapping):
        raise _Unknown("owner_reference_raw_inputs_missing")
    pointer_text = resolver_raw.get("country_pointer")
    try:
        owner_pointer = int(pointer_text, 0) if isinstance(pointer_text, str) else pointer_text
    except (TypeError, ValueError) as exc:
        raise _Unknown("owner_country_pointer_invalid") from exc
    try:
        _identity._user_pointer(owner_pointer, "owner_country_pointer", aligned=True)
    except Exception as exc:
        raise _Unknown(f"owner_country_pointer_invalid:{type(exc).__name__}") from exc
    raw_inputs["owner_tag"] = resolved.get("value")
    raw_inputs["owner_country_pointer"] = hex(owner_pointer)
    return dict(resolved), owner_pointer


def _read_bases(reader: Any, record: int, province_id: int,
                raw_inputs: dict[str, Any]) -> dict[str, dict[str, Any]]:
    bases: dict[str, dict[str, Any]] = {}
    for name, offset, _bonus_offset in _COMPONENTS:
        address = _add(record, offset, f"{name}_base")
        value, raw = _read_i32(
            reader, address, f"province_development.base.{name}[{province_id}]")
        bases[name] = {"address": hex(address), "raw": value, "raw_hex": raw.hex()}
    raw_inputs["bases"] = deepcopy(bases)
    return bases


def _read_bonus_context(reader: Any, owner_pointer: int, province_id: int,
                        raw_inputs: dict[str, Any]) -> tuple[int, str, int | None]:
    pointer_address = _add(
        owner_pointer, COUNTRY_TRIBAL_POINTER_OFFSET, "tribal_pointer_cell")
    tribal_pointer, pointer_raw = _read_u64(
        reader, pointer_address, "province_development.owner.tribal_pointer")
    raw_inputs.update({
        "tribal_pointer_address": hex(pointer_address),
        "tribal_pointer_raw_hex": pointer_raw.hex(),
        "tribal_pointer": hex(tribal_pointer),
    })
    if tribal_pointer == 0:
        raw_inputs["bonus_gate"] = "null_tribal_pointer"
        return 0, "null_tribal_pointer", None
    try:
        _identity._user_pointer(tribal_pointer, "tribal_pointer", aligned=True)
    except Exception as exc:
        raise _Unknown(f"tribal_pointer_invalid:{type(exc).__name__}") from exc

    capital_id_address = _add(
        owner_pointer, COUNTRY_PROVINCE_ID_OFFSET, "owner_province_id")
    capital_id, capital_raw = _read_i32(
        reader, capital_id_address, "province_development.owner.province_id")
    raw_inputs.update({
        "owner_province_id_address": hex(capital_id_address),
        "owner_province_id_raw_hex": capital_raw.hex(),
        "owner_province_id": capital_id,
    })
    if capital_id != province_id:
        raw_inputs["bonus_gate"] = "owner_province_id_mismatch"
        return tribal_pointer, "owner_province_id_mismatch", capital_id
    raw_inputs["bonus_gate"] = "owner_province_id_match"
    return tribal_pointer, "owner_province_id_match", capital_id


def _components(reader: Any, bases: Mapping[str, Mapping[str, Any]],
                tribal_pointer: int, bonus_gate: str, province_id: int,
                raw_inputs: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], int]:
    components: dict[str, dict[str, Any]] = {}
    total = 0
    for name, _base_offset, bonus_offset in _COMPONENTS:
        base_raw = bases[name]["raw"]
        bonus_raw = None
        bonus_raw_hex = None
        quotient = 0
        bonus_value = 0
        bonus_address = None
        bonus_read = False
        if bonus_gate == "owner_province_id_match":
            bonus_address_int = _add(tribal_pointer, bonus_offset, f"{name}_bonus")
            bonus_raw, bonus_bytes = _read_i32(
                reader, bonus_address_int,
                f"province_development.bonus.{name}[{province_id}]")
            bonus_raw_hex = bonus_bytes.hex()
            quotient = _trunc_div_1000(bonus_raw)
            bonus_value = quotient * SCALE
            bonus_address = hex(bonus_address_int)
            bonus_read = True
        component = _wrap_i32(base_raw + bonus_value)
        total = _wrap_i32(total + component)
        components[name] = {
            "base_raw": base_raw,
            "bonus_read": bonus_read,
            "bonus_address": bonus_address,
            "bonus_raw": bonus_raw,
            "bonus_raw_hex": bonus_raw_hex,
            "bonus_truncated_quotient": quotient,
            "bonus_value": bonus_value,
            "component_raw": component,
        }
    raw_inputs["components"] = deepcopy(components)
    return components, total


def read_fields(reader: Any, base: Any, binding: Any,
                fields: list[str] | tuple[str, ...]) -> dict[str, dict[str, Any]]:
    """Read only G02.development using an existing province binding and reader.

    The callable or ``.read`` reader is used directly; no second budget or
    process handle is created. Other field IDs are unknown and cause no
    corresponding reads. The owner is resolved through the existing state
    helper, which validates the entire 64-bit reference against the country
    table. A parent must apply observer/admission checks and compare two passes.
    """
    selected = _fields_list(fields)
    if selected is None:
        return {FIELD_ID: _unknown("field_selector_invalid")}
    if not selected:
        return {}
    unique = tuple(dict.fromkeys(selected))
    if len(unique) != len(selected):
        return {field: _unknown("duplicate_field_requested") for field in unique}
    result = {
        field: _unknown("unsupported_field")
        for field in unique if field != FIELD_ID
    }
    if FIELD_ID not in unique:
        return result

    raw_inputs: dict[str, Any] = {"field": FIELD_ID}
    try:
        if not callable(reader) and not callable(getattr(reader, "read", None)):
            raise _Unknown("reader_not_callable_or_readable")
        try:
            module_base, record, normalized = _validate_binding(base, binding)
        except Exception as exc:
            raise _Unknown(f"province_binding_invalid:{type(exc).__name__}") from exc
        province_id = normalized["province_id"]
        raw_inputs.update({
            "module_base": hex(module_base),
            "province_binding": deepcopy(normalized),
            "province_id": province_id,
            "province_record_pointer": hex(record),
        })

        owner, owner_pointer = _resolve_owner(reader, module_base, record, raw_inputs)
        bases = _read_bases(reader, record, province_id, raw_inputs)
        tribal_pointer, bonus_gate, capital_id = _read_bonus_context(
            reader, owner_pointer, province_id, raw_inputs)
        raw_inputs["bonus_context"] = {
            "gate": bonus_gate,
            "owner_province_id": capital_id,
            "owner_country_pointer": hex(owner_pointer),
            "tribal_pointer": hex(tribal_pointer),
        }
        components, total = _components(
            reader, bases, tribal_pointer, bonus_gate, province_id, raw_inputs)
        raw_inputs["component_raw_values"] = {
            name: components[name]["component_raw"] for name, _, _ in _COMPONENTS
        }
        raw_inputs["total_raw"] = total
        raw_inputs["display_integer"] = _trunc_div_1000(total)
        raw_inputs["owner"] = {
            "tag": owner.get("value"),
            "resolution": deepcopy(owner),
        }
        result[FIELD_ID] = {
            "status": "known",
            "value": total,
            "scale": SCALE,
            "period": "current",
            "basis": _BASIS,
            "partial": True,
            "complete": False,
            "raw_inputs": raw_inputs,
        }
    except _Unknown as exc:
        result[FIELD_ID] = _unknown(exc.reason, raw_inputs)
    except Exception as exc:
        result[FIELD_ID] = _unknown(f"DEVELOPMENT_READ_FAILED:{type(exc).__name__}", raw_inputs)
    return result


__all__ = ["FIELD_ID", "read_fields"]
