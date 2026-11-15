"""Canonical digests for joining independently captured religion bindings.

This module accepts already validated known leaf fields. It never reads
process memory and returns only SHA-256 digests, so callers can compare the
object binding of a displayed name with the object binding of native keys.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any

from . import country_faith_memory as _faith
from .model import canonical


_HEX_16 = re.compile(r"[0-9a-fA-F]{16}\Z")
_MISSING = object()
_PRIMARY_POINTER_RAW_KEYS = (
    "primary_religion_pointer_raw_hex",
    "primary_religion_pointer_before_raw_hex",
    "primary_religion_pointer_after_raw_hex",
)
_GROUP_POINTER_RAW_KEYS = (
    "religion_group_pointer_raw_hex",
    "religion_group_pointer_before_raw_hex",
    "religion_group_pointer_after_raw_hex",
)


def _pointer(value: Any, label: str) -> int:
    parsed = _faith._parse_uint(value, label)
    return _faith._user_pointer(parsed, label, aligned=True)


def _validate_pointer_raw(raw_inputs: Mapping[str, Any], keys: tuple[str, ...],
                          pointer: int, label: str) -> int:
    """Validate every supplied raw copy; return the number of copies checked."""
    expected = pointer.to_bytes(8, "little")
    checked = 0
    for key in keys:
        if key not in raw_inputs:
            continue
        value = raw_inputs[key]
        if not isinstance(value, str) or _HEX_16.fullmatch(value) is None:
            raise ValueError(f"{label}_raw_hex_invalid:{key}")
        try:
            raw = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError(f"{label}_raw_hex_invalid:{key}") from exc
        if len(raw) != 8 or raw != expected:
            raise ValueError(f"{label}_raw_mismatch:{key}")
        checked += 1
    return checked


def _digest(material: dict[str, str]) -> str:
    return hashlib.sha256(canonical(material).encode("utf-8")).hexdigest()


def binding_digests(field: Any, country: str, *,
                    require_group: bool = False) -> dict[str, str]:
    """Return canonical SHA-256 digests for the captured native object binding.

    ``field`` must be a known leaf-field mapping whose ``raw_inputs`` preserve
    the country binding, module base, and primary religion pointer. A group
    digest is included when a valid group pointer is present. If
    ``require_group`` is true, an absent or invalid group binding is an error.
    The returned object contains digests only and never exposes pointers.
    """
    if type(require_group) is not bool:
        raise ValueError("require_group_invalid")
    if not isinstance(field, Mapping) or field.get("status") != "known":
        raise ValueError("field_not_known")
    raw_inputs = field.get("raw_inputs")
    if not isinstance(raw_inputs, Mapping):
        raise ValueError("raw_inputs_invalid")
    if not isinstance(country, str):
        raise ValueError("country_invalid")

    target_binding = raw_inputs.get("country_binding")
    try:
        bound_country_pointer, binding = _faith._binding(target_binding)
    except Exception as exc:
        raise ValueError(f"country_binding_invalid:{type(exc).__name__}") from exc
    if binding["tag"] != country:
        raise ValueError("country_binding_tag_mismatch")

    raw_country_pointer = _pointer(raw_inputs.get("country_pointer"), "country_pointer")
    if raw_country_pointer != bound_country_pointer:
        raise ValueError("country_pointer_binding_mismatch")

    module_base_value = _faith._parse_uint(raw_inputs.get("module_base"), "module_base")
    module_base = _faith._user_pointer(module_base_value, "module_base")

    primary_pointer = _pointer(
        raw_inputs.get("primary_religion_pointer"), "primary_religion_pointer")
    _validate_pointer_raw(raw_inputs, _PRIMARY_POINTER_RAW_KEYS,
                          primary_pointer, "primary_religion_pointer")

    fullref_value = _faith._parse_uint(binding["fullref"], "country_fullref")
    fullref_raw = bytes.fromhex(binding["fullref_raw_hex"])
    if len(fullref_raw) != 8 or fullref_raw != fullref_value.to_bytes(8, "little"):
        raise ValueError("country_fullref_raw_invalid")

    common = {
        "country": binding["tag"],
        "module_base": hex(module_base),
        "country_pointer": hex(bound_country_pointer),
        "country_fullref": hex(fullref_value),
        "primary_religion_pointer": hex(primary_pointer),
    }
    material = {"schema": "information.religion_binding.v1", **common}
    result = {"religion_binding_sha256": _digest(material)}

    group_value = raw_inputs.get("religion_group_pointer", _MISSING)
    group_raw_present = any(key in raw_inputs for key in _GROUP_POINTER_RAW_KEYS)
    group_pointer: int | None = None
    if group_value is not _MISSING:
        group_pointer = _pointer(group_value, "religion_group_pointer")
    elif group_raw_present:
        supplied_raw = [raw_inputs[key] for key in _GROUP_POINTER_RAW_KEYS
                        if key in raw_inputs]
        parsed_raw: list[int] = []
        for key, value in zip(
                (key for key in _GROUP_POINTER_RAW_KEYS if key in raw_inputs), supplied_raw):
            if not isinstance(value, str) or _HEX_16.fullmatch(value) is None:
                raise ValueError(f"religion_group_pointer_raw_hex_invalid:{key}")
            parsed_raw.append(int.from_bytes(bytes.fromhex(value), "little"))
        if not parsed_raw or any(value != parsed_raw[0] for value in parsed_raw[1:]):
            raise ValueError("religion_group_pointer_raw_mismatch")
        group_pointer = _pointer(parsed_raw[0], "religion_group_pointer")

    if group_pointer is None:
        if require_group:
            raise ValueError("religion_group_pointer_missing")
        return result

    _validate_pointer_raw(raw_inputs, _GROUP_POINTER_RAW_KEYS,
                          group_pointer, "religion_group_pointer")
    group_material = {
        "schema": "information.religion_group_binding.v1",
        **common,
        "religion_group_pointer": hex(group_pointer),
    }
    result["religion_group_binding_sha256"] = _digest(group_material)
    return result


__all__ = ["binding_digests"]
