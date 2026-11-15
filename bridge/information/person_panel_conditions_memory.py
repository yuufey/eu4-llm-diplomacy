"""Bounded private reader for three selected-country panel condition inputs.

This leaf reads country panel property slots and projects only the boolean
property rule established for this fixed B23 layout. It does not execute game
helpers, infer government type names, inspect TLS, or claim that a panel was
rendered.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any


COUNTRY_FULLREF_OFFSET = 0x20
COUNTRY_PANEL_ATTRIBUTES_POINTER_OFFSET = 0x1420
PANEL_ATTRIBUTES_BASE_OFFSET = 0x38

HEIR_PANEL_SLOT_OFFSET = 0xB8
HEIR_SPECIAL_NAME_SLOT_OFFSET = 0xA8
MONARCHISTS_SLOT_OFFSET = 0x1F8

PROPERTY_TOKEN_OFFSET = 0x0
PROPERTY_VALUE_OFFSET = 0x8
PROPERTY_TOKEN_SIZE = 4
PROPERTY_VALUE_SIZE = 1

HEIR_TLS_GATE_FIRST_RVA = 0x233FEB4
HEIR_TLS_GATE_SECOND_RVA = 0x233FEB6

MAX_COUNTRY_SLOTS = 4096
MAX_READ_CALLS = 32
MAX_TOTAL_READ_BYTES = 4096
MAX_SINGLE_READ_BYTES = 8
MIN_USER_ADDRESS = 0x10000
MAX_USER_ADDRESS_EXCLUSIVE = 0x800000000000
MAX_U64 = 0xFFFFFFFFFFFFFFFF

_TAG_RE = re.compile(r"[A-Z0-9]{3}\Z")
_FIELD_SLOTS = {
    "heir_panel": HEIR_PANEL_SLOT_OFFSET,
    "heir_special_name": HEIR_SPECIAL_NAME_SLOT_OFFSET,
    "monarchists": MONARCHISTS_SLOT_OFFSET,
}


class PersonPanelReadError(ValueError):
    """A bounded address, field, or memory read could not be validated."""


def _parse_uint(value: Any, label: str, *, maximum: int = MAX_U64) -> int:
    if isinstance(value, bool):
        raise PersonPanelReadError(f"{label}_invalid")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value, 0)
        except ValueError as exc:
            raise PersonPanelReadError(f"{label}_invalid") from exc
    else:
        raise PersonPanelReadError(f"{label}_invalid")
    if not 0 <= parsed <= maximum:
        raise PersonPanelReadError(f"{label}_out_of_range")
    return parsed


def _user_pointer(value: int, label: str, *, aligned: bool = False) -> int:
    if not MIN_USER_ADDRESS <= value < MAX_USER_ADDRESS_EXCLUSIVE:
        raise PersonPanelReadError(f"{label}_invalid")
    if aligned and value & 7:
        raise PersonPanelReadError(f"{label}_unaligned")
    return value


def _checked_add(base: int, offset: int, label: str) -> int:
    _user_pointer(base, f"{label}_base")
    if type(offset) is not int or offset < 0 or base > MAX_U64 - offset:
        raise PersonPanelReadError(f"{label}_arithmetic_invalid")
    return _user_pointer(base + offset, label)


def _read_exact(limiter: Any, address: int, size: int, label: str,
                state: dict[str, Any]) -> bytes:
    if type(size) is not int or not 0 < size <= MAX_SINGLE_READ_BYTES:
        raise PersonPanelReadError(f"{label}_size_invalid")
    _user_pointer(address, f"{label}_address")
    end = address + size
    if end > MAX_USER_ADDRESS_EXCLUSIVE or end <= address:
        raise PersonPanelReadError(f"{label}_range_invalid")
    if state["calls"] >= MAX_READ_CALLS:
        raise PersonPanelReadError("read_call_budget_exceeded")
    if state["bytes_requested"] + size > MAX_TOTAL_READ_BYTES:
        raise PersonPanelReadError("read_byte_budget_exceeded")
    state["calls"] += 1
    state["bytes_requested"] += size
    try:
        if callable(limiter):
            result = limiter(address, size, label)
        else:
            reader = getattr(limiter, "read", None)
            if not callable(reader):
                raise PersonPanelReadError("limiter_read_unavailable")
            result = reader(address, size, label)
    except Exception as exc:
        state["reads"].append({
            "address": hex(address),
            "size": size,
            "label": label,
            "status": "failed",
            "error": f"{type(exc).__name__}:{str(exc)[:160]}",
        })
        raise PersonPanelReadError(f"read_failed:{label}:{type(exc).__name__}") from exc
    if not isinstance(result, (bytes, bytearray, memoryview)):
        state["reads"].append({
            "address": hex(address), "size": size, "label": label,
            "status": "failed", "error": "read_result_not_bytes",
        })
        raise PersonPanelReadError(f"read_result_not_bytes:{label}")
    raw = bytes(result)
    if len(raw) != size:
        state["reads"].append({
            "address": hex(address), "size": size, "label": label,
            "status": "failed", "error": f"short_read:{len(raw)}:{size}",
            "raw_hex": raw.hex(),
        })
        raise PersonPanelReadError(f"short_read:{label}:{len(raw)}:{size}")
    state["reads"].append({
        "address": hex(address), "size": size, "label": label,
        "status": "ok", "raw_hex": raw.hex(),
    })
    return raw


def _binding(target_binding: Any) -> tuple[int, int, dict[str, Any]]:
    if not isinstance(target_binding, Mapping):
        raise PersonPanelReadError("target_binding_invalid")
    tag = target_binding.get("tag")
    if not isinstance(tag, str) or not _TAG_RE.fullmatch(tag):
        raise PersonPanelReadError("target_binding_tag_invalid")
    slot = target_binding.get("slot")
    if type(slot) is not int or not 0 <= slot < MAX_COUNTRY_SLOTS:
        raise PersonPanelReadError("target_binding_slot_invalid")
    pointer = _user_pointer(
        _parse_uint(target_binding.get("country_pointer"), "target_country_pointer"),
        "target_country_pointer",
        aligned=True,
    )
    fullref = _parse_uint(target_binding.get("fullref"), "target_country_fullref")
    if ((fullref >> 32) & 0xFFFF) != slot:
        raise PersonPanelReadError("target_binding_fullref_slot_mismatch")
    tag_raw = (fullref & 0xFFFFFF).to_bytes(3, "little")
    try:
        fullref_tag = tag_raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise PersonPanelReadError("target_binding_fullref_tag_invalid") from exc
    if fullref_tag != tag:
        raise PersonPanelReadError("target_binding_fullref_tag_mismatch")
    fullref_raw_hex = fullref.to_bytes(8, "little").hex()
    supplied_raw = target_binding.get("fullref_raw_hex")
    if supplied_raw is not None and supplied_raw != fullref_raw_hex:
        raise PersonPanelReadError("target_binding_fullref_raw_mismatch")
    normalized = {
        "tag": tag,
        "slot": slot,
        "country_pointer": hex(pointer),
        "fullref": hex(fullref),
        "fullref_raw_hex": fullref_raw_hex,
        "country_fullref_address": target_binding.get("country_fullref_address"),
        "table_entry_address": target_binding.get("table_entry_address"),
        "table_entry_raw_hex": target_binding.get("table_entry_raw_hex"),
    }
    return pointer, fullref, normalized


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _parse_property_boolean(limiter: Any, property_pointer: int,
                            field_inputs: dict[str, Any],
                            state: dict[str, Any], field_name: str) -> dict[str, Any]:
    field_inputs["property_pointer"] = hex(property_pointer)
    field_inputs["property_pointer_raw_hex"] = property_pointer.to_bytes(8, "little").hex()
    try:
        property_pointer = _user_pointer(
            property_pointer, f"{field_name}_property_pointer", aligned=True)
    except PersonPanelReadError as exc:
        return _unknown(str(exc))

    token_address = _checked_add(
        property_pointer, PROPERTY_TOKEN_OFFSET, f"{field_name}_property_token_address")
    field_inputs["property_token_address"] = hex(token_address)
    try:
        token_raw = _read_exact(
            limiter, token_address, PROPERTY_TOKEN_SIZE,
            f"person_panel.{field_name}.property_token", state)
    except PersonPanelReadError as exc:
        return _unknown(str(exc))
    token = int.from_bytes(token_raw, "little", signed=True)
    normalized_token = token if token >= 0 else (~token & 0xFFFFFFFF)
    field_inputs["property_token_raw_hex"] = token_raw.hex()
    field_inputs["property_token_signed"] = token
    field_inputs["property_token_normalized"] = normalized_token

    if normalized_token == 0:
        field_inputs["property_type_outcome"] = "token_0_bool"
        value_address = _checked_add(
            property_pointer, PROPERTY_VALUE_OFFSET,
            f"{field_name}_property_value_address")
        field_inputs["property_value_address"] = hex(value_address)
        try:
            value_raw = _read_exact(
                limiter, value_address, PROPERTY_VALUE_SIZE,
                f"person_panel.{field_name}.property_bool_value", state)
        except PersonPanelReadError as exc:
            return _unknown(str(exc))
        value = value_raw[0] != 0
        field_inputs["property_value_raw_hex"] = value_raw.hex()
        field_inputs["property_bool_value"] = value
        return {
            "status": "known",
            "value": value,
            "reason": "bool_property_nonzero_byte" if value else "bool_property_zero_byte",
        }
    if normalized_token <= 9:
        field_inputs["property_type_outcome"] = "token_1_to_9_non_bool"
        return {
            "status": "known",
            "value": False,
            "reason": "non_bool_property_type_projects_false",
        }
    field_inputs["property_type_outcome"] = "token_10_plus_unresolved_or_throwing"
    return _unknown("property_type_token_unresolved_or_throwing")


def _read_field(limiter: Any, base: int, country_pointer: int,
                attributes_pointer: int, field_name: str, slot_offset: int,
                state: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    field_inputs: dict[str, Any] = {
        "slot_offset": hex(slot_offset),
        "property_type_resolution": "static_projection_only_no_native_call",
    }
    try:
        slot_address = _checked_add(
            attributes_pointer, slot_offset, f"{field_name}_property_slot_address")
        field_inputs["property_slot_address"] = hex(slot_address)
        property_pointer_raw = _read_exact(
            limiter, slot_address, 8,
            f"person_panel.{field_name}.property_pointer", state)
        property_pointer = int.from_bytes(property_pointer_raw, "little")
        field_inputs["property_pointer_raw_hex"] = property_pointer_raw.hex()
        field_inputs["property_pointer"] = hex(property_pointer) if property_pointer else None
        if property_pointer == 0:
            result = {
                "status": "known",
                "value": False,
                "reason": "null_property_default_false",
            }
        else:
            result = _parse_property_boolean(
                limiter, property_pointer, field_inputs, state, field_name)

        if field_name == "heir_panel" and result.get("status") == "known":
            field_inputs["property_condition_reason"] = result["reason"]
            if result.get("value") is True:
                result["reason"] = (
                    "projected_true_selects_heir_character_name_info_branch")
            else:
                result["reason"] = (
                    "projected_false_hides_monarch_heir_name_election_info_not_no_heir")

        if field_name == "heir_special_name" and result.get("status") == "known":
            if result.get("value") is False:
                result["reason"] = f"{result['reason']};tls_gate_not_needed_for_false"
            else:
                first_address = _checked_add(
                    base, HEIR_TLS_GATE_FIRST_RVA, "heir_tls_gate_first_address")
                second_address = _checked_add(
                    base, HEIR_TLS_GATE_SECOND_RVA, "heir_tls_gate_second_address")
                field_inputs["tls_gate_first_address"] = hex(first_address)
                field_inputs["tls_gate_second_address"] = hex(second_address)
                try:
                    first_raw = _read_exact(
                        limiter, first_address, 1,
                        "person_panel.heir_special_name.tls_gate_first", state)
                except PersonPanelReadError as exc:
                    result = _unknown(str(exc))
                else:
                    first = first_raw[0]
                    field_inputs["tls_gate_first_raw_hex"] = first_raw.hex()
                    field_inputs["tls_gate_first"] = first
                    try:
                        second_raw = _read_exact(
                            limiter, second_address, 1,
                            "person_panel.heir_special_name.tls_gate_second", state)
                    except PersonPanelReadError as exc:
                        result = _unknown(str(exc))
                    else:
                        second = second_raw[0]
                        field_inputs["tls_gate_second_raw_hex"] = second_raw.hex()
                        field_inputs["tls_gate_second"] = second
                        field_inputs["tls_fastpath"] = first != 0 and second == 0
                        if field_inputs["tls_fastpath"]:
                            result["reason"] = "bool_property_true_tls_bypass_gate"
                        else:
                            result = _unknown("tls_required_not_observed")
        return result, field_inputs
    except Exception as exc:
        return _unknown(str(exc) or type(exc).__name__), field_inputs


def read_person_panel_conditions(limiter: Any, base: int,
                                 target_binding: Mapping[str, Any]) -> dict[str, Any]:
    """Read selected-country heir-panel, special-name, and monarchist conditions.

    Results are independent per field. A missing country attributes pointer
    leaves all fields unknown because the observed global fallback is not
    implemented here. Empty property slots are known false; property token 0
    reads one value byte, tokens 1..9 project false, and tokens 10+ remain
    unknown. The heir field additionally requires the observed two-byte
    fastpath; otherwise a true property is withheld as TLS-dependent.
    """
    state: dict[str, Any] = {"calls": 0, "bytes_requested": 0, "reads": []}
    raw_inputs: dict[str, Any] = {"field_inputs": {}}
    global_reason: str | None = None
    country_pointer: int | None = None
    attributes_pointer: int | None = None
    try:
        module_base = _user_pointer(_parse_uint(base, "module_base"), "module_base")
        raw_inputs["module_base"] = hex(module_base)
        country_pointer, expected_fullref, normalized_binding = _binding(target_binding)
        raw_inputs["target_binding"] = normalized_binding
        fullref_address = _checked_add(
            country_pointer, COUNTRY_FULLREF_OFFSET, "target_country_fullref_address")
        actual_fullref_raw = _read_exact(
            limiter, fullref_address, 8, "person_panel.target_fullref", state)
        actual_fullref = int.from_bytes(actual_fullref_raw, "little")
        raw_inputs["target_fullref_address"] = hex(fullref_address)
        raw_inputs["target_fullref_raw_hex"] = actual_fullref_raw.hex()
        raw_inputs["target_fullref"] = hex(actual_fullref)
        if actual_fullref != expected_fullref:
            raise PersonPanelReadError("target_binding_fullref_memory_mismatch")

        attributes_pointer_address = _checked_add(
            country_pointer, COUNTRY_PANEL_ATTRIBUTES_POINTER_OFFSET,
            "country_panel_attributes_pointer_address")
        attributes_pointer_raw = _read_exact(
            limiter, attributes_pointer_address, 8,
            "person_panel.country_attributes_pointer", state)
        attributes_owner = int.from_bytes(attributes_pointer_raw, "little")
        raw_inputs["country_attributes_pointer_address"] = hex(attributes_pointer_address)
        raw_inputs["country_attributes_pointer_raw_hex"] = attributes_pointer_raw.hex()
        raw_inputs["country_attributes_pointer"] = (
            hex(attributes_owner) if attributes_owner else None)
        if attributes_owner == 0:
            raise PersonPanelReadError(
                "country_attributes_pointer_null_global_fallback_not_implemented")
        attributes_owner = _user_pointer(
            attributes_owner, "country_attributes_pointer", aligned=True)
        attributes_pointer = _checked_add(
            attributes_owner, PANEL_ATTRIBUTES_BASE_OFFSET,
            "country_panel_attributes_base")
        raw_inputs["country_panel_attributes_base"] = hex(attributes_pointer)
    except Exception as exc:
        global_reason = str(exc) or type(exc).__name__

    result: dict[str, Any] = {}
    if global_reason is not None:
        for field_name in _FIELD_SLOTS:
            result[field_name] = _unknown(global_reason)
            raw_inputs["field_inputs"][field_name] = {}
    else:
        assert country_pointer is not None and attributes_pointer is not None
        for field_name, slot_offset in _FIELD_SLOTS.items():
            field_result, field_inputs = _read_field(
                limiter, module_base, country_pointer, attributes_pointer,
                field_name, slot_offset, state)
            result[field_name] = field_result
            raw_inputs["field_inputs"][field_name] = field_inputs

    raw_inputs["read_calls"] = state["calls"]
    raw_inputs["bytes_requested"] = state["bytes_requested"]
    raw_inputs["reads"] = state["reads"]
    result["raw_inputs"] = raw_inputs
    result["basis"] = "B23_monarch_heir_panel_property_static_projection"
    result["gaps"] = [
        "PROPERTY_TYPE_NAMES_ARE_NOT_RESOLVED",
        "PROPERTY_VALUES_ARE_MEMORY_PROJECTIONS_NOT_NATIVE_CALL_RESULTS",
        "HEIR_TRUE_REQUIRES_UNOBSERVED_TLS_CONTEXT_UNLESS_FASTPATH_GATE_MATCHES",
        "HEIR_PANEL_FALSE_DOES_NOT_PROVE_THERE_IS_NO_HEIR",
        "GLOBAL_COUNTRY_ATTRIBUTE_FALLBACK_NOT_IMPLEMENTED",
        "NO_PANEL_RENDER_OR_PUBLIC_VISIBILITY_OBSERVED",
    ]
    return result


__all__ = [
    "COUNTRY_FULLREF_OFFSET",
    "COUNTRY_PANEL_ATTRIBUTES_POINTER_OFFSET",
    "PANEL_ATTRIBUTES_BASE_OFFSET",
    "HEIR_PANEL_SLOT_OFFSET",
    "HEIR_SPECIAL_NAME_SLOT_OFFSET",
    "MONARCHISTS_SLOT_OFFSET",
    "PROPERTY_TOKEN_OFFSET",
    "PROPERTY_VALUE_OFFSET",
    "HEIR_TLS_GATE_FIRST_RVA",
    "HEIR_TLS_GATE_SECOND_RVA",
    "read_person_panel_conditions",
]
